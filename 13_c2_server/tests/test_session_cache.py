"""
DAYANJING v4 — 13_c2_server/tests/test_session_cache.py

会话恢复缓存测试。

要证明的核心性质（不是"能存能取"）：
  1) 密钥分离：cache_key 与主密钥、与任何会话密钥都不同（域分离成立）
  2) 计数器延续：恢复后 counter 从断点继续，绝不归零
     —— 归零即 IV 重用，是 GCM 的致命误用
  3) 篡改/错密钥/AAD 不符一律抛错，绝不返回半解出的数据
  4) 条目绑定到 implant：A 的条目不能当 B 的用
  5) 拒绝退化会话（k_c2s == k_s2c）
  6) TTL 过期与 sweep
"""

import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_layer import hkdf                      # noqa: E402
from key_derivation import derive_session          # noqa: E402
from session_cache import SessionCache, CacheError, derive_cache_key  # noqa: E402

PASS = 0
FAIL = 0


def check(cond, name, extra=""):
    global PASS, FAIL
    if cond:
        print(f"[PASS] {name}" + (f"  {extra}" if extra else ""))
        PASS += 1
    else:
        print(f"[FAIL] {name}" + (f"  {extra}" if extra else ""))
        FAIL += 1


def real_session(master, implant_id, generation=1):
    """用真实派生链产出会话密钥（不是随手造的随机字节）。"""
    server_static_id = bytes(range(16))
    transcript = bytes([0xA5] * 32)
    k_c2s, k_s2c, _ = derive_session(master, transcript,
                                     server_static_id, implant_id, generation)
    return k_c2s, k_s2c, server_static_id


def main():
    print("=== test_session_cache ===")
    master = bytes([0x11] * 16)   # derive_session 要求 16 字节
    k_c2s, k_s2c, sid = real_session(master, "implant-A")

    # ---- 1. 密钥分离 ----
    ck = derive_cache_key(master, sid)
    print(f"      cache_key={ck[:8].hex()}...")
    check(ck[:16] != master[:16], "cache_key 不等于主密钥（单向派生）")
    check(ck[:16] != k_c2s, "cache_key 不等于 k_c2s（域分离）")
    check(ck[:16] != k_s2c, "cache_key 不等于 k_s2c（域分离）")
    # 不同 server_static_id => 不同 cache_key
    ck2 = derive_cache_key(master, bytes([0xFF] * 16))
    check(ck2 != ck, "不同 server_static_id 派生出不同 cache_key")

    # ---- 2. 往返一致性 ----
    c = SessionCache(master, sid, ttl=3600)
    c.put("implant-A", 1, k_c2s, k_s2c, seq_out=7, seq_in=5,
          cell_send_ctr=100, cell_recv_ctr=90)
    e = c.get("implant-A")
    check(e is not None, "put 后 get 命中")
    check(e["k_c2s"] == k_c2s, "恢复后 k_c2s 一致")
    check(e["k_s2c"] == k_s2c, "恢复后 k_s2c 一致")
    check(e["generation"] == 1, "恢复后 generation 一致")

    # ---- 3. 计数器延续（本模块存在的核心理由）----
    check(e["seq_out"] == 7 and e["seq_in"] == 5, "seq 延续，未归零")
    check(e["cell_send_ctr"] == 100, "cell 发送计数延续，未归零")
    check(e["cell_recv_ctr"] == 90, "cell 接收计数延续，未归零")
    check(e["cell_send_ctr"] != 0, "cell 计数不为 0（归零即 IV 重用）")

    # ---- 4. 篡改一律失败 ----
    blob = bytearray(c._entries["implant-A"])
    blob[-1] ^= 0x01                      # 改密文末字节
    c._entries["implant-A"] = bytes(blob)
    try:
        c.get("implant-A")
        check(False, "篡改密文被拒")
    except CacheError:
        check(True, "篡改密文被拒（AEAD 生效）")
    c.drop("implant-A")

    c.put("implant-A", 1, k_c2s, k_s2c, 1, 1, 10, 10)
    blob = bytearray(c._entries["implant-A"])
    blob[20] ^= 0x80                      # 改 tag
    c._entries["implant-A"] = bytes(blob)
    try:
        c.get("implant-A")
        check(False, "篡改 tag 被拒")
    except CacheError:
        check(True, "篡改 tag 被拒")
    c.drop("implant-A")

    # ---- 5. 错主密钥解不开 ----
    c.put("implant-A", 1, k_c2s, k_s2c, 3, 3, 30, 30)
    other = SessionCache(bytes([0x22] * 16), sid, ttl=3600)
    other._entries = dict(c._entries)     # 拿到同样的密文
    other._created = dict(c._created)
    try:
        other.get("implant-A")
        check(False, "错主密钥解不开缓存")
    except CacheError:
        check(True, "错主密钥解不开缓存（主密钥泄露前缓存不可用）")

    # ---- 6. AAD 绑定：A 的条目不能当 B 用 ----
    # 注意：直接 get("implant-B") 只会因"条目不存在"返回 None，走不到 AAD 校验。
    # 真正的性质是：**把 A 的密文移植到 B 名下**，解密必须因 AAD 不符而失败。
    check(c.get("implant-B") is None, "不存在的条目返回 None")
    a_blob = c._entries["implant-A"]
    c._entries["implant-B"] = a_blob
    c._created["implant-B"] = time.time()
    try:
        c.get("implant-B")
        check(False, "移植到 B 名下的 A 条目被拒")
    except CacheError:
        check(True, "移植到 B 名下的 A 条目被拒（AAD 绑定 implant_id）")
    c.drop("implant-B")
    # 移植后不得影响 A 自身
    check(c.get("implant-A") is not None, "移植尝试不影响原条目 A")

    # ---- 7. 拒绝退化会话 ----
    try:
        c.put("implant-D", 1, k_c2s, k_c2s, 0, 0, 0, 0)
        check(False, "k_c2s == k_s2c 被拒")
    except CacheError:
        check(True, "k_c2s == k_s2c 被拒（拒绝退化会话）")

    # ---- 8. TTL 过期 ----
    c2 = SessionCache(master, sid, ttl=1)
    c2.put("implant-T", 1, k_c2s, k_s2c, 1, 1, 1, 1)
    check(c2.get("implant-T") is not None, "TTL 内可读")
    c2._created["implant-T"] = time.time() - 100   # 手动回拨创建时间
    check(c2.get("implant-T") is None, "超过 TTL 后条目不可用并自动清除")
    check(len(c2) == 0, "过期条目已被清除")

    # ---- 9. sweep ----
    c3 = SessionCache(master, sid, ttl=1)
    for i in range(5):
        c3.put(f"imp-{i}", 1, k_c2s, k_s2c, 1, 1, 1, 1)
    check(len(c3) == 5, "写入 5 条")
    c3._created = {k: time.time() - 100 for k in c3._created}
    n = c3.sweep()
    check(n == 5 and len(c3) == 0, f"sweep 清理全部过期条目 (n={n})")

    # ---- 10. 非法 implant_id ----
    try:
        c.put("../escape", 1, k_c2s, k_s2c, 0, 0, 0, 0)
        check(False, "含路径穿越的 implant_id 被拒")
    except CacheError:
        check(True, "含路径穿越的 implant_id 被拒")

    print(f"=== result: {PASS} pass, {FAIL} fail ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
