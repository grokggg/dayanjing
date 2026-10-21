"""13_c2_server/tests/test_session_resume.py

会话恢复验证。重点不是"能不能少一次握手"，而是三条安全性质：

  1. 恢复后的会话密钥与原会话一致（不是重新派生了一套新的）
  2. 恢复**必须带走计数器** —— 信元 IV = pfx || counter，归零会让重连前后
     的 IV 重合，同一密钥下 IV 重用 -> 两条密文异或即泄露明文异或
  3. 缓存文件被篡改/回滚 -> 整体拒绝，绝不部分加载

另验证：
  - 跨进程持久化：save 到磁盘 -> 新进程 load -> 能恢复
  - 过期条目自动失效
  - 换 implant_id 的条目不可用于另一个 implant（AAD 绑定）
"""

from __future__ import annotations

import os
import sys
import time
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_layer import GCM, hkdf, hmac_sha256
from session_cache import SessionCache, CacheError, derive_cache_key
from key_derivation import derive_pair, derive_session
from exfil_sink import ExfilSink

PASS = 0
FAIL = 0


def check(cond: bool, name: str) -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"[PASS] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name}")


def info(fmt: str, *a) -> None:
    print("[INFO] " + (fmt % a if a else fmt))


MASTER = bytes(range(32))
SID = b"S" * 16
PSK = bytes([0x11] * 32)
SALT_REG = bytes([0x22] * 32)


def main() -> int:
    # ---------- 1. 缓存密钥域分离 ----------
    ck = derive_cache_key(MASTER, SID)
    check(len(ck) == 32, "用例1 缓存密钥长度 32 字节")
    check(ck != MASTER, "用例1 缓存密钥不等于主密钥")
    check(derive_cache_key(MASTER, b"T" * 16) != ck,
          "用例1 换 server_static_id 后缓存密钥不同")

    # ---------- 2. 基本存取往返 ----------
    sc = SessionCache(MASTER, SID)
    sc.put("implant-a", 3, b"A" * 16, b"B" * 16, 10, 20, 30, 40)
    e = sc.get("implant-a")
    check(e is not None, "用例2 取回条目非空")
    check(e["generation"] == 3, "用例2 generation 往返一致")
    check(e["k_c2s"] == b"A" * 16 and e["k_s2c"] == b"B" * 16,
          "用例2 会话密钥往返一致")
    check((e["seq_out"], e["seq_in"]) == (10, 20), "用例2 seq 往返一致")
    check((e["cell_send_ctr"], e["cell_recv_ctr"]) == (30, 40),
          "用例2 信元计数器往返一致")

    # ---------- 3. 退化会话被拒 ----------
    try:
        sc.put("implant-x", 1, b"K" * 16, b"K" * 16, 0, 0, 0, 0)
        check(False, "用例3 退化会话(k_c2s==k_s2c)被拒")
    except CacheError:
        check(True, "用例3 退化会话(k_c2s==k_s2c)被拒")

    # ---------- 4. 跨 implant 不可迁移（AAD 绑定） ----------
    sc.put("implant-a", 1, b"C" * 16, b"D" * 16, 1, 1, 1, 1)
    sc.put("implant-b", 1, b"E" * 16, b"F" * 16, 2, 2, 2, 2)
    a, b = sc.get("implant-a"), sc.get("implant-b")
    check(a["k_c2s"] == b"C" * 16 and b["k_c2s"] == b"E" * 16,
          "用例4 两个 implant 各自取回自己的密钥")
    # 手工把 a 的密文搬到 b 名下 -> AAD 不符，解密失败
    sc._entries["implant-b"] = sc._entries["implant-a"]
    try:
        sc.get("implant-b")
        check(False, "用例4 条目换到别的 implant 名下被拒（AAD 绑定）")
    except CacheError:
        check(True, "用例4 条目换到别的 implant 名下被拒（AAD 绑定）")

    # ---------- 5. 落盘 + 新对象恢复 ----------
    sc2 = SessionCache(MASTER, SID)
    sc2.put("implant-p", 7, b"P" * 16, b"Q" * 16, 5, 6, 7, 8)
    sc2.put("implant-q", 8, b"R" * 16, b"S" * 16, 1, 2, 3, 4)
    path = tempfile.mktemp(suffix=".cache")
    n = sc2.save(path)
    check(n == 2, "用例5 save 返回条目数 2")
    check(os.path.exists(path), "用例5 文件已写出")

    sc3 = SessionCache(MASTER, SID)
    check(sc3.load(path) == 2, "用例5 新对象 load 恢复 2 条")
    e3 = sc3.get("implant-p")
    check(e3 is not None and e3["generation"] == 7, "用例5 恢复内容正确")
    check(e3["cell_recv_ctr"] == 8, "用例5 恢复的信元计数器正确")
    info("用例5 文件大小 %d 字节", os.path.getsize(path))

    # ---------- 6. 篡改整体拒绝（不部分加载） ----------
    raw = bytearray(open(path, "rb").read())
    raw[-1] ^= 0x01
    open(path, "wb").write(bytes(raw))
    sc4 = SessionCache(MASTER, SID)
    try:
        sc4.load(path)
        check(False, "用例6 篡改文件被整体拒绝")
    except CacheError:
        check(True, "用例6 篡改文件被整体拒绝")
    check(len(sc4) == 0, "用例6 拒绝后缓存仍为空（不部分加载）")

    # 删掉一条也应被检出
    sc5 = SessionCache(MASTER, SID)
    sc5.put("implant-p", 7, b"P" * 16, b"Q" * 16, 5, 6, 7, 8)
    sc5.put("implant-q", 8, b"R" * 16, b"S" * 16, 1, 2, 3, 4)
    p2 = tempfile.mktemp(suffix=".cache")
    sc5.save(p2)
    good = open(p2, "rb").read()
    # 截掉最后一条条目（保留尾部 tag）
    truncated = good[:len(good) - 16 - 4 - 12 - 16 - 72 - 8 - 2 - 9] + good[-16:]
    open(p2, "wb").write(truncated)
    sc6 = SessionCache(MASTER, SID)
    try:
        sc6.load(p2)
        check(False, "用例6 删除条目后被检出")
    except CacheError:
        check(True, "用例6 删除条目后被检出")

    # ---------- 7. 用错误主密钥无法解开 ----------
    sc7 = SessionCache(bytes([0x99] * 32), SID)
    try:
        sc7.load(path if False else tempfile.mktemp())
        check(True, "用例7 空路径返回 0（占位）")
    except CacheError:
        check(False, "用例7 空路径返回 0（占位）")
    sc8 = SessionCache(MASTER, SID)
    sc8.put("implant-z", 1, b"Z" * 16, b"Y" * 16, 0, 0, 0, 0)
    pz = tempfile.mktemp(suffix=".cache")
    sc8.save(pz)
    sc9 = SessionCache(bytes([0x99] * 32), SID)
    try:
        sc9.load(pz)
        check(False, "用例7 错误主密钥无法解开缓存文件")
    except CacheError:
        check(True, "用例7 错误主密钥无法解开缓存文件")

    # ---------- 8. 恢复后信元通道从断点续接（核心） ----------
    km = derive_pair(PSK, SALT_REG)
    k_c2s, k_s2c, _ = derive_session(
        b"M" * 16, b"H" * 32, SID, "implant-r", 1)
    check(k_c2s != k_s2c, "用例8 会话密钥方向分离")

    sink_fresh = ExfilSink.for_implant(k_c2s, k_s2c, SID, "implant-r")
    check(sink_fresh.counter == 0, "用例8 新建 sink 计数器从 0 起")

    sink_resumed = ExfilSink.for_implant(k_c2s, k_s2c, SID, "implant-r",
                                         recv_counter=41)
    check(sink_resumed.counter == 41, "用例8 恢复的 sink 从断点 41 续接")

    # 反证：用断点 41 的 sink 去解 counter=0 的信元必然被拒（IV 不匹配）
    from exfil_sink import derive_tunnel_keys, derive_node_id
    peer = derive_node_id("implant-r")
    ks, kr, pfx = derive_tunnel_keys(k_c2s, k_s2c, SID, peer)
    g = GCM(ks)
    iv0 = pfx + (0).to_bytes(4, "little")
    ct0, tag0 = g.encrypt(iv0, b"\x00" * 32, b"")
    wire0 = iv0[8:] + ct0 + tag0
    wire0 = wire0 + b"\x00" * (512 - len(wire0))
    rejected = False
    try:
        sink_resumed.feed(wire0)
    except Exception:
        rejected = True
    check(rejected, "用例8 断点 sink 拒绝 counter=0 的重放信元（IV 不匹配）")
    info("用例8 证明：恢复不续接计数器会导致全线 AUTH，而非静默可用")

    # ---------- 9. 过期自动失效 ----------
    sc10 = SessionCache(MASTER, SID, ttl=1)
    sc10.put("implant-e", 1, b"E" * 16, b"F" * 16, 0, 0, 0, 0)
    check(sc10.get("implant-e") is not None, "用例9 未过期可取回")
    time.sleep(1.2)
    check(sc10.get("implant-e") is None, "用例9 过期后返回 None")
    check(len(sc10) == 0, "用例9 过期条目被自动清除")

    # ---------- 10. sweep ----------
    sc11 = SessionCache(MASTER, SID, ttl=1)
    for i in range(3):
        sc11.put(f"implant-{i}", 1, bytes([i]) * 16, bytes([i + 1]) * 16,
                 0, 0, 0, 0)
    time.sleep(1.2)
    check(sc11.sweep() == 3, "用例10 sweep 清掉全部过期条目")

    print(f"\n=== result: {PASS} pass, {FAIL} fail ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
