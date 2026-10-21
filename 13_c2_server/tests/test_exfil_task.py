"""
DAYANJING v4 — C2 下行任务通道测试（跨语言对齐）
=================================================

重点在 **跨语言对齐**：用 21_exfil 的 C 侧真实代码（dump_task）编码命令与
回执，Python 侧解码；再反向由 Python 编码、C 侧解码。只让 Python 自编自解
会把"两边同步错"掩盖掉 —— 两边都错成一样也会通过。

验证的性质：
  1. 线上格式两端逐字节一致（命令 56B / 回执 32B）
  2. 命令确实走会话 AEAD：篡改必被拒
  3. 编码唯一性两端一致：非 SET_CFG 带配置、保留位非 0 都被拒
  4. 配置校验两端一致：倒挂区间、window_us=0 带配额都被拒
"""

import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from frame import SealedEnvelope, ROLE_SERVER  # noqa: E402
import exfil_task as T                          # noqa: E402

DUMP = os.path.join(ROOT, "..", "21_exfil", "build", "dump_task")

# frame.py 强制 k_send != k_recv（正确约束：方向密钥必须分离）。
# 因此按方向拆分：命令由服务端用 KS 封装，回执由植入体用 KR 封装。
KS = bytes.fromhex("00112233445566778899aabbccddeeff")  # 服务端 -> 植入体
KR = bytes.fromhex("ffeeddccbbaa99887766554433221100")  # 植入体 -> 服务端
PFX = bytes.fromhex("0102030405060708")

g_pass = 0
g_fail = 0


def check(name, cond, detail=""):
    global g_pass, g_fail
    if cond:
        print(f"[PASS] {name}")
        g_pass += 1
    else:
        print(f"[FAIL] {name}" + (f"  {detail}" if detail else ""))
        g_fail += 1


# ---------------------------------------------------------------------------
# A. Python 侧自测
# ---------------------------------------------------------------------------

def test_codec():
    for op in (T.OP_START, T.OP_ONCE, T.OP_STOP, T.OP_SET_CFG, T.OP_QUERY):
        cfg = T.default_cfg() if op == T.OP_SET_CFG else None
        pl = T.encode_cmd(op, 0x1234, cfg)
        check(f"A codec: opcode={op} 长度 56", len(pl) == T.CMD_LEN)
        d = T.decode_cmd(pl)
        check(f"A codec: opcode={op} 往返一致",
              d["opcode"] == op and d["task_id"] == 0x1234)
        if op == T.OP_SET_CFG:
            check("A codec: SET_CFG 配置往返一致", d["cfg"] == cfg)

    a = T.encode_ack(T.OP_START, T.ST_OK, 9, T.MODE_CONTINUOUS, 7, 3, 123456)
    check("A codec: 回执长度 32", len(a) == T.ACK_LEN)
    da = T.decode_ack(a)
    check("A codec: 回执往返一致",
          da["opcode"] == T.OP_START and da["task_id"] == 9
          and da["mode"] == T.MODE_CONTINUOUS and da["frames_sent"] == 7
          and da["window_frames"] == 3 and da["window_bytes"] == 123456)


def test_canonical():
    # 非 SET_CFG 带配置 -> 拒
    try:
        T.encode_cmd(T.OP_START, 1, T.default_cfg())
        check("A canon: 非 SET_CFG 带配置被拒", False, "未抛异常")
    except T.TaskError:
        check("A canon: 非 SET_CFG 带配置被拒", True)

    # 保留位非 0 -> 拒
    pl = bytearray(T.encode_cmd(T.OP_START, 1))
    pl[T.CMD_OFF_FLAGS] = 1
    try:
        T.decode_cmd(bytes(pl))
        check("A canon: flags 非 0 被拒", False, "未抛异常")
    except T.TaskError:
        check("A canon: flags 非 0 被拒", True)

    pl = bytearray(T.encode_cmd(T.OP_START, 1))
    pl[T.CMD_OFF_PAD] = 1
    try:
        T.decode_cmd(bytes(pl))
        check("A canon: pad 非 0 被拒", False, "未抛异常")
    except T.TaskError:
        check("A canon: pad 非 0 被拒", True)

    # 未知 opcode
    try:
        T.encode_cmd(99, 1)
        check("A canon: 未知 opcode 被拒", False, "未抛异常")
    except T.TaskError:
        check("A canon: 未知 opcode 被拒", True)


def test_cfg():
    c = T.default_cfg()
    check("A cfg: 默认配置合法", T.cfg_ok(c))

    c2 = dict(c)
    c2["max_interval_us"] = c2["min_interval_us"] - 1
    check("A cfg: 抖动区间倒挂被拒", not T.cfg_ok(c2))

    c3 = dict(c)
    c3["window_us"] = 0
    check("A cfg: window_us=0 带配额被拒", not T.cfg_ok(c3))

    c4 = dict(c)
    c4["window_us"] = 0
    c4["window_max_frames"] = 0
    c4["window_max_bytes"] = 0
    check("A cfg: window_us=0 且无配额 合法", T.cfg_ok(c4))

    try:
        T.encode_cmd(T.OP_SET_CFG, 1, c2)
        check("A cfg: 非法配置不得下发", False, "未抛异常")
    except T.TaskError:
        check("A cfg: 非法配置不得下发", True)


# ---------------------------------------------------------------------------
# B. C 侧真编码 -> Python 解码
# ---------------------------------------------------------------------------

def _read_records(path):
    with open(path, "rb") as f:
        blob = f.read()
    count = struct.unpack_from("<I", blob, 0)[0]
    pos = 4
    out = []
    for _ in range(count):
        kind = blob[pos]
        wlen = struct.unpack_from("<I", blob, pos + 1)[0]
        pos += 5
        out.append((kind, blob[pos:pos + wlen]))
        pos += wlen
    return out


def test_c_to_python():
    if not os.path.exists(DUMP):
        check("B 跨语言: dump_task 存在", False, f"missing {DUMP}")
        return

    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "task.bin")
        p = subprocess.run(
            [DUMP, "gen", path, KS.hex(), PFX.hex()],
            capture_output=True)
        if p.returncode != 0:
            check("B 跨语言: C 侧生成成功", False, p.stderr.decode()[:200])
            return
        check("B 跨语言: C 侧生成成功", True)

        recs = _read_records(path)
        check("B 跨语言: 记录数 7", len(recs) == 7, f"got {len(recs)}")

        env = SealedEnvelope(KR, KS, ROLE_SERVER)
        ok_cmd = 0
        saw_setcfg = False
        for kind, wire in recs:
            got = env.decode(wire)
            if got is None:
                continue
            seq, mt, pl = got
            if mt == T.MSG_TASK:
                d = T.decode_cmd(pl)
                ok_cmd += 1
                if d["opcode"] == T.OP_SET_CFG:
                    saw_setcfg = True
                    check("B 跨语言: SET_CFG 配置字段一致",
                          d["cfg"]["min_interval_us"] == 500000
                          and d["cfg"]["max_interval_us"] == 1500000
                          and d["cfg"]["burst_max"] == 16
                          and d["cfg"]["window_us"] == 10000000
                          and d["cfg"]["window_max_frames"] == 8
                          and d["cfg"]["window_max_bytes"] == 4 * 1024 * 1024
                          and d["cfg"]["dedup"] == 1)
            elif mt == T.MSG_TASK_ACK:
                a = T.decode_ack(pl)
                if a["opcode"] == T.OP_START:
                    check("B 跨语言: 回执字段一致",
                          a["status"] == T.ST_OK and a["task_id"] == 1
                          and a["mode"] == T.MODE_CONTINUOUS
                          and a["frames_sent"] == 7
                          and a["window_frames"] == 3
                          and a["window_bytes"] == 123456)

        check("B 跨语言: 5 条命令全部解开", ok_cmd == 5, f"got {ok_cmd}")
        check("B 跨语言: 含 SET_CFG", saw_setcfg)


# ---------------------------------------------------------------------------
# C. Python 编码 -> C 侧解码
# ---------------------------------------------------------------------------

def test_python_to_c():
    if not os.path.exists(DUMP):
        check("C 跨语言: dump_task 存在", False, f"missing {DUMP}")
        return

    env = SealedEnvelope(KR, KS, ROLE_SERVER)
    ch = T.TaskChannel(env, start_seq=1)

    cfg = T.default_cfg()
    cfg["min_interval_us"] = 250000
    cfg["max_interval_us"] = 750000
    cfg["window_max_frames"] = 4

    wires = [
        (1, ch.start(101)),
        (1, ch.once(102)),
        (1, ch.stop(103)),
        (1, ch.query(104)),
        (1, ch.set_cfg(105, cfg)),
    ]

    blob = struct.pack("<I", len(wires))
    for kind, w in wires:
        blob += bytes([kind]) + struct.pack("<I", len(w)) + w

    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "in.bin")
        with open(path, "wb") as f:
            f.write(blob)

        p = subprocess.run([DUMP, "chk", path, KR.hex()],
                           capture_output=True)
        check("C 跨语言: C 侧解码退出码 0", p.returncode == 0,
              p.stderr.decode()[:200])

        lines = p.stdout.decode().strip().splitlines()
        check("C 跨语言: 解码出 5 条", len(lines) == 5, f"got {len(lines)}")

        joined = "\n".join(lines)
        check("C 跨语言: START 被识别", "opcode=1 task_id=101" in joined)
        check("C 跨语言: ONCE 被识别", "opcode=2 task_id=102" in joined)
        check("C 跨语言: STOP 被识别", "opcode=3 task_id=103" in joined)
        check("C 跨语言: QUERY 被识别", "opcode=5 task_id=104" in joined)
        check("C 跨语言: SET_CFG 配置被识别",
              "opcode=4 task_id=105" in joined
              and "cfg_min=250000" in joined
              and "cfg_max=750000" in joined
              and "wframes=4" in joined)
        check("C 跨语言: 无误码行", "ERROR" not in joined)


# ---------------------------------------------------------------------------
# D. 篡改必被拒
# ---------------------------------------------------------------------------

def test_tamper():
    """
    篡改必被拒。
    用 C 侧生成的帧（KS 封装）做验证：env 的 k_recv = KS 可正常解出，
    篡改任意字节后 AEAD 即拒绝 —— 证明命令确实受会话密钥保护。
    """
    if not os.path.exists(DUMP):
        check("D 篡改: dump_task 存在", False, f"missing {DUMP}")
        return

    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "t.bin")
        p = subprocess.run([DUMP, "gen", path, KS.hex(), PFX.hex()],
                           capture_output=True)
        if p.returncode != 0:
            check("D 篡改: C 侧生成成功", False, p.stderr.decode()[:200])
            return
        recs = _read_records(path)

        env = SealedEnvelope(KR, KS, ROLE_SERVER)   # k_recv == KS
        kind, wire = recs[0]

        got = env.decode(wire)
        check("D 篡改: 正常帧可解", got is not None)
        if got is None:
            return
        seq, mt, pl = got
        check("D 篡改: 类型为命令", mt == T.MSG_TASK)
        check("D 篡改: 内容正确", T.decode_cmd(pl)["task_id"] == 1)

        # 改 tag 末字节
        w1 = bytearray(wire)
        w1[-1] ^= 0x01
        check("D 篡改: 改 tag 后被拒", env.decode(bytes(w1)) is None)

        # 改密文区
        w2 = bytearray(wire)
        w2[len(w2) // 2] ^= 0x01
        check("D 篡改: 改密文后被拒", env.decode(bytes(w2)) is None)

        # 错密钥（另一会话）不得下令
        bad = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
        env2 = SealedEnvelope(KR, bad, ROLE_SERVER)
        check("D 篡改: 错密钥被拒", env2.decode(recs[1][1]) is None)


# ---------------------------------------------------------------------------

def main():
    print("=== test_exfil_task: C2 下行任务通道（跨语言）===")
    test_codec()
    test_canonical()
    test_cfg()
    test_c_to_python()
    test_python_to_c()
    test_tamper()
    print(f"\ntotal={g_pass + g_fail} pass={g_pass} fail={g_fail}")
    return 0 if g_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
