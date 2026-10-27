#!/usr/bin/env python3
"""红线巡检自检：证明状态机三态可判别，不是恒绿。

三条注入，方向各异：
  G1 伪造 R4 编译器在 PATH  -> 必须报 PENDING（环境具备却无证据）
  G2 再放证据文件           -> 必须转 VERIFIED 且退出 0
  G3 证据文件为 0 字节      -> 必须仍报 PENDING（空文件不算证据）
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(ROOT, "redline_check.py")
EV = os.path.join(ROOT, "evidence")

PASS = 0
FAIL = 0


def ck(name, ok, detail=""):
    global PASS, FAIL
    PASS += 1 if ok else 0
    FAIL += 0 if ok else 1
    print("[%s] %s %s" % ("OK" if ok else "FAIL", name, detail))


def run_check(env=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    p = subprocess.run([sys.executable, "-u", CHECK], capture_output=True,
                       text=True, env=e, timeout=120)
    return p.returncode, p.stdout


def main():
    # 基线：当前真实状态
    rc0, out0 = run_check()
    ck("G0 基线无 PENDING", rc0 == 0 and "PENDING" not in out0.split("=== 汇总 ===")[0],
       "rc=%s" % rc0)

    # G1: PATH 注入伪造的 aarch64 编译器
    fake = tempfile.mkdtemp(prefix="rlfake_")
    gcc = os.path.join(fake, "aarch64-linux-gnu-gcc")
    with open(gcc, "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod(gcc, 0o755)

    rc1, out1 = run_check({"PATH": fake + ":" + os.environ["PATH"]})
    seg1 = out1.split("=== 汇总 ===")[0]
    r4_line = [l for l in out1.split("\n") if "R4" in l and "[" in l]
    ck("G1 伪造编译器 -> R4 报 PENDING",
       r4_line and "PENDING" in r4_line[0], r4_line[0].strip() if r4_line else "未找到R4行")
    ck("G1 整体退出码为 1（报警）", rc1 == 1, "rc=%s" % rc1)

    # G2: 放真实证据文件
    ev_path = os.path.join(EV, "R4.evidence")
    rc2, out2 = run_check({"PATH": fake + ":" + os.environ["PATH"]})
    with open(ev_path, "w") as f:
        f.write("R4 证据占位（自检用）\n")
    rc3, out3 = run_check({"PATH": fake + ":" + os.environ["PATH"]})
    r4b = [l for l in out3.split("\n") if "R4" in l and "[" in l]
    ck("G2 有证据 -> R4 转 VERIFIED",
       r4b and "VERIFIED" in r4b[0], r4b[0].strip() if r4b else "无")
    ck("G2 整体退出码回 0", rc3 == 0, "rc=%s" % rc3)

    # G3: 证据文件清空 -> 空文件不算证据
    with open(ev_path, "w") as f:
        pass
    rc4, out4 = run_check({"PATH": fake + ":" + os.environ["PATH"]})
    r4c = [l for l in out4.split("\n") if "R4" in l and "[" in l]
    ck("G3 空证据文件 -> 仍 PENDING",
       r4c and "PENDING" in r4c[0], r4c[0].strip() if r4c else "无")
    ck("G3 整体退出码为 1", rc4 == 1, "rc=%s" % rc4)

    # 清理：不得留下伪造证据
    if os.path.exists(ev_path):
        os.remove(ev_path)
    shutil.rmtree(fake, ignore_errors=True)
    rc5, _ = run_check()
    ck("G4 清理后回到基线", rc5 == 0, "rc=%s" % rc5)
    ck("G4 证据目录已清空", not os.path.exists(ev_path), "")

    print("\ntotal=%d pass=%d fail=%d" % (PASS + FAIL, PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
