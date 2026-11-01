#!/usr/bin/env python3
"""探测：当前环境的用户态模拟器能否执行 i386 (x86 32-bit) 静态 musl 二进制。

【为什么要单独一条探测】
  架构产物能否"被执行验证"，取决于模拟器是否支持该架构。支持与否是
  环境属性，不是产品属性。若把它混进 R4b，i386 跑不起来会让整条 R4b
  永远 PENDING/BLOCKED，掩盖 arm64 与 arm 已经真跑过的事实；反过来
  若不记，又会让人误以为 i386 也已验证。

  判定方式是对照实验，不是猜：编一个同目标（x86-linux-musl 静态）的
  hello world 并在模拟器里跑。它能跑，说明 i386 产物具备被验证的条件；
  它跑不起来，说明是模拟器的限制 —— 此时 R4c 应为 BLOCKED（环境限制），
  而不是 PENDING（该验没验）或 VERIFIED。

退出码：0 = 模拟器可跑 i386；1 = 不能；2 = 无法判定（无模拟器/无 zig）
"""
import os
import subprocess
import sys

CACHE = "/tmp/i386_emu_probe.result"
WORK = "/tmp/i386_emu_probe"


def build_and_run():
    os.makedirs(WORK, exist_ok=True)
    src = os.path.join(WORK, "h.c")
    binp = os.path.join(WORK, "h_i386")
    if not (os.path.exists(src) and os.path.exists(binp)):
        open(src, "w").write('#include <stdio.h>\nint main(void){printf("C\\n");return 0;}\n')
        try:
            import ziglang
            zig = os.path.join(os.path.dirname(ziglang.__file__), "zig")
        except Exception:
            return 2
        r = subprocess.run([zig, "cc", "-target", "x86-linux-musl", "-static",
                            src, "-o", binp], capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            return 2
    try:
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
        ql = Qiling([binp], "/tmp/a64root_guard", verbose=QL_VERBOSE.OFF)
        ql.run()
        return 0 if ql.os.exit_code == 0 else 1
    except Exception:
        return 1


def main():
    if os.path.exists(CACHE):
        try:
            return int(open(CACHE).read().strip())
        except Exception:
            pass
    rc = build_and_run()
    try:
        open(CACHE, "w").write(str(rc))
    except Exception:
        pass
    return rc


if __name__ == "__main__":
    sys.exit(main())
