#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cron 落点形态守卫：源码变异反向验证。

为什么必须做反向
----------------
test_persist_cron_impl.c 的 32 项断言全绿，只能说明"当前实现满足这些判据"。
若判据本身在某些实现下恒为真（例如探测函数无论输入都返回同一形态、权限
断言恰好被 umask 掩盖、切换场景压根没造出旧痕迹），全绿就是摆设 —— 而这
正是本仓反复出现过的失效形态。

故对 src/persist.c 施加三处变异，每处都必须让守卫变红：

  M1 "未知 -> 回退" 改回 "未知 -> cron.d"
     模拟的正是被修掉的缺陷本身。不变红则说明探测断言没有鉴别力。
  M2 回退分支去掉 chmod 0600
     真 Vixie cron 的加载判据是 (st_mode & 07777) != 0600 即拒绝。
     不变红说明权限断言可被 umask 等偶然因素掩盖。
  M3 卸载只清当前形态
     模拟"探测到 A 就只清 A"。不变红说明切换场景没真正造出旧痕迹，
     那条断言（本轮就是它抓出了实现漏洞）是恒绿的。

判据是"必须 fail > 0"，不是"必须 fail == N"：不同变异影响面不同，
钉死数量会让无关的实现调整误伤守卫。
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MOD = os.path.dirname(HERE)
SRC = os.path.join(MOD, "src", "persist.c")
TEST = os.path.join(MOD, "build", "test_persist_cron_impl")

MUTATIONS = [
    ("M1 未知发行版不再回退到 /etc/crontab",
     "    /* 未知：保守走通用路径 */\n    return CRON_IMPL_SYSCRONTAB;",
     "    /* 变异 */\n    return CRON_IMPL_CROND;"),
    ("M2 回退分支不做 chmod 0600",
     "        if (append_marker_line(path, MARKER, full) != 0) return -1;\n"
     "        chmod(path, 0600);",
     "        if (append_marker_line(path, MARKER, full) != 0) return -1;\n"
     "        /* 变异：不设权限 */"),
    ("M3 卸载只清当前探测到的形态",
     "        unlink(cd);\n"
     "        if (filter_out_marker(ct, MARKER) != 0) return -1;\n"
     "        if (needs_marker) return 0;      /* 当前形态即 crontab，已清 */",
     "        if (needs_marker) {\n"
     "            if (filter_out_marker(path, MARKER) != 0) return -1;\n"
     "            return 0;\n"
     "        }\n"
     "        unlink(cd);"),
]


def run_test():
    """返回 (pass, fail)。编译失败视为 fail=1。"""
    b = subprocess.run(["make", "-C", MOD, "build/test_persist_cron_impl"],
                       capture_output=True, text=True, timeout=180)
    if b.returncode != 0:
        return (0, 1)
    r = subprocess.run([TEST], capture_output=True, text=True, timeout=120)
    p = f = 0
    for line in r.stdout.splitlines():
        if line.strip().startswith("--- total=") and "pass=" in line:
            try:
                # 直接按字段名取，不要用 total - pass 反推：
                # 首版正是这么写的，把 pass 的值赋给了 fail，于是基线被判成
                # "pass=0 fail=32"，三条变异又因"pass>0"全部误判为通过 ——
                # 整个守卫的结论是反的，而输出看起来完全正常。
                p = int(line.split("pass=")[1].split(" ")[0])
                f = int(line.split("fail=")[1].split(" ")[0])
            except (ValueError, IndexError):
                pass
    return (p, f)


def main():
    orig = open(SRC).read()
    ok = 0
    bad = 0

    def report(name, cond, detail=""):
        nonlocal ok, bad
        if cond:
            ok += 1
            print("[OK]   %s %s" % (name, detail))
        else:
            bad += 1
            print("[FAIL] %s %s" % (name, detail))

    # 基线：还原态必须全绿
    open(SRC, "w").write(orig)
    os.utime(SRC, None)
    p, f = run_test()
    base_ok = (f == 0 and p > 0)
    report("B0 还原态守卫全绿", base_ok, "-- pass=%d fail=%d" % (p, f))

    for name, old, new in MUTATIONS:
        if old not in orig:
            report(name, False, "-- 变异锚点未命中，守卫失效")
            continue
        open(SRC, "w").write(orig.replace(old, new, 1))
        os.utime(SRC, None)
        p, f = run_test()
        report(name, f > 0, "-- 变异后 pass=%d fail=%d（必须 fail>0）" % (p, f))

    # 还原并复核
    open(SRC, "w").write(orig)
    os.utime(SRC, None)
    p, f = run_test()
    report("B1 还原后守卫恢复全绿", f == 0 and p > 0,
           "-- pass=%d fail=%d" % (p, f))

    print("=== cron 形态守卫: %d PASS / %d FAIL ===" % (ok, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
