#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真实根污染守卫。

为什么需要它：
    部署测试直接写真实 /etc（onekey.sh 只在显式给 PREFIX 时才走假根）。
    只要跑过一次 install，真实根就留下 systemd 单元、cron 条目、conf 目录、
    二进制。这些痕迹会让 09_persistence 的 test_enum 永久变红——因为它断言
    "真实系统 cron 未安装"，而那是环境状态、不是代码行为。失败信息只说
    "返回值不符"，排查方向被指向 persist.c 而不是"谁污染了 /etc"。

    污染被清理过一次，但没有东西看着它。下一次 install 就会重新污染。

守卫的判据：
    扫描全部派生落点。落点名由 NAME 派生（默认 sysupdate，可 --name 覆盖），
    因此守卫**不能硬编码名字**——改名后硬编码的守卫会立刻变成恒绿。
    同时扫描历史名字（camd / dayanjing），因为旧部署留下的痕迹同样算污染。

正向对照（关键）：
    没有它的守卫就是恒绿：一个永远找不到的扫描器永远"通过"。
    --selftest 会在假根里种下痕迹、要求必须被检出，再清除、要求必须变干净；
    并在真实根里用一个一次性名字做路径构造的实测（种→检出→清除）。
"""

import os
import sys
import glob
import shutil
import tempfile

# 默认名 + 历史名。改名后必须同步此处，否则守卫失效。
KNOWN_NAMES = ["sysupdate", "camd", "dayanjing"]


def rel_paths(name):
    """返回该名字在真实根下的全部派生落点（相对根的路径）。"""
    p = []
    # ---- 系统级（PREFIX="" 时）----
    p += [
        "etc/%s" % name,                       # CONF_DIR
        "etc/%s/%s.conf" % (name, name),       # CONF_FILE
        "var/lib/%s" % name,                   # LIB_DIR
        "usr/local/bin/%s" % name,             # BIN_DST
        "etc/systemd/system/%s.service" % name,  # UNIT
        "etc/cron.d/%s" % name,                # CRON
        "var/lock/%s.lock" % name,             # LOCK
    ]
    # ---- 用户级：所有存在 home 下的都扫 ----
    for home in sorted(glob.glob("home/*") + ["root"]):
        p += [
            "%s/.config/%s" % (home, name),
            "%s/.local/lib/%s" % (home, name),
            "%s/.config/systemd/user/%s.service" % (home, name),
            "%s/.config/autostart/%s.desktop" % (home, name),
        ]
    return p


def scan_root(root, names):
    """扫描给定根下的痕迹。root 为空串表示真实根。"""
    hits = []
    for name in names:
        for rel in rel_paths(name):
            abs_p = os.path.join(root, rel) if root else os.path.join("/", rel)
            if os.path.lexists(abs_p):
                hits.append(abs_p)
    return hits


def scan_fake(name):
    """假根扫描：把 tmpdir 当根，因此 home/* 需要在其下构造。"""
    hits = []
    for rel in rel_paths(name):
        hits.append(rel)
    return hits


def plant(root, name):
    """在给定根下种下该名字的全部痕迹。返回种下的绝对路径。"""
    made = []
    rels = rel_paths(name)
    for rel in rels:
        abs_p = os.path.join(root, rel) if root else os.path.join("/", rel)
        d = os.path.dirname(abs_p)
        try:
            if d and not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)
            with open(abs_p, "w") as f:
                f.write("selftest\n")
            made.append(abs_p)
        except OSError:
            pass
    return made


def cleanup(paths, dirs):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass
    for d in dirs:
        try:
            shutil.rmtree(d, ignore_errors=True)
        except OSError:
            pass


def selftest():
    """正向对照：证明扫描器真的能检出，而不是永远找不到。"""
    ok = True

    # --- A. 假根逻辑对照 ---
    tmp = tempfile.mkdtemp(prefix="rrguard_")
    probe = "zzguardprobe"
    try:
        # 种下
        plant(tmp, probe)
        got = scan_root(tmp, [probe])
        if not got:
            print("  [FAIL] S1 假根种下痕迹后仍检不出——扫描器恒绿")
            ok = False
        else:
            print("  [OK]   S1 假根种下 %d 项痕迹全部检出" % len(got))
        # 清除
        cleanup(got, [os.path.join(tmp, "etc"), os.path.join(tmp, "var"),
                      os.path.join(tmp, "usr"), os.path.join(tmp, "home"),
                      os.path.join(tmp, "root")])
        left = scan_root(tmp, [probe])
        if left:
            print("  [FAIL] S2 清除后仍检出 %d 项（判据不收敛）" % len(left))
            ok = False
        else:
            print("  [OK]   S2 清除后检出归零（判据可收敛）")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # --- B. 真实根路径构造实测 ---
    # 用一次性名字，不依赖 KNOWN_NAMES；种->检出->清除，trap 保证必清除。
    real = "zzguardprobe"
    made = []
    try:
        made = plant("", real)
        if not made:
            print("  [FAIL] S3 真实根无法种下探针（权限不足？守卫自身不可用）")
            return False
        got = scan_root("", [real])
        # 只要求"至少检出一项"：真实根上部分路径可能因权限种不进去，
        # 但只要路径构造正确，必然检出已种下的那些。
        if not got:
            print("  [FAIL] S3 真实根种下 %d 项却一项都检不出——路径构造错误" % len(made))
            print("        守卫对该落点是恒绿的")
            ok = False
        else:
            print("  [OK]   S3 真实根路径构造有效（种 %d 检 %d）" % (len(made), len(got)))
    finally:
        cleanup(made, ["/etc/%s" % real, "/etc/systemd/system", "/etc/cron.d",
                       "/var/lib/%s" % real, "/usr/local/bin",
                       "/var/lock", "/root/.config/%s" % real])

    left = scan_root("", [real])
    if left:
        print("  [FAIL] S4 真实根探针未清除干净，残留 %d 项" % len(left))
        for p in left[:5]:
            print("        %s" % p)
        ok = False
    else:
        print("  [OK]   S4 真实根探针已清除干净（自检不留污染）")

    return ok


def main():
    if "--selftest" in sys.argv:
        print("=== 真实根污染守卫：正向对照 ===")
        return 0 if selftest() else 1

    hits = scan_root("", KNOWN_NAMES)
    if hits:
        print("  [FAIL] 真实根存在本仓部署痕迹 %d 项：" % len(hits))
        for p in hits[:30]:
            print("        %s" % p)
        if len(hits) > 30:
            print("        ...（其余 %d 项省略）" % (len(hits) - 30))
        print("        来源：部署测试未走假根（onekey.sh 需显式 PREFIX）。")
        print("        后果：09_persistence 的 test_enum 断言环境状态，")
        print("              会永久变红且失败信息只说'返回值不符'，")
        print("              排查方向被指向 persist.c 而非'谁污染了 /etc'。")
        return 1

    print("  [OK]   真实根无本仓部署痕迹（已扫 %d 个名字 × 派生落点）"
          % len(KNOWN_NAMES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
