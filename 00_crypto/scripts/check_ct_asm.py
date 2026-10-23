#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
常量时间比较的【机器码级】守卫。

为什么需要它（这不是锦上添花）：

    mutation_audit 的 M13/M14/M15 能捕获【源码级】早退 —— 它们改的是
    C 源码，插桩计数会发现步数 < len。但那测的是源码语义，不是最终
    机器码。编译器理论上仍可把一个"无副作用"的累积循环优化成早退
    （例如识别出 diff 一旦非零则结果已定，插入条件跳出）。那一层
    源码测试【永远测不到】，只能审查汇编。

    本脚本把那次人工审查固化为可复跑的判据：反汇编生产构建中的
    crypto_constant_time_eq，统计条件跳转。

判据：

    正确实现在 -O2 下应恰好有 2 条条件跳转：
      1) 函数开头 len == 0 的守卫（与输入内容无关）
      2) 循环回边，且只比较 i != len

    任何与 diff 相关的控制流都会引入第 3 条。早退（break/return/
    循环条件带 !diff）无论源码怎么写，落到机器码上都必然多出一条
    条件跳转 —— 这正是源码级测试之外那一层的保障。

    反向也重要：若某天编译器改变代码布局导致这里不是 2 条，脚本会
    失败并要求人工复查，而不是悄悄放过。宁可因编译器升级而红灯，
    也不能让"早退已覆盖"的说法建立在一个无人再检查的一次性观察上。

防假通过（与审计脚本同源的教训）：

    - 断言循环回边确实存在（否则函数可能被优化成完全不同的形式，
      跳转数为 0，条件"<= 2"平凡成立 -> 假通过）。
    - 断言 diff 的累积指令（or）确实存在（否则函数可能已被彻底改写）。
    - 只用生产目标文件（build/crypto_gcm.o），不涉 CRYPTO_CT_INSTRUMENT，
      因为要看的就是生产路径的机器码。

用法：

    python3 scripts/check_ct_asm.py
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OBJ = ROOT / "build" / "crypto_gcm.o"
SYM = "crypto_constant_time_eq"

# 条件跳转助记符（x86-64）。jmp 是无条件跳转，不算。
COND_JMP = re.compile(
    r"^\s*j(?:a|ae|b|be|c|e|g|ge|l|le|na|nae|nb|nbe|nc|ne|ng|nge|nl|nle|no|np|ns|nz|o|p|pe|po|s|z)\s"
)
BACK_JMP = re.compile(r"^\s*j(?:mp|[a-z]{1,3})\s+[0-9a-f]+\s+<" + SYM + r"\+0x([0-9a-f]+)>")
ANY_JMP = re.compile(r"^\s*j(?:mp|[a-z]{1,3})\s")
OR_INSN = re.compile(r"^\s*or\s")


def die(msg: str) -> "None":
    print(f"[FAIL] {msg}")
    sys.exit(1)


def main() -> int:
    if not OBJ.exists():
        die(f"生产目标文件不存在: {OBJ}（先 make build/crypto_gcm.o）")

    out = subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn", str(OBJ)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    # 提取该函数的指令体：从 "<sym>:" 之后到下一个符号标签或空段结束。
    lines = out.splitlines()
    body: list[str] = []
    inside = False
    for ln in lines:
        if f"<{SYM}>:" in ln:
            inside = True
            continue
        if inside:
            if re.match(r"^[0-9a-f]+ <", ln):  # 下一个符号
                break
            body.append(ln)

    if not body:
        die(f"未能在 {OBJ} 中定位 <{SYM}>: —— 函数可能被内联或改名，判据已失效")

    # 取指令助记符部分
    insns = []
    for ln in body:
        m = re.match(r"^\s*[0-9a-f]+:\s*(.*)$", ln)
        if m:
            insns.append(m.group(1).strip())

    conds = [i for i in insns if COND_JMP.match(i)]
    anyj = [i for i in insns if ANY_JMP.match(i)]
    has_or = any(OR_INSN.match(i) for i in insns)

    print(f"[INFO] 目标文件: {OBJ}")
    print(f"[INFO] 函数体指令数: {len(insns)}")
    print(f"[INFO] 条件跳转数: {len(conds)}")
    for c in conds:
        print(f"[INFO]   {c}")
    print(f"[INFO] 含 or（diff 累积）: {has_or}")

    # 全部问题收集后统一报告，而不是命中第一条就退出。
    #
    # 原因（实测得来）：早退变异下 GCC 会把 `diff |= x; if (diff) break;`
    # 改写掉，结果【or 指令也消失了】。若先判 has_or，报的是"判据失效"
    # 而掩盖了"条件跳转数 2 -> 3"这条最直接的诊断。两者都可能是同一
    # 个根因的两面，必须一起看到。
    problems: list[str] = []

    # 防假通过：函数必须真的还是那个"累积 + 循环"的形态。
    if not anyj:
        problems.append("函数体内没有任何跳转 —— 循环去哪了？判据已失效")
    if not has_or:
        problems.append("函数体内没有 or 指令 —— diff 累积去哪了？")

    # 回边必须存在：否则"<= 2"会因函数被改写为顺序代码而平凡成立。
    addrs = []
    for ln in body:
        m = re.match(r"^\s*([0-9a-f]+):\s*(.*)$", ln)
        if m:
            addrs.append((m.group(1), m.group(2).strip()))
    addr_of = {}
    order = []
    for a, i in addrs:
        addr_of[a] = len(order)
        order.append(a)

    back_edge = False
    for a, i in addrs:
        m = re.search(r"<" + SYM + r"\+0x([0-9a-f]+)>", i)
        if m and ANY_JMP.match(i):
            tgt_off = int(m.group(1), 16)
            cur_off = int(a, 16) - int(order[0], 16)
            if tgt_off < cur_off:  # 向后跳 = 回边 = 存在循环
                back_edge = True
    if not back_edge:
        problems.append("未发现向后跳转（回边）—— 循环不存在，判据已失效")

    if len(conds) != 2:
        problems.append(
            f"条件跳转数为 {len(conds)}，期望 2（len==0 守卫 + 循环回边）"
        )

    if problems:
        print("[FAIL] 机器码级常量时间检查未通过：")
        for p in problems:
            print(f"       - {p}")
        print(
            "       多出的条件跳转通常意味着出现了与 diff 相关的控制流（早退）。\n"
            "       也可能是编译器版本变化改变了代码布局 —— 两种情况都必须人工\n"
            "       复查，不可直接放宽阈值。这是本脚本存在的意义：把一次性的人工\n"
            "       审查变成每次都能复跑的判据。"
        )
        return 1

    print("[PASS] 机器码级：循环体内无与 diff 相关的控制流（无早退路径）")
    print("[PASS] 机器码级：回边仅依赖 i != len，diff 从不参与分支判断")
    return 0


if __name__ == "__main__":
    sys.exit(main())
