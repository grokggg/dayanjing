#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""守卫：两个结构化变异生成器不得各自持有探测基础设施的本地副本。

背景：gen_ch_struct.py 与 gen_cke_struct.py 此前逐字复制了 port_free /
next_free_port / probe_openssl / probe_openssl_retry / openssl_available /
记录层判定。危险不在重复本身，而在于：

    两处各自跑出的期望值都会固化进头文件。一旦有人只在一侧修了探测逻辑
    （端口重试、判据收紧、超时窗口），另一侧不跟着变，而两边仍然"全绿"
    —— 于是同一套真值体系里存在两套口径。固化下来的常量不会暴露这个分叉，
    它只会表现为"某个用例的期望值和另一组不一致"，那时没人知道该信哪个。

现在这些实现统一在 tls_truth.py。本脚本防止它们被复制回去。

为什么不用 grep 而用 ast：
    注释里提到 port_free 不算定义，被注释掉的 def 也不算。字符串匹配会把
    注释和历史说明判成违规，也会漏掉缩进在类/条件块里的真实定义。
"""
import ast
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHARED = "tls_truth.py"

# 必须在公共模块里，且不得出现在任何生成器里
MUST_BE_SHARED = ["port_free", "next_free_port", "probe_openssl",
                  "probe_openssl_retry", "classify_records",
                  "openssl_available"]

GENERATORS = ["gen_ch_struct.py", "gen_cke_struct.py"]


def top_defs(path):
    tree = ast.parse(open(path, encoding="utf-8").read())
    return {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}


def imported_modules(path):
    tree = ast.parse(open(path, encoding="utf-8").read())
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            out |= {a.name for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.module:
            out.add(n.module)
    return out


def main():
    bad = []

    sp = os.path.join(ROOT, "scripts", SHARED)
    have = top_defs(sp)
    for f in MUST_BE_SHARED:
        if f not in have:
            bad.append("%s 缺少 %s —— 公共模块不该被削薄" % (SHARED, f))

    for g in GENERATORS:
        gp = os.path.join(ROOT, "scripts", g)
        if not os.path.exists(gp):
            bad.append("%s 不存在" % g)
            continue
        defs = top_defs(gp)
        dup = sorted(set(MUST_BE_SHARED) & defs)
        if dup:
            bad.append("%s 持有本地副本 %s —— 改一处漏另一处会制造两套真值口径"
                       % (g, ", ".join(dup)))
        # 生成器必须真的 import 了公共模块。只删掉本地定义而不接公共模块，
        # 会在调用点 NameError —— 但那种失败发生在跑到那一例时，可能几十秒后。
        if "tls_truth" not in imported_modules(gp):
            bad.append("%s 未 import %s" % (g, SHARED))

    if bad:
        print("[FAIL] 探测基础设施出现重复实现")
        for b in bad:
            print("       %s" % b)
        return 1

    print("[PASS] 探测基础设施无重复：%d 个生成器共用 %s 的 %d 个实现"
          % (len(GENERATORS), SHARED, len(MUST_BE_SHARED)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
