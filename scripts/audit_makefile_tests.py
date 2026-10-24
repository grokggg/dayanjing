#!/usr/bin/env python3
"""审计：每个模块声明的测试二进制，是否都会被默认目标（make）构建出来。

为什么需要这一层
----------------
回归脚本 run_all_tests.sh 的做法是：先 `make`，再执行 build/ 下所有 test_*。
于是成立一个隐含契约——

    make 必须产出回归会跑的每一个测试二进制。

契约一旦破坏，build/ 里留下的上一次 `make test` 的旧二进制会被继续跑：
源码改了、旧产物没重建、报告照样全绿。实测三处：

    08_lateral  all 只产出 liblateral.a    -> 清空 build 后 make 产出 0 个测试
    14_p2p      all 只产出 2/16             -> 14 个套件在跑陈旧产物
    21_exfil    all 漏 test_tol

这是"假通过"里最难发现的一类：它不是断言写错，而是被测物与源码脱节，
且仅在 build/ 恰好有旧文件时成立——干净检出时反而会暴露（0 个测试被判 FAIL）。

判定方法
--------
不读 Makefile 猜，而是让 make 自己算：对默认目标执行 `make -n -B`（-B 强制
重算全图，-n 只打印不执行），从打印出的命令里抽取 `-o <path>`，凡 basename
以 test_ 开头的即为"默认目标会构建"的集合。与 Makefile 中声明的测试目标
集合做差集。

用法
----
    python3 scripts/audit_makefile_tests.py          # 全部模块
    python3 scripts/audit_makefile_tests.py 14_p2p   # 指定模块

退出码：0 = 无缺失；1 = 存在缺失（应视为回归失败）。
"""

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 路径形式：$(BUILD)/test_xxx、$(SHIM_BUILD)/test_xxx、build/test_xxx
DECL_PATH_RE = re.compile(r'(?:\$\([A-Za-z_]+\)|build)/\s*(test_[A-Za-z0-9_]+)')
# 变量形式：TESTS := test_a test_b ...（agent_windows 用这种写法，
# 只认路径形式会让整个模块被审计跳过——是审计自身的盲区）
DECL_ASSIGN_RE = re.compile(r'^\s*[A-Z][A-Z0-9_]*\s*:?=\s*(.*)$')
DECL_BARE_RE = re.compile(r'\b(test_[A-Za-z0-9_]+)\b(?!\.)')
# 模块可声明"回归实际会调用的其他目标"，如 agent_windows 的 winshim-build
AUDIT_GOALS_RE = re.compile(r'^\s*AUDIT_GOALS\s*:?=\s*(.*)$', re.M)

BUILT_RE = re.compile(r'-o\s+(\S+)')


def _join_continuations(text: str) -> str:
    """把反斜杠续行合并成一行，否则跨行的变量定义只能读到第一段。"""
    out, buf = [], ''
    for line in text.splitlines():
        if line.rstrip().endswith('\\'):
            buf += line.rstrip()[:-1] + ' '
        else:
            out.append(buf + line)
            buf = ''
    if buf:
        out.append(buf)
    return '\n'.join(out)


def declared_tests(mf: str):
    """Makefile 中声明过的测试目标名（basename）。"""
    raw = open(mf, encoding='utf-8', errors='replace').read()
    src = _join_continuations(raw)
    names = {m.group(1) for m in DECL_PATH_RE.finditer(src)}
    for line in src.splitlines():
        mo = DECL_ASSIGN_RE.match(line)
        if mo and not mo.group(1).startswith('$('):
            names |= set(DECL_BARE_RE.findall(mo.group(1)))
    return names


def audit_goals(mf: str):
    raw = open(mf, encoding='utf-8', errors='replace').read()
    mo = AUDIT_GOALS_RE.search(_join_continuations(raw))
    return mo.group(1).split() if mo else []


def built_by_goals(md: str, goals, timeout: int = 300):
    """make 在给定目标上实际会构建出的测试二进制 basename 集合。"""
    out = set()
    for g in goals:
        try:
            p = subprocess.run(['make', '-n', '-B'] + ([g] if g else []), cwd=md,
                               capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return None, f'TIMEOUT({g or "default"})'
        except OSError as e:
            return None, str(e)
        if p.returncode != 0:
            return None, f'make -n {g or "default"} rc={p.returncode}'
        for m in BUILT_RE.finditer(p.stdout):
            b = os.path.basename(m.group(1))
            if b.startswith('test_'):
                out.add(b)
    return out, 'OK'


def orphan_binaries(md: str, declared):
    """build/ 里存在、但 Makefile 已不再声明的测试二进制（陈旧残留）。"""
    orphans = []
    for dirpath, _dirs, files in os.walk(os.path.join(md, 'build')):
        for f in files:
            if f.startswith('test_') and not f.endswith(('.c', '.o')):
                if f not in declared:
                    orphans.append(os.path.relpath(os.path.join(dirpath, f), md))
    return sorted(orphans)


def main():
    args = sys.argv[1:]
    mods = args if args else sorted(
        d for d in os.listdir(ROOT)
        if os.path.isfile(os.path.join(ROOT, d, 'Makefile'))
        and os.path.isdir(os.path.join(ROOT, d))
    )
    bad = 0
    for m in mods:
        md = os.path.join(ROOT, m)
        mf = os.path.join(md, 'Makefile')
        if not os.path.isfile(mf):
            continue
        decl = declared_tests(mf)
        if not decl:
            continue
        goals = [None] + audit_goals(mf)
        built, st = built_by_goals(md, goals)
        if built is None:
            print(f'[ERR ] {m}: {st}')
            bad += 1
            continue
        miss = sorted(decl - built)
        orph = orphan_binaries(md, decl)
        gdesc = '默认目标' + (f' + {" ".join(audit_goals(mf))}' if len(goals) > 1 else '')
        if miss:
            bad += 1
            print(f'[MISS] {m}: 声明 {len(decl)} 个测试目标，'
                  f'{gdesc}只构建 {len(decl) - len(miss)} 个，缺 {len(miss)}: {miss}')
        elif orph:
            print(f'[WARN] {m}: 全部 {len(decl)} 个均会被构建；'
                  f'但 build/ 有 {len(orph)} 个已不再声明的残留: {orph}')
        else:
            print(f'[OK  ] {m}: {len(decl)} 个测试目标全部由{gdesc}构建')
    print('---')
    print('MISS 模块数 =', bad)
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
