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
# 模块可声明"由专用驱动执行的测试"，如 02_c2 的 test_align（需 Python 侧夹具）
RUN_BY_RE = re.compile(r'^\s*RUN_BY\s*:?=\s*(.*)$', re.M)

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


def run_by(mf: str):
    """{测试名: 驱动路径}——这些测试不由默认目标构建，而由专用脚本驱动。"""
    raw = open(mf, encoding='utf-8', errors='replace').read()
    mo = RUN_BY_RE.search(_join_continuations(raw))
    out = {}
    if mo:
        for item in mo.group(1).split():
            if '=' in item:
                k, v = item.split('=', 1)
                out[k.strip()] = v.strip()
    return out


def orphan_sources(md: str, mf: str):
    """tests/ 下存在、但 Makefile 从未引用的测试源码。

    这是与"跑陈旧产物"方向相反的缺口：被测二进制根本不存在，
    源码里的断言一次都没执行过。实测 02_c2/tests/test_align.c
    写了三年从未被编译——跨语言协议对齐无人把关。
    """
    tdir = os.path.join(md, 'tests')
    if not os.path.isdir(tdir):
        return []
    raw = open(mf, encoding='utf-8', errors='replace').read()
    src = _join_continuations(raw)
    orphans = []
    for f in sorted(os.listdir(tdir)):
        if not (f.startswith('test_') and f.endswith(('.c', '.cpp', '.cc'))):
            continue
        stem = os.path.splitext(f)[0]
        # \b 保证 test_c2 不会匹配到 test_c2_frame
        if not re.search(r'\b%s\b' % re.escape(stem), src):
            orphans.append('tests/' + f)
    return orphans


# test 目标配方中"真正被执行"的测试：行首必须是 ./，
# 即该程序是自己跑起来，而不是被当作前一个命令的参数。
# 反例（真实发生过）：./$(BUILD)/test_exfil_cover_circuit $(BUILD)/test_tol
#   -> test_tol 在文本里"出现过"，于是 orphan_sources 放行；
#      但它是被当参数传给一个根本不读 argv 的程序，28 个断言从未运行。
# 行内"命令位置"上的测试路径：允许 ./ 前缀，也允许 @ / timeout N / ENV=VAL 等前缀。
# 关键：只认命令位置，不认参数位置——
#   ./build/test_a build/test_b   -> 只算 test_a，test_b 是参数（真缺陷，实测发生过）
#   @timeout 300 build/test_front -> 算 test_front（24_front 的真实写法）
EXEC_PATH_RE = re.compile(
    r'^(?:\./)?(?:\$\([A-Za-z_]+\)|build)/\s*(test_[A-Za-z0-9_]+)$')

# 变量/循环执行形式：很多模块不逐个写 ./build/test_xxx，而是
#   ./$(TST_BIN)                      (01_proto)
#   for t in $(TESTS); do $$t; done   (25_tls)
#   for t in $(TEST_BINS); do ./$$t; done (agent_windows)
# 只认字面 ./build/test_xxx 会把这些模块整片误报成"从未执行"。
EXEC_VAR_RE = re.compile(r'\./\s*\$\(([A-Za-z_][A-Za-z0-9_]*)\)')
LOOP_VAR_RE = re.compile(r'for\s+\w+\s+in\s+\$\(([A-Za-z_][A-Za-z0-9_]*)\)')
# 循环体里对循环变量的真实调用：$t（shell）或 $$t（make 转义后即 $t）
LOOP_CALL_RE = re.compile(r'\$\$?\w+\b')


VAR_REF_RE = re.compile(r'\$\(([A-Za-z_][A-Za-z0-9_]*)\s*[:)]')


def var_defs(mf: str):
    """{变量名: 该变量值里出现的 test_* 名集合}。

    支持替换引用展开：agent_windows 写的是
        TESTS     := test_pipeline test_implant ...
        TEST_BINS := $(TESTS:%=$(BUILD)/%)
    TEST_BINS 的值里没有字面 test_* 名，必须回溯到 TESTS 才拿得到，
    否则整个模块会被误报成"从未执行"。
    """
    src = _join_continuations(open(mf, encoding='utf-8', errors='replace').read())
    out, refs = {}, {}
    for line in src.splitlines():
        mo = DECL_ASSIGN_RE.match(line)
        if not mo:
            continue
        vname = line.split(':', 1)[0].split('=', 1)[0].strip()
        val = mo.group(1)
        names = set(DECL_PATH_RE.findall(val))
        names |= set(DECL_BARE_RE.findall(val))
        out.setdefault(vname, set()).update(names)
        refs.setdefault(vname, set()).update(VAR_REF_RE.findall(val))
    # 传递闭包：$(A:%=...) 引用的变量，其测试名并入 A
    changed = True
    while changed:
        changed = False
        for v, rs in refs.items():
            for r in rs:
                add = out.get(r, set()) - out.get(v, set())
                if add:
                    out[v] = out.get(v, set()) | add
                    changed = True
    return out


def executed_vars(mf: str, goal: str = 'test'):
    """配方中以变量形式整体执行的变量名集合（含 for 循环遍历的变量）。"""
    lines = recipe_lines(mf, goal)
    joined = '\n'.join(lines)
    vs = set(EXEC_VAR_RE.findall(joined))
    looped = set(LOOP_VAR_RE.findall(joined))
    # 只有当循环体真的调用了循环变量，才算这个变量被"执行"
    if looped and LOOP_CALL_RE.search(joined):
        vs |= looped
    return vs


def recipe_lines(mf: str, goal: str = 'test'):
    """目标 goal 的配方行（已合并反斜杠续行）。"""
    src = _join_continuations(open(mf, encoding='utf-8', errors='replace').read())
    out, in_recipe = [], False
    target_re = re.compile(r'^%s\s*:' % re.escape(goal))
    for line in src.splitlines():
        if not line.strip():
            in_recipe = False
            continue
        if not line.startswith('\t'):
            in_recipe = bool(target_re.match(line))
            continue
        if in_recipe:
            out.append(line)
    return out


def cmd_token(line: str):
    """配方行里真正被执行的命令 token（剥掉 @ / - / timeout N / ENV=VAL 前缀）。"""
    s = line.strip().lstrip('@-').strip()
    toks = s.split()
    i = 0
    while i < len(toks):
        t = toks[i]
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', t):   # 环境变量赋值
            i += 1
            continue
        if t == 'timeout':                              # timeout [N] cmd...
            i += 1
            while i < len(toks) and re.match(r'^[0-9]+[smhd]?$|^-[a-zA-Z]$|^--', toks[i]):
                i += 1
            continue
        break
    return toks[i] if i < len(toks) else ''


def executed_in_recipe(mf: str, goal: str = 'test'):
    """配方里位于命令位置被真正执行的测试名集合。"""
    names = set()
    for line in recipe_lines(mf, goal):
        mo = EXEC_PATH_RE.match(cmd_token(line))
        if mo:
            names.add(mo.group(1))
    return names


def py_driven(tdir: str, stem: str):
    """tests/ 下的 .py 驱动是否真实调用了该二进制。

    反例（误报来源）：test_exfil_fidelity 不在 test 的 shell 配方里，
    而是由 verify-exfil-fidelity 目标的 python3 tests/verify_exfil_fidelity.py
    通过 subprocess.run([BIN, ...]) 执行。只看 shell 配方会把它误判为未执行。
    因此要求 .py 里同时出现该二进制名与真实子进程调用，避免宽松豁免。
    """
    call_re = re.compile(r'\b(subprocess\.(run|Popen|call|check_output|check_call)'
                         r'|os\.system|os\.popen)\b')
    for f in sorted(os.listdir(tdir)):
        if not f.endswith('.py'):
            continue
        try:
            body = open(os.path.join(tdir, f), encoding='utf-8',
                        errors='replace').read()
        except OSError:
            continue
        if re.search(r'\b%s\b' % re.escape(stem), body) and call_re.search(body):
            return True
    return False


def built_but_never_run(md: str, mf: str, goal: str = 'test'):
    """tests/ 下有源码、Makefile 也声明了，但配方从未 ./ 执行过的测试。

    与 orphan_sources 的区别：后者只查"名字是否被提到过"，
    因此"加了依赖/构建规则却没加执行"这种半截修复会静默通过——
    源码被编译进 build/，断言却一次都没跑。
    """
    tdir = os.path.join(md, 'tests')
    if not os.path.isdir(tdir):
        return []
    executed = executed_in_recipe(mf, goal)
    vdefs = var_defs(mf)
    var_covered = set()
    for v in executed_vars(mf, goal):
        var_covered |= vdefs.get(v, set())
    raw = _join_continuations(open(mf, encoding='utf-8', errors='replace').read())
    rb = run_by(mf)
    out = []
    for f in sorted(os.listdir(tdir)):
        if not (f.startswith('test_') and f.endswith(('.c', '.cpp', '.cc'))):
            continue
        stem = os.path.splitext(f)[0]
        # 未被声明构建的不归这里管（orphan_sources 已报）
        if not re.search(r'\b%s\b' % re.escape(stem), raw):
            continue
        if (stem in rb or stem in executed or stem in var_covered
                or py_driven(tdir, stem)):
            continue
        out.append('tests/' + f)
    return out


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
        # 由专用驱动执行的测试：不要求默认目标构建它，但驱动必须真实存在
        rb = run_by(mf)
        for t, drv in sorted(rb.items()):
            if not os.path.isfile(os.path.join(ROOT, drv)):
                bad += 1
                print(f'[MISS] {m}: RUN_BY 声明 {t} 由 {drv} 驱动，但该文件不存在')
        ext = set(rb)
        miss = sorted((decl - built) - ext)
        orph = orphan_binaries(md, decl)
        srcorph = orphan_sources(md, mf)
        if srcorph:
            bad += 1
            print(f'[MISS] {m}: {len(srcorph)} 个测试源码从未被 Makefile 引用，'
                  f'其断言从未执行: {srcorph}')
        neverrun = built_but_never_run(md, mf)
        if neverrun:
            # 不阻断：回归 run_c 的实际做法是 make（默认目标）后
            # find build/ -name 'test_*' -perm -u+x 逐个执行，不看 Makefile 配方。
            # 因此"配方没写执行"不影响回归覆盖——真正的覆盖判据是
            # "是否被默认目标构建进 build/"（上面 miss 检查已把关）。
            # 这里只提示：手动 make test 会漏跑，且配方与产物不一致是腐烂信号。
            print(f'[WARN] {m}: {len(neverrun)} 个测试未在 test 配方中执行'
                  f'（回归靠 find build/ 覆盖，不影响回归；但 make test 会漏）'
                  f': {neverrun}')
        gdesc = '默认目标' + (f' + {" ".join(audit_goals(mf))}' if len(goals) > 1 else '')
        if miss:
            bad += 1
            print(f'[MISS] {m}: 声明 {len(decl)} 个测试目标，'
                  f'{gdesc}只构建 {len(decl) - len(miss)} 个，缺 {len(miss)}: {miss}')
        elif orph:
            print(f'[WARN] {m}: 全部 {len(decl)} 个均会被构建；'
                  f'但 build/ 有 {len(orph)} 个已不再声明的残留: {orph}')
        else:
            extra = f'（另 {len(ext)} 个由专用驱动执行）' if ext else ''
            print(f'[OK  ] {m}: {len(decl)} 个测试目标全部由{gdesc}构建{extra}')
    print('---')
    print('MISS 模块数 =', bad)
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
