#!/usr/bin/env python3
"""
测试捕获能力审计（audit_test_power.py）
=====================================

要解决的问题
------------
"551/551 全过" 和 "0 条断言" 在报告上没有区别，如果一个模块的测试
恒真（断言自洽、假设与实现共享同一个错误），它永远全绿，也永远
证明不了任何东西。

本脚本不审计产品代码，审计的是**测试本身有没有能力失败**。

方法
----
机械化语义反转：把产品代码里某个 `if (cond)` 改成 `if (0)`，
使该分支永不执行。这必然改变程序行为（除非该分支本来就恒假，
而那本身就是缺陷，被报出来也有价值）。

- 测试变红  -> CAPTURED，说明测试真的在测这条路径
- 测试仍全绿 -> SURVIVED，该变异未被任何断言覆盖
- 一个模块 K 次变异全部 SURVIVED -> BLIND，该模块数字不可信

变异选择不依赖对代码的理解（只看括号匹配），因此可规模化到全仓，
避免"只变异我恰好想到的那几处"造成的选择偏差。

硬规则
------
1. 编译失败的变异不计入 SURVIVED（它不是"测不出"，是"没跑起来"）。
2. 变异必须还原：用备份文件 + finally，异常也还原。
3. 还原后必须校验 git 干净，否则中止并大声报错——
   留着变异的代码比不审计危险得多。
4. 空测试集合不算通过：一个测试二进制都跑不到即判 BLIND。

用法
----
    python3 scripts/audit_test_power.py --dry MODULE        # 只看会变异什么
    python3 scripts/audit_test_power.py --mod 24_front -k 3  # 真跑
"""

import os
import re
import sys
import json
import shutil
import random
import hashlib
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BAK_SUFFIX = ".tpbak"


def strip_comments(src):
    """把注释与字符串字面量替换成空格，保持长度不变（偏移可直接用于原文）。"""
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n - 2 if j < 0 else j
            for k in range(i, j + 2):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 2
        elif src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif src[i] in "\"'":
            q = src[i]
            i += 1
            while i < n and src[i] != q:
                if src[i] == "\\":
                    i += 1
                i += 1
            i += 1
        else:
            i += 1
    return "".join(out)


def find_ifs(src):
    """返回 [(if起始, '('下标, ')'下标, 条件文本)]，按出现顺序。"""
    st = strip_comments(src)
    res = []
    for m in re.finditer(r"\bif\s*\(", st):
        if m.start() > 0 and st[m.start() - 1] == "#":
            continue  # 预处理指令
        open_i = m.end() - 1
        depth, end = 0, None
        for k in range(open_i, len(st)):
            if st[k] == "(":
                depth += 1
            elif st[k] == ")":
                depth -= 1
                if depth == 0:
                    end = k
                    break
        if end is None:
            continue
        cond = st[open_i + 1:end].strip()
        if not cond or len(cond) > 300:
            continue
        # 跳过宏定义续行等异常形态
        if "\n" in cond and not cond.startswith("\n"):
            cond_one = " ".join(cond.split())
        else:
            cond_one = " ".join(cond.split())
        res.append((m.start(), open_i, end, cond_one))
    return res


def product_sources(mod):
    """模块产品源码（排除 tests/、build/、include/）。"""
    d = os.path.join(ROOT, mod, "src")
    if not os.path.isdir(d):
        return []
    out = []
    for root, dirs, files in os.walk(d):
        dirs[:] = [x for x in dirs if x not in ("build", ".git")]
        for f in sorted(files):
            if f.endswith((".c", ".cpp", ".cc")):
                out.append(os.path.join(root, f))
    return out


def inject(path, item):
    """把某个 if (cond) 改成 if (0)，返回 True/False。"""
    start, open_i, end, cond = item
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        src = fh.read()
    if not os.path.exists(path + BAK_SUFFIX):
        shutil.copy2(path, path + BAK_SUFFIX)
    new = src[:start] + "if (0)" + src[end + 1:]
    if new == src:
        return False
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(new)
    os.utime(path, None)
    return True


def restore(path):
    """还原文件，并**必须刷新 mtime**。

    shutil.move 保留备份的时间戳，于是还原后 .c 的 mtime 回到变异之前，
    比变异期间编译出的 .o 更旧 —— make 判定"产物最新"而跳过重编译，
    build/ 里就永久留着一份变异版目标文件。后续所有测试都在跑变异体，
    而源码看起来是干净的。这正是本脚本要抓的那类事故，却由自己制造。
    """
    bak = path + BAK_SUFFIX
    if os.path.exists(bak):
        shutil.move(bak, path)
        os.utime(path, None)


def file_sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def heal_leftovers(mods):
    """启动自愈：清理上一次被强杀留下的变异残留。

    为什么要它：本脚本用备份文件 + finally 保证还原，但 finally 挡不住
    SIGKILL / 沙盒 502 直接杀进程。实测发生过：进程被杀后 front.c 停在
    变异态、.tpbak 留在树上，而下一次 make 会拿变异源码去编——审计工具
    自己把被测物改坏了，且没有任何报错。

    所以还原不能只依赖"本次运行善终"，必须在每次启动时先扫一遍：
    发现 .tpbak 就立刻还原并刷新 mtime（刷新理由见 restore 的注释）。
    """
    healed = []
    for mod in mods:
        mdir = os.path.join(ROOT, mod)
        for dirpath, _dirs, files in os.walk(mdir):
            for fn in files:
                if fn.endswith(BAK_SUFFIX):
                    path = os.path.join(dirpath, fn[: -len(BAK_SUFFIX)])
                    bak = path + BAK_SUFFIX
                    shutil.move(bak, path)
                    os.utime(path, None)
                    healed.append(os.path.relpath(path, ROOT))
    if healed:
        print("[HEAL] 发现并还原残留变异（上次运行被强杀）：")
        for h in healed:
            print("       %s" % h)
        print("[HEAL] 已刷新 mtime；相关产物需在下次构建时重编")
    return healed


def run_module_tests(mod, timeout=600):
    """重建该模块并跑 build/ 下所有测试二进制。返回 (是否全部通过, 跑了几个, 详情)。

    rc=77 是 SKIP（缺夹具等），既不算通过也不算失败；但若一个模块里
    所有测试都 SKIP，则视为空集合——"没测"不能冒充"测了"。
    """
    mdir = os.path.join(ROOT, mod)
    env = dict(os.environ)
    env["HF_CASES"] = os.path.join(ROOT, "24_front", "tests", "data", "hf_cases.txt")
    try:
        b = subprocess.run(["make", "-C", mdir], capture_output=True,
                           text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return None, 0, ["make 超时"]
    if b.returncode != 0:
        return None, 0, ["make 失败(编译错误，不计入)"]

    bdir = os.path.join(mdir, "build")
    bins = []
    if os.path.isdir(bdir):
        for f in sorted(os.listdir(bdir)):
            p = os.path.join(bdir, f)
            if f.startswith("test_") and os.path.isfile(p) and os.access(p, os.X_OK):
                bins.append(p)
    if not bins:
        return None, 0, ["build/ 下无可执行测试（空集合不算通过）"]

    ran, fails, skips, hangs, detail = 0, 0, 0, 0, []
    for p in bins:
        try:
            r = subprocess.run([p], capture_output=True, text=True,
                               timeout=45, env=env)
        except subprocess.TimeoutExpired:
            # 变异让测试挂住了：行为确实变了，但断言没能给出结论。
            # 单列为 HANG，绝不计入 SURVIVED（那是"测试没能力"，两回事）。
            hangs += 1
            detail.append("%s HANG(>45s)" % os.path.basename(p))
            ran += 1
            continue
        ran += 1
        if r.returncode == 77:
            skips += 1
            detail.append("%s SKIP(77)" % os.path.basename(p))
            continue
        if r.returncode != 0:
            fails += 1
            head = ""
            for ln in (r.stdout + r.stderr).splitlines():
                if "FAIL" in ln or "fail" in ln:
                    head = ln.strip()
                    break
            detail.append("%s rc=%d %s" % (os.path.basename(p), r.returncode, head[:90]))
    if skips and skips == ran:
        return None, ran, ["全部 %d 个测试均 SKIP(77)" % skips]
    return (fails == 0 and hangs == 0), ran, detail


def git_dirty():
    """只关心**已跟踪**文件是否被改动。

    用 status 会把本脚本自身这类未跟踪的新文件算成"未还原"，
    上一版就因此误报 FATAL——误报多了会被习惯性忽略，等于没有守卫。
    """
    r = subprocess.run(["git", "-C", ROOT, "diff", "--name-only"],
                       capture_output=True, text=True)
    return [l for l in r.stdout.splitlines() if l.strip()]


def main():
    args = sys.argv[1:]
    dry = "--dry" in args
    k = 3
    if "-k" in args:
        k = int(args[args.index("-k") + 1])
    mods = []
    if "--mod" in args:
        mods = args[args.index("--mod") + 1].split(",")
    seed = 20261024
    if "--seed" in args:
        seed = int(args[args.index("--seed") + 1])

    if not mods:
        print("[ERR] 需指定 --mod MOD[,MOD...]")
        return 2

    random.seed(seed)
    report = {}

    # 先自愈，再动手：避免把上一次强杀留下的变异当成当前基线
    heal_leftovers(mods)

    for mod in mods:
        srcs = product_sources(mod)
        if not srcs:
            print("[MISS] %s 无产品源码" % mod)
            report[mod] = {"status": "MISS"}
            continue

        cands = []
        for s in srcs:
            try:
                with open(s, "r", encoding="utf-8", errors="replace") as fh:
                    src = fh.read()
            except OSError:
                continue
            for it in find_ifs(src):
                cands.append((s, it))
        if not cands:
            print("[MISS] %s 无可变异的 if" % mod)
            report[mod] = {"status": "MISS"}
            continue

        print("=== %s：候选 if %d 处，抽样 %d ===" % (mod, len(cands), k))
        if dry:
            pick = random.sample(cands, min(k, len(cands)))
            for s, it in pick:
                print("  %s:%s\n      if (%s)" % (
                    os.path.relpath(s, ROOT),
                    src_offset_line(s, it[0]), it[3][:100]))
            continue

        # 基线：未变异时必须全过
        ok, ran, detail = run_module_tests(mod)
        if ok is not True:
            print("[BASE-FAIL] %s 基线未通过，跳过（先修基线）: %s"
                  % (mod, "; ".join(detail[:3])))
            report[mod] = {"status": "BASE_FAIL", "detail": detail[:5]}
            continue
        print("  基线 PASS（%d 个测试二进制）" % ran)

        pick = random.sample(cands, min(k, len(cands)))
        captured = survived = compiled_fail = 0
        orig = {}          # 被变异文件 -> 变异前的 sha256
        for s, it in pick:
            rel = os.path.relpath(s, ROOT)
            orig.setdefault(s, file_sha(s))
            try:
                if not inject(s, it):
                    continue
                ok2, ran2, detail2 = run_module_tests(mod)
                if ok2 is None:
                    compiled_fail += 1
                    print("  [SKIP-编译] %s  if (%s)" % (rel, it[3][:60]))
                elif ok2 is False:
                    captured += 1
                    print("  [CAPTURED] %s  if (%s)" % (rel, it[3][:60]))
                    for d in detail2[:2]:
                        print("        %s" % d)
                else:
                    survived += 1
                    print("  [SURVIVED] %s  if (%s)  <-- 无任何断言覆盖"
                          % (rel, it[3][:60]))
            finally:
                restore(s)

        # 还原判据：只看**被变异过的文件**是否回到变异前的字节。
        # 不能用"整个 git 树干净"——工作区里常有本轮合法的未提交改动，
        # 那样会把合法改动误报成 FATAL；而 FATAL 会让本次报告直接不落盘，
        # 误报多了又会像其他守卫一样被习惯性忽略。
        bad = []
        for s, h in orig.items():
            rel = os.path.relpath(s, ROOT)
            if os.path.exists(s + BAK_SUFFIX):
                bad.append("%s（残留备份 .tpbak）" % rel)
            elif file_sha(s) != h:
                bad.append("%s（内容未回到变异前）" % rel)
        if bad:
            print("[FATAL] %s 变异未完全还原！" % mod)
            for l in bad[:5]:
                print("   " + l)
            return 1

        status = "CAPTURED" if captured else ("BLIND" if survived else "SKIP")
        print("  -> %s: 捕获%d 存活%d 编译跳过%d [%s]"
              % (mod, captured, survived, compiled_fail, status))
        report[mod] = {"status": status, "captured": captured,
                       "survived": survived, "compile_skip": compiled_fail}

    if not dry:
        with open(os.path.join(ROOT, "scripts", "test_power_report.json"), "w") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        blind = [m for m, v in report.items() if v.get("status") == "BLIND"]
        if blind:
            print("\n[结论] 以下模块测试无捕获能力：%s" % ", ".join(blind))
            return 1
    return 0


def src_offset_line(path, off):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()[:off].count("\n") + 1
    except OSError:
        return "?"


if __name__ == "__main__":
    sys.exit(main())
