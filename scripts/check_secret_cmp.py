#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
全仓 memcmp 分类守卫 —— 把"哪些比较必须是常量时间"变成可复跑判据。

为什么需要它（M9 的教训推广）：

    M9/M13/M14/M15 只钉住了 crypto_constant_time_eq 这一个函数本身。
    但真正的风险面是【调用点】：任何人随时可以在别处写一行
    memcmp(tag, expected, n)，功能完全正确、所有测试全绿，却引入
    逐字节早退的时序预言机。源码级插桩看不见它（那个函数根本没被
    调用），机器码守卫也看不见它（它审的是 crypto_constant_time_eq
    的函数体，不是别人的调用点）。

    所以必须有一层【调用点】审计：枚举全仓每一处 memcmp，要求每一处
    都被显式分类。未分类 -> 失败。分类为 SECRET -> 失败（必须改用
    crypto_constant_time_eq）。这样将来新增任何一处 memcmp 都会被
    拦下并要求人工判定，而不是悄悄混进去。

判据来源：
    scripts/secret_cmp_allow.json —— { "文件|规范化行": 分类 }

    分类取值：
      PUBLIC     公开常量（magic / 协议标识 / HTTP 头名），无秘密可言
      ID         节点 ID 等公开标识符（随报文明文传输，不是秘密）
      ORDER      需要符号结果的大小比较，memcmp 不可替代
      PATTERN    内存/报文中搜索模式串（pat / NEEDLE），非比较秘密
      DEGENERATE 检查两个自有密钥是否退化相等（两边都是自己的密钥，
                 比较结果不依赖外部输入），可接受
      SECRET     【禁止】比较秘密/认证值，必须改用 crypto_constant_time_eq

    规范化行：去掉行首空白与注释后的代码文本。用文本而非行号做键，
    是因为行号会随任何编辑漂移，而跑偏的行号会让守卫静默失效 ——
    一个指向错误位置的守卫比没有守卫更危险。
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALLOW = os.path.join(ROOT, "scripts", "secret_cmp_allow.json")
BANNED = "SECRET"

# 源码里标注判据的标记。值必须与 allowlist 的分类一致，由本脚本校验。
# 判据只存在于 JSON 时，改代码的人看不到，重构时容易把某个 SECRET 点
# 悄悄改回 memcmp 而不知道为什么被拦 —— 所以注释必须由脚本强制同步。
MARK = "SEC-CMP"

# 各分类的默认理由。具体调用点若有更强的证据，用 --why 覆盖。
REASON = {
    "PUBLIC": "双方均为公开数据（传输中可见或可自行计算），无秘密可泄露",
    "ID": "标识符相等性判定，非秘密凭证；攻击者无法提交猜测来探测",
    "DEGENERATE": "退化比较（判两方是否相等以拒绝同值输入），结果调用方本就已知，不构成预言",
    "ORDER": "排序/规范序比较，仅泄露 1 比特顺序；比较对象为自有或公开 ID",
    "PATTERN": "内存模式/特征扫描，非秘密比较",
    "SECRET": "秘密或认证判据，必须改用 crypto_constant_time_eq",
}

# 只扫产品代码；测试里的 memcmp 不参与（它们比较的是自己构造的期望值）
SRC_GLOBS = ("src", "include")

_CACHE = {}


def cls(v):
    """allowlist 的值可为分类字符串，也可为 {"class":..,"why":..}。"""
    if isinstance(v, dict):
        return v.get("class", "")
    return v if isinstance(v, str) else ""


def why(v):
    return v.get("why", "") if isinstance(v, dict) else ""


def _lines(rel):
    """带缓存地读取仓库内相对路径。"""
    if rel not in _CACHE:
        _CACHE[rel] = open(os.path.join(ROOT, rel), encoding="utf-8",
                           errors="replace").read().splitlines()
    return _CACHE[rel]


def mark_at(rel, idx):
    """返回第 idx 行（0 基）上方那条注释里的分类；无则 None。"""
    try:
        lines = _lines(rel)
    except Exception:
        return None
    j = idx - 1
    while j >= 0:
        s = lines[j].strip()
        if s.startswith("/*") and MARK in s:
            for tok in s.replace("/*", " ").replace("*/", " ").split():
                if tok.startswith(MARK + ":"):
                    return tok.split(":", 2)[1].split(":")[0]
            return None
        if s == "" or s.startswith("/*") or s.startswith("*"):
            j -= 1
            continue
        return None
    return None


def orphan_marks():
    """扫 src/include 里所有标注，返回不属于任何 memcmp 调用点的孤儿。"""
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames
                       if d not in ("build", ".git", "__pycache__", "tests")]
        if not any(p in dirpath.split(os.sep) for p in SRC_GLOBS):
            continue
        for fn in filenames:
            if not fn.endswith((".c", ".h", ".cpp")):
                continue
            rel = os.path.relpath(os.path.join(dirpath, fn), ROOT)
            try:
                lines = _lines(rel)
            except Exception:
                continue
            for i, ln in enumerate(lines):
                # 必须是真正的标注 "SEC-CMP:<CLASS>:"；正文里提到
                # "不在 SEC-CMP 扫描范围" 这类说明不算标注，否则会被判成孤儿。
                if (MARK + ":") in ln and "/*" in ln:
                    nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
                    # 标注必须紧邻它说明的那条比较语句
                    if "memcmp" not in nxt and "constant_time_eq" not in nxt:
                        out.append((rel, i + 1, ln.strip()[:120]))
    return out


def norm(line):
    """规范化：去行首空白、去 // 注释、压掉连续空白。"""
    line = re.sub(r"//.*$", "", line).strip()
    return re.sub(r"\s+", " ", line)


def strip_block_comments(lines):
    """
    返回与 lines 等长的"仅代码"文本列表，块注释内容替换为空格（保行号）。

    必需：扫描器此前按整行子串匹配 "memcmp"，于是一句写了解释的比较代码
    只要注释里出现 "非 memcmp" 就会被当成调用点；同理 "已改用 crypto_ct_cmp"
    这类说明也会制造假阳性。判据必须只看真正会被编译的代码。
    """
    out = []
    in_blk = False
    for ln in lines:
        res = []
        i = 0
        while i < len(ln):
            if in_blk:
                if ln.startswith("*/", i):
                    res.append("  ")
                    i += 2
                    in_blk = False
                else:
                    res.append(" " if ln[i] != "\t" else "\t")
                    i += 1
            elif ln.startswith("/*", i):
                res.append("  ")
                i += 2
                in_blk = True
            elif ln.startswith("//", i):
                break
            else:
                res.append(ln[i])
                i += 1
        out.append("".join(res))
    return out


def scan():
    """返回 [(file, lineno, normline)]，含跨行调用（括号未闭合则续读）。"""
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames
                       if d not in ("build", ".git", "__pycache__", "tests")]
        if not any(p in dirpath.split(os.sep) for p in SRC_GLOBS):
            continue
        for fn in filenames:
            if not fn.endswith((".c", ".h", ".cpp")):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, ROOT)
            try:
                lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
            except Exception:
                continue
            # 只在"代码文本"里找 memcmp；注释里的字样不算调用点
            code = strip_block_comments(lines)
            i = 0
            while i < len(lines):
                if "memcmp" in code[i]:
                    buf, depth, j = code[i], code[i].count("(") - code[i].count(")"), i
                    while depth > 0 and j + 1 < len(lines) and j - i < 3:
                        j += 1
                        buf += " " + code[j]
                        depth = buf.count("(") - buf.count(")")
                    out.append((rel, i + 1, norm(buf)))
                    i = j + 1
                else:
                    i += 1
    return out


def main():
    global ROOT, ALLOW
    argv = sys.argv[1:]
    # --root <dir> / --allow <json>：把扫描根与判据表参数化，供 fixture 复用。
    # 默认行为与加参数前逐字相同（不传即走仓库根与 scripts/secret_cmp_allow.json）。
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--root", "--allow") and i + 1 < len(argv):
            if a == "--root":
                ROOT = os.path.abspath(argv[i + 1])
            else:
                ALLOW = os.path.abspath(argv[i + 1])
            i += 2
            continue
        break
    args = argv[i:]
    sites = scan()
    try:
        allow = json.load(open(ALLOW, encoding="utf-8"))
    except Exception:
        allow = {}

    # --classify 文件:行号=分类 [...] —— 用行号定位（编辑当下稳定），
    # 落盘时仍转成"文件|规范化行"键。行号会漂移，所以只在分类这一刻用它。
    if "--classify" in args:
        specs = []
        i = args.index("--classify") + 1
        while i < len(args) and not args[i].startswith("--"):
            specs.append(args[i])
            i += 1
        byline = {(f, ln): "%s|%s" % (f, text) for f, ln, text in sites}
        n = 0
        for sp in specs:
            try:
                loc, cat = sp.split("=", 1)
                f, ln = loc.rsplit(":", 1)
                key = byline[(f, int(ln))]
            except Exception:
                print("[FAIL] 无法定位 %s（行号不存在或格式非 文件:行号=分类）" % sp)
                return 2
            allow[key] = cat
            n += 1
        json.dump(allow, open(ALLOW, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2, sort_keys=True)
        print("[INFO] 已写入 %d 条分类（allowlist 现有 %d 条）" % (n, len(allow)))
        return 0

    # --why 文件:行号=理由 —— 给某条分类附上具体证据（覆盖该分类的默认理由）
    if "--why" in args:
        specs = []
        i = args.index("--why") + 1
        while i < len(args) and not args[i].startswith("--"):
            specs.append(args[i])
            i += 1
        byline = {(f, ln): "%s|%s" % (f, text) for f, ln, text in sites}
        n = 0
        for sp in specs:
            try:
                loc, reason = sp.split("=", 1)
                f, ln = loc.rsplit(":", 1)
                key = byline[(f, int(ln))]
            except Exception:
                print("[FAIL] 无法定位 %s" % sp)
                return 2
            c = cls(allow.get(key))
            if not c:
                print("[FAIL] %s 尚未分类，先 --classify 再 --why" % sp)
                return 2
            allow[key] = {"class": c, "why": reason}
            n += 1
        json.dump(allow, open(ALLOW, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2, sort_keys=True)
        print("[INFO] 已写入 %d 条证据（allowlist 现有 %d 条）" % (n, len(allow)))
        return 0

    if "--prune" in args:
        seen = {"%s|%s" % (f, t) for f, _, t in sites}
        before = len(allow)
        allow = {k: v for k, v in allow.items() if k in seen}
        json.dump(allow, open(ALLOW, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2, sort_keys=True)
        print("[INFO] 清理失效条目 %d 条（%d -> %d）" % (before - len(allow), before, len(allow)))
        return 0

    unknown, banned, stale = [], [], []
    seen = set()
    for f, ln, text in sites:
        key = "%s|%s" % (f, text)
        seen.add(key)
        if key not in allow:
            unknown.append((f, ln, text))
        elif cls(allow[key]) == BANNED:
            banned.append((f, ln, text, cls(allow[key])))
    for k in allow:
        if k not in seen:
            stale.append(k)

    print("[INFO] 扫描到 memcmp 调用点 %d 处（产品代码）" % len(sites))
    print("[INFO] 已分类 %d 处" % (len(sites) - len(unknown)))

    # 同一文件内出现完全相同的规范化行时，两个调用点共用一个键 ——
    # 若它们的分类不同，后者会静默覆盖前者。必须显式暴露，不能让它悄悄发生。
    multi = {}
    for f, ln, text in sites:
        multi.setdefault("%s|%s" % (f, text), []).append(ln)
    coll = {k: v for k, v in multi.items() if len(v) > 1}
    if coll:
        print("[WARN] %d 个键对应多处调用点（它们只能共用一个分类）：" % len(coll))
        for k, v in sorted(coll.items()):
            print("       行 %s" % ", ".join(str(x) for x in v))
            print("         %s" % k[:150])

    if stale:
        print("[WARN] %d 条 allowlist 条目已失效（对应 memcmp 已不存在）：" % len(stale))
        for k in stale:
            print("       %s" % k)

    if banned:
        print("[FAIL] %d 处被判定为秘密比较，必须改用 crypto_constant_time_eq：" % len(banned))
        for f, ln, text, _ in banned:
            print("       %s:%d" % (f, ln))
            print("         %s" % text[:150])
    if unknown:
        print("[FAIL] %d 处 memcmp 未分类（新增调用点必须人工判定）：" % len(unknown))
        for f, ln, text in unknown:
            print("       %s:%d" % (f, ln))
            print("         %s" % text[:150])
        print("[HINT] 判定后写入 scripts/secret_cmp_allow.json；"
              "若比较的是秘密/认证值，分类填 SECRET 并把代码改成 crypto_constant_time_eq")

    # 源码注释与 allowlist 必须一致：判据要写在改代码的人看得见的地方。
    annot_bad, annot_miss = [], []
    for f, ln, text in sites:
        key = "%s|%s" % (f, text)
        if key not in allow:
            continue
        want = cls(allow[key])
        got = mark_at(f, ln - 1)
        if got is None:
            annot_miss.append((f, ln, want))
        elif got != want:
            annot_bad.append((f, ln, want, got))
    orph = orphan_marks()

    if annot_miss:
        print("[FAIL] %d 处已分类调用点缺少源码判据注释：" % len(annot_miss))
        for f, ln, want in annot_miss[:10]:
            print("       %s:%d (分类 %s)" % (f, ln, want))
        print("[HINT] 运行 scripts/annotate_secret_cmp.py 写入")
    if annot_bad:
        print("[FAIL] %d 处源码注释分类与 allowlist 不一致：" % len(annot_bad))
        for f, ln, want, got in annot_bad[:10]:
            print("       %s:%d allowlist=%s 注释=%s" % (f, ln, want, got))
    if orph:
        print("[FAIL] %d 条判据注释已失去对应调用点（代码改了但注释留着）：" % len(orph))
        for f, ln, t in orph[:10]:
            print("       %s:%d  %s" % (f, ln, t))

    if banned or unknown or annot_bad or annot_miss or orph:
        print("[FAIL] 秘密比较守卫未通过")
        return 1
    print("[PASS] 全仓 memcmp 均已分类、无秘密比较、判据注释与 allowlist 一致")
    return 0


if __name__ == "__main__":
    sys.exit(main())
