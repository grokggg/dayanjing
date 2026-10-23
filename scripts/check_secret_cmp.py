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

# 只扫产品代码；测试里的 memcmp 不参与（它们比较的是自己构造的期望值）
SRC_GLOBS = ("src", "include")


def norm(line):
    """规范化：去行首空白、去 // 注释、压掉连续空白。"""
    line = re.sub(r"//.*$", "", line).strip()
    return re.sub(r"\s+", " ", line)


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
            i = 0
            while i < len(lines):
                if "memcmp" in lines[i] and not lines[i].strip().startswith("*"):
                    buf, depth, j = lines[i], lines[i].count("(") - lines[i].count(")"), i
                    while depth > 0 and j + 1 < len(lines) and j - i < 3:
                        j += 1
                        buf += " " + lines[j]
                        depth = buf.count("(") - buf.count(")")
                    out.append((rel, i + 1, norm(buf)))
                    i = j + 1
                else:
                    i += 1
    return out


def main():
    args = sys.argv[1:]
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
        elif allow[key] == BANNED:
            banned.append((f, ln, text, allow[key]))
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

    if banned or unknown:
        print("[FAIL] 秘密比较守卫未通过")
        return 1
    print("[PASS] 全仓 memcmp 均已分类，且无秘密比较使用 memcmp")
    return 0


if __name__ == "__main__":
    sys.exit(main())
