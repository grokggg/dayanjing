#!/usr/bin/env python3
"""把 scripts/secret_cmp_allow.json 里的分类与证据写回源码注释。

用法：
    python3 scripts/annotate_secret_cmp.py          # 实际写入
    python3 scripts/annotate_secret_cmp.py --dry    # 只打印将要做的改动

为什么要写回源码：判据只存在 JSON 里，改代码的人看不到。重构时把某处
悄悄改回 memcmp，守卫会拦下，但他要花很久才搞懂为什么。注释就在调用点
上面，判据当场可见。

写入后由 check_secret_cmp.py 反向校验：注释分类必须与 allowlist 一致，
且不允许出现"注释还在、memcmp 已改"的孤儿注释。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_secret_cmp as G  # noqa: E402

ROOT = G.ROOT


def main():
    dry = "--dry" in sys.argv
    sites = G.scan()
    allow = __import__("json").load(open(G.ALLOW, encoding="utf-8"))

    # 按文件分组，一次读入一次写出
    todo = {}
    for f, ln, text in sites:
        key = "%s|%s" % (f, text)
        if key not in allow:
            continue
        c = G.cls(allow[key])
        if c == G.BANNED:
            # SECRET 点不该还是 memcmp；保留在 allowlist 里只为守卫报错
            continue
        reason = G.why(allow[key]) or G.REASON.get(c, "")
        todo.setdefault(f, []).append((ln, c, reason))

    n_new = n_fix = n_ok = 0
    touched = []
    for f in sorted(todo):
        path = os.path.join(ROOT, f)
        lines = open(path, encoding="utf-8").read().splitlines(keepends=True)
        # 从后往前改，避免插入导致行号位移
        for ln, c, reason in sorted(todo[f], key=lambda x: -x[0]):
            idx = ln - 1
            indent = " " * (len(lines[idx]) - len(lines[idx].lstrip()))
            want = "%s/* %s:%s: %s */\n" % (indent, G.MARK, c, reason)
            prev = lines[idx - 1].strip() if idx > 0 else ""
            if G.MARK in prev:
                if prev.split(G.MARK + ":", 1)[1].split(":")[0] == c:
                    n_ok += 1
                    continue
                lines[idx - 1] = want
                n_fix += 1
            else:
                lines.insert(idx, want)
                n_new += 1
        touched.append(f)
        if not dry:
            open(path, "w", encoding="utf-8").write("".join(lines))
        G._CACHE.pop(f, None)

    print("[INFO] 已分类调用点 %d 处（跨 %d 个文件）"
          % (sum(len(v) for v in todo.values()), len(todo)))
    print("[INFO] 新增注释 %d，修正分类不一致 %d，已一致 %d" % (n_new, n_fix, n_ok))
    if dry:
        print("[INFO] --dry：未写入任何文件")
    else:
        for f in touched:
            print("       写入 %s" % f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
