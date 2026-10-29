#!/usr/bin/env python3
"""为红线证据打源码指纹戳。

证据若只记"跑过什么"，改了源码之后它照样显示 VERIFIED ——
那份证据对应的是旧代码，却冒充新代码的状态。

用法：
  python3 redline/stamp.py <redline-id>            打印该红线的 SRC 行
  python3 redline/stamp.py <redline-id> --append <证据文件>
                                                   追加到已有证据末尾

本脚本只做两件事：算当前源码的 SHA256、写成 SRC 行。
它不生成证据内容 —— 证据正文必须由真实执行产生。
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from redline_check import REDLINES, REPO  # noqa: E402


def src_lines(rid):
    rl = next((x for x in REDLINES if x["id"] == rid), None)
    if rl is None:
        raise SystemExit("未知红线: %s" % rid)
    out = []
    for rel in rl.get("sources", []):
        fp = os.path.join(REPO, rel)
        if not os.path.isfile(fp):
            raise SystemExit("绑定源不存在: %s" % rel)
        raw = open(fp, "rb").read()
        out.append("SRC %s %s %d" % (rel, hashlib.sha256(raw).hexdigest(), len(raw)))
    return out


def main():
    args = [a for a in sys.argv[1:]]
    if not args:
        raise SystemExit(__doc__)
    rid = args[0]
    lines = src_lines(rid)
    if "--append" in args:
        ev = args[args.index("--append") + 1]
        with open(ev, "a") as f:
            f.write("\n# ---- 源码指纹（改了下列任一文件，本证据即失效）----\n")
            for l in lines:
                f.write(l + "\n")
        print("[stamp] 已追加 %d 条 SRC 到 %s" % (len(lines), ev))
    else:
        for l in lines:
            print(l)


if __name__ == "__main__":
    main()
