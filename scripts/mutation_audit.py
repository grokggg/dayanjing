#!/usr/bin/env python3
"""
变异审计：把"此前声称已修复"的缺陷逐个变异回退，验证测试是否真能捕获。

存活(survived) = 测试仍全绿 = 该用例证明不了任何事 = 真实缺口。
捕获(caught)   = 测试失败   = 修复真的被防回归保护住了。
"""
import os, shutil, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MUTATIONS = [
    {
        "id": "M1",
        "desc": "25_deploy: 关闭组装摘要校验（篡改的制品也能 seal）",
        "file": "25_deploy/src/drop.c",
        "old": "if (crypto_constant_time_eq(d, a->digest, DP_DIGEST_LEN) == 0)",
        "new": "if (0)",
        "mod": "25_deploy",
        "bin": "build/test_drop",
    },
    {
        "id": "M2",
        "desc": "19_defense: ptrace 回退为在调用进程自身执行（自伤）",
        "file": "19_defense/src/debug.c",
        "old": "pid = fork();",
        "new": "pid = 0;",
        "mod": "19_defense",
        "bin": "build/test_defense",
    },
    {
        "id": "M3",
        "desc": "20_packer: 入口 nop 垫恒为 0（首字节变回恒定签名）",
        "file": "20_packer/src/poly.c",
        "old": "int npad = (int)rnd(p, 3);",
        "new": "int npad = 0;",
        "mod": "20_packer",
        "bin": "build/test_poly",
        "all_occurrences": True,
    },
]


def sh(cmd, cwd, timeout=600):
    try:
        p = subprocess.run(cmd, shell=True, cwd=cwd, timeout=timeout,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return -999, "TIMEOUT"


def build(mod):
    d = os.path.join(ROOT, mod)
    rc, out = sh("make clean >/dev/null 2>&1; make -s 2>&1 | tail -5", d, 900)
    return rc, out


def main():
    results = []
    for m in MUTATIONS:
        path = os.path.join(ROOT, m["file"])
        if not os.path.exists(path):
            results.append((m["id"], "SKIP", "文件不存在"))
            continue
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()
        if m["old"] not in src:
            results.append((m["id"], "SKIP", "未找到变异锚点"))
            continue

        bak = path + ".mutbak"
        shutil.copy2(path, bak)
        try:
            if m.get("all_occurrences"):
                mutated = src.replace(m["old"], m["new"])
            else:
                mutated = src.replace(m["old"], m["new"], 1)
            with open(path, "w", encoding="utf-8") as f:
                f.write(mutated)

            rc, out = build(m["mod"])
            if rc != 0:
                results.append((m["id"], "BUILD_FAIL", out.strip()[:200]))
                continue

            binpath = os.path.join(ROOT, m["mod"], m["bin"])
            if not os.path.exists(binpath):
                results.append((m["id"], "SKIP", "测试二进制不存在: " + m["bin"]))
                continue
            trc, tout = sh("./" + m["bin"], os.path.join(ROOT, m["mod"]), 300)
            if trc == 0:
                results.append((m["id"], "SURVIVED", "测试仍全绿 —— 该缺陷无法被捕获"))
            else:
                fails = [l for l in tout.splitlines() if "FAIL" in l]
                results.append((m["id"], "CAUGHT",
                                "失败 %d 项, 例: %s" % (len(fails), fails[0][:90] if fails else "rc=%d" % trc)))
        finally:
            shutil.move(bak, path)
            build(m["mod"])

    print("\n=== 变异审计结果 ===")
    for rid, verdict, detail in results:
        print("[%-8s] %s : %s" % (rid, verdict, detail))
    survived = [r for r in results if r[1] == "SURVIVED"]
    print("\n存活(证明不了任何事) = %d / %d" % (len(survived), len(results)))


if __name__ == "__main__":
    main()
