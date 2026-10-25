#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""元守卫：给 Python 侧守卫本身做正反双向防回归。

为什么需要这一层：

    check_gen_dedup.py 与 check_secret_cmp.py 是仓库里唯二【没有测试的
    Python 守卫】。C 侧每个断言都有 mutation_audit 里的变异条目盯着，
    它们没有 —— 于是唯一的失效模式无人看管：

        守卫自己被改坏 -> 恒返回"通过" -> 报告一片全绿 -> 无人察觉。

    这和 C 侧"测试假设掩盖缺陷"是同一类，只是更隐蔽：守卫的价值恰恰在于
    "在正确的时候变红"，而一个恒绿的守卫看起来和健康的守卫一模一样。

判据是【双向】的，缺一不可：

    合规 fixture -> 必须 PASS（证明守卫不会误报，否则它会被人当成噪音关掉）
    违规 fixture -> 必须 FAIL（证明守卫真的在履职，这是唯一有价值的那一侧）

    只验合规侧 = 恒绿守卫照样通过；只验违规侧 = 一个对所有输入都报 FAIL
    的守卫也算通过。两侧都验，"恒绿"与"恒红"都会被抓到。

fixture 在 scripts/tests/fixtures/ 下，是最小自洽样本：
    dedup_ok / dedup_bad         —— 生成器是否复制回公共探测实现
    secretcmp_ok / secretcmp_bad —— memcmp 是否被判为秘密比较
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "scripts", "tests", "fixtures")

PY = sys.executable or "python3"


def run(cmd):
    p = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
    out = p.stdout.decode("utf-8", "replace")
    return p.returncode, out


def main():
    # 子守卫若崩了（语法错误、ImportError、参数写错），退出码同样是 1 ——
    # 与"履职报 FAIL"在退出码上无法区分。靠输出标记区分：正常跑完的子守卫
    # 必然打印 [PASS] 或 [FAIL]，两者都没有说明它没跑到判定就死了。
    #
    # 不区分的后果：元守卫腐坏后，变异审计会把"它崩了"记成"它抓到了变异"，
    # 于是审计报告一片 CAUGHT，而实际什么都没验。
    def crashed(out):
        return "[PASS]" not in out and "[FAIL]" not in out

    cases = [
        # (守卫名, 命令, 期望退出码)
        ("check_gen_dedup  真实仓库",
         [PY, "scripts/check_gen_dedup.py"], 0),
        ("check_gen_dedup  合规 fixture（必须 PASS）",
         [PY, "scripts/check_gen_dedup.py", "--dir",
          "scripts/tests/fixtures/dedup_ok"], 0),
        ("check_gen_dedup  违规 fixture（必须 FAIL）",
         [PY, "scripts/check_gen_dedup.py", "--dir",
          "scripts/tests/fixtures/dedup_bad"], 1),

        ("check_secret_cmp 真实仓库",
         [PY, "scripts/check_secret_cmp.py"], 0),
        ("check_secret_cmp 合规 fixture（必须 PASS）",
         [PY, "scripts/check_secret_cmp.py", "--root",
          "scripts/tests/fixtures/secretcmp_ok", "--allow",
          "scripts/tests/fixtures/secretcmp_ok/allow.json"], 0),
        ("check_secret_cmp 违规 fixture（必须 FAIL）",
         [PY, "scripts/check_secret_cmp.py", "--root",
          "scripts/tests/fixtures/secretcmp_bad", "--allow",
          "scripts/tests/fixtures/secretcmp_bad/allow.json"], 1),
    ]

    bad = []
    for name, cmd, want in cases:
        rc, out = run(cmd)
        if crashed(out):
            print("[FATAL] 子守卫未产出判定标记（崩溃或参数错误），命令：%s"
                  % " ".join(cmd))
            print("       %s" % out.strip().splitlines()[-1][:160]
                  if out.strip() else "       （无输出）")
            return 1
        if rc != want:
            bad.append("%s -> 期望退出码 %d，实测 %d" % (name, want, rc))
            for ln in out.strip().splitlines()[:6]:
                bad.append("       %s" % ln)

    if bad:
        print("[FAIL] Python 侧守卫自身失效（恒绿或恒红）")
        for b in bad:
            print("       %s" % b)
        return 1

    print("[PASS] Python 侧守卫双向有效：%d 个方向（合规须 PASS / 违规须 FAIL）"
          % len(cases))
    return 0


if __name__ == "__main__":
    sys.exit(main())
