#!/usr/bin/env python3
"""回归失败分类守卫：验证「环境故障」与「代码缺陷」被正确区分。

为什么需要它：
  SEQ:77 全仓回归跑到最后两个守卫步骤时 virtiofs 出现 Stale file handle，
  两步被记成 failed，汇总 49/4。事后四项全部定性为环境所致（单独重跑即绿），
  但代价是【核心链路没验完就交卷】：被吃掉的正是 21_exfil_guards
  （摄像头链路守卫）与 agent_windows_guards。

  修复把这类失败改为「立即中止 + 保留断点 + 退出码 3」。本守卫验证该判定：
  既不能把代码缺陷误认成环境故障（那回归永远跑不完），也不能把环境故障记成
  failed（那核心守卫等于没跑过）。

反向验证（缺了它本守卫就是恒绿）：
  R1 去掉环境签名识别 -> T1 必须【不再】中止，而是计入 failed。
"""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FC = os.path.join(ROOT, "scripts", "reg_failclass.sh")

PASS = 0
FAIL = 0


def check(ok, name, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("[OK]   %s%s" % (name, ("  " + detail) if detail else ""))
    else:
        FAIL += 1
        print("[FAIL] %s%s" % (name, ("  " + detail) if detail else ""))


def run_case(logs, fc_path):
    """在 sh 里 source 失败分类文件，执行一次 record_fail，返回 (rc, out)。"""
    args = " ".join("'%s'" % p for p in logs)
    script = (
        'failed=0\n'
        '. "%s" >/dev/null 2>&1 || exit 99\n'
        'record_fail %s\n'
        'echo "FAILED=$failed"\n' % (fc_path, args)
    )
    r = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=60)
    return r.returncode, (r.stdout + r.stderr)


def w(tmp, name, content):
    p = os.path.join(tmp, name)
    with open(p, "w") as f:
        f.write(content)
    return p


def main():
    if not os.path.isfile(FC):
        check(False, "F0 reg_failclass.sh 存在")
        return 1
    check(True, "F0 reg_failclass.sh 存在")

    tmp = tempfile.mkdtemp(prefix="fc_")

    # ---- T1：环境故障 -> 必须中止（退出码 3），且【不】计入 failed ----
    for sig in ["grep: x: Stale file handle",
                "sh: can't cd to /data/x: No such file",
                "cc: Read-only file system",
                "cp: error: Input/output error",
                "write: No space left on device"]:
        p = w(tmp, "t1.log", "[FAIL] something\n%s\n" % sig)
        rc, out = run_case([p], FC)
        check(rc == 3 and "FAILED=" not in out,
              "T1 环境故障被中止(%s)" % sig[:26], "rc=%d" % rc)
        check(rc != 0 and "ENV_ABORT" in out,
              "T1b 中止时打印可识别标记", "rc=%d" % rc)

    # ---- T2：真实代码缺陷 -> 必须计入 failed，且【不】中止 ----
    p = w(tmp, "t2.log", "FAIL: assert_eq(buf, expected)\n  at test_x.c:42\n")
    rc, out = run_case([p], FC)
    check(rc == 0 and "FAILED=1" in out, "T2 代码缺陷计入 failed", "rc=%d out=%r" % (rc, out.strip()))

    # ---- T3：无日志的真失败（如「未找到测试可执行文件」）不得被误判成环境 ----
    rc, out = run_case([], FC)
    check(rc == 0 and "FAILED=1" in out, "T3 无日志失败计入 failed", "rc=%d" % rc)

    # ---- T4：不存在的日志路径不得误判 ----
    rc, out = run_case([os.path.join(tmp, "nope.log")], FC)
    check(rc == 0 and "FAILED=1" in out, "T4 缺失日志计入 failed", "rc=%d" % rc)

    # ---- R1 反向：去掉签名识别后，T1 必须【不再】中止 ----
    src = open(FC).read()
    broken = src.replace(
        'if env_sig_hit "$@"; then',
        'if false; then', 1)
    if broken == src:
        check(False, "R1 反向注入点存在")
    else:
        bp = os.path.join(tmp, "broken.sh")
        with open(bp, "w") as f:
            f.write(broken)
        p = w(tmp, "r1.log", "[FAIL] x\ngrep: y: Stale file handle\n")
        rc, out = run_case([p], bp)
        check(rc == 0 and "FAILED=1" in out,
              "R1 反向：去掉识别后环境故障被误计为 failed（证明 T1 非恒绿）",
              "rc=%d out=%r" % (rc, out.strip()))

    # ---- F5：退出码 3 与「有 3 个代码缺陷」的 exit 3 撞车，必须可区分 ----
    # 不能靠数源码里 "exit 3" 的出现次数：注释里也会出现该字样，数文本会把
    # 「注释提了一句」判成「有两个出口」。改为行为断言：连续三次真实缺陷
    # 失败后 failed=3 且【无】ENV_ABORT 标记；环境中止时 rc=3 且【有】标记。
    p1 = w(tmp, "f1.log", "FAIL: a\n")
    p2 = w(tmp, "f2.log", "FAIL: b\n")
    script = ('failed=0\n. "%s" >/dev/null 2>&1 || exit 99\n'
              'record_fail "%s"\nrecord_fail "%s"\nrecord_fail "%s"\n'
              'echo "FAILED=$failed"\n' % (FC, p1, p2, p2))
    r = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=60)
    check("FAILED=3" in r.stdout and "ENV_ABORT" not in r.stdout,
          "F5 三次代码缺陷 -> failed=3 且无 ENV_ABORT", "out=%r" % r.stdout.strip())

    p3 = w(tmp, "f3.log", "FAIL: c\ngrep: z: Stale file handle\n")
    rc, out = run_case([p3], FC)
    check(rc == 3 and "ENV_ABORT" in out,
          "F5b 环境中止 -> rc=3 且带 ENV_ABORT（与 failed=3 可区分）", "rc=%d" % rc)

    print("---")
    print("PASS=%d FAIL=%d" % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
