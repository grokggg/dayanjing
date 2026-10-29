#!/usr/bin/env python3
"""红线巡检自检：证明状态机三态可判别，不是恒绿。

三条注入，方向各异：
  G1 移除 R4 证据（能力仍在）  -> 必须报 PENDING（环境具备却无证据）
  G2 放回非空证据              -> 必须转 VERIFIED 且退出 0
  G3 证据文件为 0 字节         -> 必须仍报 PENDING（空文件不算证据）
  G4 恢复原始证据              -> 必须回到基线，且一份不丢

【本轮修掉的两个真缺陷 —— 都是自检自身的问题】

1) G1 的注入从未真正生效。
   旧实现往 PATH 塞一个伪造的 aarch64-linux-gnu-gcc，而 R4 的探测是
   `python3 -c 'import ziglang' || ls artifacts/...`，**根本不看 PATH**。
   R4 翻转成 VERIFIED 之前，探测恒失败 -> 恒 BLOCKED，G1 期望的 PENDING
   从来没出现过；之所以多年"通过"，是因为当时 R4 状态恰好满足断言的
   另一半。改成真实生效的注入：直接移走证据文件（能力不变），这才精确
   命中"环境具备却无证据"这个语义。

2) 自检会**销毁真实证据**。
   旧实现把 R4.evidence 覆盖成占位文字、清空、最后 `os.remove` 删除 ——
   被删的是上一轮真实实跑留下的证据（1588 字节），而输出里写的是
   "G4 清理后回到基线""证据目录已清空"，看起来像打扫卫生。实测证据目录
   少了 R4.evidence，且巡检因此永久多一条 PENDING。
   自检绝不能碰真实产物：改为先整体备份、再用副本操作、结束逐份还原并
   断言一份不差。
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(ROOT, "redline_check.py")
EV = os.path.join(ROOT, "evidence")
SUBJECT = "R4"

PASS = 0
FAIL = 0


def ck(name, ok, detail=""):
    global PASS, FAIL
    PASS += 1 if ok else 0
    FAIL += 0 if ok else 1
    print("[%s] %s %s" % ("OK" if ok else "FAIL", name, detail))


def run_check(env=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    p = subprocess.run([sys.executable, "-u", CHECK], capture_output=True,
                       text=True, env=e, timeout=120)
    return p.returncode, p.stdout


def has_pending(out):
    """按状态行判定，不是按关键字子串。

    【历史 bug】曾写 `"PENDING" not in out` —— 而 R4c 的说明文字里正好有
    "不是 PENDING，更不是 VERIFIED" 这句话，子串匹配必然命中，于是
    "无 PENDING" 的断言永远失败（或反过来永远成立，取决于断言方向）。
    这与之前"grep 出 PENDING 其实是帮助文本"是同一个坑。必须按行首状态判定。
    """
    return any(l.startswith("[PENDING") for l in out.split("\n"))


def state_of(out, rid):
    for l in out.split("\n"):
        if l.startswith("[") and (" %s " % rid) in l:
            return l.strip()
    for l in out.split("\n"):
        if l.startswith("[") and rid in l.split()[1:2]:
            return l.strip()
    return ""


def main():
    # ---- 备份：自检期间绝不丢失任何真实证据 ----
    backup = tempfile.mkdtemp(prefix="rlbak_")
    ev_path = os.path.join(EV, "%s.evidence" % SUBJECT)
    had_real = os.path.exists(ev_path)
    if had_real:
        shutil.copy2(ev_path, os.path.join(backup, os.path.basename(ev_path)))

    # 基线：当前真实状态
    rc0, out0 = run_check()
    ck("G0 基线无 PENDING", rc0 == 0 and not has_pending(out0), "rc=%s" % rc0)

    base_line = state_of(out0, SUBJECT)
    ck("G0b 基线下 %s 确实具备能力且已有证据" % SUBJECT,
       "VERIFIED" in base_line, base_line)

    # ---- G1: 移走证据（能力不变） -> 必须 PENDING ----
    if os.path.exists(ev_path):
        os.remove(ev_path)
    rc1, out1 = run_check()
    l1 = state_of(out1, SUBJECT)
    ck("G1 移除证据（能力仍在）-> %s 报 PENDING" % SUBJECT,
       "PENDING" in l1, l1)
    ck("G1 整体退出码为 1（报警）", rc1 == 1, "rc=%s" % rc1)

    # ---- G2: 放回非空证据 -> VERIFIED ----
    with open(ev_path, "w") as f:
        f.write("%s 证据占位（自检用，非空）\n" % SUBJECT)
    rc2, out2 = run_check()
    ck("G2 有证据 -> %s 转 VERIFIED" % SUBJECT,
       "VERIFIED" in state_of(out2, SUBJECT), state_of(out2, SUBJECT))
    ck("G2 整体退出码回 0", rc2 == 0, "rc=%s" % rc2)

    # ---- G3: 空文件不算证据 -> 仍 PENDING ----
    open(ev_path, "w").close()
    rc3, out3 = run_check()
    ck("G3 空证据文件 -> 仍 PENDING",
       "PENDING" in state_of(out3, SUBJECT), state_of(out3, SUBJECT))
    ck("G3 整体退出码为 1", rc3 == 1, "rc=%s" % rc3)

    # ---- G4: 逐份还原，一份不差 ----
    if had_real:
        shutil.copy2(os.path.join(backup, os.path.basename(ev_path)), ev_path)
    elif os.path.exists(ev_path):
        os.remove(ev_path)
    rc4, out4 = run_check()
    ck("G4 还原后回到基线（无 PENDING）",
       rc4 == 0 and not has_pending(out4), "rc=%s" % rc4)
    if had_real:
        same = os.path.exists(ev_path) and os.path.getsize(ev_path) > 0
        ck("G4b 真实证据已还原且非空", same,
           "size=%d" % (os.path.getsize(ev_path) if os.path.exists(ev_path) else -1))
    shutil.rmtree(backup, ignore_errors=True)

    print("\ntotal=%d pass=%d fail=%d" % (PASS + FAIL, PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
