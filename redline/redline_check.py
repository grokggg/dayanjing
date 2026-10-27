#!/usr/bin/env python3
"""红线巡检：把"从未验证"从文档文字变成持续被检查的状态。

三条状态，语义严格区分：
  BLOCKED   环境不具备 -> 不可验证，是硬限制，不是偷懒
  PENDING   环境具备但没有证据 -> 这才是必须报警的，伪造最容易发生在这里
  VERIFIED  环境具备且有证据文件 -> 结论可引用

本脚本只判定状态，不替任何人生成证据。
证据必须是真实实跑的输出，由人放到 evidence/ 下。
"""
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(ROOT)
EV = os.path.join(ROOT, "evidence")


def run(cmd):
    try:
        # 历史 bug：此处曾写 r["probe"] —— r 是未定义变量，抛 NameError 被
        # 下面的 except 吞掉并返回 -1，于是**所有红线恒判 BLOCKED**：
        # PENDING 永远 0，"环境具备却未验证必须报警"这个防伪造机制从未工作。
        # 参数名就是 cmd，直接用它。
        cmd = cmd.replace("{REPO}", REPO)
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as e:
        return -1, str(e)


# 每条红线：环境探测 + 一旦具备应跑的验证 + 证据文件名
REDLINES = [
    {
        "id": "R1",
        "name": "V4L2 真设备采集",
        "why": "整条链唯一没有流过真实像素的环节；全程 mock 合成帧",
        # 注意：/sys/class/video4linux 目录可能"存在但为空"，ls 空目录返回 0，
        # 会误判成环境具备。必须用 grep -q . 要求有实际条目。
        "probe": "ls /dev/video* >/dev/null 2>&1 || "
                 "(test -d /sys/class/video4linux && ls /sys/class/video4linux 2>/dev/null | grep -q .)",
        "verify": "camd --backend v4l2 --sink file:///tmp/rl1.bin --batches 1 "
                  "后断言输出帧分辨率与真实设备能力一致，而非 1x1 合成",
        "ev": "R1.evidence",
    },
    {
        "id": "R2",
        "name": "systemd 运行时驻留",
        "why": "生产环境主路径；enable/restart/is-active/MainPID/Restart=always 从未真跑",
        # 探测口径修正：原判据要求宿主 PID 1 就是 systemd，会永远 BLOCKED。
        # 但 PID/mount namespace 里可以起真正的 systemd 作真正的 PID 1（实测可行：
        # /proc/1/comm=systemd、systemctl daemon-reload rc=0、journald/logind 拉起）。
        # 那是真 systemd 路径，不是模拟。故探测改为"能否造出该环境"。
        # 注意不能用 systemctl is-system-running：ns 内它返回 starting，rc=1。
        "probe": "command -v unshare >/dev/null && "
                  "(test -x /lib/systemd/systemd || test -x /usr/lib/systemd/systemd) && "
                  "unshare --fork --pid --mount-proc --mount --propagation private /bin/true",
        "verify": "onekey install 后断言 is-active=active 且 MainPID!=0，"
                  "kill -9 后观察 Restart 拉起且 C2 继续收到字节",
        "ev": "R2.evidence",
    },
    {
        "id": "R3",
        "name": "cron 实际执行",
        "why": "条目已写、分位正确，但守护进程不在，从未真正触发过一次",
        "probe": "pgrep -x cron >/dev/null || pgrep -x crond >/dev/null",
        "verify": "对齐到 cron 分位后等待触发，断言 C2 收到新字节",
        "ev": "R3.evidence",
    },
    {
        "id": "R3a",
        "name": "cron.d 加载期契约（真 cron 静默不执行的已知原因）",
        "why": "真 cron 守护不可得（apt 无 cron 包、无 busybox），但它在加载 "
               "/etc/cron.d/* 时的硬行为可静态真验：文件名含点、漏 user 字段、"
               "group/other 可写、非 root 属主、缺 PATH、末行无换行、命令不存在"
               "——违反任意一条都会导致整个文件被跳过且无任何可见症状",
        # probe 用 {REPO} 占位符：subprocess 走 shell=True，cwd 不固定，
        # 相对路径会在不同调用位置得到不同结果，必须展开成绝对路径。
        "probe": "test -f {REPO}/21_exfil/onekey.sh && "
                 "test -f {REPO}/21_exfil/tests/verify_cron_contract.py && "
                 "command -v unshare >/dev/null",
        "verify": "install 到假根后断言 7 条契约，并对每条做反向注入证明非恒绿",
        "ev": "R3a.evidence",
    },
    {
        "id": "R4",
        "name": "arm64/arm 真产物",
        "why": "多架构分发机制齐备，但缺真实交叉产物；现有 arm64 包是改了 e_machine 的合成品",
        "probe": "command -v aarch64-linux-gnu-gcc >/dev/null",
        "verify": "交叉编译后 readelf -h 确认 e_machine=AArch64，"
                  "且该产物在 arm64 机器上 checkpayload 通过并实际运行",
        "ev": "R4.evidence",
    },
]


def main():
    print("=== 红线巡检 ===\n")
    pending = 0
    for r in REDLINES:
        rc, out = run(r["probe"])
        if rc != 0:
            state = "BLOCKED"
            detail = "环境不具备（硬限制）"
        else:
            ev_path = os.path.join(EV, r["ev"])
            if os.path.exists(ev_path) and os.path.getsize(ev_path) > 0:
                state = "VERIFIED"
                detail = "证据: %s" % r["ev"]
            else:
                state = "PENDING"
                detail = "环境已具备但无证据 —— 必须验证"
                pending += 1
        print("[%-8s] %s  %s" % (state, r["id"], r["name"]))
        print("           %s" % r["why"])
        print("           %s" % detail)
        if state == "PENDING":
            print("           应跑: %s" % r["verify"])
        print()

    print("=== 汇总 ===")
    print("PENDING（环境具备却未验证，须立即补）: %d" % pending)
    if pending:
        print("\n[ALARM] 存在可验证却未验证的红线。")
        print("        在此状态下声称该红线\"已验证\"即为伪造。")
        return 1
    print("无 PENDING。BLOCKED 项是环境硬限制，不得记为已验证。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
