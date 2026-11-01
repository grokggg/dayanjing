#!/usr/bin/env python3
"""红线巡检：把"从未验证"从文档文字变成持续被检查的状态。

三条状态，语义严格区分：
  BLOCKED   环境不具备 -> 不可验证，是硬限制，不是偷懒
  PENDING   环境具备但没有证据 -> 这才是必须报警的，伪造最容易发生在这里
  VERIFIED  环境具备且有证据文件 -> 结论可引用

本脚本只判定状态，不替任何人生成证据。
证据必须是真实实跑的输出，由人放到 evidence/ 下。
"""
import re
import hashlib
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
        cmd = cmd.replace("{VENDOR}", VENDOR)
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as e:
        return -1, str(e)


# 每条红线：环境探测 + 一旦具备应跑的验证 + 证据文件名
REDLINES = [
    {
        "id": "R1",
        "name": "V4L2 真设备采集",
        "why": "整条链唯一没有流过真实像素的环节；全程 mock 合成帧。"
               "\n      【已实证：本环境造不出可用字符设备，三条路全堵】"
               "\n      (1) 内核模块：无 /lib/modules、无 modprobe，装不了 v4l2loopback/vivid"
               "\n      (2) CUSE：无 libfuse3 开发头无法编译；且内核 fs/fuse/cuse.c 的"
               "\n          cuse_dev_operations 没有 .mmap，而后端必走 mmap"
               "\n      (3) FUSE：fuse_init_inode 对 S_IFCHR 走 init_special_inode()，"
               "\n          i_fop 被换成 def_chr_fops，open 走 chrdev_open 而非 FUSE，"
               "\n          表现为 Permission denied 且服务端零请求（实测对照："
               "\n          同一份服务端改 S_IFREG 后 open/ioctl/mmap 全部正常）",
        # 注意：/sys/class/video4linux 目录可能"存在但为空"，ls 空目录返回 0，
        # 会误判成环境具备。必须用 grep -q . 要求有实际条目。
        # 判据必须是"能打开"，不是"存在"。实测本环境 /dev/video0 存在且
        # 是主设备号 81 的字符设备节点，但无驱动：open 返回 ENXIO。
        # 用 ls 判存在会把"节点在、驱动不在"误判成环境具备 —— 与
        # /sys/class/video4linux 空目录那次是同一类"存在≠可用"的错误。
        "probe": "for d in /dev/video*; do test -c \"$d\" || continue; "
                 "python3 -c \"import os,sys;os.open(sys.argv[1],os.O_RDWR|os.O_NONBLOCK)\" \"$d\" "
                 ">/dev/null 2>&1 && exit 0; done; exit 1",
        "verify": "camd --backend v4l2 --sink file:///tmp/rl1.bin --batches 1 "
                  "后断言输出帧分辨率与真实设备能力一致，而非 1x1 合成",
        "ev": "R1.evidence",
        "sources": [
            "agent_windows/src/cam_linux_v4l2.c",
        ],
    },
    {
        "id": "R1b",
        "name": "V4L2 内核 ABI（ioctl 序列 + mmap 取帧）",
        "why": "真设备分支依赖的全部内核 ABI：ioctl 命令号、结构体布局与大小、"
               "mmap 取帧、DQBUF 语义。这些错了真机上就是 ENOTTY/EINVAL/段错误，"
               "而本沙盒没有摄像头，此前从未有任何东西验过。",
        # 用 FUSE 造用户态设备即可验证，不需要真摄像头。
        "probe": "test -c /dev/fuse && test -w /dev/fuse && command -v gcc >/dev/null",
        "verify": "python3 {REPO}/21_exfil/tests/verify_v4l2_abi.py",
        "ev": "R1b.evidence",
        "sources": [
            "agent_windows/src/cam_linux_v4l2.c",
            "agent_windows/tests/v4l2sim_shim.c",
            "21_exfil/tests/verify_v4l2_abi.py",
        ],
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
        "sources": [
            "21_exfil/onekey.sh",
        ],
    },
    {
        "id": "R3",
        "name": "cron 实际执行",
        "why": "条目已写、分位正确，但守护进程不在，从未真正触发过一次",
        # probe 判据修正：原判据是 `pgrep -x cron || pgrep -x crond`，它问的是
        # "此刻有没有 cron 在跑"，而环境里跑的是哪个 cron 完全不受控 —— 实测
        # 就撞上一个 vixie cron：它的 pathnames.h 只有 CRON_DENY、没有
        # CRON_DIR，根本不扫描 /etc/cron.d，于是条目永远不触发，而 probe
        # 判定"环境具备"。真正该问的是"能不能起一个会读 /etc/cron.d 的真
        # cron"，即构建脚本与编译器是否可用。
        "probe": "test -f {REPO}/scripts/build_cronie.sh && command -v gcc >/dev/null",
        "verify": "真 cronie 守护进程 + 真 install + 对齐分钟等真实触发，"
                  "断言 C2 新增字节；反向去掉 user 字段必须不再触发",
        "ev": "R3.evidence",
        "sources": [
            "21_exfil/onekey.sh",
            "redline/verify_r3_cron.py",
            "scripts/build_cronie.sh",
        ],
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
        "sources": [
            "21_exfil/onekey.sh",
            "21_exfil/tests/verify_cron_contract.py",
        ],
    },
    {
        "id": "R4",
        "name": "arm64 真产物（编译+打包+架构分派）",
        "why": "多架构分发的判据齐备，但需要真交叉产物来证明它不是合成品",
        "probe": "python3 -c 'import ziglang' >/dev/null 2>&1 "
                 "|| ls artifacts/camd-aarch64-musl >/dev/null 2>&1",
        "verify": "zig cc -target aarch64-linux-musl 编出 camd，"
                  "确认 e_machine=183 且无 INTERP 段（静态）；"
                  "打进多架构包后，用假 uname 模拟 arm64 目标，"
                  "断言选中 arm64 段且错配被点名",
        "ev": "R4.evidence",
        "sources": [
            "scripts/build_cross.sh",
            "21_exfil/make_onekey.py",
        ],
    },
    {
        "id": "R4b",
        "name": "跨架构产物真执行（arm64 / arm）",
        "why": "产物能编出来，不等于能在 arm64 上跑起来；无 qemu 时执行路径无从验证",
        # 探测口径修正：qemu 装不上（apt: Unable to locate package；PyPI 无该包），
        # 但 PyPI 有纯 Python 的 qiling，支持 ARM64 Linux ELF + 系统调用。
        # "没有模拟器"同样是渠道问题。判据改为：有任意可用模拟器 且 有 arm64 产物。
        # 判据修正：qiling 装在持久 vendor 目录（比 site-packages 不易被环境
        # 清理），必须显式带 PYTHONPATH，否则默认 site-packages 被清后本红线
        # 会误判 STALE —— 那是"环境不具备"与"路径没指对"混为一谈。
        "probe": "(command -v qemu-aarch64 >/dev/null "
                 "|| command -v qemu-aarch64-static >/dev/null "
                 "|| PYTHONPATH={VENDOR} python3 -c 'import qiling' >/dev/null 2>&1) "
                 "&& test -f {REPO}/artifacts/camd-aarch64-musl",
        "verify": "PYTHONPATH={VENDOR} python3 {REPO}/21_exfil/tests/verify_arm64_exec.py",
        "ev": "R4b.evidence",
        "sources": [
            "21_exfil/tests/verify_arm64_exec.py",
        ],
    },
    {
        "id": "R4c",
        "name": "i386 产物执行",
        "why": "32 位 x86 存量目标仍大量存在（老工控机、瘦客户端、旧办公机）；"
               "\n      产物已能编出（e_machine=3 静态），但该架构字节能否跑起来未验。"
               "\n      【认知修正 —— 此前误判为环境限制，勿再退回】"
               "\n      前几轮记为 BLOCKED，理由是「qiling 对 x86-32 支持不足」，"
               "\n      依据是同目标 hello world 在模拟器下同样 UcError。"
               "\n      那个推理漏了：宿主本身就是 x86_64，Linux 内核自带 IA32"
               "\n      compatibility，32 位静态 ELF 可**原生执行**，根本不需要模拟器。"
               "\n      实测 camd-i386-musl --help 直接 RC=0。所以这是排查路径选错，"
               "\n      不是环境不具备。（判据也踩过坑：帮助文本走 stderr 不是 stdout，"
               "\n      只查 stdout 会把「能跑」误判成「无 IA32 兼容」。）",
        # 判据是被测产物自身能否原生执行，不猜内核配置、不依赖任何模拟器。
        # 产物缺失也走这里 -> BLOCKED（提示先跑 build_cross.sh），语义正确。
        "probe": "test -x {REPO}/artifacts/camd-i386-musl && "
                 "{REPO}/artifacts/camd-i386-musl --help 2>&1 | grep -q -- '--sink'",
        "verify": "跑 21_exfil/tests/verify_i386_exec.py：原生执行 i386 产物，"
                  "断言采集+编码+加密+回传端到端成立、线上无 JPEG 明文",
        "ev": "R4c.evidence",
        "sources": [
            "21_exfil/tests/verify_i386_exec.py",
        ],
    },
]


# 产物指纹绑定：证据必须记下它所验证的那份产物的哈希。
# 没有这层绑定，重新编译产物后旧证据仍会被判 VERIFIED ——
# 即"用旧产物的证据冒充新产物的状态"，这是防伪造机制的第三个漏洞。
# 模拟器/依赖的持久安装位。放 /data 而非 site-packages：
# 后者会被环境清理，导致证据"在但不可复现"（STALE）。
VENDOR = os.environ.get("QILING_VENDOR", "/data/workspace/vendor")


ARTIFACT_OF_ARCH = {
    "aarch64": "artifacts/camd-aarch64-musl",
    "arm":     "artifacts/camd-arm-musl",
    "i386":    "artifacts/camd-i386-musl",
}


def check_evidence_fresh(ev_path):
    """返回 (ok, reason)。

    两层绑定：
      HASH <arch> <sha> <size>   证据对应哪份编译产物（产物类证据）
      SRC  <path> <sha>  <size>  证据对应哪份源码文本（日志类证据）

    历史漏洞：只绑产物，日志类证据（R1b/R2/R3a 等）改了源码仍显示
    VERIFIED —— 即"用旧源码的证据冒充新源码的状态"。
    更隐蔽的是：证据里没有指纹行时旧实现直接 return True（"无法校验也
    不降级"），那等于给所有未绑定证据发了免检证，机制形同虚设。
    故此处改为：该红线定义了 sources 而证据里没有 SRC 行 -> 判失效。
    """
    try:
        txt = open(ev_path, "r", errors="replace").read()
    except OSError as e:
        return False, "证据不可读: %s" % e

    # ---- 第二层：源码指纹 ----
    wanted = {l for l in txt.splitlines() if l.startswith("SRC ")}
    rid = os.path.basename(ev_path).split(".")[0]
    rl = next((x for x in REDLINES if x["id"] == rid), None)
    if rl and rl.get("sources"):
        if not wanted:
            return False, ("证据未绑定源码指纹（缺 SRC 行）—— 无法证明它对应当前源码，"
                           "请用 redline/stamp.py 重新生成")
        for rel in rl["sources"]:
            fp = os.path.join(REPO, rel)
            if not os.path.isfile(fp):
                return False, "绑定源已不存在: %s" % rel
            raw = open(fp, "rb").read()
            cur = hashlib.sha256(raw).hexdigest()
            hit = any(l == "SRC %s %s %d" % (rel, cur, len(raw)) for l in wanted)
            if not hit:
                return False, "源码已改动，证据对应的是旧代码: %s" % rel

    lines = [l for l in txt.splitlines() if l.startswith("HASH ")]
    if not lines:
        # 该红线的证据不绑定产物（如纯日志类），无法校验也不降级。
        return True, None
    checked = 0
    for l in lines:
        parts = l.split()
        if len(parts) != 4:
            continue
        arch, sha, size = parts[1], parts[2], int(parts[3])
        rel = ARTIFACT_OF_ARCH.get(arch)
        if not rel:
            continue
        fp = os.path.join(REPO, rel)
        if not os.path.isfile(fp):
            return False, "指纹 %s 对应的产物已不存在: %s" % (arch, rel)
        raw = open(fp, "rb").read()
        cur = hashlib.sha256(raw).hexdigest()
        checked += 1
        if cur != sha or len(raw) != size:
            return False, "指纹与当前 %s 产物不一致（该证据对应的是旧产物）" % arch
    if checked == 0:
        return True, None
    return True, None



# 第三层：证据自证结果。
# 历史漏洞（第五处）：状态机只校验"证据存在 + 指纹匹配"，从不看证据
# 内容本身是否通过。实测 R3.evidence 末尾写着 PASS=10 FAIL=2、正文含
# 两条 [FAIL]，状态机照样把它判成 VERIFIED —— 一份失败的运行输出被
# 当成"已验证"的证据。
# 只认显式汇总行 FAIL=<n>：反向验证的预期失败也写成 [FAIL]，数行会误伤。
FAIL_SUMMARY_RE = re.compile(r"\bFAIL\s*[:=]\s*(\d+)")


def check_evidence_selfresult(ev_path):
    """返回 (ok, reason)。证据自证有失败则不得支撑 VERIFIED。"""
    try:
        txt = open(ev_path, "r", errors="replace").read()
    except OSError as e:
        return False, "证据不可读: %s" % e
    nums = [int(m) for m in FAIL_SUMMARY_RE.findall(txt)]
    if not nums:
        # 该证据不写汇总行，无法判定也不降级（避免误伤预期反向）
        return True, None
    if max(nums) > 0:
        return False, ("证据自证 %d 项失败 —— 它是失败的运行输出，"
                       "不得用作'已验证'的依据；请修复后重新生成" % max(nums))
    return True, None


def main():
    print("=== 红线巡检 ===\n")
    pending = 0
    stale = 0
    for r in REDLINES:
        rc, out = run(r["probe"])
        ev_path = os.path.join(EV, r["ev"])
        ev_exists = os.path.exists(ev_path) and os.path.getsize(ev_path) > 0
        if rc != 0:
            if ev_exists:
                # 证据在、环境却退化了：这份证据现在无法复现。
                # 它只能证明"曾经跑通过"，不能证明"当前成立"——
                # 这正是拿旧证据冒充当前状态的窗口，必须点名。
                state = "STALE"
                detail = ("证据 %s 存在，但当前环境已不具备（probe 失败）——"
                          "该证据无法复现，不得据此声称本红线已验证" % r["ev"])
                stale += 1
            else:
                state = "BLOCKED"
                detail = "环境不具备（硬限制）"
        else:
            if ev_exists:
                ok, why = check_evidence_fresh(ev_path)
                if ok:
                    ok2, why2 = check_evidence_selfresult(ev_path)
                    if ok2:
                        state = "VERIFIED"
                        detail = "证据: %s" % r["ev"]
                    else:
                        state = "PENDING"
                        detail = "%s（证据 %s）" % (why2, r["ev"])
                        pending += 1
                else:
                    state = "PENDING"
                    detail = "证据已失效 —— %s" % why
                    pending += 1
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
    print("STALE  （证据在但环境已不具备、无法复现）: %d" % stale)
    if stale:
        print("\n[ALARM] 存在「有证据但当前无法复现」的红线。")
        print("        这些证据只能证明曾经跑通过，不能证明当前成立。")
        print("        凭它们声称已验证即为伪造 —— 应先恢复环境并重跑。")
    if pending or stale:
        print("\n[ALARM] 存在可验证却未验证的红线。")
        print("        在此状态下声称该红线\"已验证\"即为伪造。")
        return 1
    print("无 PENDING / 无 STALE。BLOCKED 项是环境硬限制，不得记为已验证。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
