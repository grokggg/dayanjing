#!/bin/sh
# 重生成指定红线的证据并打上源码指纹。
#
# 为什么需要它：改了任一绑定源（如 onekey.sh），证据的 SRC 指纹即刻失效，
# 红线由 VERIFIED 翻 PENDING 并 ALARM —— 这是机制按设计工作，不是误报。
# 但它要求"改了源码就得重跑证据"，而重跑需要知道每个红线跑哪个守卫、
# 证据写到哪、指纹怎么打。散在各处就容易漏，本脚本把它固化成一条命令。
#
# 用法: sh redline/regen_evidence.sh R3a [R2 R3 ...]
set -eu
REPO=/data/workspace/dayanjing
cd "$REPO"
EV=redline/evidence

for rid in "$@"; do
    case "$rid" in
        R2)  GUARD="python3 redline/verify_r2_systemd.py" ;;
        R3)  GUARD="python3 redline/verify_r3_cron.py" ;;
        R3a) GUARD="python3 21_exfil/tests/verify_cron_contract.py" ;;
        R4b) GUARD="python3 21_exfil/tests/verify_arm64_exec.py" ;;
        R4c) GUARD="python3 21_exfil/tests/verify_i386_exec.py" ;;
        R1b) GUARD="python3 agent_windows/tests/v4l2_realpath_probe" ;;
        *)   echo "未知红线或缺少重生成脚本: $rid" >&2; exit 2 ;;
    esac
    echo "=== $rid : $GUARD ==="
    # 守卫输出直接即证据：判据正文 + HASH/SRC 指纹都必须落在文件里，
    # 否则"有证据"只是"有个文件"，指纹校验无从谈起。
    sh -c "$GUARD" > "$EV/$rid.evidence" 2>&1
    rc=$?
    python3 redline/stamp.py "$rid" --append "$EV/$rid.evidence"
    if [ "$rc" -ne 0 ]; then
        echo "[WARN] $rid 守卫退出码 $rc —— 证据未通过，红线不会翻 VERIFIED"
    fi
done
