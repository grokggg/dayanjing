#!/bin/sh
# 定位"到底哪个回归目标污染了真实根"。
#
# 为什么需要它：verify-autoroot 以"真实根干净"为基线，一旦前面的目标
# 往真实 /etc 写了驻留，F6/F10/R1-e/R2-d 会全红、make test 整条挂掉，
# 而报错只说"守卫 rc=1"，排查方向会被指向 autoroot 自己 —— 它不是污染源。
#
# 本次实证：污染源是 verify-onekey-sink（直接跑 camd，既未设 CAMD_SVC_NAME
# 也未给 --root，服务名回退项目名，驻留写真实根）。而该守卫自身
# EXIT=0 完全不报警 —— 缺陷是静默的，只有下游会红。
#
# 用法: sh scripts/find_realroot_polluter.sh
# 输出首个报脏的目标即污染源（其后目标都会继承污染，不算）。
set -u
EXFIL=/data/workspace/dayanjing/21_exfil

TARGETS="verify-upload verify-c2 verify-c2-reverse verify-tls-sink \
verify-onekey-sink verify-onekey-arch verify-onekey-front \
verify-sshkey-persist verify-svcname verify-cron-exec verify-prefix \
verify-name-stealth verify-cmdline-stealth verify-unit-contract \
verify-daemon-resilience verify-uninstall-unit verify-uninstall-busy \
verify-persist-selfheal verify-autoroot verify-user-deploy"

# 清掉既有痕迹，否则首个目标就"脏"，定位失去意义
rm -f /etc/cron.d/dayanjing /etc/systemd/system/dayanjing.service \
      /etc/cron.d/sysupdate /etc/systemd/system/sysupdate.service 2>/dev/null

FIRST=""
for t in $TARGETS; do
    echo "### TARGET $t"
    make -C "$EXFIL" "$t" >/dev/null 2>&1
    DIRTY=$(ls /etc/cron.d/ /etc/systemd/system/ 2>/dev/null \
            | grep -iE "dayanjing|sysupdate" | tr '\n' ' ')
    if [ -n "$DIRTY" ]; then
        echo "    REALROOT: $DIRTY"
        if [ -z "$FIRST" ]; then
            FIRST="$t"
            echo "    >>> 首个污染源 = $t（其后目标为继承污染）"
        fi
        # 清掉，让下一个目标从干净基线开始，才能区分"继承"与"新增"
        rm -f /etc/cron.d/dayanjing /etc/systemd/system/dayanjing.service \
              /etc/cron.d/sysupdate /etc/systemd/system/sysupdate.service 2>/dev/null
    else
        echo "    REALROOT: clean"
    fi
done

echo
if [ -z "$FIRST" ]; then
    echo "未发现污染源（每个目标跑完真实根均干净）"
    exit 0
fi
echo "首个污染源: $FIRST"
exit 1
