#!/bin/sh
# 构建真 cron 守护进程（cronie），供 R3「cron 实际执行」红线使用。
#
# 为什么必须自己编
# ----------------
# 本环境 /usr/sbin/cron、/usr/sbin/crond、busybox crond 全部不存在，
# 且无外网 apt（403），装不上任何现成实现。
#
# 为什么选 cronie 而不是 vixie cron
# ---------------------------------
# 实测：vixie cron 源码的 pathnames.h **只有 CRON_DENY，没有 CRON_DIR**，
# 即它根本不扫描 /etc/cron.d。用它去验证「cron.d 条目会被执行」，得到的
# 是永远不触发的假阴性 —— 那会把产品判成缺陷，而真正的错在测试选型。
# cronie 的 src/structs.h 明确写着 tabname 是「/etc/cron.d/ file name」，
# 且 SYS_CROND_DIR 是其一等配置项，与产品写入路径一致。
#
# 为什么手工写 config.h
# ---------------------
# 环境无 autoconf / automake / libtool，configure 跑不起来；而带 configure
# 的发布包要走 release-assets.githubusercontent.com，被网络策略拒绝
# （实测 403 policy_default_denied）。故按 configure.ac 的 AC_DEFINE 与
# src/Makemodule.am 里 cron-paths.h 的模板原样手抄。
# 只开必需项：PAM / SELinux / Audit / inotify 全部关闭（无对应头文件）。
#
# 用法: sh scripts/build_cronie.sh [输出目录]
# 默认目录在 /var/tmp 而非 /tmp：/tmp 会被环境周期性清空，产物消失后
# 守卫会在"等待对齐"阶段报 No such file，排查方向被引向脚本本身。
set -eu

OUTDIR=${1:-/var/tmp/cronsrc}
SRC=$OUTDIR/cronie-master
REPO_URL="https://codeload.github.com/cronie-crond/cronie/tar.gz/refs/heads/master"

mkdir -p "$OUTDIR"

if [ ! -f "$SRC/src/cron.c" ]; then
    # github.com 主站被封，但 codeload 放行（见仓库推送说明）
    curl -sL "$REPO_URL" -o "$OUTDIR/cronie.tgz"
    # 解到临时目录再改名：直接解到 $OUTDIR 后若先 rm -rf $SRC 会把刚解出来的
    # 源码删掉（实测踩出来：那次 mv 把 tarball 本身改成了 cronie-master，
    # 表现为"源码不可用"而真实原因是脚本自毁）。
    rm -rf "$OUTDIR/.xtmp" "$SRC"
    mkdir -p "$OUTDIR/.xtmp"
    tar xzf "$OUTDIR/cronie.tgz" -C "$OUTDIR/.xtmp"
    mv "$OUTDIR"/.xtmp/*/ "$SRC"
fi

[ -f "$SRC/src/cron.c" ] || { echo "[FATAL] cronie 源码不可用: $SRC" >&2; exit 1; }

cat > "$SRC/config.h" <<'EOF'
#ifndef _CRON_CONFIG_H_
#define _CRON_CONFIG_H_
#define HAVE_UNISTD_H 1
#define HAVE_LIMITS_H 1
#define HAVE_FCNTL_H 1
#define HAVE_SYS_CDEFS_H 1
#define HAVE_FCNTL 1
#define HAVE_FLOCK 1
#define HAVE_FCHOWN 1
#define HAVE_SAVED_UIDS 1
#define HAVE_STRUCT_TM_TM_GMTOFF 1
#define DEBUGGING 1
#define MAILARG "/usr/sbin/sendmail"
#define MAILFMT "%s -FCronDaemon -i -odi -oem -oi -t -f %s"
#define SYSLOG 1
#define CAPITALIZE_FOR_PS 1
#define ENABLE_SYSCRONTAB 1
#define EDITOR "vi"
#define CRON_VERSION "1.7.2"
#define PACKAGE_VERSION "1.7.2"
#define PACKAGE_STRING "cronie 1.7.2"
#endif
EOF

cat > "$SRC/src/cron-paths.h" <<'EOF'
#ifndef _CRON_PATHS_H_
#define _CRON_PATHS_H_
#define SPOOL_DIR "/var/spool/cron"
#define CRON_HOSTNAME ".cron.hostname"
#define CRON_ALLOW "/etc/cron.allow"
#define CRON_DENY "/etc/cron.deny"
#define CRON_PID_DIR "/run"
#define SYSCRONTAB "/etc/crontab"
#define SYS_CROND_DIR "/etc/cron.d"
#define SYSCONFDIR "/etc"
#endif
EOF

# gcc 必须在源码目录里跑：config.h 与 src/*.h 都是相对路径引用的，
# 在仓库根执行会得到 "No such file or directory"（实测踩出来）。
cd "$SRC"
gcc -O1 -w -D_GNU_SOURCE -I. -Isrc -DHAVE_CONFIG_H -o "$OUTDIR/crond" \
    src/cron.c src/database.c src/do_command.c src/entry.c src/env.c \
    src/job.c src/misc.c src/popen.c src/pw_dup.c src/security.c \
    src/user.c cronie_common.c

[ -x "$OUTDIR/crond" ] || { echo "[FATAL] 编译失败" >&2; exit 1; }
"$OUTDIR/crond" -V
echo "CROND=$OUTDIR/crond"
