#!/bin/bash
# 跨网络命名空间部署验证。
#
# 与回环自检的本质区别：每个节点跑在**独立的网络栈**里（各自 lo、各自路由表、
# 各自 ARP 邻居表），经网桥 L2 互通 —— 跨主机部署会遇到的路由/邻居/绑定地址
# 问题在这里都会真实暴露（回环上 127.0.0.1 全通配，什么都测不出来）。
#
# 用法: bash tools/deploy_crossns.sh
set -u

BR=xbr0
SUB=10.9.0
OUT=/tmp/xns_deploy
TOPO=/tmp/xns_topo.json
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
BIN=$ROOT/14_p2p/static/p2p_node

# alias:ip:netns
NODES="endpoint:${SUB}.11:xnsep edge0:${SUB}.12:xnse0 edge1:${SUB}.13:xnse1 core:${SUB}.14:xnscore"
TARGET_IP=${SUB}.20
TARGET_NS=xnstarget
ECHO_PORT=9100

cleanup() {
    # 注意：删除 netns 后 veth 的宿主端会残留在根命名空间里，
    # 只删 netns 会导致下一次运行撞名（RTNETLINK File exists）。
    for spec in $NODES; do
        ns=${spec##*:}
        ip link del "v${ns}" 2>/dev/null
        ip netns del "$ns" 2>/dev/null
    done
    ip link del "v${TARGET_NS}" 2>/dev/null
    ip netns del "$TARGET_NS" 2>/dev/null
    ip link del "$BR" 2>/dev/null
    pkill -f xns_echo.py 2>/dev/null
}
trap cleanup EXIT
cleanup

if [ ! -x "$BIN" ]; then
    echo "[xns] 二进制不存在，先构建: $BIN"
    make -C "$ROOT/14_p2p" static >/dev/null 2>&1 || {
        echo "[xns] 构建失败"; exit 1; }
fi

echo "[xns] 建网桥 $BR"
ip link add "$BR" type bridge || { echo "[xns] 网桥创建失败（无权限？）"; exit 2; }
ip link set "$BR" up

# 目标栈（最终 echo 服务）
ip netns add "$TARGET_NS"
ip link add "v${TARGET_NS}" type veth peer name "p${TARGET_NS}" || { echo "[xns] veth 失败"; exit 2; }
ip link set "p${TARGET_NS}" netns "$TARGET_NS"
ip -n "$TARGET_NS" link set "p${TARGET_NS}" name eth0
ip link set "v${TARGET_NS}" master "$BR"
ip link set "v${TARGET_NS}" up
ip -n "$TARGET_NS" addr add "${TARGET_IP}/24" dev eth0
ip -n "$TARGET_NS" link set eth0 up
ip -n "$TARGET_NS" link set lo up

cat > /tmp/xns_echo.py <<'EOF'
import socket, threading, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(16)
print("echo up", flush=True)
while True:
    c, _ = s.accept()
    def h(cc=c):
        d = cc.recv(65536)
        cc.sendall(d)
        cc.close()
    threading.Thread(target=h, daemon=True).start()
EOF
ip netns exec "$TARGET_NS" python3 /tmp/xns_echo.py "$TARGET_IP" "$ECHO_PORT" \
    > /tmp/xns_echo.log 2>&1 &
sleep 1
echo "[xns] 目标 echo: ${TARGET_IP}:${ECHO_PORT} (ns=$TARGET_NS)"

# 节点栈
i=0
NETNS_MAP=""
for spec in $NODES; do
    alias=${spec%%:*}; rest=${spec#*:}; ipa=${rest%%:*}; ns=${rest##*:}
    i=$((i+1))
    ip netns add "$ns"
    ip link add "v${ns}" type veth peer name "p${ns}"
    ip link set "p${ns}" netns "$ns"
    ip -n "$ns" link set "p${ns}" name eth0
    ip link set "v${ns}" master "$BR"
    ip link set "v${ns}" up
    ip -n "$ns" addr add "${ipa}/24" dev eth0
    ip -n "$ns" link set eth0 up
    ip -n "$ns" link set lo up
    [ -n "$NETNS_MAP" ] && NETNS_MAP="$NETNS_MAP,"
    NETNS_MAP="$NETNS_MAP${alias}=${ns}"
    echo "[xns] $alias -> $ipa (ns=$ns)"
done

# 拓扑：每节点显式 host + 端口（跨栈时无法在部署机探测对端空闲端口）
cat > "$TOPO" <<EOF
{
  "probe_interval_ms": 2000,
  "nodes": [
    {"alias":"endpoint","role":"endpoint","host":"${SUB}.11","listen_port":42011,"mgmt_port":43011,"neighbors":["edge0"]},
    {"alias":"edge0",   "role":"edge",     "host":"${SUB}.12","listen_port":42012,"mgmt_port":43012,"neighbors":["endpoint","edge1"]},
    {"alias":"edge1",   "role":"edge",     "host":"${SUB}.13","listen_port":42013,"mgmt_port":43013,"neighbors":["edge0","core"]},
    {"alias":"core",    "role":"core",     "host":"${SUB}.14","listen_port":42014,"mgmt_port":43014,"neighbors":["edge1"]}
  ]
}
EOF

# 连通性前置检查：此时节点尚未启动，只验证跨栈能到达目标 echo
echo "[xns] 连通性检查(跨栈 -> 目标):"
ip netns exec xnsep python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(3)
try:
    s.connect(('${TARGET_IP}', ${ECHO_PORT}))
    s.sendall(b'PING'); print('  ok  ->', s.recv(64))
except Exception as e:
    print('  FAIL->', e); sys.exit(1)
s.close()
" 2>&1 | head -4

rm -rf "$OUT"
echo "[xns] 生成配置并跨栈启动..."
python3 -u "$HERE/deploy.py" --topology "$TOPO" --out "$OUT" --run \
    --no-echo --echo-host "$TARGET_IP" --echo-port "$ECHO_PORT" \
    --netns-map "$NETNS_MAP" 2>&1 | tail -25
