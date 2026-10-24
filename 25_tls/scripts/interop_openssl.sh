#!/bin/sh
# interop_openssl.sh — 与真实 OpenSSL 的双向互操作验证
#
# 为什么必须有它：
#   test_tls_srv.c 做的是"自家客户端 <-> 自家服务端"的闭环。闭环证明的是
#   "两端一致"，不证明"符合协议"。真实回源之后接的是真实世界的 TLS 实现，
#   它们发的 ClientHello 带着几十个扩展、不同的扩展顺序与长度编码。只有
#   对连一次 OpenSSL，才能证明我们的解析器不会在真实报文上崩掉。
#
# 两个方向：
#   A. 我们的服务端  <-  真实 OpenSSL s_client
#   B. 我们的客户端  ->  真实 OpenSSL s_server
#
# 反向对照（不做就是恒绿）：
#   A-NEG 给 s_client 一个错误 CA：握手必须失败。若"Verify return code: 0"
#        在证链失败时依然打印，那这条断言就是恒真的，等于没验。
#   B-NEG 我们客户端校验错误主机名：必须返回 CERT 失败。证明主机名校验
#        是真的在跑，而不是被我们悄悄跳过。
#
# 三个必须记住的环境事实（每条都曾让人误判）：
#   1. openssl 的 s_client / s_server 把 stdin EOF 当成"退出"。必须用
#      "<产生数据> ; sleep N" 喂住 stdin，否则对端在握手前就关掉连接，
#      表现为 "transport error"，而真因是 stdin 早就 EOF 了。
#   2. s_server 默认会生成 2048 位临时 DH 参数，耗时可达数十秒。用 -no_dhe。
#      否则现象是"客户端连不上"，真因是服务端还没 bind 完。
#   3. 后台进程必须 setsid 且三个 fd 全部重定向。否则它会持有调用方的
#      stdout，让上层等不到 EOF —— 表现为"命令挂起"，与被测代码无关。

set -u
cd "$(dirname "$0")/.." || exit 99

ONLY=${1:-both}    # 只跑一个方向：A | B | both。分段跑是为了把单次耗时压下来。

DATA=tests/data
BUILD=build
pass=0
fail=0

ok()   { pass=$((pass+1)); printf '[PASS] %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '[FAIL] %s\n' "$1"; }
chk()  { if [ "$2" -eq 0 ]; then ok "$1"; else bad "$1"; fi; }

if ! command -v openssl >/dev/null 2>&1; then
    echo "[FATAL] 未找到 openssl，无法做跨实现互操作"; exit 98
fi
if [ ! -x "$BUILD/tls_srv_tcp" ] || [ ! -x "$BUILD/tls_cli_tcp" ]; then
    echo "[FATAL] 缺少互操作工具，先跑 make"; exit 97
fi

echo "--- openssl: $(openssl version) ---"

wait_for_log() {
    _f=$1; _pat=$2; _i=0
    while [ $_i -lt 150 ]; do
        if [ -f "$_f" ] && grep -q "$_pat" "$_f" 2>/dev/null; then return 0; fi
        _i=$((_i+1)); sleep 0.1
    done
    return 1
}

# 分离启动：新会话 + 三 fd 全重定向，并且返回进程组 id 便于整组回收。
spawn() {
    setsid sh -c "$1" </dev/null >"$2" 2>&1 &
    echo $!
}

PORT_A=$((21000 + $$ % 9000))
PORT_AN=$((PORT_A + 1))
PORT_B=$((PORT_A + 2))
PORT_BN=$((PORT_A + 3))

# =====================================================================
# A. 我们的服务端 <- OpenSSL s_client
# =====================================================================
if [ "$ONLY" = both ] || [ "$ONLY" = A ]; then
echo "=== A: 自研服务端 <- OpenSSL s_client ==="
rm -f /tmp/io_a_srv.log /tmp/io_a_cli.log
GPA=$(spawn "\"$PWD/$BUILD/tls_srv_tcp\" $PORT_A \"$PWD/$DATA/leaf.pem\" \
             \"$PWD/$DATA/leaf.key\" h2" /tmp/io_a_srv.log)
wait_for_log /tmp/io_a_srv.log "SRV-LISTEN"; chk "A: 服务端就绪" $?

( printf 'HELLO-INTEROP\n'; sleep 2 ) | timeout 20 openssl s_client \
    -connect 127.0.0.1:"$PORT_A" -tls1_2 \
    -cipher ECDHE-RSA-AES128-GCM-SHA256 -curves X25519 \
    -CAfile "$DATA/ca.pem" -servername front.test \
    -verify_hostname front.test -verify_return_error -alpn h2 \
    >/tmp/io_a_cli.log 2>&1
A_RC=$?
chk "A: OpenSSL 客户端握手并验链成功（rc=0）" "$A_RC"

grep -q "Verify return code: 0 (ok)" /tmp/io_a_cli.log
chk "A: OpenSSL 报告 Verify return code: 0" $?
grep -q "Cipher *: *ECDHE-RSA-AES128-GCM-SHA256" /tmp/io_a_cli.log
chk "A: 协商套件为 ECDHE-RSA-AES128-GCM-SHA256" $?
grep -qi "ALPN protocol: h2" /tmp/io_a_cli.log
chk "A: OpenSSL 侧确认 ALPN=h2" $?
grep -q "HELLO-INTEROP" /tmp/io_a_cli.log
chk "A: 客户端收到服务端回显（往返成立）" $?

wait_for_log /tmp/io_a_srv.log "SRV-DONE"; chk "A: 服务端正常收尾" $?
grep -q "SRV-HANDSHAKE OK"  /tmp/io_a_srv.log; chk "A: 服务端侧握手成功" $?
grep -q "SRV-SNI front.test" /tmp/io_a_srv.log; chk "A: 服务端观察到的 SNI = front.test（域前置观测点）" $?
grep -q "SRV-ALPN h2"       /tmp/io_a_srv.log; chk "A: 服务端侧 ALPN=h2" $?
grep -q "SRV-ECHO OK"       /tmp/io_a_srv.log; chk "A: 服务端完成回显" $?
grep -q "SRV-CLOSE OK"      /tmp/io_a_srv.log; chk "A: 服务端发出 close_notify" $?
kill -TERM -"$GPA" 2>/dev/null

# ---- A-NEG：错误 CA 必须握手失败 ----
echo "=== A-NEG: 错误信任库必须失败 ==="
rm -f /tmp/io_an_srv.log /tmp/io_an_cli.log
GPAN=$(spawn "\"$PWD/$BUILD/tls_srv_tcp\" $PORT_AN \"$PWD/$DATA/leaf.pem\" \
              \"$PWD/$DATA/leaf.key\" h2" /tmp/io_an_srv.log)
wait_for_log /tmp/io_an_srv.log "SRV-LISTEN"
( printf 'HELLO\n'; sleep 1 ) | timeout 12 openssl s_client \
    -connect 127.0.0.1:"$PORT_AN" -tls1_2 \
    -cipher ECDHE-RSA-AES128-GCM-SHA256 -curves X25519 \
    -CAfile "$DATA/selfsigned.pem" -servername front.test \
    -verify_hostname front.test -verify_return_error -alpn h2 \
    >/tmp/io_an_cli.log 2>&1
AN_RC=$?
if [ "$AN_RC" -ne 0 ]; then ok "A-NEG: 错误 CA 下 OpenSSL 拒绝（rc=$AN_RC）"
else bad "A-NEG: 错误 CA 竟然通过——verify 断言可能是恒真的"; fi
kill -TERM -"$GPAN" 2>/dev/null

fi

if [ "$ONLY" = both ] || [ "$ONLY" = B ]; then
# =====================================================================
# B. 我们的客户端 -> OpenSSL s_server
# =====================================================================
echo "=== B: 自研客户端 -> OpenSSL s_server ==="
rm -f /tmp/io_b_srv.log /tmp/io_b_cli.log
# -no_dhe：否则它会先生成 2048 位临时 DH 参数，bind 前就要等几十秒。
GPB=$(spawn "sleep 14 | timeout 12 openssl s_server -accept $PORT_B \
             -cert \"$PWD/$DATA/leaf.pem\" -key \"$PWD/$DATA/leaf.key\" \
             -tls1_2 -no_dhe -cipher ECDHE-RSA-AES128-GCM-SHA256 \
             -curves X25519 -alpn h2 -rev" /tmp/io_b_srv.log)

# s_server 没有就绪行，用"重试直到不再是 connect 失败"判定就绪。
# 只重试 connect 失败：握手失败绝不重试，否则把真实缺陷掩盖成时序问题。
B_TRY=0
while [ $B_TRY -lt 12 ]; do
    timeout 6 "$BUILD/tls_cli_tcp" 127.0.0.1 "$PORT_B" front.test front.test \
        "$DATA/ca.pem" h2 rev >/tmp/io_b_cli.log 2>&1
    B_RC=$?
    grep -q "CLI-FAIL connect" /tmp/io_b_cli.log || break
    B_TRY=$((B_TRY+1)); sleep 0.2
done
if [ $B_TRY -lt 12 ]; then ok "B: 客户端连上 s_server（重试 $B_TRY 次）"
else bad "B: s_server 始终未就绪"; fi

cat /tmp/io_b_cli.log
chk "B: 我们的客户端与 OpenSSL 握手成功（rc=0）" "$B_RC"
grep -q "CLI-HANDSHAKE OK"  /tmp/io_b_cli.log; chk "B: 客户端侧握手成功" $?
grep -q "CLI-READ .* MATCH" /tmp/io_b_cli.log; chk "B: 应用数据往返逐字节一致（对端倒序回写后仍逐字节吻合）" $?
grep -q "CLI-CLOSE OK"      /tmp/io_b_cli.log; chk "B: 客户端发出 close_notify" $?
# 注意：s_server 的 stdout 只打印连接信息，不打印收到的应用数据。
# "它确实收到了我们的数据"这点的证据在客户端侧 —— 我们读回来的字节
# 恰好是我们发出内容的倒序，除了"它收到并回写"之外没有别的可能来源。
grep -q "Protocol version: TLSv1.2" /tmp/io_b_srv.log
chk "B: s_server 侧确认 TLS 版本为 1.2" $?
grep -qi "ECDHE-RSA-AES128-GCM-SHA256" /tmp/io_b_srv.log
chk "B: s_server 侧确认套件一致" $?
kill -TERM -"$GPB" 2>/dev/null

# ---- B-NEG：错误主机名必须被我们的客户端拒绝 ----
echo "=== B-NEG: 错误主机名必须被拒绝 ==="
rm -f /tmp/io_bn_cli.log
GPBN=$(spawn "sleep 12 | timeout 10 openssl s_server -accept $PORT_BN \
              -cert \"$PWD/$DATA/leaf.pem\" -key \"$PWD/$DATA/leaf.key\" \
              -tls1_2 -no_dhe -cipher ECDHE-RSA-AES128-GCM-SHA256 \
              -curves X25519 -alpn h2" /dev/null)
BN_TRY=0
while [ $BN_TRY -lt 12 ]; do
    timeout 6 "$BUILD/tls_cli_tcp" 127.0.0.1 "$PORT_BN" front.test evil.test \
        "$DATA/ca.pem" h2 >/tmp/io_bn_cli.log 2>&1
    BN_RC=$?
    grep -q "CLI-FAIL connect" /tmp/io_bn_cli.log || break
    BN_TRY=$((BN_TRY+1)); sleep 0.2
done
cat /tmp/io_bn_cli.log
if [ "$BN_RC" -ne 0 ] && grep -q "certificate verification failed" /tmp/io_bn_cli.log; then
    ok "B-NEG: 错误主机名被拒（certificate verification failed）"
else
    bad "B-NEG: 错误主机名未被拒（rc=$BN_RC）——主机名校验可能没在跑"
fi
kill -TERM -"$GPBN" 2>/dev/null

fi

echo
echo "=== interop($ONLY): $pass pass, $fail fail ==="
[ "$fail" -eq 0 ] || exit 1
exit 0
