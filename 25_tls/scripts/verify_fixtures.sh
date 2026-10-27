#!/bin/sh
# 校验 25_tls 测试夹具的**语义正确性** —— 存在不等于正确。
#
# 为什么需要这个脚本（上一轮的真实教训）：
#   tests/data/ 被 .gitignore 忽略，夹具不入库。环境重建后我手工重签了
#   leaf.pem，文件齐备、openssl verify 也通过，但 SAN 只给了 IP 型
#   (IP:127.0.0.1) 而没有 DNS 名。消费方 test_tls_hs.c 用 "front.test"
#   做 SNI，于是校验失败：
#       hostname mismatch (leaf_cn=127.0.0.1, san0=(none))
#   症状是"TLS 校验失败"，排查方向被引向产品代码；若有人此时去放宽断言，
#   就把一个环境缺口永久化成了守卫失效。
#
#   因此这里不止判"文件在不在"，还判"内容是否满足消费方的契约"。
#   任何一条不满足都必须 DIE 并点名成因，不允许静默放过。
set -u

DIR="$(cd "$(dirname "$0")/.." && pwd)/tests/data"
fail=0

ok()   { echo "[OK] $1"; }
bad()  { echo "[FAIL] $1"; fail=1; }
info() { echo "[INFO] $1"; }

need() {
    if [ -f "$DIR/$1" ] && [ -s "$DIR/$1" ]; then
        ok "夹具存在: $1"
    else
        bad "夹具缺失或为空: $1（先跑 make testdata 或 sh scripts/gen_testdata.sh）"
    fi
}

echo "=== 25_tls 夹具语义校验 ==="

# ---- 1. 被源码/测试实际消费的文件，逐一判存在 ----
# 来源：grep -rhoE '"[a-z_]+\.(pem|bin|hex|cnf|csr|key)"' tests/*.c src/*.c
echo "--- 存在性（消费者清单）---"
need ca.pem
need ca.key
need leaf.pem
need leaf.key
need selfsigned.pem
need real_chain.pem
need rsa.pem
need rsa_n.bin
need rsa_e.bin
need rsa_msg.bin
need rsa_sig.bin

if [ "$fail" -ne 0 ]; then
    echo "=== 夹具校验失败（存在性）==="
    exit 1
fi

# ---- 2. 正向素材：OpenSSL 自己必须验得过 ----
# 我们的实现若与 OpenSSL 结论不一致，说明是我们的实现错，不是素材错。
#
# 但仅判 "openssl verify 通过" 是不够的 —— 本沙盒的系统信任库里装了
# MITM 代理 CA（/etc/ssl/certs/zeroproxy-ca.pem），于是：
#     openssl verify real_chain.pem        # 不指定 -CAfile
#     -> OK          哪怕它并非由我方 CA 签发
# 即"verify 通过"在此环境下不能证明"由我方 CA 签发"。故补一条结构性判据：
# leaf 的 issuer 必须等于 ca.pem 的 subject。
echo "--- 正向链：OpenSSL 交叉验证 ---"
if openssl verify -CAfile "$DIR/ca.pem" "$DIR/leaf.pem" >/dev/null 2>&1; then
    ok "OpenSSL 接受 CA -> leaf（正向素材有效）"
else
    bad "OpenSSL 拒绝 CA -> leaf（正向素材无效，不能拿来测我们的实现）"
fi

CA_SUBJ="$(openssl x509 -in "$DIR/ca.pem" -noout -subject 2>/dev/null | sed 's/^subject=//')"
LEAF_ISS="$(openssl x509 -in "$DIR/leaf.pem" -noout -issuer  2>/dev/null | sed 's/^issuer=//')"
if [ -n "$CA_SUBJ" ] && [ "$CA_SUBJ" = "$LEAF_ISS" ]; then
    ok "leaf.issuer == ca.subject（确由我方 CA 签发，非被系统信任库放行）"
else
    bad "leaf.issuer != ca.subject：ca=[$CA_SUBJ] leaf.issuer=[$LEAF_ISS]"
fi

# ---- 3. 核心契约：叶子证书必须含 DNS 型 SAN，且覆盖消费方使用的 SNI ----
# 消费方：tests/test_tls_hs.c  run_client(..., "front.test", ... ca.pem)
# 上一轮失效正是这里：SAN 只有 IP:127.0.0.1，无 DNS 名 -> SNI 匹配不上。
# 注意我们的实现对 IP 型 SAN 报告 san0=(none)（只解析 dNSName），
# 因此"用 IP 证书直连"的形态会校验失败且诊断不点名 —— 契约必须显式锁定。
echo "--- 契约：SAN 必须覆盖消费方 SNI ---"
SAN="$(openssl x509 -in "$DIR/leaf.pem" -noout -ext subjectAltName 2>/dev/null)"
case "$SAN" in
    *"DNS:front.test"*)
        ok "leaf.pem SAN 含 DNS:front.test（与 test_tls_hs.c 的 SNI 一致）" ;;
    *)
        bad "leaf.pem SAN 缺少 DNS:front.test，消费方 SNI=front.test 会匹配失败。实际 SAN: $SAN" ;;
esac

# 反向对照：若出现 IP 型 SAN 而无 DNS 型，正是上一轮失效形态，单独点名
case "$SAN" in
    *"IP:"*) info "leaf.pem 含 IP 型 SAN（我们的实现只解析 dNSName，IP 型等价于没有）" ;;
esac

# ---- 4. 私钥与证书必须配对 ----
# 不配对的症状是握手在签名阶段失败，很容易被误判成协议实现问题。
echo "--- 配对：leaf.key 与 leaf.pem ---"
KM="$(openssl rsa  -in "$DIR/leaf.key" -noout -modulus 2>/dev/null)"
CM="$(openssl x509 -in "$DIR/leaf.pem" -noout -modulus 2>/dev/null)"
if [ -n "$KM" ] && [ "$KM" = "$CM" ]; then
    ok "leaf.key 与 leaf.pem 公钥一致"
else
    bad "leaf.key 与 leaf.pem 公钥不一致（握手会在签名阶段失败）"
fi

# ---- 5. RSA 素材：签名必须被 OpenSSL 判为有效 ----
echo "--- RSA 素材：签名可验证 ---"
# 用临时文件而非进程替换：本脚本是 POSIX sh，dash 不支持 <(...)
PUB="$(mktemp)"
openssl rsa -in "$DIR/rsa.pem" -pubout -out "$PUB" 2>/dev/null
if openssl dgst -sha256 -verify "$PUB" \
        -signature "$DIR/rsa_sig.bin" "$DIR/rsa_msg.bin" >/dev/null 2>&1; then
    ok "rsa_sig.bin 可被 rsa.pem 验签通过"
else
    bad "rsa_sig.bin 验签失败（素材与消费者期望不符）"
fi
rm -f "$PUB"

# ---- 6. 自签证书契约 ----
echo "--- 自签证书契约 ---"
SS="$(openssl x509 -in "$DIR/selfsigned.pem" -noout -ext subjectAltName 2>/dev/null)"
case "$SS" in
    *"DNS:test.local"*) ok "selfsigned.pem SAN 含 DNS:test.local" ;;
    *) bad "selfsigned.pem SAN 缺少 DNS:test.local。实际 SAN: $SS" ;;
esac

# ---- 7. 负向素材：抓取依赖外网，缺失时必须点名成因 ----
echo "--- 负向素材 ---"
if [ -s "$DIR/real_chain.pem" ]; then
    ok "real_chain.pem 存在"
    # 判据必须是 issuer 结构，不能用 openssl verify —— 系统信任库含 MITM CA，
    # 无 -CAfile 时它对任何 zeroproxy 签发的证书都返回 OK，会把负向素材判成"可信"。
    RC_ISS="$(openssl x509 -in "$DIR/real_chain.pem" -noout -issuer 2>/dev/null | sed 's/^issuer=//')"
    if [ -n "$RC_ISS" ] && [ "$RC_ISS" != "$CA_SUBJ" ]; then
        ok "real_chain.issuer 非我方 CA（负向对照有效）: $RC_ISS"
    else
        bad "real_chain 由我方 CA 签发或 issuer 为空，负向对照退化为正向。issuer=[$RC_ISS]"
    fi
else
    bad "real_chain.pem 缺失或为空 —— 它由 gen_testdata.sh 抓取外网证书产出，网络不可用时不会生成"
fi

# ---- 8. 接线：夹具路径必须是单一产地，且经得起 make -C 调用 ----
# 真实教训：25_tls/Makefile 曾有一条规则重复定义 -DTLS_TESTDATA 且用 $(PWD)
# （make 启动时的目录），而 CFLAGS 里用的是 $(CURDIR)（make -C 切换后的目录）。
# 全仓回归脚本按 make -C <mod> 调用 -> 两者不等 -> 该测试去找
# <仓库根>/tests/data，报 "[FATAL] 缺 leaf.key"，而夹具其实齐备。
# 症状指向"夹具缺失"，真实成因是"路径变量用错"，排查会被彻底带偏。
echo "--- 接线：TLS_TESTDATA 单一产地 ---"
# DIR = <repo>/25_tls/tests/data，故 Makefile 在上两级、仓库根在上三级
MK="$DIR/../../Makefile"
if [ ! -f "$MK" ]; then
    # 找不到就必须是失败 —— 否则 "grep 不到 PWD" 会被当成"未使用 PWD"而假通过，
    # 那正是恒绿守卫的形态。
    bad "找不到 Makefile: $MK（判据失效，不能据此判定通过）"
elif grep -v '^[[:space:]]*#' "$MK" | grep -q 'PWD'; then
    bad "Makefile 仍含 \$(PWD)：make -C 调用时它与 \$(CURDIR) 不等，会导致夹具路径错位"
else
    ok "Makefile 未使用 \$(PWD)（路径统一走 \$(CURDIR)，单一产地）"
fi

echo "--- 接线：make -C 调用下 cke_struct 必须能找到夹具 ---"
REPO="$(cd "$DIR/../../.." && pwd)"
TMPLOG="$(mktemp)"
# 先删二进制再构建：make 不会因 Makefile 变更而重建目标，
# 若沿用旧二进制，改了 -D 也测不出来 —— 守卫会变成恒绿。
# TLS_TESTDATA 只被测试 .c 使用，不影响库 .o，故只重链即可。
rm -f "$REPO/25_tls/build/test_tls_cke_struct"
# 必须从仓库根调用：\$(PWD) 取的是调用方工作目录，只有从仓库根跑 make -C
# 才会与 \$(CURDIR) 不等，缺陷才暴露。若从模块目录内调用，两者恰好相等，
# 守卫会假通过 —— 这正是"单独跑通过、全仓回归失败"的成因。
if ( cd "$REPO" && make -C 25_tls build/test_tls_cke_struct >"$TMPLOG" 2>&1 ); then
    OUT="$("$REPO/25_tls/build/test_tls_cke_struct" 2>&1)"
    echo "$OUT" | sed -n '/result:/p' | sed 's/^/    /'
    if echo "$OUT" | grep -q "0 fail"; then
        ok "make -C 调用 + 运行 cke_struct：0 fail（夹具路径正确）"
    else
        bad "cke_struct 在 make -C 调用下非 0 fail，夹具路径可能仍错位"
    fi
else
    bad "make -C ... build/test_tls_cke_struct 构建失败"
    sed -n '1,10p' "$TMPLOG" | sed 's/^/    /'
fi
rm -f "$TMPLOG"

echo "=== 夹具校验结束 ==="
if [ "$fail" -eq 0 ]; then
    echo "[PASS] 25_tls 夹具语义校验   RC=0"
    exit 0
fi
echo "[FAIL] 25_tls 夹具语义校验   RC=1"
exit 1
