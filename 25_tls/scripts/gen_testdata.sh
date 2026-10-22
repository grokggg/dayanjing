#!/bin/sh
# 生成 25_tls 测试素材 —— 全部由 OpenSSL 产生，用于跨实现交叉验证。
# 我们的实现若能通过 OpenSSL 产生的签名/证书，才是真的对，不是自己对得上。
#
# 关于 real_chain.pem（重要，曾导致误判）：
#   本沙盒的出站 HTTPS 经过 MITM 代理，openssl s_client 抓到的"服务端证书"
#   是被代理重签过的坏证书（AKI/SKI 不自洽）。连 OpenSSL 自己都验不过它：
#       error 30 at 0 depth lookup: authority and subject key identifier mismatch
#   因此不能用它做"链校验通过"的正向用例 —— 那会把实现正确拒绝的行为判成 FAIL。
#   现在：正向用例用本地自造 CA 签发的合法链；MITM 坏链保留为负向对照，
#   断言"我们的实现拒绝它，且与 OpenSSL 的结论一致"。
set -e
cd "$(dirname "$0")/.."
mkdir -p tests/data

echo "[*] 生成 RSA-2048 密钥"
openssl genrsa -out tests/data/rsa.pem 2048 2>/dev/null

echo "[*] 提取 n / e"
openssl rsa -in tests/data/rsa.pem -modulus -noout 2>/dev/null \
    | sed 's/^Modulus=//' > tests/data/rsa_n.hex
python3 - <<'PY'
import binascii
h = open('tests/data/rsa_n.hex').read().strip()
open('tests/data/rsa_n.bin','wb').write(binascii.unhexlify(h))
open('tests/data/rsa_e.bin','wb').write(bytes([0x01,0x00,0x01]))   # e = 65537
PY

echo "[*] 用 OpenSSL 签名一段消息"
head -c 1000 /dev/urandom > tests/data/rsa_msg.bin
openssl dgst -sha256 -sign tests/data/rsa.pem \
    -out tests/data/rsa_sig.bin tests/data/rsa_msg.bin

echo "[*] 生成自签证书（CN=test.local, SAN=DNS:test.local）"
openssl req -x509 -new -key tests/data/rsa.pem \
    -out tests/data/selfsigned.pem -days 30 \
    -subj "/CN=test.local" -addext "subjectAltName=DNS:test.local" 2>/dev/null

# ---------------------------------------------------------------------------
# 正向链素材：自造 CA 签发的叶子证书（两级链，AKI/SKI 自洽）
# 用途：验证"链校验通过"这条正向路径。OpenSSL 必须也验得过，否则素材无效。
# ---------------------------------------------------------------------------
echo "[*] 生成两级链：CA -> leaf(front.test)"
openssl genrsa -out tests/data/ca.key 2048 2>/dev/null
openssl req -x509 -new -key tests/data/ca.key -sha256 -days 3650 \
    -out tests/data/ca.pem -subj "/CN=Dayanjing Test CA/O=Dayanjing" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" 2>/dev/null

openssl genrsa -out tests/data/leaf.key 2048 2>/dev/null
openssl req -new -key tests/data/leaf.key -out tests/data/leaf.csr \
    -subj "/CN=front.test" 2>/dev/null
cat > tests/data/leaf_ext.cnf <<'CNF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:front.test,DNS:cdn.front.test
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
CNF
openssl x509 -req -in tests/data/leaf.csr -CA tests/data/ca.pem \
    -CAkey tests/data/ca.key -CAcreateserial -days 3650 -sha256 \
    -out tests/data/leaf.pem -extfile tests/data/leaf_ext.cnf 2>/dev/null

# 交叉验证：OpenSSL 必须验得过，否则说明素材本身有问题，不能拿来测我们
if openssl verify -CAfile tests/data/ca.pem tests/data/leaf.pem >/dev/null 2>&1; then
    echo "[+] OpenSSL 交叉验证通过：CA -> leaf 合法（正向素材有效）"
else
    echo "[-] OpenSSL 交叉验证失败：正向素材无效" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 负向素材：MITM 环境下抓到的坏链（AKI/SKI 不自洽）
# 用途：断言我们的实现拒绝它，且与 OpenSSL 结论一致。
# ---------------------------------------------------------------------------
echo "[*] 抓取出站服务端证书链（MITM 环境下预期是坏链）"
if timeout 20 openssl s_client -connect api.github.com:443 \
        -servername api.github.com -tls1_2 -showcerts </dev/null 2>/dev/null \
        | awk '/BEGIN CERT/,/END CERT/' > tests/data/mitm_chain.pem; then
    if [ -s tests/data/mitm_chain.pem ]; then
        if openssl verify -CAfile /etc/zeroproxy-tls/ca-bundle.pem \
                tests/data/mitm_chain.pem >/dev/null 2>&1; then
            echo "[!] MITM 链竟被 OpenSSL 接受，负向对照失效，改用自验"
            cp tests/data/mitm_chain.pem tests/data/real_chain.pem
            rm -f tests/data/mitm_chain.pem
        else
            echo "[+] MITM 坏链已保存（OpenSSL 也拒绝 -> 有效负向素材）"
        fi
    else
        echo "[-] 抓取为空"
        rm -f tests/data/mitm_chain.pem
    fi
else
    echo "[-] 无法抓取"
    rm -f tests/data/mitm_chain.pem
fi

echo "[+] 素材就绪"
ls tests/data/
