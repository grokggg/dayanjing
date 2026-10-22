#!/bin/sh
# 生成 25_tls 测试素材 —— 全部由 OpenSSL 产生，用于跨实现交叉验证。
# 我们的实现若能通过 OpenSSL 产生的签名/证书，才是真的对，不是自己对得上。
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

echo "[*] 尝试抓取真实服务端证书链（用于真实链校验）"
if timeout 20 openssl s_client -connect api.github.com:443 \
        -servername api.github.com -tls1_2 -showcerts </dev/null 2>/dev/null \
        | awk '/BEGIN CERT/,/END CERT/' > tests/data/real_chain.pem; then
    if [ -s tests/data/real_chain.pem ]; then
        echo "[+] 真实链已保存 ($(grep -c 'BEGIN CERT' tests/data/real_chain.pem) 张)"
    else
        echo "[-] 抓取为空，真实链用例将跳过"
        rm -f tests/data/real_chain.pem
    fi
else
    echo "[-] 无法抓取，真实链用例将跳过"
    rm -f tests/data/real_chain.pem
fi

echo "[+] 素材就绪"
ls -la tests/data/
