#!/usr/bin/env python3
"""独立进程对照: 用 pycryptodome AES-GCM 产生标准 GHASH 真值.
做法: 对给定 key, 构造 GCM 加密, 使得产生的 tag 等于 GHASH 结果.
      tag = GHASH( (len(A)||len(C))_64 || A_padded || C_padded ) * H  XOR  E_K(J0)
      当 A=C=empty 时, tag = GHASH(0^128)*H XOR E_K(J0) = H*H XOR E_K(J0)
      无法直接等同 GHASH 输出, 因此改用: 加密一个任意明文 P, 同时 update 对应的 AAD,
      记录 tag, 然后用同一 key 解密验证, 并反向用我的实现重算整个 GHASH 链.

更直接的用法: 调用方传 (K, nonce, aad, ct), 本脚本返回 pycryptodome 产生的 tag.
我的实现重算 tag 后与这个真值对比.

stdin:  JSON {"K": hex, "nonce": hex, "aad": hex, "ct": hex}
stdout: JSON {"tag": hex, "H": hex, "j0": hex}
"""
import sys, json, subprocess, os


def _compute(payload: str) -> str:
    env = dict(os.environ)
    p = subprocess.run(
        [sys.executable, "-c", """
import sys, json
from Crypto.Cipher import AES
req = json.loads(sys.stdin.read())
K = bytes.fromhex(req["K"])
nonce = bytes.fromhex(req["nonce"])
aad = bytes.fromhex(req.get("aad", ""))
ct = bytes.fromhex(req["ct"])
c = AES.new(K, AES.MODE_GCM, nonce=nonce)
c.update(aad)
tag = c.encrypt_and_digest(ct)[1]
# 取 H 用于外部对照
from Crypto.Util.number import bytes_to_long
H = AES.new(K, AES.MODE_ECB).encrypt(b'\\x00'*16)
j0 = bytes.fromhex(req.get("j0", ""))
out = {"tag": tag.hex(), "H": H.hex()}
if j0:
    out["j0"] = j0.hex()
print(json.dumps(out))
"""],
        input=payload, capture_output=True, text=True, env=env,
    )
    if p.returncode != 0:
        raise RuntimeError("ref failed: %s | %s" % (p.stdout, p.stderr))
    return p.stdout.strip()


if __name__ == "__main__":
    print(_compute(sys.stdin.read()))
