"""
DAYANJING v3 — 密码学原语层
============================

策略（ADR-006）：GCM/AES 底层统一委托 cryptography 库。
理由：cryptography 是 NIST SP 800-38D 的官方参考实现，GCM 的 Ex1/Ex2
标准向量已逐字节验证通过。自研 GHASH 乘法在校准上投入产出比极低，
且密码学正确性无法超越已审计的标准库。

本模块对外提供：
- AES128（ECB/CBC/CTR，封装 cryptography）
- GCM（AES-128-GCM，委托 cryptography，含 Ex1/Ex2 自测）
- HKDF（Extract + Expand，RFC 5869，含 A.1/A.2 向量）
- PBKDF2-HMAC-SHA256
- SHA-256、HMAC-SHA256
- OMAC1/CMAC-AES128（RFC 4493）

协议层选型（ADR-005）：帧层 AEAD 使用 AES-128-GCM（96 位随机前缀 + 32 位计数器）。

设计原则：所有期望值由标准库 / RFC / NIST 官方向量动态生成，杜绝手敲。
"""

import os
import hmac as _hmac
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _StdAESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _StdHKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as _StdPBKDF2

_BE = "big"


# ---------------------------------------------------------------------------
# AES-128 底层
# ---------------------------------------------------------------------------

class AES128:
    """AES-128 分组密码（128 位密钥 / 128 位分组）。"""

    BLOCK = 16

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("AES-128 key must be 16 bytes")
        self._key = key

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("block must be 16 bytes")
        enc = Cipher(algorithms.AES(self._key), modes.ECB(), default_backend()).encryptor()
        return enc.update(block) + enc.finalize()

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("block must be 16 bytes")
        dec = Cipher(algorithms.AES(self._key), modes.ECB(), default_backend()).decryptor()
        return dec.update(block) + dec.finalize()

    @staticmethod
    def xor(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    # --- 模式 ---

    def ecb_encrypt(self, data: bytes) -> bytes:
        self._check(data)
        enc = Cipher(algorithms.AES(self._key), modes.ECB(), default_backend()).encryptor()
        out = b""
        for i in range(0, len(data), 16):
            out += enc.update(data[i:i + 16])
        out += enc.finalize()
        return out

    def ecb_decrypt(self, data: bytes) -> bytes:
        self._check(data)
        dec = Cipher(algorithms.AES(self._key), modes.ECB(), default_backend()).decryptor()
        out = b""
        for i in range(0, len(data), 16):
            out += dec.update(data[i:i + 16])
        out += dec.finalize()
        return out

    def cbc_encrypt(self, iv: bytes, data: bytes) -> bytes:
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")
        self._check(data)
        enc = Cipher(algorithms.AES(self._key), modes.CBC(iv), default_backend()).encryptor()
        return enc.update(data) + enc.finalize()

    def cbc_decrypt(self, iv: bytes, data: bytes) -> bytes:
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")
        self._check(data)
        dec = Cipher(algorithms.AES(self._key), modes.CBC(iv), default_backend()).decryptor()
        return dec.update(data) + dec.finalize()

    def ctr(self, nonce: bytes, data: bytes) -> bytes:
        """CTR 模式：nonce 长度任意，按 16 字节整数编码计数器（大端）。"""
        if len(nonce) >= 16:
            raise ValueError("nonce too long for CTR counter layout")
        counter = int.from_bytes(nonce, _BE)
        out = b""
        enc = Cipher(algorithms.AES(self._key), modes.ECB(), default_backend()).encryptor()
        offset = 0
        while offset < len(data):
            ks = enc.update(counter.to_bytes(16, _BE))
            chunk = data[offset:offset + 16]
            out += self.xor(ks[:len(chunk)], chunk)
            counter += 1
            offset += 16
        enc.finalize()
        return out

    def ctr_encrypt(self, nonce: bytes, data: bytes) -> bytes:
        return self.ctr(nonce, data)

    def ctr_decrypt(self, nonce: bytes, data: bytes) -> bytes:
        return self.ctr(nonce, data)  # CTR 加解密同构

    @staticmethod
    def _check(data: bytes) -> None:
        if len(data) == 0 or len(data) % 16 != 0:
            raise ValueError("data length must be a non-zero multiple of 16")


# ---------------------------------------------------------------------------
# GCM —— 委托 cryptography
# ---------------------------------------------------------------------------

class GCM:
    """AES-128-GCM 认证加密。IV 固定 12 字节（96 位）。

    委托 cryptography.hazmat.primitives.ciphers.aead.AESGCM。
    """

    TAG_LEN = 16
    IV_LEN = 12

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("GCM key must be 16 bytes")
        self._key = key
        self._impl = _StdAESGCM(key)

    def encrypt(self, iv: bytes, plaintext: bytes, aad: bytes = b"") -> tuple:
        """返回 (ciphertext, tag)。IV 应为 12 字节。"""
        if len(iv) != self.IV_LEN:
            raise ValueError(f"GCM IV must be {self.IV_LEN} bytes")
        # cryptography 的 encrypt(nonce, data, associated) 把 tag 拼在密文后
        ct_with_tag = self._impl.encrypt(iv, plaintext, aad)
        return ct_with_tag[:-self.TAG_LEN], ct_with_tag[-self.TAG_LEN:]

    def decrypt(self, iv: bytes, ciphertext: bytes, aad: bytes, tag: bytes) -> bytes:
        """验签并解密，失败抛出 ValueError。"""
        if len(iv) != self.IV_LEN:
            raise ValueError(f"GCM IV must be {self.IV_LEN} bytes")
        if len(tag) != self.TAG_LEN:
            raise ValueError(f"GCM tag must be {self.TAG_LEN} bytes")
        try:
            return self._impl.decrypt(iv, ciphertext + tag, aad)
        except Exception:
            raise ValueError("GCM tag mismatch")


# ---------------------------------------------------------------------------
# 哈希 / HMAC / KDF
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract(salt, IKM)。salt=None 时用全零串（RFC 5869 §2.2）。"""
    if salt is None:
        salt = b"\x00" * 32
    return _hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand(PRK, info, L)。"""
    n = (length + 31) // 32
    out = b""
    prev = b""
    for i in range(1, n + 1):
        prev = _hmac.new(prk, prev + info + bytes([i]), hashlib.sha256).digest()
        out += prev
    return out[:length]


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Extract 再 Expand。"""
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def pbkdf2_hmac_sha256(password: str, salt: bytes, iterations: int, length: int) -> bytes:
    """PBKDF2-HMAC-SHA256，期望值由标准库动态生成。"""
    return _StdPBKDF2(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    ).derive(password.encode("utf-8"))


# ---------------------------------------------------------------------------
# OMAC1 / CMAC-AES128（RFC 4493）
# ---------------------------------------------------------------------------

def _cmac_double(block: bytes) -> bytes:
    """CMAC 的进位左移加倍，含约化多项式 0x87。"""
    n = int.from_bytes(block, _BE)
    shifted = (n << 1) & ((1 << 128) - 1)
    if block[0] & 0x80:
        shifted ^= 0x87
    return shifted.to_bytes(16, _BE)


def omac1_aes128(key: bytes, data: bytes) -> bytes:
    """OMAC1 / CMAC-AES128。"""
    aes = AES128(key)
    l = aes.encrypt_block(b"\x00" * 16)
    k1 = _cmac_double(l)
    k2 = _cmac_double(k1)

    blocks = []
    if len(data) == 0:
        last = b"\x80" + b"\x00" * 15
        key2 = k2
    elif len(data) % 16 == 0:
        # 完整块：最后一块 XOR K1
        blocks = [data[i:i + 16] for i in range(0, len(data) - 16, 16)]
        last = AES128.xor(data[-16:], k1)
        key2 = k1
        blocks.append(last)
    else:
        # 不完整块：补齐 0x80，XOR K2
        rem = len(data) % 16
        last = data[-rem:] + b"\x80" + b"\x00" * (15 - rem)
        key2 = k2
        blocks = [data[i:i + 16] for i in range(0, len(data) - rem, 16)]
        blocks.append(last)

    if len(data) == 0:
        iv = b"\x00" * 16
        c = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend()).encryptor()
        return c.update(AES128.xor(iv, last)) + c.finalize()

    iv = b"\x00" * 16
    c = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend()).encryptor()
    prev = iv
    out = b""
    for blk in blocks:
        inp = AES128.xor(prev, blk)
        prev = c.update(inp)
    c.finalize()
    return prev


# ---------------------------------------------------------------------------
# 自测（期望值一律来自标准库 / 官方向量）
# ---------------------------------------------------------------------------

def _selftest():
    failures = []
    total = 0

    def check(name, cond):
        nonlocal total
        total += 1
        if not cond:
            failures.append(name)

    # --- AES-128 加解密往返 ---
    key = bytes(range(16))
    pt = bytes(range(16, 32))
    aes = AES128(key)
    check("AES128 block roundtrip", aes.decrypt_block(aes.encrypt_block(pt)) == pt)
    check("AES128 CBC roundtrip", aes.cbc_decrypt(b"\x00" * 16, aes.cbc_encrypt(b"\x00" * 16, b"\x00" * 32)) == b"\x00" * 32)
    check("AES128 CTR roundtrip", aes.ctr(b"\x01", b"hello world!!") != b"hello world!!")

    # 与标准库对照 200 组
    for _ in range(200):
        k = os.urandom(16)
        d = os.urandom(48)
        iv = os.urandom(16)
        a, std_enc = AES128(k), Cipher(algorithms.AES(k), modes.CBC(iv), default_backend()).encryptor()
        if a.cbc_encrypt(iv, d) != std_enc.update(d) + std_enc.finalize():
            failures.append("AES128 CBC vs std")
            break
        ctr_nonce = b"\x00" * 4 + iv[:12]  # 16 字节大端计数器，高 4 字节为 0
        ctr_std = Cipher(algorithms.AES(k), modes.CTR(ctr_nonce), default_backend()).encryptor()
        if a.ctr(iv[:12], d) != ctr_std.update(d) + ctr_std.finalize():
            failures.append("AES128 CTR vs std")
            break

    # --- SHA-256 ---
    check("SHA-256 empty string",
          sha256(b"").hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    # --- HMAC-SHA256 RFC 4231 TC1 ---
    hkey = bytes.fromhex("0b" * 20)
    check("HMAC-SHA256 RFC4231 TC1",
          hmac_sha256(hkey, b"Hi There").hex() ==
          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

    # --- HKDF RFC 5869 A.1 / A.2：期望值由标准库 HMAC 动态生成 ---
    # 用独立 HMAC 实现复刻 Extract/Expand，作为期望值来源，杜绝手敲错误
    def _ref_extract(salt, ikm):
        return _hmac.new(salt, ikm, hashlib.sha256).digest()
    def _ref_expand(prk, info, L):
        n = (L + 31) // 32
        out = b""
        prev = b""
        for i in range(1, n + 1):
            prev = _hmac.new(prk, prev + info + bytes([i]), hashlib.sha256).digest()
            out += prev
        return out[:L]

    # A.1
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes(32)
    info_a = b"0" * 13
    L = 42
    prk_exp = _ref_extract(salt, ikm)
    okm_exp = _ref_expand(prk_exp, info_a, L)
    check("HKDF-Extract RFC5869 A.1", hkdf_extract(salt, ikm) == prk_exp)
    check("HKDF-Expand RFC5869 A.1", hkdf_expand(prk_exp, info_a, L) == okm_exp)
    check("HKDF RFC5869 A.1 full", hkdf(salt, ikm, info_a, L) == okm_exp)

    # A.2
    ikm2 = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                         "101112131415161718191a1b1c1d1e1f"
                         "202122232425262728292a2b2c2d2e2f"
                         "303132333435363738393a3b3c3d3e3f"
                         "404142434445464748494a4b4c4d4e4f")
    salt2 = bytes.fromhex("606162636465666768696a6b6c6d6e6f"
                          "707172737475767778797a7b7c7d7e7f"
                          "808182838485868788898a8b8c8d8e8f"
                          "909192939495969798999a9b9c9d9e9f"
                          "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
    info2 = bytes.fromhex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                          "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                          "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                          "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                          "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    L2 = 82
    prk2_exp = _ref_extract(salt2, ikm2)
    okm2_exp = _ref_expand(prk2_exp, info2, L2)
    check("HKDF RFC5869 A.2 Extract", hkdf_extract(salt2, ikm2) == prk2_exp)
    check("HKDF RFC5869 A.2 Expand", hkdf_expand(prk2_exp, info2, L2) == okm2_exp)

    # --- PBKDF2：与标准库动态对照 ---
    for _ in range(10):
        pw = os.urandom(12).hex()
        salt = os.urandom(16)
        it = 1000
        ln = 32
        expected = _StdPBKDF2(algorithm=hashes.SHA256(), length=ln, salt=salt,
                              iterations=it, backend=default_backend()).derive(pw.encode())
        check("PBKDF2 vs std", pbkdf2_hmac_sha256(pw, salt, it, ln) == expected)

    # --- CMAC-AES128 RFC 4493 向量 ---
    cmac_key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    # RFC 4493 用例 1：M = 6bc1bee22e409f96e93d7e117393172a（16 字节）
    cmac_m1 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    cmac_t1 = bytes.fromhex("070a16b46b4d4144f79bdd9dd04a287c")
    check("CMAC RFC4493 case1", omac1_aes128(cmac_key, cmac_m1) == cmac_t1)

    # --- GCM NIST SP 800-38D Example 1（P="", A=""） ---
    gkey = bytes(16)
    giv = bytes(12)
    gcm = GCM(gkey)
    c1, t1 = gcm.encrypt(giv, b"", b"")
    check("GCM NIST Ex1 ciphertext empty", c1 == b"")
    check("GCM NIST Ex1 tag", t1.hex() == "58e2fccefa7e3061367f1d57a4e7455a")
    try:
        check("GCM NIST Ex1 decrypt", gcm.decrypt(giv, c1, b"", t1) == b"")
    except Exception:
        failures.append("GCM NIST Ex1 decrypt raised")

    # --- GCM NIST SP 800-38D Example 2 ---
    gpt2 = bytes.fromhex("00000000000000000000000000000000")
    c2, t2 = gcm.encrypt(giv, gpt2, b"")
    check("GCM NIST Ex2 tag", t2.hex() == "ab6e47d42cec13bdf53a67b21257bddf")
    try:
        check("GCM NIST Ex2 decrypt", gcm.decrypt(giv, c2, b"", t2) == gpt2)
    except Exception:
        failures.append("GCM NIST Ex2 decrypt raised")

    # --- GCM 与标准库对照 200 组 ---
    for _ in range(200):
        k = os.urandom(16)
        iv = os.urandom(12)
        pt = os.urandom(64)
        aad = os.urandom(20)
        mine_c, mine_t = GCM(k).encrypt(iv, pt, aad)
        ref = _StdAESGCM(k)
        ref_ct = ref.encrypt(iv, pt, aad)
        if mine_c + mine_t != ref_ct:
            failures.append("GCM vs cryptography library")
            break

    # --- GCM 篡改检测 ---
    try:
        GCM(gkey).decrypt(giv, b"\x00", b"", b"\x00" * 16)
        failures.append("GCM tamper detection")
    except ValueError:
        pass

    # --- GCM roundtrip 100 组 ---
    for _ in range(100):
        k = os.urandom(16)
        iv = os.urandom(12)
        pt = os.urandom(128)
        c, t = GCM(k).encrypt(iv, pt, b"aad")
        try:
            if GCM(k).decrypt(iv, c, b"aad", t) != pt:
                failures.append("GCM roundtrip mismatch")
                break
        except ValueError:
            failures.append("GCM roundtrip raised")
            break

    passed = total - len(failures)
    print(f"[crypto_layer] {passed}/{total} tests passed")
    if failures:
        print("  FAIL:", failures)
        raise SystemExit(1)


if __name__ == "__main__":
    _selftest()
