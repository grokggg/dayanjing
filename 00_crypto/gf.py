#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
有限域算术: GF(2^8) 与 GF(2^128)
AES (FIPS 197) 与 GHASH (NIST SP 800-38D) 的数学底座。

设计原则:
    1. 不手敲任何查找表。SBOX 由 AES 代数结构程序化生成;
       GF(2^8) 用多项式(peasant)乘法而非预计算 exp/log 表,
       消除"手敲对数表抄错"这一整类缺陷 (R05/R06/R18/R19/R32/R33)。
    2. 所有运算为纯函数, 无模块级可变状态, 天然线程安全 (R32)。
    3. 大整数显式 & 掩码, 防止 Python 大整数无界导致的位泄漏 (R02)。

GF(2^8) 约化多项式:  m(x) = x^8 + x^4 + x^3 + x + 1  = 0x11b  (FIPS 197)
GF(2^128) 约化多项式: m(x) = x^128 + x^7 + x^2 + x + 1  (GHASH, NIST SP 800-38D)
"""

# --------------------------------------------------------------------- #
#  GF(2^8)
# --------------------------------------------------------------------- #

def gf8_mul(a: int, b: int) -> int:
    """
    GF(2^8) 多项式乘法, 俄罗斯农民算法.
    约化多项式 m(x) = x^8 + x^4 + x^3 + x + 1 = 0x11b (FIPS 197 §4.2).
    采用"被乘数左移进位->约化, 乘数右移取位"的经典实现,
    与 FIPS 197 §4.2.1 的 xtime 运算等价.
    """
    a &= 0xFF
    b &= 0xFF
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a <<= 1
        if hi:
            a ^= 0x1B          # 0x11b 去除 x^8 项后低 8 位
        a &= 0xFF
        b >>= 1
    return p


def gf8_pow(x: int, n: int) -> int:
    """GF(2^8) 快速幂, 用于求逆: x^(255) = 1, 故 x^(-1) = x^254."""
    x &= 0xFF
    n &= 0xFF
    if x == 0:
        return 0              # 0 无逆元, 约定返回 0 (R18)
    res = 1
    base = x
    while n:
        if n & 1:
            res = gf8_mul(res, base)
        base = gf8_mul(base, base)
        n >>= 1
    return res


def gf8_inv(x: int) -> int:
    """GF(2^8) 乘法逆元. 费马小定理: x^(2^8-1)=1 => x^(-1)=x^254."""
    return gf8_pow(x, 254)


def gf8_div(a: int, b: int) -> int:
    """GF(2^8) 除法: a / b = a * b^(-1)."""
    return gf8_mul(a, gf8_inv(b))


# --------------------------------------------------------------------- #
#  AES SBOX / INV_SBOX  (FIPS 197 §5.1.1)
# --------------------------------------------------------------------- #

def _build_sbox() -> bytes:
    """
    按 FIPS 197 §5.1.1 代数定义程序化生成 SBOX, 256 字节一次成型.
    映射:  x -> y = A * x^(-1) + c
    其中 A 为 8x8 矩阵, c = 0x63. 矩阵元素 a_{i,j} = 1 当且仅当
    i + j mod 8 属于 {0, 4, 5, 6, 7}, 即:
        b'_i = sum_{j: i+j mod 8 in {0,4,5,6,7}} b_j   (GF(2) 上求和)
    """
    C = 0x63
    sbox = bytearray(256)
    for i in range(256):
        xi = gf8_inv(i)
        out = 0
        for row in range(8):                     # 输出位 row = b'_row
            bit = 0
            for col in range(8):                 # 输入位 col = b_col
                if ((row - col) % 8) in (0, 1, 2, 3, 4):
                    bit ^= (xi >> col) & 1
            bit ^= (C >> row) & 1
            out |= bit << row
        sbox[i] = out
    return bytes(sbox)


SBOX = _build_sbox()


def _build_inv_sbox() -> bytes:
    """SBOX 的逆置换, O(n) 桶排, 不手敲."""
    inv = bytearray(256)
    for i in range(256):
        inv[SBOX[i]] = i
    return bytes(inv)


INV_SBOX = _build_inv_sbox()


# --------------------------------------------------------------------- #
#  GF(2^128)  ——  GHASH (NIST SP 800-38D §2.5)
# --------------------------------------------------------------------- #

# NIST SP 800-38D §2.5: m(x) = x^128 + x^7 + x^2 + x + 1
# 作为 128 位块的最左字节是 0xE1, 其余为 0.
_M128 = 0xE1000000000000000000000000000000 & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


def _gf128_reduce(p: int) -> int:
    """对 256 位中间结果做 GF(2^128) 约化."""
    while p.bit_length() > 128:
        k = p.bit_length() - 129
        p ^= _M128 << k
    return p & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


def gf128_mul(x: int, y: int) -> int:
    """
    GHASH 乘法, NIST SP 800-38D §2.5 Algorithm 1.
    X, Y 为 128 位块, 以整数大端表示 (最高位 = bit 127).
    算法: Z(0)=0, V(0)=X; 对 i=0..127:
        Z(i+1) = Z(i) XOR (Y_i * V(i))
        V(i+1) = V(i) * x   (在 GF(2^128) 上乘本原元 x)
    乘 x 在系数表示下等价于右移一位: 若原最低位(bit0)为 1, 异或 Rb (0xe1).
    """
    MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    x &= MASK
    y &= MASK
    z = 0
    v = x
    for i in range(128):
        # Y_i: 第 i 位, 从最高位(bit127) 到最低位(bit0)
        if (y >> (127 - i)) & 1:
            z ^= v
        # V <- V * x: 右移一位; 若 bit0 原本为 1, 异或 Rb (0xe1 左移到最高字节位)
        lsb = v & 1
        v >>= 1
        if lsb:
            v ^= (0xE1 << 120) & MASK
    return z


def gf128_pow(x: int, n: int) -> int:
    """GF(2^128) 快速幂, 用于推导 H 的各次幂."""
    x &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    res = 1  # 乘法单位元
    base = x
    while n:
        if n & 1:
            res = gf128_mul(res, base)
        base = gf128_mul(base, base)
        n >>= 1
    return res


# --------------------------------------------------------------------- #
#  自检验 (模块加载即跑, 零外部依赖)
# --------------------------------------------------------------------- #

def _selfcheck() -> dict:
    results = {}

    # --- GF(2^8) ---
    # 可逆性: 任意 a != 0, a * inv(a) = 1
    results["gf8_inverse_identity"] = all(
        gf8_mul(i, gf8_inv(i)) == 1 for i in range(1, 256)
    )
    results["gf8_inv_zero"] = gf8_inv(0) == 0
    # 已知等式抽查 (来自 FIPS 197 测试向量)
    results["gf8_mul_known_1"] = gf8_mul(0xD4, gf8_inv(0xD4)) == 0x01
    results["gf8_mul_known_2"] = gf8_mul(0x53, 0xCA) == 0x01
    results["gf8_mul_known_3"] = gf8_mul(0x57, 0x83) == 0xC1

    # --- SBOX ---
    # 验证策略: 不依赖手敲的 256 字节表 (R31 教训), 改用代数不变量
    sbox = SBOX
    results["sbox_len"] = len(sbox) == 256
    results["sbox_bijection"] = len(set(sbox)) == 256
    # 双射 + 互逆: SBOX[INV_SBOX[x]] == x 且 INV_SBOX[SBOX[x]] == x
    results["inv_sbox_is_inverse"] = all(
        INV_SBOX[sbox[i]] == i for i in range(256)
    )
    results["sbox_is_inv_inverse"] = all(
        sbox[INV_SBOX[i]] == i for i in range(256)
    )
    # FIPS 197 已知映射抽查 (仅保留程序化核对过的值)
    results["sbox_known_00"] = sbox[0x00] == 0x63
    results["sbox_known_01"] = sbox[0x01] == 0x7C
    results["sbox_known_53"] = sbox[0x53] == 0xED
    results["sbox_known_ff"] = sbox[0xFF] == 0x16

    # --- GF(2^128) ---
    # 单位元: 多项式 1, 即整数 1 (按 GHASH 大端字节表示)
    h = 0x66E94BD4EF8A2C3B884CFA59CA342B2E1
    results["gf128_identity"] = gf128_mul(h, 1) == h
    results["gf128_identity_rev"] = gf128_mul(1, h) == h
    results["gf128_zero"] = gf128_mul(h, 0) == 0
    # 交换律 / 结合律 (随机抽值, 大数域)
    import random
    random.seed(0xC0DECAFE)
    a = random.getrandbits(128)
    b = random.getrandbits(128)
    c = random.getrandbits(128)
    results["gf128_commutative"] = gf128_mul(a, b) == gf128_mul(b, a)
    results["gf128_associative"] = (
        gf128_mul(gf128_mul(a, b), c) == gf128_mul(a, gf128_mul(b, c))
    )
    # 逆元存在性: 任意非零 h, h * inv(h) = 1  (GF(2^128) 中可构造)
    inv_h = gf128_pow(h, (1 << 128) - 2)   # 费马: h^(2^128-1)=1
    results["gf128_inverse"] = gf128_mul(h, inv_h) == 1
    # 129 位溢出已被掩码
    big = gf128_mul((1 << 128) - 1, (1 << 128) - 1)
    results["gf128_no_overflow"] = big.bit_length() <= 128

    return results


if __name__ == "__main__":
    r = _selfcheck()
    failed = [k for k, v in r.items() if not v]
    for k, v in r.items():
        print(f"{'PASS' if v else 'FAIL':4} {k}")
    print("---")
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("ALL GF SELFCHECKS PASSED")
