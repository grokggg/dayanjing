#include "crypto.h"

#include <string.h>
#include <stdint.h>

/* ==================== Poly1305（RFC 7539 §2.5）====================
 *
 * 采用 OpenBSD / Monocypher 风格的 26-bit limb 实现。
 * 130-bit 数用 5 个 26-bit limbs（小端）：
 *   value = v[0] + v[1]*2^26 + v[2]*2^52 + v[3]*2^78 + v[4]*2^104
 *
 * 运算：
 *   - 加法：limb 直接加，然后归约
 *   - 乘法：schoolbook 5x5，用 64-bit 累加器，再归约
 *   - 归约：把 v[4] 的溢出折叠（2^130 ≡ 5 mod P）
 *
 * 这个实现的关键 invariant：v[i] 可以暂时超过 26-bit（最多到 30-bit），
 * 但每次运算后都调用 p1305_mod 收紧到 < P。
 */

typedef struct {
    uint32_t v[5];   /* 26-bit limbs */
} p1305_t;

/* ============ 归约：a < P ============ */
static void p1305_mod(p1305_t *a) {
    uint32_t c;

    /* 第一遍：v[0..3] 进位传播，v[4] 保留溢出 */
    c = a->v[0] >> 26; a->v[0] &= 0x3ffffff; a->v[1] += c;
    c = a->v[1] >> 26; a->v[1] &= 0x3ffffff; a->v[2] += c;
    c = a->v[2] >> 26; a->v[2] &= 0x3ffffff; a->v[3] += c;
    c = a->v[3] >> 26; a->v[3] &= 0x3ffffff; a->v[4] += c;

    /* v[4] 可能很大（最多约 2^30）。把 v[4] >> 26 的部分当作 2^130 的倍数折叠：
     * 2^130 ≡ 5 (mod P)，所以每 2^26 个 v[4] 单位 → 低位加 5。
     */
    uint32_t q = a->v[4] >> 26;
    a->v[4] &= 0x3ffffff;
    /* q * 5 加到 v[0]，可能有进位链 */
    uint64_t s = (uint64_t)a->v[0] + (uint64_t)q * 5;
    a->v[0] = (uint32_t)(s & 0x3ffffff); s >>= 26;
    s += a->v[1]; a->v[1] = (uint32_t)(s & 0x3ffffff); s >>= 26;
    s += a->v[2]; a->v[2] = (uint32_t)(s & 0x3ffffff); s >>= 26;
    s += a->v[3]; a->v[3] = (uint32_t)(s & 0x3ffffff); s >>= 26;
    a->v[4] += (uint32_t)s;   /* 这次的溢出再折叠 */

    /* 若 v[4] 又溢出，再折叠一次（最多 2 次，因为 q < 2^4） */
    q = a->v[4] >> 26;
    if (q) {
        a->v[4] &= 0x3ffffff;
        uint64_t s2 = (uint64_t)a->v[0] + (uint64_t)q * 5;
        a->v[0] = (uint32_t)(s2 & 0x3ffffff); s2 >>= 26;
        s2 += a->v[1]; a->v[1] = (uint32_t)(s2 & 0x3ffffff); s2 >>= 26;
        s2 += a->v[2]; a->v[2] = (uint32_t)(s2 & 0x3ffffff); s2 >>= 26;
        s2 += a->v[3]; a->v[3] = (uint32_t)(s2 & 0x3ffffff); s2 >>= 26;
        a->v[4] += (uint32_t)s2;
        a->v[4] &= 0x3ffffff;
    }

    /* 最终：若 a >= 2^130 - 5，减 P。
     * P = 2^130 - 5，26-bit limbs：{0x3fffffb, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff}
     */
    static const uint32_t Pl[5] = {0x3fffffb, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff};
    int ge = 1;
    for (int i = 4; i >= 0; i--) {
        if (a->v[i] < Pl[i]) { ge = 0; break; }
        if (a->v[i] > Pl[i]) { ge = 1; break; }
    }
    if (ge) {
        int64_t borrow = 0;
        for (int i = 0; i < 5; i++) {
            int64_t ss = (int64_t)a->v[i] - (int64_t)Pl[i] - borrow;
            a->v[i] = (uint32_t)(ss & 0x3ffffff);
            borrow = (ss < 0) ? 1 : 0;
        }
    }
}

/* a += b */
static void p1305_add(p1305_t *a, const p1305_t *b) {
    a->v[0] += b->v[0];
    a->v[1] += b->v[1];
    a->v[2] += b->v[2];
    a->v[3] += b->v[3];
    a->v[4] += b->v[4];
    p1305_mod(a);
}

/* a *= r（mod 2^130 - 5），r 已钳位 */
static void p1305_mul(p1305_t *a, const p1305_t *r) {
    /* schoolbook 5x5，用 64-bit 累加器。
     * 26x26 = 52 bit，每项 < 2^52，5x5 总和 < 5*2^52 < 2^55，
     * 用 uint64_t 安全。
     */
    const uint64_t a0 = a->v[0], a1 = a->v[1], a2 = a->v[2], a3 = a->v[3], a4 = a->v[4];
    const uint64_t r0 = r->v[0], r1 = r->v[1], r2 = r->v[2], r3 = r->v[3], r4 = r->v[4];

    uint64_t h[10] = {0};
    /* 用 double-and-add 风格，避免 10 个临时数组：
     * h[k] = sum_{i+j=k} a[i]*r[j]
     */
    h[0] = a0 * r0;
    h[1] = a0 * r1 + a1 * r0;
    h[2] = a0 * r2 + a1 * r1 + a2 * r0;
    h[3] = a0 * r3 + a1 * r2 + a2 * r1 + a3 * r0;
    h[4] = a0 * r4 + a1 * r3 + a2 * r2 + a3 * r1 + a4 * r0;
    h[5] = a1 * r4 + a2 * r3 + a3 * r2 + a4 * r1;
    h[6] = a2 * r4 + a3 * r3 + a4 * r2;
    h[7] = a3 * r4 + a4 * r3;
    h[8] = a4 * r4;

    /* 现在 h[i] 是 2^(26i) 的系数，但每个 h[i] 可能 > 2^26。
     * 把它们重新按 26-bit 基数展开成 9 个 limb，然后折叠进 5 个。
     *
     * 方法：把 h[i] 看成 52-bit 数（每两个 limb 一个），
     * 展开成 26-bit 的 t[0..9]：
     *   t[2i]   = h[i] & 3ffffff
     *   t[2i+1] = h[i] >> 26
     */
    uint64_t t[10];
    t[0] = h[0] & 0x3ffffff;
    t[1] = (h[0] >> 26) + (h[1] & 0x3ffffff);
    t[2] = (h[1] >> 26) + (h[2] & 0x3ffffff);
    t[3] = (h[2] >> 26) + (h[3] & 0x3ffffff);
    t[4] = (h[3] >> 26) + (h[4] & 0x3ffffff);
    t[5] = (h[4] >> 26) + (h[5] & 0x3ffffff);
    t[6] = (h[5] >> 26) + (h[6] & 0x3ffffff);
    t[7] = (h[6] >> 26) + (h[7] & 0x3ffffff);
    t[8] = (h[7] >> 26) + (h[8] & 0x3ffffff);
    t[9] = (h[8] >> 26);

    /* 进位传播 t[0..9]，折叠 t[5..9] 进 t[0..4] */
    /* 利用 2^130 ≡ 5 (mod P)：
     *   t[5] 是 2^130 的系数 → 加 t[5]*5 到低位
     *   t[6] 是 2^156 的系数 = 2^26 * 2^130 → 加 t[6]*5 到 limb 1 开始的位置
     *   ... 即 t[k] (k>=5) 等价于 t[k] * 5 * 2^(26*(k-5))
     *
     * 正确做法：把 t[5..9] 当成一个高位 130-bit 数，乘以 5 后加回低位。
     * 由于乘法会再次产生高位，递归处理。
     */

    /* 第一步：把 t[5..9] * 5 的结果加回 t[0..4]，可能产生新的 t[5] 溢出 */
    /* t[5]*5 加到 limb 0..1（5 < 2^26，只占 3 bit） */
    uint64_t f5 = t[5] * 5;
    t[0] += f5 & 0x3ffffff;
    t[1] += f5 >> 26;

    uint64_t f6 = t[6] * 5;
    t[1] += f6 & 0x3ffffff;
    t[2] += f6 >> 26;

    uint64_t f7 = t[7] * 5;
    t[2] += f7 & 0x3ffffff;
    t[3] += f7 >> 26;

    uint64_t f8 = t[8] * 5;
    t[3] += f8 & 0x3ffffff;
    t[4] += f8 >> 26;

    uint64_t f9 = t[9] * 5;
    t[4] += f9 & 0x3ffffff;
    /* t[5] 可能再次溢出（来自 f6>>26..f9>>26 的累积） */

    /* 现在进位传播 t[0..4]，溢出的部分重新折叠 */
    /* 先做完整进位，把所有进位收集到 t[5] 及以上 */
    uint64_t carry = t[0] >> 26; t[0] &= 0x3ffffff; t[1] += carry;
    carry = t[1] >> 26; t[1] &= 0x3ffffff; t[2] += carry;
    carry = t[2] >> 26; t[2] &= 0x3ffffff; t[3] += carry;
    carry = t[3] >> 26; t[3] &= 0x3ffffff; t[4] += carry;
    carry = t[4] >> 26; t[4] &= 0x3ffffff;
    /* carry 现在是 2^130 的倍数，需要 *5 加回 */
    while (carry > 0) {
        uint64_t fc = carry * 5;
        t[0] += fc & 0x3ffffff; carry = t[0] >> 26; t[0] &= 0x3ffffff;
        t[1] += (fc >> 26) + carry; carry = t[1] >> 26; t[1] &= 0x3ffffff;
        t[2] += carry; carry = t[2] >> 26; t[2] &= 0x3ffffff;
        t[3] += carry; carry = t[3] >> 26; t[3] &= 0x3ffffff;
        t[4] += carry; carry = t[4] >> 26; t[4] &= 0x3ffffff;
    }

    a->v[0] = (uint32_t)t[0];
    a->v[1] = (uint32_t)t[1];
    a->v[2] = (uint32_t)t[2];
    a->v[3] = (uint32_t)t[3];
    a->v[4] = (uint32_t)t[4];

    /* 最终 mod P */
    p1305_mod(a);
}

/* 从字节构造块（小端 130-bit）。
 * 16 字节完整块：bit 128 = 1
 * n<16 字节 final 块：bit n*8 = 1
 */
static void block_from_msg(p1305_t *out, const uint8_t *msg, size_t len, int final) {
    /* 块 = msg（最多 16 字节）+ 标记位（final: bit len*8=1，完整块: bit 128=1）+ 零填充 */
    uint8_t buf[17] = {0};  /* 136 bit */
    if (msg && len > 0) {
        size_t n = len < 16 ? len : 16;
        memcpy(buf, msg, n);
    }
    if (final && len < 16) {
        size_t bit = len * 8;
        buf[bit >> 3] |= (uint8_t)(1 << (bit & 7));
    } else {
        buf[16] = 0x01;  /* bit 128 = 1 */
    }

    /* 把 17 字节（136 bit）拼成 __int128：buf 是小端，所以
     *   low  = buf[0..15] 小端 = 128-bit
     *   high = buf[16] 作为第 128..135 bit
     * 我们用 (low + (high128 << 128)) 但因为不能左移 128，改为直接提取 limb。
     *
     * limb i = (whole >> (26*i)) & 0x3ffffff
     * whole = L + H*2^128，其中 L = 128-bit low，H = buf[16]（8-bit high）
     * limb i 从 L 取 26 bit，跨越 L/H 边界时从 H 补。
     */
    unsigned __int128 L = 0;
    for (int i = 15; i >= 0; i--) L = (L << 8) | buf[i];
    /* L 现在 = buf[0] + buf[1]*2^8 + ... + buf[15]*2^120（小端 128-bit）... 
     * 不对，上面循环得到的是大端。改小端： */
    L = 0;
    for (int i = 0; i < 16; i++) L |= (unsigned __int128)buf[i] << (8 * i);
    uint8_t H = buf[16];  /* bit 128..135 */

    for (int i = 0; i < 5; i++) {
        int bit = i * 26;
        if (bit + 26 <= 128) {
            /* limb 完全在 L 内 */
            out->v[i] = (uint32_t)((L >> bit) & 0x3ffffffULL);
        } else if (bit < 128) {
            /* limb 跨越 128-bit 边界：取 L 的低部分 + H 的高部分 */
            int low_bits = 128 - bit;
            unsigned __int128 low = (L >> bit) & ((1ULL << low_bits) - 1);
            int high_bits = 26 - low_bits;  /* <= 26 */
            unsigned __int128 high = (unsigned __int128)(H & ((1 << high_bits) - 1)) << low_bits;
            out->v[i] = (uint32_t)(low | high);
        } else {
            /* limb 完全在 H 内（bit >= 128） */
            int shift = bit - 128;
            out->v[i] = (uint32_t)((H >> shift) & 0x3f);  /* 最多 8 bit */
        }
    }
}

/* 计算 Poly1305 MAC */
crypto_err_t crypto_poly1305(uint8_t mac[16], const uint8_t *msg, size_t msg_len,
                            const uint8_t key[32]) {
    if (!mac || !key) return CRYPTO_ERR;

    /* r 钳位：RFC 7539 §2.5.1 */
    uint8_t r_bytes[16];
    memcpy(r_bytes, key, 16);
    r_bytes[3]  &= 0x0f; r_bytes[7]  &= 0x0f;
    r_bytes[11] &= 0x0f; r_bytes[15] &= 0x0f;
    r_bytes[4]  &= 0xfc; r_bytes[8]  &= 0xfc;
    r_bytes[12] &= 0xfc;

    /* r 转 26-bit limb：128-bit 小端整数按 26-bit 提取 */
    unsigned __int128 rv = 0;
    for (int i = 0; i < 16; i++) rv |= (unsigned __int128)r_bytes[i] << (8 * i);

    p1305_t r;
    for (int i = 0; i < 5; i++) {
        r.v[i] = (uint32_t)((rv >> (26 * i)) & 0x3ffffffULL);
    }

    p1305_t acc = {{0}};

    size_t off = 0;
    while (msg_len >= 16) {
        p1305_t blk;
        block_from_msg(&blk, msg + off, 16, 0);
        p1305_add(&acc, &blk);
        p1305_mul(&acc, &r);
        off += 16;
        msg_len -= 16;
    }
    if (msg_len > 0) {
        p1305_t blk;
        block_from_msg(&blk, msg + off, msg_len, 1);
        p1305_add(&acc, &blk);
        p1305_mul(&acc, &r);
    }

    /* acc -> 130-bit __int128 + s */
    unsigned __int128 accv = 0;
    for (int i = 4; i >= 0; i--) accv = (accv << 26) | acc.v[i];

    unsigned __int128 sv = 0;
    for (int i = 31; i >= 16; i--) sv = (sv << 8) | key[i];   /* s 小端 */

    unsigned __int128 tagv = accv + sv;   /* 130-bit + 128-bit = 最多 131-bit */
    /* 取低 128-bit，小端写入 mac */
    uint64_t low128 = (uint64_t)(tagv & ((unsigned __int128)0xffffffffffffffffULL));
    for (int i = 0; i < 8; i++) mac[i] = (uint8_t)((low128 >> (i * 8)) & 0xff);
    uint64_t high128 = (uint64_t)((tagv >> 64) & ((unsigned __int128)0xffffffffffffffffULL));
    for (int i = 0; i < 8; i++) mac[8 + i] = (uint8_t)((high128 >> (i * 8)) & 0xff);

    crypto_wipe(r_bytes, sizeof(r_bytes));
    crypto_wipe(&acc, sizeof(acc));
    crypto_wipe(&r, sizeof(r));
    return CRYPTO_OK;
}
