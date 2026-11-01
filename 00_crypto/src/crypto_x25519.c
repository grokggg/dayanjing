/*
 * DAYANJING v4 — 00_crypto/src/crypto_x25519.c
 *
 * X25519 (RFC 7748) 自研实现。设计说明见 include/crypto_x25519.h。
 * 域 GF(2^255-19)，16-bit limb 小端表示。
 */

#include "crypto_x25519.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* 域元素：16 个 16-bit limb，value = SUM l[i] * 2^(16i)  (mod p)      */
/* ------------------------------------------------------------------ */

typedef struct { uint32_t l[16]; } fe;

/* p = 2^255 - 19 = 0x7fff ffff...ffed */
static const fe FE_P = {{
    0xffed, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x7fff
}};

/* 2p —— 供 fe_sub 走"加 2p 再减"的正值路径 */
static const fe FE_2P = {{
    0xffda, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
}};

static void fe_zero(fe *o) { memset(o->l, 0, sizeof o->l); }

static void fe_copy(fe *o, const fe *a) { memcpy(o->l, a->l, sizeof o->l); }

static void fe_frombytes(fe *o, const uint8_t b[32]) {
    for (int i = 0; i < 16; i++)
        o->l[i] = (uint32_t)b[2 * i] | ((uint32_t)b[2 * i + 1] << 8);
    /* X25519 接收 u 坐标时屏蔽最高位（RFC 7748 §5 允许的非规范值处理） */
    o->l[15] &= 0x7fff;
}

static void fe_tobytes(uint8_t b[32], const fe *a) {
    for (int i = 0; i < 16; i++) {
        b[2 * i]     = (uint8_t)(a->l[i] & 0xff);
        b[2 * i + 1] = (uint8_t)((a->l[i] >> 8) & 0xff);
    }
}

/* 返回 1 表示 a >= p */
static int fe_geq_p(const fe *a) {
    for (int i = 15; i >= 0; i--) {
        if (a->l[i] > FE_P.l[i]) return 1;
        if (a->l[i] < FE_P.l[i]) return 0;
    }
    return 1;
}

/* o -= p（假定 o >= p 时调用；带借位传播） */
static void fe_sub_p(fe *o) {
    uint32_t borrow = 0;
    for (int i = 0; i < 16; i++) {
        uint32_t d = o->l[i] + 0x10000u - FE_P.l[i] - borrow;
        o->l[i] = d & 0xffff;
        borrow = (d >= 0x10000u) ? 0u : 1u;
    }
    (void)borrow;
}

/* 规范归约：反复减 p 直到 < p。输入 < 2^256，最多减 2 次，取 4 次上界 */
static void fe_canonical(fe *o) {
    for (int i = 0; i < 4 && fe_geq_p(o); i++) fe_sub_p(o);
}

/* o = (a + b) mod p */
static void fe_add(fe *o, const fe *a, const fe *b) {
    uint64_t c = 0;
    for (int i = 0; i < 16; i++) {
        c += (uint64_t)a->l[i] + b->l[i];
        o->l[i] = (uint32_t)(c & 0xffff);
        c >>= 16;
    }
    /* 进位出 limb15 = 2^256 ≡ 38 (mod p) */
    if (c) {
        uint64_t t = (uint64_t)o->l[0] + 38ull * c;
        o->l[0] = (uint32_t)(t & 0xffff);
        c = t >> 16;
        for (int i = 1; c && i < 16; i++) {
            t = (uint64_t)o->l[i] + c;
            o->l[i] = (uint32_t)(t & 0xffff);
            c = t >> 16;
        }
    }
    fe_canonical(o);
}

/* o = (a - b) mod p */
static void fe_sub(fe *o, const fe *a, const fe *b) {
    /* 走正值路径：o = a + (2p - b)，再规范归约 */
    fe t;
    uint32_t borrow = 0;
    for (int i = 0; i < 16; i++) {
        uint32_t d = FE_2P.l[i] + 0x10000u - b->l[i] - borrow;
        t.l[i] = d & 0xffff;
        borrow = (d >= 0x10000u) ? 0u : 1u;
    }
    fe_add(o, a, &t);
    fe_canonical(o);
}

/* o = (a * b) mod p */
static void fe_mul(fe *o, const fe *a, const fe *b) {
    uint64_t t[32];
    memset(t, 0, sizeof t);
    for (int i = 0; i < 16; i++) {
        uint64_t ai = a->l[i];
        if (!ai) continue;
        for (int j = 0; j < 16; j++)
            t[i + j] += ai * (uint64_t)b->l[j];
    }
    /*
     * 折回：limb i (i>=16) 表示 2^(16i) = 2^(16(i-16)) * 2^256
     *       而 2^256 = 2 * 2^255 ≡ 38 (mod p)，故乘 38 折到 i-16。
     * 每轮先向上传播进位，再折回高位；三轮后高位必为 0。
     */
    for (int r = 0; r < 3; r++) {
        for (int i = 0; i < 31; i++) {
            t[i + 1] += t[i] >> 16;
            t[i] &= 0xffff;
        }
        for (int i = 31; i >= 16; i--) {
            if (!t[i]) continue;
            t[i - 16] += 38ull * t[i];
            t[i] = 0;
        }
    }
    for (int i = 0; i < 31; i++) {
        t[i + 1] += t[i] >> 16;
        t[i] &= 0xffff;
    }
    for (int i = 31; i >= 16; i--) {
        if (!t[i]) continue;
        t[i - 16] += 38ull * t[i];
        t[i] = 0;
    }
    for (int i = 0; i < 31; i++) {
        t[i + 1] += t[i] >> 16;
        t[i] &= 0xffff;
    }
    /* 残留高位（若有）再折一次 */
    for (int i = 16; i < 32; i++) {
        if (!t[i]) continue;
        t[i - 16] += 38ull * t[i];
        t[i] = 0;
    }
    for (int i = 0; i < 31; i++) {
        t[i + 1] += t[i] >> 16;
        t[i] &= 0xffff;
    }
    for (int i = 0; i < 16; i++) o->l[i] = (uint32_t)(t[i] & 0xffff);
    fe_canonical(o);
}

static void fe_sq(fe *o, const fe *a) { fe_mul(o, a, a); }

/* o = 1 */
static void fe_one(fe *o) {
    fe_zero(o);
    o->l[0] = 1;
}

/* o = a^(p-2)（费马小定理求逆）；a = 0 时结果仍为 0 */
static void fe_invert(fe *o, const fe *a) {
    /* 指数 p-2 = 2^255 - 21 = 0x7fff...ffeb */
    static const uint8_t e[32] = {
        0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
    };
    fe r, x;
    fe_one(&r);
    fe_copy(&x, a);
    /* 左到右（MSB 优先）：每轮先平方累加器，再按指数位决定是否乘底数 */
    for (int i = 254; i >= 0; i--) {
        fe_sq(&r, &r);
        int bit = (e[i >> 3] >> (i & 7)) & 1;
        if (bit) {
            fe t;
            fe_mul(&t, &r, &x);
            fe_copy(&r, &t);
        }
    }
    fe_copy(o, &r);
}

/* 常数时间条件交换：mask 为 0xFFFFFFFF 时交换 */
static void fe_cswap(fe *a, fe *b, uint32_t mask) {
    for (int i = 0; i < 16; i++) {
        uint32_t t = mask & (a->l[i] ^ b->l[i]);
        a->l[i] ^= t;
        b->l[i] ^= t;
    }
}

/* ------------------------------------------------------------------ */
/* X25519                                                              */
/* ------------------------------------------------------------------ */

static void clamp_scalar(uint8_t k[32]) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

const char *x25519_errstr(int e) {
    switch (e) {
        case X25519_OK:      return "ok";
        case X25519_ERR_ARG: return "invalid argument";
        default:             return "unknown";
    }
}

int x25519_public_key(const uint8_t priv[X25519_KEY_LEN],
                      uint8_t pub[X25519_KEY_LEN]) {
    if (!priv || !pub) return X25519_ERR_ARG;

    uint8_t k[32];
    memcpy(k, priv, 32);
    clamp_scalar(k);

    /* Montgomery ladder：X25519(k, u=9) */
    fe x1, x2, z2, x3, z3;
    uint8_t base[32];
    memset(base, 0, 32);
    base[0] = 9;

    fe_frombytes(&x1, base);
    fe_one(&x2);  fe_zero(&z2);
    fe_copy(&x3, &x1); fe_one(&z3);

    uint32_t swap = 0;
    static const uint32_t A24 = 121665;   /* (A-2)/4, A = 486662 */

    for (int t = 254; t >= 0; t--) {
        uint32_t kt = (uint32_t)((k[t >> 3] >> (t & 7)) & 1);
        swap ^= kt;
        fe_cswap(&x2, &x3, 0u - swap);
        fe_cswap(&z2, &z3, 0u - swap);
        swap = kt;

        fe A, AA, B, BB, E, C, D, DA, CB, t1, t2, a24E;
        fe_add(&A, &x2, &z2);  fe_sq(&AA, &A);
        fe_sub(&B, &x2, &z2);  fe_sq(&BB, &B);
        fe_sub(&E, &AA, &BB);
        fe_add(&C, &x3, &z3);
        fe_sub(&D, &x3, &z3);
        fe_mul(&DA, &D, &A);
        fe_mul(&CB, &C, &B);

        fe_add(&t1, &DA, &CB); fe_sq(&x3, &t1);
        fe_sub(&t1, &DA, &CB); fe_sq(&t2, &t1); fe_mul(&z3, &x1, &t2);
        fe_mul(&x2, &AA, &BB);

        fe e24;
        fe_zero(&e24);
        e24.l[0] = A24 & 0xffff;
        e24.l[1] = A24 >> 16;
        fe_mul(&a24E, &e24, &E);
        fe_add(&t1, &AA, &a24E);
        fe_mul(&z2, &E, &t1);
    }
    fe_cswap(&x2, &x3, 0u - swap);
    fe_cswap(&z2, &z3, 0u - swap);

    fe inv;
    fe_invert(&inv, &z2);
    fe out;
    fe_mul(&out, &x2, &inv);
    fe_canonical(&out);
    fe_tobytes(pub, &out);
    return X25519_OK;
}

int x25519_shared(const uint8_t priv[X25519_KEY_LEN],
                  const uint8_t peer_pub[X25519_KEY_LEN],
                  uint8_t out[X25519_KEY_LEN]) {
    if (!priv || !peer_pub || !out) return X25519_ERR_ARG;

    uint8_t k[32];
    memcpy(k, priv, 32);
    clamp_scalar(k);

    fe x1, x2, z2, x3, z3;
    fe_frombytes(&x1, peer_pub);
    fe_one(&x2);  fe_zero(&z2);
    fe_copy(&x3, &x1); fe_one(&z3);

    uint32_t swap = 0;
    static const uint32_t A24 = 121665;

    for (int t = 254; t >= 0; t--) {
        uint32_t kt = (uint32_t)((k[t >> 3] >> (t & 7)) & 1);
        swap ^= kt;
        fe_cswap(&x2, &x3, 0u - swap);
        fe_cswap(&z2, &z3, 0u - swap);
        swap = kt;

        fe A, AA, B, BB, E, C, D, DA, CB, t1, t2, a24E;
        fe_add(&A, &x2, &z2);  fe_sq(&AA, &A);
        fe_sub(&B, &x2, &z2);  fe_sq(&BB, &B);
        fe_sub(&E, &AA, &BB);
        fe_add(&C, &x3, &z3);
        fe_sub(&D, &x3, &z3);
        fe_mul(&DA, &D, &A);
        fe_mul(&CB, &C, &B);

        fe_add(&t1, &DA, &CB); fe_sq(&x3, &t1);
        fe_sub(&t1, &DA, &CB); fe_sq(&t2, &t1); fe_mul(&z3, &x1, &t2);
        fe_mul(&x2, &AA, &BB);

        fe e24;
        fe_zero(&e24);
        e24.l[0] = A24 & 0xffff;
        e24.l[1] = A24 >> 16;
        fe_mul(&a24E, &e24, &E);
        fe_add(&t1, &AA, &a24E);
        fe_mul(&z2, &E, &t1);
    }
    fe_cswap(&x2, &x3, 0u - swap);
    fe_cswap(&z2, &z3, 0u - swap);

    fe inv;
    fe_invert(&inv, &z2);
    fe out_fe;
    fe_mul(&out_fe, &x2, &inv);
    fe_canonical(&out_fe);
    fe_tobytes(out, &out_fe);

    /* 低阶点防护：共享秘密全零 => 不可用，拒绝写出 */
    uint8_t zero = 0;
    for (int i = 0; i < 32; i++) zero |= out[i];
    if (zero == 0) {
        memset(out, 0, 32);
        return X25519_ERR_ARG;
    }
    return X25519_OK;
}

int x25519_generate_keypair(uint8_t priv[X25519_KEY_LEN],
                            uint8_t pub[X25519_KEY_LEN]) {
    if (!priv || !pub) return X25519_ERR_ARG;
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return X25519_ERR_ARG;
    size_t n = fread(priv, 1, X25519_KEY_LEN, f);
    fclose(f);
    if (n != X25519_KEY_LEN) return X25519_ERR_ARG;
    return x25519_public_key(priv, pub);
}
