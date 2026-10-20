/*
 * DAYANJING v3 — crypto_gcm.c
 *
 * AES-128 + GCM 自研实现。
 * 见 crypto_gcm.h 的设计说明。
 */

#include "crypto_gcm.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>


/* =====================================================================
 * AES S-Box（FIPS 197 标准）
 * ===================================================================== */
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* 乘法逆元 S-Box（用于 InvSubBytes，解密用） */
static const uint8_t rsbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/* =====================================================================
 * AES 轮常量（Rcon）
 * ===================================================================== */
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* =====================================================================
 * 密钥扩展（Key Expansion）
 * ===================================================================== */
typedef struct {
    uint8_t round_key[176];   /* 11 轮 × 16 字节 = 176 字节 */
} aes128_ctx_t;

static uint8_t xtime(uint8_t b)
{
    return (uint8_t)(((b << 1) ^ ((b & 0x80) ? 0x1b : 0)) & 0xFF);
}

static void key_expansion(const uint8_t key[GCM_KEY_LEN], aes128_ctx_t *ctx)
{
    uint8_t *rk = ctx->round_key;
    int i;

    memcpy(rk, key, 16);

    for (i = 1; i <= 10; i++) {
        uint8_t temp[4];

        /* 取出上一轮的最后一列 */
        temp[0] = rk[(i - 1) * 16 + 13];
        temp[1] = rk[(i - 1) * 16 + 14];
        temp[2] = rk[(i - 1) * 16 + 15];
        temp[3] = rk[(i - 1) * 16 + 12];

        /* SubWord(RotWord(temp)) */
        temp[0] = sbox[temp[0]];
        temp[1] = sbox[temp[1]];
        temp[2] = sbox[temp[2]];
        temp[3] = sbox[temp[3]];

        temp[0] ^= rcon[i];

        /*
         * 生成第 i 轮密钥：w[4i+j] = w[4(i-1)+j] XOR temp
         * 每算出一个 word，temp 直接更新为该 word（标准 AES 密钥扩展），
         * 不可再做 RotWord —— 否则第 2 个 word 起全线错位。
         */
        for (int j = 0; j < 4; j++) {
            int base = (i - 1) * 16 + j * 4;
            int nbase = i * 16 + j * 4;
            rk[nbase + 0] = (uint8_t)(rk[base + 0] ^ temp[0]);
            rk[nbase + 1] = (uint8_t)(rk[base + 1] ^ temp[1]);
            rk[nbase + 2] = (uint8_t)(rk[base + 2] ^ temp[2]);
            rk[nbase + 3] = (uint8_t)(rk[base + 3] ^ temp[3]);

            temp[0] = rk[nbase + 0];
            temp[1] = rk[nbase + 1];
            temp[2] = rk[nbase + 2];
            temp[3] = rk[nbase + 3];
        }
    }
}

/* =====================================================================
 * AES 轮函数
 * ===================================================================== */
void add_round_key(uint8_t state[16], const uint8_t rk[16])
{
    for (int i = 0; i < 16; i++)
        state[i] ^= rk[i];
}

void sub_bytes(uint8_t state[16])
{
    for (int i = 0; i < 16; i++)
        state[i] = sbox[state[i]];
}

void inv_sub_bytes(uint8_t state[16])
{
    for (int i = 0; i < 16; i++)
        state[i] = rsbox[state[i]];
}

/* ShiftRows */
void shift_rows(uint8_t state[16])
{
    uint8_t t;

    /* 第 2 行：左移 1 */
    t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
    /* 第 3 行：左移 2 */
    t = state[2]; state[2] = state[10]; state[10] = t;
    t = state[6]; state[6] = state[14]; state[14] = t;
    /* 第 4 行：左移 3（右移 1） */
    t = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t;
}

void inv_shift_rows(uint8_t state[16])
{
    uint8_t t;

    t = state[1]; state[1] = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = t;
    t = state[2]; state[2] = state[10]; state[10] = t;
    t = state[6]; state[6] = state[14]; state[14] = t;
    t = state[15]; state[15] = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = t;
}

/* MixColumns 的 xtime 乘法 */
static uint8_t mul2(uint8_t b) { return xtime(b); }
static uint8_t mul3(uint8_t b) { return (uint8_t)(xtime(b) ^ b); }

void mix_columns(uint8_t state[16])
{
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        uint8_t s0 = state[i + 0], s1 = state[i + 1];
        uint8_t s2 = state[i + 2], s3 = state[i + 3];

        state[i + 0] = (uint8_t)(mul2(s0) ^ mul3(s1) ^ s2 ^ s3);
        state[i + 1] = (uint8_t)(s0 ^ mul2(s1) ^ mul3(s2) ^ s3);
        state[i + 2] = (uint8_t)(s0 ^ s1 ^ mul2(s2) ^ mul3(s3));
        state[i + 3] = (uint8_t)(mul3(s0) ^ s1 ^ s2 ^ mul2(s3));
    }
}

/*
 * InvMixColumns —— 系数矩阵 {0x0e,0x0b,0x0d,0x09} 循环矩阵：
 *   s0' = 14*s0 ^ 11*s1 ^ 13*s2 ^  9*s3
 *   s1' =  9*s0 ^ 14*s1 ^ 11*s2 ^ 13*s3
 *   s2' = 13*s0 ^  9*s1 ^ 14*s2 ^ 11*s3
 *   s3' = 11*s0 ^ 13*s1 ^  9*s2 ^ 14*s3
 * 其中 9=x8^x1、11=x8^x2^x1、13=x8^x4^x1、14=x8^x4^x2（xN 为连续 mul2）。
 */
static uint8_t mul9(uint8_t b)  { return (uint8_t)(mul2(mul2(mul2(b))) ^ b); }
static uint8_t mul11(uint8_t b) { return (uint8_t)(mul2(mul2(mul2(b))) ^ mul2(b) ^ b); }
static uint8_t mul13(uint8_t b) { return (uint8_t)(mul2(mul2(mul2(b))) ^ mul2(mul2(b)) ^ b); }
static uint8_t mul14(uint8_t b) { return (uint8_t)(mul2(mul2(mul2(b))) ^ mul2(mul2(b)) ^ mul2(b)); }

void inv_mix_columns(uint8_t state[16])
{
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        uint8_t s0 = state[i + 0], s1 = state[i + 1];
        uint8_t s2 = state[i + 2], s3 = state[i + 3];

        state[i + 0] = (uint8_t)(mul14(s0) ^ mul11(s1) ^ mul13(s2) ^ mul9(s3));
        state[i + 1] = (uint8_t)(mul9(s0)  ^ mul14(s1) ^ mul11(s2) ^ mul13(s3));
        state[i + 2] = (uint8_t)(mul13(s0) ^ mul9(s1)  ^ mul14(s2) ^ mul11(s3));
        state[i + 3] = (uint8_t)(mul11(s0) ^ mul13(s1) ^ mul9(s2)  ^ mul14(s3));
    }
}

/* =====================================================================
 * AES-128 加解密
 * ===================================================================== */
void aes128_encrypt_block(const uint8_t key[GCM_KEY_LEN],
                          const uint8_t in[GCM_BLOCK],
                          uint8_t out[GCM_BLOCK])
{
    aes128_ctx_t ctx;
    uint8_t state[16];

    key_expansion(key, &ctx);
    memcpy(state, in, 16);

    /* 初始 AddRoundKey */
    add_round_key(state, ctx.round_key);

    /* 9 轮完整轮 */
    for (int r = 1; r <= 9; r++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, ctx.round_key + r * 16);
    }

    /* 末轮（无 MixColumns） */
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, ctx.round_key + 10 * 16);

    memcpy(out, state, 16);
}

void aes128_decrypt_block(const uint8_t key[GCM_KEY_LEN],
                          const uint8_t in[GCM_BLOCK],
                          uint8_t out[GCM_BLOCK])
{
    aes128_ctx_t ctx;
    uint8_t state[16];

    key_expansion(key, &ctx);
    memcpy(state, in, 16);

    add_round_key(state, ctx.round_key + 10 * 16);
    inv_shift_rows(state);
    inv_sub_bytes(state);

    for (int r = 9; r >= 1; r--) {
        add_round_key(state, ctx.round_key + r * 16);
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
    }

    add_round_key(state, ctx.round_key);
    memcpy(out, state, 16);
}

/* =====================================================================
 * GCM：GF(2^128) 乘法 —— MSB-first 标准表示
 *
 * 归约多项式：x^128 + x^7 + x^2 + x + 1
 * R = 0xE1 << 120
 * ===================================================================== */
/*
 * NIST SP 800-38D GMULT：
 *   Z = 0; V = Y
 *   for i = 0 .. 127:
 *       if X[i] == 1:  Z ^= V
 *       if V 的最低有效位（byte[15] 的 bit0，即 x^127 系数）为 1:
 *           V = (V >> 1) ^ R      R = 0xe1 || 0^120
 *       else:
 *           V = V >> 1
 *
 * 注意：GCM 的比特序约定最左位为 x^0，因此"乘以 x"是**右移**，
 * 归约多项式 0xe1 异或进 V[0]（最高字节），不是左移。
 */
static void gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16])
{
    uint8_t Z[16] = {0};
    uint8_t V[16];

    memcpy(V, y, 16);

    for (int i = 0; i < 128; i++) {
        /* 从左（MSB）到右逐位扫描 X */
        int xi = (x[i >> 3] >> (7 - (i & 7))) & 1;
        if (xi) {
            for (int j = 0; j < 16; j++)
                Z[j] ^= V[j];
        }

        /* V = V * x ：右移一位，移出的位做归约 */
        int lsb = V[15] & 1;
        for (int j = 15; j > 0; j--)
            V[j] = (uint8_t)((V[j] >> 1) | (V[j - 1] << 7));
        V[0] = (uint8_t)(V[0] >> 1);
        if (lsb)
            V[0] ^= 0xE1;
    }

    memcpy(out, Z, 16);
}

void ghash(const uint8_t h[GCM_BLOCK],
           const uint8_t *x, size_t len_x,
           uint8_t out[GCM_BLOCK])
{
    uint8_t y[16] = {0};
    uint8_t block[16];

    if (len_x % GCM_BLOCK != 0) {
        /* 调用方负责把 X 对齐到 16 字节 */
        memset(out, 0, GCM_BLOCK);
        return;
    }

    for (size_t i = 0; i < len_x; i += GCM_BLOCK) {
        for (int j = 0; j < GCM_BLOCK; j++)
            block[j] = (uint8_t)(y[j] ^ x[i + j]);
        gf128_mul(h, block, y);
    }

    memcpy(out, y, GCM_BLOCK);
}

/* =====================================================================
 * GCTR_K：GCM 计数器模式
 * ===================================================================== */
static void gctr(const uint8_t key[GCM_KEY_LEN],
                 const uint8_t icb[GCM_BLOCK],
                 const uint8_t *in, size_t len,
                 uint8_t *out)
{
    uint8_t cb[GCM_BLOCK];
    uint8_t ks[GCM_BLOCK];
    size_t processed = 0;

    memcpy(cb, icb, GCM_BLOCK);

    while (processed < len) {
        size_t chunk = (len - processed < GCM_BLOCK) ? (len - processed) : GCM_BLOCK;

        aes128_encrypt_block(key, cb, ks);

        for (size_t j = 0; j < chunk; j++)
            out[processed + j] = (uint8_t)(in[processed + j] ^ ks[j]);

        /* 计数器递增（最低 32 位，小端，标准 GCM 定义） */
        int carry = 1;
        for (int k = 15; k >= 12 && carry; k--) {
            int sum = cb[k] + carry;
            cb[k] = (uint8_t)sum;
            carry = sum >> 8;
        }

        processed += chunk;
    }
}

/*
 * GCM 的 J0 生成（IV 为 96 位时）：
 *   J0 = IV || 0x00000001
 */
static void make_j0(const uint8_t iv[GCM_IV_LEN], uint8_t j0[GCM_BLOCK])
{
    memcpy(j0, iv, GCM_IV_LEN);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;
}

/* 将 64 位长度编码为 64 位大端，拼成 128 位 len 块 */
static void make_len_block(uint64_t len_aad, uint64_t len_ct, uint8_t out[16])
{
    /* len_aad_bits (64-bit BE) || len_ct_bits (64-bit BE) */
    uint64_t la = len_aad << 3;   /* 转 bit 长度 */
    uint64_t lc = len_ct << 3;
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    la = __builtin_bswap64(la);
    lc = __builtin_bswap64(lc);
#endif
    memcpy(out, &la, 8);
    memcpy(out + 8, &lc, 8);
}

/* =====================================================================
 * GCM Seal / Open
 * ===================================================================== */
int gcm_seal(const uint8_t key[GCM_KEY_LEN],
             const uint8_t iv[GCM_IV_LEN],
             const uint8_t *aad, size_t len_aad,
             const uint8_t *plaintext, size_t len_pt,
             uint8_t *ciphertext,
             uint8_t tag[GCM_TAG_LEN])
{
    uint8_t H[GCM_BLOCK];
    uint8_t J0[GCM_BLOCK];
    uint8_t S[GCM_BLOCK];
    uint8_t inc32_j0[GCM_BLOCK];
    uint8_t *x;
    size_t x_len;
    size_t aad_pad = (16 - (len_aad % 16)) % 16;
    size_t ct_pad = (16 - (len_pt % 16)) % 16;

    if (!key || !iv || !ciphertext || !tag)
        return GCM_ERR_KEY;

    /* H = E_K(0^128) */
    uint8_t zero[16] = {0};
    aes128_encrypt_block(key, zero, H);

    /* 构造 GHASH 输入 X = AAD || 0^p || C || 0^q || len(AAD) || len(C) */
    x_len = len_aad + aad_pad + len_pt + ct_pad + 16;
    x = (uint8_t *)malloc(x_len);
    if (!x)
        return GCM_ERR_AUTH;   /* 无合适错误码，复用 */

    memset(x, 0, x_len);
    if (len_aad > 0 && aad)
        memcpy(x, aad, len_aad);
    /* aad 填充区已为零 */

    /* J0 = IV || 0^31 || 1 */
    make_j0(iv, J0);

    /* inc32(J0) —— GCTR 的起始计数器（J0 本身留给标签） */
    memcpy(inc32_j0, J0, GCM_BLOCK);
    int carry = 1;
    for (int k = 15; k >= 12 && carry; k--) {
        int sum = inc32_j0[k] + carry;
        inc32_j0[k] = (uint8_t)sum;
        carry = sum >> 8;
    }

    /* C = GCTR_K(inc32(J0), P) —— 必须先加密，GHASH 要覆盖密文 */
    gctr(key, inc32_j0, plaintext ? plaintext : (const uint8_t *)"", len_pt, ciphertext);

    /* GHASH 输入是 A || C（密文，不是明文） */
    if (len_pt > 0)
        memcpy(x + len_aad + aad_pad, ciphertext, len_pt);
    /* ct 填充区已为零 */
    make_len_block(len_aad, len_pt, x + x_len - 16);

    /* Y = GHASH(H, X) */
    ghash(H, x, x_len, S);

    /* T = MSB_t( GHASH(H,X) ^ E_K(J0) ) —— 用 J0，不是 inc32(J0) */
    aes128_encrypt_block(key, J0, inc32_j0);
    for (int i = 0; i < GCM_TAG_LEN; i++)
        tag[i] = (uint8_t)(S[i] ^ inc32_j0[i]);

    free(x);
    return GCM_OK;
}

int gcm_open(const uint8_t key[GCM_KEY_LEN],
             const uint8_t iv[GCM_IV_LEN],
             const uint8_t *aad, size_t len_aad,
             const uint8_t *ciphertext, size_t len_ct,
             const uint8_t tag[GCM_TAG_LEN],
             uint8_t *plaintext)
{
    uint8_t H[GCM_BLOCK];
    uint8_t J0[GCM_BLOCK];
    uint8_t S[GCM_BLOCK];
    uint8_t expected_tag[GCM_TAG_LEN];
    uint8_t *x;
    size_t x_len;
    size_t aad_pad = (16 - (len_aad % 16)) % 16;
    size_t ct_pad = (16 - (len_ct % 16)) % 16;

    if (!key || !iv || !ciphertext || !tag || !plaintext)
        return GCM_ERR_KEY;

    uint8_t zero[16] = {0};
    aes128_encrypt_block(key, zero, H);

    x_len = len_aad + aad_pad + len_ct + ct_pad + 16;
    x = (uint8_t *)malloc(x_len);
    if (!x)
        return GCM_ERR_AUTH;

    memset(x, 0, x_len);
    if (len_aad > 0 && aad)
        memcpy(x, aad, len_aad);
    if (len_ct > 0 && ciphertext)
        memcpy(x + len_aad + aad_pad, ciphertext, len_ct);
    make_len_block(len_aad, len_ct, x + x_len - 16);

    /* J0 = IV || 0^31 || 1 */
    make_j0(iv, J0);

    ghash(H, x, x_len, S);

    /* T = MSB_t( GHASH(H,X) ^ E_K(J0) ) */
    aes128_encrypt_block(key, J0, expected_tag);
    for (int i = 0; i < GCM_TAG_LEN; i++)
        expected_tag[i] ^= S[i];

    free(x);

    /* 固定时间比较 tag */
    if (!crypto_constant_time_eq(tag, expected_tag, GCM_TAG_LEN))
        return GCM_ERR_AUTH;

    /* 验签通过，解密：P = GCTR_K(inc32(J0), C) */
    make_j0(iv, J0);
    int carry = 1;
    for (int k = 15; k >= 12 && carry; k--) {
        int sum = J0[k] + carry;
        J0[k] = (uint8_t)sum;
        carry = sum >> 8;
    }
    gctr(key, J0, ciphertext, len_ct, plaintext);

    return GCM_OK;
}

/* =====================================================================
 * 固定时间比较
 * ===================================================================== */
int crypto_constant_time_eq(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}
