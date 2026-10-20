/*
 * DAYANJING v3 — crypto_hash.c
 *
 * SHA-256 / HMAC-SHA256 / HKDF(RFC 5869) 自研实现。
 * 与 Python 侧 crypto_layer.py 的 sha256/hmac_sha256/hkdf_extract/hkdf_expand
 * 逐字节对齐，使 C 端与 Python 端可互操作。
 */

#include "crypto_hash.h"
#include <stdlib.h>
#include <string.h>

/* ---- 内部工具 ---- */

/* 安全擦除：用 volatile 指针阻止编译器优化掉 memset */
static void secure_zero(void *p, size_t n)
{
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) *vp++ = 0;
}

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | ((uint32_t)p[3]);
}

static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static void store_be64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v >> 56); p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40); p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24); p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);  p[7] = (uint8_t)(v);
}

/* FIPS 180-4 §4.2.2 轮常量 */
static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

/* ====================================================================
 * SHA-256
 * ==================================================================== */

void sha256_init(sha256_ctx *c)
{
    if (!c) return;
    c->h[0] = 0x6a09e667u; c->h[1] = 0xbb67ae85u;
    c->h[2] = 0x3c6ef372u; c->h[3] = 0xa54ff53au;
    c->h[4] = 0x510e527fu; c->h[5] = 0x9b05688cu;
    c->h[6] = 0x1f83d9abu; c->h[7] = 0x5be0cd19u;
    c->buf_len  = 0;
    c->total_len = 0;
}

static void sha256_compress(sha256_ctx *c, const uint8_t block[SHA256_BLOCK_LEN])
{
    uint32_t w[64];
    uint32_t a, b, cc, d, e, f, g, hh;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = load_be32(block + i * 4);
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i - 15], 7)  ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR32(w[i - 2], 17)  ^ ROR32(w[i - 2], 19)  ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g = c->h[6]; hh = c->h[7];

    for (i = 0; i < 64; i++) {
        uint32_t S1  = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
        uint32_t ch  = (e & f) ^ ((~e) & g);
        uint32_t t1  = hh + S1 + ch + K[i] + w[i];
        uint32_t S0  = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2  = S0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }

    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += hh;
}

void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len)
{
    if (!c) return;
    if (!data || len == 0) return;

    c->total_len += (uint64_t)len;

    /* 先填满当前部分块 */
    if (c->buf_len > 0) {
        size_t need = SHA256_BLOCK_LEN - c->buf_len;
        size_t take = (len < need) ? len : need;
        memcpy(c->buf + c->buf_len, data, take);
        c->buf_len += take;
        data += take;
        len  -= take;
        if (c->buf_len == SHA256_BLOCK_LEN) {
            sha256_compress(c, c->buf);
            c->buf_len = 0;
        }
    }

    /* 整块直接压缩 */
    while (len >= SHA256_BLOCK_LEN) {
        sha256_compress(c, data);
        data += SHA256_BLOCK_LEN;
        len  -= SHA256_BLOCK_LEN;
    }

    /* 剩余部分留到下一轮 */
    if (len > 0) {
        memcpy(c->buf, data, len);
        c->buf_len = len;
    }
}

void sha256_final(sha256_ctx *c, uint8_t out[SHA256_DIGEST_LEN])
{
    uint8_t  tail[128];
    size_t   zeros, t = 0;
    uint64_t bitlen;
    int i;

    if (!c || !out) return;

    bitlen = c->total_len * 8;

    /* 填充：0x80 || 若干 0x00 || 8 字节大端位长，使总长 ≡ 0 (mod 64)，
     * 且长度字段前恰有 56 字节。 */
    tail[t++] = 0x80;
    zeros = (56 - ((c->buf_len + 1) % SHA256_BLOCK_LEN) + SHA256_BLOCK_LEN) % SHA256_BLOCK_LEN;
    memset(tail + t, 0, zeros);
    t += zeros;
    store_be64(tail + t, bitlen);
    t += 8;

    sha256_update(c, tail, t);

    for (i = 0; i < 8; i++)
        store_be32(out + i * 4, c->h[i]);

    secure_zero(tail, sizeof(tail));
}

void sha256(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_LEN])
{
    sha256_ctx c;
    sha256_init(&c);
    if (data && len) sha256_update(&c, data, len);
    sha256_final(&c, out);
}

/* ====================================================================
 * HMAC-SHA256（RFC 2104）
 * ==================================================================== */

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[HMAC_SHA256_LEN])
{
    uint8_t k[SHA256_BLOCK_LEN];
    uint8_t ki[SHA256_BLOCK_LEN];
    uint8_t ko[SHA256_BLOCK_LEN];
    uint8_t inner[SHA256_DIGEST_LEN];
    sha256_ctx c;
    size_t i;

    if (!out) return;

    memset(k, 0, sizeof(k));
    if (key && key_len > 0) {
        if (key_len > SHA256_BLOCK_LEN) {
            sha256(key, key_len, k);          /* 长密钥先哈希 */
        } else {
            memcpy(k, key, key_len);
        }
    }

    for (i = 0; i < sizeof(k); i++) {
        ki[i] = (uint8_t)(k[i] ^ 0x36);
        ko[i] = (uint8_t)(k[i] ^ 0x5c);
    }

    /* inner = H(ki || data) */
    sha256_init(&c);
    sha256_update(&c, ki, sizeof(ki));
    if (data && data_len) sha256_update(&c, data, data_len);
    sha256_final(&c, inner);

    /* out = H(ko || inner) */
    sha256_init(&c);
    sha256_update(&c, ko, sizeof(ko));
    sha256_update(&c, inner, sizeof(inner));
    sha256_final(&c, out);

    secure_zero(k, sizeof(k));
    secure_zero(ki, sizeof(ki));
    secure_zero(ko, sizeof(ko));
}

/* ====================================================================
 * HKDF（RFC 5869），PRF = HMAC-SHA256
 * ==================================================================== */

int hkdf_extract(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 uint8_t prk[HKDF_HASH_LEN])
{
    uint8_t zero[HKDF_HASH_LEN];
    const uint8_t *s;
    size_t sl;

    if (!prk) return HASH_ERR_ARG;

    /* RFC 5869 §2.2：salt 未提供时用 HashLen 个零字节 */
    memset(zero, 0, sizeof(zero));
    if (!salt || salt_len == 0) {
        s  = zero;
        sl = HKDF_HASH_LEN;
    } else {
        s  = salt;
        sl = salt_len;
    }

    hmac_sha256(s, sl, ikm, ikm_len, prk);
    return HASH_OK;
}

int hkdf_expand(const uint8_t prk[HKDF_HASH_LEN],
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t len)
{
    uint8_t *tmp;
    uint8_t  t[HKDF_HASH_LEN];
    size_t   tlen = 0, done = 0;
    uint8_t  ctr = 1;

    if (!prk || !okm) return HASH_ERR_ARG;
    if (len == 0 || len > 255 * HKDF_HASH_LEN) return HASH_ERR_LEN;

    /* T(i) = HMAC(PRK, T(i-1) || info || i)，拼接后一次性喂给 HMAC */
    tmp = (uint8_t *)malloc(HKDF_HASH_LEN + info_len + 1);
    if (!tmp) return HASH_ERR_ARG;

    while (done < len) {
        size_t take;
        memcpy(tmp, t, tlen);
        if (info && info_len) memcpy(tmp + tlen, info, info_len);
        tmp[tlen + info_len] = ctr;

        hmac_sha256(prk, HKDF_HASH_LEN, tmp, tlen + info_len + 1, t);

        take = (len - done < HKDF_HASH_LEN) ? (len - done) : HKDF_HASH_LEN;
        memcpy(okm + done, t, take);
        done += take;
        tlen = HKDF_HASH_LEN;   /* 第 2 轮起 T(i-1) 为上一轮完整摘要 */
        ctr++;
    }

    secure_zero(t, sizeof(t));
    secure_zero(tmp, HKDF_HASH_LEN + info_len + 1);
    free(tmp);
    return HASH_OK;
}

int hkdf(const uint8_t *salt, size_t salt_len,
         const uint8_t *ikm, size_t ikm_len,
         const uint8_t *info, size_t info_len,
         uint8_t *okm, size_t len)
{
    uint8_t prk[HKDF_HASH_LEN];
    int r;

    r = hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    if (r != HASH_OK) return r;

    r = hkdf_expand(prk, info, info_len, okm, len);
    secure_zero(prk, sizeof(prk));
    return r;
}
