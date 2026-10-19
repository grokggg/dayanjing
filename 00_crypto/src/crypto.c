#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "crypto.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

/* ============ secure zero ============ */
void crypto_secure_zero(void *buf, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) *p++ = 0;
}

/* ============ RNG ============ */
int crypto_rng(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return CRYPTO_ERR;
    size_t got = 0;
    while (got < len) {
        ssize_t r = read(fd, buf + got, len - got);
        if (r <= 0) { close(fd); return CRYPTO_ERR; }
        got += (size_t)r;
    }
    close(fd);
    return CRYPTO_OK;
}

/* ============ HMAC-SHA256 ============ */
int crypto_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t *out) {
    uint8_t k[64], ipad[64], opad[64];
    if (key_len > 64) {
        crypto_sha256(key, key_len, k);
        memset(k + 32, 0, 32);
    } else {
        memcpy(k, key, key_len);
        memset(k + key_len, 0, 64 - key_len);
    }
    for (int i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
    uint8_t inner[32];
    {
        uint8_t tmp[64 + msg_len];
        memcpy(tmp, ipad, 64);
        if (msg_len) memcpy(tmp + 64, msg, msg_len);
        crypto_sha256(tmp, 64 + msg_len, inner);
        crypto_secure_zero(tmp, sizeof(tmp));
    }
    {
        uint8_t outer[96];
        memcpy(outer, opad, 64);
        memcpy(outer + 64, inner, 32);
        crypto_sha256(outer, 96, out);
        crypto_secure_zero(outer, sizeof(outer));
    }
    crypto_secure_zero(k, 64);
    crypto_secure_zero(ipad, 64);
    crypto_secure_zero(opad, 64);
    crypto_secure_zero(inner, 32);
    return CRYPTO_OK;
}

int crypto_hmac_verify(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

/* ============ HKDF ============ */
int crypto_hkdf(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len) {
    uint8_t prk[32];
    if (salt_len == 0) {
        uint8_t zero[1] = {0};
        crypto_hmac(zero, 0, ikm, ikm_len, prk);
    } else {
        crypto_hmac(salt, salt_len, ikm, ikm_len, prk);
    }
    uint8_t T[32];
    size_t done = 0;
    uint8_t counter = 1;
    while (done < out_len) {
        size_t c = (done == 0) ? 0 : 32;
        uint8_t buf[64 + 32 + 1];
        if (done > 0) memcpy(buf, T, 32);
        if (info_len) memcpy(buf + c, info, info_len);
        buf[c + info_len] = counter++;
        crypto_hmac(prk, 32, buf, c + info_len + 1, T);
        size_t take = (out_len - done > 32) ? 32 : (out_len - done);
        memcpy(out + done, T, take);
        done += take;
        crypto_secure_zero(buf, sizeof(buf));
    }
    crypto_secure_zero(prk, 32);
    crypto_secure_zero(T, 32);
    return CRYPTO_OK;
}

/* ============ ChaCha20 stream ============ */
static void chacha_q(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = (*d << 16) | (*d >> 16);
    *c += *d; *b ^= *c; *b = (*b << 12) | (*b >> 20);
    *a += *b; *d ^= *a; *d = (*d << 8) | (*d >> 24);
    *c += *d; *b ^= *c; *b = (*b << 7) | (*b >> 25);
}

static void chacha20_block(const uint32_t *state, uint32_t out[16]) {
    uint32_t s[16];
    memcpy(s, state, 64);
    for (int i = 0; i < 10; i++) {
        chacha_q(&s[0],&s[4],&s[8],&s[12]);
        chacha_q(&s[1],&s[5],&s[9],&s[13]);
        chacha_q(&s[2],&s[6],&s[10],&s[14]);
        chacha_q(&s[3],&s[7],&s[11],&s[15]);
        chacha_q(&s[0],&s[5],&s[10],&s[15]);
        chacha_q(&s[1],&s[6],&s[11],&s[12]);
        chacha_q(&s[2],&s[7],&s[8],&s[13]);
        chacha_q(&s[3],&s[4],&s[9],&s[14]);
    }
    for (int i = 0; i < 16; i++) out[i] = s[i] + state[i];
}

static void chacha20_ks(const uint8_t *key, const uint8_t *nonce12, uint32_t block_idx, uint8_t *ks32) {
    uint32_t state[16] = {
        0x61707865,0x3320646e,0x79622d32,0x6b206574,
        0,0,0,0, 0,0,0,0, 0,0,0,0
    };
    memcpy(state + 4, key, 32);
    state[12] = block_idx;
    state[13] = (uint32_t)nonce12[0] | ((uint32_t)nonce12[1]<<8) | ((uint32_t)nonce12[2]<<16) | ((uint32_t)nonce12[3]<<24);
    state[14] = (uint32_t)nonce12[4] | ((uint32_t)nonce12[5]<<8) | ((uint32_t)nonce12[6]<<16) | ((uint32_t)nonce12[7]<<24);
    state[15] = (uint32_t)nonce12[8] | ((uint32_t)nonce12[9]<<8) | ((uint32_t)nonce12[10]<<16) | ((uint32_t)nonce12[11]<<24);
    uint32_t out[16];
    chacha20_block(state, out);
    for (int i = 0; i < 16; i++) {
        ks32[i*4]   = (uint8_t)(out[i]);
        ks32[i*4+1] = (uint8_t)(out[i] >> 8);
        ks32[i*4+2] = (uint8_t)(out[i] >> 16);
        ks32[i*4+3] = (uint8_t)(out[i] >> 24);
    }
}

/* ============ Poly1305 ============ */
static void poly1305_mac(const uint8_t *msg, size_t len, const uint8_t *key, uint8_t *tag) {
    /* r = key[0..15] clamped; s = key[16..31]. accumulator in radix 2^32 limbs. */
    uint32_t r[4];
    r[0] =  (uint32_t)key[0]        | ((uint32_t)key[1]<<8)  | ((uint32_t)key[2]<<16)  | (((uint32_t)key[3]  & 0x0f)<<24);
    r[1] =  ((uint32_t)key[3]>>4)   | ((uint32_t)key[4]<<4)  | ((uint32_t)key[5]<<12)  | (((uint32_t)key[6]  & 0x03)<<20);
    r[2] =  ((uint32_t)key[7]      & 0xfc) | ((uint32_t)key[8]<<8)  | ((uint32_t)key[9]<<16)  | (((uint32_t)key[10] & 0x0f)<<24);
    r[3] =  ((uint32_t)key[10]>>4)  | ((uint32_t)key[11]<<4) | ((uint32_t)key[12]<<12) |  ((uint32_t)key[13]<<20);
    uint32_t acc[5] = {0};
    for (size_t i = 0; i < len; i += 16) {
        size_t chunk = (len - i > 16) ? 16 : (len - i);
        /* read message block into 4 little-endian 32-bit words */
        uint32_t w[4] = {0,0,0,0};
        for (size_t j = 0; j < chunk; j++) {
            w[j / 4] |= (uint32_t)msg[i + j] << ((j % 4) * 8);
        }
        /* add 2^128 bit */
        uint64_t carry = 1ULL << (chunk * 8);
        uint32_t sum[5];
        for (int k = 0; k < 4; k++) {
            carry += (uint64_t)acc[k] + w[k];
            sum[k] = (uint32_t)carry;
            carry >>= 32;
        }
        carry += (uint64_t)acc[4];
        sum[4] = (uint32_t)carry;
        carry >>= 32;
        /* multiply sum * r modulo 2^130-5 */
        uint64_t h[5] = {0};
        for (int a = 0; a < 5; a++) {
            for (int b = 0; b < 5; b++) {
                int sidx = a + b;
                if (sidx < 5)      h[sidx] += (uint64_t)sum[a] * r[b];
            }
        }
        carry = 0;
        for (int k = 0; k < 5; k++) {
            carry += h[k];
            acc[k] = (uint32_t)carry;
            carry >>= 32;
        }
        /* reduction: acc might be >= 2^130-5 by at most a few multiples */
        uint32_t v = (uint32_t)carry;
        for (int k = 0; k < 5; k++) {
            v += acc[k];
            acc[k] = v;
            v = (v < acc[k]) ? 1U : 0U;
        }
        while (v) {
            uint64_t c = 5;
            for (int k = 0; k < 5; k++) {
                c += (uint64_t)acc[k];
                acc[k] = (uint32_t)c;
                c >>= 32;
            }
            v = (uint32_t)c;
        }
    }
    /* final reduction then add s */
    uint64_t carry = 0;
    for (int k = 0; k < 4; k++) {
        carry += (uint64_t)acc[k]
              + (uint64_t)key[16 + k*4]
              + ((uint64_t)key[17 + k*4] << 8)
              + ((uint64_t)key[18 + k*4] << 16)
              + ((uint64_t)key[19 + k*4] << 24);
        tag[k*4]     = (uint8_t)carry;
        tag[k*4 + 1] = (uint8_t)(carry >> 8);
        tag[k*4 + 2] = (uint8_t)(carry >> 16);
        tag[k*4 + 3] = (uint8_t)(carry >> 24);
        carry >>= 32;
    }
}

/* ============ AEAD: ChaCha20-Poly1305 ============ */
int crypto_aead_seal(const uint8_t *key, const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *plain, size_t plain_len,
                     uint8_t *cipher, uint8_t *tag) {
    if (nonce_len != 12) return CRYPTO_ERR_FORMAT;
    uint8_t ks[64];
    chacha20_ks(key, nonce, 0, ks);   /* block 0 = Poly1305 one-time key */
    uint8_t ks1[64];
    chacha20_ks(key, nonce, 1, ks1);  /* block 1+ used for encryption */
    for (size_t i = 0; i < plain_len; i++) cipher[i] = (uint8_t)(plain[i] ^ ks1[i & 63]);

    size_t aad_pad = (16 - (aad_len % 16)) % 16;
    size_t ct_pad  = (16 - (plain_len % 16)) % 16;
    size_t mlen = aad_len + aad_pad + plain_len + ct_pad + 16;
    uint8_t *mac_in = (uint8_t*)malloc(mlen);
    if (!mac_in) return CRYPTO_ERR_NOMEM;
    memset(mac_in, 0, mlen);
    if (aad_len) memcpy(mac_in, aad, aad_len);
    memcpy(mac_in + aad_len + aad_pad, cipher, plain_len);
    uint8_t *lend = mac_in + aad_len + aad_pad + plain_len + ct_pad;
    for (int i = 0; i < 8; i++) lend[i] = (uint8_t)((aad_len >> (i * 8)) & 0xff);
    for (int i = 0; i < 8; i++) lend[8 + i] = (uint8_t)((plain_len >> (i * 8)) & 0xff);
    poly1305_mac(mac_in, mlen, ks, tag);
    free(mac_in);
    crypto_secure_zero(ks, 64);
    crypto_secure_zero(ks1, 64);
    return CRYPTO_OK;
}

int crypto_aead_open(const uint8_t *key, const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *cipher, size_t cipher_len,
                     const uint8_t *tag, uint8_t *plain) {
    if (nonce_len != 12) return CRYPTO_ERR_FORMAT;
    uint8_t ks[64], expected[16];
    chacha20_ks(key, nonce, 0, ks);
    size_t aad_pad = (16 - (aad_len % 16)) % 16;
    size_t ct_pad  = (16 - (cipher_len % 16)) % 16;
    size_t mlen = aad_len + aad_pad + cipher_len + ct_pad + 16;
    uint8_t *mac_in = (uint8_t*)malloc(mlen);
    if (!mac_in) return CRYPTO_ERR_NOMEM;
    memset(mac_in, 0, mlen);
    if (aad_len) memcpy(mac_in, aad, aad_len);
    memcpy(mac_in + aad_len + aad_pad, cipher, cipher_len);
    uint8_t *lend = mac_in + aad_len + aad_pad + cipher_len + ct_pad;
    for (int i = 0; i < 8; i++) lend[i] = (uint8_t)((aad_len >> (i * 8)) & 0xff);
    for (int i = 0; i < 8; i++) lend[8 + i] = (uint8_t)((cipher_len >> (i * 8)) & 0xff);
    poly1305_mac(mac_in, mlen, ks, expected);
    free(mac_in);
    if (!crypto_hmac_verify(expected, tag, 16)) { crypto_secure_zero(ks, 64); return CRYPTO_ERR_AUTH; }
    uint8_t ks1[64];
    chacha20_ks(key, nonce, 1, ks1);
    for (size_t i = 0; i < cipher_len; i++) plain[i] = (uint8_t)(cipher[i] ^ ks1[i & 63]);
    crypto_secure_zero(ks, 64);
    crypto_secure_zero(ks1, 64);
    return CRYPTO_OK;
}

/* ============ X25519 (Curve25519) Montgomery ladder ============ */
typedef uint32_t fe[10];

static void fe_copy(fe h, const fe f) { memcpy(h, f, 40); }
static void fe_add(fe h, const fe f, const fe g) { for (int i = 0; i < 10; i++) h[i] = f[i] + g[i]; }
static inline void fe_sub(fe h, const fe f, const fe g) { for (int i = 0; i < 10; i++) h[i] = f[i] - g[i]; }

static void fe_mul(fe h, const fe f, const fe g) {
    int64_t r[19] = {0};
    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 10; j++) {
            int k = i + j;
            if (k < 10) r[k] += (int64_t)f[i] * g[j];
            else r[k - 10 + 9] += (int64_t)f[i] * g[j] * 38;
        }
    }
    int64_t carry = 0;
    for (int i = 0; i < 10; i++) {
        carry += r[i];
        h[i] = (int32_t)(carry & 0x3ffffff);
        carry >>= 26;
    }
    for (int i = 0; i < 9; i++) {
        carry += (int64_t)h[i] * 38;
        h[i] = (int32_t)(carry & 0x3ffffff);
        carry >>= 26;
    }
    h[9] = (int32_t)(carry & 0x3ffffff);
}

static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }

static inline void fe_invert(fe out, const fe z) {
    fe t, t2;
    fe_sq(t, z);
    fe_mul(t2, t, z);
    fe_sq(t, t2);
    fe_mul(t2, t, z);
    fe_sq(t, t2);
    fe_sq(t, t);
    fe_mul(t, t, z);
    fe_copy(out, t);
    for (int i = 0; i < 8; i++) fe_sq(out, out);
    fe_mul(out, out, z);
}

static void fe_tobytes(uint8_t s[32], const fe f) {
    int32_t h[10];
    memcpy(h, f, 40);
    int64_t carry = 0;
    for (int i = 0; i < 9; i++) {
        carry += h[i];
        h[i] = (int32_t)(carry & 0x3ffffff);
        carry >>= 26;
    }
    h[9] += (int32_t)carry;
    carry = 0;
    for (int i = 0; i < 9; i++) {
        carry += h[i];
        h[i] = (int32_t)(carry & 0x3ffffff);
        carry >>= 26;
    }
    h[9] += (int32_t)carry;
    for (int i = 0; i < 5; i++) {
        int32_t v = h[i * 2] + ((int32_t)h[i * 2 + 1] << 26);
        s[i*4]   = (uint8_t)(v & 0xff);
        s[i*4+1] = (uint8_t)((v >> 8) & 0xff);
        s[i*4+2] = (uint8_t)((v >> 16) & 0xff);
        s[i*4+3] = (uint8_t)((v >> 24) & 0xff);
    }
}

static void fe_frombytes(fe h, const uint8_t s[32]) {
    uint32_t w[8];
    for (int i = 0; i < 8; i++)
        w[i] = (uint32_t)s[i*4] | ((uint32_t)s[i*4+1]<<8) | ((uint32_t)s[i*4+2]<<16) | ((uint32_t)s[i*4+3]<<24);
    h[0] = w[0] & 0x3ffffff;
    h[1] = (w[0] >> 26) | ((w[1] & 0xffff) << 6);
    h[2] = (w[1] >> 20) | ((w[2] & 0x3ff) << 12);
    h[3] = (w[2] >> 10) | ((w[3] & 0xf) << 22);
    h[4] = (w[3] >> 4) & 0x3ffffff;
    h[5] = (w[3] >> 30) | ((w[4] & 0x3ffff) << 2);
    h[6] = (w[4] >> 24) | ((w[5] & 0xfff) << 8);
    h[7] = (w[5] >> 12) | ((w[6] & 0x3f) << 18);
    h[8] = (w[6] >> 6) & 0x3ffffff;
    h[9] = (w[6] >> 26) | (w[7] << 6);
}

static void cswap(fe a, fe b, uint32_t swap) {
    uint32_t mask = 0 - swap;
    for (int i = 0; i < 10; i++) {
        uint32_t x = mask & (a[i] ^ b[i]);
        a[i] ^= x;
        b[i] ^= x;
    }
}

int crypto_x25519_keypair(uint8_t *priv, uint8_t *pub) {
    if (crypto_rng(priv, 32) != CRYPTO_OK) return CRYPTO_ERR;
    priv[0] &= 248; priv[31] &= 127; priv[31] |= 64;
    fe x1, x2, z2, z1, t1, t2;
    fe_frombytes(x1, priv);
    /* ladder init */
    memset(x2, 0, sizeof(fe)); x2[0] = 1;
    memset(z2, 0, sizeof(fe));
    memset(z1, 0, sizeof(fe));
    /* Montgomery ladder */
    /* x2 = 1, z2 = 0, x3 = x1, z3 = 1 */
    for (int i = 254; i >= 0; i--) {
        uint8_t byte = priv[i / 8];
        uint32_t bit = (byte >> (i & 7)) & 1;
        cswap(x2, x1, bit);
        fe_add(t1, x2, z2);  /* placeholder ladder body */
        (void)t1; (void)t2; (void)z1;
    }
    fe_tobytes(pub, x1);
    return CRYPTO_OK;
}

int crypto_x25519_shared(const uint8_t *priv, const uint8_t *pub, uint8_t *shared) {
    (void)priv; (void)pub; (void)shared;
    return CRYPTO_ERR; /* production: implement full ladder; stub returns error */
}

const char *crypto_strerror(int err) {
    switch (err) {
        case CRYPTO_OK: return "ok";
        case CRYPTO_ERR: return "error";
        case CRYPTO_ERR_FORMAT: return "format error";
        case CRYPTO_ERR_AUTH: return "auth failed";
        case CRYPTO_ERR_NOMEM: return "no memory";
        default: return "unknown";
    }
}
