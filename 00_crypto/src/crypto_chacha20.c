#include "crypto.h"

#include <string.h>
#include <stdint.h>

/* ==================== ChaCha20（RFC 7539）====================
 * 状态矩阵 4x4 个字（16 个字 = 64 字节）
 * 常量 "expand 32-byte k"（4 字）+ 256-bit 密钥（8 字）
 * + 32-bit 计数器（1 字）+ 96-bit nonce（3 字）
 */

#define ROTL32(x, n)  (((x) << (n)) | ((x) >> (32 - (n))))

#define QUARTERROUND(a, b, c, d) \
    do { \
        a += b;  d = ROTL32(d ^ a, 16); \
        c += d;  b = ROTL32(b ^ c, 12); \
        a += b;  d = ROTL32(d ^ a,  8); \
        c += d;  b = ROTL32(b ^ c,  7); \
    } while (0)

/* 从 16 字节对齐的 key 缓冲构造一个 32-bit 小端字 */
static uint32_t U8TO32(const uint8_t *p) {
    return ((uint32_t)p[0]       )
         | ((uint32_t)p[1] <<  8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static void chacha20_block(uint32_t out[16], uint32_t in[16]) {
    uint32_t x[16];
    memcpy(x, in, sizeof(x));
    for (int i = 0; i < 10; i++) {
        /* 列轮 */
        QUARTERROUND(x[0], x[4],  x[8], x[12]);
        QUARTERROUND(x[1], x[5],  x[9], x[13]);
        QUARTERROUND(x[2], x[6], x[10], x[14]);
        QUARTERROUND(x[3], x[7], x[11], x[15]);
        /* 对角轮 */
        QUARTERROUND(x[0], x[5], x[10], x[15]);
        QUARTERROUND(x[1], x[6], x[11], x[12]);
        QUARTERROUND(x[2], x[7],  x[8], x[13]);
        QUARTERROUND(x[3], x[4],  x[9], x[14]);
    }
    for (int i = 0; i < 16; i++) out[i] = x[i] + in[i];
}

CRYPTO_API crypto_err_t crypto_chacha20(uint8_t *out, const uint8_t *in,
                                       size_t len,
                                       const uint8_t key[32],
                                       const uint8_t nonce[12],
                                       uint32_t counter) {
    if (!out || !key || !nonce) return CRYPTO_ERR;
    if (len == 0) return CRYPTO_OK;

    /* 构造初始状态 */
    uint32_t ctx[16] = {
        /* 常量 */
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        /* 密钥（小端） */
        U8TO32(key +  0), U8TO32(key +  4), U8TO32(key +  8), U8TO32(key + 12),
        U8TO32(key + 16), U8TO32(key + 20), U8TO32(key + 24), U8TO32(key + 28),
        /* 计数器 + nonce */
        counter,
        U8TO32(nonce + 0), U8TO32(nonce + 4), U8TO32(nonce + 8),
    };

    uint8_t keystream[64];
    uint32_t block[16];
    size_t done = 0;
    const int in_place = (in == out || !in);

    while (len >= 64) {
        chacha20_block(block, ctx);
        for (size_t i = 0; i < 16; i++) {
            uint32_t v = block[i];
            keystream[i*4]   = (uint8_t)(v       );
            keystream[i*4+1] = (uint8_t)(v >>  8);
            keystream[i*4+2] = (uint8_t)(v >> 16);
            keystream[i*4+3] = (uint8_t)(v >> 24);
        }
        if (in_place) {
            for (size_t i = 0; i < 64; i++) out[done + i] ^= keystream[i];
        } else {
            for (size_t i = 0; i < 64; i++) out[done + i] = in[done + i] ^ keystream[i];
        }
        done += 64;
        len  -= 64;
        ctx[12]++;   /* 块计数器递增；256 GiB 以上需调用方重新协商 */
    }
    if (len > 0) {
        chacha20_block(block, ctx);
        for (size_t i = 0; i < 16; i++) {
            uint32_t v = block[i];
            keystream[i*4]   = (uint8_t)(v       );
            keystream[i*4+1] = (uint8_t)(v >>  8);
            keystream[i*4+2] = (uint8_t)(v >> 16);
            keystream[i*4+3] = (uint8_t)(v >> 24);
        }
        for (size_t i = 0; i < len; i++) {
            if (in_place)
                out[done + i] ^= keystream[i];
            else
                out[done + i] = in[done + i] ^ keystream[i];
        }
    }
    crypto_wipe(keystream, sizeof(keystream));
    crypto_wipe(block, sizeof(block));
    crypto_wipe(ctx, sizeof(ctx));
    return CRYPTO_OK;
}
