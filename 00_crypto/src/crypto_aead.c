#include "crypto.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* ==================== ChaCha20-Poly1305 AEAD（RFC 7539 §2.8）===================
 * 
 * 加密：
 *   1. 用 key+nonce 加密全零 64 字节块，取前 32 字节作 Poly1305 一次性密钥
 *   2. 用 key+nonce（counter=1）加密明文，得到密文
 *   3. 构造附加数据块：AAD || pad1 || ciphertext || pad2 || len(AAD)||len(ct)
 *      其中 pad1/pad2 是补零到 16 字节对齐的填充
 *   4. 对该块计算 Poly1305，得到 16 字节认证标签
 *   5. 输出 = ciphertext || tag
 *
 * 解密：
 *   1. 重新计算期望 tag（先算 MAC 再解，避免解密后验证导致的时序差异）
 *   2. 常量时间比较 tag
 *   3. 失败则清零 plaintext 缓冲并返回 TAG_MISMATCH
 */

/* RFC 7539 §2.8 规定的 Poly1305 输入格式：
 *   AAD || pad1(0..15) || ciphertext || pad2(0..15) || len(AAD,64bit) || len(ct,64bit)
 * 两个长度域均为小端 64-bit。
 */

CRYPTO_API crypto_err_t crypto_aead_seal(uint8_t *ciphertext, size_t *out_len,
                                        const uint8_t *plaintext, size_t pt_len,
                                        const uint8_t *ad, size_t ad_len,
                                        const uint8_t key[32],
                                        const uint8_t nonce[12]) {
    if (!ciphertext || !out_len || !key || !nonce) return CRYPTO_ERR;
    if (pt_len > SIZE_MAX - 16) return CRYPTO_OVERFLOW;
    *out_len = pt_len + 16;

    /* 1. 生成 Poly1305 一次性密钥 */
    uint8_t poly_key[32] = {0};
    crypto_chacha20(poly_key, poly_key, 32, key, nonce, 0);

    /* 2. 加密明文（counter 从 1 开始，保留 0 给 key block） */
    crypto_chacha20(ciphertext, plaintext, pt_len, key, nonce, 1);

    /* 3. 计算 Poly1305 标签 */
    /* 为符合 RFC 7539 §2.8 的精确格式，构造完整输入缓冲 */
    size_t aad_pad = (16 - (ad_len % 16)) % 16;
    size_t ct_pad  = (16 - (pt_len % 16)) % 16;
    size_t total = ad_len + aad_pad + pt_len + ct_pad + 8 + 8;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) {
        crypto_wipe(poly_key, sizeof(poly_key));
        return CRYPTO_NOMEM;
    }
    size_t off = 0;
    if (ad && ad_len > 0) { memcpy(buf + off, ad, ad_len); off += ad_len; }
    memset(buf + off, 0, aad_pad); off += aad_pad;
    memcpy(buf + off, ciphertext, pt_len); off += pt_len;
    memset(buf + off, 0, ct_pad); off += ct_pad;
    /* 长度域（小端 64-bit） */
    uint64_t ad_bits  = (uint64_t)ad_len  * 8;
    uint64_t ct_bits  = (uint64_t)pt_len  * 8;
    for (int i = 0; i < 8; i++) buf[off++] = (uint8_t)(ad_bits >> (i * 8));
    for (int i = 0; i < 8; i++) buf[off++] = (uint8_t)(ct_bits >> (i * 8));

    uint8_t tag[16];
    crypto_poly1305(tag, buf, total, poly_key);
    memcpy(ciphertext + pt_len, tag, 16);

    crypto_wipe(buf, total);
    free(buf);
    crypto_wipe(poly_key, sizeof(poly_key));
    crypto_wipe(tag, sizeof(tag));
    return CRYPTO_OK;
}

CRYPTO_API crypto_err_t crypto_aead_open(uint8_t *plaintext, size_t *out_len,
                                        const uint8_t *ciphertext, size_t ct_len,
                                        const uint8_t *ad, size_t ad_len,
                                        const uint8_t key[32],
                                        const uint8_t nonce[12]) {
    if (!plaintext || !out_len || !ciphertext || !key || !nonce) return CRYPTO_ERR;
    if (ct_len < 16) return CRYPTO_ERR;
    size_t pt_len = ct_len - 16;
    const uint8_t *tag = ciphertext + pt_len;

    /* 1. 生成期望的 Poly1305 密钥 */
    uint8_t poly_key[32] = {0};
    crypto_chacha20(poly_key, poly_key, 32, key, nonce, 0);

    /* 2. 构造与 seal 完全相同的输入，计算期望 tag */
    size_t aad_pad = (16 - (ad_len % 16)) % 16;
    size_t ct_pad  = (16 - (pt_len % 16)) % 16;
    size_t total = ad_len + aad_pad + pt_len + ct_pad + 8 + 8;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) {
        crypto_wipe(poly_key, sizeof(poly_key));
        return CRYPTO_NOMEM;
    }
    size_t off = 0;
    if (ad && ad_len > 0) { memcpy(buf + off, ad, ad_len); off += ad_len; }
    memset(buf + off, 0, aad_pad); off += aad_pad;
    memcpy(buf + off, ciphertext, pt_len); off += pt_len;
    memset(buf + off, 0, ct_pad); off += ct_pad;
    uint64_t ad_bits = (uint64_t)ad_len * 8;
    uint64_t ct_bits = (uint64_t)pt_len * 8;
    for (int i = 0; i < 8; i++) buf[off++] = (uint8_t)(ad_bits >> (i * 8));
    for (int i = 0; i < 8; i++) buf[off++] = (uint8_t)(ct_bits >> (i * 8));

    uint8_t expected[16];
    crypto_poly1305(expected, buf, total, poly_key);
    crypto_wipe(buf, total);
    free(buf);

    /* 3. 常量时间比较 tag —— 必须早于解密，防止 oracle */
    int eq = crypto_ct_memcmp(tag, expected, 16);
    crypto_wipe(poly_key, sizeof(poly_key));
    if (eq != 0) {
        crypto_wipe(expected, sizeof(expected));
        return CRYPTO_TAG_MISMATCH;
    }

    /* 4. 认证通过，解密 */
    crypto_chacha20(plaintext, ciphertext, pt_len, key, nonce, 1);
    *out_len = pt_len;
    crypto_wipe(expected, sizeof(expected));
    return CRYPTO_OK;
}
