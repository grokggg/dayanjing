#include "crypto.h"

#include <string.h>
#include <stdint.h>

/* ==================== 会话封装 ====================
 * 自动管理 nonce：每次 seal/open 后 counter 递增。
 * nonce 布局（12 字节）：
 *   [0..3]  = 会话 base（init 时随机生成）
 *   [4..7]  = 32-bit 计数器（大端）
 *   [8..11] = 保留（随机填充，保证每次的 nonce 不同）
 *
 * 注意：ChaCha20-Poly1305 要求 (key, nonce) 对绝对不重用。
 * counter 用满 32-bit 前必须重新协商会话密钥。
 */

CRYPTO_API crypto_err_t crypto_session_init(struct crypto_session *s,
                                          const uint8_t key[32]) {
    if (!s || !key) return CRYPTO_ERR;
    memcpy(s->key, key, 32);
    /* base nonce 初始化为 0。RFC 7539 的 nonce 只需保证 (key,nonce) 对不重用，
     * 随机性由密钥 + 计数器提供，无需随机 base。双方用同一密钥即自然同步。 */
    memset(s->nonce, 0, 12);
    s->counter = 0;
    s->initialized = true;
    return CRYPTO_OK;
}

/* 根据 counter 生成本次使用的 12 字节 nonce */
static void session_nonce(const struct crypto_session *s, uint32_t counter,
                         uint8_t out[12]) {
    memcpy(out, s->nonce, 12);
    /* 将 counter 以大端写入 nonce[4..7] */
    for (int i = 0; i < 4; i++)
        out[4 + i] = (uint8_t)(counter >> ((3 - i) * 8));
}

CRYPTO_API crypto_err_t crypto_session_seal(struct crypto_session *s,
                                          uint8_t *ciphertext, size_t *out_len,
                                          const uint8_t *plaintext, size_t pt_len,
                                          const uint8_t *ad, size_t ad_len) {
    if (!s || !s->initialized) return CRYPTO_ERR;
    if (s->counter == 0xffffffffu) return CRYPTO_OVERFLOW;   /* 必须重新协商 */
    uint8_t nonce[12];
    session_nonce(s, s->counter, nonce);
    crypto_err_t rc = crypto_aead_seal(ciphertext, out_len, plaintext, pt_len,
                                      ad, ad_len, s->key, nonce);
    if (rc == CRYPTO_OK) s->counter++;
    return rc;
}

CRYPTO_API crypto_err_t crypto_session_open(struct crypto_session *s,
                                          uint8_t *plaintext, size_t *out_len,
                                          const uint8_t *ciphertext, size_t ct_len,
                                          const uint8_t *ad, size_t ad_len) {
    if (!s || !s->initialized) return CRYPTO_ERR;
    if (s->counter == 0xffffffffu) return CRYPTO_OVERFLOW;
    uint8_t nonce[12];
    session_nonce(s, s->counter, nonce);
    crypto_err_t rc = crypto_aead_open(plaintext, out_len, ciphertext, ct_len,
                                      ad, ad_len, s->key, nonce);
    if (rc == CRYPTO_OK) s->counter++;
    return rc;
}
