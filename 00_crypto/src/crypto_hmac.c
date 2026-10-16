#include "crypto.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5C
#define HMAC_BLOCK 64   /* SHA-256 的压缩函数块长 */

CRYPTO_API crypto_err_t crypto_hmac(uint8_t out[32], const uint8_t *key,
                                   size_t key_len, const uint8_t *msg,
                                   size_t msg_len) {
    if (!out) return CRYPTO_ERR;

    uint8_t k[HMAC_BLOCK];
    crypto_wipe(k, sizeof(k));

    /* 密钥标准化：超过块长先哈希，不足则补零 */
    if (key_len > HMAC_BLOCK) {
        crypto_sha256(k, key, key_len);
    } else if (key) {
        memcpy(k, key, key_len);
    }

    uint8_t ikeypad[HMAC_BLOCK];
    uint8_t okeypad[HMAC_BLOCK];
    for (size_t i = 0; i < HMAC_BLOCK; i++) {
        ikeypad[i] = (uint8_t)(k[i] ^ HMAC_IPAD);
        okeypad[i] = (uint8_t)(k[i] ^ HMAC_OPAD);
    }

    /* inner = H(ikeypad || msg) */
    uint8_t inner[32];
    /* 这里用分段方式避免大缓冲分配：构造 inner 时先喂 ikeypad 再喂 msg */
    /* 简化实现：使用栈上 64 + msg_len 的临时缓冲 */
    /* 当 msg 很长时栈可能溢出，因此限制单次 msg 长度 */
    if (msg_len > 1024 * 1024) {
        crypto_wipe(k, sizeof(k));
        return CRYPTO_OVERFLOW;
    }
    unsigned char *buf = (unsigned char *)malloc(HMAC_BLOCK + msg_len);
    if (!buf) {
        crypto_wipe(k, sizeof(k));
        return CRYPTO_NOMEM;
    }
    memcpy(buf, ikeypad, HMAC_BLOCK);
    if (msg && msg_len > 0) memcpy(buf + HMAC_BLOCK, msg, msg_len);
    crypto_sha256(inner, buf, HMAC_BLOCK + msg_len);
    crypto_wipe(buf, HMAC_BLOCK + msg_len);
    free(buf);

    /* outer = H(okeypad || inner) */
    unsigned char obuf[HMAC_BLOCK + 32];
    memcpy(obuf, okeypad, HMAC_BLOCK);
    memcpy(obuf + HMAC_BLOCK, inner, 32);
    crypto_sha256(out, obuf, HMAC_BLOCK + 32);

    crypto_wipe(k, sizeof(k));
    crypto_wipe(ikeypad, sizeof(ikeypad));
    crypto_wipe(okeypad, sizeof(okeypad));
    crypto_wipe(inner, sizeof(inner));
    crypto_wipe(obuf, sizeof(obuf));
    return CRYPTO_OK;
}

CRYPTO_API crypto_err_t crypto_hmac_verify(const uint8_t mac[32],
                                         const uint8_t *key, size_t key_len,
                                         const uint8_t *msg, size_t msg_len) {
    if (!mac) return CRYPTO_ERR;
    uint8_t expect[32];
    crypto_err_t rc = crypto_hmac(expect, key, key_len, msg, msg_len);
    if (rc != CRYPTO_OK) return rc;
    /* 常量时间比较 */
    int eq = crypto_ct_memcmp(expect, mac, 32);
    crypto_wipe(expect, sizeof(expect));
    return eq == 0 ? CRYPTO_OK : CRYPTO_TAG_MISMATCH;
}

/* ==================== HKDF-SHA256（RFC 5869）====================
 * extract: PRK = HMAC-SHA256(salt, IKM)
 * expand:  OKM = T(1) || T(2) || ... 直到够长
 */
CRYPTO_API crypto_err_t crypto_kdf_extract(uint8_t prk[32], const uint8_t *salt,
                                          size_t salt_len, const uint8_t *ikm,
                                          size_t ikm_len) {
    if (!prk) return CRYPTO_ERR;
    /* salt 为空时按 RFC 用全零字符串 */
    if ((!salt || salt_len == 0)) {
        uint8_t zero[32] = {0};
        return crypto_hmac(prk, zero, sizeof(zero), ikm, ikm_len);
    }
    return crypto_hmac(prk, salt, salt_len, ikm, ikm_len);
}

CRYPTO_API crypto_err_t crypto_kdf_expand(uint8_t *okm, size_t okm_len,
                                         const uint8_t prk[32],
                                         const uint8_t *info, size_t info_len) {
    if (!okm || !prk) return CRYPTO_ERR;
    if (okm_len == 0) return CRYPTO_OK;
    /* RFC 5869 限制：不超过 255 个块，即 255*32 = 8160 字节 */
    if (okm_len > 255 * 32) return CRYPTO_OVERFLOW;

    uint8_t T[32];
    crypto_wipe(T, sizeof(T));
    size_t done = 0;
    uint8_t counter = 1;
    unsigned char *buf = (unsigned char *)malloc(32 + info_len + 1);
    if (!buf) return CRYPTO_NOMEM;

    while (done < okm_len) {
        size_t off = 0;
        if (counter > 1) {
            memcpy(buf, T, 32);
            off = 32;
        }
        if (info && info_len > 0) {
            memcpy(buf + off, info, info_len);
            off += info_len;
        }
        buf[off++] = counter;
        crypto_hmac(T, prk, 32, buf, off);

        size_t take = okm_len - done;
        if (take > 32) take = 32;
        memcpy(okm + done, T, take);
        done += take;
        counter++;
    }
    crypto_wipe(buf, 32 + info_len + 1);
    free(buf);
    crypto_wipe(T, sizeof(T));
    return CRYPTO_OK;
}

CRYPTO_API crypto_err_t crypto_kdf_derive(uint8_t *okm, size_t okm_len,
                                        const uint8_t *master_key,
                                        size_t mk_len, const uint8_t *info,
                                        size_t info_len) {
    if (!okm) return CRYPTO_ERR;
    uint8_t prk[32];
    crypto_err_t rc = crypto_kdf_extract(prk, NULL, 0, master_key, mk_len);
    if (rc != CRYPTO_OK) return rc;
    rc = crypto_kdf_expand(okm, okm_len, prk, info, info_len);
    crypto_wipe(prk, sizeof(prk));
    return rc;
}
