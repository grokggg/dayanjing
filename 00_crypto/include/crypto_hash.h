/*
 * DAYANJING v3 — crypto_hash.h
 *
 * SHA-256 / HMAC-SHA256 / HKDF(RFC 5869) 自研实现（C11）。
 *
 * 存在理由：
 *   00_crypto 原本只有 AES-128-GCM。而 Python 侧（crypto_layer.py /
 *   key_derivation.py）的密钥派生建立在 HKDF-SHA256 之上。C 侧若要与
 *   Python 侧互操作（c2 握手、会话密钥派生），必须具备同一套 KDF，
 *   否则两端派生结果必然不同。本文件补齐这一层，使 C 与 Python 可对通。
 *
 * 契约（与 Python 侧逐字节一致）：
 *   - SHA-256  : FIPS 180-4，输出 32 字节
 *   - HMAC     : RFC 2104，key > 64 字节时先哈希，ipad/opad 标准构造
 *   - HKDF     : RFC 5869 Extract+Expand，底层 PRF 为 HMAC-SHA256
 *   - Extract  : salt 为空时按 RFC 5869 §2.2 使用 HashLen(32) 个零字节
 *
 * 不依赖 OpenSSL。
 */

#ifndef DAYANJING_CRYPTO_HASH_H
#define DAYANJING_CRYPTO_HASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 常量 ---- */
#define SHA256_DIGEST_LEN 32
#define SHA256_BLOCK_LEN  64
#define HMAC_SHA256_LEN   32
#define HKDF_HASH_LEN     32   /* HMAC-SHA256 的 PRK / HashLen */

/* ---- 返回值 ---- */
#define HASH_OK        0
#define HASH_ERR_ARG  -1    /* 参数非法（NULL 指针等） */
#define HASH_ERR_LEN  -2    /* 输出长度非法（Expand 的 L 过大或为 0） */

/* ====================================================================
 * SHA-256
 * ==================================================================== */

typedef struct {
    uint32_t h[8];
    uint8_t  buf[SHA256_BLOCK_LEN];
    size_t   buf_len;
    uint64_t total_len;   /* 已处理的消息总字节数 */
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[SHA256_DIGEST_LEN]);

/* 一次性哈希：data 可为 NULL（len=0），此时等价于哈希空串 */
void sha256(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_LEN]);

/* ====================================================================
 * HMAC-SHA256（RFC 2104）
 * ==================================================================== */

/*
 * key 可为 NULL（key_len=0），此时按 RFC 2104 使用零填充密钥。
 * key_len > 64 时先做一次 SHA-256 压缩（标准行为）。
 */
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[HMAC_SHA256_LEN]);

/* ====================================================================
 * HKDF（RFC 5869），PRF = HMAC-SHA256
 * ==================================================================== */

/*
 * Extract: PRK = HMAC(salt, IKM)
 * salt 为 NULL 或 salt_len==0 时，按 §2.2 使用 32 个零字节。
 * 返回 HASH_OK 表示成功，prk 写出 32 字节。
 */
int hkdf_extract(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 uint8_t prk[HKDF_HASH_LEN]);

/*
 * Expand: OKM = T(1) | T(2) | ... 的前 len 字节
 *   T(0) = 空串
 *   T(i) = HMAC(PRK, T(i-1) | info | byte(i))
 * len 必须 >= 1 且 <= 255 * 32（RFC 5869 §2.3 上限），否则返回 HASH_ERR_LEN。
 */
int hkdf_expand(const uint8_t prk[HKDF_HASH_LEN],
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t len);

/*
 * 便捷封装：Extract 再 Expand。
 * 等价 Python 侧 hkdf(salt, ikm, info, length)。
 */
int hkdf(const uint8_t *salt, size_t salt_len,
         const uint8_t *ikm, size_t ikm_len,
         const uint8_t *info, size_t info_len,
         uint8_t *okm, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_CRYPTO_HASH_H */
