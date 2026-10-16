#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 统一导出宏：配合 -fvisibility=hidden，只有 CRYPTO_API 标注的符号对外可见。
 * 与 11_edr_bypass/ 的 DS_API 保持一致的做法。
 */
#if defined(_WIN32)
#  if defined(CRYPTO_BUILD_SHARED)
#    define CRYPTO_API __declspec(dllexport)
#  else
#    define CRYPTO_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#  define CRYPTO_API __attribute__((visibility("default")))
#else
#  define CRYPTO_API
#endif

#define CRYPTO_VERSION        "0.1.0"

/* 所有对称密钥统一 256-bit */
#define CRYPTO_KEY_LEN        32
/* ChaCha20-Poly1305 nonce：96-bit（RFC 7539 §2.6） */
#define CRYPTO_NONCE_LEN      12
/* 认证标签：128-bit */
#define CRYPTO_TAG_LEN        16
/* SHA-256 / HMAC-SHA256 输出长度 */
#define CRYPTO_HASH_LEN       32
#define CRYPTO_HMAC_LEN       32

/* ==================== 错误码 ==================== */
typedef enum {
    CRYPTO_OK            = 0,
    CRYPTO_ERR           = -1,
    CRYPTO_INVALID_KEY   = -2,
    CRYPTO_INVALID_NONCE = -3,
    CRYPTO_TAG_MISMATCH  = -4,   /* 认证失败：密文被篡改或密钥错误 */
    CRYPTO_NOMEM         = -5,
    CRYPTO_RNG_FAILED    = -6,
    CRYPTO_NOTSUP        = -7,   /* 未实现（如 X25519 / Ed25519） */
    CRYPTO_OVERFLOW      = -8,   /* 长度溢出 */
} crypto_err_t;

CRYPTO_API const char *crypto_strerror(crypto_err_t e);

/* ==================== 安全内存 ==================== */
/* explicit_bzero / memset_s 的安全清零：编译器不得优化掉 */
CRYPTO_API void crypto_wipe(void *buf, size_t len);

/* 锁页 / 解锁（防止密钥被换出到 swap） */
CRYPTO_API int  crypto_mlock(const void *addr, size_t len);
CRYPTO_API int  crypto_munlock(void *addr, size_t len);

/* ==================== 安全随机数 ==================== */
/* 密码学安全随机数，失败返回 CRYPTO_RNG_FAILED */
CRYPTO_API crypto_err_t crypto_rng(void *out, size_t len);
CRYPTO_API uint32_t      crypto_rng_u32(void);
CRYPTO_API uint64_t      crypto_rng_u64(void);

/* ==================== 常量时间比较 ==================== */
/* 无论输入如何，耗时恒定；返回 0 表示相等。用于 HMAC / tag 校验。 */
CRYPTO_API int crypto_ct_memcmp(const void *a, const void *b, size_t len);

/* ==================== SHA-256 ==================== */
CRYPTO_API crypto_err_t crypto_sha256(uint8_t out[CRYPTO_HASH_LEN],
                                     const uint8_t *msg, size_t msg_len);

/* ==================== HMAC-SHA256 ==================== */
CRYPTO_API crypto_err_t crypto_hmac(uint8_t out[CRYPTO_HMAC_LEN],
                                   const uint8_t *key, size_t key_len,
                                   const uint8_t *msg, size_t msg_len);

/* 常量时间验证；不要在调用方用 memcmp，那会泄漏时序 */
CRYPTO_API crypto_err_t crypto_hmac_verify(const uint8_t mac[CRYPTO_HMAC_LEN],
                                          const uint8_t *key, size_t key_len,
                                          const uint8_t *msg, size_t msg_len);

/* ==================== HKDF-SHA256（RFC 5869）=================== */
CRYPTO_API crypto_err_t crypto_kdf_extract(uint8_t prk[CRYPTO_HASH_LEN],
                                           const uint8_t *salt, size_t salt_len,
                                           const uint8_t *ikm, size_t ikm_len);

CRYPTO_API crypto_err_t crypto_kdf_expand(uint8_t *okm, size_t okm_len,
                                          const uint8_t prk[CRYPTO_HASH_LEN],
                                          const uint8_t *info, size_t info_len);

/* 一键派生：master -> 用途隔离的子密钥 */
CRYPTO_API crypto_err_t crypto_kdf_derive(uint8_t *okm, size_t okm_len,
                                         const uint8_t *master_key,
                                         size_t mk_len,
                                         const uint8_t *info, size_t info_len);

/* ==================== ChaCha20 原始流密码 ==================== */
/* counter 从 0 起；调用方负责 nonce 不重用 */
CRYPTO_API crypto_err_t crypto_chacha20(uint8_t *out, const uint8_t *in,
                                        size_t len,
                                        const uint8_t key[CRYPTO_KEY_LEN],
                                        const uint8_t nonce[CRYPTO_NONCE_LEN],
                                        uint32_t counter);

/* Poly1305 MAC（内部使用，AEAD 层调用；也导出供高级用户使用）
 * 实现 RFC 7539 §2.5 的 130-bit 素数域运算。
 */
CRYPTO_API crypto_err_t crypto_poly1305(uint8_t mac[16], const uint8_t *msg,
                                       size_t msg_len, const uint8_t key[32]);

/* ==================== AEAD：ChaCha20-Poly1305（RFC 7539）=================== */
/*
 * ciphertext 缓冲区必须能容纳 pt_len + CRYPTO_TAG_LEN 字节。
 * 输出布局：ciphertext[0 .. pt_len-1] 为密文，末尾 16 字节为认证标签。
 * 解密时若返回 CRYPTO_TAG_MISMATCH，plaintext 缓冲区保持未写入状态。
 */
CRYPTO_API crypto_err_t crypto_aead_seal(uint8_t *ciphertext, size_t *out_len,
                                        const uint8_t *plaintext, size_t pt_len,
                                        const uint8_t *ad, size_t ad_len,
                                        const uint8_t key[CRYPTO_KEY_LEN],
                                        const uint8_t nonce[CRYPTO_NONCE_LEN]);

CRYPTO_API crypto_err_t crypto_aead_open(uint8_t *plaintext, size_t *out_len,
                                        const uint8_t *ciphertext, size_t ct_len,
                                        const uint8_t *ad, size_t ad_len,
                                        const uint8_t key[CRYPTO_KEY_LEN],
                                        const uint8_t nonce[CRYPTO_NONCE_LEN]);

/* ==================== 会话封装：自动管理 nonce ==================== */
struct crypto_session {
    uint8_t  key[CRYPTO_KEY_LEN];
    uint8_t  nonce[CRYPTO_NONCE_LEN];   /* 用作 base nonce，前 4 字节为计数器 */
    uint32_t counter;                    /* 单调递增，溢出即报错 */
    bool     initialized;
};

CRYPTO_API crypto_err_t crypto_session_init(struct crypto_session *s,
                                           const uint8_t key[CRYPTO_KEY_LEN]);

CRYPTO_API crypto_err_t crypto_session_seal(struct crypto_session *s,
                                           uint8_t *ciphertext,
                                           size_t *out_len,
                                           const uint8_t *plaintext,
                                           size_t pt_len,
                                           const uint8_t *ad, size_t ad_len);

CRYPTO_API crypto_err_t crypto_session_open(struct crypto_session *s,
                                           uint8_t *plaintext,
                                           size_t *out_len,
                                           const uint8_t *ciphertext,
                                           size_t ct_len,
                                           const uint8_t *ad, size_t ad_len);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_H */
