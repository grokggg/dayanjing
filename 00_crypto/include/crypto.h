#define _GNU_SOURCE
#ifndef CRYPTO_H
#define _POSIX_C_SOURCE 200809L
#define CRYPTO_H

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

#define CRYPTO_OK             0
#define CRYPTO_ERR           (-1)
#define CRYPTO_ERR_FORMAT    (-2)
#define CRYPTO_ERR_AUTH      (-3)
#define CRYPTO_ERR_NOMEM     (-4)

#define CRYPTO_KEY_LEN       32
#define CRYPTO_NONCE_LEN     12
#define CRYPTO_TAG_LEN       16
#define CRYPTO_HASH_LEN      32
#define CRYPTO_HMAC_LEN      32
#define CRYPTO_X25519_LEN    32

typedef struct {
    uint8_t key[CRYPTO_KEY_LEN];
} crypto_aead_ctx_t;

/* AEAD: ChaCha20-Poly1305 (self-contained, no OpenSSL) */
int crypto_aead_seal(const uint8_t *key, const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *plain, size_t plain_len,
                     uint8_t *cipher, uint8_t *tag);
int crypto_aead_open(const uint8_t *key, const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *cipher, size_t cipher_len,
                     const uint8_t *tag, uint8_t *plain);

/* HKDF-SHA256 */
int crypto_hkdf(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *out, size_t out_len);

/* HMAC-SHA256 */
int crypto_hmac(const uint8_t *key, size_t key_len,
                const uint8_t *msg, size_t msg_len,
                uint8_t *out);
/* constant-time compare */
int crypto_hmac_verify(const uint8_t *a, const uint8_t *b, size_t len);

/* secure zero */
void crypto_secure_zero(void *buf, size_t len);

/* CSPRNG */
int crypto_rng(uint8_t *buf, size_t len);

/* X25519 */
int crypto_x25519_keypair(uint8_t *priv, uint8_t *pub);
int crypto_x25519_shared(const uint8_t *priv, const uint8_t *pub, uint8_t *shared);

/* SHA-256 (for HKDF) */
void crypto_sha256(const uint8_t *msg, size_t len, uint8_t *digest);

const char *crypto_strerror(int err);

#endif
