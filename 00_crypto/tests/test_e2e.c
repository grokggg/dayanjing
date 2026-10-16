#include "crypto.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

/* 端到端测试：模拟一个最小 C2 协议帧的加密通信
 *
 * 协议设计：
 *   - master_key 派生出 enc_key（AEAD）和 auth_key（HMAC）
 *   - 每条消息 = AEAD(seal(payload))，AAD 里放消息序号
 *   - HMAC 覆盖整个密文，用于无状态快速拒绝
 *   - 模拟 1000 条消息，验证往返 + 抗篡改
 */
struct frame {
    uint8_t hmac[32];      /* 外层 HMAC */
    uint8_t ciphertext[2048];
    size_t   ct_len;
};

static void build_frame(const uint8_t enc_key[32], const uint8_t auth_key[32],
                       uint64_t seq, const uint8_t *payload, size_t plen,
                       struct frame *out) {
    /* AAD = 序列号（小端 64-bit），同时用它派生 nonce（取低 96-bit） */
    uint8_t aad[8];
    for (int i = 0; i < 8; i++) aad[i] = (uint8_t)(seq >> (i * 8));
    uint8_t nonce[12];
    memset(nonce, 0, sizeof(nonce));
    memcpy(nonce, aad, 8);   /* nonce[0..7] = seq; nonce[8..11] = 0 */

    size_t o = 0;
    crypto_aead_seal(out->ciphertext, &o, payload, plen, aad, 8, enc_key, nonce);
    out->ct_len = o;

    /* 外层 HMAC 覆盖密文（独立密钥，用于无状态快速拒绝） */
    crypto_hmac(out->hmac, auth_key, 32, out->ciphertext, o);
}

static crypto_err_t open_frame(const uint8_t enc_key[32], const uint8_t auth_key[32],
                              uint64_t seq, const struct frame *f,
                              uint8_t *payload_out, size_t *out_len) {
    /* 1. 外层 HMAC 验证（无状态快速拒绝恶意/损坏帧） */
    crypto_err_t rc = crypto_hmac_verify(f->hmac, auth_key, 32,
                                        f->ciphertext, f->ct_len);
    if (rc != CRYPTO_OK) return rc;

    /* 2. AEAD 解密（用相同方式派生 nonce 和 AAD） */
    uint8_t aad[8];
    for (int i = 0; i < 8; i++) aad[i] = (uint8_t)(seq >> (i * 8));
    uint8_t nonce[12];
    memset(nonce, 0, sizeof(nonce));
    memcpy(nonce, aad, 8);
    return crypto_aead_open(payload_out, out_len,
                          f->ciphertext, f->ct_len,
                          aad, 8, enc_key, nonce);
}

int main(void) {
    printf("[*] 端到端集成测试：模拟 C2 协议帧\n");

    /* ---- 1. 主密钥派生两个用途隔离的子密钥 ---- */
    uint8_t master[32];
    crypto_rng(master, 32);
    uint8_t enc_key[32], auth_key[32];
    crypto_kdf_derive(enc_key, 32, master, 32, (const uint8_t *)"c2-enc", 6);
    crypto_kdf_derive(auth_key, 32, master, 32, (const uint8_t *)"c2-auth", 7);
    assert(memcmp(enc_key, auth_key, 32) != 0);
    printf("  [+] 主密钥派生 enc_key / auth_key（用途隔离）\n");

    /* ---- 2. 1000 条消息往返 ---- */
    struct frame *frames = malloc(1000 * sizeof(struct frame));
    assert(frames);
    uint8_t *payloads = malloc(1000 * 256);
    assert(payloads);

    for (int i = 0; i < 1000; i++) {
        /* 生成随机 payload */
        size_t plen = 16u + (size_t)(i % 240);   /* 16..255 字节 */
        crypto_rng(payloads + i * 256, plen);
        build_frame(enc_key, auth_key, (uint64_t)i,
                   payloads + i * 256, plen, &frames[i]);
    }
    printf("  [+] 构建 1000 条加密帧\n");

    /* ---- 3. 逐条解密验证 ---- */
    uint8_t *decrypted = malloc(2048);
    assert(decrypted);
    for (int i = 0; i < 1000; i++) {
        size_t plen = 16u + (size_t)(i % 240);
        size_t olen = 0;
        crypto_err_t rc = open_frame(enc_key, auth_key, (uint64_t)i,
                                    &frames[i], decrypted, &olen);
        assert(rc == CRYPTO_OK);
        assert(olen == plen);
        assert(memcmp(decrypted, payloads + i * 256, plen) == 0);
    }
    printf("  [+] 1000 条帧全部正确解密\n");

    /* ---- 4. 篡改其中一条的密文：HMAC 层应拒绝 ---- */
    frames[42].ciphertext[5] ^= 0x01;
    size_t olen = 0;
    crypto_err_t rc = open_frame(enc_key, auth_key, 42,
                               &frames[42], decrypted, &olen);
    assert(rc == CRYPTO_TAG_MISMATCH);
    printf("  [+] 篡改帧 #42 被 HMAC 层拒绝\n");

    /* ---- 5. 序列号错乱：AEAD 层应拒绝 ---- */
    /* 恢复帧 #42，改用错误 seq 解密 */
    frames[42].ciphertext[5] ^= 0x01;   /* 还原 */
    rc = open_frame(enc_key, auth_key, 99,   /* 错误 seq */
                   &frames[42], decrypted, &olen);
    assert(rc == CRYPTO_TAG_MISMATCH);
    printf("  [+] 错误序列号 -> AEAD 拒绝\n");

    /* ---- 6. 密钥全零擦除后不可用 ---- */
    crypto_wipe(master, 32);
    crypto_wipe(enc_key, 32);
    crypto_wipe(auth_key, 32);
    int allzero = 1;
    for (int i = 0; i < 32; i++) if (master[i]) allzero = 0;
    assert(allzero);
    printf("  [+] 主密钥已安全擦除\n");

    free(frames);
    free(payloads);
    free(decrypted);

    printf("\n[+] 端到端集成测试全部通过\n");
    return 0;
}
