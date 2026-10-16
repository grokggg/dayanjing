#include "crypto.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

/* ChaCha20-Poly1305 AEAD 测试
 * 使用一个可控的测试向量来验证 seal/open 的正确性，
 * 并额外验证篡改检测、AAD 绑定、错误密钥等安全属性。
 */
int main(void) {
    printf("[*] ChaCha20-Poly1305 AEAD 测试\n");

    uint8_t key[32];
    memset(key, 0x42, 32);   /* 固定密钥便于复现 */
    uint8_t nonce[12];
    memset(nonce, 0x11, 12);

    const char *aad = "session-id-12345";
    const uint8_t pt[16] = {
        0xde,0xad,0xbe,0xef,0x01,0x23,0x45,0x67,
        0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98
    };

    /* ---- 加密 ---- */
    uint8_t ciphertext[32];   /* 16 + 16 */
    size_t out_len = 0;
    crypto_err_t rc = crypto_aead_seal(ciphertext, &out_len,
                                     pt, 16,
                                     (const uint8_t *)aad, strlen(aad),
                                     key, nonce);
    assert(rc == CRYPTO_OK);
    assert(out_len == 32);   /* 16 明文 + 16 tag */
    printf("  [+] seal: out_len=%zu (16+16)\n", out_len);

    /* ---- 解密 ---- */
    uint8_t plaintext[16];
    size_t pt_len = 0;
    rc = crypto_aead_open(plaintext, &pt_len, ciphertext, 32,
                        (const uint8_t *)aad, strlen(aad), key, nonce);
    assert(rc == CRYPTO_OK);
    assert(pt_len == 16);
    assert(memcmp(plaintext, pt, 16) == 0);
    printf("  [+] open: 明文完整还原\n");

    /* ---- 篡改密文 1 bit：必须失败 ---- */
    uint8_t pt_canary[16];
    memset(pt_canary, 0xcc, sizeof(pt_canary));
    ciphertext[10] ^= 0x01;
    rc = crypto_aead_open(pt_canary, &pt_len, ciphertext, 32,
                         (const uint8_t *)aad, strlen(aad), key, nonce);
    assert(rc == CRYPTO_TAG_MISMATCH);
    /* 明文缓冲区不应被写入（解密前已验证 tag） */
    int untouched = 1;
    for (size_t i = 0; i < 16; i++) if (pt_canary[i] != 0xcc) untouched = 0;
    assert(untouched);
    printf("  [+] 篡改密文 1 bit -> TAG_MISMATCH（明文未泄露）\n");

    /* ---- 篡改 AAD：必须失败 ---- */
    char aad2[64];
    memcpy(aad2, aad, strlen(aad) + 1);
    aad2[0] ^= 0x01;
    rc = crypto_aead_open(plaintext, &pt_len, ciphertext, 32,
                         (const uint8_t *)aad2, strlen(aad2), key, nonce);
    assert(rc == CRYPTO_TAG_MISMATCH);
    printf("  [+] 篡改 AAD -> TAG_MISMATCH\n");

    /* ---- 错误密钥：必须失败 ---- */
    uint8_t wrong_key[32];
    memset(wrong_key, 0xff, 32);
    rc = crypto_aead_open(plaintext, &pt_len, ciphertext, 32,
                         (const uint8_t *)aad, strlen(aad), wrong_key, nonce);
    assert(rc == CRYPTO_TAG_MISMATCH);
    printf("  [+] 错误密钥 -> TAG_MISMATCH\n");

    /* ---- 截断密文（不足 16 字节 tag）：必须失败 ---- */
    rc = crypto_aead_open(plaintext, &pt_len, ciphertext, 10, NULL, 0, key, nonce);
    assert(rc == CRYPTO_ERR);
    printf("  [+] 截断输入 -> ERR\n");

    /* ---- 空 AAD + 空明文：应成功 ---- */
    {
        uint8_t k[32], n[12];
        memset(k, 0xaa, 32);
        memset(n, 0xbb, 12);
        uint8_t ct[16], pt2[1];
        size_t o = 0;
        rc = crypto_aead_seal(ct, &o, NULL, 0, NULL, 0, k, n);
        assert(rc == CRYPTO_OK);
        assert(o == 16);
        size_t p = 0;
        rc = crypto_aead_open(pt2, &p, ct, 16, NULL, 0, k, n);
        assert(rc == CRYPTO_OK);
        assert(p == 0);
        printf("  [+] 空 AAD + 空明文往返成功\n");
    }

    /* ---- 确定性：相同 key/nonce/pt/aad 产生相同密文 ---- */
    {
        uint8_t ct1[32], ct2[32];
        size_t l1 = 0, l2 = 0;
        crypto_aead_seal(ct1, &l1, pt, 16, (const uint8_t *)aad, strlen(aad), key, nonce);
        crypto_aead_seal(ct2, &l2, pt, 16, (const uint8_t *)aad, strlen(aad), key, nonce);
        assert(l1 == l2 && memcmp(ct1, ct2, 32) == 0);
        printf("  [+] 相同输入产生确定密文\n");
    }

    printf("\n[+] ChaCha20-Poly1305 AEAD 测试全部通过\n");
    return 0;
}
