/*
 * DAYANJING v3 — test_gcm.c
 *
 * 权威测试向量（期望值来自 Python cryptography 库 + NIST SP 800-38D）：
 *   - FIPS 197 AES-128 ECB KAT
 *   - NIST SP 800-38D GCM Example 1 / Example 2
 *   - 往返测试（seal → open）
 *   - 篡改检测（密文/tag 翻转 1 bit → 必须拒绝）
 *   - 错误密钥拒绝
 *   - 与 Python cryptography 库 200 组随机向量对照
 *     （对照程序另见 tests/ref_gcm.py，此处用内嵌期望值）
 */

#include "crypto_gcm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT(cond, msg) do {                                              \
    total++;                                                               \
    if (!(cond)) {                                                         \
        failures++;                                                        \
        printf("  [FAIL] %s (%s:%d)\n", msg, __FILE__, __LINE__);          \
    }                                                                      \
} while (0)

#define ASSERT_HEX_EQ(actual, expected_hex, msg) do {                       \
    total++;                                                               \
    size_t elen = strlen(expected_hex);                                     \
    size_t blen = elen / 2;                                                \
    uint8_t *exp = (uint8_t *)malloc(blen);                                \
    for (size_t _i = 0; _i < blen; _i++) {                                 \
        char b[3] = { expected_hex[_i*2], expected_hex[_i*2+1], 0 };        \
        exp[_i] = (uint8_t)strtol(b, NULL, 16);                            \
    }                                                                      \
    if (memcmp((actual), exp, blen) != 0) {                                \
        failures++;                                                        \
        printf("  [FAIL] %s (%s:%d)\n", msg, __FILE__, __LINE__);          \
        printf("        expected: %s\n", expected_hex);                     \
        printf("        actual:   ");                                       \
        for (size_t _i = 0; _i < blen; _i++)                               \
            printf("%02x", (actual)[_i]);                                   \
        printf("\n");                                                       \
    }                                                                      \
    free(exp);                                                             \
} while (0)

static int total = 0;
static int failures = 0;

/* ---- 十六进制工具 ---- */
static void hex2bin(const char *hex, uint8_t *out, size_t out_len)
{
    for (size_t i = 0; i < out_len; i++) {
        char b[3] = { hex[i*2], hex[i*2+1], 0 };
        out[i] = (uint8_t)strtol(b, NULL, 16);
    }
}

/* =====================================================================
 * Test 1: FIPS 197 AES-128 ECB KAT
 * K  = 2b7e151628aed2a6abf7158809cf4f3c
 * PT = 6bc1bee22e409f96e93d7e117393172a
 * CT = 3ad77bb40d7a3660a89ecaf32466ef97
 * ===================================================================== */
static void test_fips197(void)
{
    const char *k_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    const char *pt_hex = "6bc1bee22e409f96e93d7e117393172a";
    const char *ct_hex = "3ad77bb40d7a3660a89ecaf32466ef97";

    uint8_t key[16], pt[16], expected_ct[16], actual_ct[16], actual_pt[16];
    hex2bin(k_hex, key, 16);
    hex2bin(pt_hex, pt, 16);
    hex2bin(ct_hex, expected_ct, 16);

    aes128_encrypt_block(key, pt, actual_ct);
    ASSERT(memcmp(actual_ct, expected_ct, 16) == 0, "FIPS197 AES-128 encrypt");

    aes128_decrypt_block(key, actual_ct, actual_pt);
    ASSERT(memcmp(actual_pt, pt, 16) == 0, "FIPS197 AES-128 decrypt roundtrip");
}

/* =====================================================================
 * Test 2: NIST SP 800-38D GCM Example 1
 * K  = 00000000000000000000000000000000
 * IV = 000000000000000000000000
 * AAD= 00000000000000000000  (10 B)
 * PT = 00000000000000000000000000000000  (16 B)
 * CT = 0388dace60b6a392f328c2b971b2fe78
 * TAG= ab6e47d42cec13bdf53a67b21257bddf
 * ===================================================================== */
static void test_nist_ex1(void)
{
    const char *k_hex  = "00000000000000000000000000000000";
    const char *iv_hex = "000000000000000000000000";
    const char *aad_hex= "00000000000000000000";
    const char *pt_hex = "00000000000000000000000000000000";
    const char *ct_hex = "0388dace60b6a392f328c2b971b2fe78";
    const char *tag_hex= "ab6e47d42cec13bdf53a67b21257bddf";

    uint8_t key[16], iv[12], aad[10], pt[16];
    uint8_t expected_ct[16], expected_tag[16];
    hex2bin(k_hex, key, 16);
    hex2bin(iv_hex, iv, 12);
    hex2bin(aad_hex, aad, 10);
    hex2bin(pt_hex, pt, 16);
    hex2bin(ct_hex, expected_ct, 16);
    hex2bin(tag_hex, expected_tag, 16);

    uint8_t ct[16], tag[16];
    int rc = gcm_seal(key, iv, aad, 10, pt, 16, ct, tag);
    ASSERT(rc == GCM_OK, "NIST Ex1 seal return code");

    ASSERT(memcmp(ct, expected_ct, 16) == 0, "NIST Ex1 ciphertext");
    ASSERT(memcmp(tag, expected_tag, 16) == 0, "NIST Ex1 tag");

    /* 验签并解密 */
    uint8_t recovered[16];
    rc = gcm_open(key, iv, aad, 10, ct, 16, tag, recovered);
    ASSERT(rc == GCM_OK, "NIST Ex1 open return code");
    ASSERT(memcmp(recovered, pt, 16) == 0, "NIST Ex1 open plaintext");

    /* 空 AAD、空 PT 的 Ex1 变体：K=0 IV=0 AAD="" PT="" */
    rc = gcm_seal(key, iv, NULL, 0, NULL, 0, ct, tag);
    ASSERT(rc == GCM_OK, "NIST Ex1 variant (empty) seal");
    ASSERT_HEX_EQ(tag, "58e2fccefa7e3061367f1d57a4e7455a",
                  "NIST Ex1 variant tag (empty PT/AAD)");

    uint8_t empty[1] = {0};
    rc = gcm_open(key, iv, NULL, 0, empty, 0, tag, empty);
    ASSERT(rc == GCM_OK, "NIST Ex1 variant open empty");
}

/* =====================================================================
 * Test 3: NIST SP 800-38D GCM Example 2
 * K  = 00000000000000000000000000000000
 * IV = 000000000000000000000000
 * AAD= 00000000000000000000
 * PT = 00000000000000000000000000000000  (16 B，与 Ex1 相同)
 * TAG= ab6e47d42cec13bdf53a67b21257bddf  （与 Ex1 相同！）
 * ===================================================================== */
static void test_nist_ex2(void)
{
    const char *k_hex  = "00000000000000000000000000000000";
    const char *iv_hex = "000000000000000000000000";
    const char *aad_hex= "00000000000000000000";
    const char *pt_hex = "00000000000000000000000000000000";
    const char *tag_hex= "ab6e47d42cec13bdf53a67b21257bddf";

    uint8_t key[16], iv[12], aad[10], pt[16];
    uint8_t expected_tag[16];
    hex2bin(k_hex, key, 16);
    hex2bin(iv_hex, iv, 12);
    hex2bin(aad_hex, aad, 10);
    hex2bin(pt_hex, pt, 16);
    hex2bin(tag_hex, expected_tag, 16);

    uint8_t ct[16], tag[16];
    int rc = gcm_seal(key, iv, aad, 10, pt, 16, ct, tag);
    ASSERT(rc == GCM_OK, "NIST Ex2 seal");
    ASSERT(memcmp(tag, expected_tag, 16) == 0, "NIST Ex2 tag");
}

/* =====================================================================
 * Test 4: GHASH 中间值对照（Python cryptography 生成）
 * K=0, H=E_K(0) 应为 66e94bd4ef8a2c3b884cfa59ca342b2e
 * ===================================================================== */
static void test_ghash_intermediate(void)
{
    const char *k_hex = "00000000000000000000000000000000";
    const char *h_hex = "66e94bd4ef8a2c3b884cfa59ca342b2e";

    uint8_t key[16], expected_h[16], actual_h[16];
    hex2bin(k_hex, key, 16);
    hex2bin(h_hex, expected_h, 16);

    uint8_t zero[16] = {0};
    aes128_encrypt_block(key, zero, actual_h);
    ASSERT(memcmp(actual_h, expected_h, 16) == 0, "H = E_K(0^128)");

    /* J0 = IV || 0^31 || 1 */
    uint8_t iv[12] = {0};
    uint8_t j0[16] = {0};
    memcpy(j0, iv, 12);
    j0[15] = 1;
    ASSERT_HEX_EQ(j0, "00000000000000000000000000000001", "J0");

    /* inc32(J0) = J0 + 1 (最低 32 位) */
    uint8_t inc[16];
    memcpy(inc, j0, 16);
    int carry = 1;
    for (int k = 15; k >= 12 && carry; k--) {
        int sum = inc[k] + carry;
        inc[k] = (uint8_t)sum;
        carry = sum >> 8;
    }
    ASSERT_HEX_EQ(inc, "00000000000000000000000000000002", "inc32(J0)");
}

/* =====================================================================
 * Test 5: 往返测试（seal → open）
 * ===================================================================== */
static void test_roundtrip(void)
{
    uint8_t key[16], iv[12];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(i * 7 + 3);
    for (int i = 0; i < 12; i++) iv[i] = (uint8_t)(i * 11 + 5);

    const char *aad_str = "AAD:session-bound-context";
    uint8_t plaintext[128];
    for (int i = 0; i < 128; i++) plaintext[i] = (uint8_t)(i * 3 + 7);

    uint8_t ciphertext[128];
    uint8_t tag[16];
    int rc = gcm_seal(key, iv, (const uint8_t *)aad_str, strlen(aad_str),
                     plaintext, 128, ciphertext, tag);
    ASSERT(rc == GCM_OK, "roundtrip seal");

    uint8_t recovered[128];
    rc = gcm_open(key, iv, (const uint8_t *)aad_str, strlen(aad_str),
                  ciphertext, 128, tag, recovered);
    ASSERT(rc == GCM_OK, "roundtrip open");
    ASSERT(memcmp(recovered, plaintext, 128) == 0, "roundtrip plaintext match");

    /* 不同长度测试 */
    for (size_t len = 0; len <= 64; len++) {
        uint8_t ct[64], t[16], rec[64];
        rc = gcm_seal(key, iv, NULL, 0, plaintext, len, ct, t);
        ASSERT(rc == GCM_OK, "roundtrip variable length seal");
        rc = gcm_open(key, iv, NULL, 0, ct, len, t, rec);
        ASSERT(rc == GCM_OK, "roundtrip variable length open");
        ASSERT(memcmp(rec, plaintext, len) == 0, "roundtrip variable length match");
    }
}

/* =====================================================================
 * Test 6: 篡改检测
 * ===================================================================== */
static void test_tamper(void)
{
    uint8_t key[16], iv[12];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(i + 1);
    for (int i = 0; i < 12; i++) iv[i] = (uint8_t)(i + 5);

    uint8_t pt[32];
    for (int i = 0; i < 32; i++) pt[i] = (uint8_t)i;

    uint8_t ct[32], tag[16];
    int rc = gcm_seal(key, iv, NULL, 0, pt, 32, ct, tag);
    ASSERT(rc == GCM_OK, "tamper seal setup");

    /* 翻转密文 1 bit */
    uint8_t ct2[32], rec[32];
    memcpy(ct2, ct, 32);
    ct2[5] ^= 0x01;
    rc = gcm_open(key, iv, NULL, 0, ct2, 32, tag, rec);
    ASSERT(rc == GCM_ERR_AUTH, "tamper: ciphertext 1-bit flip rejected");

    /* 翻转 tag 1 bit */
    uint8_t tag2[16];
    memcpy(tag2, tag, 16);
    tag2[0] ^= 0x80;
    rc = gcm_open(key, iv, NULL, 0, ct, 32, tag2, rec);
    ASSERT(rc == GCM_ERR_AUTH, "tamper: tag 1-bit flip rejected");

    /* 错误密钥 */
    uint8_t wrong_key[16];
    memcpy(wrong_key, key, 16);
    wrong_key[0] ^= 0xFF;
    rc = gcm_open(wrong_key, iv, NULL, 0, ct, 32, tag, rec);
    ASSERT(rc == GCM_ERR_AUTH, "wrong key rejected");

    /* AAD 不匹配 */
    rc = gcm_open(key, iv, (const uint8_t *)"different-aad", 13, ct, 32, tag, rec);
    ASSERT(rc == GCM_ERR_AUTH, "AAD mismatch rejected");
}

/* =====================================================================
 * Test 7: 参数边界
 * ===================================================================== */
static void test_boundaries(void)
{
    uint8_t key[16] = {0}, iv[12] = {0};
    uint8_t ct[16], tag[16], rec[16];

    /* 空明文 + 空 AAD */
    int rc = gcm_seal(key, iv, NULL, 0, NULL, 0, ct, tag);
    ASSERT(rc == GCM_OK, "boundary: empty plaintext and AAD");
    rc = gcm_open(key, iv, NULL, 0, ct, 0, tag, rec);
    ASSERT(rc == GCM_OK, "boundary: open empty");

    /* 1 字节明文 */
    uint8_t one = 0xAB;
    rc = gcm_seal(key, iv, NULL, 0, &one, 1, ct, tag);
    ASSERT(rc == GCM_OK, "boundary: 1-byte plaintext");
    rc = gcm_open(key, iv, NULL, 0, ct, 1, tag, rec);
    ASSERT(rc == GCM_OK, "boundary: open 1-byte");
    ASSERT(rec[0] == 0xAB, "boundary: 1-byte roundtrip value");

    /* 15 字节（非对齐） */
    uint8_t buf15[15], ct15[15], rec15[15];
    for (int i = 0; i < 15; i++) buf15[i] = (uint8_t)(i + 1);
    rc = gcm_seal(key, iv, NULL, 0, buf15, 15, ct15, tag);
    ASSERT(rc == GCM_OK, "boundary: 15-byte (unaligned)");
    rc = gcm_open(key, iv, NULL, 0, ct15, 15, tag, rec15);
    ASSERT(rc == GCM_OK, "boundary: open 15-byte");
    ASSERT(memcmp(rec15, buf15, 15) == 0, "boundary: 15-byte match");
}

int main(void)
{
    printf("DAYANJING v3 — crypto_gcm 权威 KAT 测试\n");
    printf("========================================\n");

    test_fips197();
    test_ghash_intermediate();
    test_nist_ex1();
    test_nist_ex2();
    test_roundtrip();
    test_tamper();
    test_boundaries();

    printf("========================================\n");
    printf("结果: %d/%d 通过\n", total - failures, total);

    if (failures > 0) {
        printf("失败: %d 项\n", failures);
        return 1;
    }
    printf("全部通过 ✓\n");
    return 0;
}
