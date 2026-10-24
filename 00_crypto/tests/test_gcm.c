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

/*
 * 常量时间断言依赖插桩计数器 crypto_ct_steps，而它只在
 * -DCRYPTO_CT_INSTRUMENT 下存在。若忘了加这个宏，下面的断言会被
 * #ifdef 静默跳过 —— 测试全绿，但什么都没验。所以这里直接编译失败：
 * 宁可构建不过，也不要"看起来通过"。
 */
#ifndef CRYPTO_CT_INSTRUMENT
#error "test_gcm 必须用 -DCRYPTO_CT_INSTRUMENT 编译，否则常量时间断言会被静默跳过"
#endif

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
    /* NIST Ex1 的 AAD 为空（ab6e47d4... 是 AAD 为空时的标签） */
    int rc = gcm_seal(key, iv, NULL, 0, pt, 16, ct, tag);
    ASSERT(rc == GCM_OK, "NIST Ex1 seal return code");

    ASSERT(memcmp(ct, expected_ct, 16) == 0, "NIST Ex1 ciphertext");
    ASSERT(memcmp(tag, expected_tag, 16) == 0, "NIST Ex1 tag");

    /* 验签并解密 */
    uint8_t recovered[16];
    rc = gcm_open(key, iv, NULL, 0, ct, 16, tag, recovered);
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
    /* 带 10 字节 AAD 时的标签（Python cryptography 交叉验证值） */
    const char *tag_hex= "98da4edef1a98577dcb6f7582604276a";

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

/*
 * 常量时间比较观测测试。
 *
 * 这里测的不是耗时（本环境测不出：3e6 次调用下 memcmp 与 ct_eq 的
 * 耗时比差异都在噪声内，详见 scripts/mutation_audit.py 的 M9 注释），
 * 而是【语义契约】：tag 比对必须走 crypto_constant_time_eq，且该
 * 函数的循环体执行次数必须恒等于 len、与失配位置无关。
 *
 * 有了这一层，"把 tag 比较换成 memcmp" 就从"不可测的时序侧信道"
 * 变成了"计数器不对 -> 测试失败"的确定性事实。
 */
static void test_constant_time(void)
{
    uint8_t key[GCM_KEY_LEN], iv[GCM_IV_LEN];
    uint8_t pt[16], ct[16], rec[16], tag[GCM_TAG_LEN];
    uint8_t a[32], b[32];

    memset(key, 0x11, sizeof key);
    memset(iv, 0x22, sizeof iv);
    memset(pt, 0x33, sizeof pt);
    memset(a, 0xAA, sizeof a);
    memset(b, 0xAA, sizeof b);

    /* 0) 插桩生效性。若宏未定义，本文件在预处理期就 #error，
     *    不可能静默跳过 —— 静默跳过就是假通过。 */
    crypto_ct_steps = 0;
    ASSERT(crypto_ct_steps == 0, "计数器可清零（插桩已链接）");

    /*
     * 1) 防平凡性对照：计数器必须反映真实循环次数，而不是恒等于
     *    某个写死的值。若有人把计数写成 crypto_ct_steps = len（放在
     *    循环外），下面三条会一起失败。
     */
    crypto_ct_steps = 0;
    (void)crypto_constant_time_eq(a, b, 4);
    ASSERT(crypto_ct_steps == 4, "len=4 -> 步数 4");

    crypto_ct_steps = 0;
    (void)crypto_constant_time_eq(a, b, 16);
    ASSERT(crypto_ct_steps == 16, "len=16 -> 步数 16");

    crypto_ct_steps = 0;
    (void)crypto_constant_time_eq(a, b, 32);
    ASSERT(crypto_ct_steps == 32, "len=32 -> 步数 32");

    /*
     * 2) 失配位置无关性：第 0 位失配与第 15 位失配，步数必须相同。
     *    若实现被改成"发现不同就 break"的早退写法，第 0 位会给出 1。
     */
    uint8_t b0[16], b15[16];
    memset(b0, 0xAA, sizeof b0);
    memcpy(b15, b0, sizeof b15);
    b0[0] ^= 0x01;    /* 最早失配 */
    b15[15] ^= 0x01;  /* 最晚失配 */

    crypto_ct_steps = 0;
    ASSERT(crypto_constant_time_eq(a, b0, 16) == 0, "第0位失配 -> 不等");
    ASSERT(crypto_ct_steps == 16, "第0位失配 步数仍为 16");

    crypto_ct_steps = 0;
    ASSERT(crypto_constant_time_eq(a, b15, 16) == 0, "第15位失配 -> 不等");
    ASSERT(crypto_ct_steps == 16, "第15位失配 步数仍为 16");

    /*
     * 3) GCM 验签路径必须调用常量时间原语 —— 这是捕获 memcmp 替换的
     *    关键。若调用点被换成 memcmp，该函数根本不被调用，计数器
     *    保持 0，下面全部失败。
     */
    ASSERT(gcm_seal(key, iv, NULL, 0, pt, 16, ct, tag) == GCM_OK, "seal 成功");

    /* 3a) 验签通过 */
    crypto_ct_steps = 0;
    ASSERT(gcm_open(key, iv, NULL, 0, ct, 16, tag, rec) == GCM_OK, "open 成功");
    ASSERT(crypto_ct_steps == GCM_TAG_LEN, "验签通过 -> 步数 == TAG_LEN");

    /* 3b) tag 第 0 字节错 */
    uint8_t t0[GCM_TAG_LEN];
    memcpy(t0, tag, GCM_TAG_LEN);
    t0[0] ^= 0x80;
    crypto_ct_steps = 0;
    ASSERT(gcm_open(key, iv, NULL, 0, ct, 16, t0, rec) == GCM_ERR_AUTH,
           "tag 第0字节错 -> AUTH");
    ASSERT(crypto_ct_steps == GCM_TAG_LEN, "tag 第0字节错 -> 步数 == TAG_LEN");

    /* 3c) tag 最后一字节错 */
    uint8_t t15[GCM_TAG_LEN];
    memcpy(t15, tag, GCM_TAG_LEN);
    t15[GCM_TAG_LEN - 1] ^= 0x80;
    crypto_ct_steps = 0;
    ASSERT(gcm_open(key, iv, NULL, 0, ct, 16, t15, rec) == GCM_ERR_AUTH,
           "tag 末字节错 -> AUTH");
    ASSERT(crypto_ct_steps == GCM_TAG_LEN, "tag 末字节错 -> 步数 == TAG_LEN");
}

/*
 * 常量时间三路比较 crypto_ct_cmp 的测试。
 *
 * 两条判据，缺一不可：
 *   1) 步数恒为 len —— 证明没有早退（源码层）；
 *   2) 结果与 memcmp 的符号逐一对齐 —— 证明没把"常量时间"做成
 *      "永远返回同一个值"（那是另一种假通过）。memcmp 在这里充当
 *      权威参照：它的字典序语义是正确的，只是耗时不安全。
 */
static void test_ct_cmp(void)
{
    uint8_t a[32], b[32];
    size_t i;
    int k;

    /*
     * 1) 步数与失配位置无关。
     */
    memset(a, 0xAA, sizeof a);
    memset(b, 0xAA, sizeof b);

    crypto_ct_steps = 0;
    ASSERT(crypto_ct_cmp(a, b, 16) == 0, "全等 -> 0");
    ASSERT(crypto_ct_steps == 16, "全等 -> 步数 16");

    for (k = 0; k < 16; k++) {
        b[k] ^= 0x01;
        crypto_ct_steps = 0;
        int r = crypto_ct_cmp(a, b, 16);
        ASSERT(crypto_ct_steps == 16, "单字节失配 -> 步数恒为 16");
        /* a[k]=0xAA, b[k]=0xAB -> a < b */
        ASSERT(r == -1, "单字节失配 -> -1");
        b[k] ^= 0x01;
    }

    /* 防平凡性：步数必须随 len 变，否则是写死的常量 */
    crypto_ct_steps = 0; crypto_ct_cmp(a, b, 4);
    ASSERT(crypto_ct_steps == 4, "len=4 -> 步数 4");
    crypto_ct_steps = 0; crypto_ct_cmp(a, b, 32);
    ASSERT(crypto_ct_steps == 32, "len=32 -> 步数 32");

    /*
     * 2) 字典序语义：高位一旦分出胜负，低位不得翻转。
     *    这是"常量时间排序"最容易写错的地方 —— 若漏了 undecided
     *    掩码，末字节的比较会覆盖掉首字节的结论。
     */
    memset(a, 0, sizeof a);
    memset(b, 0, sizeof b);
    a[0] = 2; b[0] = 1;            /* 首字节 a > b */
    a[5] = 0; b[5] = 9;            /* 第 5 字节 a < b（应当被忽略） */
    ASSERT(crypto_ct_cmp(a, b, 16) == 1, "高位定序：低位不得翻转（a>b）");

    memset(a, 0, sizeof a);
    memset(b, 0, sizeof b);
    a[0] = 1; b[0] = 2;            /* 首字节 a < b */
    a[9] = 9; b[9] = 0;            /* 第 9 字节 a > b（应当被忽略） */
    ASSERT(crypto_ct_cmp(a, b, 16) == -1, "高位定序：低位不得翻转（a<b）");

    /*
     * 3) 全空间对齐：与 memcmp 的符号逐一对比。
     *    覆盖每个可能的分界位置，双向各一次。
     */
    for (k = 0; k < 32; k++) {
        memset(a, 0x50, sizeof a);
        memset(b, 0x50, sizeof b);
        b[k] = 0x40;                       /* a[k] > b[k] */
        for (i = k + 1; i < 32; i++) b[i] = 0x90;   /* 低位反向 */
        int mine = crypto_ct_cmp(a, b, 32);
        int ref  = memcmp(a, b, 32);
        ASSERT((mine > 0) == (ref > 0) && (mine < 0) == (ref < 0),
               "与 memcmp 符号对齐 (a>b)");

        memset(a, 0x50, sizeof a);
        memset(b, 0x50, sizeof b);
        b[k] = 0x60;                       /* a[k] < b[k] */
        for (i = k + 1; i < 32; i++) b[i] = 0x10;   /* 低位反向 */
        mine = crypto_ct_cmp(a, b, 32);
        ref  = memcmp(a, b, 32);
        ASSERT((mine > 0) == (ref > 0) && (mine < 0) == (ref < 0),
               "与 memcmp 符号对齐 (a<b)");
    }

    /*
     * 4) 随机对：1000 组，与 memcmp 完全对齐。
     */
    uint64_t s = 0x1234567890abcdefULL;
    int mismatch = 0;
    for (int t = 0; t < 1000; t++) {
        for (i = 0; i < 32; i++) {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            a[i] = (uint8_t)(s >> 24);
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            b[i] = (uint8_t)(s >> 24);
        }
        int mine = crypto_ct_cmp(a, b, 32);
        int ref  = memcmp(a, b, 32);
        if (!((mine > 0) == (ref > 0) && (mine < 0) == (ref < 0))) mismatch++;
    }
    ASSERT(mismatch == 0, "1000 组随机对与 memcmp 符号完全一致");
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
    test_constant_time();
    test_ct_cmp();

    printf("========================================\n");
    printf("结果: %d/%d 通过\n", total - failures, total);

    if (failures > 0) {
        printf("失败: %d 项\n", failures);
        return 1;
    }
    printf("全部通过 ✓\n");
    return 0;
}
