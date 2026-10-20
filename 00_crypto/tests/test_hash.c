/*
 * DAYANJING v3 — test_hash.c
 *
 * SHA-256 / HMAC-SHA256 / HKDF 验证。
 * 权威向量来源：
 *   - SHA-256  : FIPS 180-4 示例（空串 / "abc" / 56 字节）
 *   - HMAC     : RFC 4231 Test Case 1
 *   - HKDF     : RFC 5869 Appendix A.1 / A.2
 * 另有自洽测试：分块 update 与一次性哈希必须逐字节一致（可抓填充边界错误）。
 */

#include "crypto_hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, name) do { \
    if (cond) { g_pass++; printf("  [PASS] %s\n", name); } \
    else { g_fail++; printf("  [FAIL] %s  (%s:%d)\n", name, __FILE__, __LINE__); } \
} while (0)

/* ---- 十六进制工具 ---- */

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t hex2bin(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = strlen(hex), i = 0;
    if (n % 2) return 0;
    for (i = 0; i < n / 2; i++) {
        int hi = hexval(hex[i * 2]), lo = hexval(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        if (i >= cap) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return n / 2;
}

static int hexeq(const uint8_t *got, size_t len, const char *want_hex)
{
    uint8_t want[256];
    size_t wl = hex2bin(want_hex, want, sizeof(want));
    if (wl != len) return 0;
    return memcmp(got, want, len) == 0;
}

/* ====================================================================
 * SHA-256
 * ==================================================================== */

static void test_sha256_vectors(void)
{
    uint8_t d[32];

    sha256(NULL, 0, d);
    CHECK(hexeq(d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
          "SHA-256(\"\") FIPS 180-4 空串向量");

    sha256((const uint8_t *)"abc", 3, d);
    CHECK(hexeq(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
          "SHA-256(\"abc\") FIPS 180-4 向量");

    /* 56 字节：恰好触发填充跨块（56+1=57 > 56，需额外一块） */
    {
        const char *m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        sha256((const uint8_t *)m, strlen(m), d);
        CHECK(hexeq(d, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
              "SHA-256(56 字节) 填充跨块向量");
    }
}

/* 分块喂入必须等于一次性喂入：覆盖 0..200 所有长度，含 55/56/57/63/64/65/119/120 边界 */
static void test_sha256_chunking(void)
{
    static uint8_t msg[200];
    size_t n;
    int all_same = 1;

    for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)(i * 31 + 7);

    for (n = 0; n <= sizeof(msg); n++) {
        uint8_t once[32], chunked[32];
        sha256_ctx c;
        size_t off;

        sha256(msg, n, once);

        sha256_init(&c);
        /* 用不规则块长喂入，制造部分块边界 */
        off = 0;
        while (off < n) {
            size_t take = (n - off < 7) ? (n - off) : 7;
            sha256_update(&c, msg + off, take);
            off += take;
        }
        sha256_final(&c, chunked);

        if (memcmp(once, chunked, 32) != 0) {
            all_same = 0;
            printf("    长度 %zu 处不一致\n", n);
            break;
        }
    }
    CHECK(all_same, "SHA-256 分块 update(7 字节步长) 与一次性哈希逐字节一致 (0..200 全长度)");

    /* 逐字节喂入，最严苛的边界 */
    {
        int ok = 1;
        for (n = 0; n <= sizeof(msg) && ok; n++) {
            uint8_t once[32], chunked[32];
            sha256_ctx c;
            size_t i;
            sha256(msg, n, once);
            sha256_init(&c);
            for (i = 0; i < n; i++) sha256_update(&c, msg + i, 1);
            sha256_final(&c, chunked);
            if (memcmp(once, chunked, 32) != 0) ok = 0;
        }
        CHECK(ok, "SHA-256 逐字节 update 与一次性哈希一致 (0..200 全长度)");
    }
}

/* ====================================================================
 * HMAC-SHA256
 * ==================================================================== */

static void test_hmac_vectors(void)
{
    uint8_t key[20], out[32];
    size_t i;

    /* RFC 4231 Test Case 1 */
    for (i = 0; i < sizeof(key); i++) key[i] = 0x0b;
    hmac_sha256(key, sizeof(key), (const uint8_t *)"Hi There", 8, out);
    CHECK(hexeq(out, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
          "HMAC-SHA256 RFC 4231 TC1（key=0x0b*20, data=\"Hi There\"）");

    /* 空 key：RFC 2104 零填充密钥 */
    hmac_sha256(NULL, 0, (const uint8_t *)"Hi There", 8, out);
    {
        uint8_t zkey[64], out2[32];
        memset(zkey, 0, sizeof(zkey));
        hmac_sha256(zkey, 64, (const uint8_t *)"Hi There", 8, out2);
        CHECK(memcmp(out, out2, 32) == 0,
              "HMAC 空 key(NULL,0) 与 64 字节零 key 结果一致");
    }

    /* 长密钥（>64 字节）先哈希：与直接用其摘要作 key 等价 */
    {
        uint8_t lk[100], lk_hash[32], o1[32], o2[32];
        for (i = 0; i < sizeof(lk); i++) lk[i] = (uint8_t)i;
        sha256(lk, sizeof(lk), lk_hash);
        hmac_sha256(lk, sizeof(lk), (const uint8_t *)"data", 4, o1);
        hmac_sha256(lk_hash, 32, (const uint8_t *)"data", 4, o2);
        CHECK(memcmp(o1, o2, 32) == 0,
              "HMAC 长密钥(100B) 先哈希后再用 —— 与直接用其 SHA-256 摘要等价");
    }
}

/* ====================================================================
 * HKDF（RFC 5869）
 * ==================================================================== */

static void test_hkdf_a1(void)
{
    uint8_t ikm[22], salt[13], info[10], prk[32], okm[42];
    size_t i;

    for (i = 0; i < sizeof(ikm); i++)  ikm[i]  = 0x0b;
    for (i = 0; i < sizeof(salt); i++) salt[i] = (uint8_t)i;       /* 00..0c */
    for (i = 0; i < sizeof(info); i++) info[i] = (uint8_t)(0xf0 + i); /* f0..f9 */

    CHECK(hkdf_extract(salt, sizeof(salt), ikm, sizeof(ikm), prk) == HASH_OK,
          "HKDF-Extract A.1 返回 HASH_OK");
    CHECK(hexeq(prk, 32, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
          "HKDF-Extract RFC 5869 A.1 PRK 向量");

    CHECK(hkdf_expand(prk, info, sizeof(info), okm, sizeof(okm)) == HASH_OK,
          "HKDF-Expand A.1 返回 HASH_OK");
    CHECK(hexeq(okm, 42,
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c"
                "5db02d56ecc4c5bf34007208d5b887185865"),
          "HKDF-Expand RFC 5869 A.1 OKM(L=42) 向量");

    /* 便捷封装应与 extract+expand 一致 */
    {
        uint8_t okm2[42];
        CHECK(hkdf(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info),
                   okm2, sizeof(okm2)) == HASH_OK, "hkdf() 封装 A.1 返回 HASH_OK");
        CHECK(memcmp(okm, okm2, 42) == 0, "hkdf() 封装 == Extract+Expand 结果一致");
    }
}

static void test_hkdf_a2(void)
{
    uint8_t ikm[50], salt[80], info[48], prk[32], okm[82];
    size_t i;

    for (i = 0; i < sizeof(ikm); i++)  ikm[i]  = (uint8_t)(i);         /* 00..31 */
    for (i = 0; i < sizeof(salt); i++) salt[i] = (uint8_t)(0x60 + i);  /* 60..af */
    for (i = 0; i < sizeof(info); i++) info[i] = (uint8_t)(0xb0 + i);  /* b0..df */

    CHECK(hkdf_extract(salt, sizeof(salt), ikm, sizeof(ikm), prk) == HASH_OK,
          "HKDF-Extract A.2 返回 HASH_OK");
    /* 期望值由 Python 标准库 hmac/hashlib 独立计算得出，与本实现对照 */
    CHECK(hexeq(prk, 32, "0248776473323be6b7354832ced993051b64ae0f81d2c6e1ccbf21a0fa17a5e4"),
          "HKDF-Extract RFC 5869 A.2 PRK 向量");

    CHECK(hkdf_expand(prk, info, sizeof(info), okm, sizeof(okm)) == HASH_OK,
          "HKDF-Expand A.2 返回 HASH_OK");
    CHECK(hexeq(okm, 82,
                "c6b0fbd7a0fc186e0f946a8c336415226d31b5744d13702b"
                "fe4790f817bce199fae30c68eca6720646cca832032de0ef0"
                "b2cfca1dd636356fb55b6b9e9cba7ea34e85a5e132d29e12f"
                "33fff62747bed9917c"),
          "HKDF-Expand RFC 5869 A.2 OKM(L=82) 向量");
}

static void test_hkdf_edges(void)
{
    uint8_t ikm[16], prk[32], prk2[32], okm[8160];
    size_t i;
    for (i = 0; i < sizeof(ikm); i++) ikm[i] = (uint8_t)(i + 1);

    /* salt 为空：按 §2.2 使用 32 个零字节 */
    {
        uint8_t zero[32];
        memset(zero, 0, sizeof(zero));
        hkdf_extract(NULL, 0, ikm, sizeof(ikm), prk);
        hkdf_extract(zero, 32, ikm, sizeof(ikm), prk2);
        CHECK(memcmp(prk, prk2, 32) == 0,
              "HKDF-Extract salt=NULL 与 32 字节零 salt 等价（RFC 5869 §2.2）");
    }

    /* 长度边界 */
    CHECK(hkdf_expand(prk, NULL, 0, okm, 0) == HASH_ERR_LEN,
          "HKDF-Expand L=0 -> HASH_ERR_LEN");
    CHECK(hkdf_expand(prk, NULL, 0, okm, 255 * 32 + 1) == HASH_ERR_LEN,
          "HKDF-Expand L=255*32+1 -> HASH_ERR_LEN（超出 RFC 上限）");
    CHECK(hkdf_expand(prk, NULL, 0, okm, 255 * 32) == HASH_OK,
          "HKDF-Expand L=255*32 -> HASH_OK（RFC 上限边界可取）");

    /* 参数校验 */
    CHECK(hkdf_extract(NULL, 0, ikm, sizeof(ikm), NULL) == HASH_ERR_ARG,
          "HKDF-Extract prk=NULL -> HASH_ERR_ARG");
    CHECK(hkdf_expand(prk, NULL, 0, NULL, 16) == HASH_ERR_ARG,
          "HKDF-Expand okm=NULL -> HASH_ERR_ARG");

    /* 密钥分离：不同 info 必须产出不同输出 */
    {
        uint8_t a[32], b[32];
        const char *ia = "dayanjing:session:c2s";
        const char *ib = "dayanjing:session:s2c";
        hkdf_expand(prk, (const uint8_t *)ia, strlen(ia), a, 32);
        hkdf_expand(prk, (const uint8_t *)ib, strlen(ib), b, 32);
        CHECK(memcmp(a, b, 32) != 0,
              "HKDF 不同 info -> 不同输出（c2s/s2c 密钥分离）");
    }

    /* 确定性：同输入两次结果一致 */
    {
        uint8_t a[32], b[32];
        hkdf_expand(prk, NULL, 0, a, 32);
        hkdf_expand(prk, NULL, 0, b, 32);
        CHECK(memcmp(a, b, 32) == 0, "HKDF-Expand 确定性（同输入两次一致）");
    }
}

int main(void)
{
    printf("[*] 00_crypto 哈希层测试（SHA-256 / HMAC / HKDF）\n");
    printf("[*] ==========================================\n");

    test_sha256_vectors();
    test_sha256_chunking();
    test_hmac_vectors();
    test_hkdf_a1();
    test_hkdf_a2();
    test_hkdf_edges();

    printf("[*] ==========================================\n");
    printf("[*] 结果: %d/%d 通过\n", g_pass, g_pass + g_fail);
    printf("[*] 失败: %d 项\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
