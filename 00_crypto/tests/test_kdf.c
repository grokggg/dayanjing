#include "crypto.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

static void hex(const uint8_t *b, size_t n, char *out) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i*2]   = H[b[i] >> 4];
        out[i*2+1] = H[b[i] & 0xf];
    }
    out[n*2] = 0;
}

/* RFC 5869 附录 A.1：HKDF-SHA256 测试向量 1 */
int main(void) {
    printf("[*] HKDF-SHA256 测试（RFC 5869）\n");
    char got[85];   /* 42 字节 * 2 + 1 */

    /* RFC 5869 Appendix A.1：IKM=0x0b*22, salt=000102...0b0c(13B 递增),
       info=0xf0..f9, L=42 */
    uint8_t ikm[22];
    memset(ikm, 0x0b, 22);
    uint8_t salt[13];
    for (int i = 0; i < 13; i++) salt[i] = (uint8_t)i;   /* 000102...0b0c */
    uint8_t info[10];
    for (int i = 0; i < 10; i++) info[i] = (uint8_t)(0xf0 + i);

    uint8_t okm[42];
    uint8_t prk[32];
    crypto_err_t rc = crypto_kdf_extract(prk, salt, 13, ikm, 22);
    assert(rc == CRYPTO_OK);
    rc = crypto_kdf_expand(okm, 42, prk, info, 10);
    assert(rc == CRYPTO_OK);
    hex(okm, 42, got);
    /* RFC 5869 TV1 标准预期值 */
    assert(strcmp(got,
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865") == 0);
    printf("  [+] HKDF TV1 (42字节) = %s\n", got);

    /* ---- 用途隔离：不同 info 派生出不同密钥 ---- */
    {
        uint8_t master[32];
        crypto_rng(master, 32);
        uint8_t enc[32], auth[32];
        rc = crypto_kdf_derive(enc, 32, master, 32,
                               (const uint8_t *)"enc-key", 7);
        assert(rc == CRYPTO_OK);
        rc = crypto_kdf_derive(auth, 32, master, 32,
                              (const uint8_t *)"auth-key", 8);
        assert(rc == CRYPTO_OK);
        assert(memcmp(enc, auth, 32) != 0);
        printf("  [+] 用途隔离：enc-key != auth-key\n");
    }

    /* ---- 长度限制：超过 8160 字节应报错 ---- */
    {
        uint8_t master[32];
        crypto_rng(master, 32);
        uint8_t big[8200];
        rc = crypto_kdf_derive(big, sizeof(big), master, 32,
                               (const uint8_t *)"x", 1);
        assert(rc == CRYPTO_OVERFLOW);
        printf("  [+] 超长派生被拒绝 (OVERFLOW)\n");
    }

    /* ---- salt 为空：应回退到全零 salt ---- */
    {
        uint8_t master[32];
        crypto_rng(master, 32);
        uint8_t a[32], b[32];
        crypto_kdf_derive(a, 32, master, 32, (const uint8_t *)"t", 1);
        crypto_kdf_derive(b, 32, master, 32, (const uint8_t *)"t", 1);
        assert(memcmp(a, b, 32) == 0);   /* 相同输入必须得到相同输出 */
        printf("  [+] 空 salt + 相同输入 = 确定性输出\n");
    }

    printf("\n[+] HKDF-SHA256 测试全部通过\n");
    return 0;
}
