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

/* RFC 7539 附录 A.1：ChaCha20 测试向量 */
int main(void) {
    printf("[*] ChaCha20 测试（RFC 7539）\n");
    char got[1024];

    /* key = 0x00,0x01,...,0x1f ; nonce = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4a,0x00,0x00,0x00,0x00
     * counter = 1
     * plaintext = 0x4c,0x61,... (UTF-8 "Ladies and Gentlemen of the class of '99: ...")
     */
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    uint8_t nonce[12] = {0};
    nonce[3] = 0; nonce[7] = 0x4a;

    const uint8_t pt[114] = {
        0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,0x6e,0x64,0x20,0x47,0x65,0x6e,0x74,0x6c,
        0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,
        0x73,0x20,0x6f,0x66,0x20,0x27,0x39,0x39,0x3a,0x20,0x49,0x66,0x20,0x49,0x20,0x63,
        0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,0x65,0x72,0x20,0x79,0x6f,0x75,0x20,0x6f,
        0x6e,0x6c,0x79,0x20,0x6f,0x6e,0x65,0x20,0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,
        0x74,0x68,0x65,0x20,0x66,0x75,0x74,0x75,0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,
        0x63,0x72,0x65,0x65,0x6e,0x20,0x77,0x6f,0x75,0x6c,0x64,0x20,0x62,0x65,0x20,0x69,
        0x74,0x2e,
    };
    uint8_t out[114];
    crypto_err_t rc = crypto_chacha20(out, pt, 114, key, nonce, 1);
    assert(rc == CRYPTO_OK);
    hex(out, 114, got);
    /* 预期密文（RFC 7539 附录 A.1） */
    static const char *expected =
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9"
        "fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c"
        "359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf8068"
        "18ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d";
    assert(strlen(expected) == 228);
    assert(strcmp(got, expected) == 0);
    printf("  [+] ChaCha20 RFC7539 附录A.1 全 114 字节匹配\n");

    /* ---- 自反性：encrypt(decrypt(x)) == x ---- */
    {
        uint8_t k[32];
        crypto_rng(k, 32);
        uint8_t n[12];
        crypto_rng(n, 12);
        uint8_t msg[256];
        crypto_rng(msg, 256);
        uint8_t ct[256], dec[256];
        crypto_chacha20(ct, msg, 256, k, n, 0);
        crypto_chacha20(dec, ct, 256, k, n, 0);
        assert(memcmp(dec, msg, 256) == 0);
        printf("  [+] 自反性验证（256 字节）\n");
    }

    /* ---- 不同 nonce 产生不同输出 ---- */
    {
        uint8_t k[32];
        crypto_rng(k, 32);
        uint8_t n1[12] = {0}, n2[12] = {0};
        n2[0] = 1;
        uint8_t msg[64] = {0x42};
        uint8_t a[64], b[64];
        crypto_chacha20(a, msg, 64, k, n1, 0);
        crypto_chacha20(b, msg, 64, k, n2, 0);
        assert(memcmp(a, b, 64) != 0);
        printf("  [+] 不同 nonce -> 不同密钥流\n");
    }

    /* ---- 空输入是合法 no-op ---- */
    {
        uint8_t k[32], n[12], dummy[1];
        crypto_rng(k, 32); crypto_rng(n, 12);
        assert(crypto_chacha20(dummy, NULL, 0, k, n, 0) == CRYPTO_OK);
        printf("  [+] 空输入返回 OK\n");
    }

    /* ---- 原地加密应等同于异地加密 ---- */
    {
        uint8_t k[32];
        crypto_rng(k, 32);
        uint8_t n[12];
        crypto_rng(n, 12);
        uint8_t msg[128];
        crypto_rng(msg, 128);
        uint8_t ip[128], op[128];
        memcpy(ip, msg, 128);
        memcpy(op, msg, 128);
        crypto_chacha20(ip, ip, 128, k, n, 5);
        crypto_chacha20(op, msg, 128, k, n, 5);
        assert(memcmp(ip, op, 128) == 0);
        printf("  [+] 原地/异地加密结果一致\n");
    }

    printf("\n[+] ChaCha20 测试全部通过\n");
    return 0;
}
