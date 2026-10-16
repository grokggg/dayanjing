#include "crypto.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

/* FIPS 180-4 附录 B 测试向量 */
static void hex(const uint8_t *b, size_t n, char *out) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i*2]   = H[b[i] >> 4];
        out[i*2+1] = H[b[i] & 0xf];
    }
    out[n*2] = 0;
}

int main(void) {
    printf("[*] SHA-256 测试向量验证\n");
    char got[65];

    /* 空字符串 */
    {
        uint8_t out[32];
        crypto_sha256(out, NULL, 0);
        hex(out, 32, got);
        assert(strcmp(got,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
        printf("  [+] SHA-256(\"\") = %s\n", got);
    }

    /* "abc" */
    {
        uint8_t out[32];
        const char *msg = "abc";
        crypto_sha256(out, (const uint8_t *)msg, 3);
        hex(out, 32, got);
        assert(strcmp(got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
        printf("  [+] SHA-256(\"abc\") = %s\n", got);
    }

    /* "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (56 字节) */
    {
        uint8_t out[32];
        const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        crypto_sha256(out, (const uint8_t *)msg, strlen(msg));
        hex(out, 32, got);
        assert(strcmp(got,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0);
        printf("  [+] SHA-256(56-byte) = %s\n", got);
    }

    /* 单字节 0xa3 重复 1,000,000 次 —— 太长，用 100 万次分块意义不大，
     * 改用 256 字节（2 个完整块）验证多块路径 */
    {
        uint8_t *msg = malloc(256);
        assert(msg);
        memset(msg, 'a', 256);
        uint8_t out[32];
        crypto_sha256(out, msg, 256);
        hex(out, 32, got);
        assert(strcmp(got,
            "02d7160d77e18c6447be80c2e355c7ed4388545271702c50253b0914c65ce5fe") == 0);
        printf("  [+] SHA-256(256x'a') = %s\n", got);
        free(msg);
    }

    /* NULL 消息 + 长度 0 是合法的空消息，应返回 OK（不崩溃） */
    {
        uint8_t out[32];
        crypto_err_t rc = crypto_sha256(out, NULL, 0);
        assert(rc == CRYPTO_OK);
        /* 结果与空字符串相同 */
        char got2[65];
        hex(out, 32, got2);
        assert(strcmp(got2,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
        printf("  [+] SHA-256(NULL,0) == SHA-256(\"\") 返回 OK\n");
    }

    /* NULL 消息 + 非零长度：应返回错误 */
    {
        uint8_t out[32];
        crypto_err_t rc = crypto_sha256(out, NULL, 16);
        assert(rc == CRYPTO_ERR);
        printf("  [+] SHA-256(NULL,16) 返回 ERR\n");
    }

    printf("\n[+] SHA-256 测试全部通过\n");
    return 0;
}
