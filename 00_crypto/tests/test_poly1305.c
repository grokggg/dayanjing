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

/* RFC 7539 附录 A.3：Poly1305 测试向量 */
int main(void) {
    printf("[*] Poly1305 测试（RFC 7539）\n");
    char got[33];

    /* key = 0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,
     *       0xa8,0x01,0x03,0x80,0x8a,0x4f,0x3c,0x4a,0x95,0x99,0xef,0xd1,0xfa,0x7f,0x56,
     *       0xe3,0x12
     * msg = 0x43,0x72,0x79,0x70,0x74,0x6f,0x67,0x72,0x61,0x70,0x68,0x69,0x63,0x20,0x46,
     *       0x6f,0x72,0x75,0x6d,0x20,0x52,0x65,0x73,0x65,0x61,0x72,0x63,0x68,0x20,0x47,
     *       0x72,0x6f,0x75,0x70
     */
    uint8_t key[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b,
    };
    uint8_t msg[34] = {
        0x43,0x72,0x79,0x70,0x74,0x6f,0x67,0x72,0x61,0x70,0x68,0x69,0x63,0x20,0x46,
        0x6f,0x72,0x75,0x6d,0x20,0x52,0x65,0x73,0x65,0x61,0x72,0x63,0x68,0x20,0x47,
        0x72,0x6f,0x75,0x70,
    };
    uint8_t mac[16];
    crypto_err_t rc = crypto_poly1305(mac, msg, 34, key);
    assert(rc == CRYPTO_OK);
    hex(mac, 16, got);
    assert(strcmp(got, "a8061dc1305136c6c22b8baf0c0127a9") == 0);
    printf("  [+] Poly1305 RFC7539 附录A.3 = %s\n", got);

    /* ---- 空消息（key 有效）应产生基于 s 的 MAC ---- */
    {
        uint8_t k[32];
        crypto_rng(k, 32);
        uint8_t m[16];
        crypto_poly1305(m, NULL, 0, k);
        /* 不为全零（概率上） */
        int allzero = 1;
        for (int i = 0; i < 16; i++) if (m[i]) allzero = 0;
        assert(!allzero);
        printf("  [+] 空消息 MAC 非零\n");
    }

    /* ---- 单字节消息（测试 <16 字节的块处理）---- */
    {
        uint8_t k[32];
        crypto_rng(k, 32);
        uint8_t m[16];
        crypto_poly1305(m, (const uint8_t *)"a", 1, k);
        printf("  [+] 单字节消息 MAC 计算成功\n");
    }

    /* ---- 恰好 16 字节消息 ---- */
    {
        uint8_t k[32];
        crypto_rng(k, 32);
        uint8_t m[16];
        crypto_poly1305(m, k, 16, k);   /* 用 key 作消息（无害） */
        printf("  [+] 16 字节消息 MAC 计算成功\n");
    }

    /* ---- 不同消息产生不同 MAC（确定性验证）---- */
    {
        uint8_t k[32];
        crypto_rng(k, 32);
        uint8_t a[16], b[16];
        crypto_poly1305(a, (const uint8_t *)"hello", 5, k);
        crypto_poly1305(b, (const uint8_t *)"world", 5, k);
        assert(memcmp(a, b, 16) != 0);
        printf("  [+] 不同消息 -> 不同 MAC\n");
    }

    /* ---- 相同输入产生相同 MAC（确定性）---- */
    {
        uint8_t k[32];
        crypto_rng(k, 32);
        uint8_t a[16], b[16];
        crypto_poly1305(a, (const uint8_t *)"repeat", 6, k);
        crypto_poly1305(b, (const uint8_t *)"repeat", 6, k);
        assert(memcmp(a, b, 16) == 0);
        printf("  [+] 相同输入 -> 确定性输出\n");
    }

    printf("\n[+] Poly1305 测试全部通过\n");
    return 0;
}
