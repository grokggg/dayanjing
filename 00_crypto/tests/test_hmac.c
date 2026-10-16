#include "crypto.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

static void hex(const uint8_t *b, size_t n, char *out) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i*2]   = H[b[i] >> 4];
        out[i*2+1] = H[b[i] & 0xf];
    }
    out[n*2] = 0;
}

/* RFC 4231 测试向量 1：key=0x0b*20, data="Hi There" */
int main(void) {
    printf("[*] HMAC-SHA256 测试（RFC 4231）\n");
    char got[65];

    /* ---- TV1 ---- */
    {
        uint8_t key[20];
        memset(key, 0x0b, 20);
        const char *msg = "Hi There";
        uint8_t out[32];
        crypto_hmac(out, key, 20, (const uint8_t *)msg, 8);
        hex(out, 32, got);
        assert(strcmp(got,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7") == 0);
        printf("  [+] HMAC-SHA256 TV1 = %s\n", got);
    }

    /* ---- TV2：key="Jefe", data="what do ya want for nothing?" (RFC 4231 §4.3) ---- */
    {
        const char *key = "Jefe";
        const char *msg = "what do ya want for nothing?";
        uint8_t out[32];
        crypto_hmac(out, (const uint8_t *)key, 4, (const uint8_t *)msg, 28);
        hex(out, 32, got);
        assert(strcmp(got,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") == 0);
        printf("  [+] HMAC-SHA256 TV2 = %s\n", got);
    }

    /* ---- TV3：key=0xaa*20, data=0xdd*50 ---- */
    {
        uint8_t key[20];
        memset(key, 0xaa, 20);
        uint8_t *msg = malloc(50);
        assert(msg);
        memset(msg, 0xdd, 50);
        uint8_t out[32];
        crypto_hmac(out, key, 20, msg, 50);
        hex(out, 32, got);
        assert(strcmp(got,
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe") == 0);
        printf("  [+] HMAC-SHA256 TV3 = %s\n", got);
        free(msg);
    }

    /* ---- hmac_verify：正确 mac 应通过 ---- */
    {
        uint8_t key[32];
        crypto_rng(key, 32);
        const char *msg = "verify-me";
        uint8_t mac[32];
        crypto_hmac(mac, key, 32, (const uint8_t *)msg, 9);
        assert(crypto_hmac_verify(mac, key, 32, (const uint8_t *)msg, 9) == CRYPTO_OK);
        printf("  [+] hmac_verify 正确 mac 通过\n");
    }

    /* ---- hmac_verify：篡改 1 bit 应失败 ---- */
    {
        uint8_t key[32];
        crypto_rng(key, 32);
        const char *msg = "verify-me";
        uint8_t mac[32];
        crypto_hmac(mac, key, 32, (const uint8_t *)msg, 9);
        mac[0] ^= 0x01;
        assert(crypto_hmac_verify(mac, key, 32, (const uint8_t *)msg, 9)
               == CRYPTO_TAG_MISMATCH);
        printf("  [+] hmac_verify 篡改 1 bit 被拒\n");
    }

    /* ---- hmac_verify：空输入 ---- */
    {
        uint8_t key[32];
        crypto_rng(key, 32);
        uint8_t mac[32];
        crypto_hmac(mac, key, 32, NULL, 0);
        assert(crypto_hmac_verify(mac, key, 32, NULL, 0) == CRYPTO_OK);
        printf("  [+] hmac_verify 空消息通过\n");
    }

    printf("\n[+] HMAC-SHA256 测试全部通过\n");
    return 0;
}
