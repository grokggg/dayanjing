#include "crypto.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

int main(void) {
    printf("[*] RNG + ct_memcmp 测试\n");

    /* ---- crypto_wipe：清零后内容必须为 0 ---- */
    uint8_t buf[64];
    for (int i = 0; i < 64; i++) buf[i] = (uint8_t)(i + 1);
    crypto_wipe(buf, sizeof(buf));
    for (int i = 0; i < 64; i++) assert(buf[i] == 0);
    printf("  [+] crypto_wipe 全零确认\n");

    /* ---- RNG 非空 + 两次不同 ---- */
    uint8_t a[32], b[32];
    crypto_err_t rc = crypto_rng(a, 32);
    assert(rc == CRYPTO_OK);
    rc = crypto_rng(b, 32);
    assert(rc == CRYPTO_OK);
    /* 概率上几乎不可能两次完全相同 */
    assert(memcmp(a, b, 32) != 0);
    printf("  [+] crypto_rng 两次输出不同\n");

    /* ---- RNG 长度为 0 是合法 no-op ---- */
    rc = crypto_rng(NULL, 0);
    assert(rc == CRYPTO_OK);
    printf("  [+] crypto_rng(len=0) 返回 OK\n");

    /* ---- ct_memcmp：相等 ---- */
    uint8_t x[16], y[16];
    memset(x, 0xAB, 16);
    memset(y, 0xAB, 16);
    assert(crypto_ct_memcmp(x, y, 16) == 0);
    printf("  [+] ct_memcmp 相等返回 0\n");

    /* ---- ct_memcmp：单 bit 差异 ---- */
    y[7] ^= 0x01;
    assert(crypto_ct_memcmp(x, y, 16) != 0);
    printf("  [+] ct_memcmp 单 bit 差异可检测\n");

    /* ---- ct_memcmp：长度 0 ---- */
    assert(crypto_ct_memcmp(x, y, 0) == 0);
    printf("  [+] ct_memcmp(len=0) 返回 0\n");

    printf("\n[+] RNG 测试全部通过\n");
    return 0;
}
