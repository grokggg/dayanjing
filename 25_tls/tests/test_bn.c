/* test_bn.c — 大数层与 RSA 验签：自洽 + 与 OpenSSL 跨实现交叉验证
 *
 * 自洽测试只能证明"自己跟自己对得上"。真正重要的是：
 *   我们实现的 RSA 验签，能验过 OpenSSL 生成的签名。
 *
 * 一条纪律：负向断言必须以正向断言通过为前提。
 *   "篡改后被拒"在"原始就没验过"时同样成立 —— 那是恒真断言，
 *   会掩盖真实的验签失败。所以这里先记 base_ok，再据此判负向结果。
 */
#include "bn.h"
#include "rsa.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 素材目录由 Makefile 以绝对路径注入：全仓回归脚本是从仓库根目录调用
   可执行文件的，用相对路径会找不到素材，表现为"莫名其妙少了几条用例"。
   把路径固定住，任何工作目录下行为一致。 */
#ifndef TLS_TESTDATA
#define TLS_TESTDATA "tests/data"
#endif
static const char *TD(const char *name) {
    static char buf[512];
    snprintf(buf, sizeof(buf), "%s/%s", TLS_TESTDATA, name);
    return buf;
}

static int fails = 0;
static int total = 0;

#define CHECK(cond, name) do { \
    total++; \
    if (cond) { printf("[PASS] %s\n", name); } \
    else { printf("[FAIL] %s\n", name); fails++; } \
} while (0)

static void t_basic(void) {
    bn_t a, b, r;
    uint8_t be[8];
    int n;

    bn_from_be(&a, (const uint8_t *)"\x00\x00\x01\x00", 4);
    CHECK(bn_bitlen(&a) == 9, "bitlen(0x100)=9");

    memset(be, 0, sizeof(be));
    n = bn_to_be(&a, be, sizeof(be));
    /* 右对齐：值落在缓冲末尾 */
    CHECK(n == 2 && be[6] == 0x01 && be[7] == 0x00, "to_be 右对齐往返");

    bn_from_be(&a, (const uint8_t *)"\x00\x07", 2);
    bn_from_be(&b, (const uint8_t *)"\x00\x08", 2);
    CHECK(bn_cmp(&a, &b) < 0, "cmp 7 < 8");
    bn_add(&r, &a, &b);
    CHECK(bn_bitlen(&r) == 4 && r.d[0] == 15, "add 7+8=15");
    bn_sub(&r, &b, &a);
    CHECK(r.d[0] == 1, "sub 8-7=1");
}

static void t_mulmod(void) {
    bn_t a, b, m, r;
    bn_from_be(&a, (const uint8_t *)"\x00\x07", 2);
    bn_from_be(&b, (const uint8_t *)"\x00\x08", 2);
    bn_from_be(&m, (const uint8_t *)"\x00\x0d", 2);
    bn_mulmod(&r, &a, &b, &m);
    CHECK(r.d[0] == 4, "mulmod 7*8 mod 13 = 4");

    bn_from_be(&a, (const uint8_t *)"\x00\x02", 2);
    bn_from_be(&m, (const uint8_t *)"\x03\xe8", 2);
    bn_modpow_u32(&r, &a, 10, &m);
    CHECK(r.d[0] == 24, "modpow 2^10 mod 1000 = 24");

    bn_from_be(&a, (const uint8_t *)"\x00\x05", 2);
    bn_from_be(&m, (const uint8_t *)"\x00\x0d", 2);
    bn_modpow_u32(&r, &a, 3, &m);
    CHECK(r.d[0] == 8, "modpow 5^3 mod 13 = 8");

    uint8_t ab[64], bb[64], mb[64];
    for (int i = 0; i < 64; i++) { ab[i] = (uint8_t)(i * 7 + 3); bb[i] = (uint8_t)(i * 11 + 5); mb[i] = (uint8_t)(i * 13 + 1); }
    mb[0] |= 0x01;
    bn_t A, B, M, A2, B2, R1, R2;
    bn_from_be(&A, ab, 64);
    bn_from_be(&B, bb, 64);
    bn_from_be(&M, mb, 64);
    bn_mod(&A2, &A, &M);
    bn_mod(&B2, &B, &M);
    bn_mulmod(&R1, &A, &B, &M);
    bn_mulmod(&R2, &A2, &B2, &M);
    CHECK(bn_cmp(&R1, &R2) == 0, "512 位 mulmod 与先归约再乘一致");

    /* e = 65537 = 2^16 + 1：a^65537 = ((a^(2^16)) * a)
       之前写成 17 次连乘（= a^17），测试自己错了，不是实现的问题。 */
    bn_t acc;
    acc = A;
    for (int i = 0; i < 16; i++) bn_mulmod(&acc, &acc, &acc, &M);
    bn_mulmod(&acc, &acc, &A, &M);
    bn_modpow_u32(&R1, &A, 65537, &M);
    CHECK(bn_cmp(&R1, &acc) == 0, "modpow e=65537 与 16 次平方+1 次乘一致");
}

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = (uint8_t *)malloc((size_t)n + 1);
    if (!b) { fclose(f); return NULL; }
    size_t got = fread(b, 1, (size_t)n, f);
    fclose(f);
    *len = got;
    return b;
}

/* 与 OpenSSL 互操作：验证 openssl dgst -sha256 -sign 产生的签名 */
static void t_rsa_openssl_sig(void) {
    size_t nlen = 0, elen = 0, slen = 0, mlen = 0;
    uint8_t *nb = read_file(TD("rsa_n.bin"), &nlen);
    uint8_t *eb = read_file(TD("rsa_e.bin"), &elen);
    uint8_t *sb = read_file(TD("rsa_sig.bin"), &slen);
    uint8_t *mb = read_file(TD("rsa_msg.bin"), &mlen);
    if (!nb || !eb || !sb || !mb) {
        printf("[SKIP] openssl 交叉验证素材缺失（先跑 scripts/gen_testdata.sh）\n");
        return;
    }
    bn_t n;
    uint32_t e = 0;
    bn_from_be(&n, nb, nlen);
    for (size_t i = 0; i < elen; i++) e = (e << 8) | eb[i];
    CHECK(bn_bitlen(&n) == 2048, "OpenSSL 密钥模数 2048 位");
    CHECK(e == 65537, "OpenSSL 密钥 e = 65537");

    rsa_err base = rsa_verify_sha256(&n, e, mb, mlen, sb, slen);
    CHECK(base == RSA_OK, "验证 OpenSSL 生成的 RSA-SHA256 签名");

    /* 负向断言只在正向通过的前提下才有意义 */
    if (base == RSA_OK) {
        sb[slen - 1] ^= 0x01;
        rsa_err r1 = rsa_verify_sha256(&n, e, mb, mlen, sb, slen);
        CHECK(r1 != RSA_OK, "篡改签名后被拒");
        sb[slen - 1] ^= 0x01;

        mb[0] ^= 0x80;
        rsa_err r2 = rsa_verify_sha256(&n, e, mb, mlen, sb, slen);
        CHECK(r2 == RSA_ERR_SIG, "消息篡改后签名不匹配（不是填充错误）");
        mb[0] ^= 0x80;

        /* 长度不符：签名长度必须等于模数字节数 */
        rsa_err r3 = rsa_verify_sha256(&n, e, mb, mlen, sb, slen - 1);
        CHECK(r3 == RSA_ERR_RANGE, "签名长度不等于模数字节数被拒");
    } else {
        printf("[FAIL] 正向验签未通过，负向断言无意义，已跳过\n");
        fails += 3; total += 3;
    }

    free(nb); free(eb); free(sb); free(mb);
}

int main(void) {
    t_basic();
    t_mulmod();
    t_rsa_openssl_sig();
    printf("\n=== %d/%d passed ===\n", total - fails, total);
    return fails == 0 ? 0 : 1;
}
