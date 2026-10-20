/*
 * DAYANJING v4 — 00_crypto/tests/test_x25519.c
 *
 * X25519 自研实现测试。
 * 权威向量由 Python cryptography 在生成时计算（见文件尾注释），
 * 不依赖人工推算 —— 避免"我以为是 RFC 向量"这类错误。
 */

#include "crypto_x25519.h"

#include <stdio.h>
#include <string.h>

#include "x25519_vectors.h"

static int g_pass = 0, g_fail = 0;

static void check(int cond, const char *name) {
    if (cond) { g_pass++; printf("[PASS] %s\n", name); }
    else      { g_fail++; printf("[FAIL] %s\n", name); }
}

static void dump(const char *tag, const uint8_t *b, size_t n) {
    printf("       %s:", tag);
    for (size_t i = 0; i < n; i++) printf(" %02x", b[i]);
    printf("\n");
}

int main(void) {
    /* ---- 1. 公钥派生：RFC 7748 向量（Python 校验过的权威值） ---- */
    {
        uint8_t ap[32] = VEC_A_PRIV, bp[32] = VEC_B_PRIV;
        uint8_t exp_apub[32] = VEC_A_PUB, exp_bpub[32] = VEC_B_PUB;
        uint8_t got[32];
        check(x25519_public_key(ap, got) == X25519_OK &&
              memcmp(got, exp_apub, 32) == 0, "public_key(RFC A priv) == RFC A pub");
        if (memcmp(got, exp_apub, 32) != 0) dump("got", got, 32);
        check(x25519_public_key(bp, got) == X25519_OK &&
              memcmp(got, exp_bpub, 32) == 0, "public_key(RFC B priv) == RFC B pub");
    }

    /* ---- 2. 共享秘密：双向一致 + 等于权威值 ---- */
    {
        uint8_t ap[32] = VEC_A_PRIV, bp[32] = VEC_B_PRIV;
        uint8_t bpub[32] = VEC_B_PUB, apub[32] = VEC_A_PUB;
        uint8_t exp[32] = VEC_SS;
        uint8_t s1[32], s2[32];
        check(x25519_shared(ap, bpub, s1) == X25519_OK, "shared(A priv, B pub) 成功");
        check(x25519_shared(bp, apub, s2) == X25519_OK, "shared(B priv, A pub) 成功");
        check(memcmp(s1, s2, 32) == 0, "双向共享秘密一致");
        check(memcmp(s1, exp, 32) == 0, "共享秘密 == Python cryptography 权威值");
        if (memcmp(s1, exp, 32) != 0) { dump("got", s1, 32); dump("exp", exp, 32); }
    }

    /* ---- 3. 第二组随机密钥（抓跨实现的系统性偏差） ---- */
    {
        uint8_t cp[32] = VEC_C_PRIV, dp[32] = VEC_D_PRIV;
        uint8_t cpub[32] = VEC_C_PUB, dpub[32] = VEC_D_PUB;
        uint8_t exp[32] = VEC_CD_SS;
        uint8_t got[32], gpub[32];
        check(x25519_public_key(cp, gpub) == X25519_OK &&
              memcmp(gpub, cpub, 32) == 0, "public_key(C priv) == C pub");
        check(x25519_public_key(dp, gpub) == X25519_OK &&
              memcmp(gpub, dpub, 32) == 0, "public_key(D priv) == D pub");
        check(x25519_shared(cp, dpub, got) == X25519_OK &&
              memcmp(got, exp, 32) == 0, "shared(C,D) == 权威值");
    }

    /* ---- 4. 密钥生成自洽：generate 的 pub 必须等于 public_key(priv) ---- */
    {
        uint8_t priv[32], pub[32], pub2[32];
        int r = x25519_generate_keypair(priv, pub);
        check(r == X25519_OK, "generate_keypair 成功");
        check(x25519_public_key(priv, pub2) == X25519_OK &&
              memcmp(pub, pub2, 32) == 0, "generate 的 pub == public_key(priv)");
        /* 两次生成不应相同 */
        uint8_t p2[32], q2[32];
        check(x25519_generate_keypair(p2, q2) == X25519_OK &&
              memcmp(priv, p2, 32) != 0, "两次 generate 私钥不同");
    }

    /* ---- 5. clamp 语义：改动被 clamp 掉的位，结果必须不变 ---- */
    {
        uint8_t priv[32] = VEC_A_PRIV;
        uint8_t tampered[32], pub1[32], pub2[32];
        memcpy(tampered, priv, 32);
        tampered[0]  |= 0x07;   /* 低 3 位会被清零 */
        tampered[31] |= 0x80;   /* 最高位会被清零 */
        tampered[31] |= 0x40;   /* 次高位会被置 1 */
        x25519_public_key(priv, pub1);
        x25519_public_key(tampered, pub2);
        check(memcmp(pub1, pub2, 32) == 0, "clamp：被钳制位不影响结果");
    }

    /* ---- 6. 低阶点防护：全零公钥 -> 共享秘密全零 -> 必须拒绝 ---- */
    {
        uint8_t priv[32] = VEC_A_PRIV, zero[32], out[32];
        memset(zero, 0, 32);
        memset(out, 0xaa, 32);
        int r = x25519_shared(priv, zero, out);
        check(r == X25519_ERR_ARG, "全零公钥（低阶点）被拒绝");
        uint8_t still[32];
        memset(still, 0, 32);
        check(memcmp(out, still, 32) == 0, "拒绝时不写出可用密钥");
    }

    /* ---- 7. 参数校验 ---- */
    {
        uint8_t priv[32] = VEC_A_PRIV, pub[32];
        check(x25519_public_key(NULL, pub) == X25519_ERR_ARG, "public_key(NULL priv) -> ARG");
        check(x25519_public_key(priv, NULL) == X25519_ERR_ARG, "public_key(NULL out) -> ARG");
        check(x25519_shared(priv, NULL, pub) == X25519_ERR_ARG, "shared(NULL peer) -> ARG");
    }

    /* ---- 8. 多次运算确定性 ---- */
    {
        uint8_t priv[32] = VEC_A_PRIV, bpub[32] = VEC_B_PUB;
        uint8_t s1[32], s2[32];
        x25519_shared(priv, bpub, s1);
        for (int i = 0; i < 50; i++) x25519_shared(priv, bpub, s2);
        check(memcmp(s1, s2, 32) == 0, "重复 50 次结果稳定");
    }

    printf("\ntotal=%d pass=%d fail=%d\n", g_pass + g_fail, g_pass, g_fail);
    return g_fail ? 1 : 0;
}
