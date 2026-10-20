/*
 * DAYANJING v2/v3 — test_c2.c
 *
 * C2 握手与会话密钥派生验证。
 *
 * 期望值来源：由 Python 侧 00_crypto/key_derivation.py 真实运行产生
 * （derive_pair / derive_session / compute_transcript / _build_context），
 * 而非手工推算——保证 C 侧与 Python 侧契约逐字节一致。
 *
 * 另覆盖：transcript 流式累积、握手状态机合法/非法转移、参数校验。
 */

#include "c2.h"
#include "crypto_hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, name) do { \
    if (cond) { g_pass++; printf("  [PASS] %s\n", name); } \
    else { g_fail++; printf("  [FAIL] %s  (%s:%d)\n", name, __FILE__, __LINE__); } \
} while (0)

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t hex2bin(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = strlen(hex), i;
    if (n % 2) return 0;
    for (i = 0; i < n / 2; i++) {
        int hi = hexval(hex[i * 2]), lo = hexval(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        if (i >= cap) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return n / 2;
}

static int hexeq(const uint8_t *got, size_t len, const char *want)
{
    uint8_t w[256];
    size_t wl = hex2bin(want, w, sizeof(w));
    if (wl != len) return 0;
    return memcmp(got, w, len) == 0;
}

/* ---- Python 侧真实输出（key_derivation.py 运行产生） ---- */
#define V_PSK    "02070c11161b20252a2f34393e43484d52575c61666b70757a7f84898e93989d"
#define V_SALT   "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
#define V_KHOLD  "56d8e93a40c88ba25efba7b95d9886d0"
#define V_KIDENT "270228b2e31e90a81cd49a236e7ec84f"

#define V_MASTER "1112131415161718191a1b1c1d1e1f20"
#define V_SID    "202122232425262728292a2b2c2d2e2f"
#define V_TH     "ef84671ed6aa2386ff8189a690c30622a90c4233bcd1f8c0a3cbee406e187f71"
#define V_KC2S   "6e1a2b53a2257d76a4aef97ddc8857ae"
#define V_KS2C   "12b8d0de298eb610838c309d7b29b685"
#define V_KCONF  "6f71b9c9e668a51a29dc994139e484b3"
#define V_CTX    "646179616e6a696e672d63322f76310000000000000007202122232425262728292a2b2c2d2e2f696d706c616e742d616c7068612d3031"

#define V_HELLO   "HELLO|v1|nonce12345678"
#define V_WELCOME "WELCOME|v1|sid"
#define V_FIN     "FIN|prefix"

/* ==================================================================== */

static void test_derive_pair(void)
{
    uint8_t psk[32], salt[32];
    c2_keymat_t km;

    hex2bin(V_PSK, psk, sizeof(psk));
    hex2bin(V_SALT, salt, sizeof(salt));

    CHECK(c2_derive_pair(psk, sizeof(psk), salt, &km) == C2_OK,
          "c2_derive_pair 返回 C2_OK");
    CHECK(hexeq(km.k_server_hold, 16, V_KHOLD),
          "k_server_hold 与 Python derive_pair 一致");
    CHECK(hexeq(km.k_identity, 16, V_KIDENT),
          "k_identity 与 Python derive_pair 一致");
    CHECK(memcmp(km.k_server_hold, km.k_identity, 16) != 0,
          "k_server_hold != k_identity（独立 info 分离）");

    /* PSK 熵不足必须拒绝 */
    CHECK(c2_derive_pair(psk, 15, salt, &km) == C2_ERR_LEN,
          "PSK 15 字节 -> C2_ERR_LEN（低于 128 bit 熵下限）");
    CHECK(c2_derive_pair(NULL, 32, salt, &km) == C2_ERR_ARG,
          "PSK=NULL -> C2_ERR_ARG");
    CHECK(c2_derive_pair(psk, 32, NULL, &km) == C2_ERR_ARG,
          "salt=NULL -> C2_ERR_ARG");
}

static void test_build_context(void)
{
    uint8_t sid[16], ctx[256];
    size_t need = 0, got = 0;

    hex2bin(V_SID, sid, sizeof(sid));

    /* 探测长度 */
    CHECK(c2_build_context(sid, "implant-alpha-01", 7, NULL, 0, &need) == C2_OK && need == 55,
          "ctx 探测长度 == 55（15 标签 + 8 代际 + 16 服务端 ID + 16 implant ID）");

    CHECK(c2_build_context(sid, "implant-alpha-01", 7, ctx, sizeof(ctx), &got) == C2_OK && got == 55,
          "ctx 实际构造返回 C2_OK 且长度 55");
    CHECK(hexeq(ctx, 55, V_CTX), "ctx 内容与 Python _build_context 逐字节一致");

    /* generation 大端编码 */
    {
        uint8_t c2[256];
        size_t l2 = 0;
        c2_build_context(sid, "x", 0x0102030405060708ULL, c2, sizeof(c2), &l2);
        CHECK(memcmp(c2 + 15, "\x01\x02\x03\x04\x05\x06\x07\x08", 8) == 0,
              "generation 大端编码正确（0x0102030405060708）");
    }

    /* 缓冲区不足 */
    CHECK(c2_build_context(sid, "implant-alpha-01", 7, ctx, 10, &got) == C2_ERR_LEN,
          "ctx 缓冲区不足 -> C2_ERR_LEN（且仍回填所需长度）");
    CHECK(got == 55, "缓冲区不足时仍回填所需长度 55");
}

static void test_derive_session(void)
{
    uint8_t master[16], sid[16], th[32];
    c2_session_keys_t sk;

    hex2bin(V_MASTER, master, sizeof(master));
    hex2bin(V_SID, sid, sizeof(sid));
    hex2bin(V_TH, th, sizeof(th));

    CHECK(c2_derive_session(master, th, sid, "implant-alpha-01", 7, &sk) == C2_OK,
          "c2_derive_session 返回 C2_OK");
    CHECK(hexeq(sk.k_c2s, 16, V_KC2S),   "k_c2s 与 Python derive_session 一致");
    CHECK(hexeq(sk.k_s2c, 16, V_KS2C),   "k_s2c 与 Python derive_session 一致");
    CHECK(hexeq(sk.k_confirm, 16, V_KCONF), "k_confirm 与 Python derive_session 一致");
    CHECK(memcmp(sk.k_c2s, sk.k_s2c, 16) != 0,
          "k_c2s != k_s2c（方向密钥分离，禁单密钥退化）");
    CHECK(memcmp(sk.k_c2s, sk.k_confirm, 16) != 0 &&
          memcmp(sk.k_s2c, sk.k_confirm, 16) != 0,
          "k_confirm 与前两者均不同（三密钥互不相等）");

    /* 参数校验 */
    CHECK(c2_derive_session(NULL, th, sid, "implant-alpha-01", 7, &sk) == C2_ERR_ARG,
          "master=NULL -> C2_ERR_ARG");
    CHECK(c2_derive_session(master, NULL, sid, "implant-alpha-01", 7, &sk) == C2_ERR_ARG,
          "transcript_hash=NULL -> C2_ERR_ARG");
    CHECK(c2_derive_session(master, th, NULL, "implant-alpha-01", 7, &sk) == C2_ERR_ARG,
          "server_static_id=NULL -> C2_ERR_ARG");
    CHECK(c2_derive_session(master, th, sid, "implant-alpha-01", 7, NULL) == C2_ERR_ARG,
          "sk=NULL -> C2_ERR_ARG");
}

static void test_transcript(void)
{
    const char *h = V_HELLO, *w = V_WELCOME, *f = V_FIN;
    c2_transcript_t t;
    uint8_t out[32];

    /* 一次性拼接 == Python compute_transcript */
    {
        uint8_t joined[128];
        size_t n = 0;
        memcpy(joined + n, h, strlen(h)); n += strlen(h);
        memcpy(joined + n, w, strlen(w)); n += strlen(w);
        memcpy(joined + n, f, strlen(f)); n += strlen(f);
        sha256(joined, n, out);
        CHECK(hexeq(out, 32, V_TH), "transcript 与 Python compute_transcript 一致");
    }

    /* 流式分三次 feed */
    c2_transcript_init(&t);
    c2_transcript_feed(&t, (const uint8_t *)h, strlen(h));
    c2_transcript_feed(&t, (const uint8_t *)w, strlen(w));
    c2_transcript_feed(&t, (const uint8_t *)f, strlen(f));
    c2_transcript_final(&t, out);
    CHECK(hexeq(out, 32, V_TH), "transcript 流式三次 feed 结果一致");
    c2_transcript_free(&t);

    /* 逐字节 feed 也必须一致 */
    {
        uint8_t joined[128];
        size_t n = 0, i;
        memcpy(joined + n, h, strlen(h)); n += strlen(h);
        memcpy(joined + n, w, strlen(w)); n += strlen(w);
        memcpy(joined + n, f, strlen(f)); n += strlen(f);
        c2_transcript_init(&t);
        for (i = 0; i < n; i++) c2_transcript_feed(&t, joined + i, 1);
        c2_transcript_final(&t, out);
        CHECK(hexeq(out, 32, V_TH), "transcript 逐字节 feed 结果一致");
        c2_transcript_free(&t);
    }

    /* 防篡改：改动任一字节，transcript 必须不同 */
    {
        uint8_t joined[128];
        size_t n = 0;
        memcpy(joined + n, h, strlen(h)); n += strlen(h);
        memcpy(joined + n, "WELCOME|v1|siX", strlen("WELCOME|v1|siX")); n += strlen("WELCOME|v1|siX");
        memcpy(joined + n, f, strlen(f)); n += strlen(f);
        sha256(joined, n, out);
        CHECK(!hexeq(out, 32, V_TH), "transcript 对消息篡改敏感（改 1 字节即变化）");
    }
}

static void test_handshake(void)
{
    c2_handshake_t hs;
    uint8_t th[32];
    c2_session_keys_t sk;
    uint8_t master[16], sid[16];

    hex2bin(V_MASTER, master, sizeof(master));
    hex2bin(V_SID, sid, sizeof(sid));

    /* 合法链 */
    c2_hs_init(&hs);
    CHECK(hs.state == C2_HS_INIT, "c2_hs_init 后状态为 INIT");
    CHECK(c2_hs_step(&hs, C2_HS_HELLO, (const uint8_t *)V_HELLO, strlen(V_HELLO)) == C2_OK,
          "INIT -> HELLO 合法");
    CHECK(c2_hs_step(&hs, C2_HS_WELCOME, (const uint8_t *)V_WELCOME, strlen(V_WELCOME)) == C2_OK,
          "HELLO -> WELCOME 合法");
    CHECK(c2_hs_step(&hs, C2_HS_FINISHED, (const uint8_t *)V_FIN, strlen(V_FIN)) == C2_OK,
          "WELCOME -> FINISHED 合法");
    CHECK(c2_hs_transcript(&hs, th) == C2_OK && hexeq(th, 32, V_TH),
          "握手 transcript 与 Python compute_transcript 一致");
    CHECK(c2_hs_step(&hs, C2_HS_ACTIVE, NULL, 0) == C2_OK,
          "FINISHED -> ACTIVE 合法");

    /* 用握手 transcript 派生会话密钥，应与 Python 真值一致 */
    CHECK(c2_derive_session(master, th, sid, "implant-alpha-01", 7, &sk) == C2_OK &&
          hexeq(sk.k_c2s, 16, V_KC2S) && hexeq(sk.k_s2c, 16, V_KS2C),
          "握手 transcript 派生的会话密钥与 Python 一致（端到端）");
    c2_hs_free(&hs);

    /* 非法转移：跳步 */
    c2_hs_init(&hs);
    CHECK(c2_hs_step(&hs, C2_HS_WELCOME, NULL, 0) == C2_ERR_STATE,
          "INIT -> WELCOME 跳步 -> C2_ERR_STATE");
    CHECK(hs.state == C2_HS_INIT, "非法转移后状态不变（仍为 INIT）");
    CHECK(c2_hs_step(&hs, C2_HS_ACTIVE, NULL, 0) == C2_ERR_STATE,
          "INIT -> ACTIVE 跳步 -> C2_ERR_STATE");
    c2_hs_free(&hs);

    /* 非法转移不得污染 transcript */
    {
        uint8_t before[32], after[32];
        c2_hs_init(&hs);
        c2_hs_step(&hs, C2_HS_HELLO, (const uint8_t *)V_HELLO, strlen(V_HELLO));
        c2_hs_transcript(&hs, before);
        c2_hs_step(&hs, C2_HS_ACTIVE, (const uint8_t *)"GARBAGE", 7);  /* 非法 */
        c2_hs_transcript(&hs, after);
        CHECK(memcmp(before, after, 32) == 0,
              "非法转移不污染 transcript（防降级/重放注入）");
        c2_hs_free(&hs);
    }

    /* ACTIVE 后不可回退 */
    c2_hs_init(&hs);
    c2_hs_step(&hs, C2_HS_HELLO, NULL, 0);
    c2_hs_step(&hs, C2_HS_WELCOME, NULL, 0);
    c2_hs_step(&hs, C2_HS_FINISHED, NULL, 0);
    c2_hs_step(&hs, C2_HS_ACTIVE, NULL, 0);
    CHECK(c2_hs_step(&hs, C2_HS_HELLO, NULL, 0) == C2_ERR_STATE,
          "ACTIVE -> HELLO 回退 -> C2_ERR_STATE");
    c2_hs_free(&hs);

    /* FAILED 是终态 */
    c2_hs_init(&hs);
    CHECK(c2_hs_step(&hs, C2_HS_FAILED, NULL, 0) == C2_OK, "任意态 -> FAILED 允许");
    CHECK(c2_hs_step(&hs, C2_HS_HELLO, NULL, 0) == C2_ERR_STATE,
          "FAILED -> HELLO -> C2_ERR_STATE（终态不可恢复）");
    CHECK(c2_hs_can(C2_HS_FAILED, C2_HS_FAILED) == 0, "FAILED -> FAILED 亦被拒（终态）");
    c2_hs_free(&hs);

    /* c2_hs_can 表驱动一致性 */
    CHECK(c2_hs_can(C2_HS_INIT, C2_HS_HELLO) == 1 &&
          c2_hs_can(C2_HS_HELLO, C2_HS_WELCOME) == 1 &&
          c2_hs_can(C2_HS_WELCOME, C2_HS_FINISHED) == 1 &&
          c2_hs_can(C2_HS_FINISHED, C2_HS_ACTIVE) == 1,
          "c2_hs_can 正向链全部允许");
    CHECK(strcmp(c2_hs_state_name(C2_HS_ACTIVE), "ACTIVE") == 0 &&
          strcmp(c2_hs_state_name(C2_HS_FAILED), "FAILED") == 0,
          "c2_hs_state_name 映射正确");
}

int main(void)
{
    printf("[*] 02_c2 握手与会话密钥派生测试\n");
    printf("[*] 期望值由 Python key_derivation.py 真实运行产生\n");
    printf("[*] ==========================================\n");

    test_derive_pair();
    test_build_context();
    test_derive_session();
    test_transcript();
    test_handshake();

    printf("[*] ==========================================\n");
    printf("[*] 结果: %d/%d 通过\n", g_pass, g_pass + g_fail);
    printf("[*] 失败: %d 项\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
