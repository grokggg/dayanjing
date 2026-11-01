/*
 * DAYANJING v3 — test_c2_frame.c
 *
 * 帧层 wire 格式验证（与 Python frame.py 对齐）。
 * 覆盖：往返一致、探测容量、篡改检测、格式自洽、AAD 构造、边界。
 */

#include "c2_frame.h"
#include "crypto_gcm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, name) do { \
    if (cond) { g_pass++; printf("  [PASS] %s\n", name); } \
    else { g_fail++; printf("  [FAIL] %s  (%s:%d)\n", name, __FILE__, __LINE__); } \
} while (0)

static uint8_t g_key[16];
static uint8_t g_prefix[8];

static void init_fixed(void)
{
    size_t i;
    for (i = 0; i < 16; i++) g_key[i]    = (uint8_t)(0x11 + i);
    for (i = 0; i < 8;  i++) g_prefix[i] = (uint8_t)(0xa0 + i);
}

static void test_roundtrip(void)
{
    const char *msg = "HELLO-C2-PAYLOAD";
    uint8_t wire[256], out[128];
    size_t cap = 0, wlen = 0, plen = 0;
    uint64_t seq = 0;
    uint32_t mt = 0;

    /* 探测 */
    CHECK(c2_frame_seal(g_key, g_prefix, 0, 7, 0x10,
                        (const uint8_t *)msg, strlen(msg),
                        NULL, 0, &cap) == C2_FRAME_OK, "seal 探测模式返回 OK");
    CHECK(cap == C2_FRAME_WIRE_LEN(strlen(msg)),
          "seal 探测长度 == 帧头开销 + Envelope 头 + payload");

    /* 实际封装 */
    wlen = sizeof(wire);
    CHECK(c2_frame_seal(g_key, g_prefix, 0, 7, 0x10,
                        (const uint8_t *)msg, strlen(msg),
                        wire, wlen, &wlen) == C2_FRAME_OK, "seal 实际封装 OK");
    CHECK(wlen == cap, "seal 实际长度 == 探测长度");

    /* 解封 */
    plen = sizeof(out);
    CHECK(c2_frame_open(g_key, wire, wlen, &seq, &mt, out, plen, &plen) == C2_FRAME_OK,
          "open 解封 OK");
    CHECK(seq == 7 && mt == 0x10, "open 还原 seq/msg_type 正确");
    CHECK(plen == strlen(msg) && memcmp(out, msg, plen) == 0,
          "open 还原 payload 字节级一致");
}

static void test_detect_tamper(void)
{
    const char *msg = "SENSITIVE-DATA";
    uint8_t wire[256], out[128];
    size_t wlen = sizeof(wire), plen = sizeof(out);
    size_t ct_len = strlen(msg);

    c2_frame_seal(g_key, g_prefix, 3, 1, 0x20,
                  (const uint8_t *)msg, ct_len, wire, wlen, &wlen);

    /* 改密文 */
    {
        uint8_t w[256];
        memcpy(w, wire, wlen);
        w[8 + 12] ^= 0x01;                      /* 首字节密文翻转 */
        plen = sizeof(out);
        CHECK(c2_frame_open(g_key, w, wlen, NULL, NULL, out, plen, &plen) == C2_FRAME_ERR_AUTH,
              "篡改密文 -> C2_FRAME_ERR_AUTH");
    }
    /* 改 tag */
    {
        uint8_t w[256];
        memcpy(w, wire, wlen);
        w[wlen - 1] ^= 0x80;
        plen = sizeof(out);
        CHECK(c2_frame_open(g_key, w, wlen, NULL, NULL, out, plen, &plen) == C2_FRAME_ERR_AUTH,
              "篡改 tag -> C2_FRAME_ERR_AUTH");
    }
    /* 改 iv */
    {
        uint8_t w[256];
        memcpy(w, wire, wlen);
        w[8] ^= 0x01;
        plen = sizeof(out);
        CHECK(c2_frame_open(g_key, w, wlen, NULL, NULL, out, plen, &plen) == C2_FRAME_ERR_AUTH,
              "篡改 iv -> C2_FRAME_ERR_AUTH");
    }
    /* 改帧头 msg_type（使 AAD 与加密时不一致） */
    {
        uint8_t w[256];
        memcpy(w, wire, wlen);
        w[4] ^= 0x01;
        plen = sizeof(out);
        CHECK(c2_frame_open(g_key, w, wlen, NULL, NULL, out, plen, &plen) != C2_FRAME_OK,
              "篡改帧头 msg_type -> 验签失败（AAD 不匹配）");
    }
    /* 错误密钥 */
    {
        uint8_t bad[16];
        memcpy(bad, g_key, 16);
        bad[0] ^= 0xff;
        plen = sizeof(out);
        CHECK(c2_frame_open(bad, wire, wlen, NULL, NULL, out, plen, &plen) == C2_FRAME_ERR_AUTH,
              "错误密钥 -> C2_FRAME_ERR_AUTH");
    }
}

static void test_format_edges(void)
{
    uint8_t wire[256], out[128];
    size_t wlen = sizeof(wire), plen;

    /* 空 payload */
    wlen = sizeof(wire);
    CHECK(c2_frame_seal(g_key, g_prefix, 0, 0, 0x01, NULL, 0, wire, wlen, &wlen) == C2_FRAME_OK,
          "空 payload seal OK");
    plen = sizeof(out);
    CHECK(c2_frame_open(g_key, wire, wlen, NULL, NULL, out, plen, &plen) == C2_FRAME_OK && plen == 0,
          "空 payload open OK 且长度 0");

    /* 长度头不自洽 */
    {
        uint8_t w[256];
        memcpy(w, wire, wlen);
        w[0] += 1;
        plen = sizeof(out);
        CHECK(c2_frame_open(g_key, w, wlen, NULL, NULL, out, plen, &plen) == C2_FRAME_ERR_FMT,
              "total_len 与实际长度不符 -> C2_FRAME_ERR_FMT");
    }

    /* 过短帧 */
    {
        uint8_t tiny[8];
        memset(tiny, 0, sizeof(tiny));
        plen = sizeof(out);
        CHECK(c2_frame_open(g_key, tiny, sizeof(tiny), NULL, NULL, out, plen, &plen)
              == C2_FRAME_ERR_FMT, "过短帧 -> C2_FRAME_ERR_FMT");
    }

    /* 缓冲区不足 */
    {
        size_t need = 0;
        const char *m = "0123456789abcdef";
        c2_frame_seal(g_key, g_prefix, 0, 1, 2, (const uint8_t *)m, 16, NULL, 0, &need);
        wlen = 10;
        CHECK(c2_frame_seal(g_key, g_prefix, 0, 1, 2, (const uint8_t *)m, 16,
                            wire, wlen, &wlen) == C2_FRAME_ERR_LEN, "seal 缓冲区不足 -> ERR_LEN");
        CHECK(wlen == need, "缓冲区不足时仍回填所需长度");
    }

    /* 参数校验 */
    CHECK(c2_frame_seal(NULL, g_prefix, 0, 1, 2, (const uint8_t *)"x", 1, wire, sizeof(wire), &wlen)
          == C2_FRAME_ERR_ARG, "key=NULL -> C2_FRAME_ERR_ARG");
    CHECK(c2_frame_seal(g_key, NULL, 0, 1, 2, (const uint8_t *)"x", 1, wire, sizeof(wire), &wlen)
          == C2_FRAME_ERR_ARG, "prefix=NULL -> C2_FRAME_ERR_ARG");
}

static void test_aad_and_iv(void)
{
    uint8_t aad[13];
    uint8_t expect[13];

    /* AAD = "c2:v1" || u32_le(1) || u32_le(msg_type) */
    memcpy(expect, "c2:v1", 5);
    expect[5] = 1; expect[6] = 0; expect[7] = 0; expect[8] = 0;
    expect[9] = 0x34; expect[10] = 0x12; expect[11] = 0; expect[12] = 0;

    CHECK(c2_frame_aad(0x1234, aad) == 13, "AAD 长度 == 13");
    CHECK(memcmp(aad, expect, 13) == 0,
          "AAD == b\"c2:v1\" || u32_le(version) || u32_le(msg_type)");

    /* IV = prefix(8B) || counter(4B 大端) */
    {
        uint8_t wire[64];
        size_t wlen = sizeof(wire);
        c2_frame_seal(g_key, g_prefix, 0x01020304u, 1, 2, (const uint8_t *)"x", 1, wire, wlen, &wlen);
        CHECK(memcmp(wire + 8, g_prefix, 8) == 0, "IV 前 8 字节 == nonce_prefix");
        CHECK(memcmp(wire + 16, "\x01\x02\x03\x04", 4) == 0,
              "IV 后 4 字节 == counter 大端编码");
    }
}

static void test_large_payload(void)
{
    static uint8_t big[60000];
    static uint8_t wire[64000];
    static uint8_t out[64000];
    size_t i, wlen = sizeof(wire), plen = sizeof(out);

    for (i = 0; i < sizeof(big); i++) big[i] = (uint8_t)(i * 7 + 3);

    CHECK(c2_frame_seal(g_key, g_prefix, 0, 99, 0x30, big, sizeof(big), wire, wlen, &wlen)
          == C2_FRAME_OK, "大 payload(60000B) seal OK");
    CHECK(c2_frame_open(g_key, wire, wlen, NULL, NULL, out, plen, &plen) == C2_FRAME_OK,
          "大 payload open OK");
    CHECK(plen == sizeof(big) && memcmp(out, big, sizeof(big)) == 0,
          "大 payload 往返字节级一致");
}

int main(void)
{
    printf("[*] 02_c2 帧层 wire 格式测试\n");
    printf("[*] ==========================================\n");

    init_fixed();
    test_roundtrip();
    test_detect_tamper();
    test_format_edges();
    test_aad_and_iv();
    test_large_payload();

    printf("[*] ==========================================\n");
    printf("[*] 结果: %d/%d 通过\n", g_pass, g_pass + g_fail);
    printf("[*] 失败: %d 项\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
