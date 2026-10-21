/*
 * DAYANJING v4 — 20_packer / test_c2_packer.c
 *
 * 与 02_c2 联编的端到端验证：真实会话密钥 -> 制品绑定 -> 解包。
 *
 * 目的不是重复测打包器，而是证明"绑定用的密钥材料确实来自 02_c2 派生链"：
 *   PSK + 注册盐 -> c2_derive_pair
 *   握手 transcript + 身份上下文 -> c2_derive_session -> k_c2s / k_s2c
 *   再交给 20_packer 做制品绑定。
 *
 * 由此得到的性质：制品与"哪一次握手、哪一个植入体、第几代密钥"绑定，
 * 换一次会话（generation 变化）或换一个植入体，制品即刻失效。
 */

#include "packer.h"
#include "c2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_total = 0;
static int g_fail  = 0;

#define CHECK(cond, name)                                                 \
    do {                                                                  \
        g_total++;                                                        \
        if (cond) {                                                       \
            printf("[PASS] %s\n", name);                                  \
        } else {                                                          \
            printf("[FAIL] %s  (%s:%d)\n", name, __FILE__, __LINE__);     \
            g_fail++;                                                     \
        }                                                                 \
    } while (0)

static uint32_t xs_state = 0x2545f491u;
static uint32_t xs_next(void)
{
    xs_state ^= xs_state << 13;
    xs_state ^= xs_state >> 17;
    xs_state ^= xs_state << 5;
    return xs_state;
}

static void fill_pattern(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(xs_next() & 0xffu);
}

/* 真实走一遍 02_c2 派生链，产出会话密钥与绑定上下文 */
static int derive(const uint8_t *psk, size_t psk_len,
                  const uint8_t salt_reg[C2_SALT_REG_LEN],
                  const uint8_t server_static_id[C2_SERVER_ID_LEN],
                  const char *implant_id,
                  uint64_t generation,
                  const uint8_t *hello, size_t hello_len,
                  const uint8_t *welcome, size_t welcome_len,
                  const uint8_t *finished, size_t finished_len,
                  c2_session_keys_t *sk,
                  uint8_t *ctx, size_t ctx_cap, size_t *ctx_len)
{
    c2_keymat_t km;
    c2_transcript_t tr;
    uint8_t th[C2_TRANSCRIPT_LEN];
    int rc;

    rc = c2_derive_pair(psk, psk_len, salt_reg, &km);
    if (rc != C2_OK) return rc;

    c2_transcript_init(&tr);
    c2_transcript_feed(&tr, hello, hello_len);
    c2_transcript_feed(&tr, welcome, welcome_len);
    c2_transcript_feed(&tr, finished, finished_len);
    c2_transcript_final(&tr, th);
    c2_transcript_free(&tr);

    rc = c2_derive_session(km.k_server_hold, th, server_static_id,
                           implant_id, generation, sk);
    if (rc != C2_OK) return rc;

    rc = c2_build_context(server_static_id, implant_id, generation,
                          ctx, ctx_cap, ctx_len);
    return rc;
}

int main(void)
{
    uint8_t psk[32], salt_reg[C2_SALT_REG_LEN];
    uint8_t sid[C2_SERVER_ID_LEN];
    c2_session_keys_t sk_a, sk_b, sk_c;
    uint8_t ctx_a[256], ctx_b[256], ctx_c[256];
    size_t  ctx_a_len = 0, ctx_b_len = 0, ctx_c_len = 0;
    size_t  ctx_cap = sizeof(ctx_a);

    static const uint8_t hello[]    = "HELLO|nonce=0123456789abcdef|ver=1";
    static const uint8_t welcome[]  = "WELCOME|sid=...|gen=1";
    static const uint8_t finished[] = "FINISHED|confirm=...";

    uint8_t raw[8192];
    uint8_t *blob, *out;
    size_t   cap, blob_len, out_len;
    int      rc;

    fill_pattern(psk, sizeof(psk));
    fill_pattern(salt_reg, sizeof(salt_reg));
    fill_pattern(sid, sizeof(sid));
    for (size_t i = 0; i < sizeof(raw); i++) raw[i] = (uint8_t)(i % 251);

    /* ---------- 1. 三条真实会话 ---------- */

    rc = derive(psk, sizeof(psk), salt_reg, sid, "implant-ALPHA", 1,
                hello, sizeof(hello) - 1u,
                welcome, sizeof(welcome) - 1u,
                finished, sizeof(finished) - 1u,
                &sk_a, ctx_a, ctx_cap, &ctx_a_len);
    CHECK(rc == C2_OK, "02_c2 派生会话 A 成功");

    /* 同参数重跑：结果必须一致（确定性） */
    {
        c2_session_keys_t sk_a2;
        uint8_t ctx_a2[256];
        size_t  ctx_a2_len = 0;
        rc = derive(psk, sizeof(psk), salt_reg, sid, "implant-ALPHA", 1,
                    hello, sizeof(hello) - 1u,
                    welcome, sizeof(welcome) - 1u,
                    finished, sizeof(finished) - 1u,
                    &sk_a2, ctx_a2, sizeof(ctx_a2), &ctx_a2_len);
        CHECK(rc == C2_OK &&
              memcmp(&sk_a, &sk_a2, sizeof(sk_a)) == 0 &&
              ctx_a_len == ctx_a2_len &&
              memcmp(ctx_a, ctx_a2, ctx_a_len) == 0,
              "会话 A 派生确定性一致");
    }

    /* 换植入体 */
    rc = derive(psk, sizeof(psk), salt_reg, sid, "implant-BRAVO", 1,
                hello, sizeof(hello) - 1u,
                welcome, sizeof(welcome) - 1u,
                finished, sizeof(finished) - 1u,
                &sk_b, ctx_b, ctx_cap, &ctx_b_len);
    CHECK(rc == C2_OK, "02_c2 派生会话 B（换植入体）成功");
    CHECK(memcmp(sk_a.k_c2s, sk_b.k_c2s, C2_KEY_LEN) != 0,
          "换植入体后会话密钥不同");
    CHECK(ctx_a_len == ctx_b_len && memcmp(ctx_a, ctx_b, ctx_a_len) != 0,
          "换植入体后绑定上下文不同");

    /* 换 generation（同植入体，密钥轮换一代） */
    rc = derive(psk, sizeof(psk), salt_reg, sid, "implant-ALPHA", 2,
                hello, sizeof(hello) - 1u,
                welcome, sizeof(welcome) - 1u,
                finished, sizeof(finished) - 1u,
                &sk_c, ctx_c, ctx_cap, &ctx_c_len);
    CHECK(rc == C2_OK, "02_c2 派生会话 C（换 generation）成功");
    CHECK(memcmp(sk_a.k_c2s, sk_c.k_c2s, C2_KEY_LEN) != 0,
          "换 generation 后会话密钥不同");

    /* 02_c2 保证单向分离，故打包器不会因退化拒绝 */
    CHECK(memcmp(sk_a.k_c2s, sk_a.k_s2c, C2_KEY_LEN) != 0,
          "会话 A 的 k_c2s != k_s2c（单向分离）");
    {
        uint8_t seed[PK_SHA_LEN];
        CHECK(pk_session_seed(sk_a.k_c2s, sk_a.k_s2c,
                              ctx_a, ctx_a_len, seed) == PK_OK,
              "真实会话密钥可用于派生打包种子");
    }

    /* ---------- 2. 真实会话密钥打包往返 ---------- */

    cap = pk_size_bound_v2(sizeof(raw));
    blob = (uint8_t *)malloc(cap);
    out  = (uint8_t *)malloc(sizeof(raw) + 64);
    if (!blob || !out) { printf("[FAIL] 内存分配\n"); return 1; }

    blob_len = cap;
    rc = pk_pack_session(raw, sizeof(raw), sk_a.k_c2s, sk_a.k_s2c,
                         ctx_a, ctx_a_len, blob, &blob_len);
    CHECK(rc == PK_OK, "用 02_c2 会话密钥打包成功");

    out_len = sizeof(raw) + 64;
    rc = pk_unpack_session(blob, blob_len, sk_a.k_c2s, sk_a.k_s2c,
                           ctx_a, ctx_a_len, out, &out_len);
    CHECK(rc == PK_OK, "用 02_c2 会话密钥解包成功");
    CHECK(out_len == sizeof(raw) && memcmp(out, raw, sizeof(raw)) == 0,
          "真实会话绑定往返字节级一致");

    /* ---------- 3. 跨会话拒绝 ---------- */

    out_len = sizeof(raw) + 64;
    rc = pk_unpack_session(blob, blob_len, sk_b.k_c2s, sk_b.k_s2c,
                           ctx_a, ctx_a_len, out, &out_len);
    CHECK(rc == PK_ERR_AUTH, "另一植入体的会话密钥解不开（AUTH）");

    out_len = sizeof(raw) + 64;
    rc = pk_unpack_session(blob, blob_len, sk_c.k_c2s, sk_c.k_s2c,
                           ctx_a, ctx_a_len, out, &out_len);
    CHECK(rc == PK_ERR_AUTH, "换 generation 后的会话密钥解不开（AUTH）");

    out_len = sizeof(raw) + 64;
    rc = pk_unpack_session(blob, blob_len, sk_a.k_c2s, sk_a.k_s2c,
                           ctx_b, ctx_b_len, out, &out_len);
    CHECK(rc == PK_ERR_BIND, "正确密钥 + 错误植入体上下文被拒（BIND）");

    /* 制品在两代密钥之间不可迁移：用 gen=2 的上下文重封，gen=1 解不开 */
    {
        uint8_t *blob_c = (uint8_t *)malloc(cap);
        size_t   blen_c = cap;
        uint8_t *tmp    = (uint8_t *)malloc(sizeof(raw) + 64);
        size_t   tmplen;

        if (!tmp) { printf("[FAIL] 内存分配\n"); return 1; }

        rc = pk_pack_session(raw, sizeof(raw), sk_c.k_c2s, sk_c.k_s2c,
                             ctx_c, ctx_c_len, blob_c, &blen_c);
        CHECK(rc == PK_OK, "gen=2 会话打包成功");

        tmplen = sizeof(raw) + 64;
        rc = pk_unpack_session(blob_c, blen_c, sk_a.k_c2s, sk_a.k_s2c,
                               ctx_c, ctx_c_len, tmp, &tmplen);
        CHECK(rc == PK_ERR_AUTH, "gen=2 制品无法用 gen=1 密钥解开（AUTH）");

        tmplen = sizeof(raw) + 64;
        rc = pk_unpack_session(blob_c, blen_c, sk_c.k_c2s, sk_c.k_s2c,
                               ctx_a, ctx_a_len, tmp, &tmplen);
        CHECK(rc == PK_ERR_BIND, "gen=2 制品配 gen=1 上下文被拒（BIND）");

        /* 同密钥同上下文仍可正常解开，排除用例自身写错 */
        tmplen = sizeof(raw) + 64;
        rc = pk_unpack_session(blob_c, blen_c, sk_c.k_c2s, sk_c.k_s2c,
                               ctx_c, ctx_c_len, tmp, &tmplen);
        CHECK(rc == PK_OK && tmplen == sizeof(raw) &&
              memcmp(tmp, raw, sizeof(raw)) == 0,
              "gen=2 制品用 gen=2 密钥正常解开（用例自身有效）");

        free(tmp);
        free(blob_c);
    }

    /* ---------- 4. 制品标识可检视 ---------- */

    {
        uint8_t id[PK_BIND_ID_LEN], want[PK_BIND_ID_LEN];
        CHECK(pk_artifact_bind_id(blob, blob_len, id) == PK_OK,
              "可取制品 bind_id");
        CHECK(pk_bind_id(ctx_a, ctx_a_len, want) == PK_OK &&
              memcmp(id, want, PK_BIND_ID_LEN) == 0,
              "制品 bind_id 与会话 A 上下文一致");
    }

    free(blob);
    free(out);

    printf("\n%d tests, %d failures\n", g_total, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
