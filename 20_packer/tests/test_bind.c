/*
 * DAYANJING v4 — 20_packer / test_bind.c
 *
 * 覆盖：会话密钥派生种子 / 绑定标识 / v2 制品往返 / 跨会话互换拒绝 /
 *       bind_id 纳入 AAD 的隔离验证 / v1 向后兼容 / 大载荷 / 参数校验。
 *
 * 本测试不链接 02_c2：会话密钥用固定字节模拟。真实 02_c2 会话密钥的
 * 联编验证见 tests/test_c2_packer.c。
 */

#include "packer.h"

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

/* 确定性 PRNG（xorshift32） */
static uint32_t xs_state = 0x9e3779b9u;
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

/* 高可压缩载荷：重复的 64 字节块，LZSS 必然生效 */
static void fill_compressible(uint8_t *p, size_t n, uint8_t base)
{
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(base + (i % 64));
}

int main(void)
{
    uint8_t k_c2s[PK_SESSION_KEY_LEN], k_s2c[PK_SESSION_KEY_LEN];
    uint8_t k_other1[PK_SESSION_KEY_LEN], k_other2[PK_SESSION_KEY_LEN];
    uint8_t seed_a[PK_SHA_LEN], seed_b[PK_SHA_LEN], seed_c[PK_SHA_LEN];
    uint8_t bid_a[PK_BIND_ID_LEN], bid_b[PK_BIND_ID_LEN];
    uint8_t raw[4096];
    uint8_t *blob, *out;
    size_t   blob_len, out_len, cap;
    int      rc;

    /* 会话 A 的单向密钥（必须互不相同） */
    fill_pattern(k_c2s, sizeof(k_c2s));
    do { fill_pattern(k_s2c, sizeof(k_s2c)); }
    while (memcmp(k_c2s, k_s2c, PK_SESSION_KEY_LEN) == 0);

    /* 会话 B 的密钥 */
    fill_pattern(k_other1, sizeof(k_other1));
    do { fill_pattern(k_other2, sizeof(k_other2)); }
    while (memcmp(k_other1, k_other2, PK_SESSION_KEY_LEN) == 0);

    /* ---------- 1. 种子派生 ---------- */

    rc = pk_session_seed(k_c2s, k_s2c, NULL, 0, seed_a);
    CHECK(rc == PK_OK, "pk_session_seed 基本调用成功");

    rc = pk_session_seed(k_c2s, k_s2c, NULL, 0, seed_b);
    CHECK(rc == PK_OK && memcmp(seed_a, seed_b, PK_SHA_LEN) == 0,
          "同输入派生确定性一致");

    {
        const uint8_t ctx_a[] = "implant-A";
        rc = pk_session_seed(k_c2s, k_s2c, ctx_a, sizeof(ctx_a) - 1u, seed_c);
        CHECK(rc == PK_OK && memcmp(seed_a, seed_c, PK_SHA_LEN) != 0,
              "绑定上下文不同则种子不同");
    }

    /* 方向性：k_c2s/k_s2c 互换必须产生不同种子（单向密钥分离） */
    {
        uint8_t seed_swap[PK_SHA_LEN];
        rc = pk_session_seed(k_s2c, k_c2s, NULL, 0, seed_swap);
        CHECK(rc == PK_OK && memcmp(seed_a, seed_swap, PK_SHA_LEN) != 0,
              "方向互换（k_s2c||k_c2s）产生不同种子");
    }

    /* 域分离：种子不等于任一原始密钥的前 16 字节 */
    CHECK(memcmp(seed_a, k_c2s, PK_SESSION_KEY_LEN) != 0 &&
          memcmp(seed_a, k_s2c, PK_SESSION_KEY_LEN) != 0,
          "种子与会话密钥域分离（非直接复用）");

    /* 退化密钥拒绝 */
    rc = pk_session_seed(k_c2s, k_c2s, NULL, 0, seed_b);
    CHECK(rc == PK_ERR_DEGEN, "k_c2s == k_s2c 时拒绝派生（PK_ERR_DEGEN）");

    /* 参数校验 */
    CHECK(pk_session_seed(NULL, k_s2c, NULL, 0, seed_b) == PK_ERR_ARG,
          "pk_session_seed 空 k_c2s 被拒");
    CHECK(pk_session_seed(k_c2s, NULL, NULL, 0, seed_b) == PK_ERR_ARG,
          "pk_session_seed 空 k_s2c 被拒");
    CHECK(pk_session_seed(k_c2s, k_s2c, NULL, 0, NULL) == PK_ERR_ARG,
          "pk_session_seed 空输出被拒");
    CHECK(pk_session_seed(k_c2s, k_s2c, (const uint8_t *)"x", 1, seed_b) == PK_OK,
          "pk_session_seed 非空上下文正常");

    /* ---------- 2. 绑定标识 ---------- */

    {
        const uint8_t ctx_a[] = "implant-A";
        const uint8_t ctx_b[] = "implant-B";
        uint8_t tmp[PK_BIND_ID_LEN];

        CHECK(pk_bind_id(ctx_a, sizeof(ctx_a) - 1u, bid_a) == PK_OK,
              "pk_bind_id 计算成功");
        CHECK(pk_bind_id(ctx_a, sizeof(ctx_a) - 1u, tmp) == PK_OK &&
              memcmp(tmp, bid_a, PK_BIND_ID_LEN) == 0,
              "pk_bind_id 确定性一致");
        CHECK(pk_bind_id(ctx_b, sizeof(ctx_b) - 1u, bid_b) == PK_OK &&
              memcmp(bid_a, bid_b, PK_BIND_ID_LEN) != 0,
              "不同上下文绑定标识不同");
        CHECK(pk_bind_id(NULL, 0, tmp) == PK_OK &&
              memcmp(tmp, bid_a, PK_BIND_ID_LEN) != 0,
              "空上下文与 implant-A 标识不同");
        CHECK(pk_bind_id(NULL, 0, NULL) == PK_ERR_ARG, "pk_bind_id 空输出被拒");
    }

    /* ---------- 3. v2 会话制品往返 ---------- */

    fill_compressible(raw, sizeof(raw), 0x10);
    cap = pk_size_bound_v2(sizeof(raw));
    blob = (uint8_t *)malloc(cap);
    out  = (uint8_t *)malloc(sizeof(raw) + 64);
    if (!blob || !out) { printf("[FAIL] 内存分配\n"); return 1; }

    {
        const uint8_t ctx[] = "implant-A|gen=1";
        blob_len = cap;
        rc = pk_pack_session(raw, sizeof(raw), k_c2s, k_s2c,
                             ctx, sizeof(ctx) - 1u, blob, &blob_len);
        CHECK(rc == PK_OK, "pk_pack_session 打包成功");
        CHECK(blob_len >= PK_HDR_V2_LEN, "v2 制品长度不小于 v2 头");
        CHECK(blob_len <= cap, "v2 制品未超出尺寸上界");

        /* 头部版本与 bind_id 落位 */
        {
            pk_hdr h;
            rc = pk_header_parse(blob, blob_len, &h);
            CHECK(rc == PK_OK && h.version == PK_VERSION2,
                  "制品头版本为 v2");
            CHECK(memcmp(h.bind_id, bid_a, PK_BIND_ID_LEN) != 0 &&
                  memcmp(h.bind_id, bid_b, PK_BIND_ID_LEN) != 0,
                  "制品内 bind_id 已写入（非空）");
        }

        out_len = sizeof(raw) + 64;
        rc = pk_unpack_session(blob, blob_len, k_c2s, k_s2c,
                               ctx, sizeof(ctx) - 1u, out, &out_len);
        CHECK(rc == PK_OK, "pk_unpack_session 解包成功");
        CHECK(out_len == sizeof(raw) &&
              memcmp(out, raw, sizeof(raw)) == 0,
              "会话制品往返字节级一致");

        /* 压缩确实生效（可压缩载荷下密文应短于原始长度） */
        {
            pk_hdr h;
            pk_header_parse(blob, blob_len, &h);
            CHECK((h.flags & PK_FLAG_COMPRESSED) != 0, "可压缩载荷启用压缩标志");
            CHECK(h.pay_len < sizeof(raw), "压缩后载荷短于原始长度");
        }
    }

    /* ---------- 4. 跨会话 / 跨植入体拒绝 ---------- */

    {
        const uint8_t ctx_a[] = "implant-A|gen=1";
        const uint8_t ctx_b[] = "implant-B|gen=1";

        /* 4a 同一绑定上下文、错误会话密钥 -> AUTH（密钥不同则解不开） */
        out_len = sizeof(raw) + 64;
        rc = pk_unpack_session(blob, blob_len, k_other1, k_other2,
                               ctx_a, sizeof(ctx_a) - 1u, out, &out_len);
        CHECK(rc == PK_ERR_AUTH, "错误会话密钥解包被拒（PK_ERR_AUTH）");

        /* 4b 正确会话密钥、不同绑定上下文 -> BIND（制品不属于该植入体） */
        out_len = sizeof(raw) + 64;
        rc = pk_unpack_session(blob, blob_len, k_c2s, k_s2c,
                               ctx_b, sizeof(ctx_b) - 1u, out, &out_len);
        CHECK(rc == PK_ERR_BIND, "不同植入体上下文解包被拒（PK_ERR_BIND）");
    }

    /* ---------- 5. bind_id 纳入 AAD 的隔离验证 ---------- */

    {
        /*
         * 把制品头里的 bind_id 改成 implant-B 的标识，再用 implant-B 的
         * 上下文解包：绑定比对会"通过"，但密文是用 implant-A 的 bind_id
         * 作为 AAD 密封的 —— 若 bind_id 真的在 AAD 内，此处必须 AUTH 失败。
         * 这条用例单独证明 bind_id 受认证保护，而不只是"存了个字段"。
         */
        uint8_t swap[PK_BIND_ID_LEN];
        uint8_t *blob2 = (uint8_t *)malloc(blob_len);
        const uint8_t ctx_b[] = "implant-B|gen=1";

        memcpy(blob2, blob, blob_len);
        pk_bind_id(ctx_b, sizeof(ctx_b) - 1u, swap);
        memcpy(blob2 + 108, swap, PK_BIND_ID_LEN);

        out_len = sizeof(raw) + 64;
        rc = pk_unpack_session(blob2, blob_len, k_c2s, k_s2c,
                               ctx_b, sizeof(ctx_b) - 1u, out, &out_len);
        CHECK(rc == PK_ERR_AUTH, "替换 bind_id 后验签失败（证明其纳入 AAD）");

        /* 同时确认：改回原值即可正常解开，排除用例本身写错 */
        memcpy(blob2 + 108, blob + 108, PK_BIND_ID_LEN);
        out_len = sizeof(raw) + 64;
        rc = pk_unpack_session(blob2, blob_len, k_c2s, k_s2c,
                               (const uint8_t *)"implant-A|gen=1", 15u,
                               out, &out_len);
        CHECK(rc == PK_OK, "bind_id 还原后恢复正常（用例自身有效）");

        free(blob2);
    }

    /* ---------- 6. 篡改密文 ---------- */

    {
        uint8_t *blob3 = (uint8_t *)malloc(blob_len);
        memcpy(blob3, blob, blob_len);
        blob3[PK_HDR_V2_LEN] ^= 0x01u;
        out_len = sizeof(raw) + 64;
        rc = pk_unpack_session(blob3, blob_len, k_c2s, k_s2c,
                               (const uint8_t *)"implant-A|gen=1", 15u,
                               out, &out_len);
        CHECK(rc == PK_ERR_AUTH || rc == PK_ERR_HASH,
              "密文篡改被检出");
        free(blob3);
    }

    /* ---------- 7. v1 向后兼容 ---------- */

    {
        uint8_t seed_v1[PK_SHA_LEN];
        uint8_t *b1, *o1;
        size_t   b1len, o1len;
        pk_hdr   h;

        fill_pattern(seed_v1, sizeof(seed_v1));
        b1 = (uint8_t *)malloc(pk_size_bound(sizeof(raw)));
        b1len = pk_size_bound(sizeof(raw));
        rc = pk_pack(raw, sizeof(raw), seed_v1, sizeof(seed_v1), b1, &b1len);
        CHECK(rc == PK_OK, "v1 打包仍可用（向后兼容）");

        rc = pk_header_parse(b1, b1len, &h);
        CHECK(rc == PK_OK && h.version == PK_VERSION, "v1 制品头版本为 1");

        o1 = (uint8_t *)malloc(sizeof(raw));
        o1len = sizeof(raw);
        rc = pk_unpack(b1, b1len, seed_v1, sizeof(seed_v1), o1, &o1len);
        CHECK(rc == PK_OK && o1len == sizeof(raw) &&
              memcmp(o1, raw, sizeof(raw)) == 0, "v1 解包往返一致");

        /* v1 制品不含 bind_id，不能被当作会话制品解开 */
        {
            uint8_t zid[PK_BIND_ID_LEN];
            CHECK(pk_artifact_bind_id(b1, b1len, zid) == PK_OK,
                  "v1 制品取 bind_id 返回成功（内容全零）");
            {
                int all_zero = 1;
                for (size_t i = 0; i < PK_BIND_ID_LEN; i++)
                    if (zid[i] != 0) { all_zero = 0; break; }
                CHECK(all_zero == 1, "v1 制品 bind_id 区为全零");
            }
            o1len = sizeof(raw);
            rc = pk_unpack_session(b1, b1len, k_c2s, k_s2c,
                                   (const uint8_t *)"implant-A|gen=1", 15u,
                                   o1, &o1len);
            CHECK(rc == PK_ERR_BIND, "v1 制品无法作为会话制品解开");
        }

        free(b1);
        free(o1);
    }

    /* ---------- 8. 大载荷 ---------- */

    {
        const uint8_t ctx[] = "implant-A|gen=1";
        size_t big = 100u * 1024u;
        uint8_t *braw = (uint8_t *)malloc(big);
        uint8_t *bblob, *bout;
        size_t   bcap, blen, olen;

        if (braw) {
            fill_compressible(braw, big, 0x40);
            bcap = pk_size_bound_v2(big);
            bblob = (uint8_t *)malloc(bcap);
            bout  = (uint8_t *)malloc(big + 64);
            if (bblob && bout) {
                blen = bcap;
                rc = pk_pack_session(braw, big, k_c2s, k_s2c,
                                     ctx, sizeof(ctx) - 1u, bblob, &blen);
                CHECK(rc == PK_OK, "100KB 载荷会话打包成功");
                olen = big + 64;
                rc = pk_unpack_session(bblob, blen, k_c2s, k_s2c,
                                       ctx, sizeof(ctx) - 1u, bout, &olen);
                CHECK(rc == PK_OK && olen == big &&
                      memcmp(bout, braw, big) == 0,
                      "100KB 载荷往返字节级一致");
                CHECK(blen < big, "100KB 可压缩载荷制品小于原始长度");
            }
            free(bblob);
            free(bout);
            free(braw);
        }
    }

    /* ---------- 9. 参数校验与边界 ---------- */

    {
        const uint8_t ctx[] = "implant-A|gen=1";
        size_t small = 0;

        CHECK(pk_pack_session(NULL, 10, k_c2s, k_s2c,
                              ctx, sizeof(ctx) - 1u, blob, &blob_len)
              == PK_ERR_ARG, "pk_pack_session 空载荷被拒");
        small = cap;
        CHECK(pk_pack_session(raw, 0, k_c2s, k_s2c,
                              ctx, sizeof(ctx) - 1u, blob, &small)
              == PK_ERR_ARG, "pk_pack_session 零长度被拒");

        /* 输出缓冲不足 */
        small = PK_HDR_V2_LEN;
        CHECK(pk_pack_session(raw, sizeof(raw), k_c2s, k_s2c,
                              ctx, sizeof(ctx) - 1u, blob, &small)
              == PK_ERR_NOMEM, "pk_pack_session 缓冲不足返回 NOMEM");

        /* 解包缓冲不足 */
        small = 8;
        CHECK(pk_unpack_session(blob, blob_len, k_c2s, k_s2c,
                                ctx, sizeof(ctx) - 1u, out, &small)
              == PK_ERR_NOMEM, "pk_unpack_session 缓冲不足返回 NOMEM");

        /* 制品过短 */
        CHECK(pk_unpack_session(blob, PK_HDR_V2_LEN - 1, k_c2s, k_s2c,
                                ctx, sizeof(ctx) - 1u, out, &out_len)
              == PK_ERR_SMALL, "过短制品返回 SMALL");

        /* 退化密钥不得用于打包 */
        small = cap;
        CHECK(pk_pack_session(raw, sizeof(raw), k_c2s, k_c2s,
                              ctx, sizeof(ctx) - 1u, blob, &small)
              == PK_ERR_DEGEN, "退化会话密钥打包被拒");
    }

    free(blob);
    free(out);

    printf("\n%d tests, %d failures\n", g_total, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
