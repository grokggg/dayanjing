/*
 * DAYANJING v4 — 20_packer / tests/test_shaped.c
 *
 * v4 多态头制品测试。
 *
 * 本文件最重要的一组用例是"跨构建逐字节取证"：生成 N 份制品，逐偏移统计
 * 取值种类数，恒定偏移（种类数 == 1）即静态签名。
 *
 * 为什么必须同时跑 v3 对照：
 *   若取证程序对 v3 也报"恒定偏移 0"，说明它根本没在测东西——v3 的前 12
 *   字节是写死的 magic + version，恒定偏移至少 12。这条反证是对取证方法
 *   本身的校准，缺了它，"v4 恒定偏移 0" 这个结论毫无意义。
 */

#include "packer.h"
#include "pack_int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int pass_cnt = 0;
static int fail_cnt = 0;

#define PASS(fmt, ...) do {                                  \
    printf("[PASS] " fmt "\n", ##__VA_ARGS__);               \
    pass_cnt++;                                              \
} while (0)

#define FAIL(fmt, ...) do {                                  \
    printf("[FAIL] " fmt "\n", ##__VA_ARGS__);               \
    fail_cnt++;                                              \
} while (0)

#define CHECK(cond, fmt, ...) do {                           \
    if (cond) PASS(fmt, ##__VA_ARGS__);                      \
    else      FAIL(fmt, ##__VA_ARGS__);                      \
} while (0)

/* ---- 取证参数 ---- */
#define NART      200          /* 每组制品份数 */
#define ART_CAP   8192         /* 单份制品缓冲 */
#define RAW_LEN   256          /* 固定载荷长度 */

static uint8_t arts[NART][ART_CAP];
static size_t  art_lens[NART];

/* 某偏移上的取值种类数（值域 0..255，用 256 位掩码统计） */
static int distinct_at(size_t off, int n)
{
    uint32_t seen[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    int      cnt = 0;
    int      k;

    for (k = 0; k < n; k++) {
        uint8_t v = arts[k][off];
        if (!(seen[v >> 5] & (1u << (v & 31u)))) {
            seen[v >> 5] |= (1u << (v & 31u));
            cnt++;
        }
    }
    return cnt;
}

/* 恒定偏移计数（种类数 == 1），并给出最小长度 */
static size_t constant_offsets(int n, size_t *min_len, size_t *first_const)
{
    size_t i, mn = (size_t)-1, cnt = 0;

    for (i = 0; i < (size_t)n; i++)
        if (art_lens[i] < mn) mn = art_lens[i];

    *min_len = mn;
    *first_const = (size_t)-1;
    for (i = 0; i < mn; i++) {
        if (distinct_at(i, n) <= 1) {
            if (*first_const == (size_t)-1) *first_const = i;
            cnt++;
        }
    }
    return cnt;
}

static void fill_raw(uint8_t *buf, size_t len, uint64_t seed)
{
    size_t i;
    /* 可压缩模式：大量重复，确保压缩分支生效 */
    for (i = 0; i < len; i++)
        buf[i] = (uint8_t)(((i % 37u) + (seed & 0xffu)) & 0xffu);
}

/* ====================================================================
 * 基础：往返
 * ==================================================================== */

static void t_roundtrip(void)
{
    uint8_t  raw[RAW_LEN];
    uint8_t  seed[PK_SHA_LEN];
    uint8_t  bind_id[PK_BIND_ID_LEN];
    uint8_t  eph_pub[PK_EPH_PUB_LEN];
    uint8_t  blob[ART_CAP];
    uint8_t  out[ART_CAP];
    size_t   bl = sizeof(blob), ol = sizeof(out);
    int      rc;

    fill_raw(raw, sizeof(raw), 1);
    memset(seed, 0x5a, sizeof(seed));
    memset(bind_id, 0x11, sizeof(bind_id));
    memset(eph_pub, 0x22, sizeof(eph_pub));

    rc = pk_pack_shaped(raw, sizeof(raw), seed, sizeof(seed),
                        bind_id, 7u, eph_pub, blob, &bl);
    CHECK(rc == PK_OK, "打包 v4 制品 rc=%d", rc);

    rc = pk_unpack_shaped(blob, bl, seed, sizeof(seed), out, &ol);
    CHECK(rc == PK_OK, "解包 v4 制品 rc=%d", rc);
    CHECK(ol == sizeof(raw) && memcmp(out, raw, sizeof(raw)) == 0,
          "往返字节级一致（ol=%zu）", ol);

    CHECK(bl >= PK_SHAPED_OVERHEAD, "制品长度不小于固定开销 bl=%zu", bl);
}

static void t_big_payload(void)
{
    uint8_t *raw, *blob, *out;
    size_t   raw_len = 100000, bl, ol;
    uint8_t  seed[PK_SHA_LEN], bind_id[PK_BIND_ID_LEN], eph_pub[PK_EPH_PUB_LEN];
    int      rc;

    raw  = (uint8_t *)malloc(raw_len);
    blob = (uint8_t *)malloc(pk_size_bound_v4(raw_len));
    out  = (uint8_t *)malloc(raw_len);
    if (!raw || !blob || !out) { FAIL("分配失败 raw_len=%zu", raw_len); return; }

    fill_raw(raw, raw_len, 3);
    memset(seed, 0x77, sizeof(seed));
    memset(bind_id, 0x33, sizeof(bind_id));
    memset(eph_pub, 0x44, sizeof(eph_pub));

    bl = pk_size_bound_v4(raw_len);
    rc = pk_pack_shaped(raw, raw_len, seed, sizeof(seed),
                        bind_id, 1u, eph_pub, blob, &bl);
    CHECK(rc == PK_OK, "大载荷打包 rc=%d", rc);

    ol = raw_len;
    rc = pk_unpack_shaped(blob, bl, seed, sizeof(seed), out, &ol);
    CHECK(rc == PK_OK, "大载荷解包 rc=%d", rc);
    CHECK(ol == raw_len && memcmp(out, raw, raw_len) == 0,
          "大载荷往返字节级一致（bl=%zu，压缩生效则远小于载荷）", bl);
    CHECK(bl < raw_len, "10 万字节载荷压缩后制品 %zu 字节（确认压缩分支生效）", bl);

    free(raw); free(blob); free(out);
}

/* ====================================================================
 * 核心取证：跨构建恒定字节
 * ==================================================================== */

/* 组 A：同一 raw、同一 seed，仅 nonce 随机 —— 最严格的情形。
   若掩码未把 nonce 纳入派生，头里的 magic/version/bind_id/epoch 会直接暴露。 */
static void t_forensics_same_seed(void)
{
    uint8_t raw[RAW_LEN];
    uint8_t seed[PK_SHA_LEN], bind_id[PK_BIND_ID_LEN], eph_pub[PK_EPH_PUB_LEN];
    size_t  min_len = 0, first_const = 0, nconst;
    int     i;

    fill_raw(raw, sizeof(raw), 9);
    memset(seed, 0xa5, sizeof(seed));
    memset(bind_id, 0x66, sizeof(bind_id));    /* 同一植入体：bind_id 恒定 */
    memset(eph_pub, 0x77, sizeof(eph_pub));

    for (i = 0; i < NART; i++) {
        size_t bl = ART_CAP;
        int rc = pk_pack_shaped(raw, sizeof(raw), seed, sizeof(seed),
                                bind_id, 42u, eph_pub, arts[i], &bl);
        if (rc != PK_OK) { FAIL("取证组A 第 %d 份打包失败 rc=%d", i, rc); return; }
        art_lens[i] = bl;
    }

    nconst = constant_offsets(NART, &min_len, &first_const);
    CHECK(nconst == 0,
          "同 seed 同载荷 %d 份：恒定偏移 %zu 个（前 %zu 字节）",
          NART, nconst, min_len);
    if (nconst != 0)
        printf("       首个恒定偏移 = %zu\n", first_const);
}

/* 组 B：同一 raw、不同 seed */
static void t_forensics_diff_seed(void)
{
    uint8_t raw[RAW_LEN];
    uint8_t bind_id[PK_BIND_ID_LEN], eph_pub[PK_EPH_PUB_LEN];
    size_t  min_len = 0, first_const = 0, nconst;
    int     i;

    fill_raw(raw, sizeof(raw), 11);
    memset(bind_id, 0x88, sizeof(bind_id));
    memset(eph_pub, 0x99, sizeof(eph_pub));

    for (i = 0; i < NART; i++) {
        uint8_t seed[PK_SHA_LEN];
        size_t  bl = ART_CAP;
        int     rc;
        memset(seed, (uint8_t)(i * 7 + 1), sizeof(seed));
        rc = pk_pack_shaped(raw, sizeof(raw), seed, sizeof(seed),
                            bind_id, (uint32_t)i, eph_pub, arts[i], &bl);
        if (rc != PK_OK) { FAIL("取证组B 第 %d 份打包失败 rc=%d", i, rc); return; }
        art_lens[i] = bl;
    }

    nconst = constant_offsets(NART, &min_len, &first_const);
    CHECK(nconst == 0,
          "异 seed %d 份：恒定偏移 %zu 个（前 %zu 字节）",
          NART, nconst, min_len);
}

/* 反证：同一套取证程序跑 v3，必须测出恒定偏移。
   否则说明取证方法失效，"v4 = 0" 是假结论。 */
static void t_forensics_v3_control(void)
{
    uint8_t raw[RAW_LEN];
    uint8_t seed[PK_SHA_LEN], bind_id[PK_BIND_ID_LEN], eph_pub[PK_EPH_PUB_LEN];
    size_t  min_len = 0, first_const = 0, nconst;
    int     i;

    fill_raw(raw, sizeof(raw), 13);
    memset(seed, 0x3c, sizeof(seed));
    memset(bind_id, 0x55, sizeof(bind_id));
    memset(eph_pub, 0x66, sizeof(eph_pub));

    for (i = 0; i < NART; i++) {
        size_t bl = ART_CAP;
        int rc = pk_pack_core(raw, sizeof(raw), seed, sizeof(seed),
                              PK_VERSION3, bind_id, 42u, eph_pub,
                              arts[i], &bl);
        if (rc != PK_OK) { FAIL("v3 对照第 %d 份打包失败 rc=%d", i, rc); return; }
        art_lens[i] = bl;
    }

    nconst = constant_offsets(NART, &min_len, &first_const);
    CHECK(nconst >= 12,
          "v3 对照：恒定偏移 %zu 个（应 >= 12，证明取证方法有效）", nconst);
    printf("[INFO] v3 首个恒定偏移 = %zu（即 magic 起始处）\n", first_const);
}

/* 制品里搜不到 magic 明文 */
static void t_no_magic_in_blob(void)
{
    uint8_t raw[RAW_LEN];
    uint8_t seed[PK_SHA_LEN], bind_id[PK_BIND_ID_LEN], eph_pub[PK_EPH_PUB_LEN];
    int     i, hits = 0;
    const uint8_t want[4] = { 'D', 'J', 'P', 'A' };

    fill_raw(raw, sizeof(raw), 17);
    memset(seed, 0x9e, sizeof(seed));
    memset(bind_id, 0xaa, sizeof(bind_id));
    memset(eph_pub, 0xbb, sizeof(eph_pub));

    for (i = 0; i < NART; i++) {
        size_t bl = ART_CAP, j;
        int rc = pk_pack_shaped(raw, sizeof(raw), seed, sizeof(seed),
                                bind_id, 3u, eph_pub, arts[i], &bl);
        if (rc != PK_OK) { FAIL("magic 扫描第 %d 份打包失败", i); return; }
        for (j = 0; j + 4 <= bl; j++)
            if (memcmp(arts[i] + j, want, 4) == 0) hits++;
    }
    CHECK(hits == 0, "%d 份制品中 'DJPA' 明文命中 %d 次", NART, hits);
}

/* nonce 必须每制品不同 */
static void t_nonce_unique(void)
{
    uint8_t raw[RAW_LEN];
    uint8_t seed[PK_SHA_LEN], bind_id[PK_BIND_ID_LEN], eph_pub[PK_EPH_PUB_LEN];
    int     i, dup = 0;

    fill_raw(raw, sizeof(raw), 19);
    memset(seed, 0x1f, sizeof(seed));
    memset(bind_id, 0xcc, sizeof(bind_id));
    memset(eph_pub, 0xdd, sizeof(eph_pub));

    for (i = 0; i < NART; i++) {
        size_t bl = ART_CAP;
        int rc = pk_pack_shaped(raw, sizeof(raw), seed, sizeof(seed),
                                bind_id, 5u, eph_pub, arts[i], &bl);
        if (rc != PK_OK) { FAIL("nonce 组第 %d 份打包失败 rc=%d", i, rc); return; }
        art_lens[i] = bl;
    }
    for (i = 1; i < NART; i++)
        if (memcmp(arts[i], arts[0], PK_NONCE_LEN) == 0) dup++;

    CHECK(dup == 0, "%d 份制品 nonce 重复 %d 次（重复即掩码退化）", NART, dup);
}

/* 关键位置必须逐制品变化（同 seed 下同 implant 的 bind_id 恒定） */
static void t_key_positions_vary(void)
{
    uint8_t raw[RAW_LEN];
    uint8_t seed[PK_SHA_LEN], bind_id[PK_BIND_ID_LEN], eph_pub[PK_EPH_PUB_LEN];
    size_t  min_len = 0, first_const = 0;
    int     i;

    fill_raw(raw, sizeof(raw), 23);
    memset(seed, 0x42, sizeof(seed));
    memset(bind_id, 0x77, sizeof(bind_id));   /* 同一植入体 */
    memset(eph_pub, 0x88, sizeof(eph_pub));

    for (i = 0; i < NART; i++) {
        size_t bl = ART_CAP;
        int rc = pk_pack_shaped(raw, sizeof(raw), seed, sizeof(seed),
                                bind_id, 9u, eph_pub, arts[i], &bl);
        if (rc != PK_OK) { FAIL("关键位置组第 %d 份打包失败 rc=%d", i, rc); return; }
        art_lens[i] = bl;
    }
    (void)constant_offsets(NART, &min_len, &first_const);

    /* v4 头 = nonce(16) + 掩码头(176)；magic 在头内偏移 0 -> 制品偏移 16 */
    CHECK(distinct_at(PK_NONCE_LEN + 0, NART) > 1,
          "原 magic 位置（偏移 %d）：取值种类 %d",
          PK_NONCE_LEN, distinct_at(PK_NONCE_LEN, NART));
    CHECK(distinct_at(PK_NONCE_LEN + 8, NART) > 1,
          "原 version 位置（偏移 %d）：取值种类 %d",
          PK_NONCE_LEN + 8, distinct_at(PK_NONCE_LEN + 8, NART));
    CHECK(distinct_at(PK_NONCE_LEN + 108, NART) > 1,
          "bind_id 位置（偏移 %d，同 implant 恒定值）：取值种类 %d",
          PK_NONCE_LEN + 108, distinct_at(PK_NONCE_LEN + 108, NART));
    CHECK(distinct_at(PK_NONCE_LEN + 140, NART) > 1,
          "epoch 位置（偏移 %d，同为 9）：取值种类 %d",
          PK_NONCE_LEN + 140, distinct_at(PK_NONCE_LEN + 140, NART));
}

/* ====================================================================
 * 篡改 / 错误密钥
 * ==================================================================== */

static void make_one(uint8_t *blob, size_t *bl,
                     uint8_t seed[PK_SHA_LEN],
                     uint8_t bind_id[PK_BIND_ID_LEN])
{
    uint8_t raw[RAW_LEN];
    uint8_t eph_pub[PK_EPH_PUB_LEN];

    fill_raw(raw, sizeof(raw), 29);
    memset(seed, 0x6d, PK_SHA_LEN);
    memset(bind_id, 0xe1, PK_BIND_ID_LEN);
    memset(eph_pub, 0xe2, PK_EPH_PUB_LEN);
    *bl = ART_CAP;
    pk_pack_shaped(raw, sizeof(raw), seed, PK_SHA_LEN,
                   bind_id, 11u, eph_pub, blob, bl);
}

static void t_tamper(void)
{
    uint8_t blob[ART_CAP], out[ART_CAP];
    uint8_t seed[PK_SHA_LEN], bind_id[PK_BIND_ID_LEN];
    size_t  bl, ol;
    int     rc;

    make_one(blob, &bl, seed, bind_id);

    /* 1. nonce */
    {
        uint8_t b[ART_CAP]; size_t l = bl;
        memcpy(b, blob, bl);
        b[0] ^= 0x01;
        ol = sizeof(out);
        rc = pk_unpack_shaped(b, l, seed, sizeof(seed), out, &ol);
        CHECK(rc == PK_ERR_AUTH, "改 nonce -> AUTH（rc=%d）", rc);
    }
    /* 2. 掩码头 */
    {
        uint8_t b[ART_CAP]; size_t l = bl;
        memcpy(b, blob, bl);
        b[PK_NONCE_LEN + 40] ^= 0x80;
        ol = sizeof(out);
        rc = pk_unpack_shaped(b, l, seed, sizeof(seed), out, &ol);
        CHECK(rc == PK_ERR_AUTH, "改掩码头 -> AUTH（rc=%d）", rc);
    }
    /* 3. 密文 */
    {
        uint8_t b[ART_CAP]; size_t l = bl;
        memcpy(b, blob, bl);
        b[PK_HDR_V4_LEN + 5] ^= 0x40;
        ol = sizeof(out);
        rc = pk_unpack_shaped(b, l, seed, sizeof(seed), out, &ol);
        CHECK(rc == PK_ERR_AUTH, "改密文 -> AUTH（rc=%d）", rc);
    }
    /* 4. tag */
    {
        uint8_t b[ART_CAP]; size_t l = bl;
        memcpy(b, blob, bl);
        b[l - 1] ^= 0x20;
        ol = sizeof(out);
        rc = pk_unpack_shaped(b, l, seed, sizeof(seed), out, &ol);
        CHECK(rc == PK_ERR_AUTH, "改 tag -> AUTH（rc=%d）", rc);
    }
    /* 5. 错误密钥：不得泄露 MAGIC / VERSION / LEN */
    {
        uint8_t bad[PK_SHA_LEN];
        memset(bad, 0x00, sizeof(bad));
        ol = sizeof(out);
        rc = pk_unpack_shaped(blob, bl, bad, sizeof(bad), out, &ol);
        CHECK(rc == PK_ERR_AUTH,
              "错误密钥 -> AUTH（rc=%d，不得为 MAGIC/VERSION/LEN）", rc);
    }
    /* 6. 截断 */
    {
        uint8_t b[ART_CAP]; size_t l = bl - 1;
        memcpy(b, blob, l);
        ol = sizeof(out);
        rc = pk_unpack_shaped(b, l, seed, sizeof(seed), out, &ol);
        CHECK(rc != PK_OK, "截断 1 字节 -> 非 OK（rc=%d）", rc);
    }
}

static void t_edges(void)
{
    uint8_t blob[ART_CAP], out[ART_CAP];
    uint8_t seed[PK_SHA_LEN], bind_id[PK_BIND_ID_LEN], eph_pub[PK_EPH_PUB_LEN];
    uint8_t raw[64];
    size_t  bl, ol;
    int     rc;

    fill_raw(raw, sizeof(raw), 31);
    memset(seed, 0x2b, sizeof(seed));
    memset(bind_id, 0xf1, sizeof(bind_id));
    memset(eph_pub, 0xf2, sizeof(eph_pub));

    /* 过短 */
    bl = ART_CAP;
    rc = pk_pack_shaped(raw, sizeof(raw), seed, sizeof(seed),
                        bind_id, 0u, eph_pub, blob, &bl);
    CHECK(rc == PK_OK, "边界基线打包 rc=%d", rc);

    ol = sizeof(out);
    rc = pk_unpack_shaped(blob, PK_SHAPED_OVERHEAD - 1, seed, sizeof(seed),
                          out, &ol);
    CHECK(rc == PK_ERR_SMALL, "制品短于开销 -> SMALL（rc=%d）", rc);

    /* 空载荷：用独立长度变量，避免把基线 bl 冲掉后污染后续用例
       （pk_pack_shaped 在 ARG 路径上不改写 out_len） */
    {
        size_t bl0 = ART_CAP;
        rc = pk_pack_shaped(NULL, 0, seed, sizeof(seed),
                            bind_id, 0u, eph_pub, blob, &bl0);
        CHECK(rc == PK_ERR_ARG, "空载荷 -> ARG（rc=%d）", rc);
    }

    /* 输出缓冲不足 */
    ol = 8;
    rc = pk_unpack_shaped(blob, bl, seed, sizeof(seed), out, &ol);
    CHECK(rc == PK_ERR_NOMEM, "输出缓冲不足 -> NOMEM（rc=%d）", rc);

    /* 容量上界足够 */
    bl = pk_size_bound_v4(sizeof(raw));
    rc = pk_pack_shaped(raw, sizeof(raw), seed, sizeof(seed),
                        bind_id, 0u, eph_pub, blob, &bl);
    CHECK(rc == PK_OK, "按 size_bound_v4 分配即可打包（rc=%d）", rc);

    /* 同载荷两次打包 -> 制品不同 */
    {
        uint8_t b1[ART_CAP], b2[ART_CAP];
        size_t  l1 = ART_CAP, l2 = ART_CAP;
        pk_pack_shaped(raw, sizeof(raw), seed, sizeof(seed),
                       bind_id, 0u, eph_pub, b1, &l1);
        pk_pack_shaped(raw, sizeof(raw), seed, sizeof(seed),
                       bind_id, 0u, eph_pub, b2, &l2);
        CHECK(l1 == l2 && memcmp(b1, b2, l1) != 0,
              "同载荷两次打包 -> 长度相同但字节不同（l1=%zu）", l1);
    }
}

/* ====================================================================
 * O(1) 查询
 * ==================================================================== */

static void t_o1_queries(void)
{
    uint8_t blob[ART_CAP];
    uint8_t seed[PK_SHA_LEN], bind_id[PK_BIND_ID_LEN];
    size_t  bl;
    uint32_t epoch = 0;
    uint8_t  got_id[PK_BIND_ID_LEN];
    int      rc;

    make_one(blob, &bl, seed, bind_id);     /* epoch = 11 */

    rc = pk_shaped_epoch(blob, bl, seed, sizeof(seed), &epoch);
    CHECK(rc == PK_OK && epoch == 11u, "epoch O(1) 查询 rc=%d epoch=%u",
          rc, epoch);

    rc = pk_shaped_bind_id(blob, bl, seed, sizeof(seed), got_id);
    CHECK(rc == PK_OK && memcmp(got_id, bind_id, PK_BIND_ID_LEN) == 0,
          "bind_id O(1) 查询 rc=%d", rc);

    {
        uint8_t bad[PK_SHA_LEN];
        memset(bad, 0x11, sizeof(bad));
        epoch = 0;
        rc = pk_shaped_epoch(blob, bl, bad, sizeof(bad), &epoch);
        CHECK(rc != PK_OK, "错误密钥下 epoch 查询失败（rc=%d）", rc);
    }
}

int main(void)
{
    printf("=== test_shaped: v4 多态头制品 ===\n");

    t_roundtrip();
    t_big_payload();
    t_forensics_same_seed();
    t_forensics_diff_seed();
    t_forensics_v3_control();
    t_no_magic_in_blob();
    t_nonce_unique();
    t_key_positions_vary();
    t_tamper();
    t_edges();
    t_o1_queries();

    printf("=== result: %d pass, %d fail ===\n", pass_cnt, fail_cnt);
    return fail_cnt == 0 ? 0 : 1;
}
