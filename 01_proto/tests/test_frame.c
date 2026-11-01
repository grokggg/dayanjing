#include "frame.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 测试需要手工构造 header，内联一份与 frame.c 一致的字节序工具 */
static void t_put_u32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}
static void t_put_u16_le(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
}

static int g_pass;
static int g_fail;
static int g_total;

#define RUN(name, expr) do {                                             \
    g_total++;                                                           \
    int _r = (expr);                                                     \
    if (_r == 0) { g_pass++; printf("  [PASS] %s\n", name); }            \
    else { g_fail++; printf("  [FAIL] %s  (err=%d)\n", name, _r); }      \
} while (0)

#define EXPECT_EQ(name, a, b) do {                                       \
    g_total++;                                                           \
    long _a = (long)(a), _b = (long)(b);                                 \
    if (_a == _b) { g_pass++; printf("  [PASS] %s  (%ld)\n", name, _a); } \
    else { g_fail++; printf("  [FAIL] %s  got=%ld want=%ld\n", name, _a, _b); } \
} while (0)

/* ---------- 1. 字段往返 ---------- */

static int test_roundtrip_empty(void)
{
    struct frame f;
    frame_init(&f);

    uint8_t buf[64];
    int n = frame_pack(&f, buf, sizeof(buf));
    if (n != FRAME_MIN_SIZE) return -100;

    struct frame g;
    frame_init(&g);
    int m = frame_unpack(&g, buf, (size_t)n);
    if (m != n) return -101;

    int rc = 0;
    if (g.hdr.magic != FRAME_MAGIC)        rc = -102;
    else if (g.hdr.version != FRAME_VERSION) rc = -103;
    else if (g.hdr.payload_len != 0)        rc = -104;
    else if (g.payload != NULL)             rc = -105;

    frame_fini(&g);
    frame_fini(&f);
    return rc;
}

static int test_roundtrip_payload(void)
{
    struct frame f;
    frame_init(&f);

    const char *msg = "hello dayanjing protocol";
    int rc = frame_set_payload(&f, (const uint8_t *)msg, strlen(msg));
    if (rc != FRAME_OK) return -110;

    size_t need = FRAME_MIN_SIZE + strlen(msg);
    uint8_t *buf = malloc(need);
    if (!buf) return -111;
    int n = frame_pack(&f, buf, need);
    if (n != (int)need) { free(buf); return -112; }

    struct frame g;
    frame_init(&g);
    int m = frame_unpack(&g, buf, (size_t)n);
    if (m != (int)need) { free(buf); frame_fini(&g); return -113; }

    rc = 0;
    if (g.hdr.payload_len != strlen(msg))               rc = -114;
    else if (!g.payload)                                rc = -115;
    else if (memcmp(g.payload, msg, strlen(msg)) != 0)  rc = -116;

    free(buf);
    frame_fini(&g);
    frame_fini(&f);
    return rc;
}

/* ---------- 2. CRC 完整性 ---------- */

static int test_crc_tamper(void)
{
    struct frame f;
    frame_init(&f);
    const uint8_t body[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    frame_set_payload(&f, body, sizeof(body));

    size_t need = FRAME_MIN_SIZE + sizeof(body);
    uint8_t *buf = malloc(need);
    frame_pack(&f, buf, need);

    /* 篡改 payload 中一个字节，重算/校验应失败 */
    buf[FRAME_HDR_SIZE + 2] ^= 0x01;

    struct frame g;
    frame_init(&g);
    int m = frame_unpack(&g, buf, need);
    free(buf);
    if (m != FRAME_ERR_CRC) { frame_fini(&g); frame_fini(&f); return -120; }

    frame_fini(&g);
    frame_fini(&f);
    return FRAME_OK;
}

static int test_crc_clean(void)
{
    struct frame f;
    frame_init(&f);
    const uint8_t body[] = {0xde, 0xad, 0xbe, 0xef};
    frame_set_payload(&f, body, sizeof(body));

    size_t need = FRAME_MIN_SIZE + sizeof(body);
    uint8_t *buf = malloc(need);
    frame_pack(&f, buf, need);

    struct frame g;
    frame_init(&g);
    int m = frame_unpack(&g, buf, need);
    free(buf);
    if (m != (int)need) { frame_fini(&g); frame_fini(&f); return -130; }

    int rc = frame_verify_crc(&g);
    frame_fini(&g);
    frame_fini(&f);
    return rc;   /* FRAME_OK if good */
}

/* ---------- 3. 截断 / 边界 ---------- */

static int test_trunc_too_short(void)
{
    struct frame f;
    frame_init(&f);
    /* 只给 10 字节，不足 FRAME_MIN_SIZE(16) */
    uint8_t buf[10] = {0};
    int r = frame_unpack(&f, buf, sizeof(buf));
    frame_fini(&f);
    return (r == FRAME_ERR_TRUNC) ? FRAME_OK : -140;
}

static int test_trunc_declared_long(void)
{
    /* 构造一个 header 声明 payload_len 很大，但 buf 很短 */
    uint8_t buf[FRAME_HDR_SIZE + 4];
    t_put_u32_le(buf + 0, FRAME_MAGIC);
    buf[4] = FRAME_VERSION;
    buf[5] = 0;
    t_put_u16_le(buf + 6, 0);
    t_put_u32_le(buf + 8, 0x100000u);   /* 1 MiB 声明，远大于 buf */

    struct frame f;
    frame_init(&f);
    int r = frame_unpack(&f, buf, sizeof(buf));
    frame_fini(&f);
    return (r == FRAME_ERR_TRUNC) ? FRAME_OK : -150;
}

static int test_toobig(void)
{
    struct frame f;
    frame_init(&f);
    /* 构造声明 payload_len = FRAME_MAX_PAYLOAD + 1 的 header */
    uint8_t buf[FRAME_HDR_SIZE + 4];
    t_put_u32_le(buf + 0, FRAME_MAGIC);
    buf[4] = FRAME_VERSION;
    buf[5] = 0;
    t_put_u16_le(buf + 6, 0);
    t_put_u32_le(buf + 8, FRAME_MAX_PAYLOAD + 1u);

    struct frame g;
    frame_init(&g);
    int r = frame_unpack(&g, buf, sizeof(buf));
    frame_fini(&g);
    frame_fini(&f);
    return (r == FRAME_ERR_TOOBIG) ? FRAME_OK : -160;
}

/* ---------- 4. magic 错误 ---------- */

static int test_bad_magic(void)
{
    uint8_t buf[FRAME_MIN_SIZE];
    memset(buf, 0, sizeof(buf));   /* magic = 0，错误 */
    t_put_u32_le(buf + 8, 0);

    struct frame f;
    frame_init(&f);
    int r = frame_unpack(&f, buf, sizeof(buf));
    frame_fini(&f);
    return (r == FRAME_ERR_FORMAT) ? FRAME_OK : -170;
}

/* ---------- 5. 大 payload 往返 ---------- */

static int test_large_payload(void)
{
    struct frame f;
    frame_init(&f);

    const size_t N = 65536;   /* 64 KiB */
    uint8_t *body = malloc(N);
    if (!body) return -180;
    for (size_t i = 0; i < N; i++) body[i] = (uint8_t)(i & 0xFF);

    int rc = frame_set_payload(&f, body, N);
    if (rc != FRAME_OK) { free(body); return -181; }

    size_t need = FRAME_MIN_SIZE + N;
    uint8_t *buf = malloc(need);
    if (!buf) { free(body); return -182; }
    int n = frame_pack(&f, buf, need);
    if (n != (int)need) { free(buf); free(body); return -183; }

    struct frame g;
    frame_init(&g);
    int m = frame_unpack(&g, buf, need);
    if (m != (int)need) { free(buf); free(body); frame_fini(&g); return -184; }

    rc = 0;
    if (g.hdr.payload_len != N)                       rc = -185;
    else if (!g.payload || memcmp(g.payload, body, N)) rc = -186;

    free(buf);
    free(body);
    frame_fini(&g);
    frame_fini(&f);
    return rc;
}

/* ---------- main ---------- */

int main(void)
{
    printf("frame unit tests\n");
    printf("===============\n");

    printf("[1] 字段往返\n");
    RUN("roundtrip_empty", test_roundtrip_empty());
    RUN("roundtrip_payload", test_roundtrip_payload());

    printf("[2] CRC 完整性\n");
    RUN("crc_tamper_rejected", test_crc_tamper());
    RUN("crc_clean_accepted", test_crc_clean());

    printf("[3] 截断与边界\n");
    RUN("trunc_too_short", test_trunc_too_short());
    RUN("trunc_declared_long", test_trunc_declared_long());
    RUN("toobig_rejected", test_toobig());

    printf("[4] magic 校验\n");
    RUN("bad_magic_rejected", test_bad_magic());

    printf("[5] 大 payload\n");
    RUN("large_64k_roundtrip", test_large_payload());

    printf("===============\n");
    printf("total=%d  pass=%d  fail=%d\n", g_total, g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
