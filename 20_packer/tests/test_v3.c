/*
 * DAYANJING v4 — 20_packer / test_v3.c
 *
 * v3 制品四项能力验证。每条都做成"反证"而非"走过场"：
 * 要证明的不是"正常路径能跑通"，而是"错误用法确实被拒绝"。
 */

#include "packer.h"

#include <stdio.h>
#include <string.h>

static int g_total = 0;
static int g_fail  = 0;

#define CHECK(cond, name) do {                                  \
    g_total++;                                                  \
    if (cond) { printf("[PASS] %s\n", (name)); }                \
    else { printf("[FAIL] %s  (line %d)\n", (name), __LINE__); g_fail++; } \
} while (0)

static const char *PAYLOAD = "DAYNJING-V3-ARTIFACT-PAYLOAD-0123456789ABCDEF";

static void fill_binding(pk_binding_t *b, const uint8_t *sid,
                         const char *impl, uint64_t gen, uint32_t epoch)
{
    memset(b, 0, sizeof(*b));
    b->version = PK_BINDING_VERSION;
    memcpy(b->server_static_id, sid, PK_SERVER_ID_LEN);
    snprintf(b->implant_id, sizeof(b->implant_id), "%s", impl);
    b->generation = gen;
    b->epoch = epoch;
}

/* ====================================================================
 * 一、规范化绑定上下文（限制 1）
 * ==================================================================== */

static void test_binding(void)
{
    uint8_t sid[PK_SERVER_ID_LEN];
    pk_binding_t b, b2;
    uint8_t e1[256];
    size_t  l1 = 0;
    int     rc;

    memset(sid, 0xA5, sizeof(sid));

    /* 往返一致 */
    fill_binding(&b, sid, "implant-alpha", 7u, 3u);
    rc = pk_binding_encode(&b, e1, sizeof(e1), &l1);
    CHECK(rc == PK_OK, "binding 编码成功");
    CHECK(l1 == 61u + strlen("implant-alpha"), "编码长度 = 61 + nid");

    rc = pk_binding_decode(e1, l1, &b2);
    CHECK(rc == PK_OK, "binding 解码成功");
    CHECK(memcmp(&b, &b2, sizeof(b)) == 0, "绑定往返结构一致");

    /* 单射性：这是 v2 缺失的核心性质。
     * ("AB","C") 与 ("A","BC") 在无长度前缀的朴素拼接下都会得到 "ABC"。 */
    {
        uint8_t sidA[PK_SERVER_ID_LEN], sidB[PK_SERVER_ID_LEN];
        uint8_t x1[256], x2[256];
        size_t  n1 = 0, n2 = 0;

        memset(sidA, 0x11, sizeof(sidA));
        memset(sidB, 0x22, sizeof(sidB));

        fill_binding(&b, sidA, "AB+CD", 1u, 0u);
        pk_binding_encode(&b, x1, sizeof(x1), &n1);
        fill_binding(&b, sidB, "AB+CD", 1u, 0u);
        pk_binding_encode(&b, x2, sizeof(x2), &n2);
        CHECK(memcmp(x1, x2, n1) != 0, "不同 server_static_id 编码不同");

        /* 更刁钻的一条：id 相同、implant 前缀/后缀错位 */
        fill_binding(&b, sidA, "AB", 1u, 0u);
        pk_binding_encode(&b, x1, sizeof(x1), &n1);
        fill_binding(&b, sidA, "A", 1u, 0u);
        pk_binding_encode(&b, x2, sizeof(x2), &n2);
        CHECK(memcmp(x1, x2, (n1 < n2 ? n1 : n2)) != 0,
              "implant 'AB' 与 'A' 编码不同（长度前缀生效）");
    }

    /* canonical 校验：尾部残留非零字节必须被拒 */
    {
        uint8_t bad[256];
        size_t  n = 0;
        fill_binding(&b, sid, "implant-alpha", 7u, 3u);
        pk_binding_encode(&b, bad, sizeof(bad), &n);
        bad[n] = 0x01;                      /* 在规范长度之后塞垃圾 */
        rc = pk_binding_decode(bad, n + 1u, &b2);
        CHECK(rc == PK_ERR_CANON, "尾部非零字节被判非规范编码");
    }

    /* implant_id 字符集 */
    {
        pk_binding_t bb;
        fill_binding(&bb, sid, "", 1u, 0u);
        CHECK(pk_binding_encode(&bb, e1, sizeof(e1), &l1) == PK_ERR_IMPLID,
              "空 implant_id 被拒");

        fill_binding(&bb, sid, "a/b", 1u, 0u);
        CHECK(pk_binding_encode(&bb, e1, sizeof(e1), &l1) == PK_ERR_IMPLID,
              "含 '/' 的 implant_id 被拒");

        fill_binding(&bb, sid, "a\\b", 1u, 0u);
        CHECK(pk_binding_encode(&bb, e1, sizeof(e1), &l1) == PK_ERR_IMPLID,
              "含 '\\\\' 的 implant_id 被拒");

        fill_binding(&bb, sid, "a:b", 1u, 0u);
        CHECK(pk_binding_encode(&bb, e1, sizeof(e1), &l1) == PK_ERR_IMPLID,
              "含 ':' 的 implant_id 被拒");

        fill_binding(&bb, sid, "..", 1u, 0u);
        CHECK(pk_binding_encode(&bb, e1, sizeof(e1), &l1) == PK_ERR_IMPLID,
              "'..' 被拒（路径穿越）");

        /* 超长 id 走 pk_binding_make：pk_binding_t 的定长缓冲会截断，
         * 因此"超长"只能在入口处被拦下，结构体层面已无超长可表达。 */
        {
            char longid[128];
            pk_binding_t lb;
            memset(longid, 'x', sizeof(longid));
            longid[PK_IMPLANT_ID_MAX + 1] = '\0';
            CHECK(pk_binding_make(sid, longid, 1u, 0u, &lb) == PK_ERR_IMPLID,
                  "超长 implant_id 被拒");
        }
    }

    /* 版本与探测 */
    {
        pk_binding_t bb;
        size_t probe = 0;
        fill_binding(&bb, sid, "implant-alpha", 7u, 3u);
        bb.version = 99u;
        CHECK(pk_binding_encode(&bb, e1, sizeof(e1), &l1) == PK_ERR_VERSION,
              "非法 binding version 被拒");

        fill_binding(&bb, sid, "implant-alpha", 7u, 3u);
        CHECK(pk_binding_encode(&bb, NULL, 0, &probe) == PK_OK && probe > 0,
              "out=NULL 时仅探测长度");
    }

    /* pk_binding_make 路径 */
    {
        pk_binding_t bb;
        CHECK(pk_binding_make(sid, "made-implant", 5u, 2u, &bb) == PK_OK,
              "pk_binding_make 成功");
        CHECK(pk_binding_make(sid, "bad/id", 5u, 2u, &bb) == PK_ERR_IMPLID,
              "pk_binding_make 拒绝非法 id");
    }
}

/* ====================================================================
 * 二、v1 废弃（限制 2）
 * ==================================================================== */

static void test_v1_retired(void)
{
    uint8_t  seed[PK_SHA_LEN];
    uint8_t  blob[4096];
    uint8_t  out[4096];
    size_t   bl = sizeof(blob), ol = sizeof(out);
    int      rc;

    memset(seed, 0x5A, sizeof(seed));

    rc = pk_pack((const uint8_t *)PAYLOAD, strlen(PAYLOAD),
                 seed, sizeof(seed), blob, &bl);
    CHECK(rc == PK_OK, "v1 打包仍可用于内部压测");

    {
        pk_hdr h;
        CHECK(pk_header_parse(blob, bl, &h) == PK_OK && h.version == PK_VERSION,
              "产出确实是 v1 制品");
    }

    /* 关键：v1 不再可解 —— 这是"v1 制品仍可独立使用"的终结 */
    rc = pk_unpack(blob, bl, seed, sizeof(seed), out, &ol);
    CHECK(rc == PK_ERR_VERSION, "v1 制品解包被拒（已废弃）");
    CHECK(strcmp(pk_errstr(rc), "unsupported or retired version (v1 deprecated)") == 0,
          "错误码语义明确");
}

/* ====================================================================
 * 三、纪元联动 与 四、前向保密（限制 3 / 4）
 * ==================================================================== */

static void test_epoch_and_pfs(void)
{
    uint8_t sid[PK_SERVER_ID_LEN];
    uint8_t k_c2s[PK_SESSION_KEY_LEN], k_s2c[PK_SESSION_KEY_LEN];
    uint8_t ipub[PK_IMPLANT_PK_LEN];
    uint8_t blob[8192], out[8192];
    size_t  bl = sizeof(blob), ol;
    pk_binding_t b;
    pk_implant_key_t ik;
    uint32_t ep = 0;
    int      rc;

    memset(sid, 0x3C, sizeof(sid));
    memset(k_c2s, 0x11, sizeof(k_c2s));
    memset(k_s2c, 0x22, sizeof(k_s2c));

    CHECK(pk_implant_key_init(&ik) == PK_OK, "植入体密钥初始化");
    CHECK(pk_implant_key_pub(&ik, ipub) == PK_OK, "取植入体静态公钥");
    CHECK(ik.n == 1 && ik.slots[0].epoch == 0u, "初始纪元为 0");

    fill_binding(&b, sid, "pfs-implant", 1u, 0u);

    /* --- 基本往返 --- */
    bl = sizeof(blob);
    rc = pk_pack_artifact((const uint8_t *)PAYLOAD, strlen(PAYLOAD), &b,
                          k_c2s, k_s2c, ipub, blob, &bl);
    CHECK(rc == PK_OK, "v3 打包成功");

    {
        uint32_t got_ep = 0xFFFFFFFFu;
        CHECK(pk_artifact_epoch(blob, bl, &got_ep) == PK_OK && got_ep == 0u,
              "制品头纪元可读且为 0");
    }

    ol = sizeof(out);
    rc = pk_unpack_artifact(blob, bl, &ik, &b, k_c2s, k_s2c, out, &ol);
    CHECK(rc == PK_OK, "v3 解包成功");
    CHECK(ol == strlen(PAYLOAD) && memcmp(out, PAYLOAD, ol) == 0,
          "解包产物字节级一致");

    /* --- 篡改：改临时公钥 -> AUTH（eph 在 AAD 内） --- */
    {
        uint8_t tam[8192];
        size_t  tl = bl;
        memcpy(tam, blob, bl);
        tam[144] ^= 0x01u;              /* eph_pub 首字节翻转 */
        ol = sizeof(out);
        rc = pk_unpack_artifact(tam, tl, &ik, &b, k_c2s, k_s2c, out, &ol);
        CHECK(rc == PK_ERR_BIND || rc == PK_ERR_AUTH,
              "篡改临时公钥被拒（BIND 或 AUTH）");
    }

    /* --- 篡改：改纪元字段 -> 被拒（epoch 在 AAD 内） --- */
    {
        uint8_t tam[8192];
        memcpy(tam, blob, bl);
        tam[140] ^= 0x01u;              /* epoch 字段翻转 */
        ol = sizeof(out);
        rc = pk_unpack_artifact(tam, bl, &ik, &b, k_c2s, k_s2c, out, &ol);
        CHECK(rc != PK_OK, "篡改纪元字段被拒");
    }

    /* --- 另一植入体：密钥不同 -> 解不开 --- */
    {
        pk_implant_key_t other;
        uint8_t opub[PK_IMPLANT_PK_LEN], blob3[8192];
        size_t bl3 = sizeof(blob3), ol3;
        pk_binding_t b3;

        pk_implant_key_init(&other);
        pk_implant_key_pub(&other, opub);
        CHECK(memcmp(opub, ipub, PK_IMPLANT_PK_LEN) != 0,
              "两个植入体静态公钥不同");
        fill_binding(&b3, sid, "pfs-implant", 1u, 0u);
        /* 用 other 的公钥打包，却用 ik 的私钥解 */
        CHECK(pk_pack_artifact((const uint8_t *)PAYLOAD, strlen(PAYLOAD), &b3,
                               k_c2s, k_s2c, opub, blob3, &bl3) == PK_OK,
              "面向另一植入体打包成功");
        ol3 = sizeof(out);
        rc = pk_unpack_artifact(blob3, bl3, &ik, &b3, k_c2s, k_s2c, out, &ol3);
        CHECK(rc == PK_ERR_AUTH || rc == PK_ERR_EXPIRED,
              "非目标植入体解不开（AUTH）");
        pk_implant_key_wipe(&other);
    }

    /* --- 会话密钥错 -> AUTH --- */
    {
        uint8_t bad_k[PK_SESSION_KEY_LEN];
        memcpy(bad_k, k_c2s, sizeof(bad_k));
        bad_k[0] ^= 0x01u;
        ol = sizeof(out);
        rc = pk_unpack_artifact(blob, bl, &ik, &b, bad_k, k_s2c, out, &ol);
        CHECK(rc == PK_ERR_AUTH, "会话密钥错被拒");
    }

    /* --- 密钥退化 -> DEGEN --- */
    {
        uint8_t blob4[8192];
        size_t bl4 = sizeof(blob4);
        pk_binding_t b4;
        fill_binding(&b4, sid, "pfs-implant", 1u, 0u);
        rc = pk_pack_artifact((const uint8_t *)PAYLOAD, strlen(PAYLOAD), &b4,
                              k_c2s, k_c2s, ipub, blob4, &bl4);
        CHECK(rc == PK_ERR_DEGEN, "k_c2s == k_s2c 被拒（DEGEN）");
    }

    /* --- 每件制品密文不同（临时密钥对不复用） --- */
    {
        uint8_t b1[8192], b2[8192];
        size_t l1 = sizeof(b1), l2 = sizeof(b2);
        pk_binding_t b5;
        fill_binding(&b5, sid, "pfs-implant", 1u, 0u);
        pk_pack_artifact((const uint8_t *)PAYLOAD, strlen(PAYLOAD), &b5,
                         k_c2s, k_s2c, ipub, b1, &l1);
        pk_pack_artifact((const uint8_t *)PAYLOAD, strlen(PAYLOAD), &b5,
                         k_c2s, k_s2c, ipub, b2, &l2);
        CHECK(l1 == l2 && memcmp(b1, b2, l1) != 0,
              "同明文两件制品字节不同（临时密钥对不复用）");
        {
            uint8_t e1[PK_EPH_PUB_LEN], e2[PK_EPH_PUB_LEN];
            memcpy(e1, b1 + 144, PK_EPH_PUB_LEN);
            memcpy(e2, b2 + 144, PK_EPH_PUB_LEN);
            CHECK(memcmp(e1, e2, PK_EPH_PUB_LEN) != 0,
                  "两件制品临时公钥不同");
        }
    }

    /* ================================================================
     * 纪元窗口与前向保密 —— 放在最后，因为轮换会改变 ik 状态
     * ================================================================ */

    /* --- 轮换 1 次，旧制品仍在保留窗口内 --- */
    CHECK(pk_implant_key_rotate(&ik, &ep) == PK_OK && ep == 1u,
          "轮换到纪元 1");
    CHECK(pk_implant_key_has_epoch(&ik, 0u) == 1, "纪元 0 仍在保留窗口");
    ol = sizeof(out);
    CHECK(pk_unpack_artifact(blob, bl, &ik, &b, k_c2s, k_s2c, out, &ol) == PK_OK,
          "纪元 0 制品在窗口内仍可解（在途容忍）");

    /* --- 再轮换 1 次，纪元 0 滚出 -> EXPIRED（PFS 兑现） --- */
    CHECK(pk_implant_key_rotate(&ik, &ep) == PK_OK && ep == 2u,
          "轮换到纪元 2");
    CHECK(pk_implant_key_has_epoch(&ik, 0u) == 0, "纪元 0 已滚出窗口");
    ol = sizeof(out);
    rc = pk_unpack_artifact(blob, bl, &ik, &b, k_c2s, k_s2c, out, &ol);
    CHECK(rc == PK_ERR_EXPIRED, "纪元 0 制品永久解不开（前向保密）");

    /* --- 主动 forget 立即失效 --- */
    {
        pk_implant_key_t ik2;
        uint8_t pub2[PK_IMPLANT_PK_LEN], blob2[8192];
        size_t bl2 = sizeof(blob2), ol2;
        pk_binding_t b2;

        pk_implant_key_init(&ik2);
        pk_implant_key_pub(&ik2, pub2);
        fill_binding(&b2, sid, "pfs-implant", 1u, 0u);
        CHECK(pk_pack_artifact((const uint8_t *)PAYLOAD, strlen(PAYLOAD), &b2,
                               k_c2s, k_s2c, pub2, blob2, &bl2) == PK_OK,
              "第二件制品打包成功");
        ol2 = sizeof(out);
        CHECK(pk_unpack_artifact(blob2, bl2, &ik2, &b2, k_c2s, k_s2c,
                                 out, &ol2) == PK_OK, "解包成功");
        CHECK(pk_implant_key_forget(&ik2, 0u) == PK_OK, "主动丢弃纪元 0 私钥");
        ol2 = sizeof(out);
        CHECK(pk_unpack_artifact(blob2, bl2, &ik2, &b2, k_c2s, k_s2c,
                                 out, &ol2) == PK_ERR_EXPIRED,
              "forget 后制品立即失效");
        pk_implant_key_wipe(&ik2);
    }

    pk_implant_key_wipe(&ik);
}

int main(void)
{
    printf("=== 规范化绑定上下文（限制 1） ===\n");
    test_binding();
    printf("\n=== v1 废弃（限制 2） ===\n");
    test_v1_retired();
    printf("\n=== 纪元联动 + 前向保密（限制 3 / 4） ===\n");
    test_epoch_and_pfs();

    printf("\ntotal=%d pass=%d fail=%d\n",
           g_total, g_total - g_fail, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
