/*
 * DAYANJING v4 — 20_packer / artifact.c
 *
 * v3 制品：ephemeral-static 种子派生 + 纪元联动 + 前向保密。
 *
 * ====================================================================
 * 派生式
 * ====================================================================
 *   ctx  = 规范化绑定上下文（含 epoch，见 binding.c）
 *   ss   = X25519(eph_priv, pk_implant@epoch)
 *   ikm  = ss(32) || k_c2s(16) || k_s2c(16)
 *   seed = HKDF-Extract(salt = ctx, ikm)
 *          -> Expand(info = "dayanjing:packer:artifact:v3", 32 字节)
 *
 * 三个成分各自解决一个不同的问题，缺一不可：
 *   ss        —— 单向性 + 前向保密：没有植入体私钥就造不出、也解不开
 *   k_c2s/s2c —— 会话绑定：只拿到植入体公钥但不在本会话，仍解不开
 *   ctx       —— 上下文隔离：跨植入体 / 跨代 / 跨纪元的制品不可互换
 *
 * ====================================================================
 * 为什么这样就有了前向保密
 * ====================================================================
 * 制品头里只有临时公钥 E（不是私钥 sk）。攻击者即使录下完整制品 +
 * 事后拿到会话密钥，仍算不出 ss —— 因为 ss 需要 sk。
 * 而 sk 按纪元轮换、滚出保留窗口后被 secure_zero 擦除（见 keyrot.c）。
 * sk 不存在的那一刻起，该纪元的录制制品就永久解不开了。
 *
 * 打包方一侧的临时私钥 eph_priv 同样在用完后立即擦除，因此 C2 侧
 * 也不保留"重算该制品种子"的能力 —— 制品是一次性的。
 *
 * ====================================================================
 * 纪元如何联动
 * ====================================================================
 * 制品头带明文 epoch（纳入 AAD）。解包时：
 *   1. 纪元不在植入体保留窗口 -> PK_ERR_EXPIRED（PFS 已兑现）
 *   2. 纪元在窗口内 -> 用该纪元私钥派生并验签
 * 因为 epoch 在 AAD 里，把旧纪元制品的头改成新纪元会直接破坏验签，
 * 不存在"改个数字就能续期"的可能。
 *
 * 密码学复用 00_crypto 的 X25519 / HKDF，不自研第二套。
 */

#include "packer.h"
#include "pack_int.h"

#include <string.h>

#include "crypto_hash.h"
#include "crypto_x25519.h"
#include "crypto_gcm.h"

static const uint8_t PK_ARTIFACT_INFO[] = "dayanjing:packer:artifact:v3";

static void art_zero(void *p, size_t n)
{
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n--) *q++ = 0;
}

/* 绑定上下文编码 + 会话密钥退化检查，两端共用 */
static int art_prepare(const pk_binding_t *b,
                       const uint8_t k_c2s[PK_SESSION_KEY_LEN],
                       const uint8_t k_s2c[PK_SESSION_KEY_LEN],
                       uint8_t *ctx, size_t ctx_cap, size_t *ctx_len)
{
    int rc;

    if (!b || !k_c2s || !k_s2c || !ctx || !ctx_len) return PK_ERR_ARG;

    /* 单向密钥退化会让"两个方向同一个密钥"，削弱分离性 —— 直接拒绝 */
    /* SEC-CMP:DEGENERATE: 拒绝双向同钥（PK_ERR_DEGEN）。相等是异常态，攻击者无法据此获得可观测预言。 */
    if (memcmp(k_c2s, k_s2c, PK_SESSION_KEY_LEN) == 0) return PK_ERR_DEGEN;

    rc = pk_binding_encode(b, ctx, ctx_cap, ctx_len);
    if (rc != PK_OK) return rc;
    if (*ctx_len > ctx_cap) return PK_ERR_NOMEM;

    return PK_OK;
}

/* ss || k_c2s || k_s2c -> HKDF-Extract/Expand -> seed */
static int art_expand(const uint8_t *ctx, size_t ctx_len,
                      const uint8_t ss[X25519_KEY_LEN],
                      const uint8_t k_c2s[PK_SESSION_KEY_LEN],
                      const uint8_t k_s2c[PK_SESSION_KEY_LEN],
                      uint8_t seed[PK_SHA_LEN])
{
    uint8_t ikm[X25519_KEY_LEN + PK_SESSION_KEY_LEN * 2];
    uint8_t prk[HKDF_HASH_LEN];
    int     rc;

    memcpy(ikm, ss, X25519_KEY_LEN);
    memcpy(ikm + X25519_KEY_LEN, k_c2s, PK_SESSION_KEY_LEN);
    memcpy(ikm + X25519_KEY_LEN + PK_SESSION_KEY_LEN, k_s2c, PK_SESSION_KEY_LEN);

    if (hkdf_extract(ctx, ctx_len, ikm, sizeof(ikm), prk) != HASH_OK) {
        art_zero(ikm, sizeof(ikm));
        return PK_ERR_ARG;
    }

    rc = hkdf_expand(prk, PK_ARTIFACT_INFO, sizeof(PK_ARTIFACT_INFO) - 1u,
                     seed, PK_SHA_LEN);

    art_zero(ikm, sizeof(ikm));
    art_zero(prk, sizeof(prk));
    return (rc == HASH_OK) ? PK_OK : PK_ERR_ARG;
}

/* ====================================================================
 * 打包方派生
 * ==================================================================== */

int pk_artifact_seed(const pk_binding_t *b,
                     const uint8_t k_c2s[PK_SESSION_KEY_LEN],
                     const uint8_t k_s2c[PK_SESSION_KEY_LEN],
                     const uint8_t pk_implant[PK_IMPLANT_PK_LEN],
                     uint8_t eph_pub_out[PK_EPH_PUB_LEN],
                     uint8_t seed[PK_SHA_LEN])
{
    uint8_t  ctx[256];
    size_t   ctx_len = 0;
    uint8_t  eph_priv[X25519_KEY_LEN];
    uint8_t  ss[X25519_KEY_LEN];
    int      rc;

    if (!pk_implant || !eph_pub_out || !seed) return PK_ERR_ARG;

    rc = art_prepare(b, k_c2s, k_s2c, ctx, sizeof(ctx), &ctx_len);
    if (rc != PK_OK) return rc;

    /* 每件制品一个临时密钥对 —— 不复用，复用会让不同制品共享 ss 前缀 */
    rc = x25519_generate_keypair(eph_priv, eph_pub_out);
    if (rc != X25519_OK) { art_zero(ctx, sizeof(ctx)); return PK_ERR_SYS; }

    rc = x25519_shared(eph_priv, pk_implant, ss);
    /* 临时私钥在此之后不再需要：立即擦除，C2 侧也不保留重算能力 */
    art_zero(eph_priv, sizeof(eph_priv));
    if (rc != X25519_OK) {
        art_zero(ctx, sizeof(ctx));
        art_zero(ss, sizeof(ss));
        return PK_ERR_ARG;
    }

    rc = art_expand(ctx, ctx_len, ss, k_c2s, k_s2c, seed);

    art_zero(ctx, sizeof(ctx));
    art_zero(ss, sizeof(ss));
    return rc;
}

/* ====================================================================
 * 解包方派生
 * ==================================================================== */

int pk_artifact_seed_open(const pk_implant_key_t *k,
                          const pk_binding_t *b,
                          const uint8_t k_c2s[PK_SESSION_KEY_LEN],
                          const uint8_t k_s2c[PK_SESSION_KEY_LEN],
                          const uint8_t eph_pub[PK_EPH_PUB_LEN],
                          uint8_t seed[PK_SHA_LEN])
{
    uint8_t  ctx[256];
    size_t   ctx_len = 0;
    uint8_t  ss[X25519_KEY_LEN];
    const pk_keyslot_t *slot = NULL;
    int      rc;

    if (!k || !eph_pub || !seed) return PK_ERR_ARG;

    rc = art_prepare(b, k_c2s, k_s2c, ctx, sizeof(ctx), &ctx_len);
    if (rc != PK_OK) return rc;

    /* 按纪元定位私钥槽：不在保留窗口 = 私钥已被擦除 = 前向保密生效 */
    for (int i = 0; i < k->n; i++) {
        if (k->slots[i].epoch == b->epoch) { slot = &k->slots[i]; break; }
    }
    if (!slot) {
        art_zero(ctx, sizeof(ctx));
        return PK_ERR_EXPIRED;
    }

    rc = x25519_shared(slot->sk, eph_pub, ss);
    if (rc != X25519_OK) {
        art_zero(ctx, sizeof(ctx));
        return PK_ERR_ARG;
    }

    rc = art_expand(ctx, ctx_len, ss, k_c2s, k_s2c, seed);

    art_zero(ctx, sizeof(ctx));
    art_zero(ss, sizeof(ss));
    return rc;
}

/* ====================================================================
 * 打包 / 解包
 * ==================================================================== */

int pk_pack_artifact(const uint8_t *raw, size_t raw_len,
                     const pk_binding_t *b,
                     const uint8_t k_c2s[PK_SESSION_KEY_LEN],
                     const uint8_t k_s2c[PK_SESSION_KEY_LEN],
                     const uint8_t pk_implant[PK_IMPLANT_PK_LEN],
                     uint8_t *out, size_t *out_len)
{
    uint8_t ctx[256];
    size_t  ctx_len = 0;
    uint8_t bid[PK_BIND_ID_LEN];
    uint8_t eph[PK_EPH_PUB_LEN];
    uint8_t seed[PK_SHA_LEN];
    int     rc;

    if (!raw || !b || !out || !out_len) return PK_ERR_ARG;
    if (raw_len == 0) return PK_ERR_ARG;

    /* bind_id 覆盖含 epoch 的规范化上下文，故纪元不同的制品 bind_id 也不同 */
    rc = pk_binding_encode(b, ctx, sizeof(ctx), &ctx_len);
    if (rc != PK_OK) return rc;

    rc = pk_bind_id(ctx, ctx_len, bid);
    if (rc != PK_OK) { art_zero(ctx, sizeof(ctx)); return rc; }

    rc = pk_artifact_seed(b, k_c2s, k_s2c, pk_implant, eph, seed);
    art_zero(ctx, sizeof(ctx));
    if (rc != PK_OK) return rc;

    rc = pk_pack_core(raw, raw_len, seed, sizeof(seed), PK_VERSION3,
                      bid, b->epoch, eph, out, out_len);

    art_zero(seed, sizeof(seed));
    return rc;
}

int pk_unpack_artifact(const uint8_t *blob, size_t blob_len,
                       const pk_implant_key_t *k,
                       const pk_binding_t *b,
                       const uint8_t k_c2s[PK_SESSION_KEY_LEN],
                       const uint8_t k_s2c[PK_SESSION_KEY_LEN],
                       uint8_t *out, size_t *out_len)
{
    uint32_t head_epoch = 0;
    uint8_t  got[PK_BIND_ID_LEN];
    uint8_t  want[PK_BIND_ID_LEN];
    uint8_t  ctx[256];
    size_t   ctx_len = 0;
    uint8_t  eph[PK_EPH_PUB_LEN];
    uint8_t  seed[PK_SHA_LEN];
    pk_binding_t b2;
    pk_hdr   h;
    int      rc;

    if (!blob || !k || !b || !out || !out_len) return PK_ERR_ARG;

    /* 1. 解析头，取纪元与临时公钥（纪元明文，用于 O(1) 定位纪元） */
    rc = pk_header_parse(blob, blob_len, &h);
    if (rc != PK_OK) return rc;
    if (h.version != PK_VERSION3) return PK_ERR_VERSION;

    head_epoch = h.epoch;
    memcpy(eph, h.eph_pub, PK_EPH_PUB_LEN);

    /* 2. 以制品头纪元重算期望 bind_id，与制品自带值比对 */
    b2 = *b;
    b2.epoch = head_epoch;

    rc = pk_binding_encode(&b2, ctx, sizeof(ctx), &ctx_len);
    if (rc != PK_OK) return rc;

    rc = pk_bind_id(ctx, ctx_len, want);
    if (rc != PK_OK) { art_zero(ctx, sizeof(ctx)); return rc; }

    rc = pk_artifact_bind_id(blob, blob_len, got);
    if (rc != PK_OK) { art_zero(ctx, sizeof(ctx)); return rc; }

    art_zero(ctx, sizeof(ctx));
    /* 同 bind.c：got 来自制品（攻击者可控），want 可能由秘密 bind_ctx 派生，
       逐字节早退会变成可远程观测的预言机 —— 必须常量时间。 */
    if (crypto_constant_time_eq(got, want, PK_BIND_ID_LEN) == 0) return PK_ERR_BIND;

    /* 3. 用该纪元私钥派生种子并解包（纪元不在窗口会在此返回 EXPIRED） */
    rc = pk_artifact_seed_open(k, &b2, k_c2s, k_s2c, eph, seed);
    if (rc != PK_OK) return rc;

    rc = pk_unpack_core(blob, blob_len, seed, sizeof(seed), out, out_len);

    art_zero(seed, sizeof(seed));
    return rc;
}
