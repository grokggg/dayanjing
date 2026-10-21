/*
 * DAYANJING v4 — 20_packer / pack.c
 *
 * 制品头序列化 + 密钥派生 + AES-128-GCM 封装 + 解压回退判断。
 * 加密与哈希全部复用 00_crypto，不自研第二套密码学。
 */

#include "packer.h"
#include "pack_int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "crypto_gcm.h"
#include "crypto_hash.h"

static const uint8_t PK_MAGIC[PK_MAGIC_LEN] = {
    'D', 'J', 'P', 'A', 'K', 0x01, 0x00, 0x00
};

static const uint8_t PK_INFO[] = "dayanjing:packer:v1";

const char *pk_errstr(int e)
{
    switch (e) {
        case PK_OK:          return "ok";
        case PK_ERR_ARG:     return "invalid argument";
        case PK_ERR_NOMEM:   return "output buffer too small";
        case PK_ERR_SMALL:   return "blob shorter than header";
        case PK_ERR_MAGIC:   return "bad magic";
        case PK_ERR_VERSION: return "unsupported or retired version (v1 deprecated)";
        case PK_ERR_LEN:     return "inconsistent length fields";
        case PK_ERR_AUTH:    return "authentication failed";
        case PK_ERR_HASH:    return "plaintext digest mismatch";
        case PK_ERR_CORRUPT: return "compressed stream corrupt";
        case PK_ERR_SYS:     return "system call failed";
        case PK_ERR_BIND:    return "binding id mismatch";
        case PK_ERR_DEGEN:   return "degenerate session keys";
        case PK_ERR_EXPIRED: return "artifact epoch outside retention window";
        case PK_ERR_IMPLID:  return "illegal implant id";
        case PK_ERR_CANON:   return "non-canonical binding encoding";
        default:             return "unknown";
    }
}

/* ---------- 小端读写（显式，不依赖结构体布局） ---------- */

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xffu);
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t get64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* ---------- 熵源：getrandom(2) 优先，失败回落 /dev/urandom ---------- */

static int pk_rand(uint8_t *buf, size_t len)
{
    size_t got = 0;

#if defined(SYS_getrandom)
    while (got < len) {
        long n = syscall(SYS_getrandom, buf + got, len - got, 0u);
        if (n <= 0) break;
        got += (size_t)n;
    }
#endif
    if (got < len) {
        FILE *f = fopen("/dev/urandom", "rb");
        if (!f) return PK_ERR_SYS;
        if (fread(buf + got, 1, len - got, f) != len - got) {
            fclose(f);
            return PK_ERR_SYS;
        }
        fclose(f);
    }
    return PK_OK;
}

/* ---------- 密钥派生 ---------- */

static int pk_derive_key(const uint8_t *salt, size_t salt_len,
                         const uint8_t *seed, size_t seed_len,
                         uint8_t key[PK_KEY_LEN])
{
    uint8_t prk[HKDF_HASH_LEN];

    if (!seed) return PK_ERR_ARG;
    if (hkdf_extract(salt, salt_len, seed, seed_len, prk) != HASH_OK)
        return PK_ERR_ARG;
    if (hkdf_expand(prk, PK_INFO, sizeof(PK_INFO) - 1u,
                    key, PK_KEY_LEN) != HASH_OK)
        return PK_ERR_ARG;
    return PK_OK;
}

/* ---------- AAD 构造（版本相关） ---------- */

static size_t pk_aad_len(uint32_t version)
{
    if (version >= PK_VERSION3) return PK_AAD_V3_LEN;
    if (version >= PK_VERSION2) return PK_AAD_V2_LEN;
    return PK_AAD_V1_LEN;
}

/* 头长度随版本变化：v1 108 / v2 140 / v3 176 */
static size_t pk_hdr_len_of(uint32_t version)
{
    if (version >= PK_VERSION3) return PK_HDR_V3_LEN;
    if (version >= PK_VERSION2) return PK_HDR_V2_LEN;
    return PK_HDR_LEN;
}

/*
 * AAD = magic|version|flags|raw_len|pay_len (32)
 *     + salt(16) + raw_sha(32)
 *     [+ bind_id(32)，v2 起]
 *     [+ epoch(4) + eph_pub(32)，v3 起]
 *
 * v2 把 bind_id 纳入认证范围：制品被搬到另一会话/植入体时，
 * 即便对方持有"形状正确"的密钥，也因 AAD 不符而验签失败。
 * v3 再把纪元与临时公钥纳入：改纪元会直接破坏验签，
 * 因此"把旧纪元制品伪装成新纪元"不成立。
 */
static void pk_build_aad(const uint8_t *hdr, uint32_t version,
                         uint8_t *aad, size_t aad_cap)
{
    size_t need = pk_aad_len(version);

    if (aad_cap < need) return;   /* 调用方保证容量；此处不越界写 */

    memcpy(aad, hdr, 32);
    memcpy(aad + 32, hdr + 32, PK_SALT_LEN);
    memcpy(aad + 48, hdr + 76, PK_SHA_LEN);
    if (version >= PK_VERSION2)
        memcpy(aad + 80, hdr + 108, PK_BIND_ID_LEN);
    if (version >= PK_VERSION3) {
        memcpy(aad + 112, hdr + 140, PK_EPOCH_LEN);
        memcpy(aad + 116, hdr + 144, PK_EPH_PUB_LEN);
    }
}

/* ====================================================================
 * 头部
 * ==================================================================== */

int pk_header_parse(const uint8_t *blob, size_t blob_len, pk_hdr *h)
{
    size_t hdr_len;

    if (!blob || !h) return PK_ERR_ARG;
    if (blob_len < PK_HDR_LEN) return PK_ERR_SMALL;
    if (memcmp(blob, PK_MAGIC, PK_MAGIC_LEN) != 0) return PK_ERR_MAGIC;

    h->version = get32(blob + 8);
    if (h->version != PK_VERSION && h->version != PK_VERSION2 &&
        h->version != PK_VERSION3)
        return PK_ERR_VERSION;

    hdr_len = pk_hdr_len_of(h->version);
    if (blob_len < hdr_len) return PK_ERR_SMALL;

    h->flags   = get32(blob + 12);
    h->raw_len = get64(blob + 16);
    h->pay_len = get64(blob + 24);

    memcpy(h->salt, blob + 32, PK_SALT_LEN);
    memcpy(h->iv,   blob + 48, PK_IV_LEN);
    memcpy(h->tag,  blob + 60, PK_TAG_LEN);
    memcpy(h->raw_sha, blob + 76, PK_SHA_LEN);

    memset(h->bind_id, 0, PK_BIND_ID_LEN);
    h->epoch = 0;
    memset(h->eph_pub, 0, PK_EPH_PUB_LEN);

    if (h->version >= PK_VERSION2)
        memcpy(h->bind_id, blob + 108, PK_BIND_ID_LEN);
    if (h->version >= PK_VERSION3) {
        h->epoch = get32(blob + 140);
        memcpy(h->eph_pub, blob + 144, PK_EPH_PUB_LEN);
    }

    /* 长度自洽：密文必须恰好填满剩余部分 */
    if (h->pay_len != (uint64_t)(blob_len - hdr_len)) return PK_ERR_LEN;
    /* 明文长度不可能为 0（打包的载荷至少 1 字节） */
    if (h->raw_len == 0) return PK_ERR_LEN;
    return PK_OK;
}

size_t pk_size_bound(size_t raw_len)
{
    /* 最坏情形：压缩后不减反增 —— 每字节字面量占 9 位，另加长度前缀 */
    size_t comp_bound = (raw_len * 9u) / 8u + 2u + PK_LZSS_PREFIX;
    size_t body = (raw_len > comp_bound) ? raw_len : comp_bound;
    return PK_HDR_LEN + body;
}

size_t pk_size_bound_v2(size_t raw_len)
{
    size_t comp_bound = (raw_len * 9u) / 8u + 2u + PK_LZSS_PREFIX;
    size_t body = (raw_len > comp_bound) ? raw_len : comp_bound;
    return PK_HDR_V2_LEN + body;
}

size_t pk_size_bound_v3(size_t raw_len)
{
    size_t comp_bound = (raw_len * 9u) / 8u + 2u + PK_LZSS_PREFIX;
    size_t body = (raw_len > comp_bound) ? raw_len : comp_bound;
    return PK_HDR_V3_LEN + body;
}

int pk_artifact_epoch(const uint8_t *blob, size_t blob_len, uint32_t *epoch)
{
    pk_hdr h;
    int    rc;

    if (!epoch) return PK_ERR_ARG;
    *epoch = 0;
    rc = pk_header_parse(blob, blob_len, &h);
    if (rc != PK_OK) return rc;
    *epoch = h.epoch;
    return PK_OK;
}

int pk_artifact_bind_id(const uint8_t *blob, size_t blob_len,
                        uint8_t id[PK_BIND_ID_LEN])
{
    pk_hdr h;
    int rc;

    if (!id) return PK_ERR_ARG;
    rc = pk_header_parse(blob, blob_len, &h);
    if (rc != PK_OK) return rc;
    memcpy(id, h.bind_id, PK_BIND_ID_LEN);
    return PK_OK;
}

/* ====================================================================
 * 打包
 * ==================================================================== */

int pk_pack_core(const uint8_t *raw, size_t raw_len,
                 const uint8_t *seed, size_t seed_len,
                 uint32_t version,
                 const uint8_t bind_id[PK_BIND_ID_LEN],
                 uint32_t epoch,
                 const uint8_t eph_pub[PK_EPH_PUB_LEN],
                 uint8_t *out, size_t *out_len)
{
    uint8_t *comp = NULL;
    size_t   comp_len = 0;
    size_t   comp_cap;
    size_t   body_len;
    size_t   hdr_len;
    const uint8_t *body;
    uint8_t  key[PK_KEY_LEN];
    uint8_t  aad[PK_AAD_V3_LEN];
    uint8_t *ct;
    uint8_t  sha[PK_SHA_LEN];
    int      rc;

    if (!raw || !out || !out_len) return PK_ERR_ARG;
    if (raw_len == 0) return PK_ERR_ARG;
    if (!seed || seed_len == 0) return PK_ERR_ARG;
    if (version != PK_VERSION && version != PK_VERSION2 &&
        version != PK_VERSION3) return PK_ERR_ARG;
    if (version >= PK_VERSION2 && !bind_id) return PK_ERR_ARG;
    if (version >= PK_VERSION3 && !eph_pub) return PK_ERR_ARG;

    hdr_len = pk_hdr_len_of(version);

    /* 容量按版本取上界：v2 制品不该被要求具备 v3 头的额外空间 */
    {
        size_t bound = (version >= PK_VERSION3) ? pk_size_bound_v3(raw_len)
                     : (version >= PK_VERSION2) ? pk_size_bound_v2(raw_len)
                     : pk_size_bound(raw_len);
        if (*out_len < bound) return PK_ERR_NOMEM;
    }

    /* --- 1. 压缩（仅在确有利时采用） --- */
    comp_cap = (raw_len * 9u) / 8u + 2u + PK_LZSS_PREFIX;
    comp = (uint8_t *)malloc(comp_cap ? comp_cap : 1u);
    if (!comp) return PK_ERR_NOMEM;

    comp_len = comp_cap;
    rc = pk_lzss_compress(raw, raw_len, comp, &comp_len);
    if (rc == PK_OK && comp_len < raw_len) {
        body = comp;
        body_len = comp_len;
    } else {
        body = raw;
        body_len = raw_len;
    }

    /* --- 2. 头 --- */
    memset(out, 0, hdr_len);
    memcpy(out, PK_MAGIC, PK_MAGIC_LEN);
    put32(out + 8,  version);
    put32(out + 12, (body == comp) ? PK_FLAG_COMPRESSED : 0u);
    put64(out + 16, (uint64_t)raw_len);
    put64(out + 24, (uint64_t)body_len);

    if (pk_rand(out + 32, PK_SALT_LEN) != PK_OK) { free(comp); return PK_ERR_SYS; }
    if (pk_rand(out + 48, PK_IV_LEN)   != PK_OK) { free(comp); return PK_ERR_SYS; }

    sha256(raw, raw_len, sha);
    memcpy(out + 76, sha, PK_SHA_LEN);

    if (version >= PK_VERSION2)
        memcpy(out + 108, bind_id, PK_BIND_ID_LEN);
    if (version >= PK_VERSION3) {
        put32(out + 140, epoch);
        memcpy(out + 144, eph_pub, PK_EPH_PUB_LEN);
    }

    /* --- 3. GCM 加密 --- */
    if (pk_derive_key(out + 32, PK_SALT_LEN, seed, seed_len, key) != PK_OK) {
        free(comp);
        return PK_ERR_ARG;
    }
    pk_build_aad(out, version, aad, sizeof(aad));

    ct = out + hdr_len;
    rc = gcm_seal(key, out + 48, aad, pk_aad_len(version),
                  body, body_len, ct, out + 60);
    if (rc != GCM_OK) { free(comp); return PK_ERR_ARG; }

    /* --- 4. 收尾 --- */
    memset(key, 0, sizeof(key));
    *out_len = hdr_len + body_len;
    free(comp);
    return PK_OK;
}

int pk_pack(const uint8_t *raw, size_t raw_len,
            const uint8_t *seed, size_t seed_len,
            uint8_t *out, size_t *out_len)
{
    return pk_pack_core(raw, raw_len, seed, seed_len,
                        PK_VERSION, NULL, 0, NULL, out, out_len);
}

/* ====================================================================
 * 解包
 * ==================================================================== */

int pk_unpack_core(const uint8_t *blob, size_t blob_len,
                   const uint8_t *seed, size_t seed_len,
                   uint8_t *out, size_t *out_len)
{
    pk_hdr   h;
    uint8_t  key[PK_KEY_LEN];
    uint8_t  aad[PK_AAD_V3_LEN];
    uint8_t *ctbuf = NULL;
    uint8_t  sha[PK_SHA_LEN];
    size_t   cap = *out_len;
    size_t   hdr_len;
    int      rc;

    if (!blob || !out || !out_len) return PK_ERR_ARG;
    if (!seed || seed_len == 0) return PK_ERR_ARG;

    rc = pk_header_parse(blob, blob_len, &h);
    if (rc != PK_OK) return rc;

    hdr_len = pk_hdr_len_of(h.version);

    if (cap < h.raw_len) return PK_ERR_NOMEM;

    if (pk_derive_key(h.salt, PK_SALT_LEN, seed, seed_len, key) != PK_OK)
        return PK_ERR_ARG;
    pk_build_aad(blob, h.version, aad, sizeof(aad));

    /* 密文 -> 中间明文（可能是压缩流） */
    ctbuf = (uint8_t *)malloc((size_t)h.pay_len ? (size_t)h.pay_len : 1u);
    if (!ctbuf) { memset(key, 0, sizeof(key)); return PK_ERR_NOMEM; }

    rc = gcm_open(key, h.iv, aad, pk_aad_len(h.version),
                  blob + hdr_len, (size_t)h.pay_len, h.tag, ctbuf);
    memset(key, 0, sizeof(key));
    if (rc == GCM_ERR_AUTH) { free(ctbuf); return PK_ERR_AUTH; }
    if (rc != GCM_OK) { free(ctbuf); return PK_ERR_ARG; }

    /* 解压或直通 */
    if (h.flags & PK_FLAG_COMPRESSED) {
        size_t dlen = (size_t)h.raw_len;
        rc = pk_lzss_decompress(ctbuf, (size_t)h.pay_len, out, &dlen);
        free(ctbuf);
        if (rc != PK_OK) return rc;
        if (dlen != (size_t)h.raw_len) return PK_ERR_CORRUPT;
        *out_len = dlen;
    } else {
        if ((size_t)h.pay_len != (size_t)h.raw_len) {
            free(ctbuf);
            return PK_ERR_LEN;
        }
        memcpy(out, ctbuf, (size_t)h.raw_len);
        free(ctbuf);
        *out_len = (size_t)h.raw_len;
    }

    /* 明文摘要比对：即便密钥正确、内容被替换也能发现 */
    sha256(out, *out_len, sha);
    if (crypto_constant_time_eq(sha, h.raw_sha, PK_SHA_LEN) == 0)
        return PK_ERR_HASH;

    return PK_OK;
}

int pk_unpack(const uint8_t *blob, size_t blob_len,
              const uint8_t *seed, size_t seed_len,
              uint8_t *out, size_t *out_len)
{
    pk_hdr h;
    int    rc;

    if (!blob || !out || !out_len) return PK_ERR_ARG;

    rc = pk_header_parse(blob, blob_len, &h);
    if (rc != PK_OK) return rc;

    /*
     * v1 已废弃，不再作为可部署制品解包。
     * 理由：v1 既无会话绑定（bind_id）也无纪元/前向保密，任何持有种子者
     * 都能在任意时间解开任意制品 —— 这正是"制品可互换、可离线重放"的根源。
     * 保留 v1 的打包入口仅供内部压测 LZSS / AES-GCM 层，产出的制品不可部署。
     */
    if (h.version < PK_VERSION2) return PK_ERR_VERSION;

    return pk_unpack_core(blob, blob_len, seed, seed_len, out, out_len);
}
