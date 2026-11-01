/*
 * DAYANJING v3 — c2_frame.c
 *
 * 帧层 AEAD 封装，与 Python 侧 frame.py 逐字节对齐。
 * 底层 AEAD 用 00_crypto 的 AES-128-GCM。
 */

#include "c2_frame.h"
#include "crypto_gcm.h"

#include <stdlib.h>
#include <string.h>

#define AAD_PREFIX "c2:v1"
#define AAD_LEN    13   /* 5 + 4 + 4 */

static void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);        p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);  p[3] = (uint8_t)(v >> 24);
}

static void put_u64le(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static uint32_t get_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t get_u64le(const uint8_t *p)
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) v |= ((uint64_t)p[i]) << (8 * i);
    return v;
}

size_t c2_frame_aad(uint32_t msg_type, uint8_t out[13])
{
    if (!out) return 0;
    memcpy(out, AAD_PREFIX, 5);
    put_u32le(out + 5, C2_PROTO_VERSION);
    put_u32le(out + 9, msg_type);
    return AAD_LEN;
}

/* 明文 Envelope：u64 seq || u32 version || u32 msg_type || u32 plen || payload */
static size_t envelope_build(uint64_t seq, uint32_t msg_type,
                             const uint8_t *payload, size_t plen,
                             uint8_t *out)
{
    put_u64le(out + 0, seq);
    put_u32le(out + 8, C2_PROTO_VERSION);
    put_u32le(out + 12, msg_type);
    put_u32le(out + 16, (uint32_t)plen);
    if (payload && plen) memcpy(out + 20, payload, plen);
    return 20 + plen;
}

int c2_frame_seal(const uint8_t key[16],
                  const uint8_t nonce_prefix[8],
                  uint32_t counter,
                  uint64_t seq,
                  uint32_t msg_type,
                  const uint8_t *payload, size_t plen,
                  uint8_t *out, size_t cap, size_t *out_len)
{
    size_t pt_len, ct_len, total, env_len;
    uint8_t *pt, *ct;
    uint8_t iv[C2_FRAME_IV_LEN];
    uint8_t aad[AAD_LEN];
    uint8_t tag[C2_FRAME_TAG_LEN];
    int i, rc;

    if (!key || !nonce_prefix || !out_len) return C2_FRAME_ERR_ARG;
    if (plen > 0 && !payload) return C2_FRAME_ERR_ARG;

    /* 明文 Envelope = 20 字节头 + payload；GCM 密文与明文等长。
     * 密文缓冲必须按 Envelope 长度分配，不能只按 payload 长度——
     * 否则 gctr 会写出缓冲区造成堆溢出。 */
    env_len = C2_ENVELOPE_HDR + plen;
    ct_len  = env_len;
    total   = C2_FRAME_OVERHEAD + ct_len;
    *out_len = total;
    if (!out) return C2_FRAME_OK;          /* 仅探测 */
    if (cap < total) return C2_FRAME_ERR_LEN;

    /* iv = 8B prefix || 4B counter（大端） */
    memcpy(iv, nonce_prefix, 8);
    for (i = 0; i < 4; i++) iv[8 + i] = (uint8_t)(counter >> (24 - 8 * i));

    pt_len = env_len;
    pt = (uint8_t *)malloc(pt_len);
    ct = (uint8_t *)malloc(ct_len);
    if (!pt || !ct) { free(pt); free(ct); return C2_FRAME_ERR_ARG; }

    envelope_build(seq, msg_type, payload, plen, pt);
    c2_frame_aad(msg_type, aad);

    rc = gcm_seal(key, iv, aad, AAD_LEN, pt, pt_len, ct, tag);
    memset(pt, 0, pt_len);
    free(pt);
    if (rc != GCM_OK) { free(ct); return C2_FRAME_ERR_AUTH; }

    /* wire = u32 total_len || u32 msg_type || iv || ct || tag */
    put_u32le(out + 0, (uint32_t)(C2_FRAME_TYPE_LEN + C2_FRAME_IV_LEN + ct_len + C2_FRAME_TAG_LEN));
    put_u32le(out + 4, msg_type);
    memcpy(out + 8, iv, C2_FRAME_IV_LEN);
    if (ct_len) memcpy(out + 8 + C2_FRAME_IV_LEN, ct, ct_len);
    memcpy(out + 8 + C2_FRAME_IV_LEN + ct_len, tag, C2_FRAME_TAG_LEN);

    free(ct);
    *out_len = total;
    return C2_FRAME_OK;
}

int c2_frame_open(const uint8_t key[16],
                  const uint8_t *wire, size_t wire_len,
                  uint64_t *seq,
                  uint32_t *msg_type,
                  uint8_t *payload, size_t cap, size_t *plen)
{
    uint32_t total_len, mt, env_mt, env_plen, env_ver;
    const uint8_t *iv, *ct, *tag;
    size_t ct_len;
    uint8_t *pt;
    uint8_t aad[AAD_LEN];
    int rc;

    if (!key || !wire || !plen) return C2_FRAME_ERR_ARG;
    if (wire_len < C2_FRAME_OVERHEAD) return C2_FRAME_ERR_FMT;

    total_len = get_u32le(wire + 0);
    /* total_len 覆盖 msg_type(4) + iv(12) + ct + tag(16) */
    if (total_len < C2_FRAME_TYPE_LEN + C2_FRAME_IV_LEN + C2_FRAME_TAG_LEN)
        return C2_FRAME_ERR_FMT;
    if (wire_len < 4u + (size_t)total_len) return C2_FRAME_ERR_FMT;
    if (total_len != wire_len - 4) return C2_FRAME_ERR_FMT;   /* 长度自洽 */

    ct_len = (size_t)total_len - C2_FRAME_TYPE_LEN - C2_FRAME_IV_LEN - C2_FRAME_TAG_LEN;

    mt  = get_u32le(wire + 4);
    iv  = wire + 8;
    ct  = wire + 8 + C2_FRAME_IV_LEN;
    tag = wire + 8 + C2_FRAME_IV_LEN + ct_len;

    /* 必须先判下界再算减法：ct_len < 20 时 ct_len - 20 在无符号下会回绕成巨大值 */
    if (ct_len < C2_ENVELOPE_HDR) return C2_FRAME_ERR_FMT;

    pt = (uint8_t *)malloc(ct_len);
    if (!pt) return C2_FRAME_ERR_ARG;

    c2_frame_aad(mt, aad);
    rc = gcm_open(key, iv, aad, AAD_LEN, ct, ct_len, tag, pt);
    if (rc != GCM_OK) { free(pt); return C2_FRAME_ERR_AUTH; }

    env_ver  = get_u32le(pt + 8);
    env_mt   = get_u32le(pt + 12);
    env_plen = get_u32le(pt + 16);

    if (env_ver != C2_PROTO_VERSION) { memset(pt, 0, ct_len); free(pt); return C2_FRAME_ERR_FMT; }
    if (env_mt != mt) { memset(pt, 0, ct_len); free(pt); return C2_FRAME_ERR_FMT; }   /* 帧头/载荷 msg_type 必须一致 */
    if (env_plen != ct_len - C2_ENVELOPE_HDR) { memset(pt, 0, ct_len); free(pt); return C2_FRAME_ERR_FMT; }

    /* 验签通过后才回填输出，失败路径不写任何输出参数 */
    if (seq)      *seq      = get_u64le(pt + 0);
    if (msg_type) *msg_type = mt;
    *plen = ct_len - C2_ENVELOPE_HDR;

    if (!payload) {                       /* 仅探测：已完整验签，不接受伪造帧 */
        memset(pt, 0, ct_len);
        free(pt);
        return C2_FRAME_OK;
    }
    if (cap < ct_len - C2_ENVELOPE_HDR) { memset(pt, 0, ct_len); free(pt); return C2_FRAME_ERR_LEN; }

    memcpy(payload, pt + C2_ENVELOPE_HDR, ct_len - C2_ENVELOPE_HDR);

    memset(pt, 0, ct_len);
    free(pt);
    return C2_FRAME_OK;
}
