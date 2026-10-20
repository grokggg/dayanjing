/*
 * DAYANJING v4 — 14_p2p/src/onion.c
 *
 * 洋葱路由分层加密。设计说明见 include/p2p_onion.h。
 *
 * 密码学全部复用 00_crypto：
 *   层密钥 = HKDF-SHA256(00_crypto/crypto_hash.c)
 *   层加密 = AES-128-GCM(00_crypto/crypto_gcm.c)
 * 不自研第二套。
 */

#include "p2p_onion.h"

#include "crypto_gcm.h"
#include "crypto_hash.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 层明文最大尺寸：16 层 × (22 头 + 28 开销) + 255 host，留足余量 */
#define ONION_BUF 4096

static void put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
}
static uint16_t get_u16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

const char *p2p_onion_errstr(int e) {
    switch (e) {
        case P2P_ONION_OK:        return "ok";
        case P2P_ONION_ERR_ARG:   return "invalid argument";
        case P2P_ONION_ERR_LEN:   return "buffer too small";
        case P2P_ONION_ERR_AUTH:  return "layer auth failed (not for me / tampered)";
        case P2P_ONION_ERR_FMT:   return "malformed layer";
        default:                  return "unknown";
    }
}

int p2p_onion_layer_key(const uint8_t master[P2P_ONION_MASTER_LEN],
                        const uint8_t salt[P2P_ONION_SALT_LEN],
                        const uint8_t hop_id[P2P_ONION_ID_LEN],
                        uint8_t out[P2P_ONION_KEY_LEN]) {
    if (!master || !salt || !hop_id || !out) return P2P_ONION_ERR_ARG;

    /* info = "p2p:onion:layer:v1" || hop_id —— 18 字节标签，无终止符 */
    const char tag[18] = "p2p:onion:layer:v1";
    uint8_t info[18 + P2P_ONION_ID_LEN];
    memcpy(info, tag, 18);
    memcpy(info + 18, hop_id, P2P_ONION_ID_LEN);

    if (hkdf(salt, P2P_ONION_SALT_LEN,
             master, P2P_ONION_MASTER_LEN,
             info, sizeof info, out, P2P_ONION_KEY_LEN) != HASH_OK) {
        return P2P_ONION_ERR_ARG;
    }
    return P2P_ONION_OK;
}

/*
 * IV 生成：优先真随机（/dev/urandom），不可用时回退到确定性派生。
 *
 * 确定性回退仍然安全的原因：IV 由 (salt, hop_id, layer_idx) 决定，
 * 而 salt 每条电路随机生成 —— 故同一 (key, IV) 组合不会跨电路复用，
 * 也不会在同一电路内跨跳复用（路径无重复节点时）。
 */
static void gen_iv(const uint8_t salt[P2P_ONION_SALT_LEN],
                   const uint8_t hop_id[P2P_ONION_ID_LEN],
                   uint32_t layer_idx,
                   uint8_t iv[P2P_ONION_IV_LEN]) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(iv, 1, P2P_ONION_IV_LEN, f) == P2P_ONION_IV_LEN) {
            fclose(f);
            return;
        }
        fclose(f);
    }
    /* 回退：SHA256(salt || hop_id || layer_idx) 前 12 字节 */
    uint8_t buf[P2P_ONION_SALT_LEN + P2P_ONION_ID_LEN + 4];
    memcpy(buf, salt, P2P_ONION_SALT_LEN);
    memcpy(buf + P2P_ONION_SALT_LEN, hop_id, P2P_ONION_ID_LEN);
    buf[P2P_ONION_SALT_LEN + P2P_ONION_ID_LEN + 0] = (uint8_t)(layer_idx & 0xff);
    buf[P2P_ONION_SALT_LEN + P2P_ONION_ID_LEN + 1] = (uint8_t)((layer_idx >> 8) & 0xff);
    buf[P2P_ONION_SALT_LEN + P2P_ONION_ID_LEN + 2] = (uint8_t)((layer_idx >> 16) & 0xff);
    buf[P2P_ONION_SALT_LEN + P2P_ONION_ID_LEN + 3] = (uint8_t)((layer_idx >> 24) & 0xff);
    uint8_t d[SHA256_DIGEST_LEN];
    sha256(buf, sizeof buf, d);
    memcpy(iv, d, P2P_ONION_IV_LEN);
}

int p2p_onion_build(const uint8_t master[P2P_ONION_MASTER_LEN],
                    const uint8_t salt[P2P_ONION_SALT_LEN],
                    const uint8_t *hops_flat, int n_hops,
                    const char *final_host, uint16_t final_port,
                    uint8_t *out, size_t cap, size_t *out_len) {
    if (!master || !salt || !out_len) return P2P_ONION_ERR_ARG;
    if (n_hops <= 0 || n_hops > P2P_ONION_MAX_LAYERS) return P2P_ONION_ERR_ARG;
    if (!hops_flat) return P2P_ONION_ERR_ARG;

    size_t host_len = final_host ? strlen(final_host) : 0;
    if (host_len > 255) return P2P_ONION_ERR_ARG;

    uint8_t cur[ONION_BUF];      /* 当前已构建的层密文（C[i]） */
    size_t  cur_len = 0;         /* 0 = 还没构建任何层（即"我是最后一跳"） */
    uint8_t pt[ONION_BUF];
    uint8_t ct[ONION_BUF];

    /* 从最后一跳往前逐层包裹 */
    for (int i = n_hops - 1; i >= 0; i--) {
        const uint8_t *hop_id = hops_flat + (size_t)i * P2P_ONION_ID_LEN;
        int is_final = (i == n_hops - 1);

        size_t hl = is_final ? host_len : 0;
        size_t pt_len = P2P_ONION_HDR_LEN + cur_len + hl;
        if (pt_len > sizeof pt) return P2P_ONION_ERR_LEN;

        memset(pt, 0, pt_len);
        pt[0] = (uint8_t)(is_final ? 1 : 0);
        pt[1] = (uint8_t)hl;
        put_u16(pt + 2, is_final ? final_port : (uint16_t)0);
        if (!is_final) {
            /* 下一跳 ID：i+1 < n_hops 必然成立（is_final 为假时） */
            memcpy(pt + 4, hops_flat + (size_t)(i + 1) * P2P_ONION_ID_LEN,
                   P2P_ONION_ID_LEN);
        }
        put_u16(pt + 20, (uint16_t)cur_len);
        if (cur_len) memcpy(pt + P2P_ONION_HDR_LEN, cur, cur_len);
        if (hl) memcpy(pt + P2P_ONION_HDR_LEN + cur_len, final_host, hl);

        /* 本跳层密钥 */
        uint8_t k[P2P_ONION_KEY_LEN];
        int rc = p2p_onion_layer_key(master, salt, hop_id, k);
        if (rc != P2P_ONION_OK) return rc;

        uint8_t iv[P2P_ONION_IV_LEN];
        gen_iv(salt, hop_id, (uint32_t)i, iv);

        uint8_t tagv[P2P_ONION_TAG_LEN];
        if (pt_len > sizeof ct) return P2P_ONION_ERR_LEN;
        /* AAD = salt：把洋葱绑定到这条电路，防止跨电路重放/拼接 */
        if (gcm_seal(k, iv, salt, P2P_ONION_SALT_LEN,
                     pt, pt_len, ct, tagv) != GCM_OK) {
            return P2P_ONION_ERR_ARG;
        }

        /* 新层密文 = iv || tag || ct */
        size_t new_len = P2P_ONION_IV_LEN + P2P_ONION_TAG_LEN + pt_len;
        if (new_len > sizeof cur) return P2P_ONION_ERR_LEN;
        memcpy(cur, iv, P2P_ONION_IV_LEN);
        memcpy(cur + P2P_ONION_IV_LEN, tagv, P2P_ONION_TAG_LEN);
        memcpy(cur + P2P_ONION_LAYER_OVH, ct, pt_len);
        cur_len = new_len;
    }

    *out_len = cur_len;
    if (!out) return P2P_ONION_OK;
    if (cap < cur_len) return P2P_ONION_ERR_LEN;
    memcpy(out, cur, cur_len);
    return P2P_ONION_OK;
}

int p2p_onion_peel(const uint8_t master[P2P_ONION_MASTER_LEN],
                   const uint8_t salt[P2P_ONION_SALT_LEN],
                   const uint8_t my_id[P2P_ONION_ID_LEN],
                   const uint8_t *onion, size_t onion_len,
                   int *final_flag,
                   uint8_t next_id[P2P_ONION_ID_LEN],
                   char *final_host, size_t host_cap, uint16_t *final_port,
                   uint8_t *inner, size_t inner_cap, size_t *inner_len) {
    if (!master || !salt || !my_id || !onion || !final_flag || !inner_len) {
        return P2P_ONION_ERR_ARG;
    }
    if (onion_len < P2P_ONION_LAYER_OVH + P2P_ONION_HDR_LEN) {
        return P2P_ONION_ERR_FMT;
    }

    const uint8_t *iv  = onion;
    const uint8_t *tagv = onion + P2P_ONION_IV_LEN;
    const uint8_t *ct  = onion + P2P_ONION_LAYER_OVH;
    size_t ct_len = onion_len - P2P_ONION_LAYER_OVH;

    uint8_t k[P2P_ONION_KEY_LEN];
    int rc = p2p_onion_layer_key(master, salt, my_id, k);
    if (rc != P2P_ONION_OK) return rc;

    uint8_t pt[ONION_BUF];
    if (ct_len > sizeof pt) return P2P_ONION_ERR_LEN;

    /* AAD 必须与 seal 端一致 */
    if (gcm_open(k, iv, salt, P2P_ONION_SALT_LEN,
                 ct, ct_len, tagv, pt) != GCM_OK) {
        /* 不是给我的层，或被篡改 —— 对外统一表现为 AUTH，不区分 */
        return P2P_ONION_ERR_AUTH;
    }

    int is_final = pt[0] ? 1 : 0;
    size_t hl = pt[1];
    uint16_t port = get_u16(pt + 2);
    size_t ilen = get_u16(pt + 20);

    /* 长度自洽检查：防止伪造层导致越界读 */
    if (P2P_ONION_HDR_LEN + ilen + hl != ct_len) return P2P_ONION_ERR_FMT;
    if (is_final) {
        if (ilen != 0) return P2P_ONION_ERR_FMT;   /* 最后一跳不应有内层 */
    } else {
        if (ilen == 0) return P2P_ONION_ERR_FMT;   /* 中继跳必须有内层 */
        if (hl != 0)   return P2P_ONION_ERR_FMT;   /* 中继跳不应带 host */
    }

    *final_flag = is_final;
    if (is_final) {
        if (final_port) *final_port = port;
        if (final_host && host_cap > 0) {
            if (host_cap < hl + 1) return P2P_ONION_ERR_LEN;
            memcpy(final_host, pt + P2P_ONION_HDR_LEN + ilen, hl);
            final_host[hl] = '\0';
        }
    } else {
        if (next_id) memcpy(next_id, pt + 4, P2P_ONION_ID_LEN);
    }

    *inner_len = ilen;
    if (!inner) return P2P_ONION_OK;          /* 仅探测 */
    if (inner_cap < ilen) return P2P_ONION_ERR_LEN;
    if (ilen) memcpy(inner, pt + P2P_ONION_HDR_LEN, ilen);
    return P2P_ONION_OK;
}

int p2p_onion_build_hdr(const uint8_t master[P2P_ONION_MASTER_LEN],
                        const uint8_t salt[P2P_ONION_SALT_LEN],
                        const uint8_t *hops_flat, int n_hops,
                        const char *final_host, uint16_t final_port,
                        uint8_t *out, size_t cap, size_t *out_len) {
    if (!out_len) return P2P_ONION_ERR_ARG;

    uint8_t onion[ONION_BUF];
    size_t  olen = 0;
    int rc = p2p_onion_build(master, salt, hops_flat, n_hops,
                             final_host, final_port,
                             onion, sizeof onion, &olen);
    if (rc != P2P_ONION_OK) return rc;
    if (olen > 0xffff) return P2P_ONION_ERR_LEN;

    size_t total = 1 + P2P_ONION_SALT_LEN + 2 + olen;
    *out_len = total;
    if (!out) return P2P_ONION_OK;
    if (cap < total) return P2P_ONION_ERR_LEN;

    size_t off = 0;
    out[off++] = 1;                                   /* version */
    memcpy(out + off, salt, P2P_ONION_SALT_LEN); off += P2P_ONION_SALT_LEN;
    put_u16(out + off, (uint16_t)olen);        off += 2;
    memcpy(out + off, onion, olen);
    return P2P_ONION_OK;
}

int p2p_onion_parse_hdr(const uint8_t *in, size_t len,
                        uint8_t salt_out[P2P_ONION_SALT_LEN],
                        const uint8_t **onion_out, size_t *onion_len) {
    if (!in || !onion_out || !onion_len) return P2P_ONION_ERR_ARG;
    if (len < 1 + P2P_ONION_SALT_LEN + 2) return P2P_ONION_ERR_FMT;
    if (in[0] != 1) return P2P_ONION_ERR_FMT;

    size_t off = 1;
    if (salt_out) memcpy(salt_out, in + off, P2P_ONION_SALT_LEN);
    off += P2P_ONION_SALT_LEN;
    size_t olen = get_u16(in + off); off += 2;
    if (len != off + olen) return P2P_ONION_ERR_FMT;

    *onion_out = in + off;
    *onion_len = olen;
    return P2P_ONION_OK;
}

int p2p_onion_build_fwd(const uint8_t *inner, size_t inner_len,
                        uint8_t *out, size_t cap, size_t *out_len) {
    if (!out_len) return P2P_ONION_ERR_ARG;
    if (inner_len > 0 && !inner) return P2P_ONION_ERR_ARG;
    if (inner_len > 0xffff) return P2P_ONION_ERR_LEN;

    size_t total = 2 + inner_len;
    *out_len = total;
    if (!out) return P2P_ONION_OK;
    if (cap < total) return P2P_ONION_ERR_LEN;
    put_u16(out, (uint16_t)inner_len);
    if (inner_len) memcpy(out + 2, inner, inner_len);
    return P2P_ONION_OK;
}

int p2p_onion_parse_fwd(const uint8_t *in, size_t len,
                        const uint8_t **inner_out, size_t *inner_len) {
    if (!in || !inner_out || !inner_len) return P2P_ONION_ERR_ARG;
    if (len < 2) return P2P_ONION_ERR_FMT;
    size_t ilen = get_u16(in);
    if (len != 2 + ilen) return P2P_ONION_ERR_FMT;
    *inner_out = in + 2;
    *inner_len = ilen;
    return P2P_ONION_OK;
}
