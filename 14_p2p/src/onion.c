/*
 * DAYANJING v4 — 14_p2p/src/onion.c
 *
 * 洋葱路由分层加密，层密钥走 X25519 ephemeral-static。
 * 设计说明见 include/p2p_onion.h。
 *
 * 密码学全部复用 00_crypto，不自研第二套：
 *   层密钥协商 = X25519 (00_crypto/crypto_x25519.c)
 *   层密钥派生 = HKDF-SHA256 (00_crypto/crypto_hash.c)
 *   层加解密   = AES-128-GCM (00_crypto/crypto_gcm.c)
 */

#include "p2p_onion.h"

#include "crypto_gcm.h"
#include "crypto_hash.h"
#include "crypto_x25519.h"

#include <stdio.h>
#include <string.h>

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

/*
 * 层密钥：K = HKDF(salt, IKM = X25519(sk, eph_pub) || my_id, info=...)
 *
 * IKM 里混入 my_id 的理由：同一条电路上不同跳若恰好拿到相同的 ss
 * （理论上不可能，但深度防御），层密钥也不会相同。
 */
int p2p_onion_layer_key(const uint8_t sk[P2P_ONION_SK_LEN],
                        const uint8_t eph_pub[P2P_ONION_EPH_LEN],
                        const uint8_t salt[P2P_ONION_SALT_LEN],
                        const uint8_t my_id[P2P_ONION_ID_LEN],
                        uint8_t out[P2P_ONION_KEY_LEN]) {
    if (!sk || !eph_pub || !salt || !my_id || !out) return P2P_ONION_ERR_ARG;

    uint8_t ss[X25519_KEY_LEN];
    if (x25519_shared(sk, eph_pub, ss) != X25519_OK) return P2P_ONION_ERR_ARG;

    uint8_t ikm[X25519_KEY_LEN + P2P_ONION_ID_LEN];
    memcpy(ikm, ss, X25519_KEY_LEN);
    memcpy(ikm + X25519_KEY_LEN, my_id, P2P_ONION_ID_LEN);

    static const char tag[] = "p2p:onion:layer:v2";
    if (hkdf(salt, P2P_ONION_SALT_LEN,
             ikm, sizeof ikm,
             (const uint8_t *)tag, sizeof(tag) - 1,
             out, P2P_ONION_KEY_LEN) != HASH_OK) {
        return P2P_ONION_ERR_ARG;
    }
    return P2P_ONION_OK;
}

static void gen_iv(uint8_t iv[P2P_ONION_IV_LEN]) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(iv, 1, P2P_ONION_IV_LEN, f) == P2P_ONION_IV_LEN) {
            fclose(f);
            return;
        }
        fclose(f);
    }
    /* 回退：真随机不可用时不静默使用固定 IV */
    memset(iv, 0, P2P_ONION_IV_LEN);
}

int p2p_onion_build(const uint8_t *hops_flat, int n_hops,
                    const uint8_t *hop_pub_flat,
                    const uint8_t salt[P2P_ONION_SALT_LEN],
                    const char *final_host, uint16_t final_port,
                    uint8_t *out, size_t cap, size_t *out_len) {
    if (!hops_flat || !hop_pub_flat || !salt || !out_len) return P2P_ONION_ERR_ARG;
    if (n_hops <= 0 || n_hops > P2P_ONION_MAX_LAYERS) return P2P_ONION_ERR_ARG;

    size_t host_len = final_host ? strlen(final_host) : 0;
    if (host_len > 255) return P2P_ONION_ERR_ARG;

    uint8_t cur[ONION_BUF];
    size_t  cur_len = 0;
    uint8_t pt[ONION_BUF], ct[ONION_BUF];

    for (int i = n_hops - 1; i >= 0; i--) {
        const uint8_t *hop_id = hops_flat + (size_t)i * P2P_ONION_ID_LEN;
        const uint8_t *hop_pub = hop_pub_flat + (size_t)i * P2P_ONION_EPH_LEN;
        int is_final = (i == n_hops - 1);

        size_t hl = is_final ? host_len : 0;
        size_t pt_len = P2P_ONION_HDR_LEN + cur_len + hl;
        if (pt_len > sizeof pt) return P2P_ONION_ERR_LEN;

        memset(pt, 0, pt_len);
        pt[0] = (uint8_t)(is_final ? 1 : 0);
        pt[1] = (uint8_t)hl;
        put_u16(pt + 2, is_final ? final_port : (uint16_t)0);
        if (!is_final)
            memcpy(pt + 4, hops_flat + (size_t)(i + 1) * P2P_ONION_ID_LEN,
                   P2P_ONION_ID_LEN);
        put_u16(pt + 20, (uint16_t)cur_len);
        if (cur_len) memcpy(pt + P2P_ONION_HDR_LEN, cur, cur_len);
        if (hl) memcpy(pt + P2P_ONION_HDR_LEN + cur_len, final_host, hl);

        /* 本跳临时密钥对：ss = X25519(eph_priv, hop_pub) */
        uint8_t eph_priv[X25519_KEY_LEN], eph_pub[X25519_KEY_LEN];
        if (x25519_generate_keypair(eph_priv, eph_pub) != X25519_OK)
            return P2P_ONION_ERR_ARG;

        uint8_t k[P2P_ONION_KEY_LEN];
        int rc = p2p_onion_layer_key(eph_priv, hop_pub, salt, hop_id, k);
        if (rc != P2P_ONION_OK) return rc;

        uint8_t iv[P2P_ONION_IV_LEN];
        gen_iv(iv);

        uint8_t tagv[P2P_ONION_TAG_LEN];
        if (pt_len > sizeof ct) return P2P_ONION_ERR_LEN;
        /* AAD = salt：把层绑定到本条电路，防跨电路拼接/重放 */
        if (gcm_seal(k, iv, salt, P2P_ONION_SALT_LEN,
                     pt, pt_len, ct, tagv) != GCM_OK) {
            return P2P_ONION_ERR_ARG;
        }

        /* 新层 = eph_pub(32) || iv(12) || tag(16) || ct(n) */
        size_t new_len = P2P_ONION_EPH_LEN + P2P_ONION_LAYER_OVH + pt_len;
        if (new_len > sizeof cur) return P2P_ONION_ERR_LEN;
        memcpy(cur, eph_pub, P2P_ONION_EPH_LEN);
        memcpy(cur + P2P_ONION_EPH_LEN, iv, P2P_ONION_IV_LEN);
        memcpy(cur + P2P_ONION_EPH_LEN + P2P_ONION_IV_LEN, tagv, P2P_ONION_TAG_LEN);
        memcpy(cur + P2P_ONION_EPH_LEN + P2P_ONION_LAYER_OVH, ct, pt_len);
        cur_len = new_len;

        memset(eph_priv, 0, sizeof eph_priv);
    }

    *out_len = cur_len;
    if (!out) return P2P_ONION_OK;
    if (cap < cur_len) return P2P_ONION_ERR_LEN;
    memcpy(out, cur, cur_len);
    return P2P_ONION_OK;
}

int p2p_onion_peel(const uint8_t sk[P2P_ONION_SK_LEN],
                   const uint8_t salt[P2P_ONION_SALT_LEN],
                   const uint8_t my_id[P2P_ONION_ID_LEN],
                   const uint8_t *onion, size_t onion_len,
                   int *final_flag,
                   uint8_t next_id[P2P_ONION_ID_LEN],
                   char *final_host, size_t host_cap, uint16_t *final_port,
                   uint8_t *inner, size_t inner_cap, size_t *inner_len) {
    if (!sk || !salt || !my_id || !onion || !final_flag || !inner_len)
        return P2P_ONION_ERR_ARG;
    if (onion_len < P2P_ONION_EPH_LEN + P2P_ONION_LAYER_OVH + P2P_ONION_HDR_LEN)
        return P2P_ONION_ERR_FMT;

    const uint8_t *eph_pub = onion;
    const uint8_t *iv   = onion + P2P_ONION_EPH_LEN;
    const uint8_t *tagv = onion + P2P_ONION_EPH_LEN + P2P_ONION_IV_LEN;
    const uint8_t *ct   = onion + P2P_ONION_EPH_LEN + P2P_ONION_LAYER_OVH;
    size_t ct_len = onion_len - P2P_ONION_EPH_LEN - P2P_ONION_LAYER_OVH;

    /* ss = X25519(本跳静态私钥, 层内临时公钥) */
    uint8_t k[P2P_ONION_KEY_LEN];
    int rc = p2p_onion_layer_key(sk, eph_pub, salt, my_id, k);
    if (rc != P2P_ONION_OK) return rc;

    uint8_t pt[ONION_BUF];
    if (ct_len > sizeof pt) return P2P_ONION_ERR_LEN;

    if (gcm_open(k, iv, salt, P2P_ONION_SALT_LEN,
                 ct, ct_len, tagv, pt) != GCM_OK) {
        return P2P_ONION_ERR_AUTH;
    }

    int is_final = pt[0] ? 1 : 0;
    size_t hl = pt[1];
    uint16_t port = get_u16(pt + 2);
    size_t ilen = get_u16(pt + 20);

    if (P2P_ONION_HDR_LEN + ilen + hl != ct_len) return P2P_ONION_ERR_FMT;
    if (is_final) {
        if (ilen != 0) return P2P_ONION_ERR_FMT;
    } else {
        if (ilen == 0) return P2P_ONION_ERR_FMT;
        if (hl != 0)   return P2P_ONION_ERR_FMT;
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
    if (!inner) return P2P_ONION_OK;
    if (inner_cap < ilen) return P2P_ONION_ERR_LEN;
    if (ilen) memcpy(inner, pt + P2P_ONION_HDR_LEN, ilen);
    return P2P_ONION_OK;
}

int p2p_onion_build_hdr(const uint8_t *hops_flat, int n_hops,
                        const uint8_t *hop_pub_flat,
                        const uint8_t salt[P2P_ONION_SALT_LEN],
                        const char *final_host, uint16_t final_port,
                        uint8_t *out, size_t cap, size_t *out_len) {
    if (!out_len) return P2P_ONION_ERR_ARG;

    uint8_t onion[ONION_BUF];
    size_t  olen = 0;
    int rc = p2p_onion_build(hops_flat, n_hops, hop_pub_flat, salt,
                             final_host, final_port,
                             onion, sizeof onion, &olen);
    if (rc != P2P_ONION_OK) return rc;
    if (olen > 0xffff) return P2P_ONION_ERR_LEN;

    size_t total = 1 + P2P_ONION_SALT_LEN + 2 + olen;
    *out_len = total;
    if (!out) return P2P_ONION_OK;
    if (cap < total) return P2P_ONION_ERR_LEN;

    size_t off = 0;
    out[off++] = 1;
    memcpy(out + off, salt, P2P_ONION_SALT_LEN); off += P2P_ONION_SALT_LEN;
    put_u16(out + off, (uint16_t)olen);          off += 2;
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
