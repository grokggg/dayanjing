/* tls_server.c — TLS 1.2 服务端实现（与 tls.c 对称）
 *
 * 对称性上踩过的点，改任一侧前必须先看这里：
 *  1. transcript：两端对所有握手消息（含对端的）按同一顺序做 SHA-256，
 *     且 Finished 用的是"不含自身"的快照。顺序只要差一条，失败点落在
 *     Finished 校验，看起来像"密钥算错"，实则只是哈希范围不同。
 *  2. 密钥方向：客户端用 ckey/civ 发、skey/siv 收；服务端必须反过来 ——
 *     用 skey/siv 发、ckey/civ 收。写反了两个方向都会报 malformed record。
 *  3. 加密开关分两个方向：收到对端 CCS 才开接收加密，发出自己 CCS 才开
 *     发送加密。合成一个标志会把对端那条明文 CCS 拿去 GCM 解密。
 */
#include "tls_server.h"
#include "tls_int.h"
#include "crypto_gcm.h"
#include "crypto_hash.h"
#include "crypto_x25519.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define TLS_VER        0x0303
#define CT_CCS         20
#define CT_ALERT       21
#define CT_HANDSHAKE   22
#define CT_APPDATA     23
#define CS_ECDHE_RSA_AES128_GCM_SHA256 0xC02F

#define HS_CLIENT_HELLO  1
#define HS_SERVER_HELLO  2
#define HS_CERTIFICATE  11
#define HS_SKE          12
#define HS_SHD          14
#define HS_CKE          16
#define HS_FINISHED     20

#define REC_HDR 5
#define MAX_REC 18432
#define MAX_HS  65536

struct tls_server_ctx {
    tls_send_cb send;
    tls_recv_cb recv;
    void       *arg;

    uint8_t chain[X509_CHAIN_MAX][X509_DER_MAX];
    size_t  chain_len[X509_CHAIN_MAX];
    int     chain_n;
    rsa_privkey key;                 /* 拷贝一份：调用方的可能随时失效 */
    int     has_key;

    char    alpn_want[64];
    int     alpn_ok;
    char    sni[256];

    uint8_t crand[32], srand[32];
    uint8_t priv[X25519_KEY_LEN], pub[X25519_KEY_LEN];
    uint8_t pms[X25519_KEY_LEN];

    sha256_ctx tr, tr_prev;
    uint8_t    master[48];
    uint8_t    ckey[16], skey[16], civ[4], siv[4];
    uint64_t   wseq, rseq;
    int        enc_on, rdec_on;
    int        handshaked;

    uint8_t rec[MAX_REC];
    uint8_t hs[MAX_HS];
    size_t  hs_len;
    uint8_t plain[MAX_REC];
};

/* ---- IO ---- */
static tls_err io_send_all(tls_server_ctx *c, const uint8_t *d, size_t n) {
    size_t off = 0;
    while (off < n) {
        int r = c->send(c->arg, d + off, n - off);
        if (r <= 0) return TLS_ERR_IO;
        off += (size_t)r;
    }
    return TLS_OK;
}

static tls_err io_recv_exact(tls_server_ctx *c, uint8_t *d, size_t n) {
    size_t got = 0;
    while (got < n) {
        int r = c->recv(c->arg, d + got, n - got);
        if (r <= 0) return TLS_ERR_IO;
        got += (size_t)r;
    }
    return TLS_OK;
}

/* ---- 记录写：服务端方向用 skey/siv ---- */
static tls_err rec_write(tls_server_ctx *c, uint8_t type, const uint8_t *data, size_t len) {
    uint8_t hdr[REC_HDR];
    if (!c->enc_on) {
        hdr[0] = type; hdr[1] = 0x03; hdr[2] = 0x03;
        hdr[3] = (uint8_t)(len >> 8); hdr[4] = (uint8_t)len;
        tls_err e = io_send_all(c, hdr, REC_HDR);
        if (e != TLS_OK) return e;
        return io_send_all(c, data, len);
    }
    uint8_t seqbe[8];
    for (int i = 0; i < 8; i++) seqbe[i] = (uint8_t)(c->wseq >> (56 - 8 * i));
    uint8_t aad[13];
    memcpy(aad, seqbe, 8);
    aad[8] = type; aad[9] = 0x03; aad[10] = 0x03;
    aad[11] = (uint8_t)(len >> 8); aad[12] = (uint8_t)len;
    uint8_t iv[GCM_IV_LEN];
    memcpy(iv, c->siv, 4);
    memcpy(iv + 4, seqbe, 8);
    if (len + 8 + GCM_TAG_LEN > MAX_REC) return TLS_ERR_RANGE;
    uint8_t *payload = c->rec;
    memcpy(payload, seqbe, 8);
    uint8_t tag[GCM_TAG_LEN];
    if (gcm_seal(c->skey, iv, aad, sizeof(aad), data, len, payload + 8, tag) != GCM_OK)
        return TLS_ERR_RECORD;
    memcpy(payload + 8 + len, tag, GCM_TAG_LEN);
    size_t total = 8 + len + GCM_TAG_LEN;
    hdr[0] = type; hdr[1] = 0x03; hdr[2] = 0x03;
    hdr[3] = (uint8_t)(total >> 8); hdr[4] = (uint8_t)total;
    tls_err e = io_send_all(c, hdr, REC_HDR);
    if (e != TLS_OK) return e;
    e = io_send_all(c, payload, total);
    if (e != TLS_OK) return e;
    c->wseq++;
    return TLS_OK;
}

/* ---- 记录读：服务端方向用 ckey/civ ---- */
static tls_err rec_read(tls_server_ctx *c, uint8_t *type, uint8_t **body, size_t *body_len) {
    uint8_t hdr[REC_HDR];
    tls_err e = io_recv_exact(c, hdr, REC_HDR);
    if (e != TLS_OK) return e;
    if (hdr[1] != 0x03) return TLS_ERR_VERSION;
    size_t len = ((size_t)hdr[3] << 8) | hdr[4];
    if (len == 0 || len > MAX_REC) return TLS_ERR_RECORD;
    e = io_recv_exact(c, c->rec, len);
    if (e != TLS_OK) return e;
    *type = hdr[0];
    if (c->rdec_on) {
        if (len < 8 + GCM_TAG_LEN) return TLS_ERR_RECORD;
        uint8_t seqbe[8];
        for (int i = 0; i < 8; i++) seqbe[i] = (uint8_t)(c->rseq >> (56 - 8 * i));
        uint8_t iv[GCM_IV_LEN];
        memcpy(iv, c->civ, 4);
        memcpy(iv + 4, c->rec, 8);
        size_t ct_len = len - 8 - GCM_TAG_LEN;
        uint8_t aad[13];
        memcpy(aad, seqbe, 8);
        aad[8] = hdr[0]; aad[9] = 0x03; aad[10] = 0x03;
        aad[11] = (uint8_t)(ct_len >> 8); aad[12] = (uint8_t)ct_len;
        int r = gcm_open(c->ckey, iv, aad, sizeof(aad),
                         c->rec + 8, ct_len, c->rec + 8 + ct_len, c->plain);
        if (r != GCM_OK) return TLS_ERR_RECORD;
        c->rseq++;
        *body = c->plain;
        *body_len = ct_len;
    } else {
        *body = c->rec;
        *body_len = len;
    }
    return TLS_OK;
}

static tls_err hs_write(tls_server_ctx *c, uint8_t type, const uint8_t *body, size_t blen) {
    static uint8_t buf[MAX_HS];
    if (blen + 4 > sizeof(buf)) return TLS_ERR_RANGE;
    buf[0] = type;
    buf[1] = (uint8_t)(blen >> 16);
    buf[2] = (uint8_t)(blen >> 8);
    buf[3] = (uint8_t)blen;
    if (blen) memcpy(buf + 4, body, blen);
    c->tr_prev = c->tr;
    sha256_update(&c->tr, buf, blen + 4);
    return rec_write(c, CT_HANDSHAKE, buf, blen + 4);
}

static tls_err hs_read(tls_server_ctx *c, uint8_t *type, uint8_t **body, size_t *blen) {
    for (;;) {
        if (c->hs_len >= 4) {
            size_t want = ((size_t)c->hs[1] << 16) | ((size_t)c->hs[2] << 8) | c->hs[3];
            if (c->hs_len >= 4 + want) {
                *type = c->hs[0];
                *body = c->hs + 4;
                *blen = want;
                c->tr_prev = c->tr;
                sha256_update(&c->tr, c->hs, 4 + want);
                size_t rest = c->hs_len - (4 + want);
                if (rest) memmove(c->hs, c->hs + 4 + want, rest);
                c->hs_len = rest;
                return TLS_OK;
            }
        }
        uint8_t rt = 0, *rb = NULL;
        size_t rl = 0;
        tls_err e = rec_read(c, &rt, &rb, &rl);
        if (e != TLS_OK) return e;
        if (rt == CT_ALERT) return TLS_ERR_ALERT;
        if (rt == CT_HANDSHAKE) {
            if (c->hs_len + rl > sizeof(c->hs)) return TLS_ERR_RANGE;
            memcpy(c->hs + c->hs_len, rb, rl);
            c->hs_len += rl;
        }
    }
}

static int fill_random(uint8_t *p, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t got = fread(p, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
}

/* ---- ClientHello 解析 ---- */
static tls_err parse_client_hello(tls_server_ctx *c, const uint8_t *b, size_t blen) {
    if (blen < 38) return TLS_ERR_HANDSHAKE;
    size_t o = 0;
    uint16_t ver = (uint16_t)((b[0] << 8) | b[1]);
    if (ver != TLS_VER) return TLS_ERR_VERSION;
    o = 2;
    memcpy(c->crand, b + 2, 32);
    o = 34;
    size_t sid = b[o++];
    if (o + sid > blen) return TLS_ERR_HANDSHAKE;
    o += sid;
    if (o + 2 > blen) return TLS_ERR_HANDSHAKE;
    uint16_t cslen = (uint16_t)((b[o] << 8) | b[o + 1]);
    o += 2;
    if (o + cslen > blen) return TLS_ERR_HANDSHAKE;
    int want_cs = 0;
    for (size_t i = 0; i + 1 < cslen; i += 2) {
        uint16_t cs = (uint16_t)((b[o + i] << 8) | b[o + i + 1]);
        if (cs == CS_ECDHE_RSA_AES128_GCM_SHA256) want_cs = 1;
    }
    if (!want_cs) return TLS_ERR_CIPHER;     /* 不挑近似套件 */
    o += cslen;
    if (o >= blen) return TLS_ERR_HANDSHAKE;
    size_t comp = b[o++];
    if (o + comp > blen) return TLS_ERR_HANDSHAKE;
    o += comp;

    int has_x25519 = 0, has_rsa_sha256 = 0, alpn_matched = (c->alpn_want[0] == 0);
    if (o + 2 <= blen) {
        uint16_t extlen = (uint16_t)((b[o] << 8) | b[o + 1]);
        o += 2;
        if (o + extlen > blen) return TLS_ERR_HANDSHAKE;
        size_t end = o + extlen;
        while (o + 4 <= end) {
            uint16_t et = (uint16_t)((b[o] << 8) | b[o + 1]);
            o += 2;
            uint16_t el = (uint16_t)((b[o] << 8) | b[o + 1]);
            o += 2;
            if (o + el > end) return TLS_ERR_HANDSHAKE;
            const uint8_t *ev = b + o;
            if (et == 0x0000 && el >= 5) {              /* server_name */
                size_t q = 2;                            /* 跳过 list 长度 */
                if (q + 3 <= el) {
                    uint8_t ty = ev[q++];
                    uint16_t hl = (uint16_t)((ev[q] << 8) | ev[q + 1]);
                    q += 2;
                    if (ty == 0 && q + hl <= el) {
                        size_t n = hl < sizeof(c->sni) - 1 ? hl : sizeof(c->sni) - 1;
                        memcpy(c->sni, ev + q, n);
                        c->sni[n] = '\0';
                    }
                }
            } else if (et == 0x000a && el >= 4) {       /* supported_groups */
                for (size_t i = 2; i + 1 < el; i += 2) {
                    uint16_t g = (uint16_t)((ev[i] << 8) | ev[i + 1]);
                    if (g == 0x001d) has_x25519 = 1;
                }
            } else if (et == 0x000d && el >= 4) {       /* signature_algorithms */
                for (size_t i = 2; i + 1 < el; i += 2) {
                    uint16_t s = (uint16_t)((ev[i] << 8) | ev[i + 1]);
                    if (s == 0x0401) has_rsa_sha256 = 1;
                }
            } else if (et == 0x0010 && c->alpn_want[0]) {  /* ALPN */
                size_t p = 2;                            /* 跳过 list 长度 */
                size_t wl = strlen(c->alpn_want);
                while (p < el) {
                    uint8_t l = ev[p++];
                    if (p + l > el) break;
                    /* SEC-CMP:PUBLIC: ALPN 协议名匹配，公开协商值（ClientHello 中明文通告），非秘密 */
                    if (l == wl && memcmp(ev + p, c->alpn_want, l) == 0) {
                        alpn_matched = 1;
                        break;
                    }
                    p += l;
                }
            }
            o += el;
        }
    }
    if (!has_x25519)    return TLS_ERR_HANDSHAKE;   /* 客户端不支持 X25519 就无从派生 */
    if (!has_rsa_sha256) return TLS_ERR_HANDSHAKE;
    if (!alpn_matched)   return TLS_ERR_HANDSHAKE;  /* 我们要 h2 而对方没通告 */
    c->alpn_ok = alpn_matched && c->alpn_want[0];
    return TLS_OK;
}

static tls_err send_server_hello(tls_server_ctx *c) {
    uint8_t body[512];
    size_t  o = 0;
    put_u16(body + o, TLS_VER); o += 2;
    memcpy(body + o, c->srand, 32); o += 32;
    body[o++] = 0;                                   /* session_id 为空 */
    put_u16(body + o, CS_ECDHE_RSA_AES128_GCM_SHA256); o += 2;
    body[o++] = 0x00;                                /* compression = null */
    size_t ext_at = o; o += 2;
    if (c->alpn_ok) {
        size_t pl = strlen(c->alpn_want);
        put_u16(body + o, 0x0010); o += 2;
        size_t ex_at = o; o += 2;
        size_t ls_at = o; o += 2;
        body[o++] = (uint8_t)pl;
        if (o + pl > sizeof(body)) return TLS_ERR_RANGE;
        memcpy(body + o, c->alpn_want, pl); o += pl;
        put_u16(body + ls_at, (uint16_t)(o - ls_at - 2));
        put_u16(body + ex_at, (uint16_t)(o - ex_at - 2));
    }
    put_u16(body + o, 0xff01); o += 2;               /* renegotiation_info */
    put_u16(body + o, 1); o += 2;
    body[o++] = 0;
    put_u16(body + ext_at, (uint16_t)(o - ext_at - 2));
    return hs_write(c, HS_SERVER_HELLO, body, o);
}

static tls_err send_certificate(tls_server_ctx *c) {
    static uint8_t body[MAX_HS];
    size_t o = 3;
    for (int i = 0; i < c->chain_n; i++) {
        if (o + 3 + c->chain_len[i] > sizeof(body)) return TLS_ERR_RANGE;
        body[o]     = (uint8_t)(c->chain_len[i] >> 16);
        body[o + 1] = (uint8_t)(c->chain_len[i] >> 8);
        body[o + 2] = (uint8_t)(c->chain_len[i]);
        o += 3;
        memcpy(body + o, c->chain[i], c->chain_len[i]);
        o += c->chain_len[i];
    }
    size_t list_len = o - 3;
    body[0] = (uint8_t)(list_len >> 16);
    body[1] = (uint8_t)(list_len >> 8);
    body[2] = (uint8_t)(list_len);
    return hs_write(c, HS_CERTIFICATE, body, o);
}

static tls_err send_ske(tls_server_ctx *c) {
    uint8_t ske[1024];
    size_t  o = 0;
    ske[o++] = 0x03;                       /* named_curve */
    put_u16(ske + o, 0x001d); o += 2;      /* X25519 */
    ske[o++] = 32;
    memcpy(ske + o, c->pub, 32); o += 32;
    size_t params_len = o;                 /* 36 */

    /* 被签内容 = client_random || server_random || params */
    uint8_t tbs[32 + 32 + 64];
    size_t  tl = 0;
    memcpy(tbs + tl, c->crand, 32); tl += 32;
    memcpy(tbs + tl, c->srand, 32); tl += 32;
    memcpy(tbs + tl, ske, params_len); tl += params_len;

    uint8_t sig[BN_MAX_BYTES];
    size_t  slen = 0;
    if (rsa_sign_sha256(&c->key, tbs, tl, sig, sizeof(sig), &slen) != RSA_OK)
        return TLS_ERR_SKE;
    if (o + 4 + slen > sizeof(ske)) return TLS_ERR_RANGE;
    put_u16(ske + o, 0x0401); o += 2;      /* rsa_pkcs1_sha256 */
    put_u16(ske + o, (uint16_t)slen); o += 2;
    memcpy(ske + o, sig, slen); o += slen;
    return hs_write(c, HS_SKE, ske, o);
}

static tls_err derive_keys(tls_server_ctx *c) {
    uint8_t seed[64];
    memcpy(seed, c->crand, 32);
    memcpy(seed + 32, c->srand, 32);
    tls_prf_sha256(c->pms, 32, "master secret", 13, seed, 64, c->master, 48);
    uint8_t seed2[64];
    memcpy(seed2, c->srand, 32);
    memcpy(seed2 + 32, c->crand, 32);
    uint8_t kb[40];
    tls_prf_sha256(c->master, 48, "key expansion", 13, seed2, 64, kb, 40);
    memcpy(c->ckey, kb, 16);
    memcpy(c->skey, kb + 16, 16);
    memcpy(c->civ, kb + 32, 4);
    memcpy(c->siv, kb + 36, 4);
    return TLS_OK;
}

tls_err tls_server_accept(tls_server_ctx *c) {
    if (!c) return TLS_ERR_ARG;
    sha256_init(&c->tr);
    c->tr_prev = c->tr;
    c->handshaked = 0;
    c->alpn_ok = 0;

    uint8_t type = 0, *body = NULL;
    size_t  blen = 0;

    tls_err e = hs_read(c, &type, &body, &blen);
    if (e != TLS_OK) return e;
    if (type != HS_CLIENT_HELLO) return TLS_ERR_HANDSHAKE;
    e = parse_client_hello(c, body, blen);
    if (e != TLS_OK) return e;

    if (fill_random(c->srand, 32) != 0) return TLS_ERR_IO;
    if (x25519_generate_keypair(c->priv, c->pub) != X25519_OK) return TLS_ERR_MEM;

    e = send_server_hello(c);
    if (e != TLS_OK) return e;
    e = send_certificate(c);
    if (e != TLS_OK) return e;
    e = send_ske(c);
    if (e != TLS_OK) return e;
    e = hs_write(c, HS_SHD, NULL, 0);
    if (e != TLS_OK) return e;

    /* ClientKeyExchange */
    e = hs_read(c, &type, &body, &blen);
    if (e != TLS_OK) return e;
    if (type != HS_CKE || blen != 33 || body[0] != 32) return TLS_ERR_HANDSHAKE;
    if (x25519_shared(c->priv, body + 1, c->pms) != X25519_OK) return TLS_ERR_MEM;
    {
        /* 低阶点攻击的防御：共享值为全零时密钥可被任何人算出。
           不检查的话握手会一路走到成功，只是密钥等于公开。 */
        uint8_t z = 0;
        for (int i = 0; i < X25519_KEY_LEN; i++) z |= c->pms[i];
        if (z == 0) return TLS_ERR_HANDSHAKE;
    }
    derive_keys(c);

    /* 对端 CCS（明文记录） */
    for (;;) {
        uint8_t rt = 0, *rb = NULL;
        size_t  rl = 0;
        e = rec_read(c, &rt, &rb, &rl);
        if (e != TLS_OK) return e;
        if (rt == CT_CCS) break;
    }
    c->rdec_on = 1;
    c->rseq = 0;

    /* 对端 Finished */
    e = hs_read(c, &type, &body, &blen);
    if (e != TLS_OK) return e;
    if (type != HS_FINISHED || blen != 12) return TLS_ERR_HANDSHAKE;
    {
        uint8_t tr_hash[SHA256_DIGEST_LEN];
        sha256_ctx tmp = c->tr_prev;              /* 不含对端 Finished */
        sha256_final(&tmp, tr_hash);
        uint8_t want[12];
        tls_prf_sha256(c->master, 48, "client finished", 15, tr_hash, 32, want, 12);
        /* 常量时间：want 由主密钥派生，对方可控 body，逐字节早退即预言机 */
        if (crypto_constant_time_eq(want, body, 12) == 0) return TLS_ERR_FINISHED;
    }

    /* 我方 CCS + Finished */
    {
        uint8_t ccs[1] = { 1 };
        e = rec_write(c, CT_CCS, ccs, 1);
        if (e != TLS_OK) return e;
        c->enc_on = 1;
        c->wseq = 0;
    }
    {
        uint8_t tr_hash[SHA256_DIGEST_LEN];
        sha256_ctx tmp = c->tr;                   /* 已含对端 Finished */
        sha256_final(&tmp, tr_hash);
        uint8_t vd[12];
        tls_prf_sha256(c->master, 48, "server finished", 15, tr_hash, 32, vd, 12);
        e = hs_write(c, HS_FINISHED, vd, 12);
        if (e != TLS_OK) return e;
    }

    c->handshaked = 1;
    return TLS_OK;
}

tls_err tls_server_read(tls_server_ctx *c, uint8_t *buf, size_t cap, size_t *out_len) {
    if (!c || !buf || !out_len) return TLS_ERR_ARG;
    if (!c->handshaked) return TLS_ERR_HANDSHAKE;
    for (;;) {
        uint8_t rt = 0, *rb = NULL;
        size_t  rl = 0;
        tls_err e = rec_read(c, &rt, &rb, &rl);
        if (e != TLS_OK) return e;
        if (rt == CT_APPDATA) {
            if (rl > cap) return TLS_ERR_RANGE;
            memcpy(buf, rb, rl);
            *out_len = rl;
            return TLS_OK;
        }
        if (rt == CT_ALERT) return TLS_ERR_ALERT;
    }
}

tls_err tls_server_write(tls_server_ctx *c, const uint8_t *data, size_t len) {
    if (!c || !data) return TLS_ERR_ARG;
    if (!c->handshaked) return TLS_ERR_HANDSHAKE;
    return rec_write(c, CT_APPDATA, data, len);
}

tls_err tls_server_init(tls_server_ctx **out, const tls_server_config *cfg,
                        tls_send_cb send, tls_recv_cb recv, void *arg) {
    if (!out || !cfg || !send || !recv) return TLS_ERR_ARG;
    if (cfg->chain_n <= 0 || cfg->chain_n > X509_CHAIN_MAX) return TLS_ERR_ARG;
    if (!cfg->key) return TLS_ERR_ARG;

    tls_server_ctx *c = (tls_server_ctx *)calloc(1, sizeof(tls_server_ctx));
    if (!c) return TLS_ERR_MEM;
    for (int i = 0; i < cfg->chain_n; i++) {
        if (!cfg->chain[i] || cfg->chain_len[i] == 0 || cfg->chain_len[i] > X509_DER_MAX) {
            free(c);
            return TLS_ERR_ARG;
        }
        memcpy(c->chain[i], cfg->chain[i], cfg->chain_len[i]);
        c->chain_len[i] = cfg->chain_len[i];
    }
    c->chain_n = cfg->chain_n;
    c->key     = *cfg->key;
    c->has_key = 1;
    if (cfg->alpn) {
        size_t n = strlen(cfg->alpn);
        if (n >= sizeof(c->alpn_want)) { free(c); return TLS_ERR_RANGE; }
        memcpy(c->alpn_want, cfg->alpn, n + 1);
    }
    c->send = send;
    c->recv = recv;
    c->arg  = arg;
    *out = c;
    return TLS_OK;
}

void tls_server_free(tls_server_ctx *c) {
    if (!c) return;
    rsa_privkey_clear(&c->key);
    memset(c->master, 0, sizeof(c->master));
    memset(c->ckey, 0, sizeof(c->ckey));
    memset(c->skey, 0, sizeof(c->skey));
    free(c);
}

int tls_server_sni(const tls_server_ctx *c, char *out, size_t cap) {
    if (!c || !out || cap == 0) return -1;
    size_t n = strlen(c->sni);
    if (n + 1 > cap) return -1;
    memcpy(out, c->sni, n + 1);
    return (int)n;
}

int tls_server_alpn(const tls_server_ctx *c, char *out, size_t cap) {
    if (!c || !out || cap == 0) return -1;
    const char *s = c->alpn_ok ? c->alpn_want : "";
    size_t n = strlen(s);
    if (n + 1 > cap) return -1;
    memcpy(out, s, n + 1);
    return (int)n;
}

/* 自测：签一段数据再自己验回来。私钥解析错（如 PKCS#8/PKCS#1 搞反）时，
   这一步立刻暴露，不必等到握手失败再去猜是哪一层错。 */
tls_err tls_server_selftest_key(const rsa_privkey *k) {
    if (!k) return TLS_ERR_ARG;
    static const uint8_t msg[] = "dayanjing tls server key selftest";
    uint8_t sig[BN_MAX_BYTES];
    size_t  slen = 0;
    if (rsa_sign_sha256(k, msg, sizeof(msg) - 1, sig, sizeof(sig), &slen) != RSA_OK)
        return TLS_ERR_SKE;
    if (rsa_verify_sha256(&k->n, k->e, msg, sizeof(msg) - 1, sig, slen) != RSA_OK)
        return TLS_ERR_SKE;
    return TLS_OK;
}
