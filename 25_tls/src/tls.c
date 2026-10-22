/* tls.c — TLS 1.2 客户端实现
 *
 * 关键设计点（都是踩过才知道要这么写）：
 *  1. transcript 不可回退 —— 校验对端 Finished 需要"不含它自身"的摘要，
 *     因此在每条握手消息写入摘要前先快照 sha256_ctx（tr_prev）。
 *  2. AEAD 记录的 explicit nonce 随记录携带（8 字节，在密文之前），
 *     IV = key_block 里的 salt(4) || explicit(8)，AAD 长度字段是明文长度。
 *  3. IO 全走回调：调用方可以是 socket、代理隧道、内存管道或域前置层。
 *  4. send/recv 回调返回实际字节数，<=0 视为失败；本层循环到满足长度。
 */
#include "tls.h"
#include "crypto_gcm.h"
#include "crypto_hash.h"
#include "crypto_x25519.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define TLS_VER          0x0303
#define CT_CCS           20
#define CT_ALERT         21
#define CT_HANDSHAKE     22
#define CT_APPDATA       23
#define CS_ECDHE_RSA_AES128_GCM_SHA256 0xC02F

#define HS_CLIENT_HELLO   1
#define HS_SERVER_HELLO   2
#define HS_CERTIFICATE   11
#define HS_SKE           12
#define HS_SHD           14
#define HS_CKE           16
#define HS_FINISHED      20

#define REC_HDR   5
#define MAX_REC   18432
#define MAX_HS    65536

const char *tls_errstr(tls_err e) {
    switch (e) {
    case TLS_OK:         return "ok";
    case TLS_ERR_ARG:    return "invalid argument";
    case TLS_ERR_MEM:    return "out of memory";
    case TLS_ERR_IO:     return "transport error";
    case TLS_ERR_RECORD: return "malformed record";
    case TLS_ERR_ALERT:  return "fatal alert received";
    case TLS_ERR_VERSION:return "unsupported version";
    case TLS_ERR_CIPHER: return "server selected unsupported cipher suite";
    case TLS_ERR_HANDSHAKE: return "malformed handshake";
    case TLS_ERR_SKE:    return "ServerKeyExchange signature invalid";
    case TLS_ERR_CERT:   return "certificate verification failed";
    case TLS_ERR_FINISHED: return "peer Finished verification failed";
    case TLS_ERR_RANGE:  return "buffer too small";
    case TLS_ERR_TRUNC:  return "truncated data";
    }
    return "unknown";
}

struct tls_ctx {
    tls_config   cfg;
    tls_send_cb  send;
    tls_recv_cb  recv;
    void        *arg;

    uint8_t  crand[32], srand[32];
    uint8_t  priv[X25519_KEY_LEN], pub[X25519_KEY_LEN];
    uint8_t  pms[X25519_KEY_LEN];

    sha256_ctx  tr;        /* transcript（含当前消息） */
    sha256_ctx  tr_prev;   /* 写入当前消息之前的快照 */
    uint8_t     master[48];
    uint8_t     ckey[16], skey[16], civ[4], siv[4];
    uint64_t    wseq, rseq;
    int         enc_on;     /* 发送方向已加密 */
    int         rdec_on;    /* 接收方向已加密 —— 必须分开跟踪 */
    int         peer_done;  /* 已校验对端 Finished */

    uint8_t  rec[MAX_REC];
    uint8_t  hs[MAX_HS];
    size_t   hs_len;
    uint8_t  plain[MAX_REC];

    x509_cert chain[X509_CHAIN_MAX];
    int       chain_n;
    /* 证书必须自己持有一份拷贝。
       踩过的坑：x509_cert 里的 tbs / sigval / der 都是指向握手缓冲的指针，
       而 hs_read 每消费一条消息就 memmove 覆盖缓冲区 —— 等收到 SHD 再去
       校验证书，那段字节早被 SKE 覆盖，表现为"签名/签发者莫名其妙不对"，
       且与消息长度、到达时机相关，极难复现。 */
    uint8_t   certbuf[X509_CHAIN_MAX][X509_DER_MAX];
    size_t    certlen[X509_CHAIN_MAX];
    x509_store anchors;
    int       anchors_loaded;

    char sni[256];
    char alpn[64];   /* ALPN 通告的协议名，如 "h2"；空串 = 不发该扩展 */
    int  handshaked;
};

/* ---- PRF (TLS 1.2 P_SHA256) ---- */
static void prf_sha256(const uint8_t *secret, size_t slen,
                       const char *label, size_t label_len,
                       const uint8_t *seed, size_t seed_len,
                       uint8_t *out, size_t out_len) {
    uint8_t a[HMAC_SHA256_LEN];
    uint8_t buf[HMAC_SHA256_LEN + 512];
    size_t  seed_total = label_len + seed_len;
    if (seed_total > 512) return;
    memcpy(buf, label, label_len);
    memcpy(buf + label_len, seed, seed_len);
    hmac_sha256(secret, slen, buf, seed_total, a);
    size_t done = 0;
    while (done < out_len) {
        size_t cp = out_len - done > HMAC_SHA256_LEN ? HMAC_SHA256_LEN : out_len - done;
        memcpy(buf, a, HMAC_SHA256_LEN);
        memcpy(buf + HMAC_SHA256_LEN, label, label_len);
        memcpy(buf + HMAC_SHA256_LEN + label_len, seed, seed_len);
        uint8_t h[HMAC_SHA256_LEN];
        hmac_sha256(secret, slen, buf, HMAC_SHA256_LEN + seed_total, h);
        memcpy(out + done, h, cp);
        done += cp;
        if (done < out_len) hmac_sha256(secret, slen, a, HMAC_SHA256_LEN, a);
    }
}

/* ---- IO ---- */
static tls_err io_send_all(tls_ctx *c, const uint8_t *d, size_t n) {
    size_t off = 0;
    while (off < n) {
        int r = c->send(c->arg, d + off, n - off);
        if (r <= 0) return TLS_ERR_IO;
        off += (size_t)r;
    }
    return TLS_OK;
}

static tls_err io_recv_exact(tls_ctx *c, uint8_t *d, size_t n) {
    size_t got = 0;
    while (got < n) {
        int r = c->recv(c->arg, d + got, n - got);
        if (r <= 0) return TLS_ERR_IO;
        got += (size_t)r;
    }
    return TLS_OK;
}

/* ---- 记录写 ---- */
static tls_err rec_write(tls_ctx *c, uint8_t type, const uint8_t *data, size_t len) {
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
    memcpy(iv, c->civ, 4);
    memcpy(iv + 4, seqbe, 8);
    if (len + 8 + GCM_TAG_LEN > MAX_REC) return TLS_ERR_RANGE;
    uint8_t *payload = c->rec;                 /* 复用发送侧缓冲 */
    memcpy(payload, seqbe, 8);
    uint8_t tag[GCM_TAG_LEN];
    if (gcm_seal(c->ckey, iv, aad, sizeof(aad), data, len, payload + 8, tag) != GCM_OK)
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

/* ---- 记录读 ---- */
static tls_err rec_read(tls_ctx *c, uint8_t *type, uint8_t **body, size_t *body_len) {
    uint8_t hdr[REC_HDR];
    tls_err e = io_recv_exact(c, hdr, REC_HDR);
    if (e != TLS_OK) return e;
    if (hdr[1] != 0x03) return TLS_ERR_VERSION;
    size_t len = ((size_t)hdr[3] << 8) | hdr[4];
    if (len == 0 || len > MAX_REC) return TLS_ERR_RECORD;
    e = io_recv_exact(c, c->rec, len);
    if (e != TLS_OK) return e;
    *type = hdr[0];
    /* 用 rdec_on 而不是 enc_on：两个方向的加密是先后独立的。
       踩过的坑：发送 CCS 后就置 enc_on=1，若接收也看这个标志，
       会把对端那条【明文】CCS 记录拿去 GCM 解密，必然报 malformed record，
       而且看起来像"密钥算错了"，极易误导排查方向。 */
    if (c->rdec_on) {
        if (len < 8 + GCM_TAG_LEN) return TLS_ERR_RECORD;
        uint8_t seqbe[8];
        for (int i = 0; i < 8; i++) seqbe[i] = (uint8_t)(c->rseq >> (56 - 8 * i));
        uint8_t iv[GCM_IV_LEN];
        memcpy(iv, c->siv, 4);
        memcpy(iv + 4, c->rec, 8);
        size_t ct_len = len - 8 - GCM_TAG_LEN;
        uint8_t aad[13];
        memcpy(aad, seqbe, 8);
        aad[8] = hdr[0]; aad[9] = 0x03; aad[10] = 0x03;
        aad[11] = (uint8_t)(ct_len >> 8); aad[12] = (uint8_t)ct_len;
        int r = gcm_open(c->skey, iv, aad, sizeof(aad),
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

/* ---- 握手消息写 ---- */
static tls_err hs_write(tls_ctx *c, uint8_t type, const uint8_t *body, size_t blen) {
    static uint8_t buf[MAX_HS];
    if (blen + 4 > sizeof(buf)) return TLS_ERR_RANGE;
    buf[0] = type;
    buf[1] = (uint8_t)(blen >> 16);
    buf[2] = (uint8_t)(blen >> 8);
    buf[3] = (uint8_t)blen;
    memcpy(buf + 4, body, blen);
    c->tr_prev = c->tr;                 /* 快照：不含本条 */
    sha256_update(&c->tr, buf, blen + 4);
    return rec_write(c, CT_HANDSHAKE, buf, blen + 4);
}

/* ---- 握手消息读 ---- */
static tls_err hs_read(tls_ctx *c, uint8_t *type, uint8_t **body, size_t *blen) {
    for (;;) {
        if (c->hs_len >= 4) {
            size_t want = ((size_t)c->hs[1] << 16) | ((size_t)c->hs[2] << 8) | c->hs[3];
            if (c->hs_len >= 4 + want) {
                *type = c->hs[0];
                *body = c->hs + 4;
                *blen = want;
                c->tr_prev = c->tr;      /* 快照：不含本条 */
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

static size_t put_u16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; return 2; }

static tls_err send_client_hello(tls_ctx *c) {
    uint8_t body[512];
    size_t o = 0;
    put_u16(body + o, TLS_VER); o += 2;
    memcpy(body + o, c->crand, 32); o += 32;
    body[o++] = 0;
    put_u16(body + o, 2); o += 2;
    put_u16(body + o, CS_ECDHE_RSA_AES128_GCM_SHA256); o += 2;
    body[o++] = 1; body[o++] = 0;

    size_t ext_at = o; o += 2;

    /* server_name */
    put_u16(body + o, 0x0000); o += 2;
    size_t sn_len_at = o; o += 2;
    size_t list_at = o; o += 2;
    body[o++] = 0x00;
    size_t hlen_at = o; put_u16(body + o, 0); o += 2;
    size_t hl = strlen(c->sni);
    if (hl > 255 || o + hl > sizeof(body)) return TLS_ERR_RANGE;
    memcpy(body + o, c->sni, hl); o += hl;
    put_u16(body + hlen_at, (uint16_t)hl);
    put_u16(body + list_at, (uint16_t)(o - list_at - 2));
    put_u16(body + sn_len_at, (uint16_t)(o - sn_len_at - 2));

    /* supported_groups: X25519 */
    put_u16(body + o, 0x000a); o += 2;
    put_u16(body + o, 4); o += 2;
    put_u16(body + o, 2); o += 2;
    put_u16(body + o, 0x001d); o += 2;

    /* ec_point_formats */
    put_u16(body + o, 0x000b); o += 2;
    put_u16(body + o, 2); o += 2;
    body[o++] = 1; body[o++] = 0;

    /* signature_algorithms: rsa_pkcs1_sha256 */
    put_u16(body + o, 0x000d); o += 2;
    put_u16(body + o, 4); o += 2;
    put_u16(body + o, 2); o += 2;
    put_u16(body + o, 0x0401); o += 2;

    /* application_layer_protocol_negotiation (ALPN, RFC 7301)
     *
     * 域前置 + HTTP/2 的前提：h2 只能在 TLS 握手阶段通过 ALPN 协商出来。
     * 不发 ALPN 的话，对端按"未协商则降级"处理，回落到 HTTP/1.1，
     * 于是客户端发 h2 preface 之后等到的根本不是 SETTINGS ——
     * 表现为"TLS 握手成功但 h2 握手失败"，很容易被误判成前置域不支持 h2。
     */
    if (c->alpn[0]) {
        size_t pl = strlen(c->alpn);
        if (pl > 255) return TLS_ERR_RANGE;
        put_u16(body + o, 0x0010); o += 2;
        size_t ex_at = o; o += 2;
        size_t ls_at = o; o += 2;                 /* protocol_name_list 长度 */
        body[o++] = (uint8_t)pl;
        if (o + pl > sizeof(body)) return TLS_ERR_RANGE;
        memcpy(body + o, c->alpn, pl); o += pl;
        put_u16(body + ls_at, (uint16_t)(o - ls_at - 2));
        put_u16(body + ex_at, (uint16_t)(o - ex_at - 2));
    }

    /* renegotiation_info */
    put_u16(body + o, 0xff01); o += 2;
    put_u16(body + o, 1); o += 2;
    body[o++] = 0;

    put_u16(body + ext_at, (uint16_t)(o - ext_at - 2));
    return hs_write(c, HS_CLIENT_HELLO, body, o);
}

static tls_err verify_cert_chain(tls_ctx *c) {
    if (!c->cfg.verify) return TLS_OK;
    if (c->chain_n <= 0) return TLS_ERR_CERT;
    if (!c->anchors_loaded) {
        if (!c->cfg.ca_path) return TLS_ERR_CERT;
        if (x509_store_load_pem(&c->anchors, c->cfg.ca_path) != X509_OK) return TLS_ERR_CERT;
        c->anchors_loaded = 1;
    }
    int64_t now = (int64_t)time(NULL);
    const char *host = c->cfg.verify_host ? c->cfg.verify_host : c->sni;
    x509_err ve = x509_verify_chain(c->chain, c->chain_n, &c->anchors, host, now);
    if (ve != X509_OK) {
        /* 细分原因必须可见：只报 "certificate verification failed" 时，
           "解析失败""签名错""主机名不符""有效期外"完全无法区分。 */
        fprintf(stderr, "[tls] cert verify: %s (chain=%d, anchors=%d, leaf_cn=%s, san0=%s)\n",
                x509_errstr(ve), c->chain_n, c->anchors.n,
                c->chain[0].cn, c->chain[0].san_n > 0 ? c->chain[0].san[0] : "(none)");
        /* 需要对比"握手收到的链"与"本地保存的链"时，设 TLS_DUMP=<路径> 导出 */
        const char *dump = getenv("TLS_DUMP");
        if (dump && c->chain_n > 0) {
            FILE *f = fopen(dump, "wb");
            if (f) {
                for (int i = 0; i < c->chain_n; i++)
                    fwrite(c->chain[i].der, 1, c->chain[i].der_len, f);
                fclose(f);
            }
        }
    }
    return ve == X509_OK ? TLS_OK : TLS_ERR_CERT;
}

tls_err tls_handshake(tls_ctx *c) {
    if (!c) return TLS_ERR_ARG;
    sha256_init(&c->tr);
    c->tr_prev = c->tr;
    c->handshaked = 0;

    tls_err e = send_client_hello(c);
    if (e != TLS_OK) return e;

    uint8_t type = 0, *body = NULL; size_t blen = 0;

    /* ServerHello */
    e = hs_read(c, &type, &body, &blen);
    if (e != TLS_OK) return e;
    if (type != HS_SERVER_HELLO || blen < 35) return TLS_ERR_HANDSHAKE;
    if (((size_t)body[0] << 8 | body[1]) != TLS_VER) return TLS_ERR_VERSION;
    memcpy(c->srand, body + 2, 32);
    size_t o = 34;
    if (o >= blen) return TLS_ERR_HANDSHAKE;
    o += body[o] + 1;                       /* session_id */
    if (o + 3 > blen) return TLS_ERR_HANDSHAKE;
    uint16_t cs = (uint16_t)((body[o] << 8) | body[o + 1]); o += 2;
    if (cs != CS_ECDHE_RSA_AES128_GCM_SHA256) return TLS_ERR_CIPHER;
    if (body[o++] != 0x00) return TLS_ERR_HANDSHAKE;

    /* Certificate */
    e = hs_read(c, &type, &body, &blen);
    if (e != TLS_OK) return e;
    if (type != HS_CERTIFICATE) return TLS_ERR_HANDSHAKE;
    {
        if (blen < 3) return TLS_ERR_HANDSHAKE;
        size_t list_len = ((size_t)body[0] << 16) | ((size_t)body[1] << 8) | body[2];
        if (list_len != blen - 3) return TLS_ERR_HANDSHAKE;
        size_t p = 3;
        c->chain_n = 0;
        while (p + 3 <= blen) {
            size_t clen = ((size_t)body[p] << 16) | ((size_t)body[p+1] << 8) | body[p+2];
            p += 3;
            if (p + clen > blen) return TLS_ERR_HANDSHAKE;
            if (c->chain_n >= X509_CHAIN_MAX) return TLS_ERR_RANGE;
            if (clen > X509_DER_MAX) return TLS_ERR_RANGE;
            memcpy(c->certbuf[c->chain_n], body + p, clen);
            c->certlen[c->chain_n] = clen;
            if (x509_parse(c->certbuf[c->chain_n], clen, &c->chain[c->chain_n]) != X509_OK)
                return TLS_ERR_CERT;
            c->chain_n++;
            p += clen;
        }
    }

    /* ServerKeyExchange */
    uint8_t peer_pub[X25519_KEY_LEN];
    e = hs_read(c, &type, &body, &blen);
    if (e != TLS_OK) return e;
    if (type != HS_SKE) return TLS_ERR_HANDSHAKE;
    {
        if (blen < 6) return TLS_ERR_HANDSHAKE;
        size_t p = 0;
        if (body[p++] != 0x03) return TLS_ERR_HANDSHAKE;
        uint16_t curve = (uint16_t)((body[p] << 8) | body[p+1]); p += 2;
        if (curve != 0x001d) return TLS_ERR_HANDSHAKE;
        size_t plen = body[p++];
        if (plen != 32 || p + 32 + 4 > blen) return TLS_ERR_HANDSHAKE;
        memcpy(peer_pub, body + p, 32); p += 32;
        size_t params_len = p;
        uint16_t sigalg = (uint16_t)((body[p] << 8) | body[p+1]); p += 2;
        if (sigalg != 0x0401) return TLS_ERR_HANDSHAKE;
        size_t siglen = (size_t)((body[p] << 8) | body[p+1]); p += 2;
        if (p + siglen != blen) return TLS_ERR_HANDSHAKE;

        uint8_t h[SHA256_DIGEST_LEN];
        sha256_ctx sc;
        sha256_init(&sc);
        sha256_update(&sc, c->crand, 32);
        sha256_update(&sc, c->srand, 32);
        sha256_update(&sc, body, params_len);
        sha256_final(&sc, h);

        if (!c->chain[0].has_rsa) return TLS_ERR_SKE;
        bn_t s, m;
        bn_from_be(&s, body + p, siglen);
        if (bn_cmp(&s, &c->chain[0].n) >= 0) return TLS_ERR_SKE;
        if (bn_modpow_u32(&m, &s, c->chain[0].e, &c->chain[0].n) != BN_OK) return TLS_ERR_SKE;
        int nbits = bn_bitlen(&c->chain[0].n);
        size_t k = (size_t)((nbits + 7) / 8);
        if (k < 32 || k > BN_MAX_BYTES) return TLS_ERR_SKE;
        uint8_t em[BN_MAX_BYTES];
        memset(em, 0, sizeof(em));
        bn_to_be(&m, em + (sizeof(em) - k), k);
        const uint8_t *q = em + (sizeof(em) - k);
        static const uint8_t DI[] = {
            0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,
            0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
        };
        if (q[0] != 0x00 || q[1] != 0x01) return TLS_ERR_SKE;
        size_t i = 2;
        while (i < k && q[i] == 0xff) i++;
        if (i < 10 || i >= k || q[i] != 0x00) return TLS_ERR_SKE;
        i++;
        if (k - i != sizeof(DI) + SHA256_DIGEST_LEN) return TLS_ERR_SKE;
        if (memcmp(q + i, DI, sizeof(DI)) != 0) return TLS_ERR_SKE;
        if (memcmp(q + i + sizeof(DI), h, SHA256_DIGEST_LEN) != 0) return TLS_ERR_SKE;
    }

    /* ServerHelloDone */
    e = hs_read(c, &type, &body, &blen);
    if (e != TLS_OK) return e;
    if (type != HS_SHD) return TLS_ERR_HANDSHAKE;

    e = verify_cert_chain(c);
    if (e != TLS_OK) return e;

    /* ClientKeyExchange */
    if (x25519_generate_keypair(c->priv, c->pub) != X25519_OK) return TLS_ERR_MEM;
    {
        uint8_t cke[33];
        cke[0] = 32;
        memcpy(cke + 1, c->pub, 32);
        e = hs_write(c, HS_CKE, cke, 33);
        if (e != TLS_OK) return e;
    }
    if (x25519_shared(c->priv, peer_pub, c->pms) != X25519_OK) return TLS_ERR_MEM;

    uint8_t seed[64];
    memcpy(seed, c->crand, 32);
    memcpy(seed + 32, c->srand, 32);
    prf_sha256(c->pms, 32, "master secret", 13, seed, 64, c->master, 48);
    uint8_t seed2[64];
    memcpy(seed2, c->srand, 32);
    memcpy(seed2 + 32, c->crand, 32);
    uint8_t kb[40];
    prf_sha256(c->master, 48, "key expansion", 13, seed2, 64, kb, 40);
    memcpy(c->ckey, kb, 16);
    memcpy(c->skey, kb + 16, 16);
    memcpy(c->civ, kb + 32, 4);
    memcpy(c->siv, kb + 36, 4);

    {
        uint8_t ccs[1] = { 1 };
        e = rec_write(c, CT_CCS, ccs, 1);
        if (e != TLS_OK) return e;
        c->enc_on = 1;
        c->wseq = 0;
    }

    {
        uint8_t tr_hash[SHA256_DIGEST_LEN];
        sha256_ctx tmp = c->tr;              /* 此刻不含 client Finished */
        sha256_final(&tmp, tr_hash);
        uint8_t vd[12];
        prf_sha256(c->master, 48, "client finished", 15, tr_hash, 32, vd, 12);
        e = hs_write(c, HS_FINISHED, vd, 12);
        if (e != TLS_OK) return e;
    }

    /* 对端 CCS（明文记录）+ Finished */
    {
        uint8_t rt = 0, *rb = NULL; size_t rl = 0;
        for (;;) {
            e = rec_read(c, &rt, &rb, &rl);
            if (e != TLS_OK) return e;
            if (rt == CT_CCS) break;
        }
        (void)rb; (void)rl;
        c->rdec_on = 1;
        c->rseq = 0;
        e = hs_read(c, &type, &body, &blen);
        if (e != TLS_OK) return e;
        if (type != HS_FINISHED || blen != 12) return TLS_ERR_HANDSHAKE;
        uint8_t tr_hash[SHA256_DIGEST_LEN];
        sha256_ctx tmp = c->tr_prev;         /* 不含对端 Finished */
        sha256_final(&tmp, tr_hash);
        uint8_t want[12];
        prf_sha256(c->master, 48, "server finished", 15, tr_hash, 32, want, 12);
        if (memcmp(want, body, 12) != 0) return TLS_ERR_FINISHED;
        c->peer_done = 1;
    }

    c->handshaked = 1;
    return TLS_OK;
}

tls_err tls_write(tls_ctx *c, const uint8_t *data, size_t len) {
    if (!c || !c->handshaked) return TLS_ERR_ARG;
    return rec_write(c, CT_APPDATA, data, len);
}

tls_err tls_read(tls_ctx *c, uint8_t *buf, size_t cap, size_t *out_len) {
    if (!c || !buf || !out_len) return TLS_ERR_ARG;
    for (;;) {
        uint8_t rt = 0, *rb = NULL; size_t rl = 0;
        tls_err e = rec_read(c, &rt, &rb, &rl);
        if (e != TLS_OK) return e;
        if (rt == CT_APPDATA) {
            if (rl > cap) return TLS_ERR_RANGE;
            memcpy(buf, rb, rl);
            *out_len = rl;
            return TLS_OK;
        }
        if (rt == CT_ALERT) return TLS_ERR_ALERT;
        /* handshake（如 NewSessionTicket）/ 其它：忽略继续 */
    }
}

static int fill_random(uint8_t *p, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t got = fread(p, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
}

tls_err tls_client_init(tls_ctx **out, const tls_config *cfg,
                        tls_send_cb send, tls_recv_cb recv, void *arg) {
    if (!out || !send || !recv) return TLS_ERR_ARG;
    tls_ctx *c = (tls_ctx *)calloc(1, sizeof(tls_ctx));
    if (!c) return TLS_ERR_MEM;
    if (cfg) {
        c->cfg = *cfg;
        if (cfg->sni) {
            size_t n = strlen(cfg->sni);
            if (n >= sizeof(c->sni)) { free(c); return TLS_ERR_RANGE; }
            memcpy(c->sni, cfg->sni, n + 1);
        }
        if (cfg->alpn) {
            size_t n = strlen(cfg->alpn);
            if (n >= sizeof(c->alpn)) { free(c); return TLS_ERR_RANGE; }
            memcpy(c->alpn, cfg->alpn, n + 1);
        }
    }
    c->send = send;
    c->recv = recv;
    c->arg  = arg;
    if (fill_random(c->crand, 32) != 0) { free(c); return TLS_ERR_IO; }
    *out = c;
    return TLS_OK;
}

void tls_free(tls_ctx *c) {
    if (!c) return;
    /* 信任库是堆分配的（见 x509_store），不释放就是每次握手泄漏一份 */
    x509_store_free(&c->anchors);
    free(c);
}

int tls_sni_echo(const tls_ctx *c, char *out, size_t cap) {
    if (!c || !out || cap == 0) return -1;
    size_t n = strlen(c->sni);
    if (n + 1 > cap) return -1;
    memcpy(out, c->sni, n + 1);
    return (int)n;
}
