/* front.c — 域前置 HTTP 层实现 */
#include "front.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define FRONT_MAX_RESP 65536
#define FRONT_PATH_MAX 128

struct front_ctx {
    front_config cfg;
    tls_ctx     *tls;
    uint64_t     rng;
    char         last_path[FRONT_PATH_MAX];
    uint8_t      resp[FRONT_MAX_RESP];
    size_t       resp_len;
    int          connected;
    char         front_store[256];
    char         real_store[256];
    char         prefix_store[128];
    char         ca_store[256];
};

const char *front_errstr(front_err e) {
    switch (e) {
    case FRONT_OK:      return "ok";
    case FRONT_ERR_ARG: return "invalid config";
    case FRONT_ERR_MEM: return "out of memory";
    case FRONT_ERR_IO:  return "transport error";
    case FRONT_ERR_TLS: return "tls layer failed";
    case FRONT_ERR_HTTP:return "unsupported http response";
    case FRONT_ERR_RANGE:return "buffer too small";
    case FRONT_ERR_STATE:return "not connected";
    }
    return "unknown";
}

static uint64_t rng_next(front_ctx *c) {
    uint64_t x = c->rng;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    c->rng = x;
    return x;
}

static void gen_path(front_ctx *c) {
    /* 段数与段长都抖动：长度恒定会在链路上形成"等长请求"节拍，
       观察者不需要解密就能提取会话特征。 */
    static const char cs[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    size_t ncs = sizeof(cs) - 1;
    size_t segs = 1 + (rng_next(c) % 3);
    char p[FRONT_PATH_MAX];
    size_t o = 0;
    const char *pre = c->cfg.path_prefix ? c->cfg.path_prefix : "/";
    size_t pl = strlen(pre);
    if (pl >= sizeof(p)) pl = sizeof(p) - 1;
    memcpy(p, pre, pl);
    o = pl;
    for (size_t s = 0; s < segs; s++) {
        size_t len = 4 + (rng_next(c) % 9);      /* 4..12 */
        for (size_t i = 0; i < len && o + 2 < sizeof(p); i++)
            p[o++] = cs[rng_next(c) % ncs];
        if (s + 1 < segs && o + 2 < sizeof(p)) p[o++] = '-';
    }
    p[o] = '\0';
    memcpy(c->last_path, p, o + 1);
}

front_err front_init(front_ctx **out, const front_config *cfg,
                     tls_send_cb send, tls_recv_cb recv, void *arg) {
    if (!out || !cfg || !send || !recv) return FRONT_ERR_ARG;
    /* 两个域名必须各自显式给出。缺一个就拒绝 —— 缺失时若回退成"用同一个"，
       前置就退化成直通，而连接照样成功，测试全绿，能力归零。 */
    if (!cfg->front_domain || !cfg->real_host) return FRONT_ERR_ARG;
    size_t fl = strlen(cfg->front_domain);
    size_t rl = strlen(cfg->real_host);
    if (fl == 0 || rl == 0) return FRONT_ERR_ARG;
    if (fl >= sizeof(((front_ctx *)0)->front_store)) return FRONT_ERR_RANGE;
    if (rl >= sizeof(((front_ctx *)0)->real_store)) return FRONT_ERR_RANGE;

    front_ctx *c = (front_ctx *)calloc(1, sizeof(front_ctx));
    if (!c) return FRONT_ERR_MEM;
    memcpy(c->front_store, cfg->front_domain, fl + 1);
    memcpy(c->real_store, cfg->real_host, rl + 1);
    if (cfg->path_prefix) {
        size_t pl = strlen(cfg->path_prefix);
        if (pl >= sizeof(c->prefix_store)) { free(c); return FRONT_ERR_RANGE; }
        memcpy(c->prefix_store, cfg->path_prefix, pl + 1);
    } else {
        memcpy(c->prefix_store, "/", 2);
    }
    if (cfg->ca_path) {
        size_t cl = strlen(cfg->ca_path);
        if (cl >= sizeof(c->ca_store)) { free(c); return FRONT_ERR_RANGE; }
        memcpy(c->ca_store, cfg->ca_path, cl + 1);
    }
    c->cfg.front_domain = c->front_store;
    c->cfg.real_host    = c->real_store;
    c->cfg.path_prefix  = c->prefix_store;
    c->cfg.ca_path      = cfg->ca_path ? c->ca_store : NULL;
    c->cfg.verify       = cfg->verify;
    c->cfg.rng_seed     = cfg->rng_seed;

    c->rng = cfg->rng_seed ? cfg->rng_seed : 0x9e3779b97f4a7c15ULL;
    if (c->rng == 0) c->rng = 1;

    tls_config tc;
    memset(&tc, 0, sizeof(tc));
    tc.sni         = c->cfg.front_domain;     /* 观察者可见的是前置域 */
    tc.verify_host = c->cfg.front_domain;     /* 证书也是前置域的 */
    tc.ca_path     = c->cfg.ca_path;
    tc.verify      = c->cfg.verify;

    tls_err e = tls_client_init(&c->tls, &tc, send, recv, arg);
    if (e != TLS_OK) { free(c); return FRONT_ERR_TLS; }
    *out = c;
    return FRONT_OK;
}

void front_free(front_ctx *c) {
    if (!c) return;
    if (c->tls) tls_free(c->tls);
    free(c);
}

front_err front_connect(front_ctx *c) {
    if (!c) return FRONT_ERR_ARG;
    if (tls_handshake(c->tls) != TLS_OK) return FRONT_ERR_TLS;
    c->connected = 1;
    return FRONT_OK;
}

front_err front_build_request(front_ctx *c, const uint8_t *frame, size_t len,
                              uint8_t *out, size_t cap, size_t *out_len) {
    if (!c || !out || !out_len) return FRONT_ERR_ARG;
    if (frame && len > cap) return FRONT_ERR_RANGE;
    gen_path(c);
    int n = snprintf((char *)out, cap,
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        c->last_path, c->cfg.real_host, len);
    if (n < 0 || (size_t)n >= cap) return FRONT_ERR_RANGE;
    size_t total = (size_t)n;
    if (frame && len) {
        if (total + len > cap) return FRONT_ERR_RANGE;
        memcpy(out + total, frame, len);
        total += len;
    }
    *out_len = total;
    return FRONT_OK;
}

front_err front_send(front_ctx *c, const uint8_t *frame, size_t len) {
    if (!c || !c->connected) return FRONT_ERR_STATE;
    static uint8_t req[FRONT_MAX_RESP];
    size_t rlen = 0;
    front_err fe = front_build_request(c, frame, len, req, sizeof(req), &rlen);
    if (fe != FRONT_OK) return fe;
    if (tls_write(c->tls, req, rlen) != TLS_OK) return FRONT_ERR_TLS;
    return FRONT_OK;
}

/* 从累积缓冲里解析出一个完整 HTTP 响应体 */
static front_err parse_response(front_ctx *c, uint8_t *buf, size_t cap, size_t *out_len) {
    const uint8_t *p = c->resp;
    size_t len = c->resp_len;
    const uint8_t *hend = NULL;
    for (size_t i = 0; i + 3 < len; i++) {
        if (p[i] == '\r' && p[i+1] == '\n' && p[i+2] == '\r' && p[i+3] == '\n') {
            hend = p + i + 4;
            break;
        }
    }
    if (!hend) return FRONT_ERR_HTTP;                  /* 头还没到齐 */

    /* 找 Content-Length */
    long cl = -1;
    int chunked = 0;
    {
        const uint8_t *hp = p;
        size_t hl = (size_t)(hend - p);
        for (size_t i = 0; i + 15 < hl; i++) {
            if ((hp[i] == 'C' || hp[i] == 'c') && !memcmp(hp + i, "Content-Length:", 15)) {
                size_t j = i + 15;
                while (j < hl && (hp[j] == ' ' || hp[j] == '\t')) j++;
                long v = 0;
                int any = 0;
                while (j < hl && hp[j] >= '0' && hp[j] <= '9') { v = v * 10 + (hp[j] - '0'); j++; any = 1; }
                if (any) cl = v;
            }
            if (!memcmp(hp + i, "Transfer-Encoding:", 18)) {
                size_t j = i + 18;
                while (j < hl && (hp[j] == ' ' || hp[j] == '\t')) j++;
                if (j + 7 <= hl && !memcmp(hp + j, "chunked", 7)) chunked = 1;
            }
        }
    }
    if (chunked) return FRONT_ERR_HTTP;                /* 明确不支持，不静默截断 */
    size_t hlen = (size_t)(hend - p);
    size_t body_avail = len - hlen;
    if (cl < 0) {
        /* 无 Content-Length：返回当前已收到的全部 body */
        if (body_avail == 0) return FRONT_ERR_IO;
        if (body_avail > cap) return FRONT_ERR_RANGE;
        memcpy(buf, hend, body_avail);
        *out_len = body_avail;
        c->resp_len = 0;
        return FRONT_OK;
    }
    if (body_avail < (size_t)cl) return FRONT_ERR_HTTP;   /* body 未到齐 */
    if ((size_t)cl > cap) return FRONT_ERR_RANGE;
    memcpy(buf, hend, (size_t)cl);
    *out_len = (size_t)cl;
    /* 剩余数据前移（可能含下一个响应） */
    size_t consumed = hlen + (size_t)cl;
    if (consumed < len) memmove(c->resp, c->resp + consumed, len - consumed);
    c->resp_len = len - consumed;
    return FRONT_OK;
}

front_err front_recv(front_ctx *c, uint8_t *buf, size_t cap, size_t *out_len) {
    if (!c || !buf || !out_len) return FRONT_ERR_ARG;
    if (!c->connected) return FRONT_ERR_STATE;
    for (int i = 0; i < 64; i++) {
        front_err fe = parse_response(c, buf, cap, out_len);
        if (fe == FRONT_OK) return FRONT_OK;
        if (fe == FRONT_ERR_RANGE) return fe;
        /* 数据不够，继续读 */
        if (c->resp_len >= sizeof(c->resp)) return FRONT_ERR_RANGE;
        uint8_t tmp[8192];
        size_t got = 0;
        if (tls_read(c->tls, tmp, sizeof(tmp), &got) != TLS_OK) return FRONT_ERR_TLS;
        if (got == 0) return FRONT_ERR_IO;
        if (c->resp_len + got > sizeof(c->resp)) return FRONT_ERR_RANGE;
        memcpy(c->resp + c->resp_len, tmp, got);
        c->resp_len += got;
    }
    return FRONT_ERR_HTTP;
}

int front_last_path(const front_ctx *c, char *out, size_t cap) {
    if (!c || !out || cap == 0) return -1;
    size_t n = strlen(c->last_path);
    if (n + 1 > cap) return -1;
    memcpy(out, c->last_path, n + 1);
    return (int)n;
}
