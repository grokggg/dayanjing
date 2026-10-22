/* front.c — 域前置 HTTP 层实现 */
#include "front.h"
#include "h2.h"
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
    /* --- HTTP/2 状态 --- */
    int          http2;
    uint32_t     next_stream_id;   /* 客户端流号恒为奇数，从 1 起 */
    int          h2_settings_done; /* 收到对端 SETTINGS 并已 ACK */
    uint8_t      h2_in[FRONT_MAX_RESP];
    size_t       h2_in_len;
    int          last_status;
    /* --- 退避状态 --- */
    uint64_t     rtt_ewma_us;      /* 0 = 尚无样本 */
    int          fail_streak;
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
    c->cfg.http2        = cfg->http2 ? 1 : 0;

    c->rng = cfg->rng_seed ? cfg->rng_seed : 0x9e3779b97f4a7c15ULL;
    if (c->rng == 0) c->rng = 1;
    c->http2          = c->cfg.http2;
    c->next_stream_id = 1;

    tls_config tc;
    memset(&tc, 0, sizeof(tc));
    tc.sni         = c->cfg.front_domain;     /* 观察者可见的是前置域 */
    tc.verify_host = c->cfg.front_domain;     /* 证书也是前置域的 */
    tc.ca_path     = c->cfg.ca_path;
    tc.verify      = c->cfg.verify;
    /* h2 模式必须在 ClientHello 里通告 ALPN "h2"，否则对端降级到 HTTP/1.1，
       之后发 h2 preface 只会等来非 SETTINGS 数据，握手必然失败。
       h1 模式不发 ALPN（发了反而多一个可指纹化的扩展）。 */
    tc.alpn        = c->http2 ? "h2" : NULL;
    /* h2 模式必须在 ClientHello 里通告 ALPN "h2"，否则对端降级到 HTTP/1.1，
       之后发 h2 preface 只会等来非 SETTINGS 数据，握手必然失败。
       h1 模式不发 ALPN（发了反而多一个可指纹化的扩展）。 */
    tc.alpn        = c->http2 ? "h2" : NULL;

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

/* HTTP/2 连接前言：发 preface + 我方 SETTINGS，并等到对端 SETTINGS 到达。
 *
 * 必须真等到对端 SETTINGS 才置 h2_settings_done。h2 是严格帧序协议：
 * 若在对端 SETTINGS 之前就发 HEADERS，对端按协议应视为连接错误并 GOAWAY，
 * 表现为"握手成功但第一个请求必定失败"——极难定位，且容易被误判成
 * 前置被 CDN 拒绝。等这一帧是协议要求，不是性能优化。 */
static front_err h2_handshake(front_ctx *c) {
    uint8_t buf[512];
    size_t  n = 0;

    if (h2_preface(buf, sizeof(buf), &n) != H2_OK) return FRONT_ERR_HTTP;
    if (tls_write(c->tls, buf, n) != TLS_OK) return FRONT_ERR_TLS;

    size_t sn = 0;
    if (h2_frame_settings(buf, sizeof(buf), &sn, 0) != H2_OK) return FRONT_ERR_HTTP;
    if (tls_write(c->tls, buf, sn) != TLS_OK) return FRONT_ERR_TLS;

    /* 等 SETTINGS（最多读 16 帧，避免恶意流导致无限循环） */
    for (int i = 0; i < 16; i++) {
        size_t got = 0;
        if (tls_read(c->tls, buf, sizeof(buf), &got) != TLS_OK) return FRONT_ERR_TLS;
        if (got == 0) return FRONT_ERR_IO;
        if (c->h2_in_len + got > sizeof(c->h2_in)) return FRONT_ERR_RANGE;
        memcpy(c->h2_in + c->h2_in_len, buf, got);
        c->h2_in_len += got;

        size_t off = 0;
        while (off + 9 <= c->h2_in_len) {
            h2_frame f;
            if (h2_frame_parse(c->h2_in + off, c->h2_in_len - off, &f) != H2_OK) break;
            off += f.consumed;
            if (f.type == H2_T_SETTINGS && !(f.flags & H2_F_ACK)) {
                size_t ack = 0;
                if (h2_frame_settings(buf, sizeof(buf), &ack, 1) != H2_OK)
                    return FRONT_ERR_HTTP;
                if (tls_write(c->tls, buf, ack) != TLS_OK) return FRONT_ERR_TLS;
                if (off < c->h2_in_len)
                    memmove(c->h2_in, c->h2_in + off, c->h2_in_len - off);
                c->h2_in_len -= off;
                c->h2_settings_done = 1;
                return FRONT_OK;
            }
            if (f.type == H2_T_GOAWAY) return FRONT_ERR_HTTP;   /* 前置拒绝 h2 */
        }
        if (off > 0 && off <= c->h2_in_len) {
            memmove(c->h2_in, c->h2_in + off, c->h2_in_len - off);
            c->h2_in_len -= off;
        }
    }
    return FRONT_ERR_HTTP;
}

front_err front_connect(front_ctx *c) {
    if (!c) return FRONT_ERR_ARG;
    if (tls_handshake(c->tls) != TLS_OK) return FRONT_ERR_TLS;
    if (c->http2 && h2_handshake(c) != FRONT_OK) return FRONT_ERR_HTTP;
    c->connected = 1;
    return FRONT_OK;
}

/* HTTP/2 请求：HEADERS（含 :authority = 真实主机）+ DATA。
 *
 * 两条与域前置直接相关的性质，已在测试中固化为断言：
 *  1. :path 沿用与 h1 相同的抖动路径 —— 恒定路径在 h2 上同样形成节拍。
 *  2. :authority 由 h2_hpack_request 以 never-indexed 字面量编码，
 *     绝不走 HPACK 静态表索引。静态表里没有我们的主机名，本就用不上索引；
 *     但一旦将来有人"优化"成索引，编码器要么失败要么写错索引号，
 *     表现为对端 400/431 而本地看不出原因。故由 h2 层保证，此处不重复实现。
 */
static front_err build_request_h2(front_ctx *c, const uint8_t *frame, size_t len,
                                  uint8_t *out, size_t cap, size_t *out_len) {
    uint8_t  blk[512];
    size_t   blen = 0;
    if (h2_hpack_request("POST", "https", c->last_path, c->cfg.real_host,
                         blk, sizeof(blk), &blen) != H2_OK)
        return FRONT_ERR_HTTP;

    size_t total = 0;
    size_t fn = 0;
    /* 有 body 时 HEADERS 不带 END_STREAM，随后单独发 DATA */
    if (h2_frame_headers(c->next_stream_id, blk, blen, len ? 0 : 1,
                         out + total, cap - total, &fn) != H2_OK)
        return FRONT_ERR_HTTP;
    total += fn;

    if (len) {
        /* 超过单帧上限必须显式报错。h2 的 DATA 若被静默截断，对端收到的
           是半条 C2 帧却以为完整 —— 与本层 h1 路径的取舍一致。 */
        if (len > H2_MAX_FRAME_PAYLOAD) return FRONT_ERR_RANGE;
        if (h2_frame_data(c->next_stream_id, frame, len, 1,
                          out + total, cap - total, &fn) != H2_OK)
            return FRONT_ERR_HTTP;
        total += fn;
    }
    *out_len = total;
    return FRONT_OK;
}

front_err front_build_request(front_ctx *c, const uint8_t *frame, size_t len,
                              uint8_t *out, size_t cap, size_t *out_len) {
    if (!c || !out || !out_len) return FRONT_ERR_ARG;
    if (frame && len > cap) return FRONT_ERR_RANGE;
    gen_path(c);
    if (c->http2) {
        front_err fe = build_request_h2(c, frame, len, out, cap, out_len);
        if (fe == FRONT_OK) c->next_stream_id += 2;   /* 客户端流号步进 2，恒奇 */
        return fe;
    }
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

/* HTTP/2 响应：逐帧解析，HEADERS 取 :status，DATA 累积到 END_STREAM。
 *
 * 421 Misdirected Request 必须被明确认出来：它的含义是"这台服务器不会为
 * :authority 指定的目标服务"，即前置节点拒绝回源到真实目标。这是域前置
 * 失效的直接信号，与普通的 5xx 处置完全不同（前者要换前置域，后者重试）。
 * 若混在通用错误里，运维上只会看到"请求失败"，无法定位到前置配置。
 */
static front_err recv_h2(front_ctx *c, uint8_t *buf, size_t cap, size_t *out_len) {
    size_t body_len = 0;
    int    got_status = 0;

    for (int i = 0; i < 64; i++) {
        /* 先消化已缓冲的帧 */
        int progress = 0;
        size_t off = 0;
        while (off + 9 <= c->h2_in_len) {
            h2_frame f;
            if (h2_frame_parse(c->h2_in + off, c->h2_in_len - off, &f) != H2_OK) break;
            off += f.consumed;
            progress = 1;

            if (f.type == H2_T_HEADERS) {
                int st = 0;
                if (h2_hpack_status(f.payload, f.len, &st) == H2_OK) {
                    c->last_status = st;
                    got_status = 1;
                    if (st == 421) return FRONT_ERR_HTTP;   /* 前置拒绝回源 */
                }
            } else if (f.type == H2_T_DATA) {
                if (body_len + f.len > cap) return FRONT_ERR_RANGE;
                memcpy(buf + body_len, f.payload, f.len);
                body_len += f.len;
                if (f.flags & H2_F_END_STREAM) {
                    if (off < c->h2_in_len)
                        memmove(c->h2_in, c->h2_in + off, c->h2_in_len - off);
                    c->h2_in_len -= off;
                    *out_len = body_len;
                    return FRONT_OK;
                }
            } else if (f.type == H2_T_GOAWAY) {
                return FRONT_ERR_HTTP;
            }
        }
        if (off > 0 && off <= c->h2_in_len) {
            memmove(c->h2_in, c->h2_in + off, c->h2_in_len - off);
            c->h2_in_len -= off;
            progress = 1;
        }
        if (progress && body_len && got_status) {
            /* 有状态有数据但没等到 END_STREAM：继续读 */
        }

        if (c->h2_in_len >= sizeof(c->h2_in)) return FRONT_ERR_RANGE;
        uint8_t tmp[8192];
        size_t  got = 0;
        if (tls_read(c->tls, tmp, sizeof(tmp), &got) != TLS_OK) return FRONT_ERR_TLS;
        if (got == 0) return FRONT_ERR_IO;
        if (c->h2_in_len + got > sizeof(c->h2_in)) return FRONT_ERR_RANGE;
        memcpy(c->h2_in + c->h2_in_len, tmp, got);
        c->h2_in_len += got;
    }
    return FRONT_ERR_HTTP;
}

front_err front_recv(front_ctx *c, uint8_t *buf, size_t cap, size_t *out_len) {
    if (!c || !buf || !out_len) return FRONT_ERR_ARG;
    if (!c->connected) return FRONT_ERR_STATE;
    if (c->http2) return recv_h2(c, buf, cap, out_len);
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

int front_last_status(const front_ctx *c) {
    return c ? c->last_status : -1;
}

/* ---- 自适应退避 ----
 *
 * 窗口以实测 RTT 为基数按失败次数翻倍，然后取全抖动。
 * 全抖动而不是固定值：一批植入体同时遭遇 CDN 故障时，固定退避会让它们
 * 在同一刻集体重试 —— 链路上就是"静默—同步爆发"，这本身就是事件特征。
 *
 * 无 RTT 样本时（一次都没成功过）用 100ms 兜底，绝不退回 0：
 * 0 会让失败路径变成紧密重试循环，把自己打成 DoS。
 */
#define FRONT_RTT_FLOOR_MS   10
#define FRONT_RTT_CEIL_MS    1000

static uint64_t backoff_base_ms(const front_ctx *c) {
    uint64_t ms = c->rtt_ewma_us ? c->rtt_ewma_us / 1000 : 100;
    if (ms < FRONT_RTT_FLOOR_MS) ms = FRONT_RTT_FLOOR_MS;
    if (ms > FRONT_RTT_CEIL_MS)  ms = FRONT_RTT_CEIL_MS;
    return ms;
}

void front_note_fail(front_ctx *c) {
    if (!c) return;
    if (c->fail_streak < 63) c->fail_streak++;
}

void front_note_success(front_ctx *c, uint64_t rtt_us) {
    if (!c) return;
    c->fail_streak = 0;
    if (!c->rtt_ewma_us) c->rtt_ewma_us = rtt_us;          /* 首样本直接采纳 */
    else c->rtt_ewma_us = (c->rtt_ewma_us * 7 + rtt_us) / 8;  /* EWMA α=1/8 */
}

uint64_t front_rtt_ewma_us(const front_ctx *c) {
    return c ? c->rtt_ewma_us : 0;
}

uint64_t front_backoff_ms(front_ctx *c) {
    if (!c || c->fail_streak == 0) return 0;
    uint64_t w = backoff_base_ms(c);
    int shift = c->fail_streak > 6 ? 6 : c->fail_streak;   /* 封顶 ×64 */
    w <<= shift;
    if (w > FRONT_BACKOFF_MAX_MS) w = FRONT_BACKOFF_MAX_MS;
    uint64_t half = w / 2;
    if (half == 0) half = 1;
    return half + (rng_next((front_ctx *)c) % half);       /* [0.5W, W) 全抖动 */
}
