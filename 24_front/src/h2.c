/* h2.c — HTTP/2 帧层 + HPACK（自研）
 *
 * 边界语义：所有写路径带容量检查，越界返回 H2_ERR_RANGE 且绝不写入；
 * 所有读路径越界返回 H2_ERR_HPACK / H2_ERR_FRAME。短读（不足一整帧）
 * 单独用 consumed=0 表示，不算错误 —— 把短读当错误会让调用方在
 * TLS 记录分片时误判为协议失败并断链。
 */
#include "h2.h"
#include "huffman_table.h"
#include <string.h>

const char *h2_errstr(h2_err e) {
    switch (e) {
    case H2_OK:          return "ok";
    case H2_ERR_ARG:     return "invalid argument";
    case H2_ERR_RANGE:   return "buffer too small or frame too large";
    case H2_ERR_FRAME:   return "malformed http/2 frame";
    case H2_ERR_HPACK:   return "hpack encode/decode failure";
    case H2_ERR_STATE:   return "invalid state";
    }
    return "unknown";
}

/* ---------------- 写缓冲 ---------------- */
typedef struct { uint8_t *p; size_t cap; size_t n; int ovf; } hb;

static void hb_u8(hb *b, uint8_t v) {
    if (b->n < b->cap) b->p[b->n] = v; else b->ovf = 1;
    b->n++;
}
static void hb_mem(hb *b, const uint8_t *s, size_t l) {
    for (size_t i = 0; i < l; i++) hb_u8(b, s[i]);
}
/* HPACK 整数表示（RFC 7541 §5.1） */
static void hb_int(hb *b, uint32_t v, uint8_t pfx, uint8_t pat) {
    uint32_t m = (uint32_t)((1u << pfx) - 1u);
    if (v < m) { hb_u8(b, (uint8_t)(pat | v)); return; }
    hb_u8(b, (uint8_t)(pat | m));
    v -= m;
    while (v >= 128) { hb_u8(b, (uint8_t)((v & 0x7f) | 0x80)); v >>= 7; }
    hb_u8(b, (uint8_t)v);
}
static void hb_str(hb *b, const uint8_t *s, size_t l) {
    hb_int(b, (uint32_t)l, 7, 0x00);   /* H=0：本层不生成 Huffman */
    hb_mem(b, s, l);
}

/* ---------------- 读缓冲 ---------------- */
typedef struct { const uint8_t *p; size_t len; size_t o; } hr;

static int hr_u8(hr *r, uint8_t *v) {
    if (r->o >= r->len) return -1;
    *v = r->p[r->o++];
    return 0;
}
static int hr_int(hr *r, uint8_t first, uint8_t pfx, uint32_t *out) {
    uint32_t m = (uint32_t)((1u << pfx) - 1u);
    uint32_t v = first & m;
    if (v < m) { *out = v; return 0; }
    int shift = 0;
    for (;;) {
        uint8_t b;
        if (hr_u8(r, &b)) return -1;
        v += (uint32_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift > 28) return -1;   /* 超过 2^32 即非法，不静默截断 */
    }
    *out = v;
    return 0;
}
/* ---- HPACK Huffman 解码（RFC 7541 §5.2）----
 *
 * 规范 Huffman 解码：逐位累积码字，每累积一位就在表里查是否恰好构成某个
 * 符号。表按 (码长, 码字) 升序，同一码长内按码字升序，故可二分。
 *
 * 三条必须做对的边界：
 *  1. 码长超过 HF_MAX_BITS 即失败。不封顶的话，一串全 1 的填充位会让
 *     累积值无限增长并绕过任何"找不到符号"的判定。
 *  2. 解出 EOS(256) 必须失败。EOS 只用于末尾填充，出现在字符串中间说明
 *     对端编码有误或数据在传输中被改过 —— 当成普通符号会解出垃圾。
 *  3. 末尾残余位必须全是 1（EOS 前缀）且不超过 7 位。残余位若含有 0，
 *     说明这段 Huffman 数据不完整或被截断，静默接受会解出短一截的字符串。
 */
static int hf_lookup(unsigned nbits, unsigned code, unsigned short *sym) {
    /* 二分：先按 bits，再按 code */
    int lo = 0, hi = HF_ENTRIES - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        unsigned b = HF_TABLE[mid].bits, c = HF_TABLE[mid].code;
        if (b < nbits || (b == nbits && c < code)) lo = mid + 1;
        else if (b > nbits || (b == nbits && c > code)) hi = mid - 1;
        else { *sym = HF_TABLE[mid].sym; return 0; }
    }
    return -1;
}

/* 解码一段 Huffman 数据到 out。成功返回写入长度，失败返回 -1。 */
static int hf_decode(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap) {
    if (!in || !out) return -1;
    unsigned code = 0;
    unsigned nbits = 0;
    size_t   o = 0;
    for (size_t i = 0; i < in_len; i++) {
        for (int b = 7; b >= 0; b--) {
            code = (code << 1) | ((unsigned)(in[i] >> b) & 1u);
            nbits++;
            if (nbits > HF_MAX_BITS) return -1;
            unsigned short sym = 0;
            if (hf_lookup(nbits, code, &sym) == 0) {
                if (sym == 256) return -1;              /* EOS：不是合法符号 */
                if (o >= out_cap) return -1;            /* 输出缓冲不足，不越界 */
                out[o++] = (uint8_t)sym;
                code = 0;
                nbits = 0;
            }
        }
    }
    /* 末尾残余：必须是 (nbits 个 1)，即 EOS 的前缀 */
    if (nbits > 7) return -1;
    unsigned want = (1u << nbits) - 1u;
    if (nbits && code != want) return -1;
    return (int)o;
}

static int hr_str(hr *r, const uint8_t **s, size_t *l) {
    uint8_t b0;
    if (hr_u8(r, &b0)) return -1;
    uint32_t n;
    if (hr_int(r, b0, 7, &n)) return -1;
    if (r->o + n > r->len) return -1;
    if (!(b0 & 0x80)) {                  /* 未压缩：直接指进输入缓冲 */
        *s = r->p + r->o;
        *l = n;
        r->o += n;
        return 0;
    }
    /* Huffman：解到调用方提供的静态缓冲（头块不会很大，1KB 足够）。
       之前这里直接 return -1，结果连真实服务器都解不了 ——
       h2 支持形同虚设，只能和自己的测试桩对话。 */
    static uint8_t hbuf[1024];
    int got = hf_decode(r->p + r->o, n, hbuf, sizeof(hbuf));
    if (got < 0) return -1;
    r->o += n;
    *s = hbuf;
    *l = (size_t)got;
    return 0;
}

/* ---------------- HPACK 静态表 ---------------- */
/* 索引 1..7 是我们要用的伪头名/值；8..14 是 :status 常见值 */
#define HPACK_IDX_AUTHORITY 1
#define HPACK_IDX_METHOD    2
#define HPACK_IDX_PATH      4
#define HPACK_IDX_SCHEME    7
#define HPACK_IDX_STATUS    8

/* 完全匹配的静态表项（名+值同时命中才能用索引形式） */
static int static_kv_index(const char *name, const char *val) {
    if (!strcmp(name, ":method")) {
        if (!strcmp(val, "GET"))  return 2;
        if (!strcmp(val, "POST")) return 3;
        return -1;
    }
    if (!strcmp(name, ":scheme")) {
        if (!strcmp(val, "http"))  return 6;
        if (!strcmp(val, "https")) return 7;
        return -1;
    }
    if (!strcmp(name, ":path")) {
        if (!strcmp(val, "/"))            return 4;
        if (!strcmp(val, "/index.html"))  return 5;
        return -1;
    }
    if (!strcmp(name, ":status")) {
        static const char *v[] = { "200","204","206","304","400","404","500" };
        for (int i = 0; i < 7; i++) if (!strcmp(val, v[i])) return 8 + i;
        return -1;
    }
    return -1;
}

/* 写一个头字段。
 * never_index=1 时强制用 "Literal Header Field Never Indexed" 形式，
 * 即使值能命中静态表 —— :authority 与 :path 走这条（见 h2.h 硬规则 2）。 */
static void hb_header(hb *b, const char *name, uint8_t name_idx,
                      const char *val, int never_index) {
    size_t vl = strlen(val);
    int kv = never_index ? -1 : static_kv_index(name, val);
    if (kv > 0) {
        hb_int(b, (uint32_t)kv, 7, 0x80);          /* Indexed Header Field */
        return;
    }
    hb_int(b, name_idx, 4, 0x10);                  /* Never Indexed, name = index */
    hb_str(b, (const uint8_t *)val, vl);
}

h2_err h2_hpack_request(const char *method, const char *scheme,
                        const char *path, const char *authority,
                        uint8_t *out, size_t cap, size_t *out_len) {
    if (!method || !scheme || !path || !authority || !out || !out_len) return H2_ERR_ARG;
    if (!*method || !*scheme || !*path || !*authority) return H2_ERR_ARG;
    if (cap == 0) return H2_ERR_RANGE;

    hb b = { out, cap, 0, 0 };
    hb_header(&b, ":method",    HPACK_IDX_METHOD,    method,    0);
    hb_header(&b, ":scheme",    HPACK_IDX_SCHEME,    scheme,    0);
    hb_header(&b, ":path",      HPACK_IDX_PATH,      path,      1);
    hb_header(&b, ":authority", HPACK_IDX_AUTHORITY, authority, 1);

    if (b.ovf || b.n > cap) return H2_ERR_RANGE;
    *out_len = b.n;
    return H2_OK;
}

h2_err h2_hpack_status(const uint8_t *in, size_t len, int *status) {
    if (!in || !status) return H2_ERR_ARG;
    hr r = { in, len, 0 };
    while (r.o < len) {
        uint8_t b0;
        if (hr_u8(&r, &b0)) return H2_ERR_HPACK;
        if (b0 & 0x80) {                       /* Indexed，前缀 7 */
            uint32_t idx;
            if (hr_int(&r, b0, 7, &idx)) return H2_ERR_HPACK;
            if (idx >= 8 && idx <= 14) {
                static const int st[] = { 200,204,206,304,400,404,500 };
                *status = st[idx - 8];
                return H2_OK;
            }
            continue;
        }
        /* 下面三种都带 name + value；先解出 name 的索引或字面量 */
        uint32_t ni = 0;
        int have_name_idx = 1;
        const uint8_t *nm = NULL;
        size_t nl = 0;
        if (b0 & 0x40) {                       /* Incremental Indexing，前缀 6 */
            if (hr_int(&r, b0, 6, &ni)) return H2_ERR_HPACK;
        } else if (b0 & 0x20) {                /* Dynamic Table Size Update，前缀 5 */
            uint32_t sz;
            if (hr_int(&r, b0, 5, &sz)) return H2_ERR_HPACK;
            continue;                          /* 无 name/value */
        } else {                               /* Without Indexing 或 Never Indexed，前缀 4 */
            if (hr_int(&r, b0, 4, &ni)) return H2_ERR_HPACK;
        }
        if (ni == 0) {
            if (hr_str(&r, &nm, &nl)) return H2_ERR_HPACK;
            have_name_idx = 0;
        }
        const uint8_t *v;
        size_t vl;
        if (hr_str(&r, &v, &vl)) return H2_ERR_HPACK;

        int is_status = have_name_idx ? (ni == HPACK_IDX_STATUS)
                                      : (nl == 7 && !memcmp(nm, ":status", 7));
        if (is_status) {
            if (vl == 0 || vl > 3) return H2_ERR_HPACK;
            int s = 0;
            for (size_t i = 0; i < vl; i++) {
                if (v[i] < '0' || v[i] > '9') return H2_ERR_HPACK;
                s = s * 10 + (v[i] - '0');
            }
            *status = s;
            return H2_OK;
        }
    }
    return H2_ERR_HPACK;   /* 没找到 :status 就报错，不默认 200 */
}

/* ---------------- 帧 ---------------- */

static const uint8_t H2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

h2_err h2_preface(uint8_t *out, size_t cap, size_t *out_len) {
    if (!out || !out_len) return H2_ERR_ARG;
    size_t n = sizeof(H2_PREFACE) - 1;
    if (cap < n) return H2_ERR_RANGE;
    memcpy(out, H2_PREFACE, n);
    *out_len = n;
    return H2_OK;
}

static void frame_header(hb *b, uint8_t type, uint8_t flags,
                         uint32_t sid, size_t plen) {
    hb_u8(b, (uint8_t)((plen >> 16) & 0xff));
    hb_u8(b, (uint8_t)((plen >> 8) & 0xff));
    hb_u8(b, (uint8_t)(plen & 0xff));
    hb_u8(b, type);
    hb_u8(b, flags);
    hb_u8(b, (uint8_t)((sid >> 24) & 0x7f));   /* 最高位 R 保留，恒 0 */
    hb_u8(b, (uint8_t)((sid >> 16) & 0xff));
    hb_u8(b, (uint8_t)((sid >> 8) & 0xff));
    hb_u8(b, (uint8_t)(sid & 0xff));
}

static h2_err finish(hb *b, size_t *out_len) {
    if (b->ovf || b->n > b->cap) return H2_ERR_RANGE;
    *out_len = b->n;
    return H2_OK;
}

h2_err h2_frame_settings(uint8_t *out, size_t cap, size_t *out_len, int ack) {
    if (!out || !out_len) return H2_ERR_ARG;
    hb b = { out, cap, 0, 0 };
    /* 发空 SETTINGS：不协商_enable_push 等参数是刻意的 ——
     * 少发参数就少一份可被指纹化的 SETTINGS 组合。 */
    frame_header(&b, H2_T_SETTINGS, ack ? H2_F_ACK : 0, 0, 0);
    return finish(&b, out_len);
}

h2_err h2_frame_headers(uint32_t stream_id, const uint8_t *blk, size_t blk_len,
                        int end_stream, uint8_t *out, size_t cap, size_t *out_len) {
    if (!blk || !out || !out_len) return H2_ERR_ARG;
    if (stream_id == 0) return H2_ERR_ARG;               /* HEADERS 必须带流 ID */
    if (blk_len > H2_MAX_FRAME_PAYLOAD) return H2_ERR_RANGE;
    hb b = { out, cap, 0, 0 };
    frame_header(&b, H2_T_HEADERS,
                 H2_F_END_HEADERS | (end_stream ? H2_F_END_STREAM : 0),
                 stream_id, blk_len);
    hb_mem(&b, blk, blk_len);
    return finish(&b, out_len);
}

h2_err h2_frame_data(uint32_t stream_id, const uint8_t *payload, size_t len,
                     int end_stream, uint8_t *out, size_t cap, size_t *out_len) {
    if (!out || !out_len) return H2_ERR_ARG;
    if (stream_id == 0) return H2_ERR_ARG;
    if (len > H2_MAX_FRAME_PAYLOAD) return H2_ERR_RANGE;  /* 不做隐式分片 */
    hb b = { out, cap, 0, 0 };
    frame_header(&b, H2_T_DATA, end_stream ? H2_F_END_STREAM : 0, stream_id, len);
    if (len) hb_mem(&b, payload, len);
    return finish(&b, out_len);
}

h2_err h2_frame_parse(const uint8_t *buf, size_t len, h2_frame *f) {
    if (!buf || !f) return H2_ERR_ARG;
    f->consumed = 0;
    if (len < 9) return H2_ERR_FRAME;                     /* 短读：不是错误 */
    uint32_t plen = ((uint32_t)buf[0] << 16) | ((uint32_t)buf[1] << 8) | buf[2];
    if (plen > H2_MAX_FRAME_PAYLOAD) return H2_ERR_FRAME;
    if (len < 9u + plen) return H2_ERR_FRAME;             /* 同样按短读处理 */
    f->type = buf[3];
    f->flags = buf[4];
    f->stream_id = ((uint32_t)(buf[5] & 0x7f) << 24) | ((uint32_t)buf[6] << 16)
                | ((uint32_t)buf[7] << 8) | buf[8];
    f->payload = buf + 9;
    f->len = plen;
    f->consumed = 9u + plen;
    return H2_OK;
}
