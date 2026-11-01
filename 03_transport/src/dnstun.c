#define _DEFAULT_SOURCE
#include "dnstun.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

const char *tx_dnstun_errstr(int e) {
    switch (e) {
        case TX_DNSTUN_OK:        return "ok";
        case TX_DNSTUN_ERR_ARGS:  return "invalid argument";
        case TX_DNSTUN_ERR_SOCK:  return "socket error";
        case TX_DNSTUN_ERR_TIMEOUT: return "timeout";
        case TX_DNSTUN_ERR_RETRY: return "retry exhausted";
        case TX_DNSTUN_ERR_PROTO: return "protocol error";
        case TX_DNSTUN_ERR_TOOBIG:return "too big";
        default:                  return "unknown";
    }
}

/* ---------------- base32 (RFC 4648, 无填充) ---------------- */
static const char b32a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static int b32v(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

static size_t b32enc(const uint8_t *in, size_t n, char *out, size_t cap) {
    size_t o = 0;
    size_t i;
    for (i = 0; i < n; i += 5) {
        uint8_t b[5];
        size_t m, j;
        uint64_t acc = 0;
        unsigned bits, chars, c;
        memset(b, 0, sizeof(b));
        m = (n - i) < 5 ? (n - i) : 5;
        memcpy(b, in + i, m);
        for (j = 0; j < m; j++) acc = (acc << 8) | (uint64_t)b[j];
        bits = (unsigned)(m * 8);
        chars = (bits + 4) / 5;
        if (o + chars >= cap) return 0;
        for (c = 0; c < chars; c++) {
            int shift = (int)bits - 5 * ((int)c + 1);
            if (shift >= 0) out[o++] = b32a[(acc >> shift) & 31u];
            else            out[o++] = b32a[(acc << (-shift)) & 31u];
        }
    }
    if (o >= cap) return 0;
    out[o] = '\0';
    return o;
}

static int b32dec(const char *s, uint8_t *out, size_t cap, size_t *olen) {
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    const char *p;
    for (p = s; *p; p++) {
        int v = b32v(*p);
        if (v < 0) return -1;
        acc = (acc << 5) | (uint32_t)v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) return -1;
            out[o++] = (uint8_t)((acc >> bits) & 0xFFu);
        }
    }
    *olen = o;
    return 0;
}

/* ---------------- QNAME 编解码 ---------------- */
int tx_dnstun_label_build(uint32_t seq, uint32_t ack, int fin,
                          const uint8_t *chunk, size_t clen,
                          const char *session, const char *domain,
                          char *out, size_t cap) {
    char b32[256];
    size_t bl = 0;
    size_t o = 0, p = 0;
    size_t sl, dl;
    int r;

    if (!out || !session || !domain || !cap) return TX_DNSTUN_ERR_ARGS;
    if (chunk == NULL && clen != 0) return TX_DNSTUN_ERR_ARGS;
    if (clen > TX_DNSTUN_CHUNK) return TX_DNSTUN_ERR_TOOBIG;

    if (clen > 0) {
        bl = b32enc(chunk, clen, b32, sizeof(b32));
        if (bl == 0) return TX_DNSTUN_ERR_TOOBIG;
    }

    /* 头部含 chunk 标签数，使解析端不必依赖 domain 的标签结构 */
    {
        size_t nl = (bl + 62) / 63;
        if (nl > 9) return TX_DNSTUN_ERR_TOOBIG;
        r = snprintf(out, cap, "%08X.%08X.%d.%u", seq, ack, fin ? 1 : 0, (unsigned)nl);
    }
    if (r < 0 || (size_t)r >= cap) return TX_DNSTUN_ERR_TOOBIG;
    o = (size_t)r;

    while (p < bl) {
        size_t n = bl - p;
        if (n > 63) n = 63;
        if (o + 1 + n >= cap) return TX_DNSTUN_ERR_TOOBIG;
        out[o++] = '.';
        memcpy(out + o, b32 + p, n);
        o += n;
        p += n;
    }

    sl = strlen(session);
    dl = strlen(domain);
    if (o + 1 + sl + 1 + dl + 1 > cap) return TX_DNSTUN_ERR_TOOBIG;
    r = snprintf(out + o, cap - o, ".%s.%s", session, domain);
    if (r < 0) return TX_DNSTUN_ERR_TOOBIG;
    o += (size_t)r;

    /* QNAME 不含结尾点，总长须 <= 253 */
    if (o > TX_DNSTUN_MAXNAME) return TX_DNSTUN_ERR_TOOBIG;
    return TX_DNSTUN_OK;
}

int tx_dnstun_label_parse(const char *name, uint32_t *seq, uint32_t *ack,
                          int *fin, uint8_t *chunk, size_t cap, size_t *clen) {
    const char *parts[32];
    size_t plen[32];
    int np = 0;
    const char *s = name;
    char b32[320];
    size_t bl = 0;
    char tmp[16];
    int i;
    size_t ol = 0;
    size_t nl = 0;

    if (!name || !seq || !ack || !fin || !chunk || !clen) return TX_DNSTUN_ERR_ARGS;

    while (*s && np < 32) {
        const char *e = strchr(s, '.');
        size_t n = e ? (size_t)(e - s) : strlen(s);
        parts[np] = s;
        plen[np] = n;
        np++;
        if (!e) break;
        s = e + 1;
    }
    /* 至少: seq ack fin nchunk session domain */
    if (np < 5) return TX_DNSTUN_ERR_PROTO;

    if (plen[0] != 8 || plen[1] != 8 || plen[2] != 1 || plen[3] != 1)
        return TX_DNSTUN_ERR_PROTO;
    if (parts[3][0] < '0' || parts[3][0] > '9') return TX_DNSTUN_ERR_PROTO;
    nl = (size_t)(parts[3][0] - '0');
    if (np < 4 + (int)nl + 2) return TX_DNSTUN_ERR_PROTO;

    memcpy(tmp, parts[0], 8); tmp[8] = '\0';
    *seq = (uint32_t)strtoul(tmp, NULL, 16);
    memcpy(tmp, parts[1], 8); tmp[8] = '\0';
    *ack = (uint32_t)strtoul(tmp, NULL, 16);
    *fin = (parts[2][0] == '1') ? 1 : 0;

    /* [4 .. 4+nl) 为净荷标签；其后 session 与 domain 本函数不关心 */
    for (i = 4; i < 4 + (int)nl; i++) {
        if (plen[i] == 0) continue;
        if (bl + plen[i] + 1 > sizeof(b32)) return TX_DNSTUN_ERR_TOOBIG;
        memcpy(b32 + bl, parts[i], plen[i]);
        bl += plen[i];
    }
    b32[bl] = '\0';

    if (bl > 0) {
        if (b32dec(b32, chunk, cap, &ol) != 0) return TX_DNSTUN_ERR_PROTO;
    } else {
        ol = 0;
    }
    *clen = ol;
    return TX_DNSTUN_OK;
}

/* ---------------- RFC 1035 报文 ---------------- */
size_t tx_dns_build_query_ex(const char *qname, uint16_t tid, uint16_t qtype,
                             uint8_t *out, size_t cap) {
    size_t o = 0;
    const char *s = qname;

    if (!qname || !out || cap < 32) return 0;

    out[o++] = (uint8_t)(tid >> 8);
    out[o++] = (uint8_t)(tid & 0xFF);
    out[o++] = 0x01; out[o++] = 0x00;              /* RD = 1 */
    out[o++] = 0x00; out[o++] = 0x01;              /* QDCOUNT = 1 */
    out[o++] = 0x00; out[o++] = 0x00;              /* ANCOUNT */
    out[o++] = 0x00; out[o++] = 0x00;              /* NSCOUNT */
    out[o++] = 0x00; out[o++] = 0x00;              /* ARCOUNT */

    while (*s) {
        const char *e = strchr(s, '.');
        size_t n = e ? (size_t)(e - s) : strlen(s);
        if (n == 0 || n > 63) return 0;
        if (o + 1 + n + 5 > cap) return 0;
        out[o++] = (uint8_t)n;
        memcpy(out + o, s, n);
        o += n;
        if (!e) break;
        s = e + 1;
    }
    if (o + 5 > cap) return 0;
    out[o++] = 0x00;                                /* 根标签 */
    out[o++] = (uint8_t)(qtype >> 8); out[o++] = (uint8_t)(qtype & 0xFF);
    out[o++] = 0x00; out[o++] = 0x01;               /* QCLASS = IN */
    return o;
}

size_t tx_dns_build_query(const char *qname, uint16_t tid, uint8_t *out, size_t cap) {
    return tx_dns_build_query_ex(qname, tid, 1 /* A */, out, cap);
}

int tx_dns_parse_query(const uint8_t *p, size_t len, char *qname, size_t cap, uint16_t *tid) {
    size_t o = 12, qo = 0;

    if (!p || !qname || !cap || len < 17) return TX_DNSTUN_ERR_PROTO;
    if (tid) *tid = (uint16_t)(((uint16_t)p[0] << 8) | p[1]);

    while (o < len) {
        uint8_t l = p[o++];
        if (l == 0) break;
        if ((l & 0xC0) == 0xC0) return TX_DNSTUN_ERR_PROTO; /* 查询段不支持压缩 */
        if (o + l > len) return TX_DNSTUN_ERR_PROTO;
        if (qo + l + 1 > cap) return TX_DNSTUN_ERR_TOOBIG;
        if (qo > 0) qname[qo++] = '.';
        memcpy(qname + qo, p + o, l);
        qo += l;
        o += l;
    }
    if (qo >= cap) return TX_DNSTUN_ERR_TOOBIG;
    qname[qo] = '\0';
    return TX_DNSTUN_OK;
}

size_t tx_dns_build_txt_reply(const uint8_t *q, size_t qlen,
                              const uint8_t *txt, size_t tlen,
                              uint8_t *out, size_t cap) {
    size_t o = 12, qend, w = 0, need;

    if (!q || !out || qlen < 17 || cap < 64) return 0;
    /* 定位 question 段结束（含 QTYPE/QCLASS 4 字节） */
    while (o < qlen && q[o] != 0) {
        uint8_t l = q[o];
        if ((l & 0xC0) == 0xC0) { o += 2; break; }
        o += 1 + l;
    }
    if (o < qlen && q[o] == 0) o += 1;
    qend = o + 4;
    if (qend > qlen) return 0;
    if (tlen > 255) return 0;

    need = qend + 2 + 2 + 2 + 4 + 2 + 1 + tlen;
    if (need > cap) return 0;

    memcpy(out, q, qend);
    w = qend;
    out[2] = 0x84; out[3] = 0x00;      /* QR=1, AA=1 */
    out[6] = 0x00; out[7] = 0x01;      /* ANCOUNT = 1 */

    out[w++] = 0xC0; out[w++] = 0x0C;  /* 名字指针，指向偏移 12 */
    out[w++] = 0x00; out[w++] = 0x10;  /* TYPE = TXT (16) */
    out[w++] = 0x00; out[w++] = 0x01;  /* CLASS = IN */
    out[w++] = 0; out[w++] = 0; out[w++] = 0; out[w++] = 0; /* TTL = 0 */
    {
        uint16_t rd = (uint16_t)(1 + tlen);
        out[w++] = (uint8_t)(rd >> 8);
        out[w++] = (uint8_t)(rd & 0xFF);
    }
    out[w++] = (uint8_t)tlen;
    if (tlen) memcpy(out + w, txt, tlen);
    w += tlen;
    return w;
}

int tx_dns_parse_txt(const uint8_t *p, size_t len, uint8_t *out, size_t cap, size_t *olen) {
    size_t o = 12;
    uint16_t qd, an;
    int i;

    if (!p || !out || !olen || len < 12) return TX_DNSTUN_ERR_PROTO;
    qd = (uint16_t)(((uint16_t)p[4] << 8) | p[5]);
    an = (uint16_t)(((uint16_t)p[6] << 8) | p[7]);
    if (an < 1) return TX_DNSTUN_ERR_PROTO;

    /* 跳过问题区 */
    for (i = 0; i < (int)qd; i++) {
        int jumps = 0;
        for (;;) {
            uint8_t l;
            if (o >= len) return TX_DNSTUN_ERR_PROTO;
            l = p[o];
            if (l == 0) { o++; break; }
            if ((l & 0xC0) == 0xC0) {              /* 压缩指针 */
                if (o + 2 > len) return TX_DNSTUN_ERR_PROTO;
                if (++jumps > 8) return TX_DNSTUN_ERR_PROTO;
                o += 2;
                break;
            }
            if ((l & 0xC0) != 0) return TX_DNSTUN_ERR_PROTO;
            o += 1u + (size_t)l;
            if (o >= len) return TX_DNSTUN_ERR_PROTO;
        }
        o += 4;
        if (o > len) return TX_DNSTUN_ERR_PROTO;
    }

    /* 遍历应答区取第一个 TXT。
       旧实现只取第一条记录且要求它是 TXT —— 真实权威端常在 TXT 前带 CNAME，
       公网应答因此整条解不出来（全部 -5）。 */
    for (i = 0; i < (int)an; i++) {
        uint16_t type, rdlen;
        uint8_t sl;
        int jumps = 0;

        for (;;) {                                  /* 跳过记录名 */
            uint8_t l;
            if (o >= len) return TX_DNSTUN_ERR_PROTO;
            l = p[o];
            if (l == 0) { o++; break; }
            if ((l & 0xC0) == 0xC0) {
                if (o + 2 > len) return TX_DNSTUN_ERR_PROTO;
                if (++jumps > 8) return TX_DNSTUN_ERR_PROTO;
                o += 2;
                break;
            }
            if ((l & 0xC0) != 0) return TX_DNSTUN_ERR_PROTO;
            o += 1u + (size_t)l;
            if (o >= len) return TX_DNSTUN_ERR_PROTO;
        }
        if (o + 10 > len) return TX_DNSTUN_ERR_PROTO;
        type  = (uint16_t)(((uint16_t)p[o] << 8) | p[o + 1]);
        rdlen = (uint16_t)(((uint16_t)p[o + 8] << 8) | p[o + 9]);
        o += 10;
        if (o + rdlen > len) return TX_DNSTUN_ERR_PROTO;

        if (type != 16) { o += rdlen; continue; }   /* CNAME/A 等：跳过继续找 */
        if (rdlen == 0) return TX_DNSTUN_ERR_PROTO;

        sl = p[o];
        if ((size_t)sl + 1 > rdlen) return TX_DNSTUN_ERR_PROTO;
        if ((size_t)sl > cap) return TX_DNSTUN_ERR_TOOBIG;
        memcpy(out, p + o + 1, sl);
        *olen = (size_t)sl;
        return TX_DNSTUN_OK;
    }
    return TX_DNSTUN_ERR_PROTO;
}

/* ---------------- 隧道端点 ---------------- */
struct tx_dnstun {
    int      sock;
    char     domain[64];
    char     session[32];
    int      timeout_ms;
    int      max_retry;
    uint32_t seq;
    uint8_t  down[4096];
    size_t   downlen;
};

int tx_dnstun_open(tx_dnstun_t **out, const char *resolver_ip, int port,
                   const char *domain, const char *session,
                   int timeout_ms, int max_retry) {
    tx_dnstun_t *t;
    struct sockaddr_in a;
    struct timeval tv;

    if (!out || !resolver_ip || !domain || !session) return TX_DNSTUN_ERR_ARGS;
    if (port <= 0 || port > 65535) return TX_DNSTUN_ERR_ARGS;

    t = (tx_dnstun_t *)calloc(1, sizeof(*t));
    if (!t) return TX_DNSTUN_ERR_SOCK;

    t->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (t->sock < 0) { free(t); return TX_DNSTUN_ERR_SOCK; }

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, resolver_ip, &a.sin_addr) != 1) {
        close(t->sock); free(t); return TX_DNSTUN_ERR_ARGS;
    }
    if (connect(t->sock, (const struct sockaddr *)&a, sizeof(a)) < 0) {
        close(t->sock); free(t); return TX_DNSTUN_ERR_SOCK;
    }

    snprintf(t->domain, sizeof(t->domain), "%s", domain);
    snprintf(t->session, sizeof(t->session), "%s", session);
    t->timeout_ms = timeout_ms > 0 ? timeout_ms : 2000;
    t->max_retry = max_retry > 0 ? max_retry : 5;

    tv.tv_sec = t->timeout_ms / 1000;
    tv.tv_usec = (t->timeout_ms % 1000) * 1000;
    setsockopt(t->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    *out = t;
    return TX_DNSTUN_OK;
}

void tx_dnstun_close(tx_dnstun_t *t) {
    if (!t) return;
    if (t->sock >= 0) close(t->sock);
    memset(t, 0, sizeof(*t));
    free(t);
}

/* 发一片并等待 ACK；返回 0 表示本片被确认 */
static int send_one(tx_dnstun_t *t, uint32_t seq, int fin,
                    const uint8_t *chunk, size_t clen) {
    char name[TX_DNSTUN_MAXNAME + 8];
    uint8_t q[512];
    size_t ql;
    int attempt;

    for (attempt = 0; attempt <= t->max_retry; attempt++) {
        uint8_t resp[2048];
        uint8_t txt[512];
        size_t tl = 0;
        ssize_t rl;

        if (tx_dnstun_label_build(seq, seq, fin, chunk, clen,
                                  t->session, t->domain,
                                  name, sizeof(name)) != TX_DNSTUN_OK)
            return TX_DNSTUN_ERR_TOOBIG;

        ql = tx_dns_build_query_ex(name, (uint16_t)(seq & 0xFFFF), 16 /* TXT */, q, sizeof(q));
        if (ql == 0) return TX_DNSTUN_ERR_PROTO;

        if (send(t->sock, q, ql, 0) < 0) continue;

        rl = recv(t->sock, resp, sizeof(resp), 0);
        if (rl <= 0) continue;                     /* 超时 -> 重传 */

        if (tx_dns_parse_txt(resp, (size_t)rl, txt, sizeof(txt), &tl) != TX_DNSTUN_OK)
            continue;
        if (tl < 5) continue;

        {
            uint32_t a = ((uint32_t)txt[0] << 24) | ((uint32_t)txt[1] << 16) |
                         ((uint32_t)txt[2] << 8) | (uint32_t)txt[3];
            if (a != seq + 1) continue;            /* 非本片确认 */

            /* 捎带下行：txt[4] 为 fin 标志，其后为数据 */
            if (tl > 5) {
                size_t dlen = tl - 5;
                if (t->downlen + dlen <= sizeof(t->down)) {
                    memcpy(t->down + t->downlen, txt + 5, dlen);
                    t->downlen += dlen;
                }
            }
            return TX_DNSTUN_OK;
        }
    }
    return TX_DNSTUN_ERR_RETRY;
}

int tx_dnstun_send(tx_dnstun_t *t, const uint8_t *data, size_t len, size_t *acked) {
    size_t sent = 0;

    /* len==0 是合法的空消息（心跳/探测），此时允许 data 为 NULL */
    if (!t) return TX_DNSTUN_ERR_ARGS;
    if (len > 0 && !data) return TX_DNSTUN_ERR_ARGS;
    if (acked) *acked = 0;

    if (len == 0) {
        /* 空载荷也要走一轮，保持语义一致 */
        int r = send_one(t, t->seq, 1, NULL, 0);
        if (r != TX_DNSTUN_OK) return r;
        t->seq++;
        if (acked) *acked = 0;
        return TX_DNSTUN_OK;
    }

    while (sent < len) {
        size_t n = len - sent;
        int fin, r;
        if (n > TX_DNSTUN_CHUNK) n = TX_DNSTUN_CHUNK;
        fin = (sent + n >= len) ? 1 : 0;

        r = send_one(t, t->seq, fin, data + sent, n);
        if (r != TX_DNSTUN_OK) {
            if (acked) *acked = sent;
            return r;
        }
        t->seq++;
        sent += n;
    }
    if (acked) *acked = sent;
    return TX_DNSTUN_OK;
}

int tx_dnstun_poll(tx_dnstun_t *t, uint8_t *out, size_t cap, size_t *olen) {
    size_t n;
    if (!t || !out || !olen) return TX_DNSTUN_ERR_ARGS;
    if (t->downlen == 0) { *olen = 0; return TX_DNSTUN_OK; }
    n = t->downlen;
    if (n > cap) n = cap;
    memcpy(out, t->down, n);
    memmove(t->down, t->down + n, t->downlen - n);
    t->downlen -= n;
    *olen = n;
    return TX_DNSTUN_OK;
}

int tx_dnstun_exchange(tx_dnstun_t *t, const uint8_t *up, size_t uplen,
                       uint8_t *down, size_t cap, size_t *downlen) {
    size_t before;
    int r;
    if (!t || !down || !downlen) return TX_DNSTUN_ERR_ARGS;
    if (uplen > TX_DNSTUN_CHUNK) return TX_DNSTUN_ERR_TOOBIG;
    before = t->downlen;
    r = send_one(t, t->seq, 1, uplen ? up : NULL, uplen);
    if (r != TX_DNSTUN_OK) return r;
    t->seq++;
    {
        size_t got = t->downlen - before;
        if (got > cap) got = cap;
        memcpy(down, t->down + before, got);
        memmove(t->down, t->down + before + got, t->downlen - before - got);
        t->downlen -= got;
        *downlen = got;
    }
    return TX_DNSTUN_OK;
}

/* ---------------- 权威端 ---------------- */
int tx_dnsauth_listen(int port, int *out_port) {
    int s;
    struct sockaddr_in a;
    socklen_t l;

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return -1;

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    if (bind(s, (const struct sockaddr *)&a, sizeof(a)) < 0) {
        close(s);
        return -1;
    }
    if (out_port) {
        l = sizeof(a);
        if (getsockname(s, (struct sockaddr *)&a, &l) == 0)
            *out_port = ntohs(a.sin_port);
        else
            *out_port = port;
    }
    return s;
}

int tx_dnsauth_serve_once(int sock, tx_dnsauth_cb cb, void *arg, int timeout_ms) {
    uint8_t buf[2048];
    uint8_t out[2048];
    uint8_t txt[TX_DNSTUN_MAXTXT + 8];
    uint8_t down[TX_DNSTUN_MAXTXT];
    uint8_t chunk[TX_DNSTUN_CHUNK + 8];
    char name[TX_DNSTUN_MAXNAME + 8];
    struct sockaddr_in from;
    socklen_t fl = sizeof(from);
    struct timeval tv;
    ssize_t n;
    uint32_t seq = 0, ack = 0;
    int fin = 0;
    size_t clen = 0, downlen = 0, tl;
    uint32_t a;

    if (sock < 0 || !cb) return TX_DNSTUN_ERR_ARGS;

    tv.tv_sec = (timeout_ms > 0 ? timeout_ms : 3000) / 1000;
    tv.tv_usec = (timeout_ms > 0 ? timeout_ms : 3000) % 1000 * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
    if (n <= 0) return TX_DNSTUN_ERR_TIMEOUT;

    if (tx_dns_parse_query(buf, (size_t)n, name, sizeof(name), NULL) != TX_DNSTUN_OK)
        return TX_DNSTUN_ERR_PROTO;

    if (tx_dnstun_label_parse(name, &seq, &ack, &fin,
                              chunk, sizeof(chunk), &clen) != TX_DNSTUN_OK)
        return TX_DNSTUN_ERR_PROTO;

    memset(down, 0, sizeof(down));
    if (cb(seq, fin, chunk, clen, down, sizeof(down), &downlen, arg) != 0)
        return TX_DNSTUN_ERR_PROTO;
    if (downlen > TX_DNSTUN_MAXTXT - 5) downlen = TX_DNSTUN_MAXTXT - 5;

    a = seq + 1;
    txt[0] = (uint8_t)(a >> 24);
    txt[1] = (uint8_t)(a >> 16);
    txt[2] = (uint8_t)(a >> 8);
    txt[3] = (uint8_t)a;
    txt[4] = (uint8_t)(fin ? 1 : 0);
    if (downlen) memcpy(txt + 5, down, downlen);
    tl = 5 + downlen;

    {
        size_t ol = tx_dns_build_txt_reply(buf, (size_t)n, txt, tl, out, sizeof(out));
        if (ol == 0) return TX_DNSTUN_ERR_PROTO;
        if (sendto(sock, out, ol, 0, (const struct sockaddr *)&from, fl) < 0)
            return TX_DNSTUN_ERR_SOCK;
    }
    return TX_DNSTUN_OK;
}
