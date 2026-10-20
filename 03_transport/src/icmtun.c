#include "tx_icmtun.h"
#include "tx_swin.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>

static const uint8_t ICMTUN_MAGIC[4] = { 0x1c, 0x2a, 0x4d, 0x54 };

const char *tx_icmtun_errstr(int e) {
    switch (e) {
        case TX_ICMTUN_OK:           return "ok";
        case TX_ICMTUN_ERR_ARGS:     return "invalid argument";
        case TX_ICMTUN_ERR_SOCK:     return "socket error";
        case TX_ICMTUN_ERR_TIMEOUT:  return "timeout";
        case TX_ICMTUN_ERR_RETRY:    return "retry exhausted";
        case TX_ICMTUN_ERR_PROTO:    return "protocol error";
        case TX_ICMTUN_ERR_TOOBIG:   return "payload too big";
        case TX_ICMTUN_ERR_NOSPACE:  return "no space";
        default:                     return "unknown";
    }
}

static uint16_t icmp_cksum(const uint16_t *b, int n) {
    unsigned long s = 0;
    while (n > 1) { s += *b++; n -= 2; }
    if (n) s += *(const uint8_t *)b;
    s = (s >> 16) + (s & 0xffff);
    s += (s >> 16);
    return (uint16_t)~s;
}

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static uint32_t get_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

size_t tx_icmp_build_echo(uint16_t id, uint16_t eseque,
                          uint32_t tseq, uint32_t tack, uint8_t flags,
                          const uint8_t *data, size_t len,
                          uint8_t *out, size_t cap) {
    if (!out || cap < TX_ICMP_HDR + TX_ICMTUN_HDR) return 0;
    if (len > TX_ICMTUN_CHUNK) return 0;
    if (len > 0 && !data) return 0;
    size_t total = TX_ICMP_HDR + TX_ICMTUN_HDR + len;
    if (total > cap) return 0;

    memset(out, 0, total);
    struct icmphdr *ic = (struct icmphdr *)out;
    ic->type = 8;
    ic->code = 0;
    ic->checksum = 0;
    ic->un.echo.id = htons(id);
    ic->un.echo.sequence = htons(eseque);

    uint8_t *p = out + TX_ICMP_HDR;
    memcpy(p, ICMTUN_MAGIC, 4);
    put_be32(p + 4, tseq);
    put_be32(p + 8, tack);
    p[12] = flags;
    p[13] = (uint8_t)len;
    if (len) memcpy(p + TX_ICMTUN_HDR, data, len);

    ic->checksum = icmp_cksum((const uint16_t *)out, (int)total);
    return total;
}

int tx_icmp_parse_echo(const uint8_t *pkt, size_t len,
                       uint16_t *id, uint16_t *eseque,
                       uint32_t *tseq, uint32_t *tack, uint8_t *flags,
                       uint8_t *data, size_t cap, size_t *dlen) {
    if (!pkt || !dlen) return TX_ICMTUN_ERR_ARGS;
    *dlen = 0;
    if (len < TX_ICMP_HDR + TX_ICMTUN_HDR) return TX_ICMTUN_ERR_PROTO;

    /* 若带 IP 头则跳过 */
    const uint8_t *ic = pkt;
    if ((pkt[0] >> 4) == 4) {
        size_t ihl = (size_t)(pkt[0] & 0x0f) * 4;
        if (ihl < 20 || len < ihl + TX_ICMP_HDR + TX_ICMTUN_HDR)
            return TX_ICMTUN_ERR_PROTO;
        ic = pkt + ihl;
    }
    if (ic[0] != 0 && ic[0] != 8) return TX_ICMTUN_ERR_PROTO;

    const uint8_t *p = ic + TX_ICMP_HDR;
    if (memcmp(p, ICMTUN_MAGIC, 4) != 0) return TX_ICMTUN_ERR_PROTO;

    uint8_t fl = p[12];
    size_t n = p[13];
    size_t avail = len - (size_t)(p + TX_ICMTUN_HDR - pkt);
    if (n > avail) return TX_ICMTUN_ERR_PROTO;
    if (n > cap) return TX_ICMTUN_ERR_NOSPACE;
    if (n > 0 && !data) return TX_ICMTUN_ERR_ARGS;
    if (n) memcpy(data, p + TX_ICMTUN_HDR, n);

    if (id)     *id     = (uint16_t)((ic[4] << 8) | ic[5]);
    if (eseque) *eseque = (uint16_t)((ic[6] << 8) | ic[7]);
    if (tseq)   *tseq   = get_be32(p + 4);
    if (tack)   *tack   = get_be32(p + 8);
    if (flags)  *flags  = fl;
    *dlen = n;
    return TX_ICMTUN_OK;
}

struct tx_icmtun {
    int      fd;
    int      timeout_ms;
    int      max_retry;
    size_t   chunk;
    uint16_t id;
    uint16_t eseq;
    struct sockaddr_in dst;
    /* 下行捎带是单帧，无需重排，用 FIFO；窗口只用于上行可靠发送 */
    uint8_t  downq[8][TX_ICMTUN_CHUNK];
    uint16_t downq_len[8];
    int      downq_head, downq_tail, downq_count;
};

int tx_icmtun_open(tx_icmtun_t **out, const char *target_ip,
                   int timeout_ms, int max_retry, size_t chunk) {
    if (!out || !target_ip) return TX_ICMTUN_ERR_ARGS;
    if (chunk == 0) chunk = TX_ICMTUN_CHUNK;
    if (chunk > TX_ICMTUN_CHUNK) chunk = TX_ICMTUN_CHUNK;

    tx_icmtun_t *t = calloc(1, sizeof(*t));
    if (!t) return TX_ICMTUN_ERR_SOCK;

    t->fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (t->fd < 0) { free(t); return TX_ICMTUN_ERR_SOCK; }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(t->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    t->timeout_ms = timeout_ms > 0 ? timeout_ms : 1000;
    t->max_retry = max_retry > 0 ? max_retry : 3;
    t->chunk = chunk;
    t->id = (uint16_t)(0x1000 | (getpid() & 0x0fff));
    t->eseq = 1;
    memset(&t->dst, 0, sizeof(t->dst));
    t->dst.sin_family = AF_INET;
    if (inet_pton(AF_INET, target_ip, &t->dst.sin_addr) != 1) {
        close(t->fd); free(t); return TX_ICMTUN_ERR_ARGS;
    }
    t->downq_head = t->downq_tail = t->downq_count = 0;
    *out = t;
    return TX_ICMTUN_OK;
}

void tx_icmtun_close(tx_icmtun_t *t) {
    if (!t) return;
    if (t->fd >= 0) close(t->fd);
    free(t);
}

/* 收一帧带 SRV 位的 reply；非隧道包或内核回显一律跳过继续等 */
static int recv_srv(tx_icmtun_t *t, uint32_t *tack, uint8_t *flags,
                    uint8_t *data, size_t cap, size_t *dlen) {
    uint8_t buf[TX_ICMTUN_MAXPKT];
    int waited = 0;
    while (waited < t->timeout_ms) {
        struct pollfd pf;
        pf.fd = t->fd; pf.events = POLLIN; pf.revents = 0;
        int pr = poll(&pf, 1, (t->timeout_ms - waited > 50) ? 50 : (t->timeout_ms - waited));
        if (pr == 0) { waited += 50; continue; }
        if (pr < 0) {
            if (errno == EINTR) continue;
            return TX_ICMTUN_ERR_SOCK;
        }
        ssize_t r = recv(t->fd, buf, sizeof buf, 0);
        if (r <= 0) continue;
        uint8_t fl = 0; uint32_t ak = 0; size_t dl = 0; uint16_t rid = 0;
        uint8_t tmp[TX_ICMTUN_CHUNK];
        int rc = tx_icmp_parse_echo(buf, (size_t)r, &rid, NULL, NULL, &ak, &fl,
                                    tmp, sizeof tmp, &dl);
        if (rc != TX_ICMTUN_OK) continue;
        if (!(fl & TX_ICMTUN_SRV)) continue;       /* 内核自动回显，忽略 */
        if (rid != t->id) continue;
        if (tack) *tack = ak;
        if (flags) *flags = fl;
        if (dlen) {
            *dlen = 0;
            if (dl > 0 && dl <= cap && data) { memcpy(data, tmp, dl); *dlen = dl; }
        }
        return TX_ICMTUN_OK;
    }
    return TX_ICMTUN_ERR_TIMEOUT;
}

static int send_one(tx_icmtun_t *t, uint32_t tseq, uint8_t flags,
                    const uint8_t *d, size_t n) {
    uint8_t pkt[TX_ICMTUN_MAXPKT];
    size_t pl = tx_icmp_build_echo(t->id, t->eseq++, tseq, 0, flags, d, n,
                                   pkt, sizeof pkt);
    if (pl == 0) return TX_ICMTUN_ERR_ARGS;
    ssize_t w = sendto(t->fd, pkt, pl, 0,
                       (struct sockaddr *)&t->dst, sizeof t->dst);
    if (w < 0) return TX_ICMTUN_ERR_SOCK;
    return TX_ICMTUN_OK;
}

int tx_icmtun_send(tx_icmtun_t *t, const uint8_t *data, size_t len) {
    if (!t) return TX_ICMTUN_ERR_ARGS;
    if (len > 0 && !data) return TX_ICMTUN_ERR_ARGS;
    if (len > (size_t)TX_SWIN_MAX * TX_ICMTUN_CHUNK) return TX_ICMTUN_ERR_TOOBIG;

    size_t nchunks = (len + t->chunk - 1) / t->chunk;
    if (len == 0) nchunks = 0;
    uint32_t total = (uint32_t)nchunks + 1;   /* 末片为 FIN */

    tx_swin_tx_t w;
    tx_swin_tx_init(&w, TX_SWIN_MAX, total);

    int retries = 0;
    int last_err = TX_ICMTUN_OK;

    while (!tx_swin_tx_done(&w)) {
        /* 窗口内尽量发 */
        uint32_t seq;
        while (tx_swin_tx_next(&w, &seq) == 0) {
            int is_fin = (seq == total - 1) ? 1 : 0;
            const uint8_t *p = NULL; size_t n = 0;
            if (!is_fin) {
                size_t off = (size_t)seq * t->chunk;
                n = (len - off > t->chunk) ? t->chunk : (len - off);
                p = data + off;
            }
            int rc = send_one(t, seq, (uint8_t)(is_fin ? TX_ICMTUN_FIN : 0), p, n);
            if (rc != TX_ICMTUN_OK) return rc;
        }
        /* 等 ACK */
        uint32_t ack = 0; uint8_t fl = 0;
        uint8_t dwn[TX_ICMTUN_CHUNK]; size_t dl = 0;
        int rc = recv_srv(t, &ack, &fl, dwn, sizeof dwn, &dl);
        if (rc != TX_ICMTUN_OK) {
            if (++retries > t->max_retry) return TX_ICMTUN_ERR_RETRY;
            last_err = rc;
            /* 超时：回退 next 到 base，重扫窗口 */
            w.next = w.base;
            continue;
        }
        if (!(fl & TX_ICMTUN_ACKV)) continue;
        if (tx_swin_tx_ack(&w, ack) != 0) continue;
        retries = 0;
        if (dl > 0 && t->downq_count < 8) {
            memcpy(t->downq[t->downq_tail], dwn, dl);
            t->downq_len[t->downq_tail] = (uint16_t)dl;
            t->downq_tail = (t->downq_tail + 1) % 8;
            t->downq_count++;
        }
    }
    (void)last_err;
    return TX_ICMTUN_OK;
}

int tx_icmtun_poll(tx_icmtun_t *t, uint8_t *out, size_t cap, size_t *olen) {
    if (!t || !olen) return TX_ICMTUN_ERR_ARGS;
    *olen = 0;
    if (t->downq_count == 0) return TX_ICMTUN_ERR_TIMEOUT;
    size_t n = t->downq_len[t->downq_head];
    if (n > cap) return TX_ICMTUN_ERR_NOSPACE;
    if (n > 0 && !out) return TX_ICMTUN_ERR_ARGS;
    if (n) memcpy(out, t->downq[t->downq_head], n);
    t->downq_head = (t->downq_head + 1) % 8;
    t->downq_count--;
    *olen = n;
    return TX_ICMTUN_OK;
}

int tx_icmpsrv_open(void) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    return fd;
}

int tx_icmpsrv_serve_once(int fd, tx_icmpsrv_cb cb, void *arg, int timeout_ms) {
    if (fd < 0 || !cb) return TX_ICMTUN_ERR_ARGS;
    uint8_t buf[TX_ICMTUN_MAXPKT];
    struct sockaddr_in src;
    socklen_t sl = sizeof src;

    int waited = 0;
    while (waited < timeout_ms) {
        struct pollfd pf;
        pf.fd = fd; pf.events = POLLIN; pf.revents = 0;
        int step = (timeout_ms - waited > 50) ? 50 : (timeout_ms - waited);
        int pr = poll(&pf, 1, step);
        if (pr == 0) { waited += 50; continue; }
        if (pr < 0) { if (errno == EINTR) continue; return TX_ICMTUN_ERR_SOCK; }

        ssize_t r = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&src, &sl);
        if (r <= 0) continue;

        uint8_t fl = 0, tmp[TX_ICMTUN_CHUNK]; size_t dl = 0;
        uint32_t tseq = 0; uint16_t rid = 0, rseq = 0;
        int rc = tx_icmp_parse_echo(buf, (size_t)r, &rid, &rseq, &tseq, NULL, &fl,
                                    tmp, sizeof tmp, &dl);
        if (rc != TX_ICMTUN_OK) continue;
        if (fl & TX_ICMTUN_SRV) continue;   /* 不处理自己/别人发的 reply */
        if (buf[0] == 4 && ((struct iphdr *)buf)->protocol != IPPROTO_ICMP) continue;

        /* 确认源是 IPv4 且能拿到源地址 */
        struct in_addr srcaddr;
        if ((buf[0] >> 4) == 4) {
            struct iphdr *ip = (struct iphdr *)buf;
            srcaddr.s_addr = ip->saddr;
        } else {
            srcaddr = src.sin_addr;
        }

        uint8_t down[TX_ICMTUN_CHUNK]; size_t downlen = 0;
        if (cb(tseq, fl, tmp, dl, down, sizeof down, &downlen, arg) != 0)
            continue;

        uint8_t pkt[TX_ICMTUN_MAXPKT];
        size_t pl = tx_icmp_build_echo(rid, rseq, tseq, tseq + 1,
                                       (uint8_t)(TX_ICMTUN_SRV | TX_ICMTUN_ACKV |
                                                 (downlen ? 0 : 0)),
                                       down, downlen, pkt, sizeof pkt);
        if (pl == 0) continue;
        /* 改写为 ECHO_REPLY */
        pkt[0] = 0;
        struct icmphdr *ic = (struct icmphdr *)pkt;
        ic->checksum = 0;
        ic->checksum = icmp_cksum((const uint16_t *)pkt, (int)pl);

        char ipstr[64];
        const char *a = inet_ntop(AF_INET, &srcaddr, ipstr, sizeof ipstr);
        struct sockaddr_in d;
        memset(&d, 0, sizeof d);
        d.sin_family = AF_INET;
        if (a) inet_pton(AF_INET, a, &d.sin_addr);
        else   d.sin_addr = src.sin_addr;
        sendto(fd, pkt, pl, 0, (struct sockaddr *)&d, sizeof d);
        return TX_ICMTUN_OK;
    }
    return TX_ICMTUN_ERR_TIMEOUT;
}
