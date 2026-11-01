/* 自研 A 记录解析器：RFC 1035 over UDP，取代 getaddrinfo。
   不依赖 libc 解析器 / NSS / dlopen，静态链接后在精简目标机也能解析。 */
#include "p2p_resolv.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DNS_PORT      53
#define MAX_PKT       1500
#define QTYPE_A       1
#define QTYPE_CNAME   5
#define CLASS_IN      1
#define MAX_CNAME     8
#define MAX_JUMPS     8
#define DEF_TIMEOUT   3000

const char *p2p_resolv_errstr(int e) {
    switch (e) {
        case P2P_RESOLV_OK:         return "ok";
        case P2P_RESOLV_ERR_ARGS:   return "invalid argument";
        case P2P_RESOLV_ERR_SOCK:   return "socket error";
        case P2P_RESOLV_ERR_SEND:   return "send failed";
        case P2P_RESOLV_ERR_RECV:   return "recv timeout";
        case P2P_RESOLV_ERR_PROTO:  return "malformed response";
        case P2P_RESOLV_ERR_NOADDR: return "no A record";
        case P2P_RESOLV_ERR_LOOP:   return "cname loop";
        case P2P_RESOLV_ERR_NORES:  return "no resolver";
        default:                    return "unknown";
    }
}

int p2p_host_is_ipv4(const char *host, uint32_t *out) {
    if (!host || !*host) return 0;
    unsigned o[4];
    int idx = 0;
    const char *p = host;
    while (idx < 4) {
        if (!isdigit((unsigned char)*p)) return 0;
        unsigned v = 0;
        int nd = 0;
        while (isdigit((unsigned char)*p)) {
            v = v * 10u + (unsigned)(*p - '0');
            if (v > 255) return 0;
            p++; nd++;
            if (nd > 3) return 0;
        }
        o[idx++] = v;
        if (idx < 4) {
            if (*p != '.') return 0;
            p++;
        }
    }
    if (*p != '\0') return 0;
    if (out) {
        uint32_t a = ((uint32_t)o[0] << 24) | ((uint32_t)o[1] << 16) |
                     ((uint32_t)o[2] << 8)  |  (uint32_t)o[3];
        *out = htonl(a);
    }
    return 1;
}

int p2p_resolv_default(char *out, size_t cap) {
    if (!out || cap == 0) return P2P_RESOLV_ERR_ARGS;
    const char *env = getenv("P2P_RESOLVER");
    if (env && *env && strlen(env) < cap) {
        memcpy(out, env, strlen(env) + 1);
        return P2P_RESOLV_OK;
    }
    FILE *f = fopen("/etc/resolv.conf", "r");
    if (!f) return P2P_RESOLV_ERR_NORES;
    char line[256];
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (strncmp(s, "nameserver", 10) != 0) continue;
        s += 10;
        while (*s == ' ' || *s == '\t') s++;
        size_t n = strcspn(s, " \t\r\n");
        if (n == 0 || n >= cap) continue;
        memcpy(out, s, n);
        out[n] = '\0';
        found = 1;
        break;
    }
    fclose(f);
    return found ? P2P_RESOLV_OK : P2P_RESOLV_ERR_NORES;
}

/* 域名 -> DNS 名字序列（长度前缀标签 + 结尾 0） */
static int encode_qname(const char *host, uint8_t *out, size_t cap, size_t *olen) {
    size_t n = strlen(host);
    if (n == 0 || n > P2P_RESOLV_MAXHOST) return P2P_RESOLV_ERR_ARGS;
    if (n + 2 > cap) return P2P_RESOLV_ERR_ARGS;

    /* 先在临时缓冲拼装（长度字节 + 标签内容），最后整体拷出。
       早期版本原地回填长度字节算到了 out[-1]，把报文写坏 —— 公网解析因此全失败。 */
    uint8_t tmp[P2P_RESOLV_MAXHOST + 2];
    size_t t = 0;
    size_t lab = 0;
    for (size_t i = 0; i <= n; i++) {
        char c = (i < n) ? host[i] : '\0';
        if (c == '.' || c == '\0') {
            if (lab == 0) return P2P_RESOLV_ERR_ARGS;      /* 空标签 */
            if (lab > 63) return P2P_RESOLV_ERR_ARGS;      /* 单标签超长 */
            if (t + 1 + lab + 1 > sizeof tmp) return P2P_RESOLV_ERR_ARGS;
            tmp[t++] = (uint8_t)lab;
            memcpy(tmp + t, host + i - lab, lab);
            t += lab;
            lab = 0;
            if (c == '\0') break;
        } else {
            lab++;
        }
    }
    tmp[t++] = 0;                                          /* 根标签 */
    if (t > cap) return P2P_RESOLV_ERR_ARGS;
    memcpy(out, tmp, t);
    *olen = t;
    return P2P_RESOLV_OK;
}

/* 跳过一个 DNS 名字（支持 0xC0 压缩指针） */
static int skip_name(const uint8_t *p, size_t len, size_t *off) {
    size_t o = *off;
    int jumps = 0;
    for (;;) {
        if (o >= len) return P2P_RESOLV_ERR_PROTO;
        uint8_t l = p[o];
        if (l == 0) { o++; *off = o; return P2P_RESOLV_OK; }
        if ((l & 0xc0) == 0xc0) {
            if (o + 2 > len) return P2P_RESOLV_ERR_PROTO;
            if (++jumps > MAX_JUMPS) return P2P_RESOLV_ERR_PROTO;
            o += 2;
            *off = o;
            return P2P_RESOLV_OK;
        }
        if ((l & 0xc0) != 0) return P2P_RESOLV_ERR_PROTO;
        o += 1u + (size_t)l;
        if (o >= len) return P2P_RESOLV_ERR_PROTO;
    }
}

/* 读取压缩指针处的名字，拼成点分形式（仅 CNAME 追赶需要） */
static int read_name(const uint8_t *p, size_t len, size_t off,
                     char *out, size_t cap) {
    size_t o = off;
    size_t w = 0;
    int jumps = 0;
    int first = 1;
    for (;;) {
        if (o >= len) return P2P_RESOLV_ERR_PROTO;
        uint8_t l = p[o];
        if (l == 0) {
            o++;
            break;
        }
        if ((l & 0xc0) == 0xc0) {
            if (o + 2 > len) return P2P_RESOLV_ERR_PROTO;
            if (++jumps > MAX_JUMPS) return P2P_RESOLV_ERR_PROTO;
            o = (size_t)((p[o] & 0x3f) << 8) | p[o + 1];
            continue;
        }
        if ((l & 0xc0) != 0) return P2P_RESOLV_ERR_PROTO;
        if (w + l + 1 >= cap) return P2P_RESOLV_ERR_PROTO;
        if (!first) out[w++] = '.';
        first = 0;
        if (o + 1u + l > len) return P2P_RESOLV_ERR_PROTO;
        memcpy(out + w, p + o + 1, l);
        w += l;
        o += 1u + l;
    }
    out[w] = '\0';
    return (w == 0) ? P2P_RESOLV_ERR_PROTO : P2P_RESOLV_OK;
}

static int query_a_once(const char *host, const char *resolver,
                        int timeout_ms, uint32_t *addr, char *cname,
                        size_t cname_cap) {
    uint8_t q[MAX_PKT];
    size_t qlen = 0;
    if (encode_qname(host, q + 12, sizeof q - 12 - 4, &qlen) != P2P_RESOLV_OK)
        return P2P_RESOLV_ERR_ARGS;

    uint16_t tid = (uint16_t)(((uintptr_t)host >> 4) ^ (uintptr_t)resolver ^
                              (uintptr_t)&timeout_ms);
    /* 报文头：ID + RD=1 + QDCOUNT=1 */
    q[0] = (uint8_t)(tid >> 8); q[1] = (uint8_t)(tid & 0xff);
    q[2] = 0x01; q[3] = 0x00;
    q[4] = 0; q[5] = 1;
    q[6] = q[7] = q[8] = q[9] = q[10] = q[11] = 0;
    /* qtype=A, qclass=IN */
    q[12 + qlen]     = 0; q[12 + qlen + 1] = QTYPE_A;
    q[12 + qlen + 2] = 0; q[12 + qlen + 3] = CLASS_IN;
    qlen += 12 + 4;

    uint32_t rip;
    if (!p2p_host_is_ipv4(resolver, &rip)) return P2P_RESOLV_ERR_ARGS;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return P2P_RESOLV_ERR_SOCK;

    struct timeval tv;
    tv.tv_sec  = (timeout_ms > 0 ? timeout_ms : DEF_TIMEOUT) / 1000;
    tv.tv_usec = (timeout_ms > 0 ? timeout_ms : DEF_TIMEOUT) % 1000 * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = rip;
    sa.sin_port = htons(DNS_PORT);

    int rc;
    if (sendto(fd, q, qlen, 0, (struct sockaddr *)&sa, sizeof sa) < 0) {
        rc = P2P_RESOLV_ERR_SEND;
        goto out;
    }

    uint8_t r[MAX_PKT];
    ssize_t n = recvfrom(fd, r, sizeof r, 0, NULL, NULL);
    if (n < 12) { rc = (n < 0) ? P2P_RESOLV_ERR_RECV : P2P_RESOLV_ERR_PROTO; goto out; }

    /* 校验事务 ID 与 QR 位 */
    if (r[0] != (uint8_t)(tid >> 8) || r[1] != (uint8_t)(tid & 0xff)) {
        rc = P2P_RESOLV_ERR_PROTO; goto out;
    }
    if (!(r[2] & 0x80)) { rc = P2P_RESOLV_ERR_PROTO; goto out; }
    if ((r[3] & 0x0f) != 0) { rc = P2P_RESOLV_ERR_PROTO; goto out; }

    size_t qd = (size_t)((r[4] << 8) | r[5]);
    size_t an = (size_t)((r[6] << 8) | r[7]);
    size_t off = 12;

    for (size_t i = 0; i < qd; i++) {
        if (skip_name(r, (size_t)n, &off) != P2P_RESOLV_OK) { rc = P2P_RESOLV_ERR_PROTO; goto out; }
        off += 4;
        if (off > (size_t)n) { rc = P2P_RESOLV_ERR_PROTO; goto out; }
    }

    rc = P2P_RESOLV_ERR_NOADDR;
    for (size_t i = 0; i < an; i++) {
        size_t nameoff = off;
        if (skip_name(r, (size_t)n, &off) != P2P_RESOLV_OK) { rc = P2P_RESOLV_ERR_PROTO; break; }
        if (off + 10 > (size_t)n) { rc = P2P_RESOLV_ERR_PROTO; break; }
        uint16_t ty = (uint16_t)((r[off] << 8) | r[off + 1]);
        uint16_t rdlen = (uint16_t)((r[off + 8] << 8) | r[off + 9]);
        off += 10;
        if (off + rdlen > (size_t)n) { rc = P2P_RESOLV_ERR_PROTO; break; }

        if (ty == QTYPE_A && rdlen == 4) {
            memcpy(addr, r + off, 4);
            rc = P2P_RESOLV_OK;
            break;
        }
        if (ty == QTYPE_CNAME && cname) {
            if (read_name(r, (size_t)n, off, cname, cname_cap) == P2P_RESOLV_OK) {
                off += rdlen;
                continue;
            }
        }
        off += rdlen;
        (void)nameoff;
    }
out:
    close(fd);
    return rc;
}

int p2p_resolve_a(const char *host, const char *resolver,
                  int timeout_ms, uint32_t *out) {
    if (!host || !*host || !out) return P2P_RESOLV_ERR_ARGS;
    if (p2p_host_is_ipv4(host, out)) return P2P_RESOLV_OK;
    if (strlen(host) > P2P_RESOLV_MAXHOST) return P2P_RESOLV_ERR_ARGS;

    char res[64];
    const char *r = resolver;
    if (!r || !*r) {
        if (p2p_resolv_default(res, sizeof res) != P2P_RESOLV_OK)
            return P2P_RESOLV_ERR_NORES;
        r = res;
    }

    char cur[P2P_RESOLV_MAXHOST + 1];
    snprintf(cur, sizeof cur, "%s", host);

    for (int depth = 0; depth <= MAX_CNAME; depth++) {
        uint32_t a = 0;
        char cn[P2P_RESOLV_MAXHOST + 1];
        cn[0] = '\0';
        int rc = query_a_once(cur, r, timeout_ms, &a, cn, sizeof cn);
        if (rc == P2P_RESOLV_OK) { *out = a; return P2P_RESOLV_OK; }
        if (rc != P2P_RESOLV_ERR_NOADDR) return rc;
        if (cn[0] == '\0') return P2P_RESOLV_ERR_NOADDR;
        if (strcmp(cn, cur) == 0) return P2P_RESOLV_ERR_LOOP;
        snprintf(cur, sizeof cur, "%s", cn);
    }
    return P2P_RESOLV_ERR_LOOP;
}

int p2p_resolve_sa(const char *host, uint16_t port,
                   const char *resolver, int timeout_ms,
                   struct sockaddr_in *out) {
    if (!host || !out) return P2P_RESOLV_ERR_ARGS;
    uint32_t a = 0;
    int rc = p2p_resolve_a(host, resolver, timeout_ms, &a);
    if (rc != P2P_RESOLV_OK) return rc;
    memset(out, 0, sizeof *out);
    out->sin_family = AF_INET;
    out->sin_addr.s_addr = a;
    out->sin_port = htons(port);
    return P2P_RESOLV_OK;
}
