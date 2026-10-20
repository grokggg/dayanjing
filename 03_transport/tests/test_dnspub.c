#define _DEFAULT_SOURCE
#include "dnstun.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int g_total = 0, g_pass = 0, g_fail = 0, g_skip = 0;

#define CHECK(cond, name) do {                                    \
    g_total++;                                                    \
    if (cond) { g_pass++; printf("[PASS] %s\n", name); }          \
    else      { g_fail++; printf("[FAIL] %s\n", name); }          \
} while (0)

#define SKIP(name) do {                                           \
    g_total++; g_skip++;                                          \
    printf("[SKIP] %s\n", name);                                  \
} while (0)

/* 向真实公网解析器发一条隧道查询，返回应答 rcode */
static int probe(const char *resolver, const char *domain, const char *session,
                 const uint8_t *chunk, size_t clen,
                 int *rcode, size_t *rlen) {
    char name[TX_DNSTUN_MAXNAME + 8];
    uint8_t q[512];
    uint8_t resp[2048];
    size_t ql;
    int s;
    struct sockaddr_in a;
    struct timeval tv;
    socklen_t sl;
    ssize_t n;

    if (tx_dnstun_label_build(0x1122, 0x3344, 1, chunk, clen,
                              session, domain, name, sizeof(name)) != TX_DNSTUN_OK)
        return -1;
    ql = tx_dns_build_query(name, 0x1234, q, sizeof(q));
    if (ql == 0) return -1;

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return -1;

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(53);
    if (inet_pton(AF_INET, resolver, &a.sin_addr) != 1) { close(s); return -1; }

    tv.tv_sec = 6;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (sendto(s, q, ql, 0, (const struct sockaddr *)&a, sizeof(a)) < 0) {
        close(s);
        return -1;
    }
    sl = sizeof(a);
    n = recvfrom(s, resp, sizeof(resp), 0, (struct sockaddr *)&a, &sl);
    close(s);
    if (n < 12) return -1;

    *rlen = (size_t)n;
    *rcode = resp[3] & 0x0F;
    return 0;
}

int main(void) {
    /* 真实公网解析器 */
    static const char *resolvers[] = {
        "8.8.8.8",        /* Google */
        "1.1.1.1",        /* Cloudflare */
        "223.5.5.5",      /* AliDNS */
        "119.29.29.29",   /* DNSPod */
        "183.60.83.19",   /* Tencent */
    };
    const int nres = (int)(sizeof(resolvers) / sizeof(resolvers[0]));

    uint8_t chunk[TX_DNSTUN_CHUNK];
    size_t i;
    int reachable = 0;
    int ri;
    char session[32];

    for (i = 0; i < sizeof(chunk); i++) chunk[i] = (uint8_t)(i * 11 + 3);

    printf("=== DNS 隧道 · 真实公网递归验证 ===\n");
    printf("（把隧道载荷编码进 QNAME，发往真实解析器，验证报文被合规接受）\n\n");

    for (ri = 0; ri < nres; ri++) {
        int rcode = -1;
        size_t rlen = 0;
        snprintf(session, sizeof(session), "s%04x%04x", ri, (int)i);
        if (probe(resolvers[ri], "tun.example.com", session,
                  chunk, sizeof(chunk), &rcode, &rlen) == 0) {
            reachable = 1;
            printf("  %-16s -> 收到 %zu 字节应答, rcode=%d\n",
                   resolvers[ri], rlen, rcode);
            CHECK(rcode != 1, "报文未被判 FORMERR（说明 QNAME 编码合规）");
            CHECK(rlen >= 12, "应答长度合法");
        } else {
            printf("  %-16s -> 无应答/不可达\n", resolvers[ri]);
        }
    }

    if (!reachable) {
        printf("\n[!] 所有公网解析器均不可达，公网验证跳过\n");
        SKIP("公网可达性");
        printf("\ntotal=%d pass=%d fail=%d skip=%d\n", g_total, g_pass, g_fail, g_skip);
        return 0;
    }

    /* 不同载荷应产生不同的查询报文 —— 验证数据确实被编码进去 */
    {
        uint8_t a1[40], a2[40];
        char n1[TX_DNSTUN_MAXNAME + 8], n2[TX_DNSTUN_MAXNAME + 8];
        memset(a1, 0x41, sizeof(a1));
        memset(a2, 0x42, sizeof(a2));
        CHECK(tx_dnstun_label_build(1, 1, 1, a1, sizeof(a1), "sess", "tun.example.com",
                                    n1, sizeof(n1)) == TX_DNSTUN_OK, "载荷A 编码成功");
        CHECK(tx_dnstun_label_build(1, 1, 1, a2, sizeof(a2), "sess", "tun.example.com",
                                    n2, sizeof(n2)) == TX_DNSTUN_OK, "载荷B 编码成功");
        CHECK(strcmp(n1, n2) != 0, "不同载荷产生不同 QNAME（数据确实入查询）");
    }

    /* 分片尺寸：100 字节满片在真实解析器上不超限 */
    {
        char name[TX_DNSTUN_MAXNAME + 8];
        int rc = tx_dnstun_label_build(0xFFFFFFFF, 0xFFFFFFFF, 1,
                                       chunk, TX_DNSTUN_CHUNK, "sess9999",
                                       "tun.example.com", name, sizeof(name));
        CHECK(rc == TX_DNSTUN_OK, "满片在最大 seq 下仍构造成功");
        if (rc == TX_DNSTUN_OK) {
            printf("  [info] 满片 QNAME 长度=%zu (上限 %d)\n",
                   strlen(name), TX_DNSTUN_MAXNAME);
            CHECK(strlen(name) <= TX_DNSTUN_MAXNAME, "满片 QNAME 不超 253");
        }
    }

    printf("\ntotal=%d pass=%d fail=%d skip=%d\n", g_total, g_pass, g_fail, g_skip);
    return g_fail ? 1 : 0;
}
