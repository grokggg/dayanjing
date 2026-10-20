/* 自研解析器测试：取代 getaddrinfo 后的正确性 + 真实公网解析 */
#include "p2p_resolv.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

static int pass = 0, fail = 0;

static void ck(int cond, const char *name) {
    if (cond) { pass++; printf("[PASS] %s\n", name); }
    else      { fail++; printf("[FAIL] %s\n", name); }
}

int main(void) {
    uint32_t a = 0;

    /* ---- 1. IPv4 字面量：不发任何报文 ---- */
    ck(p2p_host_is_ipv4("127.0.0.1", &a) == 1 && ntohl(a) == 0x7f000001u, "literal 127.0.0.1");
    ck(p2p_host_is_ipv4("1.2.3.4",   &a) == 1 && ntohl(a) == 0x01020304u, "literal 1.2.3.4");
    ck(p2p_host_is_ipv4("255.255.255.255", &a) == 1 && ntohl(a) == 0xffffffffu, "literal 255.255.255.255");
    ck(p2p_host_is_ipv4("0.0.0.0",   &a) == 1 && ntohl(a) == 0u, "literal 0.0.0.0");

    /* ---- 2. 非字面量必须判否（否则会被当域名发出去） ---- */
    ck(p2p_host_is_ipv4("localhost", &a) == 0, "reject localhost");
    ck(p2p_host_is_ipv4("1.2.3",     &a) == 0, "reject 3 octets");
    ck(p2p_host_is_ipv4("1.2.3.4.5", &a) == 0, "reject 5 octets");
    ck(p2p_host_is_ipv4("256.1.1.1", &a) == 0, "reject >255");
    ck(p2p_host_is_ipv4("1.2.3.a",   &a) == 0, "reject alpha");
    ck(p2p_host_is_ipv4("",          &a) == 0, "reject empty");
    ck(p2p_host_is_ipv4("1..2",      &a) == 0, "reject empty label");
    ck(p2p_host_is_ipv4("1.2.3.4 ",  &a) == 0, "reject trailing space");

    /* ---- 3. 字面量走 resolve_a 不应联网就返回 ---- */
    ck(p2p_resolve_a("127.0.0.1", NULL, 0, &a) == P2P_RESOLV_OK && ntohl(a) == 0x7f000001u,
       "resolve_a literal short-circuit");

    /* ---- 4. 参数校验 ---- */
    ck(p2p_resolve_a(NULL, NULL, 0, &a) == P2P_RESOLV_ERR_ARGS, "args: null host");
    ck(p2p_resolve_a("a.com", NULL, 0, NULL) == P2P_RESOLV_ERR_ARGS, "args: null out");

    char longhost[P2P_RESOLV_MAXHOST + 8];
    memset(longhost, 'a', sizeof longhost - 1);
    longhost[sizeof longhost - 1] = '\0';
    ck(p2p_resolve_a(longhost, NULL, 0, &a) == P2P_RESOLV_ERR_ARGS, "args: host too long");

    /* ---- 5. sockaddr 便捷接口 ---- */
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    ck(p2p_resolve_sa("10.20.30.40", 8080, NULL, 0, &sa) == P2P_RESOLV_OK &&
       sa.sin_family == AF_INET && sa.sin_port == htons(8080) &&
       sa.sin_addr.s_addr == htonl(0x0a141e28u), "resolve_sa fills addr+port");

    /* ---- 6. 默认解析器发现 ---- */
    char res[64];
    int rr = p2p_resolv_default(res, sizeof res);
    printf("[INFO] 默认解析器: %s (%s)\n", rr == P2P_RESOLV_OK ? res : "(none)",
           p2p_resolv_errstr(rr));
    ck(rr == P2P_RESOLV_OK || rr == P2P_RESOLV_ERR_NORES, "resolv_default 不崩溃");

    /* ---- 7. 真实公网解析（无网络时 SKIP，不算失败） ---- */
    const char *rsv[] = { "223.5.5.5", "119.29.29.29", "8.8.8.8", "1.1.1.1" };
    int done = 0;
    for (size_t i = 0; i < sizeof rsv / sizeof rsv[0] && !done; i++) {
        int rc = p2p_resolve_a("example.com", rsv[i], 4000, &a);
        if (rc == P2P_RESOLV_OK) {
            char buf[32];
            inet_ntop(AF_INET, &a, buf, sizeof buf);
            printf("[PASS] 真实公网解析 example.com -> %s (via %s)\n", buf, rsv[i]);
            pass++;
            done = 1;
        } else if (rc == P2P_RESOLV_ERR_RECV) {
            printf("[INFO] 解析器 %s 超时，换下一个\n", rsv[i]);
        } else {
            printf("[INFO] 解析器 %s 返回 %s\n", rsv[i], p2p_resolv_errstr(rc));
        }
    }
    if (!done) printf("[SKIP] 无可用公网解析器（网络不可达），公网解析未验证\n");

    printf("\ntotal=%d pass=%d fail=%d\n", pass + fail, pass, fail);
    return fail ? 1 : 0;
}
