#include "lateral.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>

static int fails = 0, total = 0;
static void ck(const char *name, int cond) {
    total++;
    if (!cond) { fails++; printf("  FAIL: %s\n", name); }
    else printf("  ok  : %s\n", name);
}

/* 在 127.0.0.1 上开一个监听 socket，返回其端口；fd 保存在 *fd */
static int open_listener(int *fd) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(s, (struct sockaddr *)&sa, sizeof sa) < 0) { close(s); return -1; }
    if (listen(s, 5) < 0) { close(s); return -1; }
    struct sockaddr_in got; socklen_t gl = sizeof got;
    if (getsockname(s, (struct sockaddr *)&got, &gl) < 0) { close(s); return -1; }
    *fd = s;
    return (int)ntohs(got.sin_port);
}

int main(void) {
    printf("=== 08_lateral 测试 ===\n");

    /* --- CIDR / 端口（原最小单元） --- */
    lat_cidr_t c;
    ck("cidr parse /24", lat_cidr_parse("192.168.1.0/24", &c) == 0);
    ck("cidr base", c.base == 0xC0A80100u);
    uint32_t hosts = 0;
    lat_cidr_hosts(&c, &hosts);
    ck("cidr hosts /24 == 254", hosts == 254);
    lat_cidr_t c32;
    lat_cidr_parse("10.0.0.1/32", &c32);
    lat_cidr_hosts(&c32, &hosts);
    ck("cidr hosts /32 == 1", hosts == 1);

    int ports[16]; size_t pn = 0;
    ck("ports parse", lat_ports_parse("80,443,1000-1002", ports, 16, &pn) == 0);
    ck("ports count == 5", pn == 5);
    ck("ports[0]==80", ports[0] == 80);
    ck("ports[4]==1002", ports[4] == 1002);

    /* --- 真实 TCP 扫描（回环） --- */
    int lfd = -1;
    int open_port = open_listener(&lfd);
    ck("listener opened", open_port > 0);
    /* 再取一个端口然后关闭，用作"关闭端口"样本 */
    int lfd2 = -1;
    int cp = open_listener(&lfd2);
    close(lfd2);
    ck("closed-port sample prepared", cp > 0 && cp != open_port);

    int splist[2]; splist[0] = open_port; splist[1] = cp;
    lat_scan_res_t res[2]; size_t found = 0;
    ck("scan_tcp ret 0", lat_scan_tcp("127.0.0.1", splist, 2, 400, res, 2, &found) == 0);
    ck("scan found 2 entries", found == 2);
    ck("scan: listening port open", res[0].open == 1);
    ck("scan: closed port not open", res[1].open == 0);
    close(lfd);

    /* --- 插件 --- */
    ck("plugin count >= 3", lat_plugin_count() >= 3);
    const lat_plugin_t *p = lat_plugin_lookup("ssh");
    ck("plugin lookup ssh", p != NULL);
    if (p) {
        char buf[256];
        size_t n = p->build_cmd("10.0.0.5", "id", buf, sizeof buf);
        ck("ssh cmd built", n > 0 && strstr(buf, "ssh") != NULL && strstr(buf, "10.0.0.5") != NULL);
        ck("ssh platform nix", p->platform == LAT_PLAT_NIX);
    }
    const lat_plugin_t *w = lat_plugin_lookup("wmi");
    ck("plugin lookup wmi", w != NULL && w->platform == LAT_PLAT_WIN);
    ck("plugin lookup nonexist", lat_plugin_lookup("nope") == NULL);
    ck("plugin at(0)", lat_plugin_at(0) != NULL && lat_plugin_at(99) == NULL);

    /* --- SOCKS5 --- */
    uint8_t g[8]; size_t gl = lat_socks5_greeting(g, sizeof g);
    ck("socks5 greeting len 3", gl == 3 && g[0] == 0x05 && g[1] == 0x01 && g[2] == 0x00);
    uint8_t rq[16]; size_t rl = lat_socks5_request("127.0.0.1", 8080, rq, sizeof rq);
    ck("socks5 request len 10", rl == 10 && rq[0] == 0x05 && rq[1] == 0x01 && rq[3] == 0x01);
    ck("socks5 request port BE", rq[8] == 0x1F && rq[9] == 0x90); /* 8080 = 0x1F90 */
    uint8_t good[2] = {0x05, 0x00};
    uint8_t bad[2]  = {0x05, 0x01};
    ck("socks5 reply ok", lat_socks5_reply_ok(good, 2) == 0);
    ck("socks5 reply reject", lat_socks5_reply_ok(bad, 2) == -1);

    printf("--- total=%d pass=%d fail=%d ---\n", total, total - fails, fails);
    return fails ? 1 : 0;
}
