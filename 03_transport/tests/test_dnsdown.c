/* 公网 DNS 下行验证。

   此前"下行未验证"的根因：我们没有自有权威域，无法让公网递归把查询转投到我们
   自己的权威端，因此无法验证"我们自己注入的 TXT 能否经公网回传"。

   本测试把这条链路拆开，验证其中**可验证的部分**：
     1. 下行数据通路真实存在 —— 用一个远端权威会主动往 TXT 里塞数据的真实域名
        （o-o.myaddr.l.google.com 会回送查询方出口 IP），经公网递归解析器取回，
        再用本模块的 tx_dns_parse_txt 解出。即：权威端注入 -> 公网递归 -> 我们解码，
        这条方向在真实互联网上跑通。
     2. 我们构造的下行 TXT 报文能被解析器正确解码（本地权威端闭环，对照用）。
     3. 异常路径不崩溃：NXDOMAIN、空应答、截断报文。

   仍未验证：我们**自己的**权威端经公网 NS 委派回传（需自有域名）。 */
#include "dnstun.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

static int pass = 0, fail = 0, skip = 0;

static void ck(int c, const char *n) {
    if (c) { pass++; printf("[PASS] %s\n", n); }
    else   { fail++; printf("[FAIL] %s\n", n); }
}

/* 向指定解析器发一条 TXT 查询，返回应答长度；失败返回 <0 */
static int udp_txt_query(const char *resolver, const char *qname,
                         uint8_t *resp, size_t cap, int timeout_ms,
                         uint8_t *rcode_out) {
    uint8_t q[512];
    uint16_t tid = (uint16_t)((uintptr_t)qname ^ (uintptr_t)resolver ^ (uintptr_t)&timeout_ms);
    size_t qlen = tx_dns_build_query_ex(qname, tid, 16 /* TXT */, q, sizeof q);
    if (qlen == 0) return -1;

    uint32_t rip;
    if (inet_pton(AF_INET, resolver, &rip) != 1) return -1;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -2;
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = rip;
    sa.sin_port = htons(53);

    if (sendto(fd, q, qlen, 0, (struct sockaddr *)&sa, sizeof sa) < 0) {
        close(fd); return -3;
    }
    ssize_t n = recvfrom(fd, resp, cap, 0, NULL, NULL);
    close(fd);
    if (n < 12) return -4;
    if (rcode_out) *rcode_out = resp[3] & 0x0f;
    return (int)n;
}

/* 粗略判断是否为点分十进制 IPv4（用于确认解出的是真实数据而非垃圾） */
static int looks_ipv4(const uint8_t *s, size_t n) {
    if (n < 7 || n > 15) return 0;
    int dots = 0, dig = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '.') { dots++; dig = 0; }
        else if (s[i] >= '0' && s[i] <= '9') dig++;
        else return 0;
        if (dig > 3) return 0;
    }
    return dots == 3;
}

int main(void) {
    uint8_t resp[2048];
    uint8_t out[512];
    size_t olen = 0;

    /* ---- 1. 公网下行数据通路：远端权威注入 -> 公网递归 -> 我们解码 ---- */
    const char *rsv[] = { "223.5.5.5", "119.29.29.29", "8.8.8.8", "1.1.1.1" };
    const char *probe_dom = "o-o.myaddr.l.google.com";   /* 该域名的权威端会回送查询方出口 IP */
    int got = 0, net_err = 0;

    for (size_t i = 0; i < sizeof rsv / sizeof rsv[0] && !got; i++) {
        uint8_t rcode = 0;
        int n = udp_txt_query(rsv[i], probe_dom, resp, sizeof resp, 5000, &rcode);
        if (n < 0) { net_err++; printf("[INFO] %s 查询失败 rc=%d\n", rsv[i], n); continue; }

        memset(out, 0, sizeof out);
        olen = 0;
        int rc = tx_dns_parse_txt(resp, (size_t)n, out, sizeof out, &olen);
        if (rc != 0 || olen == 0) {
            printf("[INFO] %s 取回 rcode=%u 但解出 0 字节 (rc=%d)\n", rsv[i], rcode, rc);
            continue;
        }
        /* 解出的应当是查询方出口 IP —— 这是权威端主动注入的真实下行数据 */
        int isip = looks_ipv4(out, olen);
        char buf[64];
        size_t cn = olen < sizeof buf - 1 ? olen : sizeof buf - 1;
        memcpy(buf, out, cn); buf[cn] = '\0';

        ck(isip, "公网下行解码出权威端注入的数据");
        printf("[PASS] 经 %s 下行取回 %zu 字节: \"%s\"%s\n",
               rsv[i], olen, buf, isip ? " (解析为出口 IPv4)" : " (非 IP 形态)");
        got = 1;
    }
    if (!got) {
        printf("[SKIP] 公网 DNS 下行未验证（%d 个解析器不可用或被策略拦截）\n", net_err);
        skip++;
    }

    /* ---- 2. 我们构造的下行 TXT 能被同一解析器解出（本地权威闭环，对照） ---- */
    {
        uint8_t q[512];
        size_t qlen = tx_dns_build_query("t.example", 0x1234, q, sizeof q);
        ck(qlen > 0, "本地对照: 查询构造成功");
        const uint8_t down[] = "HELLO-DOWNLINK";
        uint8_t rep[512];
        size_t rlen = tx_dns_build_txt_reply(q, qlen, down, sizeof down - 1, rep, sizeof rep);
        ck(rlen > 0, "本地对照: TXT 应答构造成功");
        memset(out, 0, sizeof out);
        olen = 0;
        int rc = tx_dns_parse_txt(rep, rlen, out, sizeof out, &olen);
        ck(rc == 0 && olen == sizeof down - 1 && memcmp(out, down, olen) == 0,
           "本地对照: 下行 TXT 往返一致");
    }

    /* ---- 3. 异常路径不崩溃 ---- */
    {
        /* NXDOMAIN */
        uint8_t rcode = 0;
        char nx[64];
        snprintf(nx, sizeof nx, "nx-%ld.invalid", (long)time(NULL));
        int n = udp_txt_query("223.5.5.5", nx, resp, sizeof resp, 4000, &rcode);
        if (n > 0) {
            memset(out, 0, sizeof out); olen = 0;
            tx_dns_parse_txt(resp, (size_t)n, out, sizeof out, &olen);
            printf("[INFO] NXDOMAIN 查询返回 rcode=%u，解析未崩溃\n", rcode);
            ck(1, "NXDOMAIN 应答不崩溃");
        } else {
            printf("[INFO] NXDOMAIN 查询未返回（网络不可达），跳过\n");
        }
        /* 截断报文 */
        memset(out, 0, sizeof out); olen = 0;
        uint8_t junk[20];
        memset(junk, 0x41, sizeof junk);
        int rc2 = tx_dns_parse_txt(junk, sizeof junk, out, sizeof out, &olen);
        ck(rc2 != 0, "截断/垃圾报文被拒绝");
        /* 空输入 */
        ck(tx_dns_parse_txt(NULL, 0, out, sizeof out, &olen) != 0, "空输入被拒绝");
        ck(tx_dns_parse_txt(resp, 0, NULL, 0, NULL) != 0, "空输出缓冲被拒绝");
    }

    printf("\ntotal=%d pass=%d fail=%d skip=%d\n", pass + fail, pass, fail, skip);
    return fail ? 1 : 0;
}
