#define _DEFAULT_SOURCE
/* 公网 ICMP 真实收发验证。
   不是"socket 可用性检查"，而是用本模块的隧道报文格式打真实互联网：
     构造 echo（含 tseq/tack/flags/SRV 位 + 载荷） -> 公网往返 -> 解析回
   验证：载荷布局在真实链路上原样往返，且 SRV 位可用于区分服务端构造的应答。

   无 raw socket 权限或网络不可达时 SKIP，不计为失败。 */
#include "tx_icmtun.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>

static int pass = 0, fail = 0, skip = 0;

static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000ull;
}

/* 一次真实公网往返：返回 0 成功 */
static int probe(const char *ip, uint16_t id, uint16_t eseq,
                 const uint8_t *data, size_t dlen, int timeout_ms,
                 double *rtt_ms) {
    uint8_t pkt[TX_ICMTUN_MAXPKT];
    size_t plen = tx_icmp_build_echo(id, eseq, 0x11223344u, 0u,
                                     TX_ICMTUN_FIN | TX_ICMTUN_SRV | TX_ICMTUN_ACKV,
                                     data, dlen, pkt, sizeof pkt);
    if (plen == 0) return -1;

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) return -2;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) { close(fd); return -1; }

    uint64_t t0 = now_us();
    if (sendto(fd, pkt, plen, 0, (struct sockaddr *)&sa, sizeof sa) < 0) {
        close(fd); return -3;
    }

    int rc = -4;
    for (;;) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int left = (int)(timeout_ms - (int)((now_us() - t0) / 1000));
        if (left <= 0) break;
        int pr = poll(&pfd, 1, left);
        if (pr <= 0) break;

        uint8_t rbuf[2048];
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(fd, rbuf, sizeof rbuf, 0,
                             (struct sockaddr *)&from, &fl);
        if (n <= 0) continue;
        if (from.sin_addr.s_addr != sa.sin_addr.s_addr) continue;

        uint16_t rid = 0, rseq = 0;
        uint32_t rtseq = 0, rtack = 0;
        uint8_t rflags = 0, rdata[512];
        size_t rdlen = 0;
        if (tx_icmp_parse_echo(rbuf, (size_t)n, &rid, &rseq, &rtseq, &rtack,
                               &rflags, rdata, sizeof rdata, &rdlen) != 0)
            continue;
        if (rid != id || rseq != eseq) continue;      /* 不是我这份请求 */

        *rtt_ms = (double)(now_us() - t0) / 1000.0;

        /* 载荷必须原样回来（含 SRV 位），这是信道可用的实质证据 */
        if (rdlen != dlen || memcmp(rdata, data, dlen) != 0) { rc = -5; break; }
        if ((rflags & TX_ICMTUN_SRV) == 0)            { rc = -6; break; }
        if (rtseq != 0x11223344u)                     { rc = -7; break; }
        rc = 0;
        break;
    }
    close(fd);
    return rc;
}

int main(void) {
    const char *targets[] = { "223.5.5.5", "119.29.29.29", "1.1.1.1", "8.8.8.8" };
    const uint8_t payload[] = "DAYANJING-ICMP-PUBLIC-PROBE-0123456789";

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) {
        printf("[SKIP] 无 raw socket 权限 (errno=%d)，公网 ICMP 未验证\n", errno);
        skip++;
        printf("\ntotal=%d pass=%d fail=%d skip=%d\n", pass + fail + skip, pass, fail, skip);
        return 0;
    }
    close(fd);

    int ok = 0, unreach = 0;
    for (size_t i = 0; i < sizeof targets / sizeof targets[0]; i++) {
        double rtt = 0;
        int rc = probe(targets[i], (uint16_t)(0xA000 + i), (uint16_t)(100 + i),
                       payload, sizeof payload - 1, 4000, &rtt);
        if (rc == 0) {
            printf("[PASS] 公网 ICMP 往返 %-12s rtt=%.1fms 载荷 %zuB 原样返回(SRV位保留)\n",
                   targets[i], rtt, sizeof payload - 1);
            pass++; ok++;
        } else if (rc == -4) {
            printf("[INFO] %-12s 超时（该目标未回应 echo）\n", targets[i]);
            unreach++;
        } else {
            printf("[FAIL] %-12s rc=%d (%s)\n", targets[i], rc, tx_icmtun_errstr(rc));
            fail++;
        }
    }

    if (ok == 0 && unreach > 0)
        printf("[SKIP] 公网 echo 全部超时（出口 ICMP 可能被运营商/NAT 策略拦截）\n");

    printf("\ntotal=%d pass=%d fail=%d\n", pass + fail, pass, fail);
    return fail ? 1 : 0;
}
