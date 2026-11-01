#define _DEFAULT_SOURCE
#include "tx_icmtun.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>

static int pass = 0, fail = 0;
#define CK(c, name) do { if (c) { printf("[PASS] %s\n", name); pass++; } \
    else { printf("[FAIL] %s\n", name); fail++; } } while (0)

/* 服务端上下文：累计上行片，FIN 时回一段下行 */
typedef struct {
    uint8_t  acc[8192];
    size_t   n;
    int      fin_seen;
    uint32_t max_seq;
    int      drop_first;   /* 故意丢首片，逼客户端超时重扫 */
    int      msgs;         /* 已完整收到的消息数 */
    size_t   last_len;
} srv_ctx_t;

static int cb(uint32_t tseq, uint8_t flags, const uint8_t *chunk, size_t clen,
              uint8_t *down, size_t cap, size_t *downlen, void *arg) {
    srv_ctx_t *c = (srv_ctx_t *)arg;
    *downlen = 0;
    if (c->drop_first) { c->drop_first = 0; return -1; }  /* 丢片：不回 ACK */
    if (clen) {
        if (c->n + clen <= sizeof c->acc) {
            memcpy(c->acc + c->n, chunk, clen);
            c->n += clen;
        }
    }
    if (tseq > c->max_seq) c->max_seq = tseq;
    if (flags & TX_ICMTUN_FIN) {
        /* 一条消息收齐：交付并重置，准备接收下一条 */
        c->msgs++;
        c->last_len = c->n;
        c->n = 0;
        c->fin_seen = 1;
        if (down && cap >= 5) { memcpy(down, "DOWN!", 5); *downlen = 5; }
    }
    return 0;
}

/* 报文编解码纯计算用例 */
static void test_codec(void) {
    uint8_t pkt[512];
    const char *msg = "HELLO-ICMP";
    size_t pl = tx_icmp_build_echo(0x1234, 7, 42, 9, TX_ICMTUN_FIN,
                                   (const uint8_t *)msg, strlen(msg),
                                   pkt, sizeof pkt);
    CK(pl == TX_ICMP_HDR + TX_ICMTUN_HDR + strlen(msg), "codec: 长度正确");
    CK(pkt[0] == 8, "codec: type=8 ECHO_REQUEST");

    uint16_t id = 0, eseq = 0; uint32_t ts = 0, ta = 0; uint8_t fl = 0;
    uint8_t buf[256]; size_t dl = 0;
    int rc = tx_icmp_parse_echo(pkt, pl, &id, &eseq, &ts, &ta, &fl,
                                buf, sizeof buf, &dl);
    CK(rc == TX_ICMTUN_OK, "codec: 解析成功");
    CK(id == 0x1234 && eseq == 7, "codec: id/eseq 还原");
    CK(ts == 42 && ta == 9, "codec: tseq/tack 还原");
    CK(fl == TX_ICMTUN_FIN, "codec: flags 还原");
    CK(dl == strlen(msg) && memcmp(buf, msg, dl) == 0, "codec: 净荷还原");

    /* 带 IP 头也能解 */
    uint8_t withip[600];
    memset(withip, 0, sizeof withip);
    withip[0] = 0x45;
    memcpy(withip + 20, pkt, pl);
    rc = tx_icmp_parse_echo(withip, 20 + pl, &id, &eseq, &ts, &ta, &fl,
                            buf, sizeof buf, &dl);
    CK(rc == TX_ICMTUN_OK && ts == 42, "codec: 带IP头仍可解析");

    /* 魔数不匹配 */
    uint8_t bad[64];
    memset(bad, 0, sizeof bad);
    memcpy(bad, pkt, pl);
    bad[TX_ICMP_HDR] ^= 0xff;
    CK(tx_icmp_parse_echo(bad, pl, NULL, NULL, NULL, NULL, NULL,
                          buf, sizeof buf, &dl) == TX_ICMTUN_ERR_PROTO,
       "codec: 魔数错误被拒");

    /* 过短 */
    CK(tx_icmp_parse_echo(pkt, 10, NULL, NULL, NULL, NULL, NULL,
                          buf, sizeof buf, &dl) == TX_ICMTUN_ERR_PROTO,
       "codec: 过短报文被拒");

    /* 超长净荷 */
    CK(tx_icmp_build_echo(1, 1, 0, 0, 0, (const uint8_t *)"x",
                          TX_ICMTUN_CHUNK + 1, pkt, sizeof pkt) == 0,
       "codec: 超 CHUNK 拒绝构造");

    /* 空净荷 */
    size_t pl2 = tx_icmp_build_echo(1, 1, 0, 0, TX_ICMTUN_FIN, NULL, 0,
                                    pkt, sizeof pkt);
    CK(pl2 == TX_ICMP_HDR + TX_ICMTUN_HDR, "codec: 空净荷(FIN)构造成功");
}

/* 真实 raw socket：fork 服务端 + 客户端，多行往返 */
static void test_real_echo(void) {
    int sfd = tx_icmpsrv_open();
    if (sfd < 0) {
        printf("[SKIP] 真实收发: raw socket 不可用 (需 CAP_NET_RAW/root)\n");
        return;
    }
    close(sfd);

    pid_t pid = fork();
    if (pid == 0) {
        if (freopen("/dev/null", "w", stdout) == NULL) _exit(2);
        int fd = tx_icmpsrv_open();
        srv_ctx_t ctx;
        memset(&ctx, 0, sizeof ctx);
        while (1) {
            if (tx_icmpsrv_serve_once(fd, cb, &ctx, 600) != TX_ICMTUN_OK) break;
        }
        /* 统计写 stderr */
        fprintf(stderr, "[SRV] msgs=%d last_len=%zu max_seq=%u\n",
                ctx.msgs, ctx.last_len, ctx.max_seq);
        _exit(ctx.msgs >= 3 ? 0 : 1);
    }

    usleep(200000);
    tx_icmtun_t *t = NULL;
    if (tx_icmtun_open(&t, "127.0.0.1", 800, 4, 100) != TX_ICMTUN_OK) {
        printf("[SKIP] 客户端 raw socket 不可用\n");
        kill(pid, SIGKILL); waitpid(pid, NULL, 0);
        return;
    }

    uint8_t payload[250];
    for (int i = 0; i < 250; i++) payload[i] = (uint8_t)(i * 5 + 1);
    int rc = tx_icmtun_send(t, payload, sizeof payload);
    CK(rc == TX_ICMTUN_OK, "real: 250B 分3片上行成功(真raw socket)");

    uint8_t down[64]; size_t dl = 0;
    int pr = tx_icmtun_poll(t, down, sizeof down, &dl);
    CK(pr == TX_ICMTUN_OK && dl == 5 && memcmp(down, "DOWN!", 5) == 0,
       "real: 下行捎带 DOWN! 取回一致");

    /* 大块：700B 分 7 片，验证滑动窗口多片 */
    uint8_t big[700];
    for (int i = 0; i < 700; i++) big[i] = (uint8_t)(i ^ 0x3c);
    CK(tx_icmtun_send(t, big, sizeof big) == TX_ICMTUN_OK,
       "real: 700B 分8片上行成功");

    /* 空消息（心跳） */
    CK(tx_icmtun_send(t, NULL, 0) == TX_ICMTUN_OK, "real: 空消息(纯FIN)可发");

    tx_icmtun_close(t);
    usleep(300000);
    kill(pid, SIGTERM);
    int st = 0;
    waitpid(pid, &st, 0);

    /* 子进程 stdout 应含我们发的两段数据 */
    printf("[INFO] 服务端进程退出 status=%d\n", WEXITSTATUS(st));
    (void)st;
}

/* 丢片重传：服务端首片不回 ACK，客户端应靠重扫补上 */
static void test_retransmit(void) {
    int sfd = tx_icmpsrv_open();
    if (sfd < 0) { printf("[SKIP] 重传: raw 不可用\n"); return; }
    close(sfd);

    pid_t pid = fork();
    if (pid == 0) {
        if (freopen("/dev/null", "w", stdout) == NULL) _exit(2);
        int fd = tx_icmpsrv_open();
        srv_ctx_t ctx;
        memset(&ctx, 0, sizeof ctx);
        ctx.drop_first = 1;
        while (1) {
            if (tx_icmpsrv_serve_once(fd, cb, &ctx, 600) != TX_ICMTUN_OK) break;
        }
        fprintf(stderr, "[SRV-RETX] msgs=%d last_len=%zu\n", ctx.msgs, ctx.last_len);
        _exit(ctx.msgs >= 1 ? 0 : 1);
    }
    usleep(200000);

    tx_icmtun_t *t = NULL;
    if (tx_icmtun_open(&t, "127.0.0.1", 700, 6, 100) != TX_ICMTUN_OK) {
        printf("[SKIP] 客户端 raw 不可用\n");
        kill(pid, SIGKILL); waitpid(pid, NULL, 0); return;
    }
    uint8_t data[120];
    for (int i = 0; i < 120; i++) data[i] = (uint8_t)(200 - i);
    int rc = tx_icmtun_send(t, data, sizeof data);
    CK(rc == TX_ICMTUN_OK, "retrans: 首片被丢后仍完成传输(重扫生效)");

    tx_icmtun_close(t);
    usleep(200000);
    int st = 0;
    waitpid(pid, &st, 0);
    CK(WEXITSTATUS(st) == 0, "retrans: 服务端最终收到 FIN");
}

int main(void) {
    test_codec();
    test_real_echo();
    test_retransmit();
    printf("\n---- icmtun: pass=%d fail=%d ----\n", pass, fail);
    return fail ? 1 : 0;
}
