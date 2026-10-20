/*
 * 08_lateral/tests/test_proxy.c
 * SOCKS5 代理转发真实测试：本地回环 + fork，跑完整握手与双工中继。
 * 不发任何外网包，全部 127.0.0.1。
 */
#define _POSIX_C_SOURCE 200809L

#include "lateral.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>

static int total = 0, fails = 0;
static void ck(const char *name, int ok) {
    total++;
    if (!ok) { fails++; printf("[FAIL] %s\n", name); }
    else       printf("[PASS] %s\n", name);
}

/* ---- 工具 ---- */
static int listen_any(int *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int on = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(0);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }
    if (listen(fd, 8) < 0) { close(fd); return -1; }
    struct sockaddr_in b; socklen_t bl = sizeof b;
    if (getsockname(fd, (struct sockaddr *)&b, &bl) == 0) *port = (int)ntohs(b.sin_port);
    return fd;
}

static int connect_port(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }
    return fd;
}

static int cli_send(int fd, const void *b, size_t n) {
    const uint8_t *p = (const uint8_t *)b; size_t s = 0;
    while (s < n) {
        ssize_t w = send(fd, p + s, n - s, 0);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        s += (size_t)w;
    }
    return 0;
}

static int cli_recv(int fd, void *b, size_t n) {
    uint8_t *p = (uint8_t *)b; size_t g = 0;
    while (g < n) {
        ssize_t r = recv(fd, p + g, n - g, 0);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
        g += (size_t)r;
    }
    return 0;
}

/* 子进程：accept 与 echo 均带超时，确保任何情况下都会自行退出，
 * 不遗留持有 stdout 管道的孤儿进程。 */
static void echo_server(int lfd) {
    struct pollfd pf;
    pf.fd = lfd; pf.events = POLLIN; pf.revents = 0;
    if (poll(&pf, 1, 8000) <= 0) _exit(1);

    int c = accept(lfd, NULL, NULL);
    if (c < 0) _exit(1);

    char buf[4096];
    for (;;) {
        struct pollfd cp;
        cp.fd = c; cp.events = POLLIN; cp.revents = 0;
        int n = poll(&cp, 1, 8000);
        if (n <= 0) break;

        ssize_t r = recv(c, buf, sizeof buf, 0);
        if (r <= 0) break;
        ssize_t off = 0;
        while (off < r) {
            ssize_t w = send(c, buf + off, (size_t)(r - off), 0);
            if (w <= 0) break;
            off += w;
        }
        if (off < r) break;
    }
    close(c);
    _exit(0);
}

static pid_t spawn_proxy(const lat_proxy_t *p) {
    pid_t pid = fork();
    if (pid == 0) {
        (void)lat_proxy_serve_once(p, 5000);
        _exit(0);
    }
    return pid;
}

/* 收割指定 pid；SIGCHLD 被忽略时 waitpid 返回 ECHILD 即视为已回收 */
static void sleep_ms(int ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    (void)nanosleep(&ts, NULL);
}

static void reap(pid_t pid) {
    for (int i = 0; i < 500; i++) {
        int st;
        pid_t r = waitpid(pid, &st, WNOHANG);
        if (r == pid || (r < 0 && errno == ECHILD)) return;
        sleep_ms(10);
    }
    /* 兜底：超时则强杀，避免遗留孤儿持有管道 */
    kill(pid, SIGKILL);
    for (int i = 0; i < 50; i++) {
        int st;
        if (waitpid(pid, &st, WNOHANG) > 0) return;
        sleep_ms(10);
    }
}

/* 取一个确定没人监听的端口 */
static int pick_closed_port(void) {
    int p = 0;
    int fd = listen_any(&p);
    if (fd < 0) return -1;
    close(fd);
    return p;
}

int main(void) {
    lat_proxy_t px;
    ck("proxy listen (port 0 auto)", lat_proxy_listen(0, &px) == 0);
    ck("proxy port assigned", px.port > 0);

    /* ---- 用例 1：IPv4 CONNECT 完整转发 ---- */
    {
        int tport = 0;
        int tlfd = listen_any(&tport);
        ck("target listener", tlfd >= 0 && tport > 0);

        pid_t ep = fork();
        if (ep == 0) { close(px.listen_fd); echo_server(tlfd); }
        pid_t pp = spawn_proxy(&px);

        int cfd = connect_port(px.port);
        ck("connect to proxy", cfd >= 0);

        uint8_t g[3] = { 0x05, 0x01, 0x00 };
        ck("send greeting", cli_send(cfd, g, 3) == 0);
        uint8_t ms[2] = { 0, 0 };
        ck("recv method select", cli_recv(cfd, ms, 2) == 0);
        ck("method = NO AUTH", ms[0] == 0x05 && ms[1] == 0x00);

        uint8_t rq[10];
        rq[0] = 0x05; rq[1] = 0x01; rq[2] = 0x00; rq[3] = 0x01;
        rq[4] = 127; rq[5] = 0; rq[6] = 0; rq[7] = 1;
        rq[8] = (uint8_t)((tport >> 8) & 0xFF);
        rq[9] = (uint8_t)(tport & 0xFF);
        ck("send CONNECT request", cli_send(cfd, rq, 10) == 0);

        uint8_t rep[10];
        ck("recv reply", cli_recv(cfd, rep, 10) == 0);
        ck("reply succeeded", rep[0] == 0x05 && rep[1] == 0x00 && rep[3] == 0x01);

        const char *msg = "HELLO-SOCKS5-RELAY-0123456789";
        size_t ml = strlen(msg);
        ck("send payload", cli_send(cfd, msg, ml) == 0);

        char rbuf[128];
        memset(rbuf, 0, sizeof rbuf);
        ck("recv echo", cli_recv(cfd, rbuf, ml) == 0);
        ck("echo bytes identical", memcmp(rbuf, msg, ml) == 0);

        /* 双向多轮：确认中继不是单向 */
        const char *m2 = "SECOND-ROUND-TRIP";
        size_t m2l = strlen(m2);
        cli_send(cfd, m2, m2l);
        char r2[64]; memset(r2, 0, sizeof r2);
        ck("second roundtrip", cli_recv(cfd, r2, m2l) == 0 && memcmp(r2, m2, m2l) == 0);

        close(cfd);
        reap(pp);
        reap(ep);
        close(tlfd);
    }

    /* ---- 用例 2：域名形式 ATYP=0x03 ---- */
    {
        int tport = 0;
        int tlfd = listen_any(&tport);
        pid_t ep = fork();
        if (ep == 0) { close(px.listen_fd); echo_server(tlfd); }
        pid_t pp = spawn_proxy(&px);

        int cfd = connect_port(px.port);
        uint8_t g[3] = { 0x05, 0x01, 0x00 };
        cli_send(cfd, g, 3);
        uint8_t ms[2]; cli_recv(cfd, ms, 2);
        ck("domain: method no-auth", ms[1] == 0x00);

        const char *host = "localhost";
        size_t hl = strlen(host);
        uint8_t rq[4 + 255 + 2];
        rq[0] = 0x05; rq[1] = 0x01; rq[2] = 0x00; rq[3] = 0x03;
        rq[4] = (uint8_t)hl;
        memcpy(rq + 5, host, hl);
        rq[5 + hl]     = (uint8_t)((tport >> 8) & 0xFF);
        rq[5 + hl + 1] = (uint8_t)(tport & 0xFF);
        cli_send(cfd, rq, 5 + hl + 2);

        uint8_t rep[10];
        ck("domain: recv reply", cli_recv(cfd, rep, 10) == 0);
        ck("domain: reply success", rep[1] == 0x00);

        const char *msg = "DOMAIN-ATYP-OK";
        cli_send(cfd, msg, strlen(msg));
        char rb[64]; memset(rb, 0, sizeof rb);
        ck("domain: echo identical",
           cli_recv(cfd, rb, strlen(msg)) == 0 && memcmp(rb, msg, strlen(msg)) == 0);

        close(cfd);
        reap(pp); reap(ep);
        close(tlfd);
    }

    /* ---- 用例 3：非 CONNECT 命令（BIND）被拒 ---- */
    {
        pid_t pp = spawn_proxy(&px);
        int cfd = connect_port(px.port);
        uint8_t g[3] = { 0x05, 0x01, 0x00 };
        cli_send(cfd, g, 3);
        uint8_t ms[2]; cli_recv(cfd, ms, 2);

        uint8_t rq[10] = { 0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90 };
        cli_send(cfd, rq, 10);
        uint8_t rep[10];
        ck("bind: recv reply", cli_recv(cfd, rep, 10) == 0);
        ck("bind: rep = command not supported", rep[1] == 0x07);
        close(cfd);
        reap(pp);
    }

    /* ---- 用例 4：连接不可达目标 -> rep 0x05 ---- */
    {
        int closed = pick_closed_port();
        ck("picked closed port", closed > 0);
        pid_t pp = spawn_proxy(&px);
        int cfd = connect_port(px.port);
        uint8_t g[3] = { 0x05, 0x01, 0x00 };
        cli_send(cfd, g, 3);
        uint8_t ms[2]; cli_recv(cfd, ms, 2);

        uint8_t rq[10];
        rq[0] = 0x05; rq[1] = 0x01; rq[2] = 0x00; rq[3] = 0x01;
        rq[4] = 127; rq[5] = 0; rq[6] = 0; rq[7] = 1;
        rq[8] = (uint8_t)((closed >> 8) & 0xFF);
        rq[9] = (uint8_t)(closed & 0xFF);
        cli_send(cfd, rq, 10);
        uint8_t rep[10];
        ck("unreachable: recv reply", cli_recv(cfd, rep, 10) == 0);
        ck("unreachable: rep = connection refused", rep[1] == 0x05);
        close(cfd);
        reap(pp);
    }

    /* ---- 用例 5：只支持 GSSAPI 的客户端被拒 ---- */
    {
        pid_t pp = spawn_proxy(&px);
        int cfd = connect_port(px.port);
        uint8_t g[3] = { 0x05, 0x01, 0x01 };   /* 只提供 GSSAPI */
        cli_send(cfd, g, 3);
        uint8_t ms[2];
        ck("gssapi: recv method", cli_recv(cfd, ms, 2) == 0);
        ck("gssapi: no acceptable methods", ms[1] == 0xFF);
        close(cfd);
        reap(pp);
    }

    /* ---- 用例 6：ATYP IPv6 不支持 ---- */
    {
        pid_t pp = spawn_proxy(&px);
        int cfd = connect_port(px.port);
        uint8_t g[3] = { 0x05, 0x01, 0x00 };
        cli_send(cfd, g, 3);
        uint8_t ms[2]; cli_recv(cfd, ms, 2);

        uint8_t rq[4] = { 0x05, 0x01, 0x00, 0x04 };
        cli_send(cfd, rq, 4);
        uint8_t rep[10];
        ck("ipv6: recv reply", cli_recv(cfd, rep, 10) == 0);
        ck("ipv6: rep = atyp not supported", rep[1] == 0x08);
        close(cfd);
        reap(pp);
    }

    lat_proxy_close(&px);
    ck("proxy closed", px.listen_fd < 0);

    printf("--- total=%d pass=%d fail=%d ---\n", total, total - fails, fails);
    return fails ? 1 : 0;
}
