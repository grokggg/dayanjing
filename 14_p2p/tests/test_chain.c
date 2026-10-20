#define _POSIX_C_SOURCE 200809L
#include "p2p.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

static int pass = 0, fail = 0;
#define CK(c, m) do { if (c) { pass++; printf("[PASS] %s\n", m); } \
                      else { fail++; printf("[FAIL] %s\n", m); } } while (0)

/* 监听回环并自动分配端口；父进程通过管道读回真实端口 */
static int listen_auto(int *out_port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;                       /* 内核分配 */
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) { close(s); return -1; }
    if (listen(s, 16) < 0) { close(s); return -1; }
    struct sockaddr_in got; socklen_t gl = sizeof got;
    if (getsockname(s, (struct sockaddr *)&got, &gl) < 0) { close(s); return -1; }
    *out_port = ntohs(got.sin_port);
    return s;
}

static int connect_to(int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) { close(s); return -1; }
    return s;
}

/* 全量收发，处理短读短写 */
static int send_all(int fd, const uint8_t *b, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, b + off, n - off, MSG_NOSIGNAL);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}
static ssize_t recv_all(int fd, uint8_t *b, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, b + off, n - off, 0);
        if (r <= 0) break;                /* 对端关闭或出错，返回已收字节 */
        off += (size_t)r;
    }
    return (ssize_t)off;
}

/* echo 目标：收到什么原样回什么 */
static pid_t spawn_echo(int *port) {
    int pfd[2]; if (pipe(pfd) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        close(pfd[0]);
        int lp = 0, s = listen_auto(&lp);
        if (s < 0) _exit(2);
        if (write(pfd[1], &lp, sizeof lp) != (ssize_t)sizeof lp) _exit(3);
        close(pfd[1]);
        for (;;) {
            int c = accept(s, NULL, NULL);
            if (c < 0) continue;
            uint8_t buf[8192];
            for (;;) {
                ssize_t r = recv(c, buf, sizeof buf, 0);
                if (r <= 0) break;
                if (send_all(c, buf, (size_t)r) < 0) break;
            }
            close(c);
        }
    }
    close(pfd[1]);
    int lp = 0;
    if (read(pfd[0], &lp, sizeof lp) != (ssize_t)sizeof lp) { close(pfd[0]); return -1; }
    close(pfd[0]);
    *port = lp;
    return pid;
}

/* 中继跳板：accept 后连下一跳，委托 p2p_relay 做双工转发 */
static pid_t spawn_relay(int next_port, int *port) {
    int pfd[2]; if (pipe(pfd) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        close(pfd[0]);
        int lp = 0, s = listen_auto(&lp);
        if (s < 0) _exit(2);
        if (write(pfd[1], &lp, sizeof lp) != (ssize_t)sizeof lp) _exit(3);
        close(pfd[1]);
        for (;;) {
            int c = accept(s, NULL, NULL);
            if (c < 0) continue;
            int t = connect_to(next_port);
            if (t < 0) { close(c); continue; }
            p2p_relay(c, t, 0);            /* 数据面：08_lateral 的 poll 双工中继 */
            close(t); close(c);
        }
    }
    close(pfd[1]);
    int lp = 0;
    if (read(pfd[0], &lp, sizeof lp) != (ssize_t)sizeof lp) { close(pfd[0]); return -1; }
    close(pfd[0]);
    *port = lp;
    return pid;
}

int main(void) {
    printf("=== 14_p2p 四级真实链路 e2e ===\n");
    signal(SIGPIPE, SIG_IGN);              /* 中继中对端断开不应杀进程 */

    int p_echo = 0, p_core = 0, p_e1 = 0, p_e0 = 0;
    pid_t pid_echo = spawn_echo(&p_echo);
    CK(pid_echo > 0 && p_echo > 0, "echo 目标启动");

    pid_t pid_core = spawn_relay(p_echo, &p_core);
    CK(pid_core > 0 && p_core > 0, "core 节点启动");

    pid_t pid_e1 = spawn_relay(p_core, &p_e1);
    CK(pid_e1 > 0 && p_e1 > 0, "edge1 节点启动");

    pid_t pid_e0 = spawn_relay(p_e1, &p_e0);
    CK(pid_e0 > 0 && p_e0 > 0, "edge0 节点启动");

    printf("[INFO] 链路: endpoint -> edge0(%d) -> edge1(%d) -> core(%d) -> echo(%d)\n",
           p_e0, p_e1, p_core, p_echo);

    /* 用例1：小 payload 四级往返 */
    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 7 + 3);
    int c = connect_to(p_e0);
    CK(c >= 0, "endpoint 连入 edge0");
    if (c >= 0) {
        uint8_t back[64]; memset(back, 0, sizeof back);
        ssize_t got = -1;
        if (send_all(c, msg, sizeof msg) == 0) got = recv_all(c, back, sizeof msg);
        CK(got == (ssize_t)sizeof msg, "四级链路收到完整回显");
        CK(got == (ssize_t)sizeof msg && memcmp(msg, back, sizeof msg) == 0,
           "四级回显与原始字节完全一致");
        close(c);
    }

    /* 用例2：大 payload 跨多跳（验证中继无长度截断） */
    size_t big = 65536;
    uint8_t *bm = calloc(big, 1);
    uint8_t *bb = calloc(big, 1);
    if (bm && bb) {
        for (size_t i = 0; i < big; i++) bm[i] = (uint8_t)(i ^ (i >> 8));
        int c2 = connect_to(p_e0);
        CK(c2 >= 0, "大 payload 连接建立");
        if (c2 >= 0) {
            ssize_t got2 = -1;
            if (send_all(c2, bm, big) == 0) got2 = recv_all(c2, bb, big);
            CK(got2 == (ssize_t)big, "64KB 经四级链路完整回显");
            CK(got2 == (ssize_t)big && memcmp(bm, bb, big) == 0, "64KB 字节级一致");
            close(c2);
        }
    } else {
        CK(0, "大 payload 内存分配");
    }
    free(bm); free(bb);

    /* 用例3：故障注入——杀掉中间 edge1，新连接应不可达 */
    kill(pid_e1, SIGKILL);
    waitpid(pid_e1, NULL, 0);
    {   /* usleep 在 POSIX 2008 已移除，用 nanosleep 避免隐式声明 */
        struct timespec ts = { 0, 120 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    int c3 = connect_to(p_e0);
    if (c3 >= 0) {
        uint8_t m3[32], b3[32];
        memset(m3, 0x5a, sizeof m3); memset(b3, 0, sizeof b3);
        ssize_t g3 = -1;
        if (send_all(c3, m3, sizeof m3) == 0) g3 = recv_all(c3, b3, sizeof m3);
        CK(g3 != (ssize_t)sizeof m3, "中间节点被杀后链路不再完整回显（故障可检出）");
        close(c3);
    } else {
        CK(1, "中间节点被杀后连接被拒（故障可检出）");
    }

    kill(pid_e0, SIGKILL); waitpid(pid_e0, NULL, 0);
    kill(pid_core, SIGKILL); waitpid(pid_core, NULL, 0);
    kill(pid_echo, SIGKILL); waitpid(pid_echo, NULL, 0);

    printf("total=%d pass=%d fail=%d\n", pass + fail, pass, fail);
    return fail ? 1 : 0;
}
