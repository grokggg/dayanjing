/*
 * 08_lateral/src/proxy.c
 * SOCKS5 代理转发（RFC 1928）。
 *
 * 能力：
 *   - lat_proxy_listen   监听本地端口
 *   - lat_proxy_handshake 完成 greeting + CONNECT，返回已连接的目标 fd
 *   - lat_proxy_relay     poll 双工中继（客户端 <-> 目标）
 *   - lat_proxy_serve_once accept 一个客户端并 fork 出子进程处理
 *
 * 仅支持 CONNECT（0x01），ATYP 支持 IPv4(0x01) 与域名(0x03)。
 * IPv6(0x04) 返回 0x08（地址类型不支持）。
 */
#define _POSIX_C_SOURCE 200809L

#include "lateral.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "p2p_resolv.h"
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>

/* ---- 内部：精确收发 ---- */
static int recv_exact(int fd, uint8_t *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;          /* 对端关闭 */
        got += (size_t)r;
    }
    return 0;
}

static int send_exact(int fd, const uint8_t *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = send(fd, buf + sent, n - sent, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

/* ---- 监听 ---- */
int lat_proxy_listen(int port, lat_proxy_t *out) {
    /* port == 0 表示由内核自动分配，绑定后回填真实端口 */
    if (!out || port < 0 || port > 65535) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int on = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    /* 默认只监听回环：代理不应对外暴露成开放代理 */
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }
    if (listen(fd, 16) < 0) { close(fd); return -1; }

    /* 自动回收子进程，避免僵尸 */
    signal(SIGCHLD, SIG_IGN);

    out->listen_fd = fd;
    out->port = port;

    /* 传 0 时由内核分配，回填真实端口 */
    struct sockaddr_in bound;
    socklen_t bl = sizeof bound;
    if (getsockname(fd, (struct sockaddr *)&bound, &bl) == 0) {
        out->port = (int)ntohs(bound.sin_port);
    }
    return 0;
}

void lat_proxy_close(lat_proxy_t *p) {
    if (p && p->listen_fd >= 0) {
        close(p->listen_fd);
        p->listen_fd = -1;
    }
}

/* ---- 连接目标（阻塞） ----
 *
 * 用自研 A 记录解析（14_p2p/src/resolv.c），不用 getaddrinfo。
 *
 * 为什么必须换掉 getaddrinfo：静态链接 glibc 时它会带入整套 NSS 机制
 * （__libc_dlopen_mode / nss_* 系列符号，以及 /etc/passwd 字符串）。
 * 这些既是动态依赖特征也是静态字符串特征，直接破坏"零依赖、无指纹"。
 * 实测：仅此一个文件就让单体产物多出 146 个 NSS 符号和 1 处 /etc/passwd。
 *
 * 依赖方向：resolv.c 是叶子原语（不依赖任何模块），因此
 *   relay.c(14_p2p) -> proxy.c(08_lateral) -> resolv.c(14_p2p)
 * 是文件级无环图，不构成模块循环。
 *
 * 仅支持 IPv4：ATYP 0x04 已在 handshake 中返回 0x08（地址类型不支持）拒绝。
 */
int lat_proxy_connect(const char *host, int port) {
    if (!host || port <= 0 || port > 65535) return -1;

    /* resolver 传 NULL：来源优先级为 P2P_RESOLVER 环境变量 > /etc/resolv.conf。
       主机名若已是点分十进制 IPv4，内部直接返回，不发起任何 DNS 查询。 */
    struct sockaddr_in sa;
    if (p2p_resolve_sa(host, (uint16_t)port, NULL,
                       LAT_PROXY_RESOLV_TIMEOUT_MS, &sa) != P2P_RESOLV_OK)
        return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (const struct sockaddr *)&sa, sizeof sa) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* ---- 握手：返回目标 fd，失败 -1 ---- */
int lat_proxy_handshake(int cfd) {
    uint8_t g[2 + 255];

    /* 1) greeting: ver, nmethods, methods[nmethods] */
    if (recv_exact(cfd, g, 2) < 0) return -1;
    if (g[0] != 0x05) return -1;

    size_t nm = g[1];
    if (nm == 0) return -1;
    if (recv_exact(cfd, g + 2, nm) < 0) return -1;

    int noauth = 0;
    for (size_t i = 0; i < nm; i++) {
        if (g[2 + i] == 0x00) { noauth = 1; break; }
    }

    uint8_t msel[2] = { 0x05, (uint8_t)(noauth ? 0x00 : 0xFF) };
    if (send_exact(cfd, msel, 2) < 0) return -1;
    if (!noauth) return -1;                     /* 只支持无认证 */

    /* 2) request: ver, cmd, rsv, atyp */
    uint8_t r[4];
    if (recv_exact(cfd, r, 4) < 0) return -1;
    if (r[0] != 0x05) return -1;

    if (r[1] != 0x01) {                         /* 非 CONNECT */
        uint8_t rep[10] = { 0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
        (void)send_exact(cfd, rep, 10);
        return -1;
    }

    char host[256];
    memset(host, 0, sizeof host);

    uint8_t atyp = r[3];
    if (atyp == 0x01) {                         /* IPv4 */
        uint8_t ip[4];
        if (recv_exact(cfd, ip, 4) < 0) return -1;
        snprintf(host, sizeof host, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    } else if (atyp == 0x03) {                  /* 域名 */
        uint8_t hl = 0;
        if (recv_exact(cfd, &hl, 1) < 0) return -1;
        if (hl == 0) return -1;
        if (recv_exact(cfd, (uint8_t *)host, hl) < 0) return -1;
        host[hl] = '\0';
    } else {                                    /* IPv6 等不支持 */
        uint8_t rep[10] = { 0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
        (void)send_exact(cfd, rep, 10);
        return -1;
    }

    uint8_t pb[2];
    if (recv_exact(cfd, pb, 2) < 0) return -1;
    int port = (pb[0] << 8) | pb[1];

    int tfd = lat_proxy_connect(host, port);
    if (tfd < 0) {
        uint8_t rep[10] = { 0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };  /* 连接被拒 */
        (void)send_exact(cfd, rep, 10);
        return -1;
    }

    uint8_t rep[10] = { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };      /* 成功 */
    if (send_exact(cfd, rep, 10) < 0) { close(tfd); return -1; }
    return tfd;
}

/* ---- poll 双工中继。idle_ms <= 0 表示无超时（直到 EOF） ---- */
int lat_proxy_relay(int cfd, int tfd, int idle_ms) {
    if (cfd < 0 || tfd < 0) return -1;
    uint8_t buf[4096];

    for (;;) {
        struct pollfd p[2];
        p[0].fd = cfd; p[0].events = POLLIN; p[0].revents = 0;
        p[1].fd = tfd; p[1].events = POLLIN; p[1].revents = 0;

        int n = poll(p, 2, idle_ms > 0 ? idle_ms : -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return 0;                   /* 空闲超时，正常退出 */

        for (int i = 0; i < 2; i++) {
            if (!(p[i].revents & POLLIN)) continue;

            int src = p[i].fd;
            int dst = (i == 0) ? tfd : cfd;

            ssize_t r = recv(src, buf, sizeof buf, 0);
            if (r < 0) {
                if (errno == EINTR) continue;
                return 0;
            }
            if (r == 0) return 0;               /* EOF，正常结束 */

            ssize_t off = 0;
            while (off < r) {
                ssize_t w = send(dst, buf + off, (size_t)(r - off), MSG_NOSIGNAL);
                if (w < 0) {
                    if (errno == EINTR) continue;
                    return 0;
                }
                off += w;
            }
        }

        if (p[0].revents & (POLLHUP | POLLERR | POLLNVAL)) return 0;
        if (p[1].revents & (POLLHUP | POLLERR | POLLNVAL)) return 0;
    }
}

/* ---- accept 一个客户端，fork 处理。父进程返回子进程 pid ---- */
int lat_proxy_serve_once(const lat_proxy_t *p, int timeout_ms) {
    if (!p || p->listen_fd < 0) return -1;

    struct pollfd pf;
    pf.fd = p->listen_fd;
    pf.events = POLLIN;
    pf.revents = 0;

    int n = poll(&pf, 1, timeout_ms > 0 ? timeout_ms : -1);
    if (n <= 0) return -1;

    int cfd = accept(p->listen_fd, NULL, NULL);
    if (cfd < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { close(cfd); return -1; }

    if (pid == 0) {
        /* 子进程：握手 + 中继 */
        signal(SIGCHLD, SIG_DFL);
        int tfd = lat_proxy_handshake(cfd);
        if (tfd >= 0) {
            (void)lat_proxy_relay(cfd, tfd, 0);
            close(tfd);
        }
        close(cfd);
        _exit(0);
    }

    close(cfd);                                  /* 父进程只留监听 fd */
    return (int)pid;
}
