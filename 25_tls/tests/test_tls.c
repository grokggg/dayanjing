/* test_tls.c — 真机 TLS 1.2 握手（连真实服务端 443）
 *
 * 不 mock 任何东西：真的 TCP、真的服务端证书、真的 X25519 交换、
 * 真的 AES-128-GCM 记录保护。所有"能跑通"的结论都来自真实握手。
 *
 * 取证重点：
 *   - SNI 在 ClientHello 里明文可见（观察者能看到）—— 域前置的基础事实
 *   - HTTP Host 头在 TLS 记录内（观察者看不到）—— 真实目标靠它传递
 *
 * 环境事实（重要）：本沙盒出口是 MITM 代理，它会【按 SNI 动态签发证书】。
 * 所以"SNI 写成别的域名就必然被证书校验拒绝"这个直觉在这里不成立 ——
 * 要验证主机名校验真的在跑，必须把 SNI 与校验用主机名分离开。
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "tls.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

static int fails = 0, total = 0;
#define CHECK(cond, name) do { \
    total++; \
    if (cond) printf("[PASS] %s\n", name); \
    else { printf("[FAIL] %s\n", name); fails++; } \
} while (0)

#define HOST "api.github.com"
#define CA   "/etc/zeroproxy-tls/ca-bundle.pem"

typedef struct {
    int fd;
    uint8_t sent[8192];
    size_t  sent_len;
} io_ctx;

static int s_send(void *arg, const uint8_t *d, size_t n) {
    io_ctx *c = (io_ctx *)arg;
    ssize_t r = send(c->fd, d, n, 0);
    if (r <= 0) return -1;
    if (c->sent_len + (size_t)r < sizeof(c->sent)) {
        memcpy(c->sent + c->sent_len, d, (size_t)r);
        c->sent_len += (size_t)r;
    }
    return (int)r;
}

static int s_recv(void *arg, uint8_t *b, size_t cap) {
    io_ctx *c = (io_ctx *)arg;
    return (int)recv(c->fd, b, cap, 0);
}

static int tcp_connect(void) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(HOST, "443", &hints, &res) != 0) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);
    return fd;
}

static void one_round(const char *sni, const char *http_host, const char *verify_host,
                      int verify, const char *ca_path,
                      tls_err *out_err, char *resp, size_t resp_cap) {
    int fd = tcp_connect();
    if (fd < 0) { if (out_err) *out_err = TLS_ERR_IO; return; }
    io_ctx io;
    memset(&io, 0, sizeof(io));
    io.fd = fd;

    tls_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.sni = sni;
    cfg.verify_host = verify_host;
    cfg.ca_path = ca_path;
    cfg.verify = verify;

    tls_ctx *c = NULL;
    if (tls_client_init(&c, &cfg, s_send, s_recv, &io) != TLS_OK) {
        if (out_err) *out_err = TLS_ERR_MEM;
        close(fd); return;
    }
    tls_err e = tls_handshake(c);
    if (out_err) *out_err = e;
    if (e == TLS_OK && resp && resp_cap) {
        char req[512];
        int n = snprintf(req, sizeof(req),
            "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: dayanjing/1\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n", http_host);
        if (tls_write(c, (const uint8_t *)req, (size_t)n) == TLS_OK) {
            size_t got = 0;
            for (int i = 0; i < 20 && got < resp_cap - 1; i++) {
                uint8_t buf[4096];
                size_t rlen = 0;
                if (tls_read(c, buf, sizeof(buf), &rlen) != TLS_OK) break;
                if (got + rlen >= resp_cap - 1) rlen = resp_cap - 1 - got;
                memcpy(resp + got, buf, rlen);
                got += rlen;
                resp[got] = '\0';
                if (strstr(resp, "\r\n\r\n")) break;
            }
        }
    }
    tls_free(c);
    close(fd);
}

int main(void) {
    int probe = tcp_connect();
    if (probe < 0) {
        printf("[SKIP] 无法连接 %s:443\n", HOST);
        return 77;
    }
    close(probe);

    /* 用例1：真机握手 + 真实 HTTP 往返 */
    char resp[8192];
    memset(resp, 0, sizeof(resp));
    tls_err e1 = TLS_ERR_IO;
    one_round(HOST, HOST, NULL, 1, CA, &e1, resp, sizeof(resp));
    printf("[INFO] 握手返回: %s\n", tls_errstr(e1));
    CHECK(e1 == TLS_OK, "真机 TLS 1.2 握手成功（X25519 + RSA 校验 + AES-GCM）");
    CHECK(strncmp(resp, "HTTP/1.", 7) == 0, "收到真实 HTTP 响应");
    if (resp[0]) printf("[INFO] 响应首行: %.60s\n", resp);

    /* 用例2：SNI 与校验主机名分离 —— 证书是同一张，只改校验目标，必须被拒。
       这条才真正证明主机名校验在跑（MITM 会按 SNI 签发，无法靠改 SNI 验证）。 */
    tls_err e2 = TLS_OK;
    one_round(HOST, HOST, "other.example.invalid", 1, CA, &e2, NULL, 0);
    printf("[INFO] 校验主机名不符返回: %s\n", tls_errstr(e2));
    CHECK(e2 == TLS_ERR_CERT, "校验主机名与证书不符被拒（主机名校验生效）");

    /* 用例2b：记录环境事实 —— MITM 按 SNI 动态签发，所以改 SNI 也能握手成功 */
    tls_err e2b = TLS_ERR_IO;
    one_round("example.com", "example.com", NULL, 1, CA, &e2b, NULL, 0);
    printf("[INFO] SNI=example.com 返回: %s（MITM 按 SNI 动态签发，故可通过）\n",
           tls_errstr(e2b));

    /* 用例3：关闭校验 —— 应当成功（对照组） */
    tls_err e3 = TLS_ERR_IO;
    one_round(HOST, HOST, NULL, 0, NULL, &e3, NULL, 0);
    printf("[INFO] 关闭校验返回: %s\n", tls_errstr(e3));
    CHECK(e3 == TLS_OK, "关闭校验后握手成功（对照组）");

    /* 用例4：信任库不可用 —— 必须报错 */
    tls_err e4 = TLS_OK;
    one_round(HOST, HOST, NULL, 1, "/nonexistent/ca-bundle.pem", &e4, NULL, 0);
    printf("[INFO] 信任库缺失返回: %s\n", tls_errstr(e4));
    CHECK(e4 == TLS_ERR_CERT, "信任库不可用被拒（不静默放行）");

    /* 用例5：域前置性质 —— 真实目标主机名只出现在加密记录内 */
    {
        int fd = tcp_connect();
        if (fd < 0) { printf("[SKIP] 连接失败\n"); }
        else {
            io_ctx io; memset(&io, 0, sizeof(io)); io.fd = fd;
            tls_config cfg; memset(&cfg, 0, sizeof(cfg));
            cfg.sni = HOST; cfg.ca_path = CA; cfg.verify = 1;
            tls_ctx *c = NULL;
            if (tls_client_init(&c, &cfg, s_send, s_recv, &io) == TLS_OK &&
                tls_handshake(c) == TLS_OK) {
                const char *real = "c2-real-target.invalid";
                char req[512];
                int n = snprintf(req, sizeof(req),
                    "GET /x HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", real);
                tls_write(c, (const uint8_t *)req, (size_t)n);
                int leak = 0;
                for (size_t i = 0; i + strlen(real) < io.sent_len; i++) {
                    if (memcmp(io.sent + i, real, strlen(real)) == 0) { leak = 1; break; }
                }
                CHECK(leak == 0, "真实目标主机名不出现在加密前字节中");
                CHECK(io.sent_len > 0, "确有字节发出（取证有效）");
                printf("[INFO] 握手+请求共发出 %zu 字节（ClientHello 含明文 SNI）\n", io.sent_len);
                tls_free(c);
            } else {
                printf("[SKIP] 取证握手失败\n");
            }
            close(fd);
        }
    }

    printf("\n=== %d/%d passed ===\n", total - fails, total);
    return fails == 0 ? 0 : 1;
}
