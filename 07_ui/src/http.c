#define _DEFAULT_SOURCE
#include "http.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

int http_parse_request(const char *buf, size_t len, http_req_t *req) {
    if (!buf || !req || len == 0) return -1;
    memset(req, 0, sizeof *req);
    req->keep_alive = 1;   /* HTTP/1.1 默认 keep-alive */

    /* 解析请求行: METHOD PATH VERSION */
    size_t i = 0;
    size_t mstart = i;
    while (i < len && buf[i] != ' ') i++;
    if (i >= len) return -1;
    size_t mlen = i - mstart;
    if (mlen >= sizeof req->method) return -1;
    memcpy(req->method, buf + mstart, mlen);
    req->method[mlen] = '\0';
    i++;   /* 跳过空格 */

    size_t pstart = i;
    while (i < len && buf[i] != ' ') i++;
    size_t plen = i - pstart;
    if (plen == 0 || plen >= sizeof req->path) return -1;
    memcpy(req->path, buf + pstart, plen);
    req->path[plen] = '\0';

    /* 找头部结束 */
    const char *hdr_end = NULL;
    for (size_t j = 0; j + 3 < len; j++) {
        if (buf[j] == '\r' && buf[j+1] == '\n' && buf[j+2] == '\r' && buf[j+3] == '\n') {
            hdr_end = buf + j;
            break;
        }
    }
    size_t hdr_len = hdr_end ? (size_t)(hdr_end - buf) : len;

    /* 扫描 Content-Length 与 Connection */
    const char *p = buf;
    while (p < buf + hdr_len) {
        const char *eol = strchr(p, '\n');
        if (!eol) break;
        size_t linelen = (size_t)(eol - p);
        if (linelen >= 15 && strncasecmp(p, "Content-Length:", 15) == 0) {
            req->content_length = atoi(p + 15);
        } else if (linelen >= 11 && strncasecmp(p, "Connection:", 11) == 0) {
            const char *v = p + 11;
            while (*v == ' ') v++;
            if (strncasecmp(v, "close", 5) == 0) req->keep_alive = 0;
        }
        p = eol + 1;
    }
    return 0;
}

size_t http_build_response(int code, const char *body, char *out, size_t cap) {
    const char *reason = (code == 200) ? "OK" : (code == 404 ? "Not Found" : "Error");
    size_t blen = body ? strlen(body) : 0;
    char head[256];
    int hl = snprintf(head, sizeof head,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n"
        "\r\n", code, reason, blen);
    if (hl < 0) return 0;
    size_t need = (size_t)hl + blen;
    if (cap < need + 1) return 0;
    memcpy(out, head, (size_t)hl);
    if (blen) memcpy(out + hl, body, blen);
    out[need] = '\0';
    return need;
}
