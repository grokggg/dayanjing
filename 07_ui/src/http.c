#define _GNU_SOURCE
#include "ui_internal.h"
#include "ui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void http_req_reset(http_req_t *req) {
    if (!req) return;
    for (int i = 0; i < req->header_count; i++) {
        free(req->header_names[i]);
        free(req->header_vals[i]);
    }
    req->header_count = 0;
    free(req->body);
    req->body = NULL;
    req->body_len = 0;
    req->body_cap = 0;
    req->content_length = -1;
    req->keep_alive = 0;
    req->status = 0;
    req->uri[0] = '\0';
    req->method = HTTP_GET;
}

static int hdr_add(http_req_t *req, const char *name, size_t nlen,
                   const char *val, size_t vlen) {
    if (req->header_count >= HTTP_MAX_HEADERS) return -1;
    int i = req->header_count++;
    req->header_names[i] = (char *)malloc(nlen + 1);
    req->header_vals[i] = (char *)malloc(vlen + 1);
    if (!req->header_names[i] || !req->header_vals[i]) return -1;
    memcpy(req->header_names[i], name, nlen);
    req->header_names[i][nlen] = '\0';
    memcpy(req->header_vals[i], val, vlen);
    req->header_vals[i][vlen] = '\0';
    for (size_t k = 0; k < nlen; k++)
        req->header_names[i][k] = (char)tolower((unsigned char)req->header_names[i][k]);
    return 0;
}

const char *http_get_header(const http_req_t *req, const char *name) {
    if (!req || !name) return NULL;
    size_t nlen = strlen(name);
    for (int i = 0; i < req->header_count; i++) {
        if (strlen(req->header_names[i]) == nlen &&
            strncasecmp(req->header_names[i], name, nlen) == 0)
            return req->header_vals[i];
    }
    return NULL;
}

/* 逐行区间解析，避免 strchr 死循环 */
static const char *find_crlf(const char *start, const char *end) {
    for (const char *p = start; p < end - 1; p++) {
        if (p[0] == '\r' && p[1] == '\n') return p;
    }
    return NULL;
}

static const char *find_lf(const char *start, const char *end) {
    for (const char *p = start; p < end; p++) {
        if (*p == '\n') return p;
    }
    return NULL;
}

int http_parse_req(http_req_t *req, const char *buf, size_t len) {
    if (!req || !buf) return -1;
    const char *end = buf + len;
    const char *line_end = find_crlf(buf, end);
    int lf_only = 0;
    if (!line_end) {
        line_end = find_lf(buf, end);
        lf_only = 1;
        if (!line_end) return 0;   /* 需要更多数据 */
    }
    size_t line_len = (size_t)(line_end - buf);

    /* 解析请求行 */
    const char *sp1 = NULL, *sp2 = NULL;
    for (size_t i = 0; i < line_len; i++) {
        if (buf[i] == ' ') {
            if (!sp1) sp1 = buf + i;
            else if (!sp2) { sp2 = buf + i; break; }
        }
    }
    if (!sp1) return -1;
    size_t method_len = (size_t)(sp1 - buf);
    if (method_len == 3 && memcmp(buf, "GET", 3) == 0) req->method = HTTP_GET;
    else if (method_len == 4 && memcmp(buf, "POST", 4) == 0) req->method = HTTP_POST;
    else if (method_len == 6 && memcmp(buf, "DELETE", 6) == 0) req->method = HTTP_DELETE;
    else return -1;

    if (!sp2) return -1;
    size_t uri_len = (size_t)(sp2 - (sp1 + 1));
    if (uri_len >= HTTP_MAX_URI) return -1;
    memcpy(req->uri, sp1 + 1, uri_len);
    req->uri[uri_len] = '\0';

    /* 跳到下一行：跳过 \r\n 或 \n */
    const char *p = line_end + (lf_only ? 1 : 2);

    /* 解析 Header（直到空行） */
    int headers_terminated = 0;
    while (p < end) {
        const char *hend = find_crlf(p, end);
        int hlf = 0;
        if (!hend) {
            hend = find_lf(p, end);
            if (!hend) return 0;   /* 需要更多数据 */
            hlf = 1;
        }
        size_t hlen = (size_t)(hend - p);
        if (hlen == 0 || (hlf && hlen == 1 && *p == '\n')) {
            /* 空行：Header 结束 */
            p = hend + (hlf ? 1 : 2);
            headers_terminated = 1;
            break;
        }
        /* 折叠头行 (obs-fold) 忽略 */
        if (*p == ' ' || *p == '\t') { p = hend + (hlf ? 1 : 2); continue; }

        const char *colon = NULL;
        for (size_t i = 0; i < hlen; i++) {
            if (p[i] == ':') { colon = p + i; break; }
        }
        if (!colon) { p = hend + (hlf ? 1 : 2); continue; }
        size_t nlen = (size_t)(colon - p);
        const char *vstart = colon + 1;
        while (vstart < hend && (*vstart == ' ' || *vstart == '\t')) vstart++;
        size_t vlen = (size_t)(hend - vstart);
        while (vlen > 0 && (vstart[vlen - 1] == ' ' || vstart[vlen - 1] == '\t' ||
                            vstart[vlen - 1] == '\r' || vstart[vlen - 1] == '\n'))
            vlen--;
        hdr_add(req, p, nlen, vstart, vlen);
        p = hend + (hlf ? 1 : 2);
    }

    /* Content-Length */
    const char *cl = http_get_header(req, "content-length");
    if (cl) req->content_length = atoi(cl);

    /* Connection: keep-alive / close */
    const char *conn = http_get_header(req, "connection");
    if (conn && strcasestr(conn, "keep-alive")) req->keep_alive = 1;
    else if (conn && strcasestr(conn, "close")) req->keep_alive = 0;
    else req->keep_alive = (req->method == HTTP_GET) ? 1 : 0; /* HTTP/1.1 默认 keep-alive */

    /* 若 header 区域未以空行终止，需要更多数据 */
    if (!headers_terminated) return 0;

    /* Body */
    size_t body_avail = (size_t)(end - p);
    if (req->content_length > 0) {
        if (body_avail < (size_t)req->content_length) return 0;  /* 需要更多数据 */
        req->body_len = (size_t)req->content_length;
    } else if (body_avail > 0) {
        req->body_len = body_avail;
    }
    if (req->body_len > 0) {
        req->body = (char *)malloc(req->body_len + 1);
        if (!req->body) return -1;
        memcpy(req->body, p, req->body_len);
        req->body[req->body_len] = '\0';
    }
    return 1;   /* 完整报文已解析 */
}
