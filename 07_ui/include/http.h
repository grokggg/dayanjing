#ifndef HTTP_H
#define HTTP_H
#include <stddef.h>

typedef struct {
    char method[8];
    char path[128];
    int  content_length;
    int  keep_alive;
} http_req_t;

/* 解析 HTTP 请求头（不含 body）。成功 0 */
int http_parse_request(const char *buf, size_t len, http_req_t *req);

/* 构造响应，返回写入字节数；cap 不足返回 0 */
size_t http_build_response(int code, const char *body, char *out, size_t cap);

#endif
