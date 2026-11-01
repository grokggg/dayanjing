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


/* ---- 路由控制台（完整能力） ---- */
typedef int (*ui_handler_t)(const http_req_t *req, const char *body,
                            char *out, size_t cap);

#define UI_ROUTE_MAX 32

int  ui_route_add(const char *method, const char *path, ui_handler_t h);
ui_handler_t ui_route_find(const char *method, const char *path);
void ui_route_reset(void);
size_t ui_route_count(void);

/* 分发：匹配路由并执行；未匹配返回 404。成功 0 */
int  ui_dispatch(const http_req_t *req, const char *body, char *out, size_t cap);

/* JSON 字符串转义，返回写入长度 */
size_t ui_json_escape(const char *in, char *out, size_t cap);

/* 简单 HTML 页面包装，返回写入长度 */
size_t ui_page(const char *title, const char *body, char *out, size_t cap);

/* 真实服务：从 fd 读一个 HTTP 请求、分发、写回响应。成功 0 */
int  ui_serve_once(int fd, char *out, size_t cap, int timeout_ms);

#endif
