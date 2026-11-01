#include "http.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int main(void) {
    /* ---- 解析 GET ---- */
    const char *get_req =
        "GET /api/v1/sessions HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    http_req_t r;
    CHECK(http_parse_request(get_req, strlen(get_req), &r) == 0);
    CHECK(strcmp(r.method, "GET") == 0);
    CHECK(strcmp(r.path, "/api/v1/sessions") == 0);
    CHECK(r.content_length == 0);
    CHECK(r.keep_alive == 1);

    /* ---- 解析 POST + Connection: close ---- */
    const char *post_req =
        "POST /api/v1/task HTTP/1.1\r\n"
        "Content-Length: 42\r\n"
        "Connection: close\r\n"
        "\r\n";
    CHECK(http_parse_request(post_req, strlen(post_req), &r) == 0);
    CHECK(strcmp(r.method, "POST") == 0);
    CHECK(strcmp(r.path, "/api/v1/task") == 0);
    CHECK(r.content_length == 42);
    CHECK(r.keep_alive == 0);

    /* ---- 构造响应 ---- */
    char out[512];
    size_t n = http_build_response(200, "ok", out, sizeof out);
    CHECK(n > 0);
    CHECK(strncmp(out, "HTTP/1.1 200 OK", 15) == 0);
    CHECK(strstr(out, "Content-Length: 2") != NULL);
    CHECK(strcmp(out + n - 2, "ok") == 0);

    /* ---- 404 ---- */
    n = http_build_response(404, "{}", out, sizeof out);
    CHECK(n > 0);
    CHECK(strstr(out, "404 Not Found") != NULL);

    /* ---- 缓冲区不足应返回 0 ---- */
    CHECK(http_build_response(200, "ok", out, 8) == 0);

    printf("07_ui http tests: fail=%d\n", fails);
    return fails ? 1 : 0;
}
