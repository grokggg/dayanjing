#define _DEFAULT_SOURCE
#include "http.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <errno.h>
#include <strings.h>

typedef struct {
    char         method[8];
    char         path[128];
    ui_handler_t h;
} ui_route_t;

static ui_route_t g_routes[UI_ROUTE_MAX];
static size_t     g_nroute;

void ui_route_reset(void){ g_nroute = 0; memset(g_routes, 0, sizeof g_routes); }
size_t ui_route_count(void){ return g_nroute; }

int ui_route_add(const char *method, const char *path, ui_handler_t h){
    if(!method || !path || !h) return -1;
    if(g_nroute >= UI_ROUTE_MAX) return -1;
    if(strlen(method) >= sizeof g_routes[0].method) return -1;
    if(strlen(path) >= sizeof g_routes[0].path) return -1;
    for(size_t i = 0; i < g_nroute; i++)
        if(strcasecmp(g_routes[i].method, method) == 0 &&
           strcmp(g_routes[i].path, path) == 0){
            g_routes[i].h = h;          /* 重复注册覆盖 */
            return 0;
        }
    snprintf(g_routes[g_nroute].method, sizeof g_routes[0].method, "%s", method);
    snprintf(g_routes[g_nroute].path,   sizeof g_routes[0].path,   "%s", path);
    g_routes[g_nroute].h = h;
    g_nroute++;
    return 0;
}

ui_handler_t ui_route_find(const char *method, const char *path){
    if(!method || !path) return NULL;
    for(size_t i = 0; i < g_nroute; i++)
        if(strcasecmp(g_routes[i].method, method) == 0 &&
           strcmp(g_routes[i].path, path) == 0)
            return g_routes[i].h;
    return NULL;
}

int ui_dispatch(const http_req_t *req, const char *body, char *out, size_t cap){
    if(!req || !out || cap == 0) return -1;
    ui_handler_t h = ui_route_find(req->method, req->path);
    char bodybuf[4096];
    if(!h){
        size_t n = http_build_response(404, "{\"error\":\"not found\"}", out, cap);
        return n == 0 ? -1 : 0;
    }
    if(h(req, body ? body : "", bodybuf, sizeof bodybuf) != 0){
        size_t n = http_build_response(500, "{\"error\":\"handler\"}", out, cap);
        return n == 0 ? -1 : 0;
    }
    size_t n = http_build_response(200, bodybuf, out, cap);
    return n == 0 ? -1 : 0;
}

size_t ui_json_escape(const char *in, char *out, size_t cap){
    if(!in || !out || cap == 0) return 0;
    size_t w = 0;
    for(const char *p = in; *p && w + 2 < cap; p++){
        unsigned char c = (unsigned char)*p;
        if(c == '"' || c == '\\'){
            out[w++] = '\\'; out[w++] = (char)c;
        } else if(c == '\n'){
            if(w + 3 >= cap) break;
            out[w++] = '\\'; out[w++] = 'n';
        } else if(c < 0x20){
            if(w + 7 >= cap) break;
            w += (size_t)snprintf(out + w, cap - w, "\\u%04x", c);
        } else {
            out[w++] = (char)c;
        }
    }
    out[w] = 0;
    return w;
}

size_t ui_page(const char *title, const char *body, char *out, size_t cap){
    if(!out || cap == 0) return 0;
    char esc_t[256], esc_b[2048];
    ui_json_escape(title ? title : "", esc_t, sizeof esc_t);
    ui_json_escape(body  ? body  : "", esc_b, sizeof esc_b);
    int n = snprintf(out, cap,
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>%s</title></head>"
        "<body><h1>%s</h1><pre>%s</pre></body></html>", esc_t, esc_t, esc_b);
    if(n < 0 || (size_t)n >= cap) return 0;
    return (size_t)n;
}

int ui_serve_once(int fd, char *out, size_t cap, int timeout_ms){
    if(fd < 0 || !out || cap == 0) return -1;
    struct timeval tv; fd_set s;
    if(timeout_ms <= 0) timeout_ms = 3000;
    tv.tv_sec = timeout_ms/1000; tv.tv_usec = (timeout_ms%1000)*1000;
    FD_ZERO(&s); FD_SET(fd, &s);
    if(select(fd+1, &s, NULL, NULL, &tv) <= 0) return -1;

    char buf[8192];
    ssize_t n = recv(fd, buf, sizeof buf - 1, 0);
    if(n <= 0) return -1;
    buf[n] = 0;

    http_req_t req;
    if(http_parse_request(buf, (size_t)n, &req) != 0) return -1;
    char resp[8192];
    if(ui_dispatch(&req, strstr(buf, "\r\n\r\n"), resp, sizeof resp) != 0) return -1;
    size_t rl = strlen(resp);
    size_t sent = 0;
    while(sent < rl){
        ssize_t w = send(fd, resp + sent, rl - sent, MSG_NOSIGNAL);
        if(w < 0){ if(errno == EINTR) continue; return -1; }
        sent += (size_t)w;
    }
    size_t cp = rl < cap ? rl : cap - 1;
    memcpy(out, resp, cp); out[cp] = 0;
    return 0;
}
