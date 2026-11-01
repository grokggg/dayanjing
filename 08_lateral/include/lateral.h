#ifndef LATERAL_H
#define LATERAL_H
#include <stdint.h>
#include <stddef.h>

typedef struct { uint32_t base; uint32_t mask; } lat_cidr_t;

int lat_cidr_parse(const char *s, lat_cidr_t *out);
int lat_cidr_hosts(const lat_cidr_t *c, uint32_t *hosts);
int lat_ports_parse(const char *spec, int *ports, size_t cap, size_t *n);

/* ---- 真实 TCP 端口扫描（connect 探测，支持超时） ---- */
typedef struct { int port; int open; } lat_scan_res_t;
int lat_scan_tcp(const char *host, const int *ports, size_t n, int timeout_ms,
                 lat_scan_res_t *res, size_t cap, size_t *found);

/* ---- 横向移动协议插件 ---- */
#define LAT_PLAT_ANY 0
#define LAT_PLAT_WIN 1
#define LAT_PLAT_NIX 2
#define LAT_NAME_MAX 16

/* 连接目标时的 DNS 解析超时（毫秒）。
   传给 p2p_resolve_sa；不含 connect 本身的超时。 */
#define LAT_PROXY_RESOLV_TIMEOUT_MS 3000

typedef struct {
    char   name[LAT_NAME_MAX];
    int    platform;
    size_t (*build_cmd)(const char *target, const char *cmd, char *out, size_t cap);
} lat_plugin_t;

int  lat_plugin_register(const lat_plugin_t *p);
const lat_plugin_t *lat_plugin_lookup(const char *name);
size_t lat_plugin_count(void);
const lat_plugin_t *lat_plugin_at(size_t i);
void lat_plugin_reset(void);

/* ---- SOCKS5 报文编解码（RFC 1928） ---- */
size_t lat_socks5_greeting(uint8_t *out, size_t cap);
size_t lat_socks5_request(const char *host, int port, uint8_t *out, size_t cap);
int    lat_socks5_reply_ok(const uint8_t *reply, size_t len);

/* ---- SOCKS5 代理转发（fork + poll 双工中继） ---- */
typedef struct { int listen_fd; int port; } lat_proxy_t;

int  lat_proxy_listen(int port, lat_proxy_t *out);
void lat_proxy_close(lat_proxy_t *p);
int  lat_proxy_connect(const char *host, int port);
int  lat_proxy_handshake(int cfd);                    /* 成功返回目标 fd */
int  lat_proxy_relay(int cfd, int tfd, int idle_ms);  /* idle_ms<=0 无超时 */
int  lat_proxy_serve_once(const lat_proxy_t *p, int timeout_ms); /* 父进程返回 pid */

#endif
