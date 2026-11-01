#include "lateral.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int lat_parse_ipv4(const char *s, uint32_t *out) {
    unsigned a[4];
    if (sscanf(s, "%u.%u.%u.%u", &a[0], &a[1], &a[2], &a[3]) != 4) return -1;
    for (int i = 0; i < 4; i++) if (a[i] > 255) return -1;
    *out = (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
    return 0;
}

int lat_cidr_parse(const char *s, lat_cidr_t *out) {
    if (!s || !out) return -1;
    char buf[64];
    size_t sl = strlen(s);
    if (sl == 0 || sl >= sizeof buf) return -1;
    memcpy(buf, s, sl + 1);
    char *slash = strchr(buf, '/');
    if (!slash) return -1;
    *slash = '\0';
    const char *bits_s = slash + 1;
    uint32_t ip;
    if (lat_parse_ipv4(buf, &ip) != 0) return -1;
    char *end = NULL;
    long bits = strtol(bits_s, &end, 10);
    if (end == bits_s || bits < 0 || bits > 32) return -1;
    uint32_t mask = 0;
    if (bits > 0) mask = (~(uint32_t)0) << (32 - bits);
    out->base = ip & mask;
    out->mask = mask;
    return 0;
}

int lat_cidr_hosts(const lat_cidr_t *c, uint32_t *hosts) {
    if (!c || !hosts) return -1;
    uint64_t size = (uint64_t)(~c->mask) + 1u;
    if (size <= 2) { *hosts = (uint32_t)size; return 0; }
    *hosts = (uint32_t)(size - 2);
    return 0;
}

int lat_ports_parse(const char *spec, int *ports, size_t cap, size_t *n) {
    if (!spec || !ports || !n || cap == 0) return -1;
    size_t cnt = 0;
    const char *p = spec;
    while (*p && cnt < cap) {
        if (*p == ',') { p++; continue; }
        char *end = NULL;
        long a = strtol(p, &end, 10);
        if (end == p) return -1;
        p = end;
        if (*p == '-') {
            p++;
            long b = strtol(p, &end, 10);
            if (end == p) return -1;
            p = end;
            if (a < 0 || b > 65535 || a > b) return -1;
            for (long v = a; v <= b && cnt < cap; v++) ports[cnt++] = (int)v;
        } else {
            if (a < 0 || a > 65535) return -1;
            ports[cnt++] = (int)a;
        }
    }
    *n = cnt;
    return 0;
}

/* ---------- 扫描 ---------- */
static int try_connect(uint32_t ip_be, int port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = ip_be;
    int rc = connect(fd, (struct sockaddr *)&sa, sizeof sa);
    if (rc == 0) { close(fd); return 1; }
    if (errno != EINPROGRESS && errno != EAGAIN) { close(fd); return 0; }
    fd_set wfds;
    FD_ZERO(&wfds); FD_SET(fd, &wfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    rc = select(fd + 1, NULL, &wfds, NULL, &tv);
    if (rc <= 0) { close(fd); return 0; }
    int err = 0; socklen_t elen = sizeof err;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0) { close(fd); return 0; }
    close(fd);
    return 1;
}

int lat_scan_tcp(const char *host, const int *ports, size_t n, int timeout_ms,
                 lat_scan_res_t *res, size_t cap, size_t *found) {
    if (!host || !ports || !res || !found || cap == 0) return -1;
    uint32_t ip = 0;
    if (lat_parse_ipv4(host, &ip) != 0) return -1;
    uint32_t ip_be = htonl(ip);
    size_t cnt = 0;
    for (size_t i = 0; i < n && cnt < cap; i++) {
        int st = try_connect(ip_be, ports[i], timeout_ms);
        res[cnt].port = ports[i];
        res[cnt].open = (st == 1) ? 1 : 0;
        cnt++;
    }
    *found = cnt;
    return 0;
}

/* ---------- 插件 ---------- */
static size_t cmd_ssh(const char *t, const char *c, char *o, size_t cap) {
    return (size_t)snprintf(o, cap, "ssh -o StrictHostKeyChecking=no %s '%s'", t, c);
}
static size_t cmd_smb(const char *t, const char *c, char *o, size_t cap) {
    return (size_t)snprintf(o, cap, "smbexec.py %s '%s'", t, c);
}
static size_t cmd_wmi(const char *t, const char *c, char *o, size_t cap) {
    return (size_t)snprintf(o, cap, "wmiexec.py %s '%s'", t, c);
}

static lat_plugin_t g_plugins[8] = {
    { "ssh", LAT_PLAT_NIX, cmd_ssh },
    { "smb", LAT_PLAT_WIN, cmd_smb },
    { "wmi", LAT_PLAT_WIN, cmd_wmi },
};
static size_t g_np = 3;

int lat_plugin_register(const lat_plugin_t *p) {
    if (!p || !p->build_cmd || p->name[0] == '\0') return -1;
    if (lat_plugin_lookup(p->name)) return -1;
    if (g_np >= 8) return -2;
    g_plugins[g_np++] = *p;
    return 0;
}
const lat_plugin_t *lat_plugin_lookup(const char *name) {
    if (!name) return NULL;
    for (size_t i = 0; i < g_np; i++)
        if (strcmp(g_plugins[i].name, name) == 0) return &g_plugins[i];
    return NULL;
}
size_t lat_plugin_count(void) { return g_np; }
const lat_plugin_t *lat_plugin_at(size_t i) { return (i < g_np) ? &g_plugins[i] : NULL; }
void lat_plugin_reset(void) { g_np = 3; }

/* ---------- SOCKS5 ---------- */
size_t lat_socks5_greeting(uint8_t *out, size_t cap) {
    if (!out || cap < 3) return 0;
    out[0] = 0x05; out[1] = 0x01; out[2] = 0x00;
    return 3;
}
size_t lat_socks5_request(const char *host, int port, uint8_t *out, size_t cap) {
    if (!host || !out || cap < 10) return 0;
    uint32_t ip = 0;
    if (lat_parse_ipv4(host, &ip) != 0) return 0;
    out[0] = 0x05; out[1] = 0x01; out[2] = 0x00; out[3] = 0x01;
    uint32_t be = htonl(ip);
    memcpy(out + 4, &be, 4);
    out[8] = (uint8_t)((port >> 8) & 0xFF);
    out[9] = (uint8_t)(port & 0xFF);
    return 10;
}
int lat_socks5_reply_ok(const uint8_t *r, size_t len) {
    if (!r || len < 2) return -1;
    if (r[0] != 0x05) return -1;
    return (r[1] == 0x00) ? 0 : -1;
}
