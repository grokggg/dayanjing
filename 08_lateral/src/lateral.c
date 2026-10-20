#include "lateral.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int parse_ipv4(const char *s, uint32_t *out) {
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
    if (parse_ipv4(buf, &ip) != 0) return -1;
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
    uint64_t size = (uint64_t)(~c->mask) + 1u;   /* 地址总数（/0 为 2^32） */
    if (size <= 2) { *hosts = (uint32_t)size; return 0; }  /* /32 ->1, /31 ->2 */
    *hosts = (uint32_t)(size - 2);               /* 去掉网络号与广播 */
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
