/* 26_lateral_auto/src/target.c —— 目标发现 */
#include "lateral_auto.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 内部：追加去重 */
static int add_unique(char hosts[][LAT_HOST_MAX], size_t cap, size_t *n,
                      const char *h)
{
    size_t l;
    if (!h || !*h) return -1;
    l = strlen(h);
    if (l == 0 || l >= LAT_HOST_MAX) return -1;

    for (size_t i = 0; i < *n; i++) {
        if (strcmp(hosts[i], h) == 0) return 0;   /* 已存在，静默去重 */
    }
    if (*n >= cap) return -1;
    memcpy(hosts[*n], h, l + 1);
    (*n)++;
    return 0;
}

static int is_hashed_entry(const char *tok)
{
    return strncmp(tok, "|1|", 3) == 0;
}

static int has_wildcard(const char *s)
{
    for (const char *p = s; *p; p++) {
        if (*p == '*' || *p == '?' || *p == '!') return 1;
    }
    return 0;
}

/*
 * known_hosts 条目形如：
 *   host1,192.168.1.5 ssh-ed25519 AAAAC3...
 *   |1|hash... ssh-rsa AAAA...        <- hashed，跳过
 *   @cert-authority *.example.com ssh-rsa AAAA...
 */
int lat_target_known_hosts(const char *path,
                           char hosts[][LAT_HOST_MAX], size_t cap, size_t *n)
{
    FILE *f;
    char line[4096];

    if (!path || !hosts || !n) return -1;
    *n = 0;

    f = fopen(path, "r");
    if (!f) return -1;

    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        char *sp;
        char *tok;

        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0') continue;

        if (strncmp(p, "@cert-authority", 15) == 0 ||
            strncmp(p, "@revoked", 8) == 0) {
            p += strcspn(p, " \t");
            while (*p == ' ' || *p == '\t') p++;
        }

        if (is_hashed_entry(p)) continue;      /* 反解无意义，跳过 */

        sp = strchr(p, ' ');
        if (!sp) continue;
        *sp = '\0';

        /* 逗号分隔的主机列表 */
        tok = p;
        for (;;) {
            char *c = strchr(tok, ',');
            if (c) *c = '\0';
            /*
             * 通配符条目不做为目标：@cert-authority 常带 "*." 前缀，
             * 连过去毫无意义，只会产生无效连接并留下痕迹。
             */
            if (has_wildcard(tok)) {
                if (!c) break;
                tok = c + 1;
                continue;
            }
            if (*tok == '[') {                 /* [host]:port 形式 */
                char *rb = strchr(tok, ']');
                if (rb) {
                    *rb = '\0';
                    add_unique(hosts, cap, n, tok + 1);
                }
            } else {
                add_unique(hosts, cap, n, tok);
            }
            if (!c) break;
            tok = c + 1;
        }
    }
    fclose(f);
    return 0;
}

/*
 * ssh_config：
 *   Host foo bar          <- 取 foo、bar
 *   Host *.example.com    <- 含通配符，跳过
 */
int lat_target_ssh_config(const char *path,
                          char hosts[][LAT_HOST_MAX], size_t cap, size_t *n)
{
    FILE *f;
    char line[1024];

    if (!path || !hosts || !n) return -1;
    *n = 0;

    f = fopen(path, "r");
    if (!f) return -1;

    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        char *sp;

        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0') continue;

        if (strncasecmp(p, "Host", 4) != 0) continue;
        p += 4;
        if (*p != ' ' && *p != '\t') continue;   /* 避免匹配 HostName */
        while (*p == ' ' || *p == '\t') p++;

        sp = strpbrk(p, "\r\n");
        if (sp) *sp = '\0';

        for (;;) {
            char *c = strchr(p, ' ');
            if (!c) c = strchr(p, '\t');
            if (c) *c = '\0';
            if (*p && !has_wildcard(p)) add_unique(hosts, cap, n, p);
            if (!c) break;
            p = c + 1;
            while (*p == ' ' || *p == '\t') p++;
        }
    }
    fclose(f);
    return 0;
}

/*
 * /etc/hosts：
 *   127.0.0.1  localhost
 *   10.0.0.5   db01 db01.internal
 */
int lat_target_hosts_file(const char *path,
                          char hosts[][LAT_HOST_MAX], size_t cap, size_t *n)
{
    FILE *f;
    char line[1024];

    if (!path || !hosts || !n) return -1;
    *n = 0;

    f = fopen(path, "r");
    if (!f) return -1;

    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        char *sp;
        int  is_loopback = 0;

        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0') continue;

        /* 地址段 */
        if (strncmp(p, "127.", 4) == 0 || strcmp(p, "::1") == 0 ||
            strncmp(p, "::1", 3) == 0)
            is_loopback = 1;

        sp = strchr(p, ' ');
        if (!sp) { sp = strchr(p, '\t'); }
        if (!sp) continue;
        *sp = '\0';

        if (is_loopback) continue;              /* 回环不是横向目标 */

        p = sp + 1;
        sp = strpbrk(p, "\r\n");
        if (sp) *sp = '\0';

        for (;;) {
            char *c = strchr(p, ' ');
            if (!c) c = strchr(p, '\t');
            if (c) *c = '\0';
            if (*p && strcmp(p, "localhost") != 0)
                add_unique(hosts, cap, n, p);
            if (!c) break;
            p = c + 1;
            while (*p == ' ' || *p == '\t') p++;
        }
    }
    fclose(f);
    return 0;
}
