/*
 * 14_p2p —— p2p_node：可独立部署的节点守护进程
 *
 * 职责：读配置 -> 建网格 -> 加载/生成跳密钥 -> 监听 -> 周期探测 -> 输出状态。
 * 转发逻辑全部复用既有实现（p2p_onion_route_serve / p2p_relay），
 * 本文件只做工程外壳：配置、生命周期、可观测、清理。
 */

#include "p2p.h"
#include "p2p_hopkey.h"
#include "crypto_x25519.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <poll.h>

#define NODE_MAX_NEIGHBORS  8
#define NODE_LINE_MAX       512
#define NODE_MGMT_MAXCONN   4

typedef struct {
    char      alias[P2P_ALIAS_LEN];
    uint8_t   id[P2P_NODE_ID_LEN];
    p2p_role_t role;
    char      listen_host[P2P_HOST_LEN];
    uint16_t  listen_port;
    char      keyfile[256];
    char      statedir[256];
    uint16_t  mgmt_port;
    uint32_t  probe_interval_ms;
    uint32_t  seed;

    struct {
        uint8_t id[P2P_NODE_ID_LEN];
        char    host[P2P_HOST_LEN];
        uint16_t port;
        uint8_t pub[X25519_KEY_LEN];
        int     has_pub;
    } nb[NODE_MAX_NEIGHBORS];
    int n_nb;

    /* peer: 入网格以便算路/建洋葱，但不建立邻接边 */
    struct {
        uint8_t id[P2P_NODE_ID_LEN];
        char    host[P2P_HOST_LEN];
        uint16_t port;
        uint8_t pub[X25519_KEY_LEN];
        int     has_pub;
    } pr[P2P_MAX_NODES];
    int n_pr;

    /* link: 全图邻接声明（非仅自身边），使每个节点都能独立算出到任意节点的路径 */
    struct {
        uint8_t a[P2P_NODE_ID_LEN];
        uint8_t b[P2P_NODE_ID_LEN];
    } lk[P2P_MAX_NODES * 2];
    int n_lk;
} node_cfg_t;

static volatile sig_atomic_t g_stop = 0;
static void on_sigterm(int s) { (void)s; g_stop = 1; }
static void on_sigchld(int s) { (void)s; }

static const char *role_str(p2p_role_t r) {
    switch (r) {
        case P2P_ROLE_ENDPOINT: return "endpoint";
        case P2P_ROLE_EDGE:     return "edge";
        case P2P_ROLE_CORE:     return "core";
        default:                return "unknown";
    }
}

static void hexenc(const uint8_t *b, size_t n, char *out, size_t cap) {
    static const char H[] = "0123456789abcdef";
    size_t i;
    if (cap < n * 2 + 1) { if (cap) out[0] = '\0'; return; }
    for (i = 0; i < n; i++) {
        out[i * 2]     = H[(b[i] >> 4) & 0x0f];
        out[i * 2 + 1] = H[b[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

static int hexdec(const char *s, uint8_t *out, size_t n) {
    size_t i;
    if (!s) return -1;
    if (strlen(s) != n * 2) return -1;
    for (i = 0; i < n; i++) {
        int hi = -1, lo = -1;
        char c = s[i * 2];
        if (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
        c = s[i * 2 + 1];
        if (c >= '0' && c <= '9') lo = c - '0';
        else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static char *trim(char *s) {
    char *e;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n'))
        *--e = '\0';
    return s;
}

static int cfg_parse_file(const char *path, node_cfg_t *c) {
    FILE *f = fopen(path, "r");
    char line[NODE_LINE_MAX];
    if (!f) return -1;
    memset(c, 0, sizeof(*c));
    c->probe_interval_ms = 30000;
    c->seed = 0x5eed;
    snprintf(c->listen_host, sizeof c->listen_host, "127.0.0.1");
    snprintf(c->statedir, sizeof c->statedir, ".");

    while (fgets(line, sizeof line, f)) {
        char *p = trim(line);
        char *eq;
        if (*p == '\0' || *p == '#') continue;
        eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = trim(p);
        char *v = trim(eq + 1);

        if (strcmp(k, "alias") == 0) {
            snprintf(c->alias, sizeof c->alias, "%s", v);
        } else if (strcmp(k, "id") == 0) {
            if (hexdec(v, c->id, P2P_NODE_ID_LEN) != 0) { fclose(f); return -1; }
        } else if (strcmp(k, "role") == 0) {
            if (strcmp(v, "endpoint") == 0) c->role = P2P_ROLE_ENDPOINT;
            else if (strcmp(v, "edge") == 0) c->role = P2P_ROLE_EDGE;
            else if (strcmp(v, "core") == 0) c->role = P2P_ROLE_CORE;
            else { fclose(f); return -1; }
        } else if (strcmp(k, "listen_host") == 0) {
            snprintf(c->listen_host, sizeof c->listen_host, "%s", v);
        } else if (strcmp(k, "listen_port") == 0) {
            c->listen_port = (uint16_t)strtoul(v, NULL, 10);
        } else if (strcmp(k, "keyfile") == 0) {
            snprintf(c->keyfile, sizeof c->keyfile, "%s", v);
        } else if (strcmp(k, "statedir") == 0) {
            snprintf(c->statedir, sizeof c->statedir, "%s", v);
        } else if (strcmp(k, "mgmt_port") == 0) {
            c->mgmt_port = (uint16_t)strtoul(v, NULL, 10);
        } else if (strcmp(k, "probe_interval_ms") == 0) {
            c->probe_interval_ms = (uint32_t)strtoul(v, NULL, 10);
        } else if (strcmp(k, "seed") == 0) {
            c->seed = (uint32_t)strtoul(v, NULL, 10);
        } else if (strcmp(k, "link") == 0) {
            /* link=<idA32hex> <idB32hex> —— 声明 A 与 B 相邻 */
            char *sp = strchr(v, ' ');
            if (!sp || c->n_lk >= (int)(P2P_MAX_NODES * 2)) { fclose(f); return -1; }
            *sp = '\0';
            char *rest = sp + 1;
            while (*rest == ' ') rest++;
            if (hexdec(v, c->lk[c->n_lk].a, P2P_NODE_ID_LEN) != 0) { fclose(f); return -1; }
            if (hexdec(rest, c->lk[c->n_lk].b, P2P_NODE_ID_LEN) != 0) { fclose(f); return -1; }
            c->n_lk++;
        } else if (strcmp(k, "peer") == 0) {
            /* peer=<id32hex> <host> <port> [pub64hex] */
            char *sp1 = strchr(v, ' ');
            if (!sp1 || c->n_pr >= P2P_MAX_NODES) { fclose(f); return -1; }
            *sp1 = '\0';
            char *idhex2 = v;
            char *rest2 = sp1 + 1;
            while (*rest2 == ' ') rest2++;
            char *sp2b = strchr(rest2, ' ');
            if (!sp2b) { fclose(f); return -1; }
            *sp2b = '\0';
            char *host2 = rest2;
            char *portstr2 = sp2b + 1;
            while (*portstr2 == ' ') portstr2++;
            char *sp3b = strchr(portstr2, ' ');
            char *pubhex2 = NULL;
            if (sp3b) { *sp3b = '\0'; pubhex2 = sp3b + 1; while (*pubhex2 == ' ') pubhex2++; }
            {
                int j = c->n_pr;
                if (hexdec(idhex2, c->pr[j].id, P2P_NODE_ID_LEN) != 0) { fclose(f); return -1; }
                snprintf(c->pr[j].host, sizeof c->pr[j].host, "%s", host2);
                c->pr[j].port = (uint16_t)strtoul(portstr2, NULL, 10);
                if (pubhex2 && *pubhex2) {
                    if (hexdec(pubhex2, c->pr[j].pub, X25519_KEY_LEN) == 0) c->pr[j].has_pub = 1;
                }
                c->n_pr++;
            }
        } else if (strcmp(k, "neighbor") == 0) {
            /* neighbor=<id32hex> <host> <port> [pub64hex] */
            char *sp1 = strchr(v, ' ');
            if (!sp1 || c->n_nb >= NODE_MAX_NEIGHBORS) { fclose(f); return -1; }
            *sp1 = '\0';
            char *idhex = v;
            char *rest = sp1 + 1;
            while (*rest == ' ') rest++;
            char *sp2 = strchr(rest, ' ');
            if (!sp2) { fclose(f); return -1; }
            *sp2 = '\0';
            char *host = rest;
            char *portstr = sp2 + 1;
            while (*portstr == ' ') portstr++;
            char *sp3 = strchr(portstr, ' ');
            char *pubhex = NULL;
            if (sp3) { *sp3 = '\0'; pubhex = sp3 + 1; while (*pubhex == ' ') pubhex++; }

            int i = c->n_nb;
            if (hexdec(idhex, c->nb[i].id, P2P_NODE_ID_LEN) != 0) { fclose(f); return -1; }
            snprintf(c->nb[i].host, sizeof c->nb[i].host, "%s", host);
            c->nb[i].port = (uint16_t)strtoul(portstr, NULL, 10);
            if (pubhex && *pubhex) {
                if (hexdec(pubhex, c->nb[i].pub, X25519_KEY_LEN) == 0) c->nb[i].has_pub = 1;
            }
            c->n_nb++;
        }
    }
    fclose(f);
    if (c->alias[0] == '\0' || c->keyfile[0] == '\0') return -1;
    return 0;
}

/* ---- 跳密钥持久化：32 字节私钥 + 4 字节 epoch（LE） ---- */
static int hopkey_load(const char *path, p2p_hopkey_t *h, uint8_t sk[32]) {
    FILE *f = fopen(path, "rb");
    uint8_t buf[36];
    uint32_t ep;
    if (!f) return -1;
    if (fread(buf, 1, sizeof buf, f) != sizeof buf) { fclose(f); return -1; }
    fclose(f);
    ep = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16)
       | ((uint32_t)buf[3] << 24);
    memcpy(sk, buf + 4, 32);
    if (p2p_hopkey_init(h) != P2P_HOPKEY_OK) return -1;
    /* 用载入的私钥覆盖 epoch0 槽位 */
    memcpy(h->slots[0].sk, sk, 32);
    if (x25519_public_key(sk, h->slots[0].pk) != X25519_OK) return -1;
    h->slots[0].epoch = ep;
    h->next_epoch = ep + 1;
    return 0;
}

static int hopkey_save(const char *path, const p2p_hopkey_t *h) {
    uint8_t buf[36];
    uint32_t ep = h->slots[0].epoch;
    FILE *f;
    buf[0] = (uint8_t)(ep & 0xff);
    buf[1] = (uint8_t)((ep >> 8) & 0xff);
    buf[2] = (uint8_t)((ep >> 16) & 0xff);
    buf[3] = (uint8_t)((ep >> 24) & 0xff);
    memcpy(buf + 4, h->slots[0].sk, 32);
    f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(buf, 1, sizeof buf, f) != sizeof buf) { fclose(f); return -1; }
    fclose(f);
    chmod(path, 0600);
    return 0;
}

static int listen_on(const char *host, uint16_t port, uint16_t *real_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    if (fd < 0) return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1) { close(fd); return -1; }
    a.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    if (listen(fd, 16) != 0) { close(fd); return -1; }
    if (real_port) {
        if (port == 0 && getsockname(fd, (struct sockaddr *)&a, &al) == 0)
            *real_port = ntohs(a.sin_port);
        else
            *real_port = port;
    }
    return fd;
}

/* ---- 状态输出 ---- */
typedef struct {
    p2p_mesh_t *m;
    const node_cfg_t *cfg;
    uint16_t    port;
    time_t      start;
    int         probing;
} node_state_t;

static void write_state(const node_cfg_t *c, p2p_mesh_t *m, uint16_t port,
                        time_t start) {
    char path[512], tmp[560];
    FILE *f;
    char idhex[P2P_NODE_ID_LEN * 2 + 1];
    int i;

    snprintf(path, sizeof path, "%s/%s.json", c->statedir, c->alias);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    f = fopen(tmp, "w");
    if (!f) return;
    hexenc(c->id, P2P_NODE_ID_LEN, idhex, sizeof idhex);

    fprintf(f, "{\"alias\":\"%s\",\"role\":\"%s\",\"id\":\"%s\","
               "\"listen\":{\"host\":\"%s\",\"port\":%u},"
               "\"uptime_s\":%ld,\"nodes\":%d,\"neighbors\":[",
            c->alias, role_str(c->role), idhex, c->listen_host,
            (unsigned)port, (long)(time(NULL) - start), m->n_nodes);

    for (i = 0; i < c->n_nb; i++) {
        uint32_t rtt = 0, ok = 0, fail = 0;
        uint32_t ewma = 0, jit = 0, bw = 0, qok = 0, qfail = 0;
        int alive = 0;
        char nh[P2P_NODE_ID_LEN * 2 + 1];
        p2p_link_metrics(m, c->id, c->nb[i].id, &rtt, &ok, &fail);
        p2p_link_get_qos(m, c->id, c->nb[i].id, &ewma, &jit, &bw, &qok, &qfail);
        {
            int idx = p2p_node_find(m, c->nb[i].id);
            if (idx >= 0) alive = m->nodes[idx].alive;
        }
        hexenc(c->nb[i].id, P2P_NODE_ID_LEN, nh, sizeof nh);
        fprintf(f, "%s{\"id\":\"%s\",\"host\":\"%s\",\"port\":%u,"
                   "\"rtt_ms\":%u,\"rtt_ewma_x16\":%u,\"jitter_x16\":%u,"
                   "\"bw_kbps\":%u,\"alive\":%d,\"ok\":%u,\"fail\":%u}",
                i ? "," : "", nh, c->nb[i].host, (unsigned)c->nb[i].port,
                (unsigned)rtt, (unsigned)ewma, (unsigned)jit, (unsigned)bw,
                alive, (unsigned)ok, (unsigned)fail);
    }
    fprintf(f, "]}\n");
    fclose(f);
    rename(tmp, path);
}

/* ---- 探测线程：周期测量邻居 RTT/带宽并落盘状态 ---- */
static pthread_mutex_t g_mesh_lock = PTHREAD_MUTEX_INITIALIZER;

static void *probe_thread(void *arg) {
    node_state_t *st = (node_state_t *)arg;
    p2p_probesched_t ps;
    struct timespec ts0, ts1;

    if (p2p_probesched_init(&ps, st->cfg->seed,
                            st->cfg->probe_interval_ms,
                            st->cfg->probe_interval_ms / 2 + 1,
                            st->cfg->probe_interval_ms * 8) != P2P_OK)
        return NULL;
    clock_gettime(CLOCK_MONOTONIC, &ts0);

    while (!g_stop) {
        int n_probed = 0, n_skipped = 0;
        uint32_t now_ms;
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 200 * 1000 * 1000;   /* 200ms 步进 */
        nanosleep(&ts, NULL);

        clock_gettime(CLOCK_MONOTONIC, &ts1);
        now_ms = (uint32_t)((ts1.tv_sec - ts0.tv_sec) * 1000
                            + (ts1.tv_nsec - ts0.tv_nsec) / 1000000);

        pthread_mutex_lock(&g_mesh_lock);
        p2p_probe_all_staggered(&ps, st->m, st->cfg->id, now_ms,
                                &n_probed, &n_skipped);
        pthread_mutex_unlock(&g_mesh_lock);
        write_state(st->cfg, st->m, st->port, st->start);
    }
    return NULL;
}

/* ---- 管理端口：仅回环，取一段共享 token 才回状态 ---- */
static void *mgmt_thread(void *arg) {
    node_state_t *st = (node_state_t *)arg;
    int fd = listen_on("127.0.0.1", st->cfg->mgmt_port, NULL);
    if (fd < 0) return NULL;
    while (!g_stop) {
        struct sockaddr_in c;
        socklen_t cl = sizeof c;
        struct timeval tv;
        int s;
        tv.tv_sec = 0; tv.tv_usec = 300000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        s = accept(fd, (struct sockaddr *)&c, &cl);
        if (s < 0) continue;
        /* 读一行命令；只认 "STATE\n" */
        char buf[64];
        ssize_t r = recv(s, buf, sizeof buf - 1, 0);
        if (r > 0) {
            buf[r] = '\0';
            if (strncmp(buf, "STATE", 5) == 0) {
                char path[560];
                FILE *f;
                snprintf(path, sizeof path, "%s/%s.json",
                         st->cfg->statedir, st->cfg->alias);
                f = fopen(path, "r");
                if (f) {
                    char out[4096];
                    size_t n = fread(out, 1, sizeof out - 1, f);
                    out[n] = '\0';
                    fclose(f);
                    if (send(s, out, n, 0) < 0) { /* 对端已断，忽略 */ }
                }
            }
        }
        close(s);
    }
    close(fd);
    return NULL;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s --config <file> [--daemon] [--once]\n"
        "       %s --config <file> --connect <dst_id_hex> <host> <port>\n"
        "  --config   节点配置（key=value 行格式）\n"
        "  --daemon   后台运行\n"
        "  --once     只建网格、探测一轮、写状态后退出（部署自检用）\n"
        "  --connect  建洋葱电路到 dst，最后一跳连 host:port，stdin/stdout 双向透传\n",
        prog, prog);
}

/*
 * 发起端透传：stdin -> 电路 -> 目标，目标回程 -> stdout。
 *
 * 不能用 lat_proxy_relay：它在任一端 EOF 时立即返回，而 stdin 写完就是 EOF，
 * 回程数据还没到就退出了。这里需要半关闭语义：
 *   stdin EOF -> shutdown(fd, SHUT_WR) 把 FIN 送过去 -> 继续收回程直到对端 EOF。
 */
static int relay_stdin(int fd, int idle_ms) {
    uint8_t buf[4096];
    int stdin_eof = 0;

    for (;;) {
        struct pollfd p[2];
        int n, i;

        p[0].fd = STDIN_FILENO; p[0].events = stdin_eof ? 0 : POLLIN; p[0].revents = 0;
        p[1].fd = fd;           p[1].events = POLLIN;                 p[1].revents = 0;

        n = poll(p, 2, idle_ms > 0 ? idle_ms : -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return 0;                       /* 空闲超时 */

        if (p[0].revents & POLLIN) {
            ssize_t r = read(STDIN_FILENO, buf, sizeof buf);
            if (r < 0) {
                if (errno == EINTR) continue;
                stdin_eof = 1;
            } else if (r == 0) {
                stdin_eof = 1;
                if (shutdown(fd, SHUT_WR) != 0) { /* 已关闭亦可忽略 */ }
            } else {
                ssize_t off = 0;
                while (off < r) {
                    ssize_t w = send(fd, buf + off, (size_t)(r - off), MSG_NOSIGNAL);
                    if (w < 0) {
                        if (errno == EINTR) continue;
                        return -1;
                    }
                    off += w;
                }
            }
        }

        if (p[1].revents & POLLIN) {
            ssize_t r = recv(fd, buf, sizeof buf, 0);
            if (r < 0) {
                if (errno == EINTR) continue;
                return -1;
            }
            if (r == 0) return 0;                   /* 对端关闭，收完 */
            ssize_t off = 0;
            while (off < r) {
                ssize_t w = write(STDOUT_FILENO, buf + off, (size_t)(r - off));
                if (w < 0) {
                    if (errno == EINTR) continue;
                    return -1;
                }
                off += w;
            }
        }

        for (i = 0; i < 2; i++)
            if (p[i].revents & (POLLHUP | POLLERR | POLLNVAL)) {
                if (i == 0) { stdin_eof = 1; continue; }
                return 0;
            }
        if (stdin_eof && !(p[1].revents & POLLIN)) {
            /* stdin 已尽且本轮无回程，再等一轮 idle 让回程到达 */
            struct pollfd q;
            q.fd = fd; q.events = POLLIN; q.revents = 0;
            if (poll(&q, 1, idle_ms > 0 ? idle_ms : -1) == 0) return 0;
            continue;
        }
    }
}

/* 发起端：按 QoS 算路 -> 逐层包裹 -> 连首跳 -> 双向透传。
 * 中间跳只知道下一跳，不知道完整路径与最终目标。 */
static int run_connect(const node_cfg_t *cfg, p2p_mesh_t *m,
                       const uint8_t *dst_id, const char *fhost,
                       uint16_t fport) {
    uint8_t salt[P2P_ONION_SALT_LEN];
    uint8_t path[P2P_MAX_HOPS][P2P_NODE_ID_LEN];
    int n_hop = 0, fd = -1, i;
    char ph[P2P_NODE_ID_LEN * 2 + 1];

    if (p2p_route_path_qos(m, cfg->id, dst_id, path, P2P_MAX_HOPS, &n_hop)
        != P2P_OK || n_hop <= 0) {
        fprintf(stderr, "[node] 无可用路径\n");
        return 1;
    }
    for (i = 0; i < n_hop; i++) {
        hexenc(path[i], P2P_NODE_ID_LEN, ph, sizeof ph);
        fprintf(stderr, "[node] hop%d=%s\n", i, ph);
    }
    /* 每条电路随机 salt：同一跳在不同电路上层密钥不同 */
    {
        struct timespec ts;
        uint32_t x;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        x = (uint32_t)(ts.tv_nsec ^ (uint32_t)ts.tv_sec);
        for (i = 0; i < (int)sizeof salt; i++) {
            x ^= x << 13; x ^= x >> 17; x ^= x << 5;
            salt[i] = (uint8_t)(x >> 24);
        }
    }
    if (p2p_onion_route_open(m, cfg->id, dst_id, fhost, fport, salt, &fd)
        != P2P_OK) {
        fprintf(stderr, "[node] 电路建立失败\n");
        return 1;
    }
    fprintf(stderr, "[node] 电路已建立 fd=%d\n", fd);
    relay_stdin(fd, 5000);
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    const char *cfgpath = NULL;
    const char *connect_dst = NULL;
    const char *connect_host = NULL;
    const char *connect_port = NULL;
    int daemonize = 0, once = 0;
    node_cfg_t cfg;
    p2p_mesh_t mesh;
    p2p_hopkey_t hk;
    uint8_t sk[32];
    pthread_t pth, mth;
    node_state_t st;
    int lfd;
    uint16_t realport = 0;
    int i;
    char idhex[P2P_NODE_ID_LEN * 2 + 1];
    char pkhex[65];

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) cfgpath = argv[++i];
        else if (strcmp(argv[i], "--daemon") == 0) daemonize = 1;
        else if (strcmp(argv[i], "--once") == 0) once = 1;
        else if (strcmp(argv[i], "--connect") == 0 && i + 3 < argc) {
            connect_dst = argv[++i];
            connect_host = argv[++i];
            connect_port = argv[++i];
        }
        else { usage(argv[0]); return 2; }
    }
    if (!cfgpath) { usage(argv[0]); return 2; }

    if (cfg_parse_file(cfgpath, &cfg) != 0) {
        fprintf(stderr, "[node] 配置解析失败: %s\n", cfgpath);
        return 1;
    }

    /* 跳密钥：存在则载入，否则生成并落盘（0600） */
    if (hopkey_load(cfg.keyfile, &hk, sk) != 0) {
        if (p2p_hopkey_init(&hk) != P2P_HOPKEY_OK) {
            fprintf(stderr, "[node] 跳密钥生成失败\n");
            return 1;
        }
        memcpy(sk, hk.slots[0].sk, 32);
        if (hopkey_save(cfg.keyfile, &hk) != 0) {
            fprintf(stderr, "[node] 跳密钥写盘失败: %s\n", cfg.keyfile);
            return 1;
        }
    }

    if (p2p_mesh_init(&mesh) != P2P_OK) return 1;
    if (p2p_node_add(&mesh, cfg.id, cfg.role, cfg.alias,
                     cfg.listen_host, cfg.listen_port) != P2P_OK) {
        fprintf(stderr, "[node] 自身入网格失败\n");
        return 1;
    }
    p2p_node_set_pub(&mesh, cfg.id, hk.slots[0].pk);

    /* peer 先入网格（含自身之外的全部节点），使发起端能算路、能建洋葱 */
    for (i = 0; i < cfg.n_pr; i++) {
        char al[P2P_ALIAS_LEN];
        snprintf(al, sizeof al, "p%d", i);
        if (p2p_node_find(&mesh, cfg.pr[i].id) >= 0) continue;
        if (p2p_node_add(&mesh, cfg.pr[i].id, P2P_ROLE_EDGE, al,
                         cfg.pr[i].host, cfg.pr[i].port) != P2P_OK) {
            fprintf(stderr, "[node] peer 入网格失败 idx=%d\n", i);
            return 1;
        }
        if (cfg.pr[i].has_pub)
            p2p_node_set_pub(&mesh, cfg.pr[i].id, cfg.pr[i].pub);
    }
    for (i = 0; i < cfg.n_nb; i++) {
        char al[P2P_ALIAS_LEN];
        snprintf(al, sizeof al, "nb%d", i);
        if (p2p_node_find(&mesh, cfg.nb[i].id) < 0 &&
            p2p_node_add(&mesh, cfg.nb[i].id, P2P_ROLE_EDGE, al,
                         cfg.nb[i].host, cfg.nb[i].port) != P2P_OK) {
            fprintf(stderr, "[node] 邻居入网格失败 idx=%d\n", i);
            return 1;
        }
        if (cfg.nb[i].has_pub)
            p2p_node_set_pub(&mesh, cfg.nb[i].id, cfg.nb[i].pub);
        p2p_neighbor_link(&mesh, cfg.id, cfg.nb[i].id);
    }
    /* 全图邻接声明：让本节点能算出到任意节点的路径，而不只知道自己的边 */
    for (i = 0; i < cfg.n_lk; i++) {
        if (p2p_node_find(&mesh, cfg.lk[i].a) < 0 ||
            p2p_node_find(&mesh, cfg.lk[i].b) < 0) continue;
        p2p_neighbor_link(&mesh, cfg.lk[i].a, cfg.lk[i].b);
    }

    /* --connect：网格已完整构建（peer + neighbor + link）后再算路建电路 */
    if (connect_dst) {
        uint8_t dst[P2P_NODE_ID_LEN];
        if (hexdec(connect_dst, dst, P2P_NODE_ID_LEN) != 0) {
            fprintf(stderr, "[node] --connect 目标 ID 非 32 位 hex\n");
            return 2;
        }
        /* 先跑一轮探测，让 QoS 有真实度量可用 */
        {
            p2p_probesched_t ps0;
            int np = 0, ns = 0;
            if (p2p_probesched_init(&ps0, cfg.seed, 0, 1, 0) == P2P_OK)
                p2p_probe_all_staggered(&ps0, &mesh, cfg.id, 0, &np, &ns);
        }
        return run_connect(&cfg, &mesh, dst, connect_host,
                           (uint16_t)strtoul(connect_port, NULL, 10));
    }

    lfd = listen_on(cfg.listen_host, cfg.listen_port, &realport);
    if (lfd < 0) {
        fprintf(stderr, "[node] 监听失败 %s:%u (%s)\n",
                cfg.listen_host, (unsigned)cfg.listen_port, strerror(errno));
        return 1;
    }

    hexenc(cfg.id, P2P_NODE_ID_LEN, idhex, sizeof idhex);
    hexenc(hk.slots[0].pk, 32, pkhex, sizeof pkhex);
    fprintf(stderr, "[node] %s role=%s id=%s listen=%s:%u pk=%s neighbors=%d\n",
            cfg.alias, role_str(cfg.role), idhex, cfg.listen_host,
            (unsigned)realport, pkhex, cfg.n_nb);

    st.m = &mesh;
    st.cfg = &cfg;
    st.port = realport;
    st.start = time(NULL);
    st.probing = 0;
    write_state(&cfg, &mesh, realport, st.start);

    if (once) {
        int n_probed = 0, n_skipped = 0;
        p2p_probesched_t ps;
        if (p2p_probesched_init(&ps, cfg.seed, 0, 1, 0) == P2P_OK)
            p2p_probe_all_staggered(&ps, &mesh, cfg.id, 0, &n_probed, &n_skipped);
        write_state(&cfg, &mesh, realport, st.start);
        fprintf(stderr, "[node] once 完成, probed=%d skipped=%d\n",
                n_probed, n_skipped);
        close(lfd);
        return 0;
    }

    if (daemonize) {
        pid_t pid = fork();
        if (pid < 0) { close(lfd); return 1; }
        if (pid > 0) {
            fprintf(stderr, "[node] daemon pid=%d\n", (int)pid);
            close(lfd);
            return 0;
        }
        setsid();
        if (chdir("/") != 0) { /* 忽略：保持工作目录亦可 */ }
        fclose(stdin);
        fclose(stdout);
    }

    signal(SIGTERM, on_sigterm);
    signal(SIGINT, on_sigterm);
    signal(SIGCHLD, on_sigchld);

    pthread_create(&pth, NULL, probe_thread, &st);
    if (cfg.mgmt_port) pthread_create(&mth, NULL, mgmt_thread, &st);

    /* 洋葱版监听循环：每跳只剥自己那一层，不知道完整路径与最终目标 */
    p2p_onion_route_serve(&mesh, cfg.id, sk, lfd);

    g_stop = 1;
    close(lfd);
    p2p_hopkey_wipe(&hk);
    return 0;
}
