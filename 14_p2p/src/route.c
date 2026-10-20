/*
 * DAYANJING v3 — 14_p2p/src/route.c
 *
 * QoS 路由与数据面的联动点。
 *
 * 与旧 test_chain 的本质区别：
 *   旧：测试里手工 spawn_relay 把 next_port 硬编码串成一条固定链，
 *       路径不经过 p2p_route_path_qos，改拓扑不生效。
 *   新：endpoint 调 p2p_route_open -> QoS 算路 -> 连首跳 -> 发电路头；
 *       每一跳按**自己 mesh 里的邻居地址**真实建连并转发剩余头。
 *       改链路 RTT/故障，路径随之改变（QoS 真正驱动转发）。
 *
 * 数据面仍委托 08_lateral 的 poll 双工中继（p2p_relay），不重复实现事件循环。
 */

#include "p2p.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* ---- 小端读写 ---- */
static void put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}
static uint16_t get_u16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* ---- 网络辅助 ---- */
static int connect_host(const char *host, uint16_t port) {
    if (!host || !port) return -1;
    struct addrinfo hints, *res = NULL;
    char portstr[8];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%u", (unsigned)port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;

    int fd = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int send_all(int fd, const uint8_t *b, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, b + off, n - off, MSG_NOSIGNAL);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static ssize_t recv_exact(int fd, uint8_t *b, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, b + off, n - off, 0);
        if (r <= 0) break;
        off += (size_t)r;
    }
    return (ssize_t)off;
}

/* ====================================================================
 * 节点地址
 * ==================================================================== */

int p2p_node_endpoint(const p2p_mesh_t *m, const uint8_t *id,
                      const char **host, uint16_t *port) {
    if (!m || !id || !host || !port) return P2P_ERR_ARGS;
    int i = p2p_node_find(m, id);
    if (i < 0) return P2P_ERR_NOTFOUND;
    *host = m->nodes[i].host;
    *port = m->nodes[i].port;
    return P2P_OK;
}

/* ====================================================================
 * 电路头编解码
 * ==================================================================== */

int p2p_route_build_hdr(const uint8_t *ids_flat, int n_ids,
                        const char *final_host, uint16_t final_port,
                        uint8_t *out, size_t cap, size_t *len) {
    if (!len) return P2P_ERR_ARGS;
    if (n_ids < 0 || n_ids > P2P_ROUTE_HDR_MAX_IDS) return P2P_ERR_ARGS;
    if (n_ids > 0 && !ids_flat) return P2P_ERR_ARGS;

    size_t host_len = final_host ? strlen(final_host) : 0;
    if (host_len > 255) return P2P_ERR_ARGS;

    size_t total = 1 + (size_t)n_ids * P2P_NODE_ID_LEN + 2 + 1 + host_len;
    *len = total;
    if (!out) return P2P_OK;
    if (cap < total) return P2P_ERR_ARGS;

    size_t off = 0;
    out[off++] = (uint8_t)n_ids;
    for (int i = 0; i < n_ids; i++) {
        memcpy(out + off, ids_flat + (size_t)i * P2P_NODE_ID_LEN, P2P_NODE_ID_LEN);
        off += P2P_NODE_ID_LEN;
    }
    put_u16(out + off, final_port); off += 2;
    out[off++] = (uint8_t)host_len;
    if (host_len) memcpy(out + off, final_host, host_len);
    return P2P_OK;
}

int p2p_route_parse_hdr(const uint8_t *in, size_t len,
                        uint8_t ids[][P2P_NODE_ID_LEN], int max_ids, int *n_ids,
                        char *final_host, size_t host_cap, uint16_t *final_port) {
    if (!in || !n_ids || !final_port) return P2P_ERR_ARGS;
    if (len < 4) return P2P_ERR_ARGS;

    int n = in[0];
    if (n < 0 || n > max_ids) return P2P_ERR_ARGS;
    size_t off = 1 + (size_t)n * P2P_NODE_ID_LEN;
    if (len < off + 3) return P2P_ERR_ARGS;

    uint16_t port = get_u16(in + off);
    size_t host_len = in[off + 2];
    if (len != off + 3 + host_len) return P2P_ERR_ARGS;
    if (final_host && host_cap > 0 && host_cap < host_len + 1) return P2P_ERR_ARGS;

    for (int i = 0; i < n; i++)
        memcpy(ids[i], in + 1 + (size_t)i * P2P_NODE_ID_LEN, P2P_NODE_ID_LEN);
    if (final_host && host_cap > 0) {
        memcpy(final_host, in + off + 3, host_len);
        final_host[host_len] = '\0';
    }
    *n_ids = n;
    *final_port = port;
    return P2P_OK;
}

/* ====================================================================
 * 逐跳转发
 * ==================================================================== */

int p2p_route_handle_conn(const p2p_mesh_t *m, const uint8_t *my_id, int cfd) {
    if (!m || !my_id || cfd < 0) return P2P_ERR_ARGS;

    /* 1) 先读 n_ids，确定后续长度 */
    uint8_t first = 0;
    if (recv_exact(cfd, &first, 1) != 1) return P2P_ERR_UNREACH;
    int n_ids = first;
    if (n_ids > P2P_ROUTE_HDR_MAX_IDS) return P2P_ERR_ARGS;

    size_t tail = (size_t)n_ids * P2P_NODE_ID_LEN + 3;   /* ids + port(2) + host_len(1) */
    uint8_t *tmp = calloc(tail, 1);
    if (!tmp) return P2P_ERR_ARGS;
    if (recv_exact(cfd, tmp, tail) != (ssize_t)tail) { free(tmp); return P2P_ERR_UNREACH; }

    size_t host_len = tmp[tail - 1];
    uint8_t *buf = calloc(1 + tail + host_len, 1);
    if (!buf) { free(tmp); return P2P_ERR_ARGS; }
    buf[0] = first;
    memcpy(buf + 1, tmp, tail);
    free(tmp);
    if (host_len) {
        if (recv_exact(cfd, buf + 1 + tail, host_len) != (ssize_t)host_len) {
            free(buf); return P2P_ERR_UNREACH;
        }
    }
    size_t total = 1 + tail + host_len;

    /* 2) 解析 */
    uint8_t ids[P2P_ROUTE_HDR_MAX_IDS][P2P_NODE_ID_LEN];
    char fhost[256]; uint16_t fport = 0;
    memset(ids, 0, sizeof ids);
    if (p2p_route_parse_hdr(buf, total, ids, P2P_ROUTE_HDR_MAX_IDS, &n_ids,
                            fhost, sizeof fhost, &fport) != P2P_OK) {
        free(buf); return P2P_ERR_ARGS;
    }
    free(buf);

    /* 3) 最后一跳（或空路径）：直连最终目标 */
    if (n_ids == 0) {
        int tfd = connect_host(fhost, fport);
        if (tfd < 0) return P2P_ERR_UNREACH;
        int rc = p2p_relay(cfd, tfd, 0);
        close(tfd);
        return rc;
    }

    /* 4) 校验 ids[0] 是自己——防止电路被错送到别的节点 */
    if (memcmp(ids[0], my_id, P2P_NODE_ID_LEN) != 0) return P2P_ERR_NOTFOUND;

    if (n_ids == 1) {
        /* 只剩自己：我即为最后一跳，连最终目标 */
        int tfd = connect_host(fhost, fport);
        if (tfd < 0) return P2P_ERR_UNREACH;
        int rc = p2p_relay(cfd, tfd, 0);
        close(tfd);
        return rc;
    }

    /* 5) 取下一跳地址（本节点自己的 mesh 视图），建连并转发剩余头 */
    const char *nhost = NULL; uint16_t nport = 0;
    if (p2p_node_endpoint(m, ids[1], &nhost, &nport) != P2P_OK) return P2P_ERR_UNREACH;
    int nfd = connect_host(nhost, nport);
    if (nfd < 0) return P2P_ERR_UNREACH;

    /* 剩余路径：弹掉自身（ids[0]），从 ids[1] 开始 */
    uint8_t rest_flat[P2P_ROUTE_HDR_MAX_IDS * P2P_NODE_ID_LEN];
    memset(rest_flat, 0, sizeof rest_flat);
    for (int i = 1; i < n_ids; i++)
        memcpy(rest_flat + (size_t)(i - 1) * P2P_NODE_ID_LEN, ids[i], P2P_NODE_ID_LEN);

    uint8_t hdr[512]; size_t hlen = 0;
    if (p2p_route_build_hdr(rest_flat, n_ids - 1, fhost, fport, hdr, sizeof hdr, &hlen) != P2P_OK) {
        close(nfd); return P2P_ERR_ARGS;
    }
    if (send_all(nfd, hdr, hlen) != 0) { close(nfd); return P2P_ERR_UNREACH; }

    int rc = p2p_relay(cfd, nfd, 0);
    close(nfd);
    return rc;
}

void p2p_route_serve(const p2p_mesh_t *m, const uint8_t *my_id, int listen_fd) {
    if (!m || !my_id || listen_fd < 0) return;
    for (;;) {
        int cfd = accept(listen_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            continue;
        }
        pid_t p = fork();
        if (p == 0) {
            /* 子进程处理单条电路 */
            p2p_route_handle_conn(m, my_id, cfd);
            close(cfd);
            _exit(0);
        }
        close(cfd);
    }
}

int p2p_route_open(const p2p_mesh_t *m, const uint8_t *from, const uint8_t *dst,
                   const char *final_host, uint16_t final_port, int *out_fd) {
    if (!m || !from || !dst || !out_fd) return P2P_ERR_ARGS;
    if (!final_host || !final_port) return P2P_ERR_ARGS;

    /* QoS 算路（不是 BFS，也不是测试硬编码） */
    uint8_t path[P2P_MAX_HOPS][P2P_NODE_ID_LEN];
    int n_hop = 0;
    memset(path, 0, sizeof path);
    int rc = p2p_route_path_qos(m, from, dst, path, P2P_MAX_HOPS, &n_hop);
    if (rc != P2P_OK) return rc;
    if (n_hop <= 0) return P2P_ERR_NOROUTE;

    const char *host = NULL; uint16_t port = 0;
    if (p2p_node_endpoint(m, path[0], &host, &port) != P2P_OK) return P2P_ERR_UNREACH;
    int fd = connect_host(host, port);
    if (fd < 0) return P2P_ERR_UNREACH;

    uint8_t path_flat[P2P_MAX_HOPS * P2P_NODE_ID_LEN];
    memset(path_flat, 0, sizeof path_flat);
    for (int i = 0; i < n_hop; i++)
        memcpy(path_flat + (size_t)i * P2P_NODE_ID_LEN, path[i], P2P_NODE_ID_LEN);

    uint8_t hdr[512]; size_t hlen = 0;
    if (p2p_route_build_hdr(path_flat, n_hop, final_host, final_port,
                            hdr, sizeof hdr, &hlen) != P2P_OK) {
        close(fd); return P2P_ERR_ARGS;
    }
    if (send_all(fd, hdr, hlen) != 0) { close(fd); return P2P_ERR_UNREACH; }

    *out_fd = fd;
    return P2P_OK;
}
