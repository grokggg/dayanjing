/*
 * DAYANJING v4 — 14_p2p/src/onion_route.c
 *
 * 洋葱路由 + QoS 动态选路 + 数据面中继 的合流。
 *
 * 与 route.c（明文电路头）的区别：
 *   route.c          : 每跳可见整条路径 + 最终目标 host:port
 *   onion_route.c    : 每跳只解出"下一跳是谁"，其余为不透明密文
 *
 * 线上帧格式（所有跳统一）：
 *     u16 LE body_len || u8 type || body
 *   type=1（首跳，endpoint 发出）：body = version(1) || salt(16) || onion
 *   type=2（中继跳转发）        ：body = inner onion（不透明）
 *
 * 每跳处理：
 *   type=1 -> 解析 salt + onion -> peel
 *   type=2 -> body 即 onion     -> peel
 *   peel 出 final=1 -> 连最终目标，relay
 *   peel 出 final=0 -> 连 next_id，以 type=2 转发 inner，relay
 *
 * 数据面仍委托 08_lateral 的 poll 双工中继（p2p_relay），不重复实现事件循环。
 */

#include "p2p.h"
#include "p2p_onion.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define ONION_MAX_BODY 4096

static void put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
}
static uint16_t get_u16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

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

/* 发一帧：u16 body_len || u8 type || body */
static int send_framed(int fd, uint8_t type,
                       const uint8_t *body, size_t body_len) {
    if (body_len + 1 > 0xffff) return -1;
    uint8_t buf[ONION_MAX_BODY + 3];
    if (body_len + 3 > sizeof buf) return -1;
    put_u16(buf, (uint16_t)(body_len + 1));
    buf[2] = type;
    if (body_len) memcpy(buf + 3, body, body_len);
    return send_all(fd, buf, body_len + 3);
}

/* 收一帧，返回 body 长度；*type 输出帧类型 */
static ssize_t recv_framed(int fd, uint8_t body[ONION_MAX_BODY], uint8_t *type) {
    uint8_t hdr[2];
    if (recv_exact(fd, hdr, 2) != 2) return -1;
    size_t n = get_u16(hdr);
    if (n < 1 || n > ONION_MAX_BODY) return -1;
    if (recv_exact(fd, body, n) != (ssize_t)n) return -1;
    *type = body[0];
    /* body 内容前移，去掉 type 字节 */
    if (n > 1) memmove(body, body + 1, n - 1);
    return (ssize_t)(n - 1);
}

/* ====================================================================
 * 发起端
 * ==================================================================== */

int p2p_onion_route_open(const p2p_mesh_t *m, const uint8_t *from,
                         const uint8_t *dst,
                         const char *final_host, uint16_t final_port,
                         const uint8_t salt[P2P_ONION_SALT_LEN],
                         int *out_fd) {
    if (!m || !from || !dst || !out_fd || !salt) return P2P_ERR_ARGS;
    if (!final_host || !final_port) return P2P_ERR_ARGS;

    /* QoS 算路（Dijkstra，按链路质量；不是 BFS，也不是硬编码） */
    uint8_t path[P2P_MAX_HOPS][P2P_NODE_ID_LEN];
    int n_hop = 0;
    memset(path, 0, sizeof path);
    int rc = p2p_route_path_qos(m, from, dst, path, P2P_MAX_HOPS, &n_hop);
    if (rc != P2P_OK) return rc;
    if (n_hop <= 0) return P2P_ERR_NOROUTE;
    if (n_hop > P2P_ONION_MAX_LAYERS) return P2P_ERR_ARGS;

    uint8_t path_flat[P2P_MAX_HOPS * P2P_NODE_ID_LEN];
    memset(path_flat, 0, sizeof path_flat);
    for (int i = 0; i < n_hop; i++)
        memcpy(path_flat + (size_t)i * P2P_NODE_ID_LEN, path[i], P2P_NODE_ID_LEN);

    uint8_t hdr[ONION_MAX_BODY];
    size_t  hlen = 0;
    /* 收集每一跳的静态公钥（层密钥协商用；私钥留在各跳本地） */
    uint8_t pub_flat[P2P_MAX_HOPS * P2P_PUBKEY_LEN];
    memset(pub_flat, 0, sizeof pub_flat);
    for (int i = 0; i < n_hop; i++) {
        if (p2p_node_get_pub(m, path[i], pub_flat + (size_t)i * P2P_PUBKEY_LEN)
            != P2P_OK) {
            return P2P_ERR_UNREACH;   /* 缺公钥的节点不能当跳板 */
        }
    }

    rc = p2p_onion_build_hdr(path_flat, n_hop, pub_flat, salt,
                             final_host, final_port, hdr, sizeof hdr, &hlen);
    if (rc != P2P_ONION_OK) return P2P_ERR_ARGS;

    const char *host = NULL; uint16_t port = 0;
    if (p2p_node_endpoint(m, path[0], &host, &port) != P2P_OK) return P2P_ERR_UNREACH;
    int fd = connect_host(host, port);
    if (fd < 0) return P2P_ERR_UNREACH;

    if (send_framed(fd, 1, hdr, hlen) != 0) {
        close(fd);
        return P2P_ERR_UNREACH;
    }
    *out_fd = fd;
    return P2P_OK;
}

/* ====================================================================
 * 中继侧
 * ==================================================================== */

int p2p_onion_route_handle(const p2p_mesh_t *m, const uint8_t *my_id,
                           const uint8_t sk[P2P_ONION_SK_LEN], int cfd) {
    if (!m || !my_id || !sk || cfd < 0) return P2P_ERR_ARGS;

    uint8_t body[ONION_MAX_BODY];
    uint8_t type = 0;
    ssize_t blen = recv_framed(cfd, body, &type);
    if (blen < 0) return P2P_ERR_UNREACH;

    const uint8_t *onion = NULL;
    size_t onion_len = 0;
    uint8_t salt[P2P_ONION_SALT_LEN];

    if (type == 1) {
        if (p2p_onion_parse_hdr(body, (size_t)blen, salt, &onion, &onion_len)
            != P2P_ONION_OK) {
            return P2P_ERR_ARGS;
        }
    } else if (type == 2) {
        /* 中继转发帧：body 即内层洋葱。salt 需从外层推导 —— 但我们不保存它。
         * 故 salt 必须随洋葱一起传递：把 salt 放在 fwd 帧里。 */
        if ((size_t)blen < P2P_ONION_SALT_LEN) return P2P_ERR_ARGS;
        memcpy(salt, body, P2P_ONION_SALT_LEN);
        onion = body + P2P_ONION_SALT_LEN;
        onion_len = (size_t)blen - P2P_ONION_SALT_LEN;
    } else {
        return P2P_ERR_ARGS;
    }

    int final_flag = 0;
    uint8_t next_id[P2P_NODE_ID_LEN];
    char fhost[256];
    uint16_t fport = 0;
    uint8_t inner[ONION_MAX_BODY];
    size_t inner_len = 0;
    memset(next_id, 0, sizeof next_id);

    int rc = p2p_onion_peel(sk, salt, my_id, onion, onion_len,
                            &final_flag, next_id, fhost, sizeof fhost, &fport,
                            inner, sizeof inner, &inner_len);
    if (rc == P2P_ONION_ERR_AUTH) return P2P_ERR_NOTFOUND;  /* 不是给我的 */
    if (rc != P2P_ONION_OK) return P2P_ERR_ARGS;

    if (final_flag) {
        int tfd = connect_host(fhost, fport);
        if (tfd < 0) return P2P_ERR_UNREACH;
        int r = p2p_relay(cfd, tfd, 0);
        close(tfd);
        return r;
    }

    /* 中继：连下一跳，转发剩余洋葱（salt + inner，本跳不解密 inner） */
    const char *nhost = NULL; uint16_t nport = 0;
    if (p2p_node_endpoint(m, next_id, &nhost, &nport) != P2P_OK) return P2P_ERR_UNREACH;
    int nfd = connect_host(nhost, nport);
    if (nfd < 0) return P2P_ERR_UNREACH;

    uint8_t fwd[ONION_MAX_BODY];
    if (P2P_ONION_SALT_LEN + inner_len > sizeof fwd) { close(nfd); return P2P_ERR_ARGS; }
    memcpy(fwd, salt, P2P_ONION_SALT_LEN);
    if (inner_len) memcpy(fwd + P2P_ONION_SALT_LEN, inner, inner_len);

    if (send_framed(nfd, 2, fwd, P2P_ONION_SALT_LEN + inner_len) != 0) {
        close(nfd);
        return P2P_ERR_UNREACH;
    }
    int r = p2p_relay(cfd, nfd, 0);
    close(nfd);
    return r;
}

void p2p_onion_route_serve(const p2p_mesh_t *m, const uint8_t *my_id,
                           const uint8_t sk[P2P_ONION_SK_LEN],
                           int listen_fd) {
    if (!m || !my_id || !sk || listen_fd < 0) return;
    for (;;) {
        int cfd = accept(listen_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            continue;
        }
        pid_t p = fork();
        if (p == 0) {
            p2p_onion_route_handle(m, my_id, sk, cfd);
            close(cfd);
            _exit(0);
        }
        close(cfd);
    }
}
