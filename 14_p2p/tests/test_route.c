/*
 * DAYANJING v3 — test_route.c
 *
 * QoS 路由与数据面的联动验证（非手工串链）：
 *   - endpoint 调 p2p_route_open，路径来自 p2p_route_path_qos
 *   - 每一跳按自己 mesh 的邻居地址真实建连，转发剩余电路头
 *   - 用例1：两条等跳路径，QoS 选 RTT 低的那条（BFS 会选另一条作对照）
 *   - 用例2：杀掉优选路径上的中间节点并标记故障 -> QoS 改走备用路径，链路仍通
 *   - 用例3：最后一条可用中间跳也故障 -> 无存活邻居 -> QoS 返回 NOROUTE
 */

#include "p2p.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

static int pass = 0, fail = 0;
#define CK(c, m) do { if (c) { pass++; printf("[PASS] %s\n", m); } \
                      else { fail++; printf("[FAIL] %s\n", m); } } while (0)

static void set_id(uint8_t *id, const char *s) {
    memset(id, 0, P2P_NODE_ID_LEN);
    memcpy(id, s, strlen(s) > P2P_NODE_ID_LEN ? P2P_NODE_ID_LEN : strlen(s));
}

static int listen_auto(int *out_port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) { close(s); return -1; }
    if (listen(s, 16) < 0) { close(s); return -1; }
    struct sockaddr_in got; socklen_t gl = sizeof got;
    if (getsockname(s, (struct sockaddr *)&got, &gl) < 0) { close(s); return -1; }
    *out_port = ntohs(got.sin_port);
    return s;
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
static ssize_t recv_all(int fd, uint8_t *b, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, b + off, n - off, 0);
        if (r <= 0) break;
        off += (size_t)r;
    }
    return (ssize_t)off;
}

/* echo 目标（最终回显服务，不是 p2p 节点） */
static pid_t spawn_echo(int *port) {
    int pfd[2]; if (pipe(pfd) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        close(pfd[0]);
        int lp = 0, s = listen_auto(&lp);
        if (s < 0) _exit(2);
        if (write(pfd[1], &lp, sizeof lp) != (ssize_t)sizeof lp) _exit(3);
        close(pfd[1]);
        for (;;) {
            int c = accept(s, NULL, NULL);
            if (c < 0) continue;
            uint8_t buf[8192];
            for (;;) {
                ssize_t r = recv(c, buf, sizeof buf, 0);
                if (r <= 0) break;
                if (send_all(c, buf, (size_t)r) < 0) break;
            }
            close(c);
        }
    }
    close(pfd[1]);
    int lp = 0;
    if (read(pfd[0], &lp, sizeof lp) != (ssize_t)sizeof lp) { close(pfd[0]); return -1; }
    close(pfd[0]);
    *port = lp;
    return pid;
}

/* 起一个 p2p 中继节点：子进程带自己的 mesh 与 my_id，调用 p2p_route_serve */
static pid_t spawn_route_node(const p2p_mesh_t *m, const uint8_t *my_id, int *port) {
    int pfd[2]; if (pipe(pfd) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        close(pfd[0]);
        int lp = 0, s = listen_auto(&lp);
        if (s < 0) _exit(2);
        if (write(pfd[1], &lp, sizeof lp) != (ssize_t)sizeof lp) _exit(3);
        close(pfd[1]);
        p2p_route_serve(m, my_id, s);
        _exit(0);
    }
    close(pfd[1]);
    int lp = 0;
    if (read(pfd[0], &lp, sizeof lp) != (ssize_t)sizeof lp) { close(pfd[0]); return -1; }
    close(pfd[0]);
    *port = lp;
    return pid;
}

/* 通过已建立的隧道发一收一，校验字节级一致 */
static int tunnel_roundtrip(int fd, const uint8_t *msg, size_t n) {
    if (send_all(fd, msg, n) != 0) return -1;
    uint8_t *back = calloc(n ? n : 1, 1);
    if (!back) return -1;
    ssize_t got = recv_all(fd, back, n);
    int ok = (got == (ssize_t)n) && (memcmp(msg, back, n) == 0);
    free(back);
    return ok ? 0 : -1;
}

int main(void) {
    printf("=== 14_p2p QoS 路由与数据面联动（真进程 + 真 socket） ===\n");
    signal(SIGPIPE, SIG_IGN);

    uint8_t ID_EP[P2P_NODE_ID_LEN], ID_E0[P2P_NODE_ID_LEN],
            ID_E1[P2P_NODE_ID_LEN], ID_CORE[P2P_NODE_ID_LEN];
    set_id(ID_EP, "ENDPOINT"); set_id(ID_E0, "EDGE0");
    set_id(ID_E1, "EDGE1");    set_id(ID_CORE, "CORE");

    /* 1) echo 目标 */
    int p_echo = 0;
    pid_t pid_echo = spawn_echo(&p_echo);
    CK(pid_echo > 0 && p_echo > 0, "echo 目标启动");

    /* 2) core（最后一跳，mesh 只需自身） */
    p2p_mesh_t m_core;
    p2p_mesh_init(&m_core);
    p2p_node_add(&m_core, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", 0);
    int p_core = 0;
    pid_t pid_core = spawn_route_node(&m_core, ID_CORE, &p_core);
    CK(pid_core > 0 && p_core > 0, "core 节点启动");

    /* 3) edge1（需知道 core 的地址） */
    p2p_mesh_t m_e1;
    p2p_mesh_init(&m_e1);
    p2p_node_add(&m_e1, ID_E1, P2P_ROLE_EDGE, "edge1", "127.0.0.1", 0);
    p2p_node_add(&m_e1, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", (uint16_t)p_core);
    p2p_neighbor_link(&m_e1, ID_E1, ID_CORE);
    int p_e1 = 0;
    pid_t pid_e1 = spawn_route_node(&m_e1, ID_E1, &p_e1);
    CK(pid_e1 > 0 && p_e1 > 0, "edge1 节点启动");

    /* 4) edge0（备用路径，同样知道 core 地址） */
    p2p_mesh_t m_e0;
    p2p_mesh_init(&m_e0);
    p2p_node_add(&m_e0, ID_E0, P2P_ROLE_EDGE, "edge0", "127.0.0.1", 0);
    p2p_node_add(&m_e0, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", (uint16_t)p_core);
    p2p_neighbor_link(&m_e0, ID_E0, ID_CORE);
    int p_e0 = 0;
    pid_t pid_e0 = spawn_route_node(&m_e0, ID_E0, &p_e0);
    CK(pid_e0 > 0 && p_e0 > 0, "edge0 节点启动");

    /* 5) endpoint 全景 mesh：两条等跳路径，RTT 差异明显 */
    p2p_mesh_t m_ep;
    p2p_mesh_init(&m_ep);
    p2p_node_add(&m_ep, ID_EP, P2P_ROLE_ENDPOINT, "endpoint", "127.0.0.1", 0);
    p2p_node_add(&m_ep, ID_E0, P2P_ROLE_EDGE, "edge0", "127.0.0.1", (uint16_t)p_e0);
    p2p_node_add(&m_ep, ID_E1, P2P_ROLE_EDGE, "edge1", "127.0.0.1", (uint16_t)p_e1);
    p2p_node_add(&m_ep, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", (uint16_t)p_core);
    p2p_neighbor_link(&m_ep, ID_EP, ID_E0);
    p2p_neighbor_link(&m_ep, ID_EP, ID_E1);
    p2p_neighbor_link(&m_ep, ID_E0, ID_CORE);
    p2p_neighbor_link(&m_ep, ID_E1, ID_CORE);
    p2p_link_set_rtt(&m_ep, ID_EP, ID_E0, 500);   /* 慢路径 */
    p2p_link_set_rtt(&m_ep, ID_EP, ID_E1, 10);    /* 快路径 */
    p2p_link_set_rtt(&m_ep, ID_E0, ID_CORE, 100);
    p2p_link_set_rtt(&m_ep, ID_E1, ID_CORE, 20);

    /* ---- 用例1：QoS 选快路径 ---- */
    uint8_t path_a[P2P_MAX_HOPS][P2P_NODE_ID_LEN];
    int n_a = 0;
    int rc = p2p_route_path_qos(&m_ep, ID_EP, ID_CORE, path_a, P2P_MAX_HOPS, &n_a);
    CK(rc == P2P_OK && n_a == 2, "QoS 算出 2 跳路径");
    CK(rc == P2P_OK && n_a >= 1 && memcmp(path_a[0], ID_E1, P2P_NODE_ID_LEN) == 0,
       "QoS 选 RTT 低的 edge1（非 BFS 顺序）");

    uint8_t path_bfs[P2P_MAX_HOPS][P2P_NODE_ID_LEN];
    int n_bfs = 0;
    p2p_route_path(&m_ep, ID_EP, ID_CORE, path_bfs, P2P_MAX_HOPS, &n_bfs);
    printf("[INFO] QoS 首跳=edge1? %d ; BFS 首跳=edge0? %d\n",
           (n_a >= 1 && memcmp(path_a[0], ID_E1, P2P_NODE_ID_LEN) == 0),
           (n_bfs >= 1 && memcmp(path_bfs[0], ID_E0, P2P_NODE_ID_LEN) == 0));

    int fd1 = -1;
    rc = p2p_route_open(&m_ep, ID_EP, ID_CORE, "127.0.0.1", (uint16_t)p_echo, &fd1);
    CK(rc == P2P_OK && fd1 >= 0, "p2p_route_open 按 QoS 建隧道成功");
    if (fd1 >= 0) {
        uint8_t msg[64];
        for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 5 + 1);
        CK(tunnel_roundtrip(fd1, msg, sizeof msg) == 0, "经 QoS 路径往返字节级一致");
        close(fd1);
    }

    /* ---- 用例2：优选路径中间节点故障 -> QoS 改走备用 ---- */
    kill(pid_e1, SIGKILL);
    waitpid(pid_e1, NULL, 0);
    p2p_node_mark_dead(&m_ep, ID_E1);
    {
        struct timespec ts = { 0, 120 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    uint8_t path_c[P2P_MAX_HOPS][P2P_NODE_ID_LEN];
    int n_c = 0;
    rc = p2p_route_path_qos(&m_ep, ID_EP, ID_CORE, path_c, P2P_MAX_HOPS, &n_c);
    CK(rc == P2P_OK && n_c >= 1 && memcmp(path_c[0], ID_E0, P2P_NODE_ID_LEN) == 0,
       "edge1 故障后 QoS 改走 edge0");
    int fd2 = -1;
    rc = p2p_route_open(&m_ep, ID_EP, ID_CORE, "127.0.0.1", (uint16_t)p_echo, &fd2);
    CK(rc == P2P_OK && fd2 >= 0, "故障后经备用路径仍能建隧道");
    if (fd2 >= 0) {
        uint8_t msg2[128];
        for (int i = 0; i < 128; i++) msg2[i] = (uint8_t)(i ^ 0x3c);
        CK(tunnel_roundtrip(fd2, msg2, sizeof msg2) == 0, "备用路径往返字节级一致");
        close(fd2);
    }

    /* ---- 用例3：最后一条可用中间跳也故障 -> 无存活邻居 -> 真 NOROUTE ----
     * 注：route_open 只负责"连首跳 + 发电路头"；下游某跳不可达会在数据面
     *     暴露（收不到回显），不是在 open 阶段返回 NOROUTE。这里验证的是
     *     QoS 不会给出一条经过故障节点的路径。 */
    p2p_node_mark_dead(&m_ep, ID_E0);
    int fd3 = -1;
    rc = p2p_route_open(&m_ep, ID_EP, ID_CORE, "127.0.0.1", (uint16_t)p_echo, &fd3);
    CK(rc == P2P_ERR_NOROUTE, "全部中间跳故障后 route_open 返回 NOROUTE");
    if (fd3 >= 0) close(fd3);

    kill(pid_e0, SIGKILL); waitpid(pid_e0, NULL, 0);
    kill(pid_core, SIGKILL); waitpid(pid_core, NULL, 0);
    kill(pid_echo, SIGKILL); waitpid(pid_echo, NULL, 0);

    printf("total=%d pass=%d fail=%d\n", pass + fail, pass, fail);
    return fail ? 1 : 0;
}
