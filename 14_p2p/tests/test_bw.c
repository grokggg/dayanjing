/*
 * DAYANJING v4 — 14_p2p/tests/test_bw.c
 *
 * 真实带宽测量测试。
 *
 * 关键：sink 必须用**真实进程 + 真实 socket**，且分快/慢两种。
 * 慢 sink 每读 8KB 睡 5ms —— 若探测只测"本地发送缓冲区有多大"
 * （不等对端回执），快慢两者的测得值会几乎一样，测试就会暴露这一点。
 */

#include "p2p.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int g_pass = 0, g_fail = 0;
static void check(int cond, const char *name) {
    if (cond) { g_pass++; printf("[PASS] %s\n", name); }
    else      { g_fail++; printf("[FAIL] %s\n", name); }
}

/* 启动一个 sink：读完全部数据后回 1 字节。slow=1 时边读边睡。 */
static pid_t start_sink(uint16_t *port, int slow) {
    int sv[2];
    if (pipe(sv) != 0) return -1;
    pid_t p = fork();
    if (p == 0) {
        close(sv[0]);
        signal(SIGPIPE, SIG_IGN);
        int lfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (bind(lfd, (struct sockaddr *)&a, sizeof a) != 0) _exit(1);
        if (listen(lfd, 4) != 0) _exit(1);
        struct sockaddr_in got;
        socklen_t gl = sizeof got;
        getsockname(lfd, (struct sockaddr *)&got, &gl);
        uint16_t np = ntohs(got.sin_port);
        if (write(sv[1], &np, sizeof np) != (ssize_t)sizeof np) _exit(1);
        close(sv[1]);

        /* 循环 accept：探测会被调用多次，sink 不能在第一次连接后就退出 */
        for (;;) {
            int cfd = accept(lfd, NULL, NULL);
            if (cfd < 0) {
                if (errno == EINTR) continue;
                break;
            }
            uint8_t buf[8192];
            for (;;) {
                ssize_t r = recv(cfd, buf, sizeof buf, 0);
                if (r <= 0) break;
                if (slow) {
                    struct timespec ts = {0, 5 * 1000 * 1000};  /* 5ms */
                    nanosleep(&ts, NULL);
                }
            }
            uint8_t one = 1;
            send(cfd, &one, 1, 0);
            close(cfd);
        }
        close(lfd);
        _exit(0);
    }
    close(sv[1]);
    uint16_t np = 0;
    if (read(sv[0], &np, sizeof np) != (ssize_t)sizeof np) np = 0;
    close(sv[0]);
    *port = np;
    return p;
}

static void stop(pid_t p) {
    if (p > 0) { kill(p, SIGKILL); waitpid(p, NULL, 0); }
}

int main(void) {
    uint16_t fast_port = 0, slow_port = 0;
    pid_t pf = start_sink(&fast_port, 0);
    pid_t ps = start_sink(&slow_port, 1);
    check(pf > 0 && ps > 0 && fast_port && slow_port, "启动快/慢两个 sink 进程");
    printf("[INFO] fast sink=%u  slow sink=%u\n", fast_port, slow_port);

    /* ---- 1. 真实测量：快 sink ---- */
    uint32_t bw_fast = 0, bw_slow = 0;
    int ack_fast = 0, ack_slow = 0;
    {
        int rc = p2p_probe_bandwidth("127.0.0.1", fast_port, 256 * 1024,
                                     &bw_fast, &ack_fast);
        check(rc == P2P_OK, "探测快链路返回 OK");
        check(ack_fast == 1, "快链路收到对端回执（测的是端到端，不是写缓冲）");
        check(bw_fast > 0, "快链路带宽 > 0");
        printf("[INFO] fast bw = %u kbps\n", bw_fast);
    }

    /* ---- 2. 真实测量：慢 sink ---- */
    {
        int rc = p2p_probe_bandwidth("127.0.0.1", slow_port, 256 * 1024,
                                     &bw_slow, &ack_slow);
        check(rc == P2P_OK, "探测慢链路返回 OK");
        check(ack_slow == 1, "慢链路收到对端回执");
        check(bw_slow > 0, "慢链路带宽 > 0");
        printf("[INFO] slow bw = %u kbps\n", bw_slow);
    }

    /* ---- 3. 取证：测量必须能区分快慢 ---- */
    check(bw_fast > bw_slow, "测得带宽：快链路 > 慢链路");
    check(bw_fast >= bw_slow * 2, "快链路至少是慢链路的 2 倍（测量有分辨力）");
    printf("[INFO] 快/慢 = %.2fx\n", bw_slow ? (double)bw_fast / bw_slow : 0.0);

    /* ---- 4. 参数校验与不可达 ---- */
    {
        uint32_t bw = 0; int acked = 0;
        check(p2p_probe_bandwidth("127.0.0.1", fast_port, 0, &bw, &acked)
              == P2P_ERR_ARGS, "bytes=0 -> ARG");
        check(p2p_probe_bandwidth(NULL, fast_port, 1024, &bw, &acked)
              == P2P_ERR_ARGS, "host=NULL -> ARG");
        /* 无人监听的端口：先占一个再关掉 */
        int tmp = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        bind(tmp, (struct sockaddr *)&a, sizeof a);
        socklen_t sl = sizeof a;
        getsockname(tmp, (struct sockaddr *)&a, &sl);
        uint16_t dead = ntohs(a.sin_port);
        close(tmp);
        check(p2p_probe_bandwidth("127.0.0.1", dead, 4096, &bw, &acked)
              == P2P_ERR_UNREACH, "端口无人监听 -> UNREACH");
    }

    /* ---- 5. 写入边度量 + 影响 QoS 选路（端到端，非单元断言） ---- */
    {
        p2p_mesh_t m;
        p2p_mesh_init(&m);
        uint8_t idA[16], idF[16], idS[16], idD[16];
        memset(idA, 0x01, 16); memset(idF, 0x02, 16);
        memset(idS, 0x03, 16); memset(idD, 0x04, 16);

        p2p_node_add(&m, idA, P2P_ROLE_ENDPOINT, "A", "127.0.0.1", 1);
        p2p_node_add(&m, idF, P2P_ROLE_EDGE, "FAST", "127.0.0.1", fast_port);
        p2p_node_add(&m, idS, P2P_ROLE_EDGE, "SLOW", "127.0.0.1", slow_port);
        p2p_node_add(&m, idD, P2P_ROLE_CORE, "D", "127.0.0.1", fast_port);

        p2p_neighbor_link(&m, idA, idF);
        p2p_neighbor_link(&m, idA, idS);
        p2p_neighbor_link(&m, idF, idD);
        p2p_neighbor_link(&m, idS, idD);

        uint32_t gf = 0, gs = 0;
        check(p2p_link_probe_bw(&m, idA, idF, 256 * 1024, &gf) == P2P_OK,
              "探测 A->FAST 并写入边度量");
        check(p2p_link_probe_bw(&m, idA, idS, 256 * 1024, &gs) == P2P_OK,
              "探测 A->SLOW 并写入边度量");
        printf("[INFO] 边度量 FAST=%u kbps  SLOW=%u kbps\n", gf, gs);

        uint32_t stored = 0;
        check(p2p_link_get_qos(&m, idA, idF, NULL, NULL, &stored, NULL, NULL)
              == P2P_OK && stored == gf, "边度量中存回了实测带宽");

        /* 两条等跳路径，RTT 同为回环量级 -> 由实测带宽决定 */
        uint8_t path[P2P_MAX_HOPS][P2P_NODE_ID_LEN];
        int n_hop = 0;
        memset(path, 0, sizeof path);
        check(p2p_route_path_qos(&m, idA, idD, path, P2P_MAX_HOPS, &n_hop)
              == P2P_OK, "QoS 算出路径");
        int first_is_fast = (n_hop > 0 && memcmp(path[0], idF, 16) == 0);
        check(first_is_fast, "QoS 首跳选带宽更高的 FAST（实测带宽驱动选路）");
        printf("[INFO] QoS 首跳 = %s\n", first_is_fast ? "FAST" : "SLOW");

        /* 反过来把 FAST 的带宽人为压低，选路必须跟着翻转 */
        p2p_link_set_bw(&m, idA, idF, 1);
        memset(path, 0, sizeof path);
        n_hop = 0;
        p2p_route_path_qos(&m, idA, idD, path, P2P_MAX_HOPS, &n_hop);
        int flipped = (n_hop > 0 && memcmp(path[0], idS, 16) == 0);
        check(flipped, "人为压低 FAST 带宽后首跳翻转到 SLOW");
    }

    stop(pf);
    stop(ps);

    printf("\ntotal=%d pass=%d fail=%d\n", g_pass + g_fail, g_pass, g_fail);
    return g_fail ? 1 : 0;
}
