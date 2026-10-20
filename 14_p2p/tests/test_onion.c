/*
 * DAYANJING v4 — 14_p2p/tests/test_onion.c
 *
 * 洋葱路由分层加密验证 + E2EE 与动态路由的叠加。
 *
 * 覆盖（单元部分，纯内存）：
 *   1. 层密钥派生确定性与按 hop 分离
 *   2. 逐跳 peel：每跳解出正确下一跳；最后一跳解出最终 host:port
 *   3. 核心性质 A：中间跳无法解密内层（用自己的密钥 peel inner -> AUTH）
 *   4. 核心性质 B：中间跳剥出的层里不含最终目标字节（看不到链路形状）
 *   5. 错误主密钥 / 篡改洋葱 -> AUTH
 *   6. salt 不同 -> 层密钥不同（跨电路隔离）
 *
 * 覆盖（端到端部分，真进程 + 真 socket）：
 *   7. 四级链路 endpoint->e0->e1->core->echo，洋葱路由逐跳转发
 *   8. 在同一 fd 上叠加 p2p_tunnel_send/recv（E2EE），字节级一致
 *
 * 注意：端口必须在 fork 之前确定。子进程复制的是 fork 时刻的 mesh，
 * 若 fork 后才回填端口，子进程拿到的仍是旧值，转发会连到已死的端口。
 */

#include "p2p.h"
#include "p2p_onion.h"
#include "p2p_crypto.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

static int pass = 0, fail = 0;
#define CK(c, m) do { if (c) { pass++; printf("[PASS] %s\n", m); } \
                      else { fail++; printf("[FAIL] %s\n", m); } } while (0)

static void mkid(uint8_t *id, uint8_t v) { memset(id, v, P2P_NODE_ID_LEN); }

/* ---- 真 socket 辅助 ---- */

static int listen_on(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    if (listen(fd, 8) != 0) { close(fd); return -1; }
    return fd;
}

/* 探测一个当前可用端口（测试环境，TOCTOU 可接受）。
 * cursor 为进出参数：成功后推进到 p+1，保证连续多次调用不返回同一端口 ——
 * 否则所有进程会抢同一个端口，后 bind 的拿 EADDRINUSE(98)。 */
static int pick_port(uint16_t *out, uint16_t *cursor) {
    for (uint16_t p = *cursor; p < 47000; p++) {
        int fd = listen_on(p);
        if (fd >= 0) { close(fd); *out = p; *cursor = (uint16_t)(p + 1); return 0; }
    }
    return -1;
}

/* echo 服务监听固定端口：收多少吐多少 */
static pid_t spawn_echo_on(uint16_t port) {
    int lfd = listen_on(port);
    if (lfd < 0) return -1;
    pid_t p = fork();
    if (p == 0) {
        setpgid(0, 0);
        for (;;) {
            int c = accept(lfd, NULL, NULL);
            if (c < 0) { if (errno == EINTR) continue; break; }
            char buf[4096];
            for (;;) {
                ssize_t r = recv(c, buf, sizeof buf, 0);
                if (r <= 0) break;
                size_t off = 0;
                while (off < (size_t)r) {
                    ssize_t w = send(c, buf + off, (size_t)r - off, MSG_NOSIGNAL);
                    if (w <= 0) break;
                    off += (size_t)w;
                }
            }
            close(c);
        }
        _exit(0);
    }
    close(lfd);
    return p;
}

/* 洋葱中继节点：持有自己的 mesh 视图与洋葱主密钥，监听固定端口 */
static pid_t spawn_onion_relay_on(const p2p_mesh_t *tmpl, const uint8_t *my_id,
                                  const uint8_t *master, uint16_t port) {
    int lfd = listen_on(port);
    if (lfd < 0) return -1;
    pid_t p = fork();
    if (p == 0) {
        setpgid(0, 0);
        p2p_onion_route_serve(tmpl, my_id, master, lfd);
        _exit(0);
    }
    close(lfd);
    return p;
}

int main(void) {
    printf("=== 14_p2p 洋葱路由分层加密测试 ===\n");

    uint8_t master[P2P_ONION_MASTER_LEN];
    memset(master, 0x5a, sizeof master);
    uint8_t salt[P2P_ONION_SALT_LEN];
    memset(salt, 0x11, sizeof salt);

    uint8_t e0[16], e1[16], core[16], ep[16];
    mkid(e0, 0x10); mkid(e1, 0x11); mkid(core, 0x12); mkid(ep, 0x13);

    /* ---- 1. 层密钥派生 ---- */
    {
        uint8_t k1[16], k2[16], k1b[16];
        CK(p2p_onion_layer_key(master, salt, e0, k1) == P2P_ONION_OK, "layer key e0");
        CK(p2p_onion_layer_key(master, salt, e1, k2) == P2P_ONION_OK, "layer key e1");
        CK(p2p_onion_layer_key(master, salt, e0, k1b) == P2P_ONION_OK, "layer key e0 again");
        CK(memcmp(k1, k2, 16) != 0, "不同跳层密钥不同");
        CK(memcmp(k1, k1b, 16) == 0, "层密钥派生确定");

        uint8_t salt2[16]; memset(salt2, 0x22, sizeof salt2);
        uint8_t k3[16];
        p2p_onion_layer_key(master, salt2, e0, k3);
        CK(memcmp(k1, k3, 16) != 0, "salt 不同则层密钥不同（跨电路隔离）");
    }

    /* ---- 2. 洋葱构建 + 逐跳 peel ---- */
    {
        uint8_t hops[3 * P2P_NODE_ID_LEN];
        memcpy(hops + 0 * 16, e0, 16);
        memcpy(hops + 1 * 16, e1, 16);
        memcpy(hops + 2 * 16, core, 16);

        uint8_t onion[4096]; size_t olen = 0;
        CK(p2p_onion_build(master, salt, hops, 3, "127.0.0.1", 9999,
                           onion, sizeof onion, &olen) == P2P_ONION_OK,
           "构建 3 跳洋葱");

        int ff = 0; uint8_t nxt[16]; char host[256]; uint16_t port = 0;
        uint8_t inner[4096]; size_t ilen = 0;

        /* 首跳 e0 剥开 */
        CK(p2p_onion_peel(master, salt, e0, onion, olen, &ff, nxt,
                          host, sizeof host, &port, inner, sizeof inner, &ilen)
           == P2P_ONION_OK, "e0 剥开自己的层");
        CK(ff == 0, "e0 不是最后一跳");
        CK(memcmp(nxt, e1, 16) == 0, "e0 解出的下一跳是 e1");
        CK(ilen > 0, "e0 拿到内层洋葱");
        CK(strstr(host, "127.0.0.1") == NULL && port == 0,
           "e0 看不到最终目标 host:port");

        /* 核心性质 A：e0 用自己的密钥解不开内层 */
        int ff2 = 0; uint8_t nxt2[16]; uint16_t p2 = 0; size_t il2 = 0;
        CK(p2p_onion_peel(master, salt, e0, inner, ilen, &ff2, nxt2,
                          host, sizeof host, &p2, NULL, 0, &il2)
           == P2P_ONION_ERR_AUTH, "e0 无法解密内层（AUTH）");

        /* e1 剥开 */
        uint8_t inner2[4096]; size_t ilen2 = 0;
        CK(p2p_onion_peel(master, salt, e1, inner, ilen, &ff, nxt,
                          host, sizeof host, &port, inner2, sizeof inner2, &ilen2)
           == P2P_ONION_OK, "e1 剥开自己的层");
        CK(ff == 0 && memcmp(nxt, core, 16) == 0, "e1 解出的下一跳是 core");
        CK(strstr(host, "127.0.0.1") == NULL && port == 0,
           "e1 也看不到最终目标");

        /* core 剥开：最后一跳 */
        CK(p2p_onion_peel(master, salt, core, inner2, ilen2, &ff, nxt,
                          host, sizeof host, &port, NULL, 0, &il2)
           == P2P_ONION_OK, "core 剥开自己的层");
        CK(ff == 1, "core 是最后一跳");
        CK(strcmp(host, "127.0.0.1") == 0 && port == 9999,
           "core 解出最终目标 host:port");

        /* 错误主密钥 */
        uint8_t bad[16]; memset(bad, 0x99, sizeof bad);
        CK(p2p_onion_peel(bad, salt, e0, onion, olen, &ff, nxt,
                          host, sizeof host, &port, NULL, 0, &il2)
           == P2P_ONION_ERR_AUTH, "错误主密钥 -> AUTH");

        /* 篡改洋葱 */
        uint8_t tampered[4096];
        memcpy(tampered, onion, olen);
        tampered[olen - 1] ^= 0x01;
        CK(p2p_onion_peel(master, salt, e0, tampered, olen, &ff, nxt,
                          host, sizeof host, &port, NULL, 0, &il2)
           == P2P_ONION_ERR_AUTH, "篡改洋葱 -> AUTH");
    }

    /* ---- 3. 端到端：真进程四级链路 + E2EE 叠加 ---- */
    {
        uint16_t e0p = 0, e1p = 0, corep = 0, echop = 0;
        uint16_t cursor = 46000;
        if (pick_port(&echop, &cursor) || pick_port(&e0p, &cursor) ||
            pick_port(&e1p, &cursor) || pick_port(&corep, &cursor)) {
            printf("[FAIL] pick port\n"); fail++; return 1;
        }

        p2p_mesh_t m;
        p2p_mesh_init(&m);
        p2p_node_add(&m, ep,   P2P_ROLE_ENDPOINT, "ep",   "127.0.0.1", 1);
        p2p_node_add(&m, e0,   P2P_ROLE_EDGE,     "e0",   "127.0.0.1", e0p);
        p2p_node_add(&m, e1,   P2P_ROLE_EDGE,     "e1",   "127.0.0.1", e1p);
        p2p_node_add(&m, core, P2P_ROLE_CORE,     "core", "127.0.0.1", corep);
        p2p_neighbor_link(&m, ep, e0);
        p2p_neighbor_link(&m, e0, e1);
        p2p_neighbor_link(&m, e1, core);
        p2p_link_set_rtt(&m, ep, e0, 1);
        p2p_link_set_rtt(&m, e0, e1, 1);
        p2p_link_set_rtt(&m, e1, core, 1);

        pid_t pe  = spawn_echo_on(echop);
        pid_t r0  = spawn_onion_relay_on(&m, e0,   master, e0p);
        pid_t r1  = spawn_onion_relay_on(&m, e1,   master, e1p);
        pid_t rc_ = spawn_onion_relay_on(&m, core, master, corep);
        if (pe < 0 || r0 < 0 || r1 < 0 || rc_ < 0) {
            printf("[FAIL] spawn\n"); fail++; return 1;
        }
        printf("[INFO] 链路: ep -> e0(%u) -> e1(%u) -> core(%u) -> echo(%u)\n",
               e0p, e1p, corep, echop);

        uint8_t csalt[P2P_ONION_SALT_LEN];
        memset(csalt, 0x77, sizeof csalt);
        int fd = -1;
        int orc = p2p_onion_route_open(&m, ep, core, "127.0.0.1", echop,
                                       master, csalt, &fd);
        CK(orc == P2P_OK && fd >= 0, "洋葱四级链路建立");
        if (fd < 0) goto cleanup_e2e;

        struct timeval tv;
        tv.tv_sec = 6; tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);


        /* E2EE 叠加：在同一 fd 上跑隧道 */
        p2p_tunnel_t ta, tb;
        uint8_t kf[16], kr[16];
        memset(kf, 0x31, 16);
        memset(kr, 0x32, 16);
        uint8_t np[8]; memset(np, 0x40, 8);
        CK(p2p_tunnel_init(&ta, kf, kr, np) == P2P_C_OK, "隧道 A 初始化");
        CK(p2p_tunnel_init(&tb, kr, kf, np) == P2P_C_OK, "隧道 B 初始化（方向相反）");

        const char *msg = "ONION-E2EE-PAYLOAD-0123456789";
        CK(p2p_tunnel_send(&ta, fd, 0x21, (const uint8_t *)msg, strlen(msg))
           == P2P_C_OK, "隧道发送（四级洋葱链路之上）");

        /* echo 把密文原样吐回，用 B 端密钥解 */
        uint8_t rbuf[512]; size_t rlen = 0;
        uint64_t seq = 0; uint32_t mt = 0;
        int rcv = p2p_tunnel_recv(&tb, fd, &seq, &mt, rbuf, sizeof rbuf, &rlen);
        CK(rcv == P2P_C_OK, "隧道接收并验签");
        CK(rcv == P2P_C_OK && rlen == strlen(msg) &&
           memcmp(rbuf, msg, rlen) == 0, "E2EE + 洋葱四级链路字节级一致");
        CK(rcv == P2P_C_OK && mt == 0x21, "msg_type 透传正确");

        close(fd);
cleanup_e2e:
        kill(-r0, SIGKILL); kill(-r1, SIGKILL); kill(-rc_, SIGKILL);
        kill(-pe, SIGKILL);
        waitpid(r0, NULL, 0); waitpid(r1, NULL, 0);
        waitpid(rc_, NULL, 0); waitpid(pe, NULL, 0);
    }

    /* ---- 4. 主动探测：真实 TCP connect 计时（解除"需外部测量后手工 set"） ---- */
    {
        uint16_t tp = 0;
        uint16_t cursor = 46100;
        if (pick_port(&tp, &cursor) != 0) { CK(0, "pick probe port"); goto done; }
        pid_t srv = spawn_echo_on(tp);
        if (srv < 0) { CK(0, "spawn probe target"); goto done; }

        p2p_mesh_t pm;
        p2p_mesh_init(&pm);
        uint8_t pa[16], pb[16], pc[16];
        mkid(pa, 0x61); mkid(pb, 0x62); mkid(pc, 0x63);
        p2p_node_add(&pm, pa, P2P_ROLE_ENDPOINT, "PA", "127.0.0.1", 1);
        p2p_node_add(&pm, pb, P2P_ROLE_EDGE,     "PB", "127.0.0.1", tp);
        p2p_node_add(&pm, pc, P2P_ROLE_EDGE,     "PC", "127.0.0.1", 1);
        p2p_neighbor_link(&pm, pa, pb);
        p2p_neighbor_link(&pm, pa, pc);

        uint32_t rtt = 0;
        CK(p2p_link_probe(&pm, pa, pb, &rtt) == P2P_OK, "主动探测回环邻居成功");
        CK(rtt >= 1, "探测 RTT 至少 1ms（回环握手极快，0 会被当作未测量）");

        uint32_t ew = 0, ok2 = 0;
        p2p_link_get_qos(&pm, pa, pb, &ew, NULL, NULL, &ok2, NULL);
        CK(ew > 0, "探测后 EWMA 已建立（不再需要外部 set）");
        CK(ok2 == 1, "探测成功计数 +1");

        /* 探测不可达邻居：必须累加失败计数，让丢包惩罚生效 */
        int prc = p2p_link_probe(&pm, pa, pc, NULL);
        uint32_t f2 = 0;
        p2p_link_get_qos(&pm, pa, pc, NULL, NULL, NULL, NULL, &f2);
        if (prc != P2P_OK) CK(f2 == 1, "探测失败累加失败计数（丢包惩罚生效）");
        else               CK(f2 == 0, "探测成功则不计失败");

        kill(-srv, SIGKILL);
        waitpid(srv, NULL, 0);
    }

done:
    printf("\n=== 洋葱路由测试 total=%d pass=%d fail=%d ===\n", pass + fail, pass, fail);
    fflush(stdout);
    _exit(fail ? 1 : 0);
}
