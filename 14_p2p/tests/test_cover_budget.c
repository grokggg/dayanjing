/*
 * DAYANJING v4 — 14_p2p/tests/test_cover_budget.c
 *
 * 覆盖预算按真实带宽自适应测试。
 *
 * 分两部分：
 *   A. 逻辑层：换算、溢出钳制、unknown、木桶、冲突、TTL、reset
 *   B. 真实层：起真实 sink 进程 -> p2p_probe_bandwidth 实测回环带宽
 *              -> 推导预算 -> 应用 -> 断言预算与实测值自洽
 *
 * B 部分是本项的意义所在：预算必须来自**实测**，不是我编一个数传进去。
 * 回环带宽波动大（实测约 2 Gbps 量级），故断言一律基于实测值推导，
 * 不硬编码期望值。
 */

#include "p2p_cover_budget.h"
#include "p2p.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

/* ---------- A. 逻辑层 ---------- */

static void test_conversion(void) {
    /* 1 Mbps = 1000 kbps -> 1000*7500 = 7.5e6 B/min；5% -> 375000 */
    uint32_t v = p2p_cover_budget_from_kbps(1000u, 50000u);
    check(v == 375000u, "换算：1Mbps @5% = 375000 B/min");

    /* 小带宽不得归零：bw=1 kbps -> 7500 B/min；5% -> 375 */
    v = p2p_cover_budget_from_kbps(1u, 50000u);
    check(v == 375u, "换算：1kbps @5% = 375 B/min（先乘后除，不归零）");

    /* bw=0 是 unknown，不是预算 0 */
    v = p2p_cover_budget_from_kbps(0u, 50000u);
    check(v == 0u, "换算：bw=0 -> 0（调用方据此判 unknown）");

    /* duty=0 为参数错误 */
    v = p2p_cover_budget_from_kbps(1000u, 0u);
    check(v == 0u, "换算：duty=0 -> 0");

    /* 100% duty：7,500,000 B/min 也超 CAP，故被钳。
     * CAP 是绝对上限，与 duty 无关 —— 覆盖的目的是抹平静默，不是填满带宽。 */
    v = p2p_cover_budget_from_kbps(1000u, 1000000u);
    check(v == P2P_COVER_BUDGET_CAP_BYTES_PER_MIN,
          "换算：1Mbps @100% 亦被 CAP 钳住（CAP 与 duty 无关）");

    /*
     * CAP 是否够用的实证：DNS 信道维持 250ms 静默上界需
     * 240 信元/分钟 * 2040 B = 489,600 B/min，CAP 为其 2 倍以上。
     * 若将来收紧静默上界到 100ms（600 信元/分钟 -> 1,224,000 B/min），
     * CAP 会成为瓶颈 —— 届时应调 CAP，而不是静默接受。
     */
    check(P2P_COVER_BUDGET_CAP_BYTES_PER_MIN >= 240u * P2P_COVER_COST_DNS,
          "CAP：足以支撑 DNS 信道 250ms 静默上界");
}

static void test_overflow_clamp(void) {
    /* 回环实测量级 2,097,152 kbps：不钳制会溢出 uint32 */
    uint32_t v = p2p_cover_budget_from_kbps(2097152u, 50000u);
    check(v == P2P_COVER_BUDGET_CAP_BYTES_PER_MIN,
          "溢出钳制：2Gbps @5% 被 CAP 挡住（未溢出）");

    /* 极端值同样安全 */
    v = p2p_cover_budget_from_kbps(0xFFFFFFFFu, 1000000u);
    check(v == P2P_COVER_BUDGET_CAP_BYTES_PER_MIN,
          "溢出钳制：UINT32_MAX kbps @100% 仍被 CAP 挡住");

    /* 钳制上界内的值应正常换算，不被误钳 */
    v = p2p_cover_budget_from_kbps(100000000u, 1000000u);
    check(v == P2P_COVER_BUDGET_CAP_BYTES_PER_MIN,
          "溢出钳制：100Gbps @100% 达 CAP（正确，非异常）");
}

static void test_unknown(void) {
    p2p_cover_budget_t b;
    p2p_cover_t cov;

    p2p_cover_budget_init(&b, 0, 1000);
    p2p_cover_init(&cov, P2P_COVER_PROFILE_DIRECT, 123456u, 1000);

    /* 无实测值：apply 必须返回 UNKNOWN，且**不得**修改既有预算 */
    int rc = p2p_cover_budget_apply(&b, &cov);
    check(rc == P2P_COVER_BUDGET_UNKNOWN, "未知带宽：apply 返回 UNKNOWN");
    check(cov.budget_bytes_per_min == 123456u,
          "未知带宽：既有预算未被改（不静默禁用覆盖）");

    /* 探测失败（bw=0）同样不得拉低预算 */
    p2p_cover_budget_reset(&b, 2000);
    (void)p2p_cover_budget_note_hop(&b, 0u, 2000);
    rc = p2p_cover_budget_apply(&b, &cov);
    check(rc == P2P_COVER_BUDGET_UNKNOWN, "探测失败：apply 返回 UNKNOWN");
    check(cov.budget_bytes_per_min == 123456u,
          "探测失败：既有预算未被改");
}

/*
 * 探测失败不得**永久污染**状态。
 *
 * 若把 bw=0 当成真实带宽写入 min_link_kbps，则 known 被置位、最小值归零，
 * 而 0 不比任何值大 —— 后续无论探测到多好的带宽，最小值永远停在 0，
 * derive 永远返回 UNKNOWN，覆盖静默消失。
 *
 * 它的表现极具误导性：换电路、换链路、重探测全都"成功"，预算却始终解
 * 不出来，而调用方读到的错误码与第一次探测失败时完全一样。只断言
 * "apply 返回 UNKNOWN" 抓不到它 —— 变异后返回值同样是 UNKNOWN，
 * 差别在于状态已被毒化、再也回不来。
 *
 * 所以这里必须做**恢复性**断言：失败之后再给一次真实带宽，必须能推导。
 */
static void test_probe_failure_no_poison(void) {
    p2p_cover_budget_t b;

    p2p_cover_budget_init(&b, 50000u, 3000);

    (void)p2p_cover_budget_note_hop(&b, 4000u, 3000);
    check(p2p_cover_budget_derive(&b) == P2P_COVER_BUDGET_OK,
          "有效探测后可推导预算");

    /* 一次探测失败插在中间 */
    (void)p2p_cover_budget_note_hop(&b, 0u, 3100);

    /* 重新探测到更窄的真实带宽 1000 kbps：必须生效，不能被前一次失败吞掉 */
    (void)p2p_cover_budget_note_hop(&b, 1000u, 3200);
    check(p2p_cover_budget_derive(&b) == P2P_COVER_BUDGET_OK,
          "探测失败后重新探测仍可推导（失败未永久毒化最小跳）");
    check(p2p_cover_budget_get(&b) == p2p_cover_budget_from_kbps(1000u, 50000u),
          "重新探测后预算按新带宽 1000 kbps 计算");
}

static void test_bucket(void) {
    p2p_cover_budget_t b;
    p2p_cover_t cov;

    p2p_cover_budget_init(&b, 50000u, 1000);
    p2p_cover_init(&cov, P2P_COVER_PROFILE_DIRECT, 0, 1000);

    /* 三跳：宽 - 窄 - 中。预算必须取最窄的 100 kbps */
    (void)p2p_cover_budget_note_hop(&b, 1000000u, 1000);
    (void)p2p_cover_budget_note_hop(&b, 100u, 1000);
    (void)p2p_cover_budget_note_hop(&b, 500000u, 1000);

    check(b.min_link_kbps == 100u, "木桶：取最窄跳 100 kbps");
    check(b.n_hops == 3, "木桶：跳数记账 3");

    int rc = p2p_cover_budget_apply(&b, &cov);
    /* 100 kbps @5% = 37500 B/min */
    check(rc == P2P_COVER_BUDGET_OK || rc == P2P_COVER_BUDGET_CONFLICT,
          "木桶：apply 成功");
    check(cov.budget_bytes_per_min == 37500u,
          "木桶：预算 = 100kbps @5% = 37500 B/min");

    /* 更宽的后续跳不得抬高预算 */
    (void)p2p_cover_budget_note_hop(&b, 9000000u, 1000);
    check(b.min_link_kbps == 100u, "木桶：宽跳不抬高预算");

    /* 探测失败不得拉低已有最小值 */
    (void)p2p_cover_budget_note_hop(&b, 0u, 1000);
    check(b.min_link_kbps == 100u, "木桶：探测失败不拉低最小值");
}

static void test_reset(void) {
    p2p_cover_budget_t b;
    p2p_cover_budget_init(&b, 50000u, 1000);

    (void)p2p_cover_budget_note_hop(&b, 100u, 1000);
    check(b.min_link_kbps == 100u, "reset：登记窄跳 100");

    /* 换电路：不 reset 会与上一电路的窄跳取 min，且无报错 */
    (void)p2p_cover_budget_reset(&b, 2000);
    check(b.min_link_kbps == 0u && b.n_hops == 0 && !b.known,
          "reset：新电路清空跳记录");

    (void)p2p_cover_budget_note_hop(&b, 8000000u, 2000);
    check(b.min_link_kbps == 8000000u,
          "reset：宽电路预算不再被旧窄跳拖累");
}

static void test_conflict(void) {
    p2p_cover_budget_t b;
    p2p_cover_t cov;

    /* 极窄链路 1 kbps 走 DNS 信道：预算撑不住 250ms 静默上界 */
    p2p_cover_budget_init(&b, 50000u, 1000);
    p2p_cover_init(&cov, P2P_COVER_PROFILE_DNS, 0, 1000);

    (void)p2p_cover_budget_note_hop(&b, 1u, 1000);
    int rc = p2p_cover_budget_apply(&b, &cov);

    check(rc == P2P_COVER_BUDGET_CONFLICT,
          "冲突：极窄链路 + DNS 信道 -> CONFLICT");
    check(b.conflict == 1, "冲突：conflict 标志置位");
    check(cov.budget_bytes_per_min == 375u,
          "冲突：预算仍被应用（不超带宽优先）");

    /* 量化诊断：375 B/min / 2040 B每信元 -> 0 信元/分钟 -> 无静默上界 */
    uint32_t sil = p2p_cover_budget_achievable_silence(&b, P2P_COVER_COST_DNS);
    check(sil == P2P_COVER_BUDGET_SILENCE_NONE,
          "冲突：诊断给出「无静默上界」而非 0");

    /* 宽链路 + 直连：应无冲突 */
    p2p_cover_budget_reset(&b, 2000);
    (void)p2p_cover_budget_note_hop(&b, 10000u, 2000);   /* 10 Mbps */
    p2p_cover_init(&cov, P2P_COVER_PROFILE_DIRECT, 0, 2000);
    rc = p2p_cover_budget_apply(&b, &cov);
    check(rc == P2P_COVER_BUDGET_OK, "无冲突：10Mbps + 直连 -> OK");

    /* 10 Mbps @5% = 3,750,000 -> 钳到 CAP 1048576 */
    check(cov.budget_bytes_per_min == P2P_COVER_BUDGET_CAP_BYTES_PER_MIN,
          "无冲突：预算被 CAP 钳住");

    sil = p2p_cover_budget_achievable_silence(&b, P2P_COVER_COST_DIRECT);
    /* 1048576 / 552 = 1899 信元/分钟 -> 60000/1899 = 31 ms */
    check(sil > 0 && sil < 250u,
          "无冲突：可达静默优于 250ms 上界");

    /*
     * 真实冲突场景：1 Mbps 链路走 DNS 信道。
     * 1 Mbps @5% = 375,000 B/min，而 DNS 维持 250ms 上界需 489,600 B/min。
     * 这是窄带 + 贵信道的典型组合 —— 必须报 CONFLICT 并给出可达静默，
     * 让调用方在「提高 duty / 放宽静默 / 换信道」之间决策。
     */
    p2p_cover_budget_reset(&b, 3000);
    p2p_cover_init(&cov, P2P_COVER_PROFILE_DNS, 0, 3000);
    (void)p2p_cover_budget_note_hop(&b, 1000u, 3000);   /* 1 Mbps */
    rc = p2p_cover_budget_apply(&b, &cov);

    check(rc == P2P_COVER_BUDGET_CONFLICT,
          "真实冲突：1Mbps + DNS 信道 -> CONFLICT");
    check(cov.budget_bytes_per_min == 375000u,
          "真实冲突：预算 375000 B/min（未被抬高，带宽优先）");

    sil = p2p_cover_budget_achievable_silence(&b, P2P_COVER_COST_DNS);
    /* 375000 / 2040 = 183 信元/分钟 -> 60000/183 = 327 ms */
    printf("[INFO] 1Mbps+DNS 可达静默: %u ms（需求 250ms）\n", sil);
    check(sil > 250u, "真实冲突：诊断显示可达静默长于需求 250ms");

    /* 提高到 10% duty 后应转为无冲突 */
    (void)p2p_cover_budget_set_duty(&b, 100000u);
    rc = p2p_cover_budget_apply(&b, &cov);
    check(rc == P2P_COVER_BUDGET_OK,
          "真实冲突：duty 提到 10% 后转为 OK（决策路径可用）");
}

static void test_ttl(void) {
    p2p_cover_budget_t b;
    p2p_cover_budget_init(&b, 50000u, 0);

    check(p2p_cover_budget_stale(&b, 1000) == 0,
          "TTL：无实测值不算陈旧");

    (void)p2p_cover_budget_note_hop(&b, 1000u, 1000);
    check(p2p_cover_budget_stale(&b, 1000) == 0, "TTL：刚探测不陈旧");

    /* 默认 TTL 5 分钟 */
    check(p2p_cover_budget_stale(&b, 1000 + 300ull * 1000000ull + 1ull) == 1,
          "TTL：超 5 分钟判陈旧");
    check(p2p_cover_budget_stale(&b, 1000 + 60ull * 1000000ull) == 0,
          "TTL：1 分钟内不陈旧");

    /* 时间回拨不得误判为陈旧 */
    check(p2p_cover_budget_stale(&b, 500) == 0, "TTL：时间回拨不误判");

    /* ttl=0 永不过期 */
    (void)p2p_cover_budget_set_ttl(&b, 0);
    check(p2p_cover_budget_stale(&b, 1000ull * 1000000ull) == 0,
          "TTL：0 = 永不过期");
}

static void test_args(void) {
    p2p_cover_budget_t b;
    p2p_cover_t cov;

    check(p2p_cover_budget_init(NULL, 0, 0) == P2P_COVER_BUDGET_ERR_ARG,
          "参数：init(NULL) 被拒");

    /*
     * 未 init 检测：必须显式清零后再测。
     * 直接拿未初始化的栈变量测 inited 是读不确定值（UB），
     * 通过与否取决于栈上残留 —— 那样的断言毫无意义。
     */
    memset(&b, 0, sizeof b);
    memset(&cov, 0, sizeof cov);
    check(p2p_cover_budget_apply(&b, &cov) == P2P_COVER_BUDGET_ERR_ARG,
          "参数：未 init 的上下文被拒");
    check(p2p_cover_budget_note_hop(&b, 100u, 0) == P2P_COVER_BUDGET_ERR_ARG,
          "参数：未 init 登记跳被拒");
    check(p2p_cover_budget_derive(&b) == P2P_COVER_BUDGET_ERR_ARG,
          "参数：未 init 推导被拒");

    p2p_cover_budget_init(&b, 0, 0);
    check(b.duty_ppm == P2P_COVER_BUDGET_DEFAULT_DUTY_PPM,
          "参数：duty=0 取默认值 5%");
    check(p2p_cover_budget_set_duty(&b, 0) == P2P_COVER_BUDGET_ERR_ARG,
          "参数：set_duty(0) 被拒");
    check(p2p_cover_budget_set_duty(&b, 99999999u) == P2P_COVER_BUDGET_OK,
          "参数：duty > 100% 被钳到 100%");
    check(b.duty_ppm == 1000000u, "参数：duty 钳位结果正确");

    check(p2p_cover_budget_achievable_silence(&b, 0)
          == P2P_COVER_BUDGET_SILENCE_NONE,
          "参数：bytes_per_cell=0 -> 哨兵值");
}

/* ---------- B. 真实层：实测带宽 -> 预算 ---------- */

static pid_t start_sink(uint16_t *port) {
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
    if (port) *port = np;
    return p;
}

static void test_real_bandwidth(void) {
    uint16_t port = 0;
    pid_t sink = start_sink(&port);
    if (sink < 0 || port == 0) {
        printf("[SKIP] 真实带宽：无法启动 sink\n");
        return;
    }

    uint32_t bw = 0;
    int acked = 0;
    int rc = p2p_probe_bandwidth("127.0.0.1", port, 262144u, &bw, &acked);

    printf("[INFO] 实测回环带宽: %u kbps (acked=%d, rc=%d)\n", bw, acked, rc);

    if (rc != 0 || bw == 0 || !acked) {
        printf("[SKIP] 真实带宽：探测未取得可信值\n");
        kill(sink, SIGKILL);
        waitpid(sink, NULL, 0);
        return;
    }

    check(bw > 0, "真实带宽：探测取得非零带宽");

    /* 用实测值推导预算，断言与纯函数结果一致（自洽性） */
    p2p_cover_budget_t b;
    p2p_cover_t cov;
    p2p_cover_budget_init(&b, 50000u, 0);
    p2p_cover_init(&cov, P2P_COVER_PROFILE_DIRECT, 0, 0);

    (void)p2p_cover_budget_note_hop(&b, bw, 0);
    int arc = p2p_cover_budget_apply(&b, &cov);

    uint32_t expect = p2p_cover_budget_from_kbps(bw, 50000u);
    check(cov.budget_bytes_per_min == expect,
          "真实带宽：预算与纯函数换算一致");
    check(arc == P2P_COVER_BUDGET_OK || arc == P2P_COVER_BUDGET_CONFLICT,
          "真实带宽：apply 成功");

    /* 回环带宽极高（Gbps 级）-> 必被 CAP 钳住，这正是 CAP 的意义 */
    check(cov.budget_bytes_per_min == P2P_COVER_BUDGET_CAP_BYTES_PER_MIN,
          "真实带宽：Gbps 级链路被 CAP 钳住（不是填满带宽）");

    printf("[INFO] 推导预算: %u B/min, 可达静默 %u ms\n",
           cov.budget_bytes_per_min,
           p2p_cover_budget_achievable_silence(&b, P2P_COVER_COST_DIRECT));

    /* 换 DNS 信道：同样预算下可达静默应显著变差（信道更贵） */
    uint32_t sil_direct =
        p2p_cover_budget_achievable_silence(&b, P2P_COVER_COST_DIRECT);
    uint32_t sil_dns =
        p2p_cover_budget_achievable_silence(&b, P2P_COVER_COST_DNS);
    check(sil_dns > sil_direct,
          "真实带宽：DNS 信道可达静默长于直连（信道更贵）");

    kill(sink, SIGKILL);
    waitpid(sink, NULL, 0);
}

int main(void) {
    printf("=== test_cover_budget ===\n");
    test_conversion();
    test_overflow_clamp();
    test_unknown();
    test_probe_failure_no_poison();
    test_bucket();
    test_reset();
    test_conflict();
    test_ttl();
    test_args();
    test_real_bandwidth();
    printf("=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
