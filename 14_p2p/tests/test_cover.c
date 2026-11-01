/*
 * DAYANJING v4 — 14_p2p/tests/test_cover.c
 *
 * 自适应覆盖流量测试。
 *
 * 本文件要证明的核心性质（不是"函数能跑通"）：
 *   1) 自适应：数据突发 => 覆盖下降；空闲 => 覆盖上升。线上总速率趋于恒定
 *   2) 信道成本：换 DNS 信道后目标总速率按 bytes_per_cell 缩放，不再打满信道
 *   3) 去相关：覆盖速率对单窗口突发**不立即响应**（EWMA 平滑），
 *      否则"覆盖流量"会变成"数据流量"的侧信道
 *   4) 无下溢：数据速率远超预算时覆盖降到下限，绝不变成巨大正数
 *   5) 预算约束：任何信道下「数据+覆盖」的预计字节数都不超预算
 */

#include "p2p_cover.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, name) do {                          \
    if (cond) { printf("[PASS] %s\n", name); g_pass++; } \
    else      { printf("[FAIL] %s\n", name); g_fail++; } \
} while (0)

#define WIN 5000000ull   /* 5s，与 P2P_COVER_WINDOW_US 一致 */

static uint32_t budget_for(uint32_t profile, uint32_t target_cells) {
    uint32_t cost = (profile == P2P_COVER_PROFILE_DNS)  ? P2P_COVER_COST_DNS
                  : (profile == P2P_COVER_PROFILE_ICMP) ? P2P_COVER_COST_ICMP
                  :                                       P2P_COVER_COST_DIRECT;
    return cost * target_cells;
}

/* ---- 1. 基本自适应 ---- */
static void t_adaptive(void) {
    p2p_cover_t c;
    uint32_t budget = budget_for(P2P_COVER_PROFILE_DIRECT, 600);

    CHECK(p2p_cover_init(&c, P2P_COVER_PROFILE_DIRECT, budget, 0) == 0,
          "init 成功");

    /* 空闲：无数据，覆盖应升到上限 */
    uint32_t r_idle = p2p_cover_rate(&c);
    printf("      空闲覆盖速率=%u (target=%u)\n",
           r_idle, p2p_cover_target_total(&c));
    CHECK(r_idle == 600, "空闲时覆盖升到上限 600");

    /* 持续数据突发：每窗口 50 信元 => 600 信元/分钟 */
    uint64_t t = 0;
    for (int i = 0; i < 12; i++) {
        t += WIN;
        p2p_cover_note_data(&c, 50, t);
    }
    uint32_t data = p2p_cover_data_rate(&c);
    uint32_t r_busy = p2p_cover_rate(&c);
    printf("      数据速率=%u 覆盖速率=%u\n", data, r_busy);
    CHECK(data > 400, "EWMA 已收敛到接近真实数据速率");
    CHECK(r_busy < r_idle, "数据突发后覆盖速率下降（自适应生效）");
    CHECK(r_busy >= P2P_COVER_DEFAULT_MIN, "覆盖不低于下限（下限不为 0）");

    /* 停止数据，覆盖应回升。
     * 注意：EWMA 衰减是渐近的（每窗口 ×3/4），20 个窗口不足以归零。
     * 这里给足 45 个窗口，验证它能真正回到上限，而非"接近上限"。 */
    for (int i = 0; i < 45; i++) {
        t += WIN;
        p2p_cover_tick(&c, t);
    }
    uint32_t r_back = p2p_cover_rate(&c);
    printf("      停发后覆盖速率=%u\n", r_back);
    CHECK(r_back > r_busy, "停发数据后覆盖速率回升");
    CHECK(r_back == 600, "空闲足够久后覆盖回到上限");
}

/* ---- 2. 去相关：EWMA 平滑，覆盖不随单窗口突发瞬间塌陷 ---- */
static void t_decorrelate(void) {
    p2p_cover_t c;
    uint32_t budget = budget_for(P2P_COVER_PROFILE_DIRECT, 600);
    p2p_cover_init(&c, P2P_COVER_PROFILE_DIRECT, budget, 0);

    /*
     * 突发 50 信元/窗口（瞬时 600/min，等于全部预算）。
     *
     * 窗口记账语义：note_data 先推进边界、再累加，因此"第一个窗口的数据"
     * 要到**下一个边界**才计入速率。这是窗口统计的固有行为，不是缺陷 ——
     * 所以这里需要两次 note_data 才能看到第一次速率反馈。
     */
    p2p_cover_note_data(&c, 50, WIN);
    p2p_cover_note_data(&c, 50, 2 * WIN);
    uint32_t r1 = p2p_cover_rate(&c);
    printf("      首个突发窗口计入后覆盖速率=%u\n", r1);
    /* 若用瞬时值，这里会直接掉到下限 2；EWMA 只反映 1/4，应只降一部分 */
    CHECK(r1 > 100, "单窗口突发不使覆盖瞬间塌陷（EWMA 平滑）");
    CHECK(r1 < 600, "单窗口突发确实拉低了覆盖（不是无响应）");

    /* 连续突发多个窗口，覆盖应逐步下降 */
    uint64_t t = 2 * WIN;
    uint32_t prev = r1;
    int monotone = 1;
    for (int i = 0; i < 6; i++) {
        t += WIN;
        p2p_cover_note_data(&c, 50, t);
        uint32_t r = p2p_cover_rate(&c);
        if (r > prev) monotone = 0;
        prev = r;
    }
    printf("      连续突发后覆盖速率=%u\n", prev);
    CHECK(monotone, "连续突发期间覆盖速率单调下降");
    CHECK(prev < r1, "连续突发后覆盖速率低于首个窗口");
}

/* ---- 3. 信道成本：换 DNS 后目标总速率被缩放 ---- */
static void t_channel_cost(void) {
    p2p_cover_t tcp, dns, icmp;
    uint32_t budget = budget_for(P2P_COVER_PROFILE_DIRECT, 600);

    p2p_cover_init(&tcp, P2P_COVER_PROFILE_DIRECT, budget, 0);
    p2p_cover_init(&dns, P2P_COVER_PROFILE_DNS, budget, 0);
    p2p_cover_init(&icmp, P2P_COVER_PROFILE_ICMP, budget, 0);

    uint32_t tt = p2p_cover_target_total(&tcp);
    uint32_t td = p2p_cover_target_total(&dns);
    uint32_t ti = p2p_cover_target_total(&icmp);
    printf("      同预算下目标速率: TCP=%u ICMP=%u DNS=%u\n", tt, ti, td);

    CHECK(tt == 600, "TCP 信道目标 = 预算/552 = 600");
    CHECK(td < tt / 3, "DNS 信道目标速率显著低于 TCP（成本被计入）");
    CHECK(ti < tt && ti > td, "ICMP 目标速率介于 TCP 与 DNS 之间");

    /*
     * 关键：DNS 下预计开销仍受预算约束。
     * 必须先调 p2p_cover_rate 填 last_rate —— 否则 projected 读到的是 0，
     * 断言 "<= budget" 会平凡通过，等于没测。
     */
    uint32_t r_dns = p2p_cover_rate(&dns);
    uint32_t pb_dns = p2p_cover_projected_bytes_per_min(&dns);
    printf("      DNS 覆盖速率=%u 预计线上字节/分钟=%u (预算=%u)\n",
           r_dns, pb_dns, budget);
    CHECK(r_dns == td, "DNS 空闲时覆盖速率等于其目标速率");
    CHECK(pb_dns <= budget, "DNS 信道预计开销不超预算");
    CHECK(pb_dns > budget / 2, "DNS 预计开销非平凡（接近预算，不是 0）");

    uint32_t r_tcp = p2p_cover_rate(&tcp);
    uint32_t pb_tcp = p2p_cover_projected_bytes_per_min(&tcp);
    CHECK(r_tcp == tt, "TCP 空闲时覆盖速率等于其目标速率");
    CHECK(pb_tcp <= budget, "TCP 信道预计开销不超预算");

    /* 切换画像应即时生效 */
    p2p_cover_set_profile(&tcp, P2P_COVER_PROFILE_DNS);
    CHECK(p2p_cover_target_total(&tcp) == td, "切换画像后目标速率即时重算");

    /* 实测成本可覆盖画像默认值 */
    p2p_cover_set_measured_cost(&tcp, 1000u);
    CHECK(p2p_cover_target_total(&tcp) == budget / 1000u,
          "实测成本覆盖画像默认值");
    CHECK(p2p_cover_set_measured_cost(&tcp, 0u) != 0, "成本为 0 被拒");
}

/* ---- 4. 无下溢：数据远超预算 ---- */
static void t_no_underflow(void) {
    p2p_cover_t c;
    uint32_t budget = budget_for(P2P_COVER_PROFILE_DIRECT, 600);
    p2p_cover_init(&c, P2P_COVER_PROFILE_DIRECT, budget, 0);

    uint64_t t = 0;
    for (int i = 0; i < 10; i++) {
        t += WIN;
        p2p_cover_note_data(&c, 5000, t);   /* 瞬时 60000/min，远超预算 */
    }
    uint32_t r = p2p_cover_rate(&c);
    printf("      数据远超预算时覆盖速率=%u\n", r);
    CHECK(r == P2P_COVER_DEFAULT_MIN, "数据超预算时覆盖饱和到下限，未下溢");
    CHECK(r < 1000, "覆盖速率未变成巨大正数（无符号下溢已防住）");
}

/* ---- 5. 禁用与边界 ---- */
static void t_bounds(void) {
    p2p_cover_t c;
    uint32_t budget = budget_for(P2P_COVER_PROFILE_DIRECT, 600);

    /* 预算 0 => 明确禁用，不是降到下限 */
    p2p_cover_init(&c, P2P_COVER_PROFILE_DIRECT, 0, 0);
    CHECK(p2p_cover_rate(&c) == 0, "预算为 0 时覆盖被禁用（不是降到下限）");
    uint32_t seed = 12345;
    CHECK(p2p_cover_due(&c, &seed, 100000, NULL) == 0, "被禁用时 due 恒为 0");

    /* 上下限 clamp */
    p2p_cover_init(&c, P2P_COVER_PROFILE_DIRECT, budget, 0);
    CHECK(p2p_cover_set_bounds(&c, 10, 20) == 0, "设置上下限成功");
    CHECK(p2p_cover_rate(&c) == 20, "空闲时取上限 20");
    CHECK(p2p_cover_set_bounds(&c, 20, 10) != 0, "min>max 被拒");

    /* min=max=0 => 覆盖为 0（显式关闭，区别于预算 0 的语义由调用方掌握） */
    p2p_cover_set_bounds(&c, 0, 0);
    CHECK(p2p_cover_rate(&c) == 0, "上下限均为 0 时覆盖为 0");

    /* 参数校验 */
    CHECK(p2p_cover_init(NULL, 0, budget, 0) != 0, "空指针 init 被拒");
    CHECK(p2p_cover_init(&c, 99, budget, 0) != 0, "非法画像被拒");
    CHECK(p2p_cover_note_data(&c, 0, 0) != 0, "n_cells=0 被拒");
}

/* ---- 6. 时间回拨安全 ---- */
static void t_time_rewind(void) {
    p2p_cover_t c;
    uint32_t budget = budget_for(P2P_COVER_PROFILE_DIRECT, 600);
    p2p_cover_init(&c, P2P_COVER_PROFILE_DIRECT, budget, 0);

    p2p_cover_note_data(&c, 30, WIN);
    uint32_t before = p2p_cover_rate(&c);

    /* 时间倒流：不应清零、不应突刺、不应崩溃 */
    p2p_cover_note_data(&c, 30, 1000ull);
    uint32_t after = p2p_cover_rate(&c);
    printf("      回拨前=%u 回拨后=%u\n", before, after);
    CHECK(after <= before, "时间回拨不使覆盖速率突刺上升");
    CHECK(after >= P2P_COVER_DEFAULT_MIN, "时间回拨后覆盖仍在合法区间");
}

/* ---- 7. due 判决的随机性与计数 ---- */
static void t_due(void) {
    p2p_cover_t c;
    uint32_t budget = budget_for(P2P_COVER_PROFILE_DIRECT, 600);
    p2p_cover_init(&c, P2P_COVER_PROFILE_DIRECT, budget, 0);

    /* 速率 600/min => 期望间隔 100ms；空闲 1000ms 应大概率触发 */
    uint32_t seed = 0x12345678u;
    int due = 0;
    for (int i = 0; i < 50; i++) {
        uint32_t d = 0;
        if (p2p_cover_due(&c, &seed, 1000u, &d)) due++;
    }
    printf("      50 次判决中触发 %d 次（概率型，非必然）\n", due);
    CHECK(due > 0, "空闲足够久时覆盖会触发");
    CHECK(due < 50, "判决含随机性（不是每次必发）");
    CHECK(c.total_cover_cells == (uint32_t)due, "覆盖计数与实际触发次数一致");

    /* 空闲不足期望间隔 => 不触发 */
    p2p_cover_set_bounds(&c, 1, 60);   /* 60/min => 期望间隔 1000ms */
    seed = 0xABCDEFu;
    int due_early = 0;
    for (int i = 0; i < 50; i++) {
        if (p2p_cover_due(&c, &seed, 10u, NULL)) due_early++;
    }
    CHECK(due_early == 0, "空闲不足期望间隔时不触发");

    /* seed=0 是不动点，必须被内部修正（否则"随机"退化成恒定） */
    p2p_cover_set_bounds(&c, P2P_COVER_DEFAULT_MIN, P2P_COVER_DEFAULT_MAX);
    seed = 0;
    int d0 = p2p_cover_due(&c, &seed, 100000u, NULL);
    CHECK(seed != 0, "seed 为 0 时被内部修正（避免不动点）");
    (void)d0;
}

int main(void) {
    printf("=== test_cover ===\n");
    t_adaptive();
    t_decorrelate();
    t_channel_cost();
    t_no_underflow();
    t_bounds();
    t_time_rewind();
    t_due();
    printf("=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
