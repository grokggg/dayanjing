/*
 * DAYANJING v4 — 14_p2p/src/mix_cover.c
 *
 * 自适应覆盖流量 -> 真实数据面的驱动层。
 *
 * 背景：cover.c 只回答"此刻应该以多快的速率发覆盖信元"，它不碰信元、
 * 不碰队列。此前没有任何代码把这个速率接到真实发送上 —— 覆盖流量是
 * "算出来了但没人发"。本文件补上这一段。
 *
 * 为什么必须单独成层，而不是塞进 mix.c 的 p2p_mix_flush：
 *   p2p_mix_flush 的语义是"每片恒定输出 batch 个信元"，覆盖信元只是
 *   用来**补满** batch 的填充物。这个语义下总速率恒等于 batch/片长，
 *   与信道成本、字节预算、实测数据速率全都无关。自适应覆盖要做的是
 *   "总速率被预算约束住"，两者是不同的控制律，混在一个函数里必然有一方
 *   被另一方破坏。故新增 p2p_mix_flush_adaptive，原 flush 保持不变。
 *
 * 三条硬规则
 *   1) 覆盖信元必须用与数据信元**同一个 cell 上下文**封装。
 *      信元层 IV = pfx || counter，counter 由接收方现算。用独立上下文
 *      另造覆盖信元会让接收方计数器错位，后续数据全线解不开 —— 表现为
 *      AUTH，而真实原因是"覆盖流量开了一条旁路"。
 *   2) note_data 必须在**发送之后**调用，且时间基准与 tick 一致。
 *      在判决前记账等于用预测值压低覆盖，数据突发时会同时出现"数据已发
 *      但覆盖没降"，总速率冲出预算。
 *   3) 单上下文下**不能**把覆盖信元插到已排队的数据信元前面。
 *      信元层 counter 严格递增，接收方按到达顺序校验；而数据信元是在
 *      enqueue 时就已封装（counter 已定），覆盖信元是出片时才封装。
 *      若把后封装的覆盖信元排在先封装的数据信元之前，接收方会看到
 *      counter 回退 -> P2P_CELL_ERR_REPLAY -> 全线解不开。
 *      本文件因此按"先数据、后覆盖"输出，且**封装顺序即发送顺序**。
 *
 *      跨流交错是 p2p_mix_flush 的职责，且它要求每条流（含覆盖流）各有
 *      独立上下文 —— 那是多路链路的场景，不是单链路自适应覆盖的场景。
 *      两者不可混用：试图在单上下文里做交错，是本次测试实际抓出来的缺陷。
 *
 * 时间全部由调用方注入（now_ms），本文件不读系统时钟。
 */

#include "p2p_mix.h"

#include <string.h>

/* 本片内允许发送的最大信元数（数据 + 覆盖），防止单片无限膨胀 */
#define MIXCOVER_MAX_PER_TICK  64u

int p2p_mix_flush_adaptive(p2p_mix_t *mx, p2p_cover_t *cov, uint32_t now_ms,
                           p2p_cell_ctx_t *cc, p2p_mix_out_t *out,
                           size_t cap_items, size_t *n_out,
                           size_t *n_real, size_t *n_cover) {
    if (!mx || !out || !n_out || !cc) return P2P_MIX_ERR_ARG;
    if (!cov) return P2P_MIX_ERR_ARG;
    if (cap_items == 0) return P2P_MIX_ERR_LEN;

    /* 本片实际经过的时间。now 落后于上一片时刻时按一个片长计，
       避免 elapsed 为 0 导致覆盖永远算不出来（无符号下溢的巨大值更糟）。 */
    uint32_t last_ms = mx->next_flush_ms - mx->period_ms;
    uint32_t elapsed_ms = (now_ms >= last_ms) ? (now_ms - last_ms)
                                              : mx->period_ms;
    if (elapsed_ms == 0) elapsed_ms = mx->period_ms;

    /* 1) 先排真实数据。上限 batch：这是背压边界，不是速率目标。 */
    size_t n_r = 0;
    p2p_mix_out_t real[P2P_MIX_MAX_BATCH];
    while (n_r < (size_t)mx->batch && mx->n > 0) {
        uint32_t streams[P2P_MIX_MAXQ];
        int ns = 0;
        for (int j = 0; j < mx->n; j++) {
            int dup = 0;
            for (int k = 0; k < ns; k++)
                if (streams[k] == mx->q[j].stream) { dup = 1; break; }
            if (!dup) streams[ns++] = mx->q[j].stream;
        }
        if (ns == 0) break;

        uint32_t x = mx->s;
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        mx->s = x;
        uint32_t pick = streams[(size_t)(x % (uint32_t)ns)];

        int best = -1;
        for (int j = 0; j < mx->n; j++) {
            if (mx->q[j].stream != pick) continue;
            if (best < 0 || mx->q[j].ord < mx->q[best].ord) best = j;
        }

        real[n_r].stream = mx->q[best].stream;
        memcpy(real[n_r].cell, mx->q[best].cell, P2P_CELL_WIRE);
        mx->q[best] = mx->q[mx->n - 1];
        mx->n--;
        n_r++;
    }

    /* 2) 发送之后记账（规则 2）。n_cells 为 0 时 note_data 视为无效调用，
          此处显式跳过，避免用 0 去推进窗口。 */
    if (n_r > 0) {
        int rc = p2p_cover_note_data(cov, (uint32_t)n_r,
                                     (uint64_t)now_ms * 1000ull);
        if (rc != P2P_COVER_OK) return P2P_MIX_ERR_ARG;
    }

    /* 3) 推进窗口并取当前覆盖速率 */
    p2p_cover_tick(cov, (uint64_t)now_ms * 1000ull);

    /*
     * 4) 本片应发几个覆盖信元：速率(信元/分钟) * 经过分钟数。
     *    用 64 位先乘后除，避免 rate*elapsed 在 uint32 下溢出
     *    （600 信元/分钟 * 60000ms 就到 3600 万，再乘就爆了）。
     *    余数不做概率补偿 —— 覆盖信元宁少勿多，超预算比少发更糟。
     */
    /*
     * 经 p2p_cover_take_due 折算：内部带余量累积，低速下不会因每次取整
     * 为 0 而永远发不出覆盖信元（见 p2p_cover.h 的 credit_milli 说明）。
     */
    uint32_t due = 0;
    int rc_due = p2p_cover_take_due(cov, elapsed_ms, &due);
    if (rc_due != P2P_COVER_OK) return P2P_MIX_ERR_ARG;
    size_t n_c = (size_t)due;

    /* 5) 容量约束：cap_items、单片上界，以及输出数组本身 */
    size_t total = n_r + n_c;
    if (total > cap_items) {
        /* 先砍覆盖，真实数据优先 —— 覆盖是可选的，数据丢了要重传 */
        if (n_c > total - cap_items) n_c -= (total - cap_items);
        else n_c = 0;
        total = n_r + n_c;
        if (total > cap_items) n_r = cap_items, n_c = 0, total = n_r;
    }
    if (total > MIXCOVER_MAX_PER_TICK) {
        size_t over = total - MIXCOVER_MAX_PER_TICK;
        if (n_c > over) n_c -= over;
        else { n_r -= (over - n_c); n_c = 0; }
        total = n_r + n_c;
    }

    /*
     * 6) 输出：先数据、后覆盖（规则 3）。
     *    数据信元在 enqueue 时已定 counter，覆盖信元在此时才封装，
     *    因此覆盖必须排在所有已封装数据之后 —— 否则接收方看到 counter
     *    回退，直接 P2P_CELL_ERR_REPLAY。
     */
    size_t ri = 0, ci = 0, emitted = 0;
    for (; ri < n_r; ri++) {
        out[emitted++] = real[ri];
    }
    for (; ci < n_c; ci++) {
        int rc = p2p_cell_pack_cover(cc, out[emitted].cell);
        if (rc != P2P_CELL_OK) return rc;
        out[emitted].stream = P2P_MIX_STREAM_COVER;
        emitted++;
    }

    /* 7) 推进下一片时刻（与 mix.c 同律，落后太多时跳到现在，不补片风暴） */
    uint32_t next = mx->next_flush_ms + mx->period_ms;
    if (now_ms > next + mx->period_ms) next = now_ms + mx->period_ms;
    mx->next_flush_ms = next;

    *n_out = emitted;
    if (n_real)  *n_real  = ri;
    if (n_cover) *n_cover = ci;
    return P2P_MIX_OK;
}

/*
 * 观察用：本片若在此时发送，预计一分钟的线上总字节数。
 * 只是把 cover 的记账转发出来，方便调用方在不发包的情况下先判断是否超预算。
 */
uint32_t p2p_mix_projected_bytes_per_min(const p2p_cover_t *cov) {
    return p2p_cover_projected_bytes_per_min((p2p_cover_t *)cov);
}
