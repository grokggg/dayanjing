/*
 * DAYANJING v4 — 14_p2p/src/cover.c
 *
 * 自适应覆盖流量实现。设计依据见 include/p2p_cover.h。
 *
 * 实现要点：
 *   1) 所有速率用 uint32「信元/分钟」，EWMA 内部 x16 定点，避免浮点
 *   2) 所有减法先做饱和判断，绝不产生无符号下溢（下溢会变成巨大正数，
 *      直接把覆盖速率打到上限 —— 表现为"越忙发越多"，正好是反效果）
 *   3) 时间全部由调用方注入，本文件不出现任何 gettimeofday/clock_gettime
 */

#include "p2p_cover.h"

#include <stddef.h>

#define COVER_OK            0
#define COVER_ERR_ARG      -1

/* EWMA 分子权重：new = (old * (W-1) + inst) / W */
#define COVER_EWMA_W        4u

static uint32_t profile_cost(uint32_t profile) {
    switch (profile) {
        case P2P_COVER_PROFILE_ICMP:   return P2P_COVER_COST_ICMP;
        case P2P_COVER_PROFILE_DNS:    return P2P_COVER_COST_DNS;
        case P2P_COVER_PROFILE_DIRECT: return P2P_COVER_COST_DIRECT;
        default:                       return P2P_COVER_COST_DIRECT;
    }
}

/* 窗口 -> 每分钟的倍率。窗口 5s 时为 12。先判零。 */
static uint32_t window_factor(uint64_t window_us) {
    if (window_us == 0) return 0;
    uint32_t per_min = (uint32_t)(60000000ull / window_us);
    return per_min == 0 ? 1u : per_min;
}

const char *p2p_cover_errstr(int e) {
    switch (e) {
        case COVER_OK:        return "ok";
        case COVER_ERR_ARG:   return "invalid argument";
        default:              return "unknown";
    }
}

int p2p_cover_init(p2p_cover_t *cov, uint32_t profile,
                   uint32_t budget_bytes_per_min, uint64_t now_us) {
    if (!cov) return COVER_ERR_ARG;
    if (profile > P2P_COVER_PROFILE_DNS) return COVER_ERR_ARG;

    cov->budget_bytes_per_min = budget_bytes_per_min;
    cov->min_cover_per_min    = P2P_COVER_DEFAULT_MIN;
    cov->max_cover_per_min    = P2P_COVER_DEFAULT_MAX;
    cov->profile              = profile;
    cov->bytes_per_cell       = profile_cost(profile);
    cov->ewma_data_x16        = 0;
    cov->win_start_us         = now_us;
    cov->win_data_cells       = 0;
    cov->last_rate            = 0;
    cov->total_cover_cells    = 0;
    cov->credit_milli         = 0;
    cov->inited               = 1;
    return COVER_OK;
}

int p2p_cover_set_profile(p2p_cover_t *cov, uint32_t profile) {
    if (!cov || !cov->inited) return COVER_ERR_ARG;
    if (profile > P2P_COVER_PROFILE_DNS) return COVER_ERR_ARG;
    cov->profile        = profile;
    cov->bytes_per_cell = profile_cost(profile);
    return COVER_OK;
}

int p2p_cover_set_measured_cost(p2p_cover_t *cov, uint32_t bytes_per_cell) {
    if (!cov || !cov->inited) return COVER_ERR_ARG;
    if (bytes_per_cell == 0) return COVER_ERR_ARG;
    cov->bytes_per_cell = bytes_per_cell;
    return COVER_OK;
}

int p2p_cover_set_budget(p2p_cover_t *cov, uint32_t budget_bytes_per_min) {
    if (!cov || !cov->inited) return COVER_ERR_ARG;
    cov->budget_bytes_per_min = budget_bytes_per_min;
    return COVER_OK;
}

int p2p_cover_set_bounds(p2p_cover_t *cov, uint32_t min_per_min,
                         uint32_t max_per_min) {
    if (!cov || !cov->inited) return COVER_ERR_ARG;
    if (min_per_min > max_per_min) return COVER_ERR_ARG;
    cov->min_cover_per_min = min_per_min;
    cov->max_cover_per_min = max_per_min;
    return COVER_OK;
}

int p2p_cover_note_data(p2p_cover_t *cov, uint32_t n_cells, uint64_t now_us) {
    if (!cov || !cov->inited || n_cells == 0) return COVER_ERR_ARG;
    /* 先推进窗口，避免跨窗口的数据被记到旧窗口里 */
    (void)p2p_cover_tick(cov, now_us);
    cov->win_data_cells += n_cells;
    return COVER_OK;
}

int p2p_cover_tick(p2p_cover_t *cov, uint64_t now_us) {
    if (!cov || !cov->inited) return COVER_ERR_ARG;

    if (now_us < cov->win_start_us) {
        /* 时间回拨：不越界推进，也不清零（清零会让覆盖速率突刺到上限） */
        return 0;
    }

    uint64_t elapsed = now_us - cov->win_start_us;
    if (elapsed < P2P_COVER_WINDOW_US) return 0;

    uint32_t factor = window_factor(elapsed);
    uint64_t inst_rate = (uint64_t)cov->win_data_cells * factor;
    if (inst_rate > 0xFFFFFFFFull / 16ull) inst_rate = 0xFFFFFFFFull / 16ull;
    uint32_t inst_x16 = (uint32_t)(inst_rate * 16u);

    /* new = (old * (W-1) + inst) / W，全程 x16 定点 */
    uint64_t acc = (uint64_t)cov->ewma_data_x16 * (COVER_EWMA_W - 1u) + inst_x16;
    cov->ewma_data_x16 = (uint32_t)(acc / COVER_EWMA_W);

    cov->win_start_us   = now_us;
    cov->win_data_cells = 0;
    return 1;
}

uint32_t p2p_cover_data_rate(p2p_cover_t *cov) {
    if (!cov || !cov->inited) return 0;
    return cov->ewma_data_x16 / 16u;
}

uint32_t p2p_cover_target_total(p2p_cover_t *cov) {
    if (!cov || !cov->inited) return 0;
    if (cov->budget_bytes_per_min == 0) return 0;
    if (cov->bytes_per_cell == 0) return 0;
    uint32_t t = cov->budget_bytes_per_min / cov->bytes_per_cell;
    return t;
}

uint32_t p2p_cover_rate(p2p_cover_t *cov) {
    if (!cov || !cov->inited) return 0;

    /* 预算为 0 => 明确禁用覆盖（不是"降到下限"） */
    if (cov->budget_bytes_per_min == 0) {
        cov->last_rate = 0;
        return 0;
    }

    uint32_t target = p2p_cover_target_total(cov);
    uint32_t data   = p2p_cover_data_rate(cov);

    uint32_t rate;
    if (target > data) {
        rate = target - data;
    } else {
        /* 饱和：数据已超预算，覆盖降到下限而非下溢 */
        rate = 0;
    }

    if (rate < cov->min_cover_per_min) rate = cov->min_cover_per_min;
    if (rate > cov->max_cover_per_min) rate = cov->max_cover_per_min;

    cov->last_rate = rate;
    return rate;
}

int p2p_cover_take_due(p2p_cover_t *cov, uint32_t elapsed_ms,
                       uint32_t *n_cells) {
    if (!cov || !n_cells) return COVER_ERR_ARG;

    uint32_t rate = p2p_cover_rate(cov);
    if (rate == 0) {            /* 预算为 0：明确禁用，余量也要清零 */
        cov->credit_milli = 0;
        *n_cells = 0;
        return COVER_OK;
    }

    /*
     * 毫信元 = rate * elapsed_ms * 1000 / 60000。
     * 全部用 64 位：600 * 60000 * 1000 = 3.6e10，远超 uint32 上限。
     */
    uint64_t add = ((uint64_t)rate * (uint64_t)elapsed_ms * 1000ull) / 60000ull;
    uint64_t total = add + (uint64_t)cov->credit_milli;

    uint32_t n = (uint32_t)(total / 1000ull);
    cov->credit_milli = (uint32_t)(total % 1000ull);

    /* 上限保护：长时间未刷新时不得一次性喷出大量覆盖信元 */
    if (n > P2P_COVER_DEFAULT_MAX) n = P2P_COVER_DEFAULT_MAX;

    *n_cells = n;
    return COVER_OK;
}

int p2p_cover_due(p2p_cover_t *cov, uint32_t *seed, uint32_t idle_ms,
                  uint32_t *out_delay) {
    if (!cov || !cov->inited || !seed) return 0;

    uint32_t rate = p2p_cover_rate(cov);
    if (rate == 0) return 0;

    uint32_t expected = 60000u / rate;
    if (expected == 0) expected = 1;
    if (idle_ms < expected) return 0;

    /* xorshift32：状态为 0 是不动点，会让"随机"退化成恒定，必须排除 */
    uint32_t x = *seed;
    if (x == 0) x = 0x9E3779B9u;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    *seed = x;

    uint32_t excess = idle_ms / expected;
    uint32_t prob = excess > 4u ? 80u : 20u * (excess > 0u ? excess : 1u);
    if (out_delay) *out_delay = x % (expected / 2u + 1u);

    if (x % 100u < prob) {
        cov->total_cover_cells++;
        return 1;
    }
    return 0;
}

uint32_t p2p_cover_projected_bytes_per_min(p2p_cover_t *cov) {
    if (!cov || !cov->inited) return 0;
    uint64_t total_cells = (uint64_t)p2p_cover_data_rate(cov)
                         + (uint64_t)cov->last_rate;
    uint64_t bytes = total_cells * (uint64_t)cov->bytes_per_cell;
    if (bytes > 0xFFFFFFFFull) return 0xFFFFFFFFu;
    return (uint32_t)bytes;
}
