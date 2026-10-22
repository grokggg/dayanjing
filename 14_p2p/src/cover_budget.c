/*
 * DAYANJING v4 — 14_p2p/src/cover_budget.c
 *
 * 覆盖预算按真实带宽自适应。设计依据见 include/p2p_cover_budget.h。
 *
 * 实现要点：
 *   1) 全程 uint64 中间量，最后钳到 uint32；bw_kbps 先钳到
 *      P2P_COVER_BUDGET_BW_CLAMP_KBPS，既防溢出也防探测异常值
 *   2) 运算顺序固定为 *7500 再套 duty —— 反序会让小带宽归零
 *   3) bw_kbps == 0 一律走 UNKNOWN，绝不修改既有预算
 *   4) 时间由调用方注入，本文件不出现任何 gettimeofday/clock_gettime
 */

#include "p2p_cover_budget.h"

#include <stddef.h>

#define B_OK        P2P_COVER_BUDGET_OK
#define B_ERR_ARG   P2P_COVER_BUDGET_ERR_ARG
#define B_UNKNOWN   P2P_COVER_BUDGET_UNKNOWN
#define B_CONFLICT  P2P_COVER_BUDGET_CONFLICT

const char *p2p_cover_budget_errstr(int e) {
    switch (e) {
        case B_OK:       return "ok";
        case B_ERR_ARG:  return "invalid argument";
        case B_UNKNOWN:  return "bandwidth unknown; budget unchanged";
        case B_CONFLICT: return "budget too low to hold max-silence bound";
        default:         return "unknown";
    }
}

uint32_t p2p_cover_budget_from_kbps(uint32_t bw_kbps, uint32_t duty_ppm) {
    if (bw_kbps == 0 || duty_ppm == 0) return 0;

    /* 钳制探测异常值，同时保证后续乘法不溢出 uint64 */
    if (bw_kbps > P2P_COVER_BUDGET_BW_CLAMP_KBPS)
        bw_kbps = P2P_COVER_BUDGET_BW_CLAMP_KBPS;

    /*
     * 顺序不可换：先 /1e6 会让小带宽归零（bw=1, duty=50000 -> 0）。
     * 故 *7500 之后再套 duty。
     *
     *   最大中间量：1e8 * 7500 = 7.5e11；* 1e6 = 7.5e17 < 1.8e19（uint64）
     */
    uint64_t v = (uint64_t)bw_kbps * 7500ull;
    v = v * (uint64_t)duty_ppm / 1000000ull;

    if (v > P2P_COVER_BUDGET_CAP_BYTES_PER_MIN)
        v = P2P_COVER_BUDGET_CAP_BYTES_PER_MIN;

    return (uint32_t)v;
}

int p2p_cover_budget_init(p2p_cover_budget_t *b, uint32_t duty_ppm,
                          uint64_t now_us) {
    if (!b) return B_ERR_ARG;

    if (duty_ppm == 0) duty_ppm = P2P_COVER_BUDGET_DEFAULT_DUTY_PPM;
    if (duty_ppm > 1000000u) duty_ppm = 1000000u;

    b->duty_ppm             = duty_ppm;
    b->min_link_kbps        = 0;
    b->n_hops               = 0;
    b->budget_bytes_per_min = 0;
    b->probed_at_us         = now_us;
    b->ttl_us               = P2P_COVER_BUDGET_DEFAULT_TTL_US;
    b->known                = 0;
    b->conflict             = 0;
    b->inited               = 1;
    return B_OK;
}

int p2p_cover_budget_set_duty(p2p_cover_budget_t *b, uint32_t duty_ppm) {
    if (!b || !b->inited) return B_ERR_ARG;
    if (duty_ppm == 0) return B_ERR_ARG;
    if (duty_ppm > 1000000u) duty_ppm = 1000000u;
    b->duty_ppm = duty_ppm;
    return B_OK;
}

int p2p_cover_budget_set_ttl(p2p_cover_budget_t *b, uint64_t ttl_us) {
    if (!b || !b->inited) return B_ERR_ARG;
    b->ttl_us = ttl_us;   /* 0 = 永不过期 */
    return B_OK;
}

int p2p_cover_budget_reset(p2p_cover_budget_t *b, uint64_t now_us) {
    if (!b || !b->inited) return B_ERR_ARG;
    b->min_link_kbps        = 0;
    b->n_hops               = 0;
    b->budget_bytes_per_min = 0;
    b->probed_at_us         = now_us;
    b->known                = 0;
    b->conflict             = 0;
    return B_OK;
}

int p2p_cover_budget_note_hop(p2p_cover_budget_t *b, uint32_t bw_kbps,
                              uint64_t now_us) {
    if (!b || !b->inited) return B_ERR_ARG;

    b->n_hops++;

    /*
     * bw == 0：探测失败。记 known 不置位（若此前无有效值），
     * 但**不动** min_link_kbps —— 一次失败不得把预算拉到 0。
     */
    if (bw_kbps == 0) return B_UNKNOWN;

    if (bw_kbps > P2P_COVER_BUDGET_BW_CLAMP_KBPS)
        bw_kbps = P2P_COVER_BUDGET_BW_CLAMP_KBPS;

    if (!b->known || bw_kbps < b->min_link_kbps) {
        b->min_link_kbps = bw_kbps;
        b->known         = 1;
        b->probed_at_us  = now_us;
    }
    return B_OK;
}

int p2p_cover_budget_derive(p2p_cover_budget_t *b) {
    if (!b || !b->inited) return B_ERR_ARG;
    if (!b->known || b->min_link_kbps == 0) return B_UNKNOWN;

    b->budget_bytes_per_min =
        p2p_cover_budget_from_kbps(b->min_link_kbps, b->duty_ppm);
    return B_OK;
}

uint32_t p2p_cover_budget_get(const p2p_cover_budget_t *b) {
    if (!b || !b->inited) return 0;
    return b->budget_bytes_per_min;
}

int p2p_cover_budget_apply(p2p_cover_budget_t *b, p2p_cover_t *cov) {
    if (!b || !cov) return B_ERR_ARG;
    if (!b->inited || !cov->inited) return B_ERR_ARG;

    int rc = p2p_cover_budget_derive(b);
    if (rc != B_OK) return rc;   /* UNKNOWN：不修改既有预算 */

    uint32_t budget = b->budget_bytes_per_min;
    if (p2p_cover_set_budget(cov, budget) != P2P_COVER_OK) return B_ERR_ARG;

    /*
     * 冲突判定：预算是否撑得住 min_cover。
     * min_cover 是需求（信元/分钟），bytes_per_cell 是信道成本；
     * 两者相乘即维持该速率所需的字节预算。
     */
    uint32_t need = 0;
    if (cov->bytes_per_cell != 0) {
        uint64_t n = (uint64_t)cov->min_cover_per_min
                   * (uint64_t)cov->bytes_per_cell;
        need = n > 0xFFFFFFFFull ? 0xFFFFFFFFu : (uint32_t)n;
    }

    b->conflict = (need > budget) ? 1 : 0;
    return b->conflict ? B_CONFLICT : B_OK;
}

uint32_t p2p_cover_budget_achievable_silence(const p2p_cover_budget_t *b,
                                             uint32_t bytes_per_cell) {
    if (!b || !b->inited) return P2P_COVER_BUDGET_SILENCE_NONE;
    if (bytes_per_cell == 0) return P2P_COVER_BUDGET_SILENCE_NONE;
    if (b->budget_bytes_per_min == 0) return P2P_COVER_BUDGET_SILENCE_NONE;

    /* 预算能支撑的覆盖速率（信元/分钟） */
    uint32_t rate = b->budget_bytes_per_min / bytes_per_cell;
    if (rate == 0) return P2P_COVER_BUDGET_SILENCE_NONE;

    /* 该速率对应的平均间隔即静默上界（毫秒） */
    uint32_t ms = 60000u / rate;
    return ms == 0 ? 1u : ms;
}

int p2p_cover_budget_stale(const p2p_cover_budget_t *b, uint64_t now_us) {
    if (!b || !b->inited) return 0;
    if (!b->known) return 0;              /* 没有实测值，谈不上陈旧 */
    if (b->ttl_us == 0) return 0;         /* 0 = 永不过期 */
    if (now_us < b->probed_at_us) return 0;  /* 时间回拨：不误判为陈旧 */
    return (now_us - b->probed_at_us) > b->ttl_us ? 1 : 0;
}
