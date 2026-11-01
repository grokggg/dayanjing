/*
 * DAYANJING v4 — 14_p2p/src/mix.c
 *
 * 混时序：时间片内跨流交错 + 恒定输出速率。
 * 设计说明见 include/p2p_mix.h。
 *
 * 本层不实现任何密码学：信元加解密仍是 p2p_cell 的职责，
 * 这里只决定"什么时候发、按什么顺序发、发多少个"。
 */

#include "p2p_mix.h"

#include <string.h>

const char *p2p_mix_errstr(int e) {
    switch (e) {
        case P2P_MIX_OK:        return "ok";
        case P2P_MIX_ERR_ARG:   return "invalid argument";
        case P2P_MIX_ERR_FULL:  return "queue full (backpressure)";
        case P2P_MIX_ERR_LEN:   return "output buffer too small";
        default:                return "unknown";
    }
}

static uint32_t mix_rand(p2p_mix_t *mx) {
    uint32_t x = mx->s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    mx->s = x;
    return x;
}

int p2p_mix_init(p2p_mix_t *mx, uint32_t seed, uint32_t period_ms,
                 uint32_t batch, uint32_t now_ms) {
    if (!mx) return P2P_MIX_ERR_ARG;
    if (period_ms == 0 || batch == 0) return P2P_MIX_ERR_ARG;
    if (batch > P2P_MIX_MAX_BATCH) return P2P_MIX_ERR_ARG;

    memset(mx, 0, sizeof *mx);
    mx->s = seed ? seed : 0x9e3779b9u;
    mx->period_ms = period_ms;
    mx->batch = batch;
    mx->next_flush_ms = now_ms + period_ms;
    return P2P_MIX_OK;
}

/* 流内序号：按 stream 取模维护，避免为每条流单独建表 */
static uint32_t next_ord(p2p_mix_t *mx, uint32_t stream) {
    uint32_t idx = stream % P2P_MIX_MAXQ;
    return mx->ord_next[idx]++;
}

int p2p_mix_enqueue(p2p_mix_t *mx, uint32_t stream,
                    const uint8_t cell[P2P_CELL_WIRE]) {
    if (!mx || !cell) return P2P_MIX_ERR_ARG;
    if (mx->n >= P2P_MIX_MAXQ) return P2P_MIX_ERR_FULL;

    p2p_mix_item_t *it = &mx->q[mx->n];
    it->stream = stream;
    it->ord    = next_ord(mx, stream);
    memcpy(it->cell, cell, P2P_CELL_WIRE);
    mx->n++;
    return P2P_MIX_OK;
}

int p2p_mix_due(const p2p_mix_t *mx, uint32_t now_ms) {
    if (!mx) return 0;
    return (now_ms >= mx->next_flush_ms) ? 1 : 0;
}

int p2p_mix_stats(const p2p_mix_t *mx, int *n_queued, int *n_streams) {
    if (!mx) return P2P_MIX_ERR_ARG;
    if (n_queued) *n_queued = mx->n;

    if (n_streams) {
        uint32_t seen[P2P_MIX_MAXQ];
        int ns = 0;
        for (int i = 0; i < mx->n; i++) {
            int dup = 0;
            for (int j = 0; j < ns; j++)
                if (seen[j] == mx->q[i].stream) { dup = 1; break; }
            if (!dup && ns < P2P_MIX_MAXQ) seen[ns++] = mx->q[i].stream;
        }
        *n_streams = ns;
    }
    return P2P_MIX_OK;
}

/*
 * 出片核心：
 *   重复「随机挑一条还有积压的流 -> 取该流队首(ord 最小) -> 移除」
 * 这样跨流顺序被打乱，但每条流内部的 ord 单调性被保留 ——
 * 信元层 IV 严格递增的要求得以满足。
 */
int p2p_mix_flush(p2p_mix_t *mx, uint32_t now_ms, p2p_cell_ctx_t *cc,
                  p2p_mix_out_t *out, size_t cap_items,
                  size_t *n_out, size_t *n_real) {
    if (!mx || !out || !n_out) return P2P_MIX_ERR_ARG;
    if (cap_items < (size_t)mx->batch) return P2P_MIX_ERR_LEN;
    if (!cc) return P2P_MIX_ERR_ARG;

    size_t emitted = 0, real = 0;

    for (uint32_t i = 0; i < mx->batch; i++) {
        if (mx->n == 0) {
            /* 真实数据不足 -> 补覆盖信元，保持每片输出量恒定 */
            int rc = p2p_cell_pack_cover(cc, out[emitted].cell);
            if (rc != P2P_CELL_OK) return rc;
            out[emitted].stream = P2P_MIX_STREAM_COVER;
            emitted++;
            continue;
        }

        /* 收集当前还有积压的流 */
        uint32_t streams[P2P_MIX_MAXQ];
        int ns = 0;
        for (int j = 0; j < mx->n; j++) {
            int dup = 0;
            for (int k = 0; k < ns; k++)
                if (streams[k] == mx->q[j].stream) { dup = 1; break; }
            if (!dup) streams[ns++] = mx->q[j].stream;
        }

        /* 随机挑一条流 */
        uint32_t pick = streams[(size_t)(mix_rand(mx) % (uint32_t)ns)];

        /* 取该流 ord 最小的那个（即队首） */
        int best = -1;
        for (int j = 0; j < mx->n; j++) {
            if (mx->q[j].stream != pick) continue;
            if (best < 0 || mx->q[j].ord < mx->q[best].ord) best = j;
        }

        memcpy(out[emitted].cell, mx->q[best].cell, P2P_CELL_WIRE);
        out[emitted].stream = mx->q[best].stream;
        /* 移除：用末位填补（顺序由 ord 保证，不依赖数组位置） */
        mx->q[best] = mx->q[mx->n - 1];
        mx->n--;
        emitted++;
        real++;
    }

    /*
     * 推进下一片时刻。若积压导致严重落后（now 已远超下一片），
     * 直接跳到现在 + 一个片长，避免"补片风暴"把欠的片一次性发出。
     */
    uint32_t next = mx->next_flush_ms + mx->period_ms;
    if (now_ms > next + mx->period_ms) next = now_ms + mx->period_ms;
    mx->next_flush_ms = next;

    *n_out = emitted;
    if (n_real) *n_real = real;
    return P2P_MIX_OK;
}
