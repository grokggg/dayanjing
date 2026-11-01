/*
 * DAYANJING v4 — 14_p2p/tests/test_mix.c
 *
 * 混时序验证：
 *   1. 每片输出项数恒定（batch），不足补覆盖、超出留队列
 *   2. 跨流位置被打乱（不同 seed 得到不同的流交替顺序）
 *   3. 流内顺序严格保持 —— 每条流是独立信元上下文，乱序会被判重放
 *   4. 队列满返回背压信号而非静默丢弃
 *
 * 注意：信元层 IV 是隐式计数器，所以"流"必须对应各自独立的连接/上下文。
 * 测试为每条流（含覆盖流）建立独立的收发上下文，模拟真实的多链路场景。
 */

#include "p2p_mix.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;
static void check(int cond, const char *name) {
    if (cond) { g_pass++; printf("[PASS] %s\n", name); }
    else      { g_fail++; printf("[FAIL] %s\n", name); }
}

#define NSTREAM 2

static uint8_t KS[NSTREAM][16], KR[NSTREAM][16];
static uint8_t KCS[16], KCR[16], PFX[8];

static void setup_keys(void) {
    for (int i = 0; i < NSTREAM; i++) {
        memset(KS[i], (uint8_t)(0x10 + i * 0x10), 16);
        memset(KR[i], (uint8_t)(0x11 + i * 0x10), 16);
    }
    memset(KCS, 0x31, sizeof KCS);
    memset(KCR, 0x32, sizeof KCR);
    memset(PFX, 0x41, sizeof PFX);
}

/* 用 "S<stream>-<seq>" 作为可识别载荷 */
static void mkpayload(uint32_t stream, int seq, uint8_t *out, size_t *len) {
    char buf[32];
    int n = snprintf(buf, sizeof buf, "S%u-%d", stream, seq);
    memcpy(out, buf, (size_t)n);
    *len = (size_t)n;
}

static int seq_of(const char *s, uint32_t *stream, int *seq) {
    if (s[0] != 'S') return 0;
    return sscanf(s + 1, "%u-%d", stream, seq) == 2;
}

int main(void) {
    setup_keys();

    p2p_cell_ctx_t s[NSTREAM], r[NSTREAM], sc, rc;
    for (int i = 0; i < NSTREAM; i++) {
        p2p_cell_init(&s[i], KS[i], KR[i], PFX);
        p2p_cell_init(&r[i], KR[i], KS[i], PFX);
    }
    p2p_cell_init(&sc, KCS, KCR, PFX);
    p2p_cell_init(&rc, KCR, KCS, PFX);

    uint8_t cell[P2P_CELL_WIRE];
    uint8_t pl[32];
    size_t  pll;

    /* ---- 1. 到期判定 ---- */
    p2p_mix_t mx;
    check(p2p_mix_init(&mx, 1, 100, 5, 1000) == P2P_MIX_OK, "init");
    check(p2p_mix_due(&mx, 1099) == 0, "差 1ms 仍不到期");
    check(p2p_mix_due(&mx, 1100) == 1, "到片长即到期");

    /* ---- 2. 恒定输出 + 覆盖填充 ---- */
    mkpayload(1, 0, pl, &pll);
    p2p_cell_pack(&s[0], P2P_CELL_CMD_DATA, pl, pll, cell);
    check(p2p_mix_enqueue(&mx, 1, cell) == P2P_MIX_OK, "入队流1");
    mkpayload(2, 0, pl, &pll);
    p2p_cell_pack(&s[1], P2P_CELL_CMD_DATA, pl, pll, cell);
    check(p2p_mix_enqueue(&mx, 2, cell) == P2P_MIX_OK, "入队流2");

    int nq = -1, ns = -1;
    p2p_mix_stats(&mx, &nq, &ns);
    check(nq == 2 && ns == 2, "统计：2 个信元 / 2 条流");

    p2p_mix_out_t out[P2P_MIX_MAX_BATCH];
    size_t n_out = 0, n_real = 0;
    check(p2p_mix_flush(&mx, 1100, &sc, out, P2P_MIX_MAX_BATCH, &n_out, &n_real)
          == P2P_MIX_OK, "出片");
    check(n_out == 5, "每片恒输出 batch 个信元");
    check(n_real == 2, "其中真实 2 个，其余为覆盖");

    /* 覆盖信元应能被覆盖上下文正常解开为 PAD */
    {
        int cover_ok = 1, cover_n = 0;
        for (size_t i = 0; i < n_out; i++) {
            if (out[i].stream != P2P_MIX_STREAM_COVER) continue;
            cover_n++;
            uint8_t cmd = 0, d[600];
            size_t  dl = 0;
            if (p2p_cell_unpack(&rc, out[i].cell, &cmd, d, sizeof d, &dl) != P2P_CELL_OK
                || cmd != P2P_CELL_CMD_PAD)
                cover_ok = 0;
        }
        check(cover_n == 3, "补了 3 个覆盖信元");
        check(cover_ok, "覆盖信元合法（cmd=PAD，可解密）");
    }

    p2p_mix_stats(&mx, &nq, &ns);
    check(nq == 0, "出片后队列清空");

    /* ---- 3. 超量：只出 batch 个，其余留队 ---- */
    {
        p2p_mix_t m2;
        p2p_mix_init(&m2, 7, 100, 3, 2000);
        for (int i = 0; i < 5; i++) {
            mkpayload(1, i, pl, &pll);
            p2p_cell_pack(&s[0], P2P_CELL_CMD_DATA, pl, pll, cell);
            p2p_mix_enqueue(&m2, 1, cell);
        }
        size_t o1 = 0, rr1 = 0;
        p2p_mix_flush(&m2, 2100, &sc, out, P2P_MIX_MAX_BATCH, &o1, &rr1);
        check(o1 == 3 && rr1 == 3, "积压 5 个也只出 3 个（恒定速率）");
        p2p_mix_stats(&m2, &nq, &ns);
        check(nq == 2, "剩余 2 个留到下一片");
    }

    /* ---- 4. 跨流混序 + 流内保序 ---- */
    {
        char orders[8][64];
        int  distinct = 0;
        int  order_ok_all = 1;

        for (int t = 0; t < 8; t++) {
            p2p_mix_t m3;
            p2p_mix_init(&m3, (uint32_t)(t + 1) * 2654435761u, 100, 5, 3000);

            /* 重建每条流的收发上下文，计数器归零 */
            p2p_cell_ctx_t s3[NSTREAM], r3[NSTREAM];
            for (int i = 0; i < NSTREAM; i++) {
                p2p_cell_init(&s3[i], KS[i], KR[i], PFX);
                p2p_cell_init(&r3[i], KR[i], KS[i], PFX);
            }

            for (int i = 0; i < 3; i++) {          /* 流1 三个 */
                mkpayload(1, i, pl, &pll);
                p2p_cell_pack(&s3[0], P2P_CELL_CMD_DATA, pl, pll, cell);
                p2p_mix_enqueue(&m3, 1, cell);
            }
            for (int i = 0; i < 2; i++) {          /* 流2 两个 */
                mkpayload(2, i, pl, &pll);
                p2p_cell_pack(&s3[1], P2P_CELL_CMD_DATA, pl, pll, cell);
                p2p_mix_enqueue(&m3, 2, cell);
            }

            size_t o3 = 0, rr3 = 0;
            p2p_mix_flush(&m3, 3100, &sc, out, P2P_MIX_MAX_BATCH, &o3, &rr3);

            /* 按 stream 分发到各自的接收上下文解出顺序 */
            char seq[64];
            int  off = 0;
            int  lastseq[NSTREAM];
            for (int i = 0; i < NSTREAM; i++) lastseq[i] = -1;
            int  order_ok = 1;

            for (size_t i = 0; i < o3; i++) {
                uint32_t st = out[i].stream;
                if (st == P2P_MIX_STREAM_COVER) {
                    off += (int)snprintf(seq + off, sizeof seq - (size_t)off, "p ");
                    continue;
                }
                int sidx = (int)st - 1;
                uint8_t cmd = 0, d[600];
                size_t  dl = 0;
                int urc = p2p_cell_unpack(&r3[sidx], out[i].cell, &cmd, d, sizeof d, &dl);
                if (urc != P2P_CELL_OK) {
                    off += (int)snprintf(seq + off, sizeof seq - (size_t)off, "? ");
                    order_ok = 0;
                    continue;
                }
                d[dl] = 0;
                uint32_t pst = 0; int pseq = -1;
                if (!seq_of((char *)d, &pst, &pseq)) { order_ok = 0; }
                if (pst != st) order_ok = 0;                 /* 载荷与流标记一致 */
                if (pseq != lastseq[sidx] + 1) order_ok = 0; /* 流内严格 +1 */
                lastseq[sidx] = pseq;
                off += (int)snprintf(seq + off, sizeof seq - (size_t)off, "%s ", (char *)d);
            }
            if (!order_ok) order_ok_all = 0;
            snprintf(orders[t], sizeof orders[t], "%s", seq);
        }
        check(order_ok_all, "8 组 seed 下流内顺序均严格保持（解密全部成功、序号递增）");

        for (int t = 0; t < 8; t++) {
            int dup = 0;
            for (int u = 0; u < t; u++)
                if (strcmp(orders[t], orders[u]) == 0) { dup = 1; break; }
            if (!dup) distinct++;
        }
        printf("[INFO] 8 组 seed 得到 %d 种不同输出顺序\n", distinct);
        check(distinct >= 2, "跨流顺序随 seed 变化（确实被混序）");
        printf("[INFO] 示例输出顺序: %s\n", orders[0]);
    }

    /* ---- 5. 背压 ---- */
    {
        p2p_mix_t m4;
        p2p_mix_init(&m4, 3, 100, 4, 4000);
        int full = 0;
        for (int i = 0; i < P2P_MIX_MAXQ + 5; i++) {
            mkpayload(1, i, pl, &pll);
            p2p_cell_pack(&s[0], P2P_CELL_CMD_DATA, pl, pll, cell);
            if (p2p_mix_enqueue(&m4, 1, cell) == P2P_MIX_ERR_FULL) { full = 1; break; }
        }
        check(full == 1, "队列满返回背压(FULL)而非静默丢弃");
    }

    /* ---- 6. 输出容量不足 ---- */
    {
        p2p_mix_t m5;
        p2p_mix_init(&m5, 3, 100, 4, 5000);
        p2p_mix_out_t one[1];
        size_t o5 = 0, rr5 = 0;
        check(p2p_mix_flush(&m5, 5100, &sc, one, 1, &o5, &rr5) == P2P_MIX_ERR_LEN,
              "输出容量不足返回 LEN");
        check(p2p_mix_flush(&m5, 5100, NULL, out, P2P_MIX_MAX_BATCH, &o5, &rr5)
              == P2P_MIX_ERR_ARG, "缺少覆盖上下文返回 ARG");
    }

    /* ---- 7. 参数校验 ---- */
    {
        p2p_mix_t m6;
        check(p2p_mix_init(&m6, 1, 0, 4, 0) == P2P_MIX_ERR_ARG, "period=0 被拒");
        check(p2p_mix_init(&m6, 1, 100, 0, 0) == P2P_MIX_ERR_ARG, "batch=0 被拒");
        check(p2p_mix_init(&m6, 1, 100, P2P_MIX_MAX_BATCH + 1, 0) == P2P_MIX_ERR_ARG,
              "batch 超上限被拒");
    }

    printf("\ntotal=%d pass=%d fail=%d\n", g_pass + g_fail, g_pass, g_fail);
    return g_fail ? 1 : 0;
}
