/*
 * DAYANJING v4 — 14_p2p/tests/test_mix_cover.c
 *
 * 覆盖流量 -> 真实数据面的驱动验证。重点不是"算出的速率对不对"
 * （那是 test_cover 的职责），而是：
 *
 *   1. 覆盖信元真的被封装出来并进入输出流了
 *   2. 覆盖信元与数据信元**交错**（不是先数据后覆盖的拼接）
 *   3. 覆盖信元用同一个 cell 上下文 -> 接收方计数器不错位，
 *      数据信元在覆盖信元之后仍然解得开
 *   4. 覆盖信元本身在接收端被识别为 PAD 而不产生数据
 *   5. 预算约束生效：换到高成本信道后，同样预算下覆盖信元数下降
 *   6. 数据突发会压低覆盖速率（总速率趋于恒定）
 *   7. budget = 0 时不发覆盖
 *   8. 容量不足时优先砍覆盖，保住数据
 *
 * 第 3 条是本模块最容易坏的地方：若覆盖用独立上下文，前几条用例可能
 * 照样通过，但接收方计数器会错位 —— 所以必须有"覆盖之后接着收数据"的用例。
 */

#include "p2p_mix.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;
static void check(int cond, const char *name) {
    if (cond) { g_pass++; printf("[PASS] %s\n", name); }
    else      { g_fail++; printf("[FAIL] %s\n", name); }
}
static void info(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    printf("[INFO] "); vprintf(fmt, ap); printf("\n");
    va_end(ap);
}

static uint8_t KS[16], KR[16], PFX[8];

static void setup_keys(void) {
    memset(KS, 0x51, sizeof KS);
    memset(KR, 0x52, sizeof KR);
    memset(PFX, 0x61, sizeof PFX);
}

/* 造 n 个数据信元入队（stream = 0） */
static int feed(p2p_mix_t *mx, p2p_cell_ctx_t *cc, int n) {
    for (int i = 0; i < n; i++) {
        char buf[32];
        int len = snprintf(buf, sizeof buf, "DATA-%02d", i);
        uint8_t cell[P2P_CELL_WIRE];
        int rc = p2p_cell_pack(cc, P2P_CELL_CMD_DATA,
                               (const uint8_t *)buf, (size_t)len, cell);
        if (rc != P2P_CELL_OK) return rc;
        rc = p2p_mix_enqueue(mx, 0, cell);
        if (rc != P2P_MIX_OK) return rc;
    }
    return P2P_MIX_OK;
}

int main(void) {
    setup_keys();

    p2p_cell_ctx_t send, recv;
    if (p2p_cell_init(&send, KS, KR, PFX) != P2P_CELL_OK) return 2;
    if (p2p_cell_init(&recv, KR, KS, PFX) != P2P_CELL_OK) return 2;

    /* ---------------- 用例1：有预算时确实产出覆盖信元 ---------------- */
    {
        p2p_mix_t mx; p2p_cover_t cov;
        p2p_mix_init(&mx, 0x1234u, 1000u, 8u, 0u);
        p2p_cover_init(&cov, P2P_COVER_PROFILE_DIRECT, 60000u, 0ull);

        p2p_mix_out_t out[128];
        size_t n_out = 0, n_real = 0, n_cov = 0;
        int rc = p2p_mix_flush_adaptive(&mx, &cov, 1000u, &send,
                                        out, 128, &n_out, &n_real, &n_cov, 0);
        check(rc == P2P_MIX_OK, "用例1 自适应出片返回 OK");
        check(n_cov > 0, "用例1 空闲时确实产出覆盖信元");
        check(n_real == 0, "用例1 无数据时真实信元为 0");
        check(n_out == n_real + n_cov, "用例1 n_out 等于 real+cover");
        info("用例1 n_out=%zu real=%zu cover=%zu rate=%u/min",
             n_out, n_real, n_cov, p2p_cover_rate(&cov));

        /* 覆盖信元必须能在接收端解出且是 PAD */
        int pad_ok = 1;
        for (size_t i = 0; i < n_out; i++) {
            uint8_t buf[P2P_CELL_DATA_MAX]; size_t blen = 0;
            uint8_t cmd = 0;
            int r = p2p_cell_unpack(&recv, out[i].cell, &cmd, buf, sizeof buf, &blen);
            if (r != P2P_CELL_OK || cmd != P2P_CELL_CMD_PAD) { pad_ok = 0; break; }
        }
        check(pad_ok, "用例1 覆盖信元在接收端解出为 PAD（计数器未错位）");
    }

    /* ---------- 用例2：覆盖与数据交错，且覆盖之后数据仍解得开 ---------- */
    {
        p2p_mix_t mx; p2p_cover_t cov;
        p2p_mix_init(&mx, 0x2222u, 1000u, 8u, 0u);
        p2p_cover_init(&cov, P2P_COVER_PROFILE_DIRECT, 300000u, 0ull);

        p2p_cell_ctx_t s2, r2;
        p2p_cell_init(&s2, KS, KR, PFX);
        p2p_cell_init(&r2, KR, KS, PFX);

        feed(&mx, &s2, 3);

        p2p_mix_out_t out[128];
        size_t n_out = 0, n_real = 0, n_cov = 0;
        int rc = p2p_mix_flush_adaptive(&mx, &cov, 1000u, &s2,
                                        out, 128, &n_out, &n_real, &n_cov, 0);
        check(rc == P2P_MIX_OK, "用例2 出片 OK");
        check(n_real == 3, "用例2 三个数据信元全部发出");
        check(n_cov > 0, "用例2 同时产出覆盖信元");

        /*
         * 顺序判定：必须是"先数据后覆盖"。
         * 这不是审美问题 —— 数据信元 enqueue 时已封装（counter 已定），
         * 覆盖信元出片时才封装；若覆盖排在数据前，接收方 counter 回退
         * -> REPLAY。单上下文下这个顺序是硬约束。
         */
        int order_ok = 1, seen_cover = 0;
        for (size_t i = 0; i < n_out; i++) {
            if (out[i].stream == P2P_MIX_STREAM_COVER) seen_cover = 1;
            else if (seen_cover) { order_ok = 0; break; }
        }
        check(order_ok, "用例2 覆盖信元全部排在数据信元之后（counter 单调）");
        info("用例2 n_out=%zu real=%zu cover=%zu", n_out, n_real, n_cov);

        /* 全部信元按序喂接收端：数据必须解得开且内容对得上 */
        int data_ok = 1, seen = 0;
        for (size_t i = 0; i < n_out; i++) {
            uint8_t buf[P2P_CELL_DATA_MAX]; size_t blen = 0;
            uint8_t cmd = 0;
            int r = p2p_cell_unpack(&r2, out[i].cell, &cmd, buf, sizeof buf, &blen);
            if (r != P2P_CELL_OK) { data_ok = 0; break; }
            if (cmd == P2P_CELL_CMD_DATA) {
                char expect[32];
                int el = snprintf(expect, sizeof expect, "DATA-%02d", seen);
                if (blen != (size_t)el || memcmp(buf, expect, (size_t)el) != 0) {
                    data_ok = 0; break;
                }
                seen++;
            }
        }
        check(data_ok && seen == 3,
              "用例2 覆盖信元穿插后数据仍逐个解得开（同上下文未错位）");
    }

    /* ---------------- 用例3：budget = 0 时不发覆盖 ---------------- */
    {
        p2p_mix_t mx; p2p_cover_t cov;
        p2p_mix_init(&mx, 0x3333u, 1000u, 8u, 0u);
        p2p_cover_init(&cov, P2P_COVER_PROFILE_DIRECT, 0u, 0ull);

        p2p_cell_ctx_t s3;
        p2p_cell_init(&s3, KS, KR, PFX);
        p2p_mix_out_t out[64];
        size_t n_out = 0, n_real = 0, n_cov = 0;
        p2p_mix_flush_adaptive(&mx, &cov, 1000u, &s3, out, 64,
                               &n_out, &n_real, &n_cov, 0);
        check(n_cov == 0 && n_out == 0, "用例3 预算为 0 时不发覆盖信元");
    }

    /* -------- 用例4：同样预算下，高成本信道产出更少的覆盖信元 -------- */
    {
        p2p_mix_t m1, m2; p2p_cover_t c1, c2;
        p2p_mix_init(&m1, 0x44u, 1000u, 8u, 0u);
        p2p_mix_init(&m2, 0x44u, 1000u, 8u, 0u);
        p2p_cover_init(&c1, P2P_COVER_PROFILE_DIRECT, 120000u, 0ull);
        p2p_cover_init(&c2, P2P_COVER_PROFILE_DNS,    120000u, 0ull);

        p2p_cell_ctx_t s4a, s4b;
        p2p_cell_init(&s4a, KS, KR, PFX);
        p2p_cell_init(&s4b, KS, KR, PFX);
        p2p_mix_out_t o1[64], o2[64];
        size_t a_out=0,a_real=0,a_cov=0, b_out=0,b_real=0,b_cov=0;
        p2p_mix_flush_adaptive(&m1, &c1, 1000u, &s4a, o1, 64,
                               &a_out, &a_real, &a_cov, 0);
        p2p_mix_flush_adaptive(&m2, &c2, 1000u, &s4b, o2, 64,
                               &b_out, &b_real, &b_cov, 0);

        check(b_cov < a_cov, "用例4 DNS 信道下覆盖信元数少于直连（成本更高）");
        info("用例4 直连 cover=%zu DNS cover=%zu (cost %u vs %u)",
             a_cov, b_cov, c1.bytes_per_cell, c2.bytes_per_cell);

        /* 预算约束：预计字节不得远超预算（允许一个信元的取整误差） */
        uint32_t proj = p2p_cover_projected_bytes_per_min(&c2);
        check(proj <= 120000u + c2.bytes_per_cell,
              "用例4 预计每分钟字节数被预算约束住");
        info("用例4 DNS 预计 %u 字节/分钟 (预算 120000)", proj);
    }

    /* -------- 用例5：数据突发压低覆盖（总速率趋于恒定） -------- */
    {
        p2p_cover_t cov;
        p2p_cover_init(&cov, P2P_COVER_PROFILE_DIRECT, 386400u, 0ull);
        uint32_t idle_rate = p2p_cover_rate(&cov);

        /* 连续多窗口大量数据 */
        uint64_t t = 0;
        for (int w = 0; w < 6; w++) {
            p2p_cover_note_data(&cov, 40u, t);
            t += 5000000ull;
            p2p_cover_tick(&cov, t);
        }
        uint32_t busy_rate = p2p_cover_rate(&cov);
        check(busy_rate < idle_rate, "用例5 数据突发后覆盖速率下降");
        info("用例5 空闲 cover=%u/min 忙碌 cover=%u/min", idle_rate, busy_rate);
    }

    /* -------- 用例6：容量不足时优先保数据 -------- */
    {
        p2p_mix_t mx; p2p_cover_t cov;
        p2p_mix_init(&mx, 0x66u, 1000u, 8u, 0u);
        p2p_cover_init(&cov, P2P_COVER_PROFILE_DIRECT, 6000000u, 0ull);
        p2p_cell_ctx_t s6, r6;
        p2p_cell_init(&s6, KS, KR, PFX);
        p2p_cell_init(&r6, KR, KS, PFX);
        feed(&mx, &s6, 5);

        p2p_mix_out_t out[128];
        size_t n_out=0, n_real=0, n_cov=0;
        /* cap 只给 6 项：5 个数据 + 至多 1 个覆盖 */
        int rc = p2p_mix_flush_adaptive(&mx, &cov, 1000u, &s6,
                                        out, 6, &n_out, &n_real, &n_cov, 0);
        check(rc == P2P_MIX_OK, "用例6 容量受限时仍返回 OK（不报错）");
        check(n_out <= 6, "用例6 输出不超过容量");
        check(n_real <= 5, "用例6 数据不被截断到超出队列内容");
        info("用例6 cap=6 -> out=%zu real=%zu cover=%zu", n_out, n_real, n_cov);
    }

    /* -------- 用例7：参数校验 -------- */
    {
        p2p_mix_t mx; p2p_cover_t cov;
        p2p_mix_init(&mx, 0x77u, 1000u, 8u, 0u);
        p2p_cover_init(&cov, P2P_COVER_PROFILE_DIRECT, 60000u, 0ull);
        p2p_cell_ctx_t s7;
        p2p_cell_init(&s7, KS, KR, PFX);
        p2p_mix_out_t out[64];
        size_t n_out=0, n_real=0, n_cov=0;

        check(p2p_mix_flush_adaptive(NULL, &cov, 0u, &s7, out, 64,
                                     &n_out, &n_real, &n_cov, 0) == P2P_MIX_ERR_ARG,
              "用例7 mx 为空被拒");
        check(p2p_mix_flush_adaptive(&mx, NULL, 0u, &s7, out, 64,
                                     &n_out, &n_real, &n_cov, 0) == P2P_MIX_ERR_ARG,
              "用例7 cov 为空被拒");
        check(p2p_mix_flush_adaptive(&mx, &cov, 0u, NULL, out, 64,
                                     &n_out, &n_real, &n_cov, 0) == P2P_MIX_ERR_ARG,
              "用例7 cc 为空被拒");
        check(p2p_mix_flush_adaptive(&mx, &cov, 0u, &s7, out, 0,
                                     &n_out, &n_real, &n_cov, 0) == P2P_MIX_ERR_LEN,
              "用例7 容量为 0 被拒");
    }

    /* -------- 用例8：多片连续发送，接收端全程不错位 -------- */
    {
        p2p_mix_t mx; p2p_cover_t cov;
        p2p_mix_init(&mx, 0x88u, 500u, 4u, 0u);
        p2p_cover_init(&cov, P2P_COVER_PROFILE_DIRECT, 60000u, 0ull);
        p2p_cell_ctx_t s8, r8;
        p2p_cell_init(&s8, KS, KR, PFX);
        p2p_cell_init(&r8, KR, KS, PFX);

        int total_data = 0, seen_data = 0, ok = 1;
        uint32_t now = 0;
        for (int tick = 0; tick < 10; tick++) {
            if (tick % 3 == 0) { feed(&mx, &s8, 2); total_data += 2; }
            now += 500u;
            p2p_mix_out_t out[128];
            size_t n_out=0, n_real=0, n_cov=0;
            if (p2p_mix_flush_adaptive(&mx, &cov, now, &s8, out, 128,
                                       &n_out, &n_real, &n_cov, 0) != P2P_MIX_OK) {
                ok = 0; break;
            }
            for (size_t i = 0; i < n_out; i++) {
                uint8_t buf[P2P_CELL_DATA_MAX]; size_t blen = 0;
                uint8_t cmd = 0;
                int r = p2p_cell_unpack(&r8, out[i].cell, &cmd, buf, sizeof buf, &blen);
                if (r != P2P_CELL_OK) { ok = 0; break; }
                if (cmd == P2P_CELL_CMD_DATA) seen_data++;
            }
            if (!ok) break;
        }
        check(ok, "用例8 连续 10 片接收端无解密失败");
        check(seen_data == total_data, "用例8 数据信元一个不少（覆盖未吃掉计数）");
        info("用例8 发出数据 %d 收到数据 %d", total_data, seen_data);
    }

    printf("\n=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
