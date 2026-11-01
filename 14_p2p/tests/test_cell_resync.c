/*
 * test_cell_resync.c —— 信元流对"单个坏信元"的恢复能力
 *
 * 背景（真实缺陷）：
 *   p2p_cell_unpack 在 gcm_open 失败时直接 return，未推进 recv_counter。
 *   由于 IV = pfx || recv_counter 是**位置相关**的，对端下一个信元按
 *   IV(N+1) 封装而本端仍按 IV(N) 解 —— 此后每一个信元都失败，链路被
 *   单个坏字节永久打死，且不可恢复。这是注入攻击的致命放大点。
 *
 * 修复：验签失败同样推进 recv_counter（吃掉一个坏信元，流位置仍 +1）。
 *
 * 本测试证明三件事：
 *   1. 单个被篡改的信元只损失它自己，下一个信元立刻恢复正常
 *   2. 修复没有削弱重放防护（位置前进了，旧信元依然解不开）
 *   3. 计数器严格按"消费的信元数"前进，无论成败
 */
#include "p2p_cell.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int total = 0, pass = 0, fail = 0;

static void check(int cond, const char *what) {
    total++;
    if (cond) { pass++; printf("[PASS] %s\n", what); }
    else      { fail++; printf("[FAIL] %s\n", what); }
}

static void fill(uint8_t *b, size_t n, unsigned seed) {
    unsigned x = seed ? seed : 1;
    for (size_t i = 0; i < n; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        b[i] = (uint8_t)(x & 0xff);
    }
}

int main(void) {
    uint8_t ks[P2P_CELL_KEY_LEN], kr[P2P_CELL_KEY_LEN], pfx[P2P_CELL_PFX_LEN];
    fill(ks, sizeof ks, 0xA5A5);
    fill(kr, sizeof kr, 0x5A5A);
    fill(pfx, sizeof pfx, 0x1234);

    p2p_cell_ctx_t A, B;
    check(p2p_cell_init(&A, ks, kr, pfx) == P2P_CELL_OK, "A 初始化");
    check(p2p_cell_init(&B, kr, ks, pfx) == P2P_CELL_OK, "B 初始化（方向相反）");

    /* ---- 1. 基线：连续 3 个信元全部正常 ---- */
    uint8_t c1[P2P_CELL_WIRE], c2[P2P_CELL_WIRE], c3[P2P_CELL_WIRE];
    const char *m1 = "alpha", *m2 = "bravo", *m3 = "charlie";
    check(p2p_cell_pack(&A, P2P_CELL_CMD_DATA, (const uint8_t *)m1, strlen(m1), c1) == P2P_CELL_OK, "打包 #1");
    check(p2p_cell_pack(&A, P2P_CELL_CMD_DATA, (const uint8_t *)m2, strlen(m2), c2) == P2P_CELL_OK, "打包 #2");
    check(p2p_cell_pack(&A, P2P_CELL_CMD_DATA, (const uint8_t *)m3, strlen(m3), c3) == P2P_CELL_OK, "打包 #3");

    uint8_t cmd = 0, buf[P2P_CELL_DATA_MAX + 1];
    size_t  dl = 0;
    check(p2p_cell_unpack(&B, c1, &cmd, buf, sizeof buf, &dl) == P2P_CELL_OK
          && dl == strlen(m1) && memcmp(buf, m1, dl) == 0, "基线 #1 解出");
    check(p2p_cell_unpack(&B, c2, &cmd, buf, sizeof buf, &dl) == P2P_CELL_OK
          && dl == strlen(m2) && memcmp(buf, m2, dl) == 0, "基线 #2 解出");
    check(p2p_cell_unpack(&B, c3, &cmd, buf, sizeof buf, &dl) == P2P_CELL_OK
          && dl == strlen(m3) && memcmp(buf, m3, dl) == 0, "基线 #3 解出");

    /* ---- 2. 重新对齐：新的一段流，中间那个信元被篡改 ---- */
    p2p_cell_ctx_t A2, B2;
    p2p_cell_init(&A2, ks, kr, pfx);
    p2p_cell_init(&B2, kr, ks, pfx);

    uint8_t g1[P2P_CELL_WIRE], g2[P2P_CELL_WIRE], g3[P2P_CELL_WIRE];
    p2p_cell_pack(&A2, P2P_CELL_CMD_DATA, (const uint8_t *)m1, strlen(m1), g1);
    p2p_cell_pack(&A2, P2P_CELL_CMD_DATA, (const uint8_t *)m2, strlen(m2), g2);
    p2p_cell_pack(&A2, P2P_CELL_CMD_DATA, (const uint8_t *)m3, strlen(m3), g3);

    check(p2p_cell_unpack(&B2, g1, &cmd, buf, sizeof buf, &dl) == P2P_CELL_OK, "篡改前 #1 正常");

    /* 篡改 #2 的末字节（模拟链路上一个比特翻转） */
    uint8_t bad[P2P_CELL_WIRE];
    memcpy(bad, g2, P2P_CELL_WIRE);
    bad[P2P_CELL_WIRE - 1] ^= 0x01;
    uint32_t ctr_before = B2.recv_counter;
    check(p2p_cell_unpack(&B2, bad, &cmd, buf, sizeof buf, &dl) == P2P_CELL_ERR_AUTH,
          "被篡改的 #2 返回 AUTH");

    /* 关键断言：失败也必须推进计数器（否则后面永久失步） */
    check(B2.recv_counter == ctr_before + 1,
          "AUTH 失败后 recv_counter 仍 +1（流位置前进）");

    /* 核心：下一个信元必须能正常解出 */
    check(p2p_cell_unpack(&B2, g3, &cmd, buf, sizeof buf, &dl) == P2P_CELL_OK
          && dl == strlen(m3) && memcmp(buf, m3, dl) == 0,
          "★ 单个坏信元后 #3 恢复正常（链路未死）");

    /* ---- 3. 修复未削弱重放防护 ---- */
    check(p2p_cell_unpack(&B2, g1, &cmd, buf, sizeof buf, &dl) == P2P_CELL_ERR_AUTH,
          "坏信元之后重放 #1 仍被拒（重放防护完好）");

    /* ---- 4. 连续多个坏信元：逐个 AUTH，之后仍可恢复 ---- */
    p2p_cell_ctx_t A3, B3;
    p2p_cell_init(&A3, ks, kr, pfx);
    p2p_cell_init(&B3, kr, ks, pfx);

    uint8_t s1[P2P_CELL_WIRE], s2[P2P_CELL_WIRE], s3[P2P_CELL_WIRE], s4[P2P_CELL_WIRE];
    p2p_cell_pack(&A3, P2P_CELL_CMD_DATA, (const uint8_t *)m1, strlen(m1), s1);
    p2p_cell_pack(&A3, P2P_CELL_CMD_DATA, (const uint8_t *)m2, strlen(m2), s2);
    p2p_cell_pack(&A3, P2P_CELL_CMD_DATA, (const uint8_t *)m3, strlen(m3), s3);
    p2p_cell_pack(&A3, P2P_CELL_CMD_DATA, (const uint8_t *)m1, strlen(m1), s4);

    p2p_cell_unpack(&B3, s1, &cmd, buf, sizeof buf, &dl);

    uint32_t c0 = B3.recv_counter;
    uint8_t tb[P2P_CELL_WIRE];
    memcpy(tb, s2, P2P_CELL_WIRE); tb[0] ^= 0xFF;
    check(p2p_cell_unpack(&B3, tb, &cmd, buf, sizeof buf, &dl) == P2P_CELL_ERR_AUTH, "突发坏人 #1 AUTH");
    memcpy(tb, s3, P2P_CELL_WIRE); tb[10] ^= 0xFF;
    check(p2p_cell_unpack(&B3, tb, &cmd, buf, sizeof buf, &dl) == P2P_CELL_ERR_AUTH, "突发坏人 #2 AUTH");
    check(B3.recv_counter == c0 + 2, "两个坏信元计数器共 +2");

    check(p2p_cell_unpack(&B3, s4, &cmd, buf, sizeof buf, &dl) == P2P_CELL_OK
          && memcmp(buf, m1, dl) == 0, "★ 突发坏信元后仍恢复正常");

    /* ---- 5. 参数校验未受影响 ---- */
    check(p2p_cell_unpack(NULL, g1, &cmd, buf, sizeof buf, &dl) == P2P_CELL_ERR_ARG, "NULL ctx -> ARG");
    check(p2p_cell_unpack(&B2, g1, &cmd, buf, sizeof buf, NULL) == P2P_CELL_ERR_ARG, "NULL len -> ARG");

    p2p_cell_wipe(&A); p2p_cell_wipe(&B);
    p2p_cell_wipe(&A2); p2p_cell_wipe(&B2);
    p2p_cell_wipe(&A3); p2p_cell_wipe(&B3);

    printf("\ntotal=%d pass=%d fail=%d\n", total, pass, fail);
    return fail ? 1 : 0;
}
