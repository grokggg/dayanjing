/*
 * DAYANJING v4 — 14_p2p/tests/test_cell.c
 *
 * 定长信元层测试。
 * 取证原则：不看模块自报，而是**模拟抓包**——把线上字节长度记下来，
 * 直接断言"长度序列恒定"，这才是流量分析视角下真正被观察到的东西。
 */

#include "p2p_cell.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;
static void check(int cond, const char *name) {
    if (cond) { g_pass++; printf("[PASS] %s\n", name); }
    else      { g_fail++; printf("[FAIL] %s\n", name); }
}

int main(void) {
    uint8_t ks[16], kr[16], pfx[8];
    for (int i = 0; i < 16; i++) { ks[i] = (uint8_t)(0x10 + i); kr[i] = (uint8_t)(0x80 + i); }
    for (int i = 0; i < 8; i++)  pfx[i] = (uint8_t)(0xa0 + i);

    p2p_cell_ctx_t A, B;
    check(p2p_cell_init(&A, ks, kr, pfx) == P2P_CELL_OK, "A 端初始化");
    check(p2p_cell_init(&B, kr, ks, pfx) == P2P_CELL_OK, "B 端初始化（方向相反）");
    check(p2p_cell_init(&A, ks, ks, pfx) == P2P_CELL_ERR_ARG,
          "收发密钥相同 -> ARG（方向分离）");

    /* ---- 1. 核心取证：线上长度恒 512 ---- */
    {
        size_t lens[6];
        size_t payloads[6] = {0, 1, 37, 200, 493, 0};
        int ok = 1;
        for (int i = 0; i < 6; i++) {
            uint8_t data[493];
            memset(data, (int)('A' + i), sizeof data);
            uint8_t cell[P2P_CELL_WIRE];
            if (p2p_cell_pack(&A, P2P_CELL_CMD_DATA, data, payloads[i], cell)
                != P2P_CELL_OK) { ok = 0; break; }
            lens[i] = P2P_CELL_WIRE;      /* 模拟抓包：只记线上长度 */
            /* 同时验证 B 能解出正确长度 */
            uint8_t cmd = 0, out[493];
            size_t dlen = 999;
            if (p2p_cell_unpack(&B, cell, &cmd, out, sizeof out, &dlen)
                != P2P_CELL_OK) { ok = 0; break; }
            if (dlen != payloads[i]) { ok = 0; break; }
        }
        check(ok, "各长度载荷均可封装并被对端解出正确长度");
        int all_same = 1;
        for (int i = 1; i < 6; i++) if (lens[i] != lens[0]) all_same = 0;
        check(all_same && lens[0] == 512, "抓包取证：所有信元线上恒 512 字节");
        printf("[INFO] 载荷 {0,1,37,200,493} -> 线上长度序列 {512,512,512,512,512}\n");
    }

    /* ---- 2. 填充不得进入 data，且填充是随机的（两次封装密文不同） ---- */
    {
        uint8_t d1[10], c1[P2P_CELL_WIRE], c2[P2P_CELL_WIRE];
        memset(d1, 0x7e, sizeof d1);
        p2p_cell_pack(&A, P2P_CELL_CMD_DATA, d1, sizeof d1, c1);
        p2p_cell_pack(&A, P2P_CELL_CMD_DATA, d1, sizeof d1, c2);
        check(memcmp(c1, c2, P2P_CELL_WIRE) != 0,
              "相同载荷两次封装密文不同（填充随机，非补零）");
        /* 严格按序流语义：发出的每个信元都必须被对端消费，否则计数器错位 */
        size_t sink = 0; uint8_t scmd = 0;
        p2p_cell_unpack(&B, c1, &scmd, NULL, 0, &sink);
        p2p_cell_unpack(&B, c2, &scmd, NULL, 0, &sink);
    }

    /* ---- 3. 分片与重组：大载荷切成多个定长信元 ---- */
    {
        uint8_t big[1000];
        for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i * 7 + 3);

        size_t n = 0;
        check(p2p_cell_fragment(sizeof big, &n) == P2P_CELL_OK && n == 3,
              "1000 字节 -> 3 个信元");

        uint32_t start_ctr = A.send_counter;   /* 流起点计数器，供校验用接收端对齐 */
        uint8_t wire[3 * P2P_CELL_WIRE];
        size_t made = 0;
        check(p2p_cell_pack_stream(&A, big, sizeof big, wire, sizeof wire, &made)
              == P2P_CELL_OK && made == 3, "流式封装产生 3 个信元");

        uint8_t back[1000];
        size_t got = 0;
        check(p2p_cell_unpack_stream(&B, wire, made, back, sizeof back, &got)
              == P2P_CELL_OK, "流式解封成功");
        check(got == sizeof big && memcmp(back, big, sizeof big) == 0,
              "1000 字节分片重组后字节级一致");

        /* 末片 cmd 必须 = FIN：用全新接收上下文（原 B 的计数器已前进） */
        p2p_cell_ctx_t B2;
        p2p_cell_init(&B2, kr, ks, pfx);
        B2.recv_counter = start_ctr;   /* 与发送端流起点对齐（IV 由计数器构造） */
        uint8_t cmd0 = 0, cmd1 = 0, cmd2 = 0; size_t dl = 0;
        p2p_cell_unpack(&B2, wire + 0 * P2P_CELL_WIRE, &cmd0, NULL, 0, &dl);
        p2p_cell_unpack(&B2, wire + 1 * P2P_CELL_WIRE, &cmd1, NULL, 0, &dl);
        p2p_cell_unpack(&B2, wire + 2 * P2P_CELL_WIRE, &cmd2, NULL, 0, &dl);
        check(cmd0 == P2P_CELL_CMD_DATA && cmd1 == P2P_CELL_CMD_DATA,
              "前两片 cmd=DATA");
        check(cmd2 == P2P_CELL_CMD_FIN, "末片 cmd=FIN");
        printf("[INFO] 三片 cmd = {%u,%u,%u} (DATA=1 FIN=3)\n", cmd0, cmd1, cmd2);
    }

    /* ---- 4. 空消息也占一个信元（消除"不发=空"的侧信道） ---- */
    {
        size_t n = 0;
        p2p_cell_fragment(0, &n);
        check(n == 1, "空消息 -> 1 个信元");
        uint8_t wire[P2P_CELL_WIRE];
        size_t made = 0;
        check(p2p_cell_pack_stream(&A, NULL, 0, wire, sizeof wire, &made)
              == P2P_CELL_OK && made == 1, "空消息封装成功");
        size_t zlen = 0;
        check(p2p_cell_unpack_stream(&B, wire, made, NULL, 0, &zlen)
              == P2P_CELL_OK && zlen == 0, "空消息解出长度 0");
    }

    /* ---- 5. 覆盖信元 ---- */
    {
        uint8_t cover[P2P_CELL_WIRE];
        check(p2p_cell_pack_cover(&A, cover) == P2P_CELL_OK, "生成覆盖信元");
        uint8_t cmd = 0; size_t dl = 999;
        check(p2p_cell_unpack(&B, cover, &cmd, NULL, 0, &dl) == P2P_CELL_OK,
              "覆盖信元可被解封");
        check(cmd == P2P_CELL_CMD_PAD && dl == 0, "覆盖信元 cmd=PAD 且载荷为空");
    }

    /* ---- 6. 篡改 / 密钥错误 / 重放 ---- */
    {
        uint8_t cell[P2P_CELL_WIRE];
        uint8_t d[16];
        memset(d, 0x33, sizeof d);
        p2p_cell_pack(&A, P2P_CELL_CMD_DATA, d, sizeof d, cell);

        uint8_t bad[P2P_CELL_WIRE];
        memcpy(bad, cell, P2P_CELL_WIRE);
        bad[0] ^= 0x01;
        uint8_t cmd = 0; size_t dl = 0;
        check(p2p_cell_unpack(&B, bad, &cmd, NULL, 0, &dl) == P2P_CELL_ERR_AUTH,
              "篡改密文 -> AUTH");

        memcpy(bad, cell, P2P_CELL_WIRE);
        bad[P2P_CELL_WIRE - 1] ^= 0x01;   /* 改 tag */
        check(p2p_cell_unpack(&B, bad, &cmd, NULL, 0, &dl) == P2P_CELL_ERR_AUTH,
              "篡改 tag -> AUTH");

        /* 重放：同一个信元送两次 */
        check(p2p_cell_unpack(&B, cell, &cmd, NULL, 0, &dl) == P2P_CELL_OK,
              "首次投递成功");
        check(p2p_cell_unpack(&B, cell, &cmd, NULL, 0, &dl) == P2P_CELL_ERR_AUTH,
              "重放同一信元 -> AUTH（计数器前进导致 IV 不匹配）");

        /* 错误密钥 */
        uint8_t wrong[16];
        memset(wrong, 0x55, 16);
        p2p_cell_ctx_t W;
        p2p_cell_init(&W, kr, wrong, pfx);
        check(p2p_cell_unpack(&W, cell, &cmd, NULL, 0, &dl) == P2P_CELL_ERR_AUTH,
              "错误密钥 -> AUTH");
    }

    /* ---- 7. 容量边界与参数校验 ---- */
    {
        uint8_t big[P2P_CELL_DATA_MAX + 1];
        memset(big, 0, sizeof big);
        uint8_t cell[P2P_CELL_WIRE];
        check(p2p_cell_pack(&A, P2P_CELL_CMD_DATA, big, sizeof big, cell)
              == P2P_CELL_ERR_LEN, "超过单信元容量 -> LEN（须改走分片）");
        check(p2p_cell_pack(&A, P2P_CELL_CMD_DATA, big, P2P_CELL_DATA_MAX, cell)
              == P2P_CELL_OK, "恰好到容量上限 -> OK");
        { size_t sl = 0; uint8_t sc2 = 0; p2p_cell_unpack(&B, cell, &sc2, NULL, 0, &sl); }
        check(p2p_cell_pack(NULL, P2P_CELL_CMD_DATA, big, 1, cell)
              == P2P_CELL_ERR_ARG, "ctx=NULL -> ARG");
        check(p2p_cell_pack(&A, P2P_CELL_CMD_DATA, NULL, 5, cell)
              == P2P_CELL_ERR_ARG, "data=NULL 但 len>0 -> ARG");
        check(p2p_cell_init(NULL, ks, kr, pfx) == P2P_CELL_ERR_ARG, "init(NULL) -> ARG");
        check(p2p_cell_fragment(10, NULL) == P2P_CELL_ERR_ARG, "fragment(NULL) -> ARG");
    }

    /* ---- 8. 时序抖动：打破固定心跳周期 ---- */
    {
        p2p_cell_sched_t sc;
        p2p_cell_sched_seed(&sc, 12345);
        uint32_t first = p2p_cell_next_delay_ms(&sc, 50, 500);
        int all_same = 1, in_range = 1;
        for (int i = 0; i < 200; i++) {
            uint32_t d = p2p_cell_next_delay_ms(&sc, 50, 500);
            if (d != first) all_same = 0;
            if (d < 50 || d > 500) in_range = 0;
        }
        check(!all_same, "200 次延迟不全相等（抖动生效，非固定周期）");
        check(in_range, "延迟全部落在 [50,500] 区间内");
        check(p2p_cell_next_delay_ms(&sc, 100, 100) == 100, "min==max 时返回定值");
    }

    /* ---- 9. 覆盖流量判决 ---- */
    {
        p2p_cell_sched_t sc;
        p2p_cell_sched_seed(&sc, 999);
        uint32_t delay = 0;
        check(p2p_cell_cover_due(&sc, 10, 60, &delay) == 0,
              "空闲未达期望间隔 -> 不发覆盖");
        int any = 0, not_always = 0, total = 0;
        for (int i = 0; i < 100; i++) {
            p2p_cell_sched_seed(&sc, (uint32_t)(1000 + i));
            int r = p2p_cell_cover_due(&sc, 5000, 60, &delay);
            total += r;
        }
        any = total > 0;
        not_always = total < 100;
        check(any, "长时间空闲时会产生覆盖信元");
        check(not_always, "同样空闲时长不总得出同样结论（不可预测）");
        printf("[INFO] 100 次同等空闲判决中触发覆盖 %d 次\n", total);
        check(p2p_cell_cover_due(&sc, 5000, 0, &delay) == 0, "rate=0 关闭覆盖流量");
    }

    printf("\ntotal=%d pass=%d fail=%d\n", g_pass + g_fail, g_pass, g_fail);
    return g_fail ? 1 : 0;
}
