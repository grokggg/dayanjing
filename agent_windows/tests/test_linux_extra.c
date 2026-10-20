/*
 * agent_windows/tests/test_linux_extra.c
 *
 * Linux 可编译补充测试：覆盖 test_pipeline.c 未触达的行为。
 * 只依赖跨平台纯 C 源码（cam_jpeg.c / cam_mock.c / camera.h），
 * 不触碰 Windows 专属后端 cam_mf.cpp，故 Linux 沙盒可直接编译运行。
 *
 * 覆盖点：
 *   1. cam_errstr 全错误码映射
 *   2. MJPEG 直通：合法帧字节级复制 / 非法帧拒绝 / 缓冲区不足回填
 *   3. YUYV422 转码：多尺寸、确定性、参数校验、探测容量
 *   4. 未支持格式（NV12/RGB24/NONE/UNKNOWN）显式报错，禁止静默把 YUV 当 JPEG
 *   5. Mock 源边界：enumerate 空参、close 后 capture、pts 单调、destroy 安全
 */

#include "camera.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, name) do { \
    if (cond) { g_pass++; printf("  [PASS] %s\n", name); } \
    else { g_fail++; printf("  [FAIL] %s  (%s:%d)\n", name, __FILE__, __LINE__); } \
} while (0)

static int is_jpeg(const uint8_t *d, size_t l)
{
    if (!d || l < 8) return 0;
    if (d[0] != 0xFF || d[1] != 0xD8) return 0;
    if (d[l - 2] != 0xFF || d[l - 1] != 0xD9) return 0;
    return 1;
}

/* 用 YUYV 编码器生成一帧合法 JPEG，作为 MJPEG 直通测试的输入 */
static size_t make_valid_jpeg(uint8_t *out, size_t cap)
{
    const int W = 16, H = 16;
    uint8_t yuyv[W * H * 2];
    for (int i = 0; i < (int)sizeof(yuyv); i++)
        yuyv[i] = (uint8_t)((i * 11 + 7) & 0xFF);

    cam_frame_t f;
    f.data   = yuyv;
    f.len    = sizeof(yuyv);
    f.fmt    = CAM_FMT_YUYV422;
    f.width  = (uint32_t)W;
    f.height = (uint32_t)H;
    f.pts_us = 1;

    size_t ocap = cap, olen = 0;
    if (cam_frame_to_jpeg(&f, out, &ocap, &olen) != CAM_OK) return 0;
    return olen;
}

int main(void)
{
    printf("[*] agent_windows Linux 补充测试（跨平台纯 C 部分）\n");
    printf("[*] ==========================================\n");

    /* ---------- 1. cam_errstr 全错误码映射 ---------- */
    {
        cam_err_t codes[] = { CAM_OK, CAM_ERR_GENERIC, CAM_ERR_NO_DEVICE,
                              CAM_ERR_NO_PERMISSION, CAM_ERR_FORMAT_NEGOTIATE,
                              CAM_ERR_TRANSFORM, CAM_ERR_TIMEOUT,
                              CAM_ERR_NOT_OPEN, CAM_ERR_INVALID_ARG };
        int ok = 1;
        for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); i++) {
            const char *s = cam_errstr(codes[i]);
            if (!s || s[0] == '\0') ok = 0;
        }
        CHECK(ok, "cam_errstr 全错误码返回非空字符串");
        CHECK(strcmp(cam_errstr(CAM_OK), "ok") == 0,
              "cam_errstr(CAM_OK) == \"ok\"");
    }

    /* ---------- 2. MJPEG 直通路径 ---------- */
    {
        uint8_t jpg[8192];
        size_t jlen = make_valid_jpeg(jpg, sizeof(jpg));
        CHECK(jlen > 0 && is_jpeg(jpg, jlen), "生成一帧合法 JPEG 作为输入");

        cam_frame_t mf;
        mf.data   = jpg;
        mf.len    = jlen;
        mf.fmt    = CAM_FMT_MJPEG;
        mf.width  = 16;
        mf.height = 16;
        mf.pts_us = 2;

        /* 2a 探测容量 */
        size_t pcap = 0, plen = 0;
        CHECK(cam_frame_to_jpeg(&mf, NULL, &pcap, &plen) == CAM_OK,
              "MJPEG 探测返回 CAM_OK");
        CHECK(plen == jlen, "MJPEG 探测 out_len == 原帧长度");

        /* 2b 实际复制，字节级一致 */
        uint8_t copy[8192];
        size_t ocap = sizeof(copy), olen = 0;
        CHECK(cam_frame_to_jpeg(&mf, copy, &ocap, &olen) == CAM_OK,
              "MJPEG 直通返回 CAM_OK");
        CHECK(olen == jlen && memcmp(copy, jpg, jlen) == 0,
              "MJPEG 直通字节级一致（未改包）");

        /* 2c 缓冲区不足 */
        uint8_t small[16];
        size_t scap = sizeof(small), slen = 0;
        CHECK(cam_frame_to_jpeg(&mf, small, &scap, &slen) == CAM_ERR_TRANSFORM,
              "MJPEG 缓冲区不足 -> CAM_ERR_TRANSFORM");
        CHECK(slen == jlen, "缓冲区不足时 out_len 回填所需长度");

        /* 2d 非法 MJPEG：截断，无 EOI */
        cam_frame_t bad = mf;
        bad.len = jlen - 1;
        size_t bcap = sizeof(copy), blen = 0;
        CHECK(cam_frame_to_jpeg(&bad, copy, &bcap, &blen) == CAM_ERR_TRANSFORM,
              "MJPEG 截断帧（无 EOI）-> CAM_ERR_TRANSFORM");

        /* 2e 非 JPEG 字节冒充 MJPEG */
        uint8_t junk[64];
        memset(junk, 0x41, sizeof(junk));
        cam_frame_t jf;
        jf.data = junk; jf.len = sizeof(junk); jf.fmt = CAM_FMT_MJPEG;
        jf.width = 8; jf.height = 8; jf.pts_us = 3;
        size_t jcap = sizeof(copy), jl = 0;
        CHECK(cam_frame_to_jpeg(&jf, copy, &jcap, &jl) == CAM_ERR_TRANSFORM,
              "非 JPEG 字节冒充 MJPEG -> CAM_ERR_TRANSFORM");
    }

    /* ---------- 3. YUYV422 转码 ---------- */
    {
        int sizes[][2] = { {8,8}, {16,16}, {32,32}, {64,64} };
        int all_ok = 1;
        for (int i = 0; i < 4; i++) {
            int W = sizes[i][0], H = sizes[i][1];
            uint8_t *yuyv = (uint8_t *)malloc((size_t)W * H * 2);
            if (!yuyv) { all_ok = 0; continue; }
            for (int k = 0; k < W * H * 2; k++)
                yuyv[k] = (uint8_t)((k * 13 + 5) & 0xFF);

            cam_frame_t f;
            f.data = yuyv; f.len = (size_t)W * H * 2;
            f.fmt = CAM_FMT_YUYV422;
            f.width = (uint32_t)W; f.height = (uint32_t)H; f.pts_us = 10;

            size_t cap = 0, len = 0;
            if (cam_frame_to_jpeg(&f, NULL, &cap, &len) != CAM_OK || len == 0) {
                all_ok = 0; free(yuyv); continue;
            }
            uint8_t *out = (uint8_t *)malloc(len + 32);
            size_t ocap = len + 32, olen = 0;
            if (cam_frame_to_jpeg(&f, out, &ocap, &olen) != CAM_OK ||
                !is_jpeg(out, olen))
                all_ok = 0;
            free(out); free(yuyv);
        }
        CHECK(all_ok, "YUYV422 多尺寸(8/16/32/64)转码均为合法 JPEG");

        /* 参数校验 */
        uint8_t yuyv[16 * 16 * 2];
        memset(yuyv, 0x33, sizeof(yuyv));
        cam_frame_t f;
        f.data = yuyv; f.len = sizeof(yuyv); f.fmt = CAM_FMT_YUYV422;
        f.width = 16; f.height = 16; f.pts_us = 0;

        CHECK(cam_frame_to_jpeg(NULL, NULL, NULL, NULL) == CAM_ERR_INVALID_ARG,
              "cam_frame_to_jpeg(NULL,...) -> CAM_ERR_INVALID_ARG");

        size_t c1 = 0, l1 = 0;
        cam_frame_t nobuf = f; nobuf.data = NULL; nobuf.len = 0;
        CHECK(cam_frame_to_jpeg(&nobuf, NULL, &c1, &l1) == CAM_ERR_INVALID_ARG,
              "空 data / len=0 -> CAM_ERR_INVALID_ARG");

        size_t c2 = 0, l2 = 0;
        cam_frame_t zero = f; zero.width = 0; zero.height = 0;
        CHECK(cam_frame_to_jpeg(&zero, NULL, &c2, &l2) == CAM_ERR_INVALID_ARG,
              "width/height 为 0 -> CAM_ERR_INVALID_ARG");

        /* 确定性：同一输入两次编码结果一致 */
        size_t ca = 0, la = 0;
        cam_frame_to_jpeg(&f, NULL, &ca, &la);
        uint8_t *o1 = (uint8_t *)malloc(la), *o2 = (uint8_t *)malloc(la);
        size_t o1c = la, o1l = 0, o2c = la, o2l = 0;
        cam_frame_to_jpeg(&f, o1, &o1c, &o1l);
        cam_frame_to_jpeg(&f, o2, &o2c, &o2l);
        CHECK(o1l > 0 && o1l == o2l && memcmp(o1, o2, o1l) == 0,
              "同输入两次编码结果一致（确定性）");
        free(o1); free(o2);
    }

    /* ---------- 4. 未支持格式显式报错 ---------- */
    {
        uint8_t raw[256];
        memset(raw, 0x55, sizeof(raw));
        size_t cap = sizeof(raw), len = 0;
        cam_frame_t nf;
        nf.data = raw; nf.len = sizeof(raw);
        nf.width = 16; nf.height = 8; nf.pts_us = 4;

        cam_err_t r[4];
        nf.fmt = CAM_FMT_NV12;    r[0] = cam_frame_to_jpeg(&nf, NULL, &cap, &len);
        nf.fmt = CAM_FMT_RGB24;   r[1] = cam_frame_to_jpeg(&nf, NULL, &cap, &len);
        nf.fmt = CAM_FMT_NONE;    r[2] = cam_frame_to_jpeg(&nf, NULL, &cap, &len);
        nf.fmt = CAM_FMT_UNKNOWN; r[3] = cam_frame_to_jpeg(&nf, NULL, &cap, &len);

        CHECK(r[0] == CAM_ERR_TRANSFORM && r[1] == CAM_ERR_TRANSFORM &&
              r[2] == CAM_ERR_TRANSFORM && r[3] == CAM_ERR_TRANSFORM,
              "NV12/RGB24/NONE/UNKNOWN -> CAM_ERR_TRANSFORM（不支持即报错，禁静默透传）");
    }

    /* ---------- 5. Mock 源边界 ---------- */
    {
        cam_source_t *s = cam_source_create("mock");
        CHECK(s != NULL, "cam_source_create(\"mock\") 返回非空");

        cam_source_t *mf = cam_source_create("mf");
        CHECK(mf != NULL, "Linux 下 backend=\"mf\" 也返回可用源（自动降级 mock）");
        cam_source_destroy(mf);

        cam_config_t cfg = { 320, 240, 10, 1000, 0, false };
        CHECK(s->open(s, &cfg) == CAM_OK, "open 成功");

        cam_device_info_t info[2];
        CHECK(s->enumerate(NULL, 2) == 0, "enumerate(NULL) -> 0");
        CHECK(s->enumerate(info, 0) == 0, "enumerate(count=0) -> 0");
        CHECK(s->enumerate(info, 2) == 1, "enumerate(count=2) -> 1 个虚拟设备");

        cam_frame_t fa, fb;
        CHECK(s->capture(s, &fa) == CAM_OK, "第一帧采集成功");
        CHECK(s->capture(s, &fb) == CAM_OK, "第二帧采集成功");
        CHECK(fb.pts_us > fa.pts_us, "pts_us 单调递增");
        CHECK(fa.fmt == CAM_FMT_MJPEG && fa.len > 0, "采集帧为 MJPEG 且长度 > 0");
        free((void *)fa.data);
        free((void *)fb.data);

        s->close(s);
        cam_frame_t fc;
        CHECK(s->capture(s, &fc) == CAM_ERR_NOT_OPEN,
              "close 后 capture -> CAM_ERR_NOT_OPEN");
        s->close(s);
        CHECK(1, "close 幂等（二次调用不崩溃）");

        cam_source_destroy(s);
        cam_source_destroy(NULL);
        CHECK(1, "cam_source_destroy(NULL) 安全");
    }

    printf("[*] ==========================================\n");
    printf("[*] 结果: %d/%d 通过\n", g_pass, g_pass + g_fail);
    printf("[*] 失败: %d 项\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
