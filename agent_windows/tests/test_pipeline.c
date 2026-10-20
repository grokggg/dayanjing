/*
 * agent_windows/tests/test_pipeline.c
 *
 * 采集 → 转码 → 密封 全链路集成测试（C 部分）。
 *
 * 职责：验证采集后端与转码层的行为正确性。
 *   - mock 后端 open / capture / close 生命周期
 *   - MJPEG 帧结构自洽（SOI / EOI / COM 段长度）
 *   - YUYV422 经 cam_frame_to_jpeg 转码产物为合法 JPEG
 *   - 异常路径错误码
 *
 * 交付字节落盘到 /tmp/dj_deliver.bin，供同目录 seal_verify.py
 * 用 00_crypto 已验证的 GCM 实现完成密封环节验证。
 * 这样避免在本程序内重复引入 crypto 依赖。
 */

#include "camera.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, name) do { \
    if (cond) { g_pass++; printf("  [PASS] %s\n", name); } \
    else { g_fail++; printf("  [FAIL] %s  (%s:%d)\n", name, __FILE__, __LINE__); } \
} while (0)

/* 判断一个 buffer 是否为合法 JPEG：SOI + EOI，且内部段结构完整。 */
static int is_jpeg(const uint8_t *d, size_t l)
{
    if (!d || l < 8) return 0;
    if (d[0] != 0xFF || d[1] != 0xD8) return 0;
    if (d[l - 2] != 0xFF || d[l - 1] != 0xD9) return 0;
    /* 校验首段 APP0/APPn 长度自洽 */
    if (d[2] == 0xFF && (d[3] & 0xE0) == 0xE0) {
        uint16_t seglen = ((uint16_t)d[4] << 8) | d[5];
        if (seglen < 2 || (size_t)6 + seglen > l) return 0;
    }
    return 1;
}

/* 把交付字节落盘，供 Python 侧做 GCM 密封验证。 */
static int deliver(const uint8_t *data, size_t len, const char *path)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) return 0;
    size_t w = fwrite(data, 1, len, fp);
    fclose(fp);
    return w == len ? (int)len : 0;
}

int main(void)
{
    printf("[*] agent_windows 采集→转码 全链路测试（C 部分）\n");
    printf("[*] ==========================================\n");

    /* ---------- 1. mock 后端生命周期 ---------- */
    cam_source_t *src = cam_source_create("mock");
    CHECK(src != NULL, "cam_source_create 返回非空");

    cam_config_t cfg = {640, 480, 15, 3000, 0, true};
    CHECK(src->open(src, &cfg) == CAM_OK, "mock open 成功");
    CHECK(src->check_permission() == true, "权限检查通过");

    cam_device_info_t info[4];
    int n = src->enumerate(info, 4);
    CHECK(n == 1, "枚举到 1 个虚拟设备");
    if (n == 1) {
        CHECK(strlen(info[0].device_id) > 0, "device_id 非空");
        CHECK(info[0].has_permission == true, "has_permission == true");
    }

    /* ---------- 2. 连续采集 5 帧，MJPEG 直通 ---------- */
    cam_frame_t f[5] = {0};
    int captured = 0;
    for (int i = 0; i < 5; i++) {
        if (src->capture(src, &f[i]) == CAM_OK && f[i].fmt == CAM_FMT_MJPEG)
            captured++;
    }
    CHECK(captured == 5, "连续 5 帧 MJPEG 采集成功");

    /* ---------- 3. 每帧是合法 JPEG，COM 序列号可解析 ---------- */
    int jpeg_ok = 0, seq_ok = 0;
    for (int i = 0; i < 5; i++) {
        const uint8_t *d = f[i].data;
        size_t l = f[i].len;
        if (!is_jpeg(d, l)) continue;
        jpeg_ok++;
        /* COM 段：FF FE <LL> <HH> <data...>
         * L 字段 = 段长度字段自身(2B) + 数据长度。
         * COM 段后紧跟 APP0 起始，故 6+comlen 应指向 0xFF 0xE0。 */
        if (d[2] == 0xFF && d[3] == 0xFE) {
            uint16_t comlen = ((uint16_t)d[4] << 8) | d[5];
            /* 数据长度 = comlen - 2，段边界应落在文件内的合法位置 */
            if (comlen >= 2 && (size_t)6 + (comlen - 2) <= l) {
                size_t data_len = comlen - 2;
                char buf[24] = {0};
                size_t cl = data_len < sizeof(buf) - 1 ? data_len : sizeof(buf) - 1;
                memcpy(buf, d + 6, cl);
                unsigned long s = 0;
                if (sscanf(buf, "frame%010lu", &s) == 1 && s == (unsigned long)(i + 1))
                    seq_ok++;
            }
        }
    }
    CHECK(jpeg_ok == 5, "5 帧均为合法 JPEG");
    CHECK(seq_ok == 5, "5 帧 COM 段序列号单调递增（帧唯一性）");

    /* ---------- 4. 交付字节落盘 ---------- */
    int delivered = 0;
    for (int i = 0; i < 3; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/tmp/dj_deliver_%d.bin", i);
        if (deliver(f[i].data, f[i].len, path) > 0) delivered++;
    }
    CHECK(delivered == 3, "3 帧交付字节落盘成功（供 Python 密封验证）");

    /* ---------- 5. YUYV422 → JPEG 转码路径 ----------
     * cam_frame_to_jpeg 为输出型接口：out=NULL 时探测容量，
     * 否则写入 out，实际写入字节数通过 out_len 返回。 */
    {
        const int W = 16, H = 16;
        uint8_t yuyv[W * H * 2];
        for (int i = 0; i < (int)sizeof(yuyv); i++)
            yuyv[i] = (uint8_t)((i * 7 + 128) & 0xFF);

        cam_frame_t yf;
        yf.data   = yuyv;
        yf.len    = sizeof(yuyv);
        yf.fmt    = CAM_FMT_YUYV422;
        yf.width  = W;
        yf.height = H;
        yf.pts_us = 9999ULL;

        /* 探测容量 */
        size_t cap = 0, written = 0;
        cam_err_t rc = cam_frame_to_jpeg(&yf, NULL, &cap, &written);
        CHECK(rc == CAM_OK, "cam_frame_to_jpeg(NULL) 探测容量成功");

        size_t alloc = (cap > written) ? cap : written;
        if (alloc == 0) alloc = 4096;  /* 兜底：实现可能直接写入 */
        uint8_t *jpg = (uint8_t *)malloc(alloc ? alloc : 1);
        size_t jpg_len = alloc;
        rc = cam_frame_to_jpeg(&yf, jpg, &jpg_len, &jpg_len);
        CHECK(rc == CAM_OK, "cam_frame_to_jpeg YUYV422 转码成功");

        int yuyv_is_jpeg = is_jpeg(jpg, jpg_len);
        CHECK(yuyv_is_jpeg == 1, "YUYV 转码产物为合法 JPEG（FFD8...FFD9）");
        if (yuyv_is_jpeg) {
            CHECK(jpg_len > 50, "转码后 JPEG 长度合理（>50 字节）");
        }
        free(jpg);
    }

    /* ---------- 6. 异常路径 ---------- */
    CHECK(src->capture(src, NULL) == CAM_ERR_INVALID_ARG,
          "capture(NULL) -> CAM_ERR_INVALID_ARG");
    CHECK(src->open(src, NULL) == CAM_ERR_INVALID_ARG,
          "open(NULL) -> CAM_ERR_INVALID_ARG");

    /* 用一个全新、未 open 的 source 验证 NOT_OPEN */
    {
        cam_source_t *fresh = cam_source_create("mock");
        cam_frame_t bad = {0};
        CHECK(fresh->capture(fresh, &bad) == CAM_ERR_NOT_OPEN,
              "未 open 直接 capture -> CAM_ERR_NOT_OPEN");
        cam_source_destroy(fresh);
    }

    /* ---------- 清理 ---------- */
    for (int i = 0; i < 5; i++) free((void *)f[i].data);
    src->close(src);
    cam_source_destroy(src);

    printf("[*] ==========================================\n");
    printf("[*] 结果: %d/%d 通过\n", g_pass, g_pass + g_fail);
    printf("[*] 失败: %d 项\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
