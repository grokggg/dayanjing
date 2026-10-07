/*
 * tools/test_transcode.c
 *
 * C 端转码自测：在 Linux（无摄像头设备）上验证 cam_jpeg.c 的逻辑正确性。
 * 使用构造的测试帧（合法 MJPEG、伪 JPEG、YUYV）喂 cam_frame_to_jpeg，
 * 验证：
 *   1. 合法 MJPEG 帧能直通交付（is_jpeg 校验通过）
 *   2. 非法字节被拒绝（不把任意字节当 JPEG 透传）
 *   3. YUYV 帧能转码为合法 JPEG 结构
 *   4. 错误码语义正确
 */

#include "camera.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* 合法基线 JPEG 测试样本（由 tools/gen_sample_jpeg.py 生成）。
 * 用 PIL 产出标准 JPEG，保证 is_jpeg() 的严格结构校验能通过。 */
#include "sample_jpeg.h"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(name, cond) do { \
    if (cond) { printf("  [PASS] %s\n", name); g_pass++; } \
    else      { printf("  [FAIL] %s\n", name); g_fail++; } \
} while (0)

int main(void)
{
    printf("=== cam_frame_to_jpeg 转码自测 ===\n\n");

    uint8_t *out = (uint8_t *)malloc(64 * 1024);
    assert(out);
    size_t out_cap = 64 * 1024;
    size_t out_len = 0;

    /* ---------- 1. MJPEG 直通：合法 JPEG ---------- */
    printf("[1] MJPEG 直通（合法帧）\n");
    cam_frame_t mjpeg_frame = {
        .data   = SAMPLE_JPEG,
        .len    = SAMPLE_JPEG_LEN,
        .fmt    = CAM_FMT_MJPEG,
        .width  = 2,
        .height = 2,
        .pts_us = 0
    };
    cam_err_t rc = cam_frame_to_jpeg(&mjpeg_frame, out, &out_cap, &out_len);
    CHECK("合法 MJPEG 帧转换返回 CAM_OK", rc == CAM_OK);
    CHECK("输出长度等于输入长度（直通）", out_len == SAMPLE_JPEG_LEN);
    CHECK("输出内容与原帧完全一致（未改动）",
          memcmp(out, SAMPLE_JPEG, SAMPLE_JPEG_LEN) == 0);

    /* ---------- 2. MJPEG 直通：非法字节被拒绝 ---------- */
    printf("\n[2] MJPEG 直通（非法帧）\n");
    uint8_t bogus[32];
    memset(bogus, 0xAB, sizeof(bogus));  /* 无任何 JPEG 标记 */
    cam_frame_t bad = {
        .data = bogus, .len = sizeof(bogus),
        .fmt = CAM_FMT_MJPEG, .width = 1, .height = 1, .pts_us = 0
    };
    rc = cam_frame_to_jpeg(&bad, out, &out_cap, &out_len);
    CHECK("非法字节被拒绝（返回 CAM_ERR_TRANSFORM）", rc == CAM_ERR_TRANSFORM);

    /* ---------- 3. MJPEG 直通：伪装头（有 FFD8 无 FFD9）被拒绝 ---------- */
    printf("\n[3] MJPEG 直通（伪装头，无 EOI）\n");
    uint8_t fake[16] = {0xFF, 0xD8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    cam_frame_t fakef = {
        .data = fake, .len = sizeof(fake),
        .fmt = CAM_FMT_MJPEG, .width = 1, .height = 1, .pts_us = 0
    };
    rc = cam_frame_to_jpeg(&fakef, out, &out_cap, &out_len);
    CHECK("伪装头（无 EOI）被拒绝", rc == CAM_ERR_TRANSFORM);

    /* ---------- 4. YUYV 转码 ---------- */
    printf("\n[4] YUYV422 转码\n");
    /* 2x2 YUYV: Y0 U Y1 V 重复两次。Y=128(灰), U=128, V=128 → 灰色块 */
    uint8_t yuyv[16] = {
        128, 128, 128, 128,  128, 128, 128, 128,
        128, 128, 128, 128,  128, 128, 128, 128
    };
    cam_frame_t yuvf = {
        .data = yuyv, .len = sizeof(yuyv),
        .fmt = CAM_FMT_YUYV422, .width = 2, .height = 2, .pts_us = 0
    };
    rc = cam_frame_to_jpeg(&yuvf, out, &out_cap, &out_len);
    CHECK("YUYV 转码返回 CAM_OK", rc == CAM_OK);
    CHECK("转码输出长度 > 0", out_len > 0);
    CHECK("转码输出以 FFD8(SOI) 开头", out[0] == 0xFF && out[1] == 0xD8);
    CHECK("转码输出以 FFD9(EOI) 结尾",
          out[out_len - 2] == 0xFF && out[out_len - 1] == 0xD9);

    /* ---------- 5. 错误参数 ---------- */
    printf("\n[5] 错误参数处理\n");
    rc = cam_frame_to_jpeg(NULL, out, &out_cap, &out_len);
    CHECK("frame=NULL 返回 CAM_ERR_INVALID_ARG", rc == CAM_ERR_INVALID_ARG);
    rc = cam_frame_to_jpeg(&mjpeg_frame, NULL, &out_cap, &out_len);
    CHECK("out=NULL 返回 CAM_ERR_INVALID_ARG", rc == CAM_ERR_INVALID_ARG);
    rc = cam_frame_to_jpeg(&mjpeg_frame, out, NULL, &out_len);
    CHECK("out_cap=NULL 返回 CAM_ERR_INVALID_ARG", rc == CAM_ERR_INVALID_ARG);

    /* ---------- 6. Mock 源状态机 ---------- */
    printf("\n[6] Mock 源状态机\n");
    cam_source_t *src = cam_source_create("mock");
    CHECK("cam_source_create 返回非空", src != NULL);
    rc = src->open(src, &(cam_config_t){.capture_ms = 1000, .prefer_mjpeg = true});
    CHECK("open 返回 CAM_OK", rc == CAM_OK);
    CHECK("check_permission 返回 true（前提 A）", src->check_permission() == true);

    cam_frame_t f1, f2;
    rc = src->capture(src, &f1);
    CHECK("第一次 capture 返回 CAM_OK", rc == CAM_OK);
    rc = src->capture(src, &f2);
    CHECK("第二次 capture 返回 CAM_OK", rc == CAM_OK);
    CHECK("连续帧数据内容不同（唯一性）", memcmp(f1.data, f2.data, f1.len) != 0);
    src->close(src);
    cam_source_destroy(src);

    free(out);

    printf("\n=== 结果: %d 通过, %d 失败 ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
