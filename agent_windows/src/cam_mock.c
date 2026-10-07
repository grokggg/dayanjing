#include "camera.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * Mock 摄像头源。
 *
 * 行为：
 *   - 模拟一个可用的虚拟设备，open/capture/close 均可正常调用
 *   - capture() 每次返回一个伪造但可识别的帧，用于验证协议链路
 *   - check_permission() 始终返回 true，模拟权限已到位的前提 A
 *
 * 用途：在沙盒（无 /dev/video*）与无 Windows 真机环境下，验证
 *       采集→转码→密封→上传的完整链路。
 */

typedef struct {
    cam_source_t   api;
    cam_config_t   cfg;
    bool           opened;
    uint64_t       seq;
    uint8_t       *frame_buf;
    size_t         frame_cap;
} mock_source_t;

/* 构造一个最小合法的 JPEG 帧，用于测试 MJPEG 直通路径。
 * 这是 1x1 像素的合法 JPEG，可校验"MJPEG 帧是否被原样交付"。 */
static const uint8_t MOCK_JPEG_1X1[] = {
    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01,
    0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    0xFF, 0xDB, 0x00, 0x43, 0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08,
    0x07, 0x07, 0x07, 0x09, 0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B,
    0x0B, 0x0C, 0x19, 0x12, 0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D,
    0x1A, 0x23, 0x1C, 0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23,
    0x1C, 0x1C, 0x28, 0x37, 0x29, 0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F,
    0x27, 0x39, 0x3D, 0x38, 0x32, 0x3C, 0x2E, 0x33, 0x34, 0x32,
    0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00,
    0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0xFB, 0xFF, 0xD9
};

static cam_err_t mock_open(cam_source_t *self, const cam_config_t *cfg)
{
    mock_source_t *m = (mock_source_t *)self;
    if (!cfg) return CAM_ERR_INVALID_ARG;
    m->cfg = *cfg;
    if (m->cfg.capture_ms == 0) m->cfg.capture_ms = 3000;
    m->opened = true;
    return CAM_OK;
}

static cam_err_t mock_capture(cam_source_t *self, cam_frame_t *frame)
{
    mock_source_t *m = (mock_source_t *)self;
    if (!m->opened) return CAM_ERR_NOT_OPEN;
    if (!frame) return CAM_ERR_INVALID_ARG;

    /* 每次返回一个新的帧：在合法 JPEG 后追加序列号，便于验证帧唯一性。
     * frame.len 必须反映实际写入字节数，不能等于 buffer 容量。
     *
     * 关键：每次 capture 返回独立的 buffer，不复用 m->frame_buf。
     * 调用方可能同时持有多帧（采集队列），复用会导致旧帧被覆盖。
     * 由调用方负责释放 frame->data。 */
    size_t base = sizeof(MOCK_JPEG_1X1);
    char   seqbuf[24];
    int    seqlen = snprintf(seqbuf, sizeof(seqbuf), "frame%010lu",
                             (unsigned long)(++m->seq));
    size_t need = base + (size_t)seqlen;
    uint8_t *out = (uint8_t *)malloc(need);
    if (!out) return CAM_ERR_GENERIC;
    memcpy(out, MOCK_JPEG_1X1, base);
    memcpy(out + base, seqbuf, (size_t)seqlen);
    frame->data   = out;
    frame->len    = need;
    frame->fmt    = CAM_FMT_MJPEG;
    frame->width  = 1;
    frame->height = 1;
    frame->pts_us = m->seq * 33333ULL;
    return CAM_OK;
}

static void mock_close(cam_source_t *self)
{
    mock_source_t *m = (mock_source_t *)self;
    m->opened = false;
}

static int mock_enumerate(cam_device_info_t *info, int count)
{
    if (!info || count <= 0) return 0;
    snprintf(info[0].device_id, sizeof(info[0].device_id), "mock://camera0");
    snprintf(info[0].friendly_name, sizeof(info[0].friendly_name),
             "Mock Camera (virtual)");
    info[0].has_permission = true;
    return 1;
}

static bool mock_check_permission(void)
{
    return true;   /* 前提 A：权限已到位 */
}

static void mock_destroy(cam_source_t *self)
{
    mock_source_t *m = (mock_source_t *)self;
    free(m->frame_buf);
    free(m);
}

cam_source_t *cam_source_create(const char *backend)
{
    (void)backend;   /* mock 后端忽略参数差异，统一返回虚拟源 */
    mock_source_t *m = (mock_source_t *)calloc(1, sizeof(*m));
    if (!m) return NULL;

    m->api.open             = mock_open;
    m->api.capture          = mock_capture;
    m->api.close            = mock_close;
    m->api.enumerate        = mock_enumerate;
    m->api.check_permission = mock_check_permission;
    m->api.priv             = m;
    m->opened               = false;
    m->seq                  = 0;
    m->frame_buf            = NULL;
    m->frame_cap            = 0;
    return &m->api;
}

void cam_source_destroy(cam_source_t *src)
{
    if (!src) return;
    src->close(src);
    mock_destroy(src);
}

const char *cam_errstr(cam_err_t e)
{
    switch (e) {
        case CAM_OK:                return "ok";
        case CAM_ERR_GENERIC:       return "generic error";
        case CAM_ERR_NO_DEVICE:     return "no camera device";
        case CAM_ERR_NO_PERMISSION: return "permission denied";
        case CAM_ERR_FORMAT_NEGOTIATE: return "format negotiate failed";
        case CAM_ERR_TRANSFORM:     return "transform failed";
        case CAM_ERR_TIMEOUT:       return "timeout";
        case CAM_ERR_NOT_OPEN:      return "device not open";
        case CAM_ERR_INVALID_ARG:   return "invalid argument";
        default:                    return "unknown";
    }
}
