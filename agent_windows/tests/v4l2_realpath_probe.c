/*
 * v4l2_realpath_probe.c — 在 V4L2 ABI 模拟器下驱动真实的 cam_linux_v4l2.c
 *
 * shim（LD_PRELOAD）让 /dev/video0 按 V4L2 ABI 回应，本程序则是普通调用方：
 * 它只调 cam_source_create(backend) -> open -> capture，与真机上完全一样。
 * 因此被验证的是产品代码本身，不是模拟器。
 *
 * 输出 KEY=VALUE 供守卫断言。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "camera.h"

static void emit(const char *k, long long v)      { printf("%s=%lld\n", k, v); }
static void emits(const char *k, const char *v)   { printf("%s=%s\n", k, v); }

/* 从 JPEG 里解析 SOF0 的真实宽高 —— 用于证明转码输出分辨率与源一致 */
static int jpeg_dims(const uint8_t *d, size_t n, int *w, int *h)
{
    if (n < 4 || d[0] != 0xFF || d[1] != 0xD8) return -1;
    size_t i = 2;
    while (i + 9 < n) {
        if (d[i] != 0xFF) { i++; continue; }
        uint8_t m = d[i + 1];
        if (m == 0xD8 || m == 0x01 || (m >= 0xD0 && m <= 0xD7)) { i += 2; continue; }
        size_t seg = ((size_t)d[i + 2] << 8) | d[i + 3];
        if (seg < 2) return -1;
        if (m >= 0xC0 && m <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC) {
            *h = (d[i + 5] << 8) | d[i + 6];
            *w = (d[i + 7] << 8) | d[i + 8];
            return 0;
        }
        i += 2 + seg;
    }
    return -1;
}

int main(int argc, char **argv)
{
    const char *backend = (argc > 1) ? argv[1] : "v4l2";

    cam_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.width       = 320;
    cfg.height      = 240;
    cfg.capture_ms  = 300;
    cfg.max_frames  = 0;
    cfg.prefer_mjpeg = true;

    cam_source_t *src = cam_source_create(backend);
    emits("CREATE", src ? "OK" : "NULL");
    if (!src) { emit("RC", 1); return 1; }

    cam_err_t e = src->open(src, &cfg);
    emits("OPEN", e == CAM_OK ? "OK" : "FAIL");
    printf("OPEN_ERR=%s\n", cam_errstr(e));
    if (e != CAM_OK) { emit("RC", 2); return 2; }

    /* 降级原因：0=真设备，1=无设备，2=有设备但打不开（被占用）。
     *
     * 必须在 open 之后立刻取。此前产品代码在 V4L2 初始化失败时静默切合成
     * 帧且 open 仍返回 CAM_OK，于是"设备不存在"与"设备被占用"在调用方看来
     * 完全一样——都是 CAPTURE=OK、都有合法 JPEG、都零报错，而后者那台机器
     * 明明有摄像头。 */
    emit("DEGRADE", (long long)cam_source_degrade(src));

    cam_frame_t f;
    memset(&f, 0, sizeof(f));
    e = src->capture(src, &f);
    emits("CAPTURE", e == CAM_OK ? "OK" : "FAIL");
    printf("CAPTURE_ERR=%s\n", cam_errstr(e));
    if (e != CAM_OK) { emit("RC", 3); return 3; }

    emit("FRAME_LEN",  (long long)f.len);
    emit("FRAME_FMT",  (long long)f.fmt);
    emit("FRAME_W",    (long long)f.width);
    emit("FRAME_H",    (long long)f.height);
    emit("FRAME_PTS",  (long long)(f.pts_us > 0 ? 1 : 0));

    /* 诊断用：把原始帧落盘，便于与 mock 帧逐字节比对 */
    {
        const char *dp = getenv("V4L2SIM_DUMP");
        if (dp && f.data && f.len) {
            FILE *fp = fopen(dp, "wb");
            if (fp) { fwrite(f.data, 1, f.len, fp); fclose(fp); }
        }
    }

    /* 帧是否非零（全零帧也是一类静默失效） */
    size_t nonzero = 0;
    for (size_t i = 0; i < f.len; i++) if (f.data[i]) nonzero++;
    emit("NONZERO", (long long)nonzero);

    int is_jpeg = (f.len >= 4 && f.data[0] == 0xFF && f.data[1] == 0xD8);
    emit("IS_JPEG_MAGIC", is_jpeg);

    /* 转码路径：探测容量 -> 真转码 -> 校验输出
     *
     * 探测模式回填的是 *out_len（所需字节数），不是 *out_cap。
     * 第一版我读 out_cap 恒为 0，误判成"转码失败"。
     * 这是 probe 的判据错，不是产品缺陷 —— 产品代码两者语义分明：
     *   out_cap = 调用方给的容量（入参），out_len = 实际/所需长度（出参）。 */
    size_t cap = 0, len = 0;
    cam_err_t t = cam_frame_to_jpeg(&f, NULL, &cap, &len);
    emits("PROBE", t == CAM_OK ? "OK" : "FAIL");
    emit("PROBE_LEN", (long long)len);

    uint8_t *out = NULL;
    if (t == CAM_OK && len > 0) {
        out = (uint8_t *)malloc(len);
        size_t c2 = len;
        size_t l2 = 0;
        cam_err_t t2 = cam_frame_to_jpeg(&f, out, &c2, &l2);
        emits("TRANSFORM", t2 == CAM_OK ? "OK" : "FAIL");
        emit("JPEG_LEN", (long long)l2);
        if (t2 == CAM_OK && l2 >= 4) {
            emit("JPEG_MAGIC", (out[0] == 0xFF && out[1] == 0xD8) ? 1 : 0);
            emit("JPEG_EOI",   (out[l2-2] == 0xFF && out[l2-1] == 0xD9) ? 1 : 0);
            {
                const char *jp = getenv("V4L2SIM_JPEGDUMP");
                if (jp) { FILE *jf = fopen(jp, "wb"); if (jf) { fwrite(out, 1, l2, jf); fclose(jf); } }
            }
            int w = 0, h = 0;
            if (jpeg_dims(out, l2, &w, &h) == 0) {
                emit("JPEG_W", w); emit("JPEG_H", h);
                emit("JPEG_DIMS_MATCH", (w == (int)f.width && h == (int)f.height) ? 1 : 0);
            } else { emit("JPEG_DIMS_MATCH", 0); }
        }
        free(out);
    }

    /* 多帧：证明流是持续的，不是开流拿到一帧就死 */
    int got = 0;
    for (int i = 0; i < 3; i++) {
        cam_frame_t g; memset(&g, 0, sizeof(g));
        if (src->capture(src, &g) == CAM_OK) got++;
    }
    emit("EXTRA_FRAMES", got);

    src->close(src);
    cam_source_destroy(src);
    emits("CLOSED", "OK");
    emit("RC", 0);
    return 0;
}
