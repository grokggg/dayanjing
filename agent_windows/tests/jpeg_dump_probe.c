/*
 * jpeg_dump_probe —— 把 cam_frame_to_jpeg 的产物落成文件，供外部真解码器校验。
 *
 * 为什么需要它：
 *   既有测试判据 is_jpeg() 只校验 SOI/EOI 两个魔数与段结构，从不真正解码。
 *   而 mock 后端产出的是 1x1 桩帧（167 字节）、走 MJPEG 直通，根本不经过
 *   真实分辨率转码。于是"摄像头链路已验证"这句话此前从未包含"画面能打开"
 *   这一层——三个编码缺陷（Huffman 按出现顺序落位、码字左对齐、prev_dc 取
 *   块内像素）因此在全绿的测试下藏了很久，直到用真解码器才暴露。
 *
 * 本 probe 不自己判断对错，只负责产出：
 *   out/frame_noise.jpg    噪声帧（与既有 test_cam_e2e 同源，xorshift）
 *   out/frame_gradient.jpg 渐变帧（更接近真实摄像头画面：平滑、低频为主）
 *   out/frame_*.yuyv       对应原始像素，供 decode 侧比对内容
 * 判定交给 tests/verify_jpeg_decode.py（PIL + ffmpeg 双解码器）。
 *
 * 必须走产品接口 cam_frame_to_jpeg，不直接调 cam_jpeg 内部函数：
 *   直接调内部函数会绕过 fmt 分派与容量探测，验到的不是部署时跑的那条路。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "camera.h"

static int dump(const char *dir, const char *tag,
                const uint8_t *yuyv, size_t ylen,
                uint32_t w, uint32_t h)
{
    cam_frame_t f;
    memset(&f, 0, sizeof(f));
    f.data = yuyv; f.len = ylen;
    f.fmt = CAM_FMT_YUYV422;
    f.width = w; f.height = h;
    f.pts_us = 1700000000999999ULL;

    size_t cap = 0, need = 0;
    cam_err_t e = cam_frame_to_jpeg(&f, NULL, &cap, &need);
    if (e != CAM_OK) {
        printf("PROBE %s PROBE_RC=%d PROBE_LEN=0\n", tag, (int)e);
        return 1;
    }
    uint8_t *jpg = (uint8_t *)malloc(need);
    if (!jpg) { printf("PROBE %s PROBE_RC=-1 PROBE_LEN=0\n", tag); return 1; }

    size_t cap2 = need, len2 = 0;
    e = cam_frame_to_jpeg(&f, jpg, &cap2, &len2);
    printf("PROBE %s PROBE_RC=%d PROBE_LEN=%zu W=%u H=%u\n",
           tag, (int)e, len2, w, h);

    char path[512];
    snprintf(path, sizeof(path), "%s/%s.jpg", dir, tag);
    FILE *fp = fopen(path, "wb");
    if (fp) { fwrite(jpg, 1, len2, fp); fclose(fp); }
    snprintf(path, sizeof(path), "%s/%s.yuyv", dir, tag);
    fp = fopen(path, "wb");
    if (fp) { fwrite(yuyv, 1, ylen, fp); fclose(fp); }

    free(jpg);
    return (e == CAM_OK && len2 > 0) ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <outdir>\n", argv[0]);
        return 2;
    }
    const char *dir = argv[1];
    uint32_t w = 320, h = 240;
    size_t ylen = (size_t)w * h * 2;

    uint8_t *noise = (uint8_t *)malloc(ylen);
    uint8_t *grad  = (uint8_t *)malloc(ylen);
    if (!noise || !grad) return 2;

    /* (a) 噪声：与既有 test_cam_e2e 同源。高熵，AC 系数极多。 */
    uint32_t sd = 0xc0ffeeu;
    for (size_t i = 0; i < ylen; i++) {
        sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5;
        noise[i] = (uint8_t)(sd & 0xff);
    }

    /* (b) 渐变：模拟真实摄像头画面——平滑、以低频为主。
     * Y 随 x 线性、U/V 随 y 缓变，避免 DCT 后 AC 爆表。
     * 真实画面必然命中符号值 0xd1 那类高位 AC 码，而纯随机帧永不命中，
     * 这正是"Huffman 按出现顺序落位"缺陷的藏身处。 */
    for (uint32_t y = 0; y < h; y++) {
        for (uint32_t x = 0; x < w; x += 2) {
            size_t o = ((size_t)y * w + x) * 2;
            uint8_t y0 = (uint8_t)(16 + (x * 200) / w);
            uint8_t y1 = (uint8_t)(16 + ((x + 1) * 200) / w);
            uint8_t u  = (uint8_t)(40 + (y * 160) / h);
            uint8_t v  = (uint8_t)(200 - (y * 120) / h);
            grad[o + 0] = y0;
            grad[o + 1] = u;
            grad[o + 2] = y1;
            grad[o + 3] = v;
        }
    }

    /* (c) 纯灰：Y=128 U=V=128。解码结果必须是均匀 (128,128,128)。
     *     它把"亮度路径/色度路径/DC 预测/码流"全部压成一个标量判据：
     *     任何一处错，均匀性立刻被破坏，且不需要参考实现。 */
    uint8_t *solid = (uint8_t *)malloc(ylen);
    /* (d) 灰阶斜坡：Y 随 x 线性、U=V=128。解码应是水平灰阶渐变。 */
    uint8_t *ramp = (uint8_t *)malloc(ylen);
    if (!solid || !ramp) { free(noise); free(grad); return 2; }
    for (uint32_t y = 0; y < h; y++) {
        for (uint32_t x = 0; x < w; x += 2) {
            size_t o = ((size_t)y * w + x) * 2;
            solid[o + 0] = 128; solid[o + 1] = 128;
            solid[o + 2] = 128; solid[o + 3] = 128;
            uint8_t yv = (uint8_t)((x * 255) / (w - 1));
            ramp[o + 0] = yv; ramp[o + 1] = 128;
            ramp[o + 2] = yv; ramp[o + 3] = 128;
        }
    }

    /* (e) 平坦但非零：Y=200 Cb=100 Cr=150。
     *     纯灰帧(128)的输入块全为 0，对任何 DC 缩放因子都不敏感——它证明
     *     不了亮度/色度的绝对值。这一帧才是"DC 归一化因子是否正确"的判据。 */
    uint8_t *flat = (uint8_t *)malloc(ylen);
    if (!flat) { free(noise); free(grad); return 2; }
    for (size_t i = 0; i < ylen; i += 4) {
        flat[i + 0] = 140; flat[i + 1] = 64;
        flat[i + 2] = 140; flat[i + 3] = 200;
    }

    int rc = 0;
    rc |= dump(dir, "frame_flat", flat, ylen, w, h);
    rc |= dump(dir, "frame_noise", noise, ylen, w, h);
    rc |= dump(dir, "frame_gradient", grad, ylen, w, h);
    rc |= dump(dir, "frame_solid", solid, ylen, w, h);
    rc |= dump(dir, "frame_ramp", ramp, ylen, w, h);

    free(noise); free(grad); free(solid); free(ramp); free(flat);
    return rc;
}
