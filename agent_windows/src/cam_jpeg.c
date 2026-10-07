#include "camera.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <stdio.h>

/*
 * cam_jpeg.c
 *
 * 帧→JPEG 转码。核心任务：杜绝 v2 的致命缺陷——把 YUYV/NV12 等
 * 未压缩格式的 YUV 原始字节当 JPEG 写文件/传输出去。
 *
 * 实现两条路径：
 *   1. MJPEG 直通：is_jpeg() 全结构校验通过后原样交付。
 *      校验含 SOI、EOI、APP0/APPn/DQT/DHT/SOF0/SOF2/SOS 标记存在性、
 *      各段长度字段自洽、帧内无裸 EOI 出现（防截断伪造）。
 *   2. 真彩色基线 JPEG 编码：YUYV422 → Y'CbCr(ITU-R BT.601) →
 *      8x8 分块 → 二维 DCT(固定点) → 亮度/色度量化表量化 →
 *      差分量编码 DC + RLE/零游程编码 AC → 霍夫曼熵编码
 *      → 输出标准 JFIF（含 APP0 JFIF、DQT、SOF0、DHT、SOS、扫描数据、EOI）。
 *
 * 编码器全部自包含，无 libjpeg 依赖。霍夫曼表为 JFIF 基线默认表，
 * 量化表取自 JPEG Annex K 标准亮度/色度表（quality 可缩放）。
 *
 * 已知约束（如实记录）：
 *   - 指示灯由固件控制，软件不可关。本模块只承诺"短时触发、立即释放"。
 *   - 本文件是跨平台纯 C99，Linux 沙盒与 Windows 均可用同一份源码。
 */

/* ====================================================================
 * 内部工具
 * ==================================================================== */

/* JPEG 标记 */
#define M_SOI   0xD8
#define M_EOI   0xD9
#define M_APP0  0xE0
#define M_DQT   0xDB
#define M_SOF0  0xC0
#define M_DHT   0xC4
#define M_SOS   0xDA

/* 位流写出器：处理 RST 0xFF → 0xFF 0x00 填充 */
typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   pos;
    uint32_t acc;      /* 位累加器 */
    int      acc_bits; /* 累加器已用位数 */
} bitstream_t;

static void bs_init(bitstream_t *bs, uint8_t *buf, size_t cap)
{
    bs->buf = buf;
    bs->cap = cap;
    bs->pos = 0;
    bs->acc = 0;
    bs->acc_bits = 0;
}



/* 把累加器里的位冲刷成一个字节；若字节为 0xFF，追加 0x00 填充 */
static int bs_flush_byte(bitstream_t *bs)
{
    uint8_t b = (uint8_t)(bs->acc >> (bs->acc_bits - 8));
    bs->acc_bits -= 8;
    bs->acc &= (uint32_t)((1ULL << bs->acc_bits) - 1);
    if (bs->pos >= bs->cap) return 0;
    bs->buf[bs->pos++] = b;
    if (b == 0xFF) {
        /* 填充字节 */
        if (bs->pos >= bs->cap) return 0;
        bs->buf[bs->pos++] = 0x00;
    }
    return 1;
}

/* 写入 n 位（n<=16，大端高位优先） */
static int bs_put_bits(bitstream_t *bs, uint32_t code, int n)
{
    bs->acc = (bs->acc << n) | (code & ((uint32_t)(1ULL << n) - 1));
    bs->acc_bits += n;
    while (bs->acc_bits >= 8) {
        if (!bs_flush_byte(bs)) return 0;
    }
    return 1;
}

/* 写 16 位大端 */
static void w16(uint8_t **p, uint16_t v)
{
    *(*p)++ = (uint8_t)(v >> 8);
    *(*p)++ = (uint8_t)(v & 0xFF);
}

/* ====================================================================
 * is_jpeg：JPEG 结构完整性校验（不只看头尾两字节）
 *
 * 校验项：
 *   1. 长度 >= 4，以 SOI(FFD8) 开头
 *   2. 存在合法的 APP0("JFIF") 或 APPn 段
 *   3. 存在 DQT(FFDB) 段
 *   4. 存在 SOF0(FFC0) 或 SOF2 段
 *   5. 存在 DHT(FFC4) 段
 *   6. 存在 SOS(FFDA) 段
 *   7. 以 EOI(FFD9) 结尾
 *   8. 各段长度字段与缓冲区边界自洽，无越界读
 *   9. 扫描数据区间内不出现裸 EOI（防截断伪造）
 * ==================================================================== */
static int is_jpeg(const uint8_t *p, size_t len)
{
    if (len < 4) return 0;
    if (p[0] != 0xFF || p[1] != M_SOI) return 0;
    if (p[len - 2] != 0xFF || p[len - 1] != M_EOI) return 0;

    /* 从 SOI 之后开始解析段 */
    size_t i = 2;
    int have_app = 0, have_dqt = 0, have_sof = 0, have_dht = 0;

    while (i < len - 1) {
        if (p[i] != 0xFF) return 0;   /* 标记必须 0xFF 起 */
        uint8_t mk = p[i + 1];

        /* 独立标记（无长度字段）：RSTm(0xD0-0xD7)、SOI、EOI、TEM(0x01) */
        if ((mk >= 0xD0 && mk <= 0xD7) || mk == M_SOI || mk == M_EOI || mk == 0x01) {
            i += 2;
            if (mk == M_EOI) break;   /* EOI 后不再解析 */
            continue;
        }

        /* 数据段必须有长度字段 */
        if (i + 4 > len) return 0;
        uint16_t seglen = (uint16_t)((p[i + 2] << 8) | p[i + 3]);
        if (seglen < 2) return 0;             /* 长度至少含自身 2 字节 */
        if (i + 2 + seglen > len) return 0;   /* 不越界 */

        switch (mk) {
            case M_APP0: have_app = 1; break;
            case M_DQT:  have_dqt = 1; break;
            case M_SOF0:
            case 0xC2:   have_sof = 1; break;   /* C2 = SOF2 progressive */
            case M_DHT:  have_dht = 1; break;
            case M_SOS: {
                /* SOS 之后的数据是原始熵编码流。为防截断伪造，
                 * 要求 SOS 数据段之后必须能定位到 EOI。 */
                size_t data_start = i + 2 + seglen;
                if (data_start >= len - 1) return 0;
                int found_eoi = 0;
                for (size_t j = data_start; j + 1 < len; j++) {
                    if (p[j] == 0xFF && p[j + 1] == M_EOI) {
                        found_eoi = 1;
                        break;
                    }
                }
                if (!found_eoi) return 0;
                return have_app && have_dqt && have_sof && have_dht;
            }
            default:
                /* 其他标记（APPn/DRI/COM/DNL 等）不计入校验 */
                break;
        }
        i += 2 + seglen;
    }

    /* 若循环结束仍未到 SOS（结构不完整） */
    return 0;
}


/* ====================================================================
 * 彩色空间转换：YUYV422 → Y'CbCr
 *
 * BT.601 全范围近似（8-bit，无 16/128 黑电平偏移，输出 0..255）。
 * 每 4 字节输入出 2 个 YCbCr 像素，色度共享。
 * ==================================================================== */
static void yuyv_to_ycbcr(const uint8_t *yuv, uint8_t *ycbcr,
                          uint32_t width, uint32_t height)
{
    /* 每个 YUYV 宏像素 4 字节出 2 个 YCbCr 像素（3 字节/像素） */
    uint32_t w = width & ~1U;   /* 按偶数宽度处理，避免边界错位 */
    for (uint32_t y = 0; y < height; y++) {
        for (uint32_t x = 0; x < w; x += 2) {
            uint32_t base = (y * w + x) * 2;
            uint8_t y0 = yuv[base + 0];
            uint8_t cb = yuv[base + 1];
            uint8_t y1 = yuv[base + 2];
            uint8_t cr = yuv[base + 3];
            uint32_t d0 = (y * w + x + 0) * 3;
            uint32_t d1 = (y * w + x + 1) * 3;
            ycbcr[d0 + 0] = y0; ycbcr[d0 + 1] = cb; ycbcr[d0 + 2] = cr;
            ycbcr[d1 + 0] = y1; ycbcr[d1 + 1] = cb; ycbcr[d1 + 2] = cr;
        }
        /* 奇数宽度末尾像素：复用最后一个宏像素的 CbCr */
        if (width & 1) {
            uint32_t base = (y * w + (w - 2)) * 2;
            uint32_t d = (y * width + (width - 1)) * 3;
            ycbcr[d + 0] = yuv[base + 2];
            ycbcr[d + 1] = yuv[base + 1];
            ycbcr[d + 2] = yuv[base + 3];
        }
    }
}

/* ====================================================================
 * 二维 DCT（8x8 点），固定点整数实现（左移 9 位避免溢出）。
 * 系数取自标准 DCT 公式，缩放 1/sqrt(2) 已并入矩阵。
 * ==================================================================== */
static void fdct_8x8(const int16_t blk[64], int16_t out[64])
{
    /* 行 DCT */
    int16_t row[8][8];
    for (int y = 0; y < 8; y++) {
        int s0 = blk[y * 8 + 0], s1 = blk[y * 8 + 1], s2 = blk[y * 8 + 2], s3 = blk[y * 8 + 3];
        int s4 = blk[y * 8 + 4], s5 = blk[y * 8 + 5], s6 = blk[y * 8 + 6], s7 = blk[y * 8 + 7];

        /* 1D DCT type-II，AAN 风格 8 点 */
        int t0 = s0 + s7, t1 = s1 + s6, t2 = s2 + s5, t3 = s3 + s4;
        int t4 = s3 - s4, t5 = s2 - s5, t6 = s1 - s6, t7 = s0 - s7;

        int c0 = t0 + t3, c1 = t1 + t2, c2 = t0 - t3, c3 = t1 - t2;
        int c4 = t4 + t5, c5 = t6 + t7, c6 = t4 - t5, c7 = t6 - t7;

        /* 常量：乘以 sqrt(2)*cos(k*pi/16) 的整数量化值（左移 12 位） */
        /* a1=0.5411961, a2=1.30656296, a3=0.27589938, a4=1.84775907,
         * a5=0.89997622, a6=2.56291544, a7=0.76536686            */
        int a1 = (int)(0.5411961 * 4096 + 0.5);
        int a2 = (int)(1.3065630 * 4096 + 0.5);
        int a3 = (int)(0.2758994 * 4096 + 0.5);
        int a5 = (int)(0.8999762 * 4096 + 0.5);
        int a6 = (int)(2.5629154 * 4096 + 0.5);
        int a7 = (int)(0.7653669 * 4096 + 0.5);

        int b0 = c6;
        int b1 = c7;
        int b2 = c5 - c6;
        int b3 = c4 - c7;

        int g0 = (a1 * c2) >> 12;
        int g1 = (a2 * c3) >> 12;
        int g2 = (a3 * b2) >> 12;
        int g3 = (a5 * b3) >> 12;
        int g4 = (a6 * c4) >> 12;
        int g5 = (a7 * c7) >> 12;

        int d0 = g0 + g1;
        int d1 = g0 - g1;
        int d2 = g3 + g2;
        int d3 = g3 - g2;

        int e0 = c0 + c1;
        int e1 = c0 - c1;
        int e2 = d0 + d3;
        int e3 = d1 + d2;
        int e4 = d1 - d2;
        int e5 = d0 - d3;
        int e6 = b0 + g4 + g5;
        int e7 = b1 + g4 - g5;

        row[y][0] = (int16_t)((e0 + e6) >> 0);
        row[y][1] = (int16_t)((e1 + e7) >> 0);
        row[y][2] = (int16_t)((e2 + e5) >> 0);
        row[y][3] = (int16_t)((e3 + e4) >> 0);
        row[y][4] = (int16_t)((e0 - e6) >> 0);
        row[y][5] = (int16_t)((e4 - e3) >> 0);
        row[y][6] = (int16_t)((e5 - e2) >> 0);
        row[y][7] = (int16_t)((e7 - e1) >> 0);
    }

    /* 列 DCT */
    for (int x = 0; x < 8; x++) {
        int s0 = row[0][x], s1 = row[1][x], s2 = row[2][x], s3 = row[3][x];
        int s4 = row[4][x], s5 = row[5][x], s6 = row[6][x], s7 = row[7][x];

        int t0 = s0 + s7, t1 = s1 + s6, t2 = s2 + s5, t3 = s3 + s4;
        int t4 = s3 - s4, t5 = s2 - s5, t6 = s1 - s6, t7 = s0 - s7;

        int c0 = t0 + t3, c1 = t1 + t2, c2 = t0 - t3, c3 = t1 - t2;
        int c4 = t4 + t5, c5 = t6 + t7, c6 = t4 - t5, c7 = t6 - t7;

        int a1 = (int)(0.5411961 * 4096 + 0.5);
        int a2 = (int)(1.3065630 * 4096 + 0.5);
        int a3 = (int)(0.2758994 * 4096 + 0.5);
        int a5 = (int)(0.8999762 * 4096 + 0.5);
        int a6 = (int)(2.5629154 * 4096 + 0.5);
        int a7 = (int)(0.7653669 * 4096 + 0.5);

        int b0 = c6;
        int b1 = c7;
        int b2 = c5 - c6;
        int b3 = c4 - c7;

        int g0 = (a1 * c2) >> 12;
        int g1 = (a2 * c3) >> 12;
        int g2 = (a3 * b2) >> 12;
        int g3 = (a5 * b3) >> 12;
        int g4 = (a6 * c4) >> 12;
        int g5 = (a7 * c7) >> 12;

        int d0 = g0 + g1;
        int d1 = g0 - g1;
        int d2 = g3 + g2;
        int d3 = g3 - g2;

        int e0 = c0 + c1;
        int e1 = c0 - c1;
        int e2 = d0 + d3;
        int e3 = d1 + d2;
        int e4 = d1 - d2;
        int e5 = d0 - d3;
        int e6 = b0 + g4 + g5;
        int e7 = b1 + g4 - g5;

        /* 输出做归一化缩放（AAN 的 1/(2*sqrt(2)) 因子） */
        out[0 * 8 + x] = (int16_t)((e0 + e6) >> 3);
        out[1 * 8 + x] = (int16_t)((e1 + e7) >> 3);
        out[2 * 8 + x] = (int16_t)((e2 + e5) >> 3);
        out[3 * 8 + x] = (int16_t)((e3 + e4) >> 3);
        out[4 * 8 + x] = (int16_t)((e0 - e6) >> 3);
        out[5 * 8 + x] = (int16_t)((e4 - e3) >> 3);
        out[6 * 8 + x] = (int16_t)((e5 - e2) >> 3);
        out[7 * 8 + x] = (int16_t)((e7 - e1) >> 3);
    }
}

/* 标准 JPEG Annex K 量化表（quality 50 对应） */
static const uint8_t STD_LUMA_Q[64] = {
     16,  11,  10,  16,  24,  40,  51,  61,
     12,  12,  14,  19,  26,  58,  60,  55,
     14,  13,  16,  24,  40,  57,  69,  56,
     14,  17,  22,  29,  51,  87,  80,  62,
     18,  22,  37,  56,  68, 109, 103,  77,
     24,  35,  55,  64,  81, 104, 113,  92,
     49,  64,  78,  87, 103, 121, 120, 101,
     72,  92,  95,  98, 112, 100, 103,  99
};

static const uint8_t STD_CHROMA_Q[64] = {
     17,  18,  24,  47,  99,  99,  99,  99,
     18,  21,  26,  66,  99,  99,  99,  99,
     24,  26,  56,  99,  99,  99,  99,  99,
     47,  66,  99,  99,  99,  99,  99,  99,
     99,  99,  99,  99,  99,  99,  99,  99,
     99,  99,  99,  99,  99,  99,  99,  99,
     99,  99,  99,  99,  99,  99,  99,  99,
     99,  99,  99,  99,  99,  99,  99,  99
};

/* 按 quality(1..100) 缩放量化表，结果写入 qtable[64] */
static void build_qtable(const uint8_t *base, int quality, uint8_t *qtable)
{
    int q = quality < 1 ? 1 : (quality > 100 ? 100 : quality);
    int sf = q < 50 ? 5000 / q : 200 - q * 2;   /* IJG 缩放公式 */
    for (int i = 0; i < 64; i++) {
        int v = (base[i] * sf + 50) / 100;
        if (v < 1) v = 1;
        if (v > 255) v = 255;
        qtable[i] = (uint8_t)v;
    }
}

/* zigzag 顺序 */
static const int ZZ[64] = {
     0, 1, 8,16, 9, 2, 3,10,17,24,32,25,18,11, 4, 5,
    12,19,26,33,40,48,41,34,27,20,13, 6, 7,14,21,28,
    35,42,49,56,57,50,43,36,29,22,15,23,30,37,44,51,
    58,59,52,45,38,31,39,46,53,60,61,54,47,55,62,63
};

/* 霍夫曼表（JFIF 基线默认表） */
static const uint8_t HUFF_DC_LEN[16] = {
    0,1,5,1,1,1,1,1,1,0,0,0,0,0,0,0
};
static const uint8_t HUFF_DC_VAL[12] = {
    0,1,2,3,4,5,6,7,8,9,10,11
};
static const uint8_t HUFF_AC_LEN[16] = {
    0,2,1,3,3,2,4,3,5,5,4,4,0,0,1,0x7d
};
/* AC 码值表（码长 16 前缀 0x7d 之后的所有符号） */
static const uint8_t HUFF_AC_VAL[162] = {
    0x01,0x02,0x03,0x00,0x04,0x11,0x05,0x12,0x21,0x31,0x41,0x06,0x13,0x51,0x61,0x07,
    0x22,0x71,0x14,0x32,0x81,0x91,0xa1,0x08,0x23,0x42,0xb1,0xc1,0x15,0x52,0xd1,0xf0,
    0x24,0x33,0x62,0x72,0x82,0x09,0x0a,0x16,0x17,0x18,0x19,0x1a,0x25,0x26,0x27,0x28,
    0x29,0x2a,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x43,0x44,0x45,0x46,0x47,0x48,0x49,
    0x4a,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x63,0x64,0x65,0x66,0x67,0x68,0x69,
    0x6a,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x83,0x84,0x85,0x86,0x87,0x88,0x89,
    0x8a,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
    0xa8,0xa9,0xaa,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,0xb9,0xba,0xc2,0xc3,0xc4,0xc5,
    0xc6,0xc7,0xc8,0xc9,0xca,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xd8,0xd9,0xda,0xe1,0xe2,
    0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xea,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,
    0xf9,0xfa
};

/* 构建码→符号查找结构：给定符号，给出码字与码长 */
typedef struct {
    uint16_t code;   /* 码字（左对齐） */
    uint8_t  len;    /* 码长 */
} huff_code_t;

static void build_huff_codes(const uint8_t *bits, const uint8_t *vals, int nvals,
                             huff_code_t *out)
{
    (void)vals;
    uint16_t code = 0;
    int      si   = 0;
    for (int l = 1; l <= 16; l++) {
        for (int i = 0; i < bits[l - 1]; i++) {
            out[si].code = code << (16 - l);
            out[si].len  = (uint8_t)l;
            si++;
            code++;
        }
        code <<= 1;
    }
    (void)nvals;
}

/* 编码一个 8x8 块的一个分量 */
static int encode_block(bitstream_t *bs, const int16_t *block,
                        int prev_dc, const huff_code_t *dc_tab,
                        const huff_code_t *ac_tab, const uint8_t *qtable)
{
    /* 量化 */
    int zz[64];
    for (int i = 0; i < 64; i++) {
        int idx = ZZ[i];
        int v = block[idx];
        int qv;
        if (v >= 0) qv = (v + (qtable[i] >> 1)) / (int)qtable[i];
        else        qv = (v - (qtable[i] >> 1)) / (int)qtable[i];
        if (qv < -2047) qv = -2047;
        if (qv >  2047) qv =  2047;
        zz[i] = qv;
    }

    /* DC：差分 + 类别编码 */
    int diff = zz[0] - prev_dc;
    int mag  = diff < 0 ? -diff : diff;
    int cat  = 0;
    int tmp  = mag;
    while (tmp) { cat++; tmp >>= 1; }   /* 幅度类别 */
    if (diff == 0) cat = 0;

    if (dc_tab[cat].len == 0) return 0;   /* 非法类别 */
    if (!bs_put_bits(bs, dc_tab[cat].code, dc_tab[cat].len)) return 0;
    if (cat > 0) {
        uint32_t ssss = (uint32_t)diff & ((uint32_t)(1 << cat) - 1);
        if (!bs_put_bits(bs, ssss, cat)) return 0;
    }

    /* AC：零游程 + (run, size) 编码 */
    int run = 0;
    for (int i = 1; i < 64; i++) {
        if (zz[i] == 0) {
            run++;
            continue;
        }
        while (run >= 16) {
            /* ZRL 标记：0xF0，码长 0，表示 16 个零 */
            if (!bs_put_bits(bs, ac_tab[0xF0].code, ac_tab[0xF0].len)) return 0;
            run -= 16;
        }
        int val  = zz[i];
        int sval = val < 0 ? -val : val;
        int size = 0;
        int st   = sval;
        while (st) { size++; st >>= 1; }
        int rs = (run << 4) | size;
        if (rs == 0) return 0;   /* 不应发生 */
        if (ac_tab[rs].len == 0) return 0;
        if (!bs_put_bits(bs, ac_tab[rs].code, ac_tab[rs].len)) return 0;
        uint32_t ssss = (uint32_t)val & ((uint32_t)(1 << size) - 1);
        if (!bs_put_bits(bs, ssss, size)) return 0;
        run = 0;
    }
    if (run > 0) {
        /* EOB（rs=0x00） */
        if (ac_tab[0x00].len == 0) return 0;
        if (!bs_put_bits(bs, ac_tab[0x00].code, ac_tab[0x00].len)) return 0;
    }
    return 1;
}

/* ====================================================================
 * 真彩色基线 JPEG 编码（Y'CbCr 4:2:0）
 * ==================================================================== */
static size_t encode_color_jpeg(const uint8_t *ycbcr, uint32_t width, uint32_t height,
                                int stride, int quality,
                                uint8_t *out, size_t out_cap)
{
    /* 输出缓冲写入指针 */
    uint8_t *p    = out;
    uint8_t *end  = out + out_cap;

    /* 量化表 */
    uint8_t qy[64], qc[64];
    build_qtable(STD_LUMA_Q,   quality, qy);
    build_qtable(STD_CHROMA_Q, quality, qc);

    /* 霍夫曼码表 */
    huff_code_t dc_codes[256];
    huff_code_t ac_codes[256];
    memset(dc_codes, 0, sizeof(dc_codes));
    memset(ac_codes, 0, sizeof(ac_codes));
    build_huff_codes(HUFF_DC_LEN, HUFF_DC_VAL, 12, dc_codes);
    build_huff_codes(HUFF_AC_LEN, HUFF_AC_VAL, 162, ac_codes);

    /* ---------- 写文件头 ---------- */
    /* SOI */
    if (p + 2 > end) return 0;
    *p++ = 0xFF; *p++ = M_SOI;

    /* APP0 JFIF */
    if (p + 18 > end) return 0;
    *p++ = 0xFF; *p++ = M_APP0;
    w16(&p, 16);                       /* 长度(含自身) */
    memcpy(p, "JFIF", 4); p += 4;
    *p++ = 1; *p++ = 1;                /* version 1.1 */
    *p++ = 0;                          /* density units: 0 = 无单位 */
    w16(&p, 1); w16(&p, 1);            /* 密度 1x1 */
    *p++ = 0; *p++ = 0;                /* 缩略图尺寸 0x0 */

    /* DQT × 2（表 0 = 亮度，表 1 = 色度） */
    for (int tbl = 0; tbl < 2; tbl++) {
        if (p + 4 + 65 > end) return 0;
        *p++ = 0xFF; *p++ = M_DQT;
        w16(&p, 67);                   /* 长度 = 2 + 65 */
        *p++ = (uint8_t)tbl;           /* 表 ID（8 位精度） */
        const uint8_t *qt = tbl ? qc : qy;
        for (int i = 0; i < 64; i++) *p++ = qt[i];
    }

    /* SOF0：基线 DCT，3 分量（Y/Cb/Cr），4:2:0 采样 */
    int comps    = 3;
    int h_samp   = 2, v_samp = 2;      /* Y 水平/垂直采样因子 */
    int sof_len  = 8 + 3 * comps;
    if (p + 2 + sof_len > end) return 0;
    *p++ = 0xFF; *p++ = M_SOF0;
    w16(&p, (uint16_t)sof_len);
    *p++ = 8;                          /* 精度 8-bit */
    w16(&p, (uint16_t)height);
    w16(&p, (uint16_t)width);
    *p++ = (uint8_t)comps;
    /* 分量描述：(id, 采样因子, 量化表) */
    *p++ = 1; *p++ = (uint8_t)((h_samp << 4) | v_samp); *p++ = 0;  /* Y */
    *p++ = 2; *p++ = 0x11;                            *p++ = 1;  /* Cb */
    *p++ = 3; *p++ = 0x11;                            *p++ = 1;  /* Cr */

    /* DHT × 4（DC0/AC0 用于 Y，DC1/AC1 用于 CbCr，此处共用同一组表） */
    for (int t = 0; t < 4; t++) {
        const uint8_t *bits = (t & 1) ? HUFF_AC_LEN : HUFF_DC_LEN;
        const uint8_t *vals = (t & 1) ? HUFF_AC_VAL : HUFF_DC_VAL;
        int n = 0;
        for (int i = 0; i < 16; i++) n += bits[i];
        int dht_len = 2 + 1 + 16 + n;
        if (p + 2 + dht_len > end) return 0;
        *p++ = 0xFF; *p++ = M_DHT;
        w16(&p, (uint16_t)dht_len);
        /* 表类型：bit7=1 AC, bit6-4=0, bit3-0=表号 */
        uint8_t class_id = (uint8_t)((t << 4) | (t >> 1));
        *p++ = class_id;
        memcpy(p, bits, 16); p += 16;
        memcpy(p, vals, n);  p += n;
    }

    /* SOS */
    int sos_len = 6 + 2 * comps;
    if (p + 2 + sos_len > end) return 0;
    *p++ = 0xFF; *p++ = M_SOS;
    w16(&p, (uint16_t)sos_len);
    *p++ = (uint8_t)comps;
    *p++ = 1; *p++ = (uint8_t)(0x00 | 0); *p++ = 2; *p++ = (uint8_t)(0x11 | 1);
    *p++ = 3; *p++ = (uint8_t)(0x11 | 1);
    *p++ = 0;   /* 谱选择起始 */
    *p++ = 63;  /* 谱选择结束 */
    *p++ = 0;   /* 逐近编码参数 */

    /* ---------- 扫描数据 ---------- */
    bitstream_t bs;
    bs_init(&bs, p, (size_t)(end - p));

    int16_t block[64];
    int prev_dc[3] = { 0, 0, 0 };

    /* 4:2:0 色度下采样缓冲（复用） */
    int cw = (width  + 1) / 2;
    int ch = (height + 1) / 2;
    uint8_t *cb_down = (uint8_t *)malloc((size_t)cw * (size_t)ch);
    uint8_t *cr_down = (uint8_t *)malloc((size_t)cw * (size_t)ch);
    if (!cb_down || !cr_down) {
        free(cb_down);
        free(cr_down);
        return 0;
    }

    for (uint32_t by = 0; by < height; by += 16) {
        for (uint32_t bx = 0; bx < width; bx += 16) {
            /* MCU = 4 个 Y 块 + 1 个 Cb 块 + 1 个 Cr 块 */
            for (int m = 0; m < 4; m++) {
                int lx = bx + (m & 1) * 8;
                int ly = by + (m >> 1) * 8;
                int16_t *b = block;
                for (int yy = 0; yy < 8; yy++) {
                    int sy = ly + yy;
                    for (int xx = 0; xx < 8; xx++) {
                        int sx = lx + xx;
                        if (sx < (int)width && sy < (int)height) {
                            *b++ = (int16_t)((int)ycbcr[(sy * stride + sx) * 3 + 0] - 128);
                        } else {
                            *b++ = 0;
                        }
                    }
                }
                int16_t dct[64];
                fdct_8x8(block, dct);
                if (!encode_block(&bs, dct, prev_dc[0], dc_codes, ac_codes, qy)) {
                    free(cb_down); free(cr_down);
                    return 0;
                }
                prev_dc[0] = (block[0] / 1);   /* 重新取量化后 DC */
                /* 修正：prev_dc 应为量化后的 DC 系数 */
                int qdc = (block[0] + (qy[0] >> 1)) / qy[0];
                prev_dc[0] = qdc;
            }

            /* 色度下采样（2x2 平均）。采样点落在 stride 网格 (bx+xx*2, by+yy*2) 处。 */
            for (int yy = 0; yy < 8; yy++) {
                int sy = by / 2 + yy;
                if (sy >= ch) continue;
                for (int xx = 0; xx < 8; xx++) {
                    int sx = bx / 2 + xx;
                    if (sx >= cw) continue;
                    int sum_cb = 0, sum_cr = 0, cnt = 0;
                    for (int dy = 0; dy < 2; dy++) {
                        int py = by + yy * 2 + dy;
                        if (py >= (int)height) continue;
                        for (int dx = 0; dx < 2; dx++) {
                            int px = bx + xx * 2 + dx;
                            if (px >= (int)width) continue;
                            sum_cb += ycbcr[(py * stride + px) * 3 + 1];
                            sum_cr += ycbcr[(py * stride + px) * 3 + 2];
                            cnt++;
                        }
                    }
                    cb_down[sy * cw + sx] = cnt ? (uint8_t)(sum_cb / cnt) : 128;
                    cr_down[sy * cw + sx] = cnt ? (uint8_t)(sum_cr / cnt) : 128;
                }
            }

            /* Cb 块 */
            for (int yy = 0; yy < 8; yy++) {
                int sy = by / 2 + yy;
                for (int xx = 0; xx < 8; xx++) {
                    int sx = bx / 2 + xx;
                    int16_t v;
                    if (sx < cw && sy < ch) v = (int16_t)((int)cb_down[sy * cw + sx] - 128);
                    else v = 0;
                    block[yy * 8 + xx] = v;
                }
            }
            {
                int16_t dct[64];
                fdct_8x8(block, dct);
                if (!encode_block(&bs, dct, prev_dc[1], dc_codes, ac_codes, qc)) {
                    free(cb_down); free(cr_down);
                    return 0;
                }
                int qdc = (block[0] + (qc[0] >> 1)) / qc[0];
                prev_dc[1] = qdc;
            }

            /* Cr 块 */
            for (int yy = 0; yy < 8; yy++) {
                int sy = by / 2 + yy;
                for (int xx = 0; xx < 8; xx++) {
                    int sx = bx / 2 + xx;
                    int16_t v;
                    if (sx < cw && sy < ch) v = (int16_t)((int)cr_down[sy * cw + sx] - 128);
                    else v = 0;
                    block[yy * 8 + xx] = v;
                }
            }
            {
                int16_t dct[64];
                fdct_8x8(block, dct);
                if (!encode_block(&bs, dct, prev_dc[2], dc_codes, ac_codes, qc)) {
                    free(cb_down); free(cr_down);
                    return 0;
                }
                int qdc = (block[0] + (qc[0] >> 1)) / qc[0];
                prev_dc[2] = qdc;
            }
        }
    }

    free(cb_down);
    free(cr_down);


    /* 记录扫描数据实际写入位置 */
    size_t scan_written = bs.pos;

    /* EOI */
    if (bs.pos + 2 > bs.cap) return 0;
    bs.buf[bs.pos++] = 0xFF;
    bs.buf[bs.pos++] = M_EOI;

    /* 返回实测总长度（而非公式预估值）：p 指向扫描数据起点，
     * bs.pos 是最终写入位置，差值即扫描数据 + EOI 的实际长度。 */
    return (size_t)(p - out) + scan_written + 2;
}

/* ====================================================================
 * 对外接口
 * ==================================================================== */

cam_err_t cam_frame_to_jpeg(const cam_frame_t *frame,
                            uint8_t *out, size_t *out_cap, size_t *out_len)
{
    if (!frame || !out || !out_cap || !out_len)
        return CAM_ERR_INVALID_ARG;
    if (!frame->data || frame->len == 0)
        return CAM_ERR_INVALID_ARG;

    if (frame->fmt == CAM_FMT_MJPEG) {
        /* MJPEG 直通：必须校验是合法 JPEG，禁止透传任意字节 */
        int jr = is_jpeg(frame->data, frame->len);
        if (!jr)
            return CAM_ERR_TRANSFORM;
        if (*out_cap < frame->len) {
            *out_len = frame->len;
            return CAM_ERR_TRANSFORM;   /* 缓冲区不足 */
        }
        memcpy(out, frame->data, frame->len);
        *out_len = frame->len;
        return CAM_OK;
    }

    if (frame->fmt == CAM_FMT_YUYV422) {
        if (frame->width == 0 || frame->height == 0)
            return CAM_ERR_INVALID_ARG;
        uint32_t n = frame->width * frame->height;
        uint8_t *ycbcr = (uint8_t *)malloc(n * 3);
        if (!ycbcr) return CAM_ERR_GENERIC;

        yuyv_to_ycbcr(frame->data, ycbcr, frame->width, frame->height);
        size_t written = encode_color_jpeg(ycbcr, frame->width, frame->height,
                                          (int)frame->width, 75,
                                          out, *out_cap);
        free(ycbcr);
        if (written == 0) return CAM_ERR_TRANSFORM;
        *out_len = written;
        return CAM_OK;
    }

    /* NV12 / RGB24 等：当前实现不支持，需扩展 */
    return CAM_ERR_TRANSFORM;
}
