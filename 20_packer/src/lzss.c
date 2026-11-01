/*
 * DAYANJING v4 — 20_packer / lzss.c
 *
 * 自研 LZSS：窗口 4096，匹配长度 3..18。
 *
 * 位流格式（LSB-first 打包成字节）：
 *   1 bit  -> 字面量，后跟 8 bit 原字节
 *   0 bit  -> 匹配，后跟 12 bit 距离 + 4 bit (长度-3)
 *
 * 选择 LZSS 而非 Huffman/LZMA 的理由：
 *   - 解压器可在 200 行内实现，能整体嵌入 stub，无外部依赖
 *   - 解压是纯流式，不需要字典预置，适合就地解码到 RWX 缓冲
 *   - 对 ELF/PE 这类含大量零段与重复重定位项的二进制，压缩率足够
 *
 * 不依赖 zlib。
 */

#include "packer.h"

#include <string.h>

/* ---------- 位流写入器 ---------- */

typedef struct {
    uint8_t  *out;
    size_t    cap;
    size_t    pos;      /* 已写字节数 */
    uint32_t  acc;      /* 位累积器 */
    int       nbits;    /* acc 中有效位数 */
    int       ovf;      /* 容量溢出标记 */
} bitw_t;

static void bw_init(bitw_t *b, uint8_t *out, size_t cap)
{
    b->out = out; b->cap = cap; b->pos = 0;
    b->acc = 0; b->nbits = 0; b->ovf = 0;
}

static void bw_put(bitw_t *b, uint32_t val, int n)
{
    if (b->ovf) return;
    b->acc |= (val & ((1u << n) - 1u)) << b->nbits;
    b->nbits += n;
    while (b->nbits >= 8) {
        if (b->pos >= b->cap) { b->ovf = 1; return; }
        b->out[b->pos++] = (uint8_t)(b->acc & 0xffu);
        b->acc >>= 8;
        b->nbits -= 8;
    }
}

static int bw_flush(bitw_t *b, size_t *out_len)
{
    if (b->ovf) { *out_len = 0; return PK_ERR_NOMEM; }
    if (b->nbits > 0) {
        if (b->pos >= b->cap) { *out_len = 0; return PK_ERR_NOMEM; }
        b->out[b->pos++] = (uint8_t)(b->acc & 0xffu);
        b->acc = 0; b->nbits = 0;
    }
    *out_len = b->pos;
    return PK_OK;
}

/* ---------- 位流读取器 ---------- */

typedef struct {
    const uint8_t *in;
    size_t   len;
    size_t   pos;
    uint32_t acc;
    int      nbits;
} bitr_t;

static void br_init(bitr_t *b, const uint8_t *in, size_t len)
{
    b->in = in; b->len = len; b->pos = 0; b->acc = 0; b->nbits = 0;
}

/* 返回 0/1 的位值；流耗尽返回 -1
 * 必须与 bw_put 的 LSB-first 顺序一致：先写的位在最低位。 */
static int br_get1(bitr_t *b)
{
    if (b->nbits == 0) {
        if (b->pos >= b->len) return -1;
        b->acc = b->in[b->pos++];
        b->nbits = 8;
    }
    b->nbits--;
    {
        int bit = (int)(b->acc & 1u);
        b->acc >>= 1;
        return bit;
    }
}

/* 读取 n 位（n<=24）；不足返回 -1
 * 位流为 LSB-first：第 i 个读到的位即数值的第 i 位。 */
static int br_getn(bitr_t *b, int n)
{
    uint32_t v = 0;
    for (int i = 0; i < n; i++) {
        int bit = br_get1(b);
        if (bit < 0) return -1;
        v |= (uint32_t)bit << i;
    }
    return (int)v;
}

/* ==================================================================== */

int pk_lzss_compress(const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t *out_len)
{
    bitw_t bw;
    size_t pos = 0;

    if (!in || !out || !out_len) return PK_ERR_ARG;
    if (*out_len < 8u) return PK_ERR_NOMEM;
    if (in_len == 0) { *out_len = 0; return PK_OK; }

    /* 8 字节 LE 前缀：原始长度，使解压端自描述且可先验容量 */
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)((in_len >> (8 * i)) & 0xffu);

    bw_init(&bw, out + 8, *out_len - 8u);

    while (pos < in_len) {
        size_t best_off = 0;
        size_t best_len = 0;
        /* 距离字段 12 位，上限 PK_LZSS_MAX_OFF，不得越界 */
        size_t wstart = (pos > PK_LZSS_MAX_OFF) ? (pos - PK_LZSS_MAX_OFF) : 0;
        size_t j;

        for (j = wstart; j < pos; j++) {
            size_t l = 0;
            while (l < PK_LZSS_MAX_MATCH && pos + l < in_len &&
                   in[j + l] == in[pos + l]) {
                l++;
            }
            if (l > best_len) {
                best_len = l;
                best_off = pos - j;
                if (l == PK_LZSS_MAX_MATCH) break;
            }
        }

        if (best_len >= PK_LZSS_MIN_MATCH) {
            bw_put(&bw, 0u, 1);
            bw_put(&bw, (uint32_t)best_off, 12);
            bw_put(&bw, (uint32_t)(best_len - PK_LZSS_MIN_MATCH), 4);
            pos += best_len;
        } else {
            bw_put(&bw, 1u, 1);
            bw_put(&bw, in[pos], 8);
            pos += 1;
        }
        if (bw.ovf) { *out_len = 0; return PK_ERR_NOMEM; }
    }

    {
        size_t blen = 0;
        int rc = bw_flush(&bw, &blen);
        if (rc != PK_OK) { *out_len = 0; return rc; }
        *out_len = 8u + blen;
        return PK_OK;
    }
}

int pk_lzss_decompress(const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t *out_len)
{
    bitr_t br;
    size_t opos = 0;
    size_t expect = 0;

    if (!in || !out || !out_len) return PK_ERR_ARG;
    if (in_len == 0) { *out_len = 0; return PK_OK; }
    if (in_len < 8u) return PK_ERR_CORRUPT;   /* 前缀不完整 */

    for (int i = 0; i < 8; i++)
        expect |= (uint64_t)in[i] << (8 * i);
    if (expect == 0) { *out_len = 0; return PK_OK; }
    if (*out_len < expect) return PK_ERR_NOMEM;

    br_init(&br, in + 8, in_len - 8u);

    /* 以 expect 为终止条件，避免最后一个字节的填充位被解成数据 */
    while (opos < expect) {
        int flag = br_get1(&br);
        if (flag < 0) return PK_ERR_CORRUPT;
        if (flag == 1) {
            int c = br_getn(&br, 8);
            if (c < 0) return PK_ERR_CORRUPT;
            out[opos++] = (uint8_t)c;
        } else {
            int off = br_getn(&br, 12);
            int extra = br_getn(&br, 4);
            size_t len;
            size_t src;
            size_t i;
            if (off < 0 || extra < 0) return PK_ERR_CORRUPT;
            len = (size_t)extra + PK_LZSS_MIN_MATCH;
            src = opos - (size_t)off;
            if ((size_t)off > opos) return PK_ERR_CORRUPT;   /* 引用越界 */
            if (opos + len > expect) return PK_ERR_CORRUPT;  /* 超出声明长度 */
            for (i = 0; i < len; i++) {
                out[opos] = out[src + i];
                opos++;
            }
        }
    }

    *out_len = opos;
    return PK_OK;
}
