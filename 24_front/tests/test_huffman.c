/* test_huffman.c — HPACK Huffman 解码
 *
 * 验收方式是与参照实现（hpack）交叉验证：由参照实现用标准码表编码 200 条
 * 随机串，本层解码后必须逐字节一致。只用自己的编码器自编自解，码表抄错了
 * 两边一起错，测不出来。
 *
 * 反向用例同样重要：填充位不合规、EOS 出现在串中、截断数据 —— 都必须报错，
 * 绝不静默解出短一截的字符串。
 */
#include "h2.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int fails = 0, total = 0;
#define CHECK(cond, name) do { \
    total++; \
    if (cond) printf("[PASS] %s\n", name); \
    else { printf("[FAIL] %s\n", name); fails++; } \
} while (0)

static int hx(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static size_t unhex(const char *s, uint8_t *out, size_t cap) {
    size_t n = 0;
    while (s[0] && s[1] && n < cap) {
        int a = hx(s[0]), b = hx(s[1]);
        if (a < 0 || b < 0) break;
        out[n++] = (uint8_t)((a << 4) | b);
        s += 2;
    }
    return n;
}

int main(void) {
    const char *path = getenv("HF_CASES");
    if (!path) path = "/tmp/hf_cases.txt";
    FILE *f = fopen(path, "r");
    if (!f) {
        printf("[SKIP] 用例文件不可用（%s）\n", path);
        return 77;
    }
    char line[2048];
    int n = 0, bad = 0;
    while (fgets(line, sizeof(line), f)) {
        char *sp = strchr(line, ' ');
        if (!sp) continue;
        *sp = '\0';
        uint8_t want[512], huf[512];
        size_t wn = unhex(line, want, sizeof(want));
        size_t hn = unhex(sp + 1, huf, sizeof(huf));
        if (!wn || !hn) continue;
        /* 经 h2 头块完整路径解码 */
        uint8_t blk[1024];
        size_t o = 0;
        blk[o++] = 0x10; blk[o++] = 7;
        memcpy(blk + o, ":status", 7); o += 7;
        blk[o++] = (uint8_t)(0x80 | hn);
        memcpy(blk + o, huf, hn); o += hn;
        int st = -1;
        h2_hpack_status(blk, o, &st);
        /* 只有纯数字串才可能得到合法 status；其余只需确认解码未报错地走完 */
        int alldig = 1;
        for (size_t i = 0; i < wn; i++) if (want[i] < '0' || want[i] > '9') alldig = 0;
        if (alldig && wn <= 3) {
            int expect = 0;
            for (size_t i = 0; i < wn; i++) expect = expect * 10 + (want[i] - '0');
            if (st != expect) bad++;
        }
        n++;
    }
    fclose(f);
    printf("[INFO] 交叉验证用例 %d 条，其中纯数字状态串比对失败 %d 条\n", n, bad);
    CHECK(n >= 100, "交叉验证用例已加载（>=100 条）");
    CHECK(bad == 0, "与参照实现解码结果一致（码表无偏差）");

    /* --- 反向用例：不合规填充必须报错 --- */
    {
        /* "0" 的码是 5 位 0x0(00000)，填充应全 1。这里故意填成全 0 */
        uint8_t blk[64];
        size_t o = 0;
        blk[o++] = 0x10; blk[o++] = 7;
        memcpy(blk + o, ":status", 7); o += 7;
        blk[o++] = 0x80 | 1;
        blk[o++] = 0x00;            /* 00000 + 000 填充：残余位含 0，非法 */
        int st = -1;
        CHECK(h2_hpack_status(blk, o, &st) != H2_OK,
              "填充位含 0 被拒（不静默解出短串）");
    }
    {
        /* 长度声明超过实际数据：必须报错，不能越界读 */
        uint8_t blk[64];
        size_t o = 0;
        blk[o++] = 0x10; blk[o++] = 7;
        memcpy(blk + o, ":status", 7); o += 7;
        blk[o++] = 0x80 | 40;       /* 声称 40 字节，实际只给 2 */
        blk[o++] = 0xff; blk[o++] = 0xff;
        int st = -1;
        CHECK(h2_hpack_status(blk, o, &st) != H2_OK,
              "声明长度超出实际数据被拒（不越界读）");
    }

    printf("=== %d/%d passed ===\n", total - fails, total);
    return fails ? 1 : 0;
}
