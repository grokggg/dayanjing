/* test_h2.c — HTTP/2 帧层与 HPACK
 *
 * 重点不是"能编出来"，而是三条硬规则真的成立：
 *   - :authority 必须是 never-indexed literal（0x1_ 前缀），不能被优化成索引
 *   - 编码结果能被独立实现解出同样的语义（跨实现验证，见 scripts/hpack_xcheck.py）
 *   - 容量不足 / 超长 / 短读 都要显式报错，绝不截断后返回 OK
 */
#include "h2.h"
#include <stdio.h>
#include <string.h>

static int fails = 0, total = 0;
#define CHECK(cond, name) do { \
    total++; \
    if (cond) printf("[PASS] %s\n", name); \
    else { printf("[FAIL] %s\n", name); fails++; } \
} while (0)

/* 自实现子串查找：memmem 是 GNU 扩展，在某些 libc/标准组合下需要 _GNU_SOURCE，
 * 隐式声明会让比较退化成指针与整数相比，断言静默失效。 */
static const uint8_t *find_sub(const uint8_t *hay, size_t hn, const char *needle) {
    size_t nl = strlen(needle);
    if (nl == 0 || nl > hn) return NULL;
    for (size_t i = 0; i + nl <= hn; i++)
        if (!memcmp(hay + i, needle, nl)) return hay + i;
    return NULL;
}

static void hexdump(const char *tag, const uint8_t *p, size_t n) {
    printf("[HEX] %s ", tag);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

int main(void) {
    uint8_t blk[512];
    size_t bl = 0;

    /* --- 基本编码：GET + https 命中静态表，path/authority 走 never-indexed --- */
    h2_err e = h2_hpack_request("GET", "https", "/api/v1/x9f2", "real.c2.example",
                                blk, sizeof(blk), &bl);
    CHECK(e == H2_OK, "HPACK 请求编码成功");
    CHECK(bl > 0, "编码长度非 0");
    /* :method GET -> indexed 2 -> 0x82 */
    CHECK(bl >= 2 && blk[0] == 0x82, ":method GET 用静态索引（0x82）");
    CHECK(bl >= 2 && blk[1] == 0x87, ":scheme https 用静态索引（0x87）");
    /* :path -> never-indexed, name idx 4 -> 0x14 */
    CHECK(bl >= 3 && blk[2] == 0x14, ":path 是 never-indexed literal（0x14）");
    hexdump("req", blk, bl);

    /* :authority 紧跟在 :path 之后，必须是 0x11 */
    size_t pos = 3;                       /* 跳过 :method :scheme 与 :path 前缀 */
    pos += (size_t)blk[pos] + 1;          /* :path 的长度字节 + 内容 */
    CHECK(pos < bl && blk[pos] == 0x11, ":authority 是 never-indexed literal（0x11）");
    CHECK(pos + 1 < bl && blk[pos + 1] == (uint8_t)strlen("real.c2.example"),
          ":authority 长度字段正确");

    /* 真实目标确实以明文字节出现在头块里 —— 这是前提：
     * 它必须出现（否则对端收不到），但只出现在加密之后（由 25_tls 保证）。 */
    CHECK(find_sub(blk, bl, "real.c2.example") != NULL,
          "真实目标出现在头块内（加密由 TLS 负责）");

    /* --- POST 走静态索引 3 --- */
    {
        uint8_t b2[512];
        size_t n2 = 0;
        CHECK(h2_hpack_request("POST", "https", "/p", "h.example",
                               b2, sizeof(b2), &n2) == H2_OK, "POST 编码成功");
        CHECK(n2 >= 1 && b2[0] == 0x83, ":method POST 用静态索引（0x83）");
    }

    /* --- 容量不足必须报错，绝不截断 --- */
    {
        uint8_t small[4];
        size_t n3 = 0;
        CHECK(h2_hpack_request("GET", "https", "/very/long/path/xxxxxxxxxx",
                               "real.c2.example", small, sizeof(small), &n3)
              == H2_ERR_RANGE, "缓冲不足返回 RANGE（不静默截断）");
    }

    /* --- 空参数必须被拒 --- */
    CHECK(h2_hpack_request("GET", "https", "/p", "", blk, sizeof(blk), &bl) == H2_ERR_ARG,
          "空 authority 被拒");
    CHECK(h2_hpack_request(NULL, "https", "/p", "h", blk, sizeof(blk), &bl) == H2_ERR_ARG,
          "NULL method 被拒");

    /* --- 解码 :status --- */
    {
        int st = 0;
        uint8_t r1[] = { 0x88 };                      /* indexed 8 = :status 200 */
        CHECK(h2_hpack_status(r1, sizeof(r1), &st) == H2_OK && st == 200,
              "解码 indexed :status 200");
        uint8_t r2[] = { 0x48, 0x03, '4', '0', '4' }; /* literal incremental, name idx 8 */
        CHECK(h2_hpack_status(r2, sizeof(r2), &st) == H2_OK && st == 404,
              "解码 literal :status 404");
        uint8_t r3[] = { 0x40, 0x07, ':','s','t','a','t','u','s', 0x03, '5','0','0' };
        CHECK(h2_hpack_status(r3, sizeof(r3), &st) == H2_OK && st == 500,
              "解码具名 :status 500");
        uint8_t r4[] = { 0x82 };                      /* 只有 :method，没有 :status */
        CHECK(h2_hpack_status(r4, sizeof(r4), &st) == H2_ERR_HPACK,
              "缺 :status 时报错（不默认 200）");
        uint8_t r5[] = { 0x48, 0x83, 0x01, 0x02 };    /* Huffman 字符串 */
        CHECK(h2_hpack_status(r5, sizeof(r5), &st) == H2_ERR_HPACK,
              "Huffman 编码的头块显式报错（不猜）");
    }

    /* --- 连接前言 --- */
    {
        uint8_t pf[64];
        size_t pn = 0;
        CHECK(h2_preface(pf, sizeof(pf), &pn) == H2_OK && pn == 24,
              "连接前言 24 字节");
        CHECK(pn == 24 && !memcmp(pf, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24),
              "前言内容正确");
    }

    /* --- SETTINGS 帧 --- */
    {
        uint8_t sf[32];
        size_t sn = 0;
        CHECK(h2_frame_settings(sf, sizeof(sf), &sn, 0) == H2_OK && sn == 9,
              "SETTINGS 帧 9 字节");
        CHECK(sn == 9 && sf[3] == H2_T_SETTINGS && sf[4] == 0, "SETTINGS 类型与 flags");
        CHECK(h2_frame_settings(sf, sizeof(sf), &sn, 1) == H2_OK && sn == 9 && sf[4] == H2_F_ACK,
              "SETTINGS ACK 置位");
        uint8_t tiny[5];
        size_t tn = 0;
        CHECK(h2_frame_settings(tiny, sizeof(tiny), &tn, 0) == H2_ERR_RANGE,
              "SETTINGS 缓冲不足报 RANGE");
    }

    /* --- HEADERS / DATA 帧 --- */
    {
        uint8_t buf[256];
        size_t n = 0;
        uint8_t hb2[64];
        size_t hbl = 0;
        h2_hpack_request("GET", "https", "/p", "h.example", hb2, sizeof(hb2), &hbl);
        CHECK(h2_frame_headers(1, hb2, hbl, 0, buf, sizeof(buf), &n) == H2_OK,
              "HEADERS 帧构造成功");
        CHECK(n == 9 + hbl, "HEADERS 帧长度 = 9 + 头块");
        CHECK(buf[3] == H2_T_HEADERS, "HEADERS 类型");
        CHECK(buf[4] == H2_F_END_HEADERS, "HEADERS 带 END_HEADERS");
        /* stream_id 大端 */
        CHECK(buf[5] == 0 && buf[6] == 0 && buf[7] == 0 && buf[8] == 1, "流 ID=1 大端编码");
        CHECK(h2_frame_headers(0, hb2, hbl, 0, buf, sizeof(buf), &n) == H2_ERR_ARG,
              "HEADERS 流 ID=0 被拒");

        uint8_t payload[8] = { 1,2,3,4,5,6,7,8 };
        CHECK(h2_frame_data(3, payload, 8, 1, buf, sizeof(buf), &n) == H2_OK && n == 17,
              "DATA 帧 9+8 字节");
        CHECK(buf[4] == H2_F_END_STREAM, "DATA END_STREAM 置位");
        uint8_t big[H2_MAX_FRAME_PAYLOAD + 1];
        memset(big, 0, sizeof(big));
        CHECK(h2_frame_data(1, big, sizeof(big), 0, buf, sizeof(buf), &n) == H2_ERR_RANGE,
              "超过帧上限报 RANGE（不隐式分片）");
    }

    /* --- 帧解析 --- */
    {
        uint8_t buf[64];
        size_t n = 0;
        h2_frame_settings(buf, sizeof(buf), &n, 0);
        h2_frame f;
        CHECK(h2_frame_parse(buf, n, &f) == H2_OK, "解析 SETTINGS 帧");
        CHECK(f.type == H2_T_SETTINGS && f.len == 0 && f.consumed == 9, "帧字段正确");
        CHECK(h2_frame_parse(buf, 5, &f) == H2_ERR_FRAME && f.consumed == 0,
              "短读返回 FRAME 且 consumed=0（不误判成协议错误）");
    }

    /* --- 往返：编码的请求头块能被本层解出合法结构而不崩 --- */
    {
        uint8_t b3[512];
        size_t n3 = 0;
        h2_hpack_request("GET", "https", "/api/v1/abc", "real.c2.example",
                         b3, sizeof(b3), &n3);
        int st = 0;
        /* 头块里没有 :status，必须报错而不是返回垃圾值 */
        CHECK(h2_hpack_status(b3, n3, &st) == H2_ERR_HPACK,
              "请求头块当作响应解码时报 HPACK（不返回假 status）");
    }

    printf("\n=== %d/%d passed ===\n", total - fails, total);
    return fails == 0 ? 0 : 1;
}
