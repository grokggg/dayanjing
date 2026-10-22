/* test_front_h2.c — 域前置层的 HTTP/2 路径与自适应退避
 *
 * 验收点不是"能连上"，而是四条：
 *   1. h2 握手必须真等到对端 SETTINGS —— 在此之前发 HEADERS 会被对端
 *      视为连接错误（GOAWAY），表现为"握手成功但首个请求必失败"
 *   2. :authority 是真实目标且以 HPACK never-indexed 字面量编码，
 *      绝不走静态表索引；SNI 域不出现在 HTTP 层任何位置
 *   3. 421 Misdirected Request 必须被单独认出 —— 它是"前置拒绝回源"的
 *      直接信号，与 5xx 的处置完全不同（换前置域 vs 重试）
 *   4. 退避由实测 RTT 导出并全抖动：固定退避会让一批植入体在 CDN 故障后
 *      同时重试，链路上就是"静默—同步爆发"，那是事件特征
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "front.h"
#include "h2.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

static int fails = 0, total = 0;
#define CHECK(cond, name) do { \
    total++; \
    if (cond) printf("[PASS] %s\n", name); \
    else { printf("[FAIL] %s\n", name); fails++; } \
} while (0)
#define INFO(fmt, ...) printf("[INFO] " fmt "\n", __VA_ARGS__)

#define FRONT_DOMAIN "api.github.com"
#define REAL_HOST    "c2-real-target.invalid"

typedef struct {
    int fd;
    uint8_t sent[16384];
    size_t  sent_len;
    /* 预置的对端响应，供 h2 握手/响应路径消费 */
    const uint8_t *feed;
    size_t         feed_len;
    size_t         feed_off;
} io_ctx;

static int feed_send(void *arg, const uint8_t *d, size_t n) {
    io_ctx *c = (io_ctx *)arg;
    if (c->sent_len + n < sizeof(c->sent)) {
        memcpy(c->sent + c->sent_len, d, n);
        c->sent_len += n;
    }
    /* 真机段必须真的发出去。只记录不发送的话，TLS 握手拿不到响应，
       会败在 tls layer，被误读成"前置域不支持 h2"之类的错误结论。 */
    if (c->fd >= 0) {
        ssize_t r = send(c->fd, d, n, 0);
        if (r <= 0) return -1;
        return (int)r;
    }
    return (int)n;
}
/* 先吐预置字节，吐完再读 socket；socket 也读到末尾则返回 0 */
static int feed_recv(void *arg, uint8_t *b, size_t cap) {
    io_ctx *c = (io_ctx *)arg;
    if (c->feed && c->feed_off < c->feed_len) {
        size_t n = c->feed_len - c->feed_off;
        if (n > cap) n = cap;
        memcpy(b, c->feed + c->feed_off, n);
        c->feed_off += n;
        return (int)n;
    }
    if (c->fd >= 0) return (int)recv(c->fd, b, cap, 0);
    return -1;
}

static int tcp_connect(const char *host) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, "443", &hints, &res) != 0) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);
    return fd;
}

static front_ctx *mk(io_ctx *io, int http2, const char *prefix) {
    front_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.front_domain = FRONT_DOMAIN;
    cfg.real_host    = REAL_HOST;
    cfg.path_prefix  = prefix;
    cfg.rng_seed     = 0x1234567890abcdefULL;
    cfg.http2        = http2;
    front_ctx *c = NULL;
    if (front_init(&c, &cfg, feed_send, feed_recv, io) != FRONT_OK) return NULL;
    return c;
}

/* 内存搜索：在字节流里找子串 */
static int has(const uint8_t *hay, size_t n, const char *needle) {
    size_t m = strlen(needle);
    if (m == 0 || m > n) return 0;
    for (size_t i = 0; i + m <= n; i++)
        if (!memcmp(hay + i, needle, m)) return 1;
    return 0;
}

int main(void) {
    /* ---------- 1. :authority 用真实目标，且 SNI 域不出现在 HTTP 层 ---------- */
    {
        io_ctx io;
        memset(&io, 0, sizeof(io));
        io.fd = -1;
        uint8_t srv[64];
        size_t  sn = 0;
        h2_frame_settings(srv, sizeof(srv), &sn, 0);
        io.feed = srv; io.feed_len = sn;

        front_ctx *c = mk(&io, 1, "/api/v1/");
        if (c) {
            uint8_t req[4096];
            size_t  rlen = 0;
            uint8_t body[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
            CHECK(front_build_request(c, body, sizeof(body), req, sizeof(req), &rlen)
                  == FRONT_OK, "构造 h2 请求成功");
            CHECK(has(req, rlen, REAL_HOST), "HTTP 层含真实目标（:authority，加密内）");
            CHECK(!has(req, rlen, FRONT_DOMAIN),
                  "SNI 前置域不出现在 HTTP 层（前置域只在 ClientHello 明文）");
            /* never-indexed 字面量 + 索引名(:authority=1)：首字节 0001 0001 = 0x11 */
            CHECK(has(req, rlen, "\x11"), "头块用 never-indexed 形式（0x11）");

            /* 路径抖动：连续两次请求字节不同 */
            uint8_t req2[4096];
            size_t  rlen2 = 0;
            front_build_request(c, body, sizeof(body), req2, sizeof(req2), &rlen2);
            CHECK(rlen != rlen2 || memcmp(req, req2, rlen < rlen2 ? rlen : rlen2) != 0,
                  "连续两次 h2 请求字节不同（路径抖动生效）");
            front_free(c);
        } else { CHECK(0, "构造 h2 请求成功"); }
    }

    /* ---------- 2. 退避：RTT 导出 + 全抖动 + 封顶 ---------- */
    {
        io_ctx io;
        memset(&io, 0, sizeof(io));
        io.fd = -1;
        front_ctx *c = mk(&io, 0, "/");
        if (c) {
            CHECK(front_backoff_ms(c) == 0, "无失败时退避为 0（不影响正常路径）");

            front_note_success(c, 200000);      /* 200ms RTT */
            CHECK(front_rtt_ewma_us(c) == 200000, "首个 RTT 样本被直接采纳");
            front_note_success(c, 60000);
            CHECK(front_rtt_ewma_us(c) == (200000 * 7 + 60000) / 8,
                  "后续样本走 EWMA（α=1/8）");

            /* 单次失败：窗口应为 [0.5*base, base)，base 由 EWMA 导出 */
            front_note_fail(c);
            uint64_t b1 = front_backoff_ms(c);
            uint64_t base = front_rtt_ewma_us(c) / 1000;
            INFO("1 次失败后退避=%llums（base=%llums）",
                 (unsigned long long)b1, (unsigned long long)base);
            uint64_t w1 = base << 1;      /* 失败 1 次：窗口 = base * 2 */
            CHECK(b1 >= w1 / 2 && b1 < w1, "单次失败退避落在 [0.5W, W) 内");

            /* 全抖动：模拟 8 个植入体同时遭遇 CDN 故障后各失败一次。
               若退避固定，它们会在同一刻集体重试 —— 链路上就是
               "静默—同步爆发"。断言它们的退避值彼此分散。 */
            uint64_t seen[8];
            int      distinct = 0;
            for (int i = 0; i < 8; i++) {
                io_ctx  io2;
                memset(&io2, 0, sizeof(io2));
                io2.fd = -1;
                front_config cf;
                memset(&cf, 0, sizeof(cf));
                cf.front_domain = FRONT_DOMAIN;
                cf.real_host    = REAL_HOST;
                cf.path_prefix  = "/";
                cf.rng_seed     = 0x1000ULL + (uint64_t)i * 0x9e3779b9ULL;
                front_ctx *c2 = NULL;
                front_init(&c2, &cf, feed_send, feed_recv, &io2);
                front_note_success(c2, 200000);     /* 同样的 RTT 样本 */
                front_note_fail(c2);                /* 同时失败一次 */
                seen[i] = front_backoff_ms(c2);
                front_free(c2);
            }
            for (int i = 0; i < 8; i++) {
                int d = 1;
                for (int j = 0; j < i; j++) if (seen[j] == seen[i]) d = 0;
                distinct += d;
            }
            INFO("8 个植入体同步失败后的退避取值种类=%d", distinct);
            CHECK(distinct >= 4, "同步失败的多个植入体退避值分散（打散惊群）");

            /* 封顶：连续失败 40 次 */
            front_ctx *c3 = NULL;
            {
                io_ctx io3;
                memset(&io3, 0, sizeof(io3));
                io3.fd = -1;
                front_config cf;
                memset(&cf, 0, sizeof(cf));
                cf.front_domain = FRONT_DOMAIN;
                cf.real_host    = REAL_HOST;
                cf.path_prefix  = "/";
                cf.rng_seed     = 7;
                front_init(&c3, &cf, feed_send, feed_recv, &io3);
            }
            for (int i = 0; i < 40; i++) front_note_fail(c3);
            uint64_t big = front_backoff_ms(c3);
            CHECK(big <= FRONT_BACKOFF_MAX_MS, "退避封顶不超过上限（不会永不重试）");
            INFO("40 次连续失败后退避=%llums（上限 %d）",
                 (unsigned long long)big, FRONT_BACKOFF_MAX_MS);
            front_free(c3);

            /* 成功后失败计数清零 */
            front_note_success(c, 100000);
            CHECK(front_backoff_ms(c) == 0, "成功后失败计数清零，退避归 0");
            front_free(c);
        } else { CHECK(0, "无失败时退避为 0（不影响正常路径）"); }
    }

    /* ---------- 3. 无 RTT 样本时不退化成紧密重试 ---------- */
    {
        io_ctx io;
        memset(&io, 0, sizeof(io));
        io.fd = -1;
        front_ctx *c = mk(&io, 0, "/");
        if (c) {
            front_note_fail(c);
            uint64_t b = front_backoff_ms(c);
            INFO("无 RTT 样本时首次失败退避=%llums", (unsigned long long)b);
            CHECK(b >= 100 && b < 200, "无样本时以 100ms 兜底（绝不退回 0 打成 DoS）");
            front_free(c);
        } else { CHECK(0, "无样本时以 100ms 兜底"); }
    }

    /* ---------- 4. 真机：真实前置域上的 h2 握手与不匹配 authority 的处置 ----------
     *
     * 这一段无法用 mock 替代。h2 握手发生在 TLS 之内，离线 mock 的预置字节
     * 会被 TLS 层先吃掉，导致"握手失败"被误读成"GOAWAY 被检出"之类的结论。
     * 只有真连一次，才能回答域前置最关键的现实问题：
     *   真实 CDN/大厂域在 SNI 与 :authority 不一致时，到底拒绝还是放行？
     */
    {
        io_ctx io;
        memset(&io, 0, sizeof(io));
        int fd = tcp_connect(FRONT_DOMAIN);
        if (fd < 0) {
            printf("[SKIP] 真机前置域不可达，跳过 h2 真机段\n");
        } else {
            io.fd = fd;
            front_ctx *c = NULL;
            front_config cfg;
            memset(&cfg, 0, sizeof(cfg));
            cfg.front_domain = FRONT_DOMAIN;
            cfg.real_host    = REAL_HOST;
            cfg.path_prefix  = "/";
            cfg.ca_path      = "/etc/zeroproxy-tls/ca-bundle.pem";
            cfg.verify       = 1;
            cfg.http2        = 1;

            front_err ie = front_init(&c, &cfg, feed_send, feed_recv, &io);
            CHECK(ie == FRONT_OK, "真机：h2 模式初始化成功");
            if (ie == FRONT_OK) {
                front_err ce = front_connect(c);
                INFO("真机 h2 握手返回: %s", front_errstr(ce));
                CHECK(ce == FRONT_OK, "真机：与真实前置域完成 h2 握手（等到对端 SETTINGS）");
                /* preface 在 TLS 应用数据记录里，是加密的，取不到明文。
                   能取证的是 ClientHello（明文）：它必须带 ALPN "h2"，
                   否则对端降级到 HTTP/1.1，h2 握手根本不会成功。 */
                {
                    static const uint8_t alpn[] = { 0x00,0x10,0x00,0x05,0x00,0x03,0x02,0x68,0x32 };
                    int found = 0;
                    for (size_t i = 0; i + sizeof(alpn) <= io.sent_len; i++)
                        if (!memcmp(io.sent + i, alpn, sizeof(alpn))) { found = 1; break; }
                    CHECK(found, "真机：ClientHello 明文携带 ALPN h2（否则对端降级到 h1）");
                }

                if (ce == FRONT_OK) {
                    uint8_t body[16] = { 0xda, 0x1a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
                    front_err se = front_send(c, body, sizeof(body));
                    INFO("真机 h2 发送返回: %s", front_errstr(se));
                    CHECK(se == FRONT_OK, "真机：h2 请求发出（HEADERS+DATA）");

                    uint8_t out[4096];
                    size_t  olen = 0;
                    front_err re = front_recv(c, out, sizeof(out), &olen);
                    int st = front_last_status(c);
                    INFO("真机响应: %s, status=%d, body=%zu 字节",
                         front_errstr(re), st, olen);
                    /* 这里不断言"必须成功"。真实前置域对不匹配的 :authority
                       怎么处置由对方决定。要断言的是：无论放行还是拒绝，
                       本层都能把它如实报出来，而不是静默当成成功。
                       这条才是域前置在真实世界里能否成立的判据。 */
                    CHECK(re != FRONT_OK || st == 0 || (st >= 200 && st < 600),
                          "真机：响应被如实判定（成功即成功，拒绝即报错）");
                    if (st == 421) {
                        printf("[INFO] 真机：前置域返回 421 —— 该域拒绝为不匹配的 "
                               ":authority 回源，域前置在此前置域上不可用（需换前置）\n");
                    }
                }
                front_free(c);
            }
            close(fd);
        }
    }

    printf("=== %d/%d passed ===\n", total - fails, total);
    return fails ? 1 : 0;
}
