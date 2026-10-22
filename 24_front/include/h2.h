/* h2.h — HTTP/2 帧层 + HPACK 头压缩（自研，不依赖 nghttp2 / OpenSSL）
 *
 * 为什么单独做这一层：域前置的 HTTP/1.1 短连接形态与真实 Web 流量差异明显
 * （每条请求一个连接、无多路复用）。HTTP/2 的多流复用更接近浏览器行为。
 *
 * 三条硬规则 —— 违反任何一条，前置就退化成"把真实目标写在明处"：
 *
 *  1. 禁止明文 h2c。
 *     :authority 就在 HEADERS 帧里，不经 TLS 等于广播真实目标。本层只构造
 *     字节，加密由 25_tls 承担；调用方必须把输出喂进 TLS 记录层。
 *     本层刻意不提供 "upgrade from h2c" 的路径。
 *
 *  2. :authority 与 :path 一律用 never-indexed literal。
 *     若让它们进 HPACK 动态表，后续请求就只用 1 字节索引表达。内容虽然仍在
 *     TLS 内，但一旦中间设备（前置 CDN）做头解压、日志记录或动态表状态转储，
 *     真实域名就被固化下来。never-indexed 是对端被明确要求不得存入的表示。
 *
 *  3. 帧长度不得让真实目标长度独自可辨。
 *     :path 随机后缀长度抖动（由 24_front 负责），本层不填充 —— 填充留给
 *     PADDED 标志，由调用方按需启用。
 */
#ifndef H2_H
#define H2_H

#include <stddef.h>
#include <stdint.h>

/* SETTINGS 约定的单帧上限。DATA 超过即需分片，本层不做隐式分片，
 * 超长直接报错 —— 静默截断会让对端收到半条消息却以为完整。 */
#define H2_MAX_FRAME_PAYLOAD 16384

typedef enum {
    H2_OK = 0,
    H2_ERR_ARG,
    H2_ERR_RANGE,      /* 缓冲不够 / 超过帧上限 */
    H2_ERR_FRAME,      /* 帧结构非法 */
    H2_ERR_HPACK,      /* HPACK 编码/解码失败 */
    H2_ERR_STATE
} h2_err;

const char *h2_errstr(h2_err e);

/* ---- HPACK ---- */

/* 编码请求头（:method :scheme :path :authority）。
 * method/scheme 命中静态表时用索引形式；path 与 authority 恒为 never-indexed。 */
h2_err h2_hpack_request(const char *method, const char *scheme,
                        const char *path, const char *authority,
                        uint8_t *out, size_t cap, size_t *out_len);

/* 解码响应头块，取 :status。取不到返回 H2_ERR_HPACK（不猜、不默认 200）。 */
h2_err h2_hpack_status(const uint8_t *in, size_t len, int *status);

/* ---- 连接与帧 ---- */

/* 客户端连接前言：24 字节固定串 */
h2_err h2_preface(uint8_t *out, size_t cap, size_t *out_len);

h2_err h2_frame_settings(uint8_t *out, size_t cap, size_t *out_len, int ack);
h2_err h2_frame_headers(uint32_t stream_id, const uint8_t *blk, size_t blk_len,
                        int end_stream, uint8_t *out, size_t cap, size_t *out_len);
h2_err h2_frame_data(uint32_t stream_id, const uint8_t *payload, size_t len,
                     int end_stream, uint8_t *out, size_t cap, size_t *out_len);

typedef struct {
    uint8_t       type;
    uint8_t       flags;
    uint32_t      stream_id;
    const uint8_t *payload;   /* 指向 buf 内部，不拷贝 */
    size_t        len;
    size_t        consumed;   /* 本帧总占用（含 9 字节帧头） */
} h2_frame;

/* 解析 buf 中的一帧。buf 不足一整帧时返回 H2_ERR_FRAME 且 consumed=0，
 * 提示调用方继续收 —— 短读不是错误，误判成错误会中断连接。 */
h2_err h2_frame_parse(const uint8_t *buf, size_t len, h2_frame *f);

/* 帧类型（RFC 7540 §11.2） */
#define H2_T_DATA          0x00
#define H2_T_HEADERS       0x01
#define H2_T_SETTINGS      0x04
#define H2_T_PING          0x06
#define H2_T_GOAWAY        0x07
#define H2_T_WINDOW_UPDATE 0x08

#define H2_F_END_STREAM    0x01
#define H2_F_END_HEADERS   0x04
#define H2_F_ACK           0x01

#endif /* H2_H */
