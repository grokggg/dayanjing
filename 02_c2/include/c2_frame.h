/*
 * DAYANJING v3 — c2_frame.h
 *
 * 帧层 AEAD 封装（C 实现），与 Python 侧 00_crypto/frame.py 逐字节对齐。
 *
 * wire 格式：
 *   u32_le(total_len) || u32_le(msg_type 明文) || iv(12B) || ct || tag(16B)
 *   total_len = 4 + 12 + len(ct) + 16
 *   iv        = 8B nonce_prefix || 4B counter(大端)
 *
 * 明文 Envelope（确定性编码）：
 *   u64_le(seq) || u32_le(version) || u32_le(msg_type) || u32_le(payload_len) || payload
 *
 * AAD（定长域分离，不含 role）：
 *   b"c2:v1" || u32_le(version) || u32_le(msg_type)
 *
 * msg_type 以明文出现在帧头：解密端据此重建与加密端完全一致的 AAD。
 * role 不进 AAD——role 只决定用 k_send 还是 k_recv，密钥分离由派生链保证。
 */

#ifndef DAYANJING_C2_FRAME_H
#define DAYANJING_C2_FRAME_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define C2_FRAME_IV_LEN   12
#define C2_FRAME_TAG_LEN  16
#define C2_FRAME_TYPE_LEN 4    /* 帧头明文 msg_type */
#define C2_PROTO_VERSION  1

/* 帧头固定开销：u32 total_len + u32 msg_type + iv(12) + tag(16) */
#define C2_FRAME_OVERHEAD (4 + C2_FRAME_TYPE_LEN + C2_FRAME_IV_LEN + C2_FRAME_TAG_LEN)

/* 明文 Envelope 头长度：u64 seq + u32 version + u32 msg_type + u32 plen */
#define C2_ENVELOPE_HDR 20

/* wire 总长 = 帧头开销 + Envelope 头 + payload 长度 */
#define C2_FRAME_WIRE_LEN(plen) (C2_FRAME_OVERHEAD + C2_ENVELOPE_HDR + (plen))

/* ---- 返回值 ---- */
#define C2_FRAME_OK        0
#define C2_FRAME_ERR_ARG  -1   /* 参数非法 */
#define C2_FRAME_ERR_LEN  -2   /* 长度非法/缓冲区不足 */
#define C2_FRAME_ERR_AUTH -3   /* 验签失败（篡改或密钥错误） */
#define C2_FRAME_ERR_FMT  -4   /* 格式错误（长度不一致/版本不符） */

/*
 * 封装一帧。
 * out 可为 NULL（仅探测所需长度，写入 *out_len）。
 */
int c2_frame_seal(const uint8_t key[16],
                  const uint8_t nonce_prefix[8],
                  uint32_t counter,
                  uint64_t seq,
                  uint32_t msg_type,
                  const uint8_t *payload, size_t plen,
                  uint8_t *out, size_t cap, size_t *out_len);

/*
 * 解封一帧。
 * payload 可为 NULL（仅探测所需长度，写入 *plen）。
 */
int c2_frame_open(const uint8_t key[16],
                  const uint8_t *wire, size_t wire_len,
                  uint64_t *seq,
                  uint32_t *msg_type,
                  uint8_t *payload, size_t cap, size_t *plen);

/* 构造 AAD，供测试/调试对照（13 字节） */
size_t c2_frame_aad(uint32_t msg_type, uint8_t out[13]);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_C2_FRAME_H */
