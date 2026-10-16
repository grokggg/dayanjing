/*
 * proto.h — DAYANJING v3 C2 协议层公共接口
 *
 * 安全不变量（继承自 13_c2_server/frame.py ADR，C 端口必须保持一致）：
 *  - 先验签后 accept：decode() 先 AEAD 验签，失败立即返回，绝不污染重放窗口
 *  - k_send ≠ k_recv 强制分离，单密钥退化路径已删除
 *  - AAD 定长域分离编码，禁止自由拼接
 *  - seq 与 nonce 解耦：nonce 抗加解密层重放，seq 抗应用层重放（含跨重连）
 *  - 重放窗口以 (implant_id, key_generation) 为键，跨重连不重置
 */
#ifndef PROTO_H
#define PROTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ==================== 常量 ==================== */
#define PROTO_VERSION       1
#define PROTO_AAD_PREFIX    "c2:v1"
#define PROTO_ROLE_CLIENT   0x01
#define PROTO_ROLE_SERVER   0x02
#define PROTO_MAX_FRAME     (16u * 1024u * 1024u)   /* 16 MiB，v3 §13 */
#define PROTO_REPLAY_WINDOW 1024
#define PROTO_NONCE_COUNTER_LIMIT  (1uLL << 32)      /* 2^32 后强制轮换 */
#define PROTO_KEY_LEN       32      /* 对称密钥 256-bit（ChaCha20-Poly1305） */
#define PROTO_AAD_LEN       15      /* "c2:v1"\0(6) + ver(4) + role(1) + type(4) */
#define PROTO_ENVELOPE_MIN  20      /* seq(8)+version(4)+type(4)+plen(4) */

/* ==================== 错误码 ==================== */
typedef enum {
    PROTO_OK            = 0,
    PROTO_ERR           = -1,
    PROTO_INVALID_ROLE  = -10,
    PROTO_KEYLEN        = -11,
    PROTO_KEYS_EQUAL    = -12,    /* k_send == k_recv */
    PROTO_COUNTER_FULL  = -13,
    PROTO_TOO_SHORT     = -14,
    PROTO_TOO_LONG      = -15,
    PROTO_LEN_MISMATCH  = -16,
    PROTO_VER_MISMATCH  = -17,
    PROTO_TYPE_MISMATCH = -18,    /* 帧头明文 type 与密文不一致 */
    PROTO_TAG_FAIL      = -19,
    PROTO_SEQ_REPLAY    = -20,
    PROTO_SEQ_TOO_OLD   = -21,
    PROTO_SEQ_GAP       = -22,
    PROTO_NOMEM         = -23,
    PROTO_RANGE         = -24,
    PROTO_NOT_FOUND     = -25,
} proto_err_t;

const char *proto_strerror(proto_err_t e);

/* ==================== 帧层 ==================== */

/* 编码后 wire = u32(total_len) || u32(msg_type 明文) || nonce(12) || ct || tag(16) */
proto_err_t proto_seal(const uint8_t k_send[PROTO_KEY_LEN],
                       uint8_t nonce_prefix[8], uint32_t *counter,
                       uint8_t *nonce_buf,      /* 出参：本次使用的 12B nonce */
                       uint64_t seq, uint32_t msg_type,
                       const uint8_t *payload, uint32_t payload_len,
                       uint8_t *out, size_t out_cap, size_t *out_len);

/*
 * 解码并验签。成功返回 PROTO_OK，seq/type/payload 通过出参返回。
 * 内部会重新编码 AAD，因此调用方需传入 role 和 msg_type（从帧头明文读出）。
 * 任何验签失败一律返回 PROTO_TAG_FAIL，调用方映射为静默关连接，不回显细节。
 */
proto_err_t proto_open(const uint8_t k_recv[PROTO_KEY_LEN], uint8_t role,
                       const uint8_t *wire, size_t wire_len,
                       uint64_t *seq, uint32_t *msg_type,
                       uint8_t *payload_out, size_t payload_cap, size_t *payload_len);

/* 构造 AAD = "c2:v1" || version(4) || role(1) || msg_type(4) 定长 14 字节 */
proto_err_t proto_build_aad(uint8_t role, uint32_t msg_type,
                            uint8_t aad[PROTO_AAD_LEN]);

/* ==================== 重放窗口 ==================== */
struct replay_key { char     implant_id[64]; uint64_t generation; };
struct replay_state;

struct replay_state *replay_new(uint32_t capacity);
void                replay_free(struct replay_state *rs);

/*
 * 判定结果。仅 ACCEPTED 允许上层处理；其余一律丢弃。
 * 本函数不区分"正常乱序"与"攻击重放"——对调用方而言都是丢弃，不回显。
 */
typedef enum {
    REPLAY_ACCEPTED  = 0,
    REPLAY_REPLAY    = 1,
    REPLAY_TOO_OLD   = 2,
    REPLAY_FUTURE_GAP= 3,
} replay_decision_t;

replay_decision_t replay_accept(struct replay_state *rs,
                                const struct replay_key *key, uint64_t seq);

/* 密钥轮换：新建代际窗口；旧代际保留但不可前进 */
void replay_rotate(struct replay_state *rs, const struct replay_key *key);

/*
 * 快照/恢复（持久化契约，与 13_c2_server/frame.py 兼容）。
 * snapshot 返回 seen 位数组 + highest，restore 重建；测试验证"恢复后旧 seq 仍判重放"。
 */
uint8_t *replay_snapshot(const struct replay_state *rs,
                         const struct replay_key *key,
                         size_t *seen_bytes, uint64_t *highest);
void     replay_restore(struct replay_state *rs, const struct replay_key *key,
                        const uint8_t *seen_bits, size_t seen_bytes, uint64_t highest);

/* 统计（仅供测试） */
uint64_t replay_highest(const struct replay_state *rs, const struct replay_key *key);
size_t   replay_seen_count(const struct replay_state *rs, const struct replay_key *key);

#ifdef __cplusplus
}
#endif
#endif /* PROTO_H */
