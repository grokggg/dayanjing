/*
 * DAYANJING v4 — p2p_onion.h
 *
 * 洋葱路由分层加密（Onion Routing）—— 解除"电路头对中间跳可见"的限制。
 *
 * ====================================================================
 * 解决的问题
 * ====================================================================
 * 旧电路头（route.h）格式：
 *     n_ids || ids[0..n] || final_port || host_len || host
 * 每一跳都能看到**整条路径**和**最终目标 host:port**。
 * 中间跳因此知道链路形状——谁在为谁转发、最终打向哪里。
 *
 * 洋葱路由后：
 *   - 每跳只能解出**自己的那一层**
 *   - 解出的内容只有「下一跳是谁」，或者「我是最后一跳，最终目标是 X」
 *   - 剩余部分是**不透明密文**，原样转发，本跳无法解密
 *
 * 于是中间跳（非最后一跳）**既不知道自己在第几跳，也不知道最终目标**。
 * 这是与旧方案的本质区别。
 *
 * ====================================================================
 * 分层构造（endpoint 侧，从最后一跳往前逐层加密）
 * ====================================================================
 *   第 n 层（最后一跳）明文：{final=1, host, port, inner=空}
 *       -> 用 K[n] 加密得 C[n]
 *   第 i 层（中间跳）明文：{final=0, next_id=hop[i+1], inner=C[i+1]}
 *       -> 用 K[i] 加密得 C[i]
 *   第 0 层（首跳）明文：{final=0, next_id=hop[1], inner=C[1]}
 *       -> 用 K[0] 加密得 C[0]
 *
 *   线上电路头 = version || salt(16) || onion_len(u16 LE) || C[0]
 *
 * 每跳处理：
 *   1. 用自己的层密钥解密收到的 onion
 *   2. final=1 -> 连最终目标，relay
 *      final=0 -> 连 next_id，把 **inner 原样**转发（不解密）
 *
 * ====================================================================
 * 密钥派生
 * ====================================================================
 *   K[i] = HKDF-SHA256(salt=onion_salt, IKM=master,
 *                      info="p2p:onion:layer:v1" || hop_id[i], L=16)
 *
 * master 为洋葱主密钥（配置分发一个即可，无需为每跳单独配密钥）。
 * onion_salt 每条电路随机生成，明文携带 —— salt 不需要保密，
 * 作用是让同一主密钥在不同电路上派生出不同的层密钥。
 *
 * 密码学复用 00_crypto（AES-128-GCM + HKDF-SHA256），不自研第二套。
 */

#ifndef DAYANJING_P2P_ONION_H
#define DAYANJING_P2P_ONION_H

#include <stddef.h>
#include <stdint.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define P2P_ONION_MASTER_LEN 16   /* 洋葱主密钥 */
#define P2P_ONION_SALT_LEN   16   /* 每条电路的随机 salt */
#define P2P_ONION_KEY_LEN    16   /* 每跳层密钥（AES-128） */
#define P2P_ONION_IV_LEN     12   /* GCM IV */
#define P2P_ONION_TAG_LEN    16   /* GCM tag */
#define P2P_ONION_MAX_LAYERS 16   /* 最大层数，须 <= P2P_MAX_HOPS */

/* 层密文 = iv(12) || tag(16) || ct(n)，故每层的固定开销 */
#define P2P_ONION_LAYER_OVH  (P2P_ONION_IV_LEN + P2P_ONION_TAG_LEN)

/* 层明文头（固定 22 字节）：
 *   u8  final_flag      1 = 本跳即最后一跳
 *   u8  host_len        最终目标主机名长度（final_flag=1 时有效）
 *   u16 port LE         最终目标端口（final_flag=1 时有效）
 *   u8  next_id[16]     下一跳 ID（final_flag=0 时有效）
 *   u16 inner_len LE    内层洋葱长度（0 = 无内层，即本跳为最后一跳）
 * 其后紧跟 inner[inner_len] 与 host[host_len]。 */
#define P2P_ONION_HDR_LEN    22
#define P2P_ONION_ID_LEN     16

/* ---- 返回值（沿用 p2p 错误码语义） ---- */
#define P2P_ONION_OK         0
#define P2P_ONION_ERR_ARG   -1
#define P2P_ONION_ERR_LEN   -2   /* 缓冲区不足 */
#define P2P_ONION_ERR_AUTH  -3   /* 层验签失败（不是给我的洋葱 / 被篡改） */
#define P2P_ONION_ERR_FMT   -4   /* 格式错误 */

/*
 * 派生某一跳的层密钥。
 *   K = HKDF(salt=onion_salt, IKM=master,
 *            info="p2p:onion:layer:v1" || hop_id, L=16)
 * 供测试直接调用以验证派生确定性；实现内部也走这一路径。
 */
int p2p_onion_layer_key(const uint8_t master[P2P_ONION_MASTER_LEN],
                        const uint8_t salt[P2P_ONION_SALT_LEN],
                        const uint8_t hop_id[P2P_ONION_ID_LEN],
                        uint8_t out[P2P_ONION_KEY_LEN]);

/*
 * 构建洋葱（endpoint 侧）。
 *
 * hops_flat : n_hops 个节点 ID 的连续缓冲（含首跳），从首跳到最后一跳
 * out       : 可为 NULL，仅探测所需长度
 *
 * 返回 P2P_ONION_OK 时 *out_len 写入洋葱总长（含 IV/TAG 开销）。
 */
int p2p_onion_build(const uint8_t master[P2P_ONION_MASTER_LEN],
                    const uint8_t salt[P2P_ONION_SALT_LEN],
                    const uint8_t *hops_flat, int n_hops,
                    const char *final_host, uint16_t final_port,
                    uint8_t *out, size_t cap, size_t *out_len);

/*
 * 剥开一层（每跳侧）。只有本跳的层密钥能解开；解不开返回 P2P_ONION_ERR_AUTH。
 *
 * 输出：
 *   final_flag : 1 = 本跳即最后一跳（此时填 final_host/final_port）
 *                0 = 需转发（此时填 next_id）
 *   inner      : 剩余洋葱（不透明，本跳不解密），可为 NULL 仅探测长度
 *
 * 注意：inner_len 为 0 且 final_flag=0 属格式错误，返回 P2P_ONION_ERR_FMT。
 */
int p2p_onion_peel(const uint8_t master[P2P_ONION_MASTER_LEN],
                   const uint8_t salt[P2P_ONION_SALT_LEN],
                   const uint8_t my_id[P2P_ONION_ID_LEN],
                   const uint8_t *onion, size_t onion_len,
                   int *final_flag,
                   uint8_t next_id[P2P_ONION_ID_LEN],
                   char *final_host, size_t host_cap, uint16_t *final_port,
                   uint8_t *inner, size_t inner_cap, size_t *inner_len);

/*
 * 构造完整电路头：version || salt || onion_len || onion
 * out 可为 NULL 仅探测长度。
 */
int p2p_onion_build_hdr(const uint8_t master[P2P_ONION_MASTER_LEN],
                        const uint8_t salt[P2P_ONION_SALT_LEN],
                        const uint8_t *hops_flat, int n_hops,
                        const char *final_host, uint16_t final_port,
                        uint8_t *out, size_t cap, size_t *out_len);

/*
 * 解析电路头，取出 salt 与洋葱（不解密）。
 * onion_out 指向 out 内部的偏移，不额外拷贝；out 的生命周期需覆盖使用期。
 */
int p2p_onion_parse_hdr(const uint8_t *in, size_t len,
                        uint8_t salt_out[P2P_ONION_SALT_LEN],
                        const uint8_t **onion_out, size_t *onion_len);

/* 中间跳转发剩余洋葱时的封装：u16 LE inner_len || inner */
int p2p_onion_build_fwd(const uint8_t *inner, size_t inner_len,
                        uint8_t *out, size_t cap, size_t *out_len);

/* 解析上一步的转发封装 */
int p2p_onion_parse_fwd(const uint8_t *in, size_t len,
                        const uint8_t **inner_out, size_t *inner_len);

const char *p2p_onion_errstr(int e);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_P2P_ONION_H */
