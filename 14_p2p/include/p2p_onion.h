/*
 * DAYANJING v4 — p2p_onion.h
 *
 * 洋葱路由分层加密（Onion Routing）—— 每跳只解出「下一跳是谁」。
 *
 * ====================================================================
 * 解决的问题
 * ====================================================================
 * 旧电路头（route.h）：n_ids || ids[] || final_port || host，
 * 每一跳都能看到**整条路径**和**最终目标** —— 中间跳知道链路形状。
 *
 * 洋葱后：每跳只能解开自己那一层，解出的内容只有「下一跳是谁」
 * （或「我是最后一跳，最终目标 X」），其余为不透明密文原样转发。
 * 中间跳**既不知道自己在第几跳，也不知道最终目标**。
 *
 * ====================================================================
 * 层密钥：X25519 ephemeral-static（Tor ntor 同构）—— 无共享主密钥
 * ====================================================================
 * 早期版本：K[i] = HKDF(salt, IKM=master, ...) —— master 全网共享，
 *           任一跳被攻破即能推导所有跳的层密钥（只要知道路径）。
 *
 * 现在：
 *   每跳持有自己的静态密钥对 (sk_i, pk_i)，私钥不进 mesh、不外传
 *   建电路方为每跳生成临时密钥对 (e_i, E_i)
 *     ss_i = X25519(e_i, pk_i) = X25519(sk_i, E_i)
 *     K[i] = HKDF(salt, IKM = ss_i || hop_id[i], info="p2p:onion:layer:v2")
 *   临时公钥 E_i 以**明文**随本层携带（解密前必须能拿到它）
 *
 * 线上每层：eph_pub(32) || iv(12) || tag(16) || ct(n)
 *
 * 性质与边界（不夸大）：
 *   1. 无全网共享密钥 —— 拿到一跳私钥只能解该跳的层，解不出其他层
 *   2. 临时密钥每电路随机 —— 同一跳在不同电路上层密钥不同
 *   3. 边界：ephemeral-static 不等于完全前向保密。若某跳静态私钥泄露
 *      且攻击者完整录制了电路建立报文，可离线还原该跳那一层
 *      （与 Tor ntor 同级；完全 PFS 需静态密钥定期轮换）
 *
 * 密码学复用 00_crypto：X25519 + HKDF-SHA256 + AES-128-GCM，不自研第二套。
 */

#ifndef DAYANJING_P2P_ONION_H
#define DAYANJING_P2P_ONION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define P2P_ONION_SALT_LEN   16   /* 每条电路的随机 salt，明文携带 */
#define P2P_ONION_KEY_LEN    16   /* 每跳层密钥（AES-128） */
#define P2P_ONION_IV_LEN     12   /* GCM IV */
#define P2P_ONION_TAG_LEN    16   /* GCM tag */
#define P2P_ONION_MAX_LAYERS 16   /* 最大层数，须 <= P2P_MAX_HOPS */

/* 层密文 = iv(12) || tag(16) || ct(n)；层线上 = eph_pub(32) || 层密文 */
#define P2P_ONION_LAYER_OVH  (P2P_ONION_IV_LEN + P2P_ONION_TAG_LEN)
#define P2P_ONION_EPH_LEN     32   /* X25519 临时公钥，明文随层携带 */
#define P2P_ONION_SK_LEN      32   /* 本跳静态私钥 */

/* 层明文头（固定 22 字节）：
 *   u8  final_flag      1 = 本跳即最后一跳
 *   u8  host_len        最终目标主机名长度（final 时有效）
 *   u16 port LE         最终目标端口（final 时有效）
 *   u8  next_id[16]     下一跳 ID（非 final 时有效）
 *   u16 inner_len LE    内层洋葱长度（0 = 无内层）
 * 其后紧跟 inner[inner_len] 与 host[host_len]。 */
#define P2P_ONION_HDR_LEN    22
#define P2P_ONION_ID_LEN     16

#define P2P_ONION_OK         0
#define P2P_ONION_ERR_ARG   -1
#define P2P_ONION_ERR_LEN   -2   /* 缓冲区不足 */
#define P2P_ONION_ERR_AUTH  -3   /* 层验签失败（不是给我的 / 被篡改） */
#define P2P_ONION_ERR_FMT   -4   /* 格式错误 */

/*
 * 派生某一跳的层密钥：
 *   ss = X25519(sk, eph_pub)          （sk 为本跳静态私钥 / 建电路方临时私钥）
 *   K  = HKDF(salt, IKM = ss || my_id, info="p2p:onion:layer:v2", L=16)
 *
 * 建电路方用 (临时私钥, 对端静态公钥)，解层方用 (本跳静态私钥, 层内临时公钥)，
 * 两边算出同一个 ss —— 这就是 X25519 的双向性。
 */
int p2p_onion_layer_key(const uint8_t sk[P2P_ONION_SK_LEN],
                        const uint8_t eph_pub[P2P_ONION_EPH_LEN],
                        const uint8_t salt[P2P_ONION_SALT_LEN],
                        const uint8_t my_id[P2P_ONION_ID_LEN],
                        uint8_t out[P2P_ONION_KEY_LEN]);

/*
 * 构建洋葱（endpoint 侧，从最后一跳往前逐层包裹）。
 *
 * hops_flat     : n_hops 个节点 ID 连续缓冲（首跳 -> 最后一跳）
 * hop_pub_flat  : n_hops 个对应跳的静态 X25519 公钥（32 字节/跳）
 * out           : 可为 NULL，仅探测所需长度
 */
int p2p_onion_build(const uint8_t *hops_flat, int n_hops,
                    const uint8_t *hop_pub_flat,
                    const uint8_t salt[P2P_ONION_SALT_LEN],
                    const char *final_host, uint16_t final_port,
                    uint8_t *out, size_t cap, size_t *out_len);

/*
 * 剥开一层（每跳侧，需要本跳静态私钥）。
 * 层密钥不对 -> P2P_ONION_ERR_AUTH（统一表现，不区分"不是给我的"与"被篡改"）。
 */
int p2p_onion_peel(const uint8_t sk[P2P_ONION_SK_LEN],
                   const uint8_t salt[P2P_ONION_SALT_LEN],
                   const uint8_t my_id[P2P_ONION_ID_LEN],
                   const uint8_t *onion, size_t onion_len,
                   int *final_flag,
                   uint8_t next_id[P2P_ONION_ID_LEN],
                   char *final_host, size_t host_cap, uint16_t *final_port,
                   uint8_t *inner, size_t inner_cap, size_t *inner_len);

/* 完整电路头：version || salt || onion_len(u16 LE) || onion */
int p2p_onion_build_hdr(const uint8_t *hops_flat, int n_hops,
                        const uint8_t *hop_pub_flat,
                        const uint8_t salt[P2P_ONION_SALT_LEN],
                        const char *final_host, uint16_t final_port,
                        uint8_t *out, size_t cap, size_t *out_len);

int p2p_onion_parse_hdr(const uint8_t *in, size_t len,
                        uint8_t salt_out[P2P_ONION_SALT_LEN],
                        const uint8_t **onion_out, size_t *onion_len);

/* 中间跳转发剩余洋葱：u16 LE inner_len || inner */
int p2p_onion_build_fwd(const uint8_t *inner, size_t inner_len,
                        uint8_t *out, size_t cap, size_t *out_len);
int p2p_onion_parse_fwd(const uint8_t *in, size_t len,
                        const uint8_t **inner_out, size_t *inner_len);

const char *p2p_onion_errstr(int e);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_P2P_ONION_H */
