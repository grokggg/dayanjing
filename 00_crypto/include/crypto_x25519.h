/*
 * DAYANJING v4 — crypto_x25519.h
 *
 * X25519（RFC 7748）—— Curve25519 上的 ECDH，自研实现。
 *
 * ====================================================================
 * 为什么需要它
 * ====================================================================
 * 洋葱路由原先的层密钥派生是：
 *     K[i] = HKDF(salt, IKM=master, info=... || hop_id)
 * master 是**全网共享**的一份配置 —— 任一跳被攻破拿到 master，
 * 就能算出**所有跳**的层密钥（只要知道路径），整条电路的形状暴露。
 *
 * 改为 X25519 后（Tor ntor 同级别的 ephemeral-static 握手）：
 *   - 每一跳持有**自己的**静态密钥对 (sk_i, pk_i)
 *   - 建电路方为每跳生成**临时**密钥对 (e_i, E_i)
 *   - 该跳层密钥 = HKDF(salt, IKM = X25519(sk_i, E_i) || my_id, info=...)
 *   - 临时公钥 E_i 明文随该层携带
 *
 * 性质：
 *   1. 不存在全网共享密钥 —— 攻破一跳只得到该跳静态私钥
 *   2. 该跳只能解开"以自己为跳"的层，解不出其他层（路径不可知）
 *   3. 临时密钥每条电路随机 —— 同一跳在不同电路上层密钥不同
 *
 * 已知边界（与 Tor ntor 相同，不夸大）：
 *   ephemeral-static 不提供完全前向保密 —— 若某跳静态私钥泄露，
 *   且攻击者完整录制了电路建立报文，可离线还原该跳那一层。
 *   要完全 PFS 需静态密钥定期轮换，属运维范畴。
 *
 * ====================================================================
 * 实现说明
 * ====================================================================
 * 域：GF(2^255 - 19)，元素以 16 个 16-bit 小端 limb 表示。
 * 乘法用 textbook 32x32 -> 折回（2^256 ≡ 38 mod p），
 * 求逆用 p-2 次幂的平方-乘。未做汇编优化，常数时间只保证到
 * "不按秘密位分支"这一层（掩码 swap、固定轮数 ladder）。
 */

#ifndef DAYANJING_CRYPTO_X25519_H
#define DAYANJING_CRYPTO_X25519_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define X25519_KEY_LEN     32
#define X25519_OK           0
#define X25519_ERR_ARG     -1

/*
 * 生成静态密钥对。私钥按 RFC 7748 做 clamp（低 3 位清零、最高位固定）。
 * 随机源为 /dev/urandom，不可用则返回 X25519_ERR_ARG。
 */
int x25519_generate_keypair(uint8_t priv[X25519_KEY_LEN],
                            uint8_t pub[X25519_KEY_LEN]);

/*
 * 由私钥计算公钥（X25519(priv, basepoint=9)）。
 * 内部对 priv 做 clamp，故传入原始随机字节即可，与 generate 结果一致。
 */
int x25519_public_key(const uint8_t priv[X25519_KEY_LEN],
                      uint8_t pub[X25519_KEY_LEN]);

/*
 * 计算共享秘密：X25519(priv, peer_pub)。
 *
 * 全零输出检查：若 peer_pub 是低阶点，共享秘密为全零，
 * 此时返回 X25519_ERR_ARG 且不写出 out —— 避免把常量密钥当成可用密钥。
 */
int x25519_shared(const uint8_t priv[X25519_KEY_LEN],
                  const uint8_t peer_pub[X25519_KEY_LEN],
                  uint8_t out[X25519_KEY_LEN]);

const char *x25519_errstr(int e);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_CRYPTO_X25519_H */
