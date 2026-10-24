/* tls_int.h — 25_tls 内部原语：客户端与服务端共用，不对外暴露
 *
 * 为什么单独一个头而不是并进 tls.h：
 *   tls.h 是调用方（植入体、域前置层）唯一该看到的东西。把 PRF 之类的内部
 *   细节放进去，等于邀请外部直接调用一个"换了实现就悄悄不一致"的函数。
 *
 * 为什么共用而不是各写一份：
 *   PRF 写两份必然出现"两份都能跑、互相连不上"的情况 —— 握手会失败在
 *   Finished 校验上，而错误信息指向密钥/摘要，排查方向完全错。
 */
#ifndef TLS_INT_H
#define TLS_INT_H

#include <stdint.h>
#include <stddef.h>

/* TLS 1.2 P_SHA256 */
void tls_prf_sha256(const uint8_t *secret, size_t slen,
                    const char *label, size_t label_len,
                    const uint8_t *seed, size_t seed_len,
                    uint8_t *out, size_t out_len);

static inline size_t put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
    return 2;
}

#endif /* TLS_INT_H */
