#ifndef EVASION_H
#define EVASION_H
#include <stddef.h>
#include <stdint.h>

/* 分片：把 frame 拆成若干 chunk。每个 chunk 固定占用 mtu 字节：
 *   [seq u16 LE][plen u16 LE][payload ... 补零到 mtu-4]
 * out 需 >= chunks*mtu。成功返回写入总字节数，*chunks 返回片数。 */
size_t ev_frag_split(const uint8_t *frame, size_t len, size_t mtu,
                     uint8_t *out, size_t cap, size_t *chunks);

/* 重组：从 chunk 缓冲区还原 frame。成功 0，*outlen 为原始长度 */
int ev_frag_reassemble(const uint8_t *chunks, size_t chunks_len, size_t mtu,
                       uint8_t *out, size_t *outlen);

/* 睡眠抖动：返回 [base_ms, base_ms+jitter_ms] 区间内的随机延迟 */
int ev_jitter(int base_ms, int jitter_ms);

/* ---- 伪装模式（进阶） ---- */
typedef enum {
    EV_MODE_NONE = 0,
    EV_MODE_DOMAIN_FRONT,   /* HTTP：Host 为前置域名，body 承载 frame */
    EV_MODE_DOH,            /* DoH 形态：POST /dns-query */
    EV_MODE_TLS_HELLO       /* TLS ClientHello 记录形态 */
} ev_mode_t;

/* 包装：把 frame 伪装成对应协议报文。返回写入长度，失败 0 */
size_t ev_camouflage(ev_mode_t mode, const uint8_t *frame, size_t len,
                     const char *host, uint8_t *out, size_t cap);

/* 解伪装：还原 frame。*out_len 入参为 out 容量，出参为实际长度 */
int ev_decamouflage(ev_mode_t mode, const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len);

#endif
