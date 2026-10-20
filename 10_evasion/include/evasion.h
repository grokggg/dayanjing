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


/* ---- 流量调度（完整能力） ---- */

typedef struct {
    size_t index;    /* 分片序号 */
    size_t offset;   /* 该片在 chunk 缓冲区中的字节偏移 */
    size_t len;      /* 该片占用长度（固定 mtu，最后一片为实际） */
    int    delay_ms; /* 该片应延迟发送的毫秒数 */
} ev_slot_t;

/* 可复现抖动：同 seed 序列产出相同结果，便于测试与流量规划 */
int ev_jitter_seeded(int base_ms, int jitter_ms, uint32_t *seed);

/* 生成发送计划：先按 mtu 分片，再为每片分配抖动延迟。
 * 成功返回片数；slots 中 offset/len 指向 chunks 缓冲区。
 * 注意：本函数只做分片布局与延迟计算，实际写入 chunks 由调用方调 ev_frag_split */
size_t ev_plan(size_t frame_len, size_t mtu, int base_ms, int jitter_ms,
               uint32_t *seed, ev_slot_t *slots, size_t scap);

#endif
