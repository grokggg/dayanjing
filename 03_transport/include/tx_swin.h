#ifndef TX_SWIN_H
#define TX_SWIN_H

#include <stddef.h>
#include <stdint.h>

/* 通用滑动窗口 ARQ（纯逻辑层，不碰 socket）。
   DNS 隧道与 ICMP 隧道共用，避免两套重传逻辑各自走偏。

   序号空间：一片数据一个序号，最后一片固定为 FIN 片（净荷长度 0）。
   即 total = 数据片数 + 1，序号 0 .. total-1。
   窗口内固定槽位，不动态分配：内存行为可预测，无泄漏面。 */

#define TX_SWIN_MAX     32      /* 窗口容量上限 */
#define TX_SWIN_CHUNK   1024    /* 单片净荷上限 */

#define TX_SWIN_ERR_ARGS    -1
#define TX_SWIN_ERR_RANGE   -2  /* 序号落在窗口之外（重复/超前） */
#define TX_SWIN_ERR_TOOBIG  -3  /* 单片超过 TX_SWIN_CHUNK */
#define TX_SWIN_ERR_NOSPACE -4  /* 输出缓冲不足 */
#define TX_SWIN_DONE        1   /* 全部交付完毕 */

typedef struct {
    uint32_t base;      /* 已确认的最小未确认序号（窗口下界） */
    uint32_t next;      /* 下一个待发序号 */
    uint32_t total;     /* 总片数，含 FIN 片 */
    uint32_t size;      /* 窗口容量，<= TX_SWIN_MAX */
} tx_swin_tx_t;

typedef struct {
    uint32_t base;      /* 下一个待交付序号 */
    uint32_t size;
    uint32_t total;     /* 已探知总片数（收到 FIN 片时确定） */
    int      closed;    /* 已收到 FIN 片 */
    uint8_t  slot[TX_SWIN_MAX][TX_SWIN_CHUNK];
    uint16_t slen[TX_SWIN_MAX];
    uint8_t  used[TX_SWIN_MAX];
} tx_swin_rx_t;

/* ---- 发送窗口 ---- */
void tx_swin_tx_init(tx_swin_tx_t *w, uint32_t size, uint32_t total);

/* 取下一个可发序号。返回 0 并写 *seq；窗口满或已发完返回 TX_SWIN_DONE */
int  tx_swin_tx_next(tx_swin_tx_t *w, uint32_t *seq);

/* 累积确认：推进 base 到 ack（不含）。ack 越界返回 RANGE */
int  tx_swin_tx_ack(tx_swin_tx_t *w, uint32_t ack);

/* 全部片均已确认 */
int  tx_swin_tx_done(const tx_swin_tx_t *w);

/* 超时重扫用：返回未确认区间 [from, from+count) */
int  tx_swin_tx_pending(const tx_swin_tx_t *w, uint32_t *from, uint32_t *count);

/* ---- 接收窗口 ---- */
void tx_swin_rx_init(tx_swin_rx_t *w, uint32_t size);

/* 收片。落在窗口内则入槽，重复片返回 OK 且不覆盖；窗口外返回 RANGE */
int  tx_swin_rx_put(tx_swin_rx_t *w, uint32_t seq, int fin,
                    const uint8_t *d, size_t n);

/* 按序交付连续片，写入 out。返回 TX_SWIN_DONE 表示已交付到 FIN */
int  tx_swin_rx_drain(tx_swin_rx_t *w, uint8_t *out, size_t cap, size_t *olen);

/* 是否已收到 FIN 且全部交付 */
int  tx_swin_rx_done(const tx_swin_rx_t *w);

#endif
