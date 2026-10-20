/*
 * DAYANJING v4 — p2p_mix.h
 *
 * 混时序（Traffic Mixing）—— 解除"信元只做了长度整形，时序仍可关联"的限制。
 *
 * ====================================================================
 * 定长信元解决了什么、没解决什么
 * ====================================================================
 * 定长信元（p2p_cell.h）让每个报文都是 512 字节，消除了"包长 == 载荷长度"
 * 的泄漏。但流量分析还有第二维：**时序与顺序**。
 *   - 命令下发是一条突发，回传截图是另一条突发
 *   - 两条流的信元在时间轴上各自成簇，簇的形状仍然可区分
 *   - 观察者在链路两侧做**关联**：入口突发与出口突发一一对应即可确认中继关系
 *
 * ====================================================================
 * 混时序的做法
 * ====================================================================
 * 把时间切成固定长度的"片(epoch/slice)"，每片只做两件事：
 *   1. 把该片内入队的信元**跨流交错**发出（保持每条流内部顺序）
 *   2. 无论这一片有多少真实数据，输出**恒定 batch 个信元**，不足补覆盖信元
 *
 * 效果：
 *   - 跨流交错 -> 多条流在时间轴上被织在一起，单条流的突发形状被打破
 *   - 恒定输出速率 -> "有数据就快、没数据就停"的对应消失
 *   - 每片输出量恒定 -> 体积相关性也被削平
 *
 * ====================================================================
 * 为什么是"保持流内顺序"的交错，而不是全随机洗牌
 * ====================================================================
 * 全随机洗牌会打乱同一条流内信元的相对顺序，而信元层（p2p_cell.h）的
 * IV = pfx || counter 是**隐式严格递增**的 —— 同一连接内乱序到达会被判为
 * 重放/错序（gcm_open 直接 AUTH 失败）。
 *
 * 因此"流"必须是**各自独立的连接/信元上下文**：每条流有自己的计数器空间，
 * 混序器改变的是"这一片里哪条流的信元先发出去"，而不是改变某条流内部
 * 信元的先后。这正是 flush 输出 (stream, cell) 对、由调用方按 stream 投递到
 * 各自链路的原因 —— 混序发生在**多条链路之间**，不在单条链路内部。
 *
 * ====================================================================
 * 已知边界（不夸大）
 * ====================================================================
 * 混时序增加**延迟**（最坏一个片长），且只能混淆"本节点出口"的时序；
 * 全局被动观察者若同时看到入口与出口，仍可能通过总字节数做统计关联。
 * 完整抗关联需要端到端覆盖流量 + 更长的时间窗，这里做到的是单跳混序。
 */

#ifndef DAYANJING_P2P_MIX_H
#define DAYANJING_P2P_MIX_H

#include "p2p_cell.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define P2P_MIX_MAXQ       64    /* 入队缓冲上限 */
#define P2P_MIX_MAX_BATCH  32    /* 每片最多输出信元数 */

#define P2P_MIX_OK        0
#define P2P_MIX_ERR_ARG  -1
#define P2P_MIX_ERR_FULL -2     /* 队列满：调用方应降速而不是丢弃后静默 */
#define P2P_MIX_ERR_LEN  -3     /* 输出缓冲不足 batch*512 */

typedef struct {
    uint32_t stream;                 /* 流标识 */
    uint32_t ord;                    /* 该流内序号，用于保持流内顺序 */
    uint8_t  cell[P2P_CELL_WIRE];
} p2p_mix_item_t;

/* 出片项：stream 决定该信元应投递到哪条链路 */
#define P2P_MIX_STREAM_COVER 0xffffffffu   /* 覆盖信元专用流 */

typedef struct {
    uint32_t stream;
    uint8_t  cell[P2P_CELL_WIRE];
} p2p_mix_out_t;

typedef struct {
    p2p_mix_item_t q[P2P_MIX_MAXQ];
    int      n;
    uint32_t s;                 /* xorshift32 状态 */
    uint32_t period_ms;         /* 片长 */
    uint32_t next_flush_ms;     /* 下一片到期时刻 */
    uint32_t batch;             /* 每片固定输出信元数 */
    uint32_t ord_next[P2P_MIX_MAXQ];  /* 按流累计序号（stream 取模索引） */
} p2p_mix_t;

int  p2p_mix_init(p2p_mix_t *mx, uint32_t seed, uint32_t period_ms,
                  uint32_t batch, uint32_t now_ms);

/*
 * 入队一个已封装好的信元（512 字节），stream 标识其所属流。
 * 队列满返回 P2P_MIX_ERR_FULL —— 这是**背压信号**，调用方应停止生成而非丢弃。
 */
int  p2p_mix_enqueue(p2p_mix_t *mx, uint32_t stream,
                     const uint8_t cell[P2P_CELL_WIRE]);

/* 该片是否到期 */
int  p2p_mix_due(const p2p_mix_t *mx, uint32_t now_ms);

/*
 * 出片：输出**恰好 batch 个** (stream, cell) 对，调用方按 stream 投递。
 *   - 真实信元按"随机挑流 + 取该流队首"交错输出（流内保序，跨流混序）
 *   - 真实信元不足 batch 时，用覆盖信元补足（stream = P2P_MIX_STREAM_COVER，
 *     用 cc 这个专门的覆盖上下文加密）
 *   - 真实信元多于 batch 时，多余部分**留在队列**等下一片（恒定输出速率）
 * n_out 输出项数（恒等于 batch），n_real 为其中真实信元数。
 * cap_items 以「项数」计，不是字节数。
 */
int  p2p_mix_flush(p2p_mix_t *mx, uint32_t now_ms, p2p_cell_ctx_t *cc,
                   p2p_mix_out_t *out, size_t cap_items,
                   size_t *n_out, size_t *n_real);

/* 队列积压与流数统计（供测试与自适应调节观察） */
int  p2p_mix_stats(const p2p_mix_t *mx, int *n_queued, int *n_streams);

const char *p2p_mix_errstr(int e);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_P2P_MIX_H */
