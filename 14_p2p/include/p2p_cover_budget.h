/*
 * DAYANJING v4 — p2p_cover_budget.h
 *
 * 覆盖预算按真实带宽自适应。
 *
 * ====================================================================
 * 被解除的限制
 * ====================================================================
 * 旧实现里 p2p_cover_init(cov, profile, budget_bytes_per_min, ...) 的
 * budget_bytes_per_min 是一个**操作员手写的常量**。三个真实问题：
 *
 *   问题一（与链路能力脱节）：
 *     预算不知道链路有多宽。在窄带链路（GPRS/卫星/低速专线）上手写
 *     一个"看着合理"的预算，覆盖流量本身就成为带宽异常 —— 比静默
 *     更直白的暴露面。在宽带链路上手写小预算，又白白放过可用余量，
 *     静默填不住。
 *
 *   问题二（多跳木桶效应未处理）：
 *     覆盖流量要穿越整条电路，任何一跳超限都会在那里成为异常。
 *     按"本机出口带宽"定的预算，对电路中间的窄跳毫无意义。
 *
 *   问题三（手写值无法随链路变化）：
 *     移动链路带宽会变。手写的常量不随实测更新，链路劣化后覆盖
 *     仍在按旧预算发，等于持续超限。
 *
 * 本模块把预算从"常量"改为**由实测带宽推导**：
 *
 *     link_bytes_per_min = bw_kbps * 7500        （kbps -> 字节/分钟）
 *     budget             = min(link_bytes_per_min * duty_ppm / 1e6, CAP)
 *
 * 多跳时 bw_kbps 取电路中的**最小值**（木桶效应）。
 *
 * ====================================================================
 * 三个必须做对的边界（都不是理论推演，是实测会踩的坑）
 * ====================================================================
 *
 * 一、uint32 溢出 —— 回环实测带宽约 2,097,152 kbps（2 Gbps）。
 *     bw * 7500 = 1.57e10，已超 uint32 上限 4.29e9；再乘 duty 分子
 *     可达 1.57e16，超 uint64 也不远。故全程用 uint64 中间量，并把
 *     bw_kbps 先钳制到 P2P_COVER_BUDGET_BW_CLAMP_KBPS。
 *
 *     顺序也不能随意换：先 /1e6 再 *7500 会让小带宽归零
 *     （bw=1, duty=50000 -> 1*50000/1e6 = 0），故必须 *7500 之后再套 duty。
 *
 * 二、bw_kbps == 0 —— 探测失败与"带宽真的是 0"必须区分。
 *     若把 0 直接算成 budget=0，覆盖会被**静默禁用**，链路退化为静默
 *     链路而调用方毫不知情。这是最危险的失败模式：不是报错，是悄悄
 *     去掉保护。故本模块对 bw=0 返回 P2P_COVER_BUDGET_UNKNOWN，
 *     **不修改**既有预算。
 *
 * 三、预算撑不住静默上界 —— 必须显式报告，不能静默接受。
 *     min_cover 由「最大可容忍静默」导出（见 p2p_cover.h），它是需求；
 *     budget 是约束。当 budget < min_cover * bytes_per_cell 时，静默
 *     填不住。本模块仍然应用预算（不超带宽优先），但返回 CONFLICT，
 *     并给出 achievable_silence_ms 让调用方量化地知道"只够填多长"。
 *     调用方的三个选择：提高 duty、放宽静默上界、换信道。
 *
 * ====================================================================
 * 为什么还要 CAP（绝对上限）
 * ====================================================================
 * 覆盖的目的是**抹平静默**，不是填满带宽。2 Gbps 回环按 5% 算出
 * 786 MB/分钟的覆盖流量是荒谬的：它自己就是最显眼的异常，且会挤占
 * 真实回传。CAP 取 1 MB/分钟 —— 足以覆盖最贵信道（DNS 2040 B/信元）
 * 下维持 250ms 静默上界所需的 489,600 B/分钟，同时挡住探测异常值。
 *
 * ====================================================================
 * 定点约定
 * ====================================================================
 * 全部用 uint64 中间量，最后钳到 uint32。时间由调用方注入，本模块
 * 不读系统时钟（与 cover.c / sched.c 一致）。
 */

#ifndef DAYANJING_P2P_COVER_BUDGET_H
#define DAYANJING_P2P_COVER_BUDGET_H

#include <stdint.h>

#include "p2p_cover.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 默认可占用链路比例：百万分之 50,000 = 5%。
 *
 * 取 5% 而不是更高的理由：探测出的是**链路容量**，不是可用带宽 ——
 * 链路上还有目标的正常业务流量。覆盖挤占业务会让目标变卡，那是
 * 用户可感知的异常，比流量特征更容易被发现。 */
#define P2P_COVER_BUDGET_DEFAULT_DUTY_PPM  50000u

/* 绝对上限（字节/分钟）。理由见文件头「为什么还要 CAP」。 */
#define P2P_COVER_BUDGET_CAP_BYTES_PER_MIN 1048576u

/* 探测值钳制上界（kbps）。100 Gbps —— 超过即视为探测异常。
 * 既防 uint64 溢出，也防异常值推导出荒谬预算。 */
#define P2P_COVER_BUDGET_BW_CLAMP_KBPS     100000000u

/* 默认 TTL：预算超过此值视为陈旧，调用方应重探。5 分钟。 */
#define P2P_COVER_BUDGET_DEFAULT_TTL_US    (300ull * 1000000ull)

/* 返回码 */
#define P2P_COVER_BUDGET_OK         0    /* 已应用 */
#define P2P_COVER_BUDGET_ERR_ARG   -1    /* 参数错误 */
#define P2P_COVER_BUDGET_UNKNOWN   -2    /* 带宽未知；既有预算未改（不静默禁用） */
#define P2P_COVER_BUDGET_CONFLICT  -3    /* 已应用，但预算撑不住 min_cover */

/*
 * 未知/无穷静默的哨兵值：预算为 0（完全无覆盖）时，静默上界不存在。
 * 用 UINT32_MAX 而不是 0 —— 0 会被误读成"静默被压到 0"，语义正好相反。
 */
#define P2P_COVER_BUDGET_SILENCE_NONE 0xFFFFFFFFu

typedef struct {
    uint32_t duty_ppm;              /* 可占用比例（百万分之） */
    uint32_t min_link_kbps;         /* 电路中最窄一跳带宽；0 = 未知 */
    uint32_t n_hops;                /* 已登记跳数 */
    uint32_t budget_bytes_per_min;  /* 推导结果（已钳 CAP） */

    uint64_t probed_at_us;          /* 探测时间基准（注入） */
    uint64_t ttl_us;                /* 有效期 */
    int      known;                 /* 是否有可信实测值 */
    int      conflict;              /* 上次应用是否撑不住 min_cover */
    int      inited;
} p2p_cover_budget_t;

/* 初始化。duty_ppm 为 0 时取默认值。 */
int p2p_cover_budget_init(p2p_cover_budget_t *b, uint32_t duty_ppm,
                          uint64_t now_us);

/* 设置可占用比例（百万分之）。0 视为参数错误。 */
int p2p_cover_budget_set_duty(p2p_cover_budget_t *b, uint32_t duty_ppm);

/* 设置 TTL；0 表示永不过期 */
int p2p_cover_budget_set_ttl(p2p_cover_budget_t *b, uint64_t ttl_us);

/*
 * 开始新电路：清空已登记跳数。
 * 必须在登记第一跳之前调用，否则会与上一电路的窄跳取 min —— 表现为
 * "换到宽带电路后预算仍然很低"，且无任何报错。
 */
int p2p_cover_budget_reset(p2p_cover_budget_t *b, uint64_t now_us);

/*
 * 登记一跳的实测带宽。保留**最小值**（木桶效应）。
 * bw_kbps == 0 表示探测失败 —— 该跳被记为 unknown 但**不影响**已有
 * 最小值（不能让一次探测失败把预算拉到 0）。
 */
int p2p_cover_budget_note_hop(p2p_cover_budget_t *b, uint32_t bw_kbps,
                              uint64_t now_us);

/* 从已登记的带宽推导预算（不修改 cover）。返回 OK / UNKNOWN / ERR_ARG。 */
int p2p_cover_budget_derive(p2p_cover_budget_t *b);

/* 当前预算（字节/分钟） */
uint32_t p2p_cover_budget_get(const p2p_cover_budget_t *b);

/*
 * 把预算应用到 cover。
 *
 * 返回：
 *   OK        已应用，且预算足以维持 min_cover
 *   CONFLICT  已应用，但预算撑不住 min_cover（静默填不住）—— 需调用方决策
 *   UNKNOWN   带宽未知，既有预算未改（绝不静默禁用覆盖）
 *   ERR_ARG   参数错误
 */
int p2p_cover_budget_apply(p2p_cover_budget_t *b, p2p_cover_t *cov);

/*
 * 诊断：给定信道单信元成本，当前预算能达到的静默上界（毫秒）。
 * 返回 P2P_COVER_BUDGET_SILENCE_NONE 表示预算为 0（无覆盖，静默无上界）。
 *
 * 这是 CONFLICT 时的量化依据 —— 调用方据此判断"是放宽静默还是加预算"。
 */
uint32_t p2p_cover_budget_achievable_silence(const p2p_cover_budget_t *b,
                                             uint32_t bytes_per_cell);

/*
 * 预算是否陈旧（超过 TTL）。陈旧不等于错误 —— 只是建议重探。
 * known == 0 时恒返回 0（没有实测值，谈不上陈旧）。
 */
int p2p_cover_budget_stale(const p2p_cover_budget_t *b, uint64_t now_us);

/*
 * 纯函数：kbps -> 字节/分钟 的换算（供测试直接断言，无需构造上下文）。
 * bytes_per_min = bw_kbps * 7500 * duty_ppm / 1e6，钳 CAP。
 * bw_kbps 为 0 时返回 0（调用方应据此判定 unknown，不要当预算用）。
 */
uint32_t p2p_cover_budget_from_kbps(uint32_t bw_kbps, uint32_t duty_ppm);

const char *p2p_cover_budget_errstr(int e);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_P2P_COVER_BUDGET_H */
