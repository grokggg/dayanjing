#define _DEFAULT_SOURCE
#include "evasion.h"
#include "evasion_internal.h"

#include <unistd.h>
#include <sys/types.h>

void jitter_sched_init(jitter_sched_t *js, int base_interval_ms,
                       int jitter_pct, uint32_t seed)
{
    if (!js) return;
    js->base_interval_ms = base_interval_ms > 0 ? base_interval_ms : 1000;
    js->jitter_pct = jitter_pct < 0 ? 0 : (jitter_pct > 200 ? 200 : jitter_pct);
    js->seed = seed ? seed : 0x9E3779B1u;
}

/*
 * 线性同余生成器 (glibc 参数), 周期长, 无需系统调用。
 * 结果归一化到 [0, 1) 区间, 用于计算抖动偏移。
 */
static uint32_t lcg_next(uint32_t *seed)
{
    *seed = (uint32_t)(*seed * 1103515245u + 12345u);
    return *seed;
}

int jitter_sched_next(jitter_sched_t *js)
{
    if (!js) return -1;
    if (js->jitter_pct == 0)
        return js->base_interval_ms;

    uint32_t r = lcg_next(&js->seed);
    /* 归一化到 [-1, 1] */
    double f = ((double)r / 4294967296.0) * 2.0 - 1.0;
    double offset = (double)js->base_interval_ms * (double)js->jitter_pct / 100.0 * f;
    int result = (int)((double)js->base_interval_ms + offset);
    if (result < 1) result = 1;
    return result;
}

int jitter_sleep(jitter_sched_t *js)
{
    int ms = jitter_sched_next(js);
    if (ms <= 0) return EVASION_OK;
    /* 用 usleep, 精度足够心跳场景 */
    return usleep((useconds_t)ms * 1000u);
}
