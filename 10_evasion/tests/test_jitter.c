#include "evasion.h"
#include "evasion_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static int test_reproducible(void)
{
    /* 同种子必须产生相同序列 */
    jitter_sched_t a, b;
    jitter_sched_init(&a, 5000, 40, 0x12345678u);
    jitter_sched_init(&b, 5000, 40, 0x12345678u);
    for (int i = 0; i < 100; i++) {
        int va = jitter_sched_next(&a);
        int vb = jitter_sched_next(&b);
        if (va != vb) {
            fprintf(stderr, "not reproducible at i=%d: %d vs %d\n", i, va, vb);
            return 1;
        }
        if (va < 1) { fprintf(stderr, "non-positive: %d\n", va); return 1; }
    }
    printf("  [PASS] jitter reproducible (seed=0x12345678, 100 rounds)\n");
    return 0;
}

static int test_jitter_bounds(void)
{
    jitter_sched_t js;
    jitter_sched_init(&js, 60000, 50, 0xDEADBEEFu);
    int minv = 0x7fffffff, maxv = -1;
    for (int i = 0; i < 50; i++) {
        int v = jitter_sched_next(&js);
        if (v < minv) minv = v;
        if (v > maxv) maxv = v;
    }
    int lo = 60000 - 60000 * 50 / 100; /* 30000 */
    int hi = 60000 + 60000 * 50 / 100; /* 90000 */
    if (minv < lo - 1 || maxv > hi + 1) {
        fprintf(stderr, "bounds: min=%d max=%d expect [%d,%d]\n", minv, maxv, lo, hi);
        return 1;
    }
    printf("  [PASS] jitter bounds [%d, %d] within [%d, %d]\n", minv, maxv, lo, hi);
    return 0;
}

static int test_zero_jitter(void)
{
    jitter_sched_t js;
    jitter_sched_init(&js, 3000, 0, 1);
    for (int i = 0; i < 50; i++) {
        int v = jitter_sched_next(&js);
        if (v != 3000) { fprintf(stderr, "zero jitter got %d\n", v); return 1; }
    }
    printf("  [PASS] jitter zero pct fixed\n");
    return 0;
}

int main(void)
{
    srand((unsigned)time(NULL));
    int f = 0;
    f |= test_reproducible();
    f |= test_jitter_bounds();
    f |= test_zero_jitter();
    return f;
}
