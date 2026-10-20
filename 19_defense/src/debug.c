#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "defense.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ptrace.h>

const char *df_errstr(int e)
{
    switch (e) {
    case DF_OK:           return "ok";
    case DF_ERR_ARGS:     return "invalid argument";
    case DF_ERR_IO:       return "io error";
    case DF_ERR_NOMEM:    return "no memory";
    case DF_ERR_UNSUP:    return "unsupported";
    case DF_ERR_NOTFOUND: return "not found";
    case DF_ERR_BUFSMALL: return "buffer too small";
    case DF_ERR_RANGE:    return "out of range";
    default:              return "unknown";
    }
}

int df_verdict_or(int a, int b)
{
    if (a < 0) return b;
    if (b < 0) return a;
    return (a > b) ? a : b;
}

/* /proc/self/status 的 TracerPid：非 0 即被跟踪 */
int df_debug_tracerpid(int *out_pid)
{
    FILE *f;
    char line[256];
    int  pid = -1;
    int  found = 0;

    if (!out_pid) return DF_ERR_ARGS;
    *out_pid = -1;

    f = fopen("/proc/self/status", "r");
    if (!f) return DF_ERR_IO;

    while (fgets(line, (int)sizeof line, f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            const char *p = line + 10;
            while (*p == ' ' || *p == '\t') p++;
            pid   = (int)strtol(p, NULL, 10);
            found = 1;
            break;
        }
    }
    fclose(f);

    if (!found) return DF_ERR_NOTFOUND;
    *out_pid = pid;
    return (pid != 0) ? DF_HOSTILE : DF_CLEAN;
}

/* PTRACE_TRACEME：已被跟踪则 EPERM。容器/seccomp 也会 EPERM，
 * 故单点不可定论，须与 TracerPid 等信号聚合。 */
int df_debug_ptrace_traceme(void)
{
    long r;

    errno = 0;
    r = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    if (r == -1L) {
        return (errno == EPERM) ? DF_HOSTILE : DF_SUSPECT;
    }
    return DF_CLEAN;
}

/* 时序：单步/断点下同一段代码耗时显著变长。
 * 阈值由调用方给，避免硬编码导致在不同主频上误判。 */
int df_debug_timing(uint64_t threshold_ns, uint64_t *out_ns)
{
    struct timespec a, b;
    uint64_t delta;
    volatile uint64_t acc = 0;
    int i;

    if (clock_gettime(CLOCK_MONOTONIC, &a) != 0) return DF_ERR_IO;

    for (i = 0; i < 100000; i++) acc = acc + (uint64_t)i;

    if (clock_gettime(CLOCK_MONOTONIC, &b) != 0) return DF_ERR_IO;

    /* 借位用无符号回绕吸收，避免 nsec 相减为负 */
    delta  = (uint64_t)(b.tv_sec - a.tv_sec) * 1000000000ULL;
    delta += (uint64_t)b.tv_nsec;
    delta -= (uint64_t)a.tv_nsec;

    (void)acc;
    if (out_ns) *out_ns = delta;
    return (delta > threshold_ns) ? DF_SUSPECT : DF_CLEAN;
}
