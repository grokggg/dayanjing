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
#include <sys/wait.h>
#include <signal.h>

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
 * 故单点不可定论，须与 TracerPid 等信号聚合。
 *
 * 关键约束：TRACEME 绝不能在调用进程自身上执行。
 *
 *   成功时，调用者会变成其父进程的 tracee。此后任何信号传递都会让它
 *   进入 tracing stop，而真实的父进程（shell、systemd、启动器、回归
 *   脚本）根本不会 PTRACE_CONT。后果是植入体在完全干净的机器上把自己
 *   卡死，现象是"进程挂起、超时杀不掉"，与是否被调试毫无关系。
 *   这是自伤，不是检测。
 *
 *   本函数此前直接在调用进程上执行 TRACEME，正是 selftest 与回归脚本
 *   间歇性挂起的根因：进程停在 ptrace_stop，父进程永远等它，
 *   而上层表现为"命令卡住"，与业务逻辑毫无联系，极难定位。
 *
 * 故改在短命子进程里执行被测动作，调用进程只回收结果：
 *   子进程未被追踪 -> TRACEME 成功 -> 退出码 0  -> CLEAN
 *   子进程已被追踪 -> EPERM        -> 退出码 2  -> HOSTILE
 *   其他错误                        -> 退出码 3  -> SUSPECT
 * 子进程 _exit 不触发 group-stop，waitpid 可正常回收，不留僵尸。
 * 未能确认子进程状态时绝不返回 CLEAN——宁可误报，不可漏报。
 */
int df_debug_ptrace_traceme(void)
{
    pid_t pid;
    int   st = 0;
    int   i, reaped = 0;

    pid = fork();
    if (pid < 0) return DF_ERR_IO;

    if (pid == 0) {
        long r;
        int  e;
        errno = 0;
        r = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        e = errno;
        if (r == -1L) _exit((e == EPERM) ? 2 : 3);
        _exit(0);
    }

    for (i = 0; i < 200; i++) {              /* 最多 2 秒 */
        pid_t w = waitpid(pid, &st, WNOHANG);
        if (w == pid) { reaped = 1; break; }
        if (w < 0) break;                    /* 无从回收：不假装成功 */
        usleep(10000);
    }
    if (!reaped) {
        kill(pid, SIGKILL);
        if (waitpid(pid, &st, 0) == pid) reaped = 1;
    }
    if (!reaped) return DF_ERR_IO;

    if (WIFEXITED(st)) {
        switch (WEXITSTATUS(st)) {
        case 0:  return DF_CLEAN;
        case 2:  return DF_HOSTILE;
        case 3:  return DF_SUSPECT;
        default: return DF_SUSPECT;
        }
    }
    /* 子进程被信号终止：不构成"被调试"的证据，也绝不报 CLEAN */
    return DF_SUSPECT;
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
