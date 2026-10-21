/*
 * test_exec_hang.c —— agent_exec 的四条挂死路径的回归防护
 * ==========================================================
 * 这些用例的存在理由：旧实现每条都能挂，而且**挂得悄无声息** ——
 * 没有报错、没有超时、只是永远不返回。单看"现有用例全过"发现不了，
 * 必须针对每条路径单独下断言。
 *
 *   1. 输出超过管道容量（64KiB）-> 父等子、子等管道，双向死锁
 *   2. timeout_ms <= 0 -> 旧实现退化成永不超时
 *   3. 命令读 stdin（cat / read）-> 读父进程 stdin，等不到 EOF
 *   4. 命令持续吐输出 -> 旧实现每轮重设 alarm，超时被无限续期
 *
 * 外加一条能力泄露防护：子进程不得持有父进程的 fd。
 */
#define _POSIX_C_SOURCE 200809L
#include "agent.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/wait.h>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)
#define PASS(m)  do { printf("[PASS] %s\n", (m)); } while (0)

static long long now_ms(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return 0;
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* ---------- 1. 超大输出不死锁 ---------- */
static void test_big_output(void)
{
    char out[128];
    size_t olen = 0;
    long long t0 = now_ms();
    /* 200000 字节 >> 64KiB 管道容量。旧实现在这里与子进程互相等待。 */
    int rc = agent_exec("head -c 200000 /dev/zero | tr '\\0' 'a'",
                        out, sizeof out, &olen, 8000);
    long long el = now_ms() - t0;

    CHECK(rc == 0);                 /* 命令本身是成功的，不该报超时 */
    CHECK(olen == sizeof(out) - 1); /* 截断到 cap-1 */
    CHECK(el < 8000);               /* 且必须是"跑完"而不是"等超时" */
    printf("[INFO] 大输出 200000B: rc=%d olen=%zu 耗时=%lldms\n", rc, olen, el);
    PASS("输出远超管道容量不死锁，且按 cap 截断");
}

/* ---------- 2. 非正超时必须拒绝，不得静默变成"永不超时" ---------- */
static void test_bad_timeout(void)
{
    char out[64];
    size_t olen = 0;
    CHECK(agent_exec("echo hi", out, sizeof out, &olen, 0) == -2);
    CHECK(agent_exec("echo hi", out, sizeof out, &olen, -1) == -2);
    PASS("timeout_ms<=0 判为参数错误（旧实现在此永久挂起）");
}

/* ---------- 3. 读 stdin 的命令不卡死 ---------- */
static void test_stdin_is_devnull(void)
{
    char out[64];
    size_t olen = 0;
    long long t0 = now_ms();
    int rc = agent_exec("cat", out, sizeof out, &olen, 3000);
    long long el = now_ms() - t0;
    CHECK(rc == 0);
    CHECK(olen == 0);
    CHECK(el < 2000);
    printf("[INFO] cat: rc=%d olen=%zu 耗时=%lldms\n", rc, olen, el);

    rc = agent_exec("read x", out, sizeof out, &olen, 3000);
    CHECK(rc != -1);
    PASS("cat / read 不因读父进程 stdin 而挂死（stdin 指向 /dev/null）");
}

/* ---------- 4. 持续输出不得让超时续期 ---------- */
static void test_timeout_not_renewed(void)
{
    char out[256];
    size_t olen = 0;
    long long t0 = now_ms();
    int rc = agent_exec("while :; do echo x; done", out, sizeof out, &olen, 400);
    long long el = now_ms() - t0;
    CHECK(rc == -1);            /* 必须判超时 */
    CHECK(el < 1500);           /* 而不是无限续期 */
    printf("[INFO] 持续输出: rc=%d 耗时=%lldms（旧实现会无限续期）\n", rc, el);
    PASS("持续输出的命令不会让超时无限续期");
}

/* ---------- 5. 超时精度：毫秒级，不是秒级 ---------- */
static void test_timeout_granularity(void)
{
    char out[64];
    size_t olen = 0;
    long long t0 = now_ms();
    int rc = agent_exec("sleep 5", out, sizeof out, &olen, 300);
    long long el = now_ms() - t0;
    CHECK(rc == -1);
    /* 旧实现 alarm((300+999)/1000)=1 秒，必然 >= 950ms */
    CHECK(el < 800);
    printf("[INFO] 300ms 超时: rc=%d 耗时=%lldms\n", rc, el);
    PASS("超时为毫秒级（旧实现最小粒度 1 秒）");
}

/* ---------- 6. 子进程不得持有父进程 fd ---------- */
static int fd_listed(const char *buf, int want)
{
    char needle[16];
    snprintf(needle, sizeof needle, "%d", want);
    const char *p = buf;
    while (*p) {
        while (*p == ' ' || *p == '\n' || *p == '\t') p++;
        const char *s = p;
        while (*p && *p != ' ' && *p != '\n' && *p != '\t') p++;
        size_t n = (size_t)(p - s);
        if (n == strlen(needle) && memcmp(s, needle, n) == 0) return 1;
    }
    return 0;
}

static void test_no_inherited_fd(void)
{
    /* 顶高 fd 号，避免与 ls 自己打开的目录 fd 撞号 */
    int dummy[8];
    for (int i = 0; i < 8; i++) dummy[i] = dup(STDOUT_FILENO);

    int probe[2];
    if (pipe(probe) != 0) {
        for (int i = 0; i < 8; i++) close(dummy[i]);
        printf("[SKIP] pipe 失败\n");
        return;
    }
    printf("[INFO] 探测 fd probe[1]=%d\n", probe[1]);

    /* 正向对照：同样的 fork，但**不关闭**继承 fd —— 探针 fd 必然出现。
     * 这一条先证明"检测方法本身有效"，否则下面的 0 命中毫无意义。 */
    {
        int pf[2];
        if (pipe(pf) == 0) {
            pid_t pid = fork();
            if (pid == 0) {
                close(pf[0]);
                dup2(pf[1], STDOUT_FILENO);
                close(pf[1]);
                execl("/bin/sh", "sh", "-c", "ls /proc/self/fd", (char *)NULL);
                _exit(127);
            }
            close(pf[1]);
            char b[1024];
            ssize_t got = read(pf[0], b, sizeof(b) - 1);
            if (got > 0) b[got] = 0; else b[0] = 0;
            close(pf[0]);
            int st = 0;
            while (waitpid(pid, &st, 0) < 0 && errno == EINTR) { }
            CHECK(fd_listed(b, probe[1]));
            PASS("正向对照：不关 fd 时探针 fd 出现在子进程（检测方法有效）");
        }
    }

    /* 真实断言：agent_exec 的子进程里不该再有它 */
    char b[1024];
    size_t bl = 0;
    int rc = agent_exec("ls /proc/self/fd", b, sizeof b, &bl, 3000);
    CHECK(rc == 0);
    printf("[INFO] agent_exec 子进程 fd 表: %s\n", b);
    CHECK(fd_listed(b, probe[1]) == 0);
    PASS("agent_exec 子进程不持有父进程 fd（否则对端等不到 EOF）");

    close(probe[0]);
    close(probe[1]);
    for (int i = 0; i < 8; i++) close(dummy[i]);
}

int main(void)
{
    alarm(120);   /* 看门狗：任何一条挂死都变成失败，而不是拖垮整个回归 */
    printf("=== 04_agent exec 挂死路径回归 ===\n");
    test_big_output();
    test_bad_timeout();
    test_stdin_is_devnull();
    test_timeout_not_renewed();
    test_timeout_granularity();
    test_no_inherited_fd();
    printf("=== result: %s (fail=%d) ===\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
