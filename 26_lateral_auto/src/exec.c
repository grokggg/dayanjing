/* 26_lateral_auto/src/exec.c —— ssh 命令行构造与真实执行 */
#include "lateral_auto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <sys/wait.h>
#include <fcntl.h>

/*
 * argv 序列（'\0' 分隔，末尾双 '\0'）：
 *   ssh
 *   -o BatchMode=yes
 *   -o StrictHostKeyChecking=no
 *   -o UserKnownHostsFile=/dev/null
 *   -o ConnectTimeout=<ceil(ms/1000)>
 *   -p <port>
 *   [-o IdentitiesOnly=yes -i <key>]     仅当提供 key_path
 *   <user>@<host>
 *   <remote_cmd>
 */
size_t lat_ssh_argv(const lat_ssh_opt_t *o, char *out, size_t cap)
{
    size_t used = 0;
    char  *p = out;
    char   tobuf[32];
    char   portbuf[32];
    char   tgt[LAT_HOST_MAX + LAT_USER_MAX + 4];

    if (!o || !out || cap < 64) return 0;
    if (!o->host || !o->user || !o->remote_cmd) return 0;

    /* 硬规则 2：ConnectTimeout 必须为正，否则挂死 */
    int cto = o->connect_timeout_ms;
    if (cto <= 0) cto = 5;
    {
        int sec = cto / 1000;
        if (sec < 1) sec = 1;          /* ssh 不接受 0 */
        /* 只写值本身：前面的 PUSH("-o") 已经给出了选项名。
           写成 "-o ConnectTimeout=N" 会让 ssh 把 "-o" 当成配置选项名，
           报 Bad configuration option 并退出 —— 每次调用都失败。 */
        snprintf(tobuf, sizeof(tobuf), "ConnectTimeout=%d", sec);
    }
    snprintf(portbuf, sizeof(portbuf), "%d", o->port > 0 ? o->port : 22);

    if (strlen(o->user) + strlen(o->host) + 2 > sizeof(tgt)) return 0;
    snprintf(tgt, sizeof(tgt), "%s@%s", o->user, o->host);

#define PUSH(s) do {                                   \
        size_t l = strlen(s) + 1;                      \
        if (used + l >= cap) return 0;                 \
        memcpy(p + used, s, l);                        \
        used += l;                                     \
    } while (0)

    PUSH("ssh");
    PUSH("-o");
    PUSH("BatchMode=yes");
    PUSH("-o");
    PUSH("StrictHostKeyChecking=no");
    PUSH("-o");
    PUSH("UserKnownHostsFile=/dev/null");
    PUSH("-o");
    PUSH(tobuf);
    PUSH("-p");
    PUSH(portbuf);
    if (o->key_path && *o->key_path) {
        PUSH("-o");
        PUSH("IdentitiesOnly=yes");
        PUSH("-i");
        PUSH(o->key_path);
    }
    PUSH(tgt);
    PUSH(o->remote_cmd);
#undef PUSH

    if (used + 1 >= cap) return 0;
    p[used] = '\0';                    /* 第二个 '\0' 终止序列 */
    used++;
    return used;
}

/* 从 argv 串恢复成 char*[] */
static int argv_split(char *blob, size_t len, char **argv, size_t cap)
{
    size_t n = 0;
    size_t i = 0;

    while (i < len) {
        if (blob[i] == '\0') break;      /* 序列终止，不产生空参数 */
        if (n >= cap) return -1;
        argv[n++] = blob + i;
        i += strlen(blob + i) + 1;
    }
    if (n >= cap) return -1;
    argv[n] = NULL;
    return (int)n;
}

/*
 * 真实 fork/exec。带硬超时：超时即 SIGKILL 子进程并回收。
 * 返回 0 表示远端命令成功（ssh 退出码 0）。
 */
int lat_ssh_exec(const lat_ssh_opt_t *o, const char *ssh_bin,
                 char *out, size_t cap, int timeout_ms)
{
    char   blob[2048];
    size_t blen;
    char  *argv[32];
    int    pfd[2];
    pid_t  pid;
    int    rc = -1;

    if (!o || !ssh_bin) return -1;
    if (out && cap > 0) out[0] = '\0';

    blen = lat_ssh_argv(o, blob, sizeof(blob));
    if (blen == 0) return -1;
    if (argv_split(blob, blen, argv, sizeof(argv) / sizeof(argv[0])) < 0)
        return -1;

    if (pipe(pfd) != 0) return -1;

    pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }

    if (pid == 0) {
        /*
         * 子进程：stdin 指向 /dev/null，stdout/stderr 指向管道，
         * 并关闭全部无关 fd（>=3）。
         *
         * 不关的后果：被执行的程序或其派生的孙进程会持有调用方的
         * stdout 管道写端。即便它早已退出，调用方仍然等不到 EOF，
         * 表现为"命令挂起"——与网络、凭据、目标存活全都无关。
         * 这是本层必须自己保证的，不能指望调用方。
         */
        int devnull = open("/dev/null", O_RDONLY);
        long maxfd  = sysconf(_SC_OPEN_MAX);
        close(pfd[0]);
        dup2(pfd[1], 1);
        dup2(pfd[1], 2);
        if (pfd[1] > 2) close(pfd[1]);
        if (devnull >= 0) {
            dup2(devnull, 0);
            if (devnull > 2) close(devnull);
        }
        if (maxfd < 0)   maxfd = 256;
        if (maxfd > 4096) maxfd = 4096;
        for (int fd = 3; fd < (int)maxfd; fd++) close(fd);
        execv(ssh_bin, argv);
        _exit(127);
    }

    close(pfd[1]);

    {
        int  hard_to = timeout_ms > 0 ? timeout_ms : 30000;
        size_t off = 0;
        int   timed_out = 0;
        int   elapsed = 0;

        for (;;) {
            struct pollfd pf;
            int pr;
            int wst;
            pid_t w;

            pf.fd = pfd[0];
            pf.events = POLLIN;
            pf.revents = 0;
            pr = poll(&pf, 1, 200);
            if (pr > 0 && (pf.revents & POLLIN)) {
                char buf[1024];
                ssize_t n = read(pfd[0], buf, sizeof(buf));
                if (n > 0) {
                    if (out && cap > 1 && off < cap - 1) {
                        size_t room = cap - 1 - off;
                        size_t take = (size_t)n < room ? (size_t)n : room;
                        memcpy(out + off, buf, take);
                        off += take;
                        out[off] = '\0';
                    }
                    /* 缓冲满仍继续排空，否则子进程阻塞在写 */
                    continue;
                }
                if (n == 0) break;      /* EOF */
                if (n < 0 && errno != EINTR && errno != EAGAIN) break;
            }

            /* 检查子进程是否已退出 */
            w = waitpid(pid, &wst, WNOHANG);
            if (w == pid) {
                /* 读残余输出 */
                for (;;) {
                    struct pollfd pf2;
                    ssize_t n;
                    char buf[1024];
                    pf2.fd = pfd[0];
                    pf2.events = POLLIN;
                    pf2.revents = 0;
                    if (poll(&pf2, 1, 0) <= 0) break;
                    n = read(pfd[0], buf, sizeof(buf));
                    if (n <= 0) break;
                    if (out && cap > 1 && off < cap - 1) {
                        size_t room = cap - 1 - off;
                        size_t take = (size_t)n < room ? (size_t)n : room;
                        memcpy(out + off, buf, take);
                        off += take;
                        out[off] = '\0';
                    }
                }
                rc = (WIFEXITED(wst) && WEXITSTATUS(wst) == 0) ? 0
                                                               : WEXITSTATUS(wst);
                goto done;
            }

            elapsed += 200;
            if (elapsed >= hard_to) {
                timed_out = 1;
                break;
            }
        }

        if (timed_out) {
            kill(pid, SIGKILL);
            { int wst; waitpid(pid, &wst, 0); }
            rc = -2;                       /* 明确区分"超时"与"非零退出" */
        }
    }

done:
    close(pfd[0]);
    return rc;
}
