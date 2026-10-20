#define _POSIX_C_SOURCE 200809L
#include "agent.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
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

static void alarm_handler(int sig) { (void)sig; }

int agent_exec(const char *cmd, char *out, size_t cap, size_t *outlen, int timeout_ms) {
    if (!cmd || !out || cap == 0 || !outlen) return -2;
    int fds[2];
    if (pipe(fds) != 0) return -2;
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return -2; }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        close(fds[1]);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    signal(SIGALRM, alarm_handler);
    if (timeout_ms > 0) alarm((unsigned)((timeout_ms + 999) / 1000));
    size_t total = 0;
    int timedout = 0;
    for (;;) {
        ssize_t n = read(fds[0], out + total, cap - 1 - total);
        if (n > 0) {
            total += (size_t)n;
            if (total >= cap - 1) break;
        } else if (n == 0) {
            break;
        } else {
            if (errno == EINTR) timedout = 1;
            break;
        }
    }
    alarm(0);
    if (timedout) kill(pid, SIGKILL);
    int status = 0;
    waitpid(pid, &status, 0);
    close(fds[0]);
    out[total] = '\0';
    *outlen = total;
    if (timedout) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return -3;
    return -2;
}
