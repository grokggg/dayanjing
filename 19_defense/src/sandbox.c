#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "defense.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 容器/cgroup 常见标识。cubebox 等沙箱一并纳入。 */
static const char *k_sandbox_markers[] = {
    "docker", "kubepods", "lxc", "containerd", "libpod",
    "podman", "cubebox", "sandbox", "firejail", "gvisor",
    NULL
};

/* 扫描 cgroup 文件内容。path 可注入，便于用临时文件做确定性测试。 */
int df_sandbox_cgroup_file(const char *path, char *out_marker, size_t cap, int *out_verdict)
{
    FILE *f;
    char  line[512];
    int   verdict = DF_CLEAN;

    if (!path) return DF_ERR_ARGS;
    if (out_marker && cap == 0) return DF_ERR_ARGS;
    if (out_marker) out_marker[0] = '\0';

    f = fopen(path, "r");
    if (!f) return DF_ERR_IO;

    while (fgets(line, (int)sizeof line, f)) {
        int i;
        for (i = 0; k_sandbox_markers[i]; i++) {
            if (strstr(line, k_sandbox_markers[i])) {
                verdict = DF_HOSTILE;
                if (out_marker && cap > 0)
                    snprintf(out_marker, cap, "%s", k_sandbox_markers[i]);
                goto done;
            }
        }
    }

done:
    fclose(f);
    if (out_verdict) *out_verdict = verdict;
    return DF_OK;
}

int df_sandbox_cgroup(char *out_marker, size_t cap, int *out_verdict)
{
    return df_sandbox_cgroup_file("/proc/1/cgroup", out_marker, cap, out_verdict);
}

/* /.dockerenv 存在即 Docker 容器 */
int df_sandbox_dockerenv(void)
{
    FILE *f = fopen("/.dockerenv", "r");
    if (f) {
        fclose(f);
        return DF_HOSTILE;
    }
    return DF_CLEAN;
}

/* 容器运行时惯用环境变量 */
int df_sandbox_env(void)
{
    static const char *names[] = {
        "container", "KUBERNETES_SERVICE_HOST", "DOCKER_HOST", "SANDBOX", NULL
    };
    int i;

    for (i = 0; names[i]; i++) {
        if (getenv(names[i])) return DF_HOSTILE;
    }
    return DF_CLEAN;
}

/* PID 1 的 comm：容器里常是 sh/bash/自定义入口，宿主多为 systemd/init */
int df_sandbox_pid1(char *out_comm, size_t cap)
{
    FILE *f;
    char  buf[256];
    size_t n;

    if (!out_comm || cap == 0) return DF_ERR_ARGS;
    out_comm[0] = '\0';

    f = fopen("/proc/1/comm", "r");
    if (!f) return DF_ERR_IO;
    if (!fgets(buf, (int)sizeof buf, f)) {
        fclose(f);
        return DF_ERR_IO;
    }
    fclose(f);

    n = strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = '\0';

    if (n + 1 > cap) return DF_ERR_BUFSMALL;
    memcpy(out_comm, buf, n + 1);
    return DF_OK;
}
