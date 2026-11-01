#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "privilege.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

/* 已知可被用于提权的 SUID 程序名（参考型清单，仅用于面枚举标注） */
static const char *k_known[] = {
    "sudo", "su", "pkexec", "passwd", "chsh", "gpasswd", "newgrp",
    "mount", "umount", "fusermount", "find", "vim", "nano", "less",
    "more", "nmap", "python", "python3", "perl", "ruby", "php",
    "awk", "bash", "sh", "cp", "mv", "tar", "zip", "wget", "curl",
    "ssh", "scp", "openssl", "docker", "lxc-start", "kubectl",
    NULL
};

int pr_suid_known(const char *name)
{
    int i;

    if (!name) return 0;
    for (i = 0; k_known[i]; i++) {
        if (strcasecmp(name, k_known[i]) == 0) return 1;
    }
    return 0;
}

/* 单文件判定：常规文件 + S_ISUID 置位 */
int pr_suid_is_setuid(const char *path)
{
    struct stat st;

    if (!path) return PR_ERR_ARGS;
    if (stat(path, &st) != 0) return PR_ERR_IO;
    if (!S_ISREG(st.st_mode)) return PR_ERR_NOTFOUND;
    return (st.st_mode & S_ISUID) ? 1 : 0;
}

/* 枚举目录下全部 setuid 常规文件。dir 可注入以便确定性测试。 */
int pr_suid_scan(const char *dir, pr_suid_cb cb, void *ctx, size_t *out_n)
{
    DIR           *d;
    struct dirent *e;
    size_t         cnt = 0;

    if (!dir) return PR_ERR_ARGS;

    d = opendir(dir);
    if (!d) return PR_ERR_IO;

    while ((e = readdir(d)) != NULL) {
        char        path[PR_PATH_MAX];
        struct stat st;
        size_t      dl = strlen(dir);
        size_t      nl = strlen(e->d_name);

        if (e->d_name[0] == '.') continue;
        if (dl + 1 + nl + 1 > sizeof path) continue;

        memcpy(path, dir, dl);
        path[dl] = '/';
        memcpy(path + dl + 1, e->d_name, nl + 1);

        if (stat(path, &st) != 0) continue;
        if (!S_ISREG(st.st_mode)) continue;
        if ((st.st_mode & S_ISUID) == 0) continue;

        cnt++;
        if (cb) {
            if (cb(e->d_name, ctx) != 0) break;
        }
    }

    closedir(d);
    if (out_n) *out_n = cnt;
    return PR_OK;
}
