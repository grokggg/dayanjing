/* DAYANJING v4 — 18_privilege 提权层
 * 内核/sudo/polkit 版本审计 + SUID 面枚举
 * 纯 C11 + POSIX，无第三方依赖。
 */
#ifndef PRIVILEGE_H
#define PRIVILEGE_H

#include <stddef.h>

#define PR_OK             0
#define PR_ERR_ARGS     (-1)
#define PR_ERR_IO       (-2)
#define PR_ERR_NOTFOUND (-3)
#define PR_ERR_BUFSMALL (-4)

#define PR_NAME_MAX     64
#define PR_PATH_MAX    256
#define PR_CVE_MAX      8

const char *pr_errstr(int e);

/* ---- version.c：版本号比较 ----
 * 支持 "5.16.11"、"1.9.5p2"、"0.105-1" 这类带后缀的形式。 */
int  pr_version_cmp(const char *a, const char *b);

/* ---- kernel.c ---- */
typedef struct pr_kernel {
    int major;
    int minor;
    int patch;
} pr_kernel_t;

int  pr_kernel_parse(const char *release, pr_kernel_t *out);

typedef struct pr_cve {
    const char *id;
    const char *desc;
    const char *vuln_from;   /* 受影响起始版本（含），NULL=不限 */
    const char *fixed_in;    /* 首个修复版本（不含），NULL=未修复 */
    int         local;       /* 1=本地提权 */
} pr_cve_t;

const pr_cve_t *pr_kernel_table(size_t *out_n);
const pr_cve_t *pr_sudo_table(size_t *out_n);
const pr_cve_t *pr_polkit_table(size_t *out_n);

/* ver 落在 [vuln_from, fixed_in) 内返回 1 */
int  pr_cve_match(const pr_cve_t *e, const char *ver);
const pr_cve_t *pr_cve_lookup(const char *id);

/* 按版本串审计，命中的 CVE 指针写入 out[] */
int  pr_kernel_audit(const char *ver, const pr_cve_t **out, size_t cap, size_t *out_n);

/* ---- sudo.c ---- */
int  pr_sudo_audit(const char *ver, const pr_cve_t **out, size_t cap, size_t *out_n);

/* ---- polkit.c ---- */
int  pr_polkit_audit(const char *ver, const pr_cve_t **out, size_t cap, size_t *out_n);

/* ---- suid.c ---- */
typedef int (*pr_suid_cb)(const char *name, void *ctx);

int  pr_suid_scan(const char *dir, pr_suid_cb cb, void *ctx, size_t *out_n);
int  pr_suid_known(const char *name);
int  pr_suid_is_setuid(const char *path);

#endif /* PRIVILEGE_H */
