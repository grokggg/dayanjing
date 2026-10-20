#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "privilege.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 版本区间来自各 CVE 的公开受影响范围。
 * 注意：发行版普遍做 backport，同版本号在不同发行版上可能已修复，
 * 故此处为「指示性」判定，实际利用前须结合目标发行版公告复核。 */

static const pr_cve_t k_kernel_cves[] = {
    { "CVE-2016-5195", "Dirty COW — 竞态写时复制",       "2.6.22", "4.8.3",   1 },
    { "CVE-2021-22555","Netfilter 堆溢出",               "2.6.19", "5.12.0",  1 },
    { "CVE-2022-0847", "DirtyPipe — 管道缓冲覆写",       "5.8.0",  "5.16.11", 1 },
    { "CVE-2022-2588", "nftables 双重释放",              "3.16.0", "5.19.2",  1 },
    { "CVE-2023-0386", "OverlayFS 属主校验绕过",         "5.11.0", "6.2.0",   1 },
};

static const pr_cve_t k_sudo_cves[] = {
    { "CVE-2019-14287", "sudo -u#-1 绕过",               "1.8.0", "1.8.28",  1 },
    { "CVE-2021-3156",  "Baron Samedit — 堆溢出",        "1.8.2", "1.9.5p2", 1 },
    { "CVE-2023-32629", "sudo 密码提示信息泄露",         "1.8.0", "1.9.15",  1 },
};

static const pr_cve_t k_polkit_cves[] = {
    { "CVE-2021-3560",  "polkit 竞争认证绕过",           "0.105", "0.119", 1 },
    { "CVE-2021-4034",  "PwnKit — pkexec 参数溢出",      "0.105", "0.120", 1 },
};

const pr_cve_t *pr_kernel_table(size_t *out_n)
{
    if (out_n) *out_n = sizeof k_kernel_cves / sizeof k_kernel_cves[0];
    return k_kernel_cves;
}

const pr_cve_t *pr_sudo_table(size_t *out_n)
{
    if (out_n) *out_n = sizeof k_sudo_cves / sizeof k_sudo_cves[0];
    return k_sudo_cves;
}

const pr_cve_t *pr_polkit_table(size_t *out_n)
{
    if (out_n) *out_n = sizeof k_polkit_cves / sizeof k_polkit_cves[0];
    return k_polkit_cves;
}

/* 解析 "5.16.11-generic" → {5,16,11}。非数字尾缀忽略。 */
int pr_kernel_parse(const char *release, pr_kernel_t *out)
{
    char   buf[64];
    size_t n;
    char  *p;

    if (!release || !out) return PR_ERR_ARGS;

    out->major = 0;
    out->minor = 0;
    out->patch = 0;

    n = strlen(release);
    if (n == 0) return PR_ERR_ARGS;
    if (n >= sizeof buf) n = sizeof buf - 1;
    memcpy(buf, release, n);
    buf[n] = '\0';

    p = buf;
    out->major = (int)strtol(p, &p, 10);
    if (*p == '.') p++;
    out->minor = (int)strtol(p, &p, 10);
    if (*p == '.') p++;
    out->patch = (int)strtol(p, &p, 10);

    return PR_OK;
}

/* ver ∈ [vuln_from, fixed_in) → 1 */
int pr_cve_match(const pr_cve_t *e, const char *ver)
{
    if (!e || !ver) return 0;
    if (e->vuln_from && pr_version_cmp(ver, e->vuln_from) < 0) return 0;
    if (e->fixed_in && pr_version_cmp(ver, e->fixed_in) >= 0) return 0;
    return 1;
}

const pr_cve_t *pr_cve_lookup(const char *id)
{
    const pr_cve_t *tbl[3];
    size_t n[3];
    size_t i, k;

    if (!id) return NULL;

    tbl[0] = pr_kernel_table(&n[0]);
    tbl[1] = pr_sudo_table(&n[1]);
    tbl[2] = pr_polkit_table(&n[2]);

    for (k = 0; k < 3; k++) {
        for (i = 0; i < n[k]; i++) {
            if (strcmp(tbl[k][i].id, id) == 0) return &tbl[k][i];
        }
    }
    return NULL;
}

static int audit_table(const pr_cve_t *tbl, size_t n, const char *ver,
                       const pr_cve_t **out, size_t cap, size_t *out_n)
{
    size_t i, cnt = 0;

    if (!ver) return PR_ERR_ARGS;

    for (i = 0; i < n; i++) {
        if (!pr_cve_match(&tbl[i], ver)) continue;
        if (out && cnt < cap) out[cnt] = &tbl[i];
        cnt++;
    }
    if (out_n) *out_n = cnt;
    return PR_OK;
}

int pr_kernel_audit(const char *ver, const pr_cve_t **out, size_t cap, size_t *out_n)
{
    size_t n = 0;
    const pr_cve_t *t = pr_kernel_table(&n);
    return audit_table(t, n, ver, out, cap, out_n);
}
