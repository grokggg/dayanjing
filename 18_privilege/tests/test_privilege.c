#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "privilege.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, name) do {                                        \
    if (cond) { printf("[PASS] %s\n", (name)); g_pass++; }            \
    else      { printf("[FAIL] %s  (line %d)\n", (name), __LINE__); g_fail++; } \
} while (0)

static char   g_names[16][PR_NAME_MAX];
static size_t g_nn = 0;

static void reset_names(void) { g_nn = 0; }

static int cb_collect(const char *name, void *ctx)
{
    size_t n;
    (void)ctx;
    if (g_nn >= 16) return 0;
    n = strlen(name);
    if (n >= PR_NAME_MAX) n = PR_NAME_MAX - 1;
    memcpy(g_names[g_nn], name, n);
    g_names[g_nn][n] = '\0';
    g_nn++;
    return 0;
}

static int cb_stop(const char *name, void *ctx)
{
    (void)name;
    (void)ctx;
    return 1;   /* 提前终止 */
}

int main(void)
{
    char        td[64];
    char       *dir;
    pr_kernel_t kv;
    const pr_cve_t *hits[PR_CVE_MAX];
    size_t      n = 0;
    size_t      kn = 0, sn = 0, pn = 0;

    /* ---- errstr ---- */
    CHECK(strcmp(pr_errstr(PR_OK), "ok") == 0, "errstr(OK)");
    CHECK(strcmp(pr_errstr(PR_ERR_ARGS), "invalid argument") == 0, "errstr(ARGS)");
    CHECK(strcmp(pr_errstr(PR_ERR_NOTFOUND), "not found") == 0, "errstr(NOTFOUND)");
    CHECK(strcmp(pr_errstr(-999), "unknown") == 0, "errstr(未知码)");

    /* ---- 版本比较 ---- */
    CHECK(pr_version_cmp("4.8.3", "4.8.3") == 0, "vercmp 相等");
    CHECK(pr_version_cmp("4.4.0", "4.8.3") < 0,  "vercmp 小于");
    CHECK(pr_version_cmp("5.16.11", "5.16.2") > 0, "vercmp 数值段非字典序");
    CHECK(pr_version_cmp("5.10", "5.10.0") < 0,  "vercmp 缺段视为小");
    CHECK(pr_version_cmp("1.9.5p1", "1.9.5p2") < 0, "vercmp p后缀 p1<p2");
    CHECK(pr_version_cmp("1.9.5p2", "1.9.5p1") > 0, "vercmp p后缀 p2>p1");
    CHECK(pr_version_cmp("1.8.31", "1.8.31p2") < 0, "vercmp 有后缀大于无后缀");
    CHECK(pr_version_cmp("0.105", "0.119") < 0, "vercmp polkit 版本");
    CHECK(pr_version_cmp("", "0") < 0, "vercmp 空串小于");
    CHECK(pr_version_cmp(NULL, "1") < 0, "vercmp NULL 视为空");
    CHECK(pr_version_cmp("1.9.5p1", "1.9.5p1") == 0, "vercmp 同后缀相等");

    /* ---- 内核版本解析 ---- */
    CHECK(pr_kernel_parse("5.16.11-generic", &kv) == PR_OK, "kparse 带尾缀");
    CHECK(kv.major == 5 && kv.minor == 16 && kv.patch == 11, "kparse 5.16.11");
    CHECK(pr_kernel_parse("4.8.3", &kv) == PR_OK && kv.major == 4 &&
          kv.minor == 8 && kv.patch == 3, "kparse 4.8.3");
    CHECK(pr_kernel_parse("6.1", &kv) == PR_OK && kv.major == 6 &&
          kv.minor == 1 && kv.patch == 0, "kparse 缺 patch 置 0");
    CHECK(pr_kernel_parse(NULL, &kv) == PR_ERR_ARGS, "kparse 空参被拒");
    CHECK(pr_kernel_parse("", &kv) == PR_ERR_ARGS, "kparse 空串被拒");

    /* ---- CVE 单条匹配 ---- */
    {
        const pr_cve_t *dcow = pr_cve_lookup("CVE-2016-5195");
        const pr_cve_t *pipe = pr_cve_lookup("CVE-2022-0847");
        CHECK(dcow != NULL, "lookup Dirty COW");
        CHECK(pipe != NULL, "lookup DirtyPipe");
        CHECK(pr_cve_match(dcow, "4.4.0") == 1, "DirtyCOW 4.4.0 受影响");
        CHECK(pr_cve_match(dcow, "4.8.3") == 0, "DirtyCOW 4.8.3 已修复");
        CHECK(pr_cve_match(dcow, "5.0.0") == 0, "DirtyCOW 5.0.0 不受影响");
        CHECK(pr_cve_match(dcow, "2.6.21") == 0, "DirtyCOW 低于起始版本");
        CHECK(pr_cve_match(pipe, "5.10.0") == 1, "DirtyPipe 5.10.0 受影响");
        CHECK(pr_cve_match(pipe, "5.17.0") == 0, "DirtyPipe 5.17.0 已修复");
        CHECK(pr_cve_match(dcow, NULL) == 0, "cve_match 空版本返 0");
        CHECK(pr_cve_match(NULL, "5.0.0") == 0, "cve_match 空条目返 0");
        CHECK(pr_cve_lookup("CVE-9999-9999") == NULL, "lookup 未知 CVE 返 NULL");
        CHECK(pr_cve_lookup(NULL) == NULL, "lookup 空参返 NULL");
    }

    /* ---- 表规模 ---- */
    (void)pr_kernel_table(&kn);
    (void)pr_sudo_table(&sn);
    (void)pr_polkit_table(&pn);
    CHECK(kn >= 5, "内核 CVE 表有条目");
    CHECK(sn >= 3, "sudo CVE 表有条目");
    CHECK(pn >= 2, "polkit CVE 表有条目");
    printf("       (表规模 kernel=%zu sudo=%zu polkit=%zu)\n", kn, sn, pn);

    /* ---- 内核审计 ---- */
    n = 0;
    CHECK(pr_kernel_audit("4.4.0", hits, PR_CVE_MAX, &n) == PR_OK, "kernel audit 4.4.0");
    CHECK(n >= 1, "4.4.0 命中至少一条");
    CHECK(strcmp(hits[0]->id, "CVE-2016-5195") == 0, "4.4.0 首条为 Dirty COW");

    n = 0;
    CHECK(pr_kernel_audit("5.10.0", hits, PR_CVE_MAX, &n) == PR_OK, "kernel audit 5.10.0");
    CHECK(n == 3, "5.10.0 命中 3 条");
    printf("       (5.10.0 命中=%zu)\n", n);

    n = 0;
    CHECK(pr_kernel_audit("6.5.0", hits, PR_CVE_MAX, &n) == PR_OK && n == 0,
          "6.5.0 无命中");
    n = 0;
    CHECK(pr_kernel_audit("5.10.0", NULL, 0, &n) == PR_OK && n == 3,
          "cap=0 时仍统计总数");
    CHECK(pr_kernel_audit(NULL, hits, PR_CVE_MAX, &n) == PR_ERR_ARGS,
          "kernel audit 空版本被拒");

    /* ---- sudo 审计 ---- */
    n = 0;
    CHECK(pr_sudo_audit("1.8.31", hits, PR_CVE_MAX, &n) == PR_OK, "sudo audit 1.8.31");
    CHECK(n == 2, "1.8.31 命中 2 条(BaronSamedit + 2023-32629)");
    n = 0;
    CHECK(pr_sudo_audit("1.9.5p2", hits, PR_CVE_MAX, &n) == PR_OK && n == 1,
          "1.9.5p2 已修 BaronSamedit，仅剩 2023-32629");
    n = 0;
    CHECK(pr_sudo_audit("1.9.17", hits, PR_CVE_MAX, &n) == PR_OK && n == 0,
          "1.9.17 无命中");
    n = 0;
    CHECK(pr_sudo_audit("1.8.27", hits, PR_CVE_MAX, &n) == PR_OK && n == 3,
          "1.8.27 三条全中(含 2019-14287)");
    CHECK(pr_sudo_audit(NULL, hits, PR_CVE_MAX, &n) == PR_ERR_ARGS,
          "sudo audit 空版本被拒");

    /* ---- polkit 审计 ---- */
    n = 0;
    CHECK(pr_polkit_audit("0.105", hits, PR_CVE_MAX, &n) == PR_OK && n == 2,
          "polkit 0.105 命中 2 条");
    n = 0;
    CHECK(pr_polkit_audit("0.119", hits, PR_CVE_MAX, &n) == PR_OK && n == 1,
          "polkit 0.119 仅剩 PwnKit");
    n = 0;
    CHECK(pr_polkit_audit("0.120", hits, PR_CVE_MAX, &n) == PR_OK && n == 0,
          "polkit 0.120 无命中");
    CHECK(pr_polkit_audit(NULL, hits, PR_CVE_MAX, &n) == PR_ERR_ARGS,
          "polkit audit 空版本被拒");

    /* ---- SUID 已知名录 ---- */
    CHECK(pr_suid_known("sudo") == 1, "known sudo");
    CHECK(pr_suid_known("pkexec") == 1, "known pkexec");
    CHECK(pr_suid_known("nmap") == 1, "known nmap");
    CHECK(pr_suid_known("definitelynotathing") == 0, "known 未知名返 0");
    CHECK(pr_suid_known(NULL) == 0, "known 空参返 0");

    /* ---- SUID 扫描（真实临时目录 + 真实 chmod） ---- */
    snprintf(td, sizeof td, "/tmp/prXXXXXX");
    dir = mkdtemp(td);
    CHECK(dir != NULL, "创建临时目录");
    if (dir) {
        size_t cnt = 0;
            char f1[PR_PATH_MAX], f2[PR_PATH_MAX], f3[PR_PATH_MAX];
            size_t dl = strlen(dir);
            memcpy(f1, dir, dl); memcpy(f1 + dl, "/sudo", 6);
            memcpy(f2, dir, dl); memcpy(f2 + dl, "/pkexec", 8);
            memcpy(f3, dir, dl); memcpy(f3 + dl, "/plain", 7);

            { FILE *f = fopen(f1, "w"); if (f) { fputs("#!/bin/sh\n", f); fclose(f); } }
            { FILE *f = fopen(f2, "w"); if (f) { fputs("#!/bin/sh\n", f); fclose(f); } }
            { FILE *f = fopen(f3, "w"); if (f) { fputs("#!/bin/sh\n", f); fclose(f); } }

            chmod(f1, 04755);
            chmod(f2, 04755);
            chmod(f3, 0755);

            CHECK(pr_suid_is_setuid(f1) == 1, "is_setuid 置位文件返 1");
            CHECK(pr_suid_is_setuid(f3) == 0, "is_setuid 未置位返 0");
            CHECK(pr_suid_is_setuid("/nonexistent/x") == PR_ERR_IO, "is_setuid 不存在返 IO");
            CHECK(pr_suid_is_setuid(NULL) == PR_ERR_ARGS, "is_setuid 空参被拒");
            CHECK(pr_suid_is_setuid(dir) == PR_ERR_NOTFOUND, "is_setuid 目录返 NOTFOUND");

            reset_names();
            cnt = 0;
            CHECK(pr_suid_scan(dir, cb_collect, NULL, &cnt) == PR_OK, "suid_scan 成功");
            CHECK(cnt == 2, "suid_scan 计数为 2");
            CHECK(g_nn == 2, "suid_scan 回调收集 2 个");
            printf("       (扫到: %s %s)\n", g_names[0], g_names[1]);
            CHECK(pr_suid_known(g_names[0]) == 1, "扫到的名字在已知名录内");

            reset_names();
            cnt = 0;
            CHECK(pr_suid_scan(dir, cb_stop, NULL, &cnt) == PR_OK, "suid_scan 提前终止仍返 OK");
            CHECK(g_nn == 0 && cnt == 1, "cb 返非0 时只计 1 个即停");

            cnt = 999;
            CHECK(pr_suid_scan(dir, NULL, NULL, &cnt) == PR_OK && cnt == 2,
                  "suid_scan 空回调仍计数");
        }
    CHECK(pr_suid_scan(NULL, NULL, NULL, &n) == PR_ERR_ARGS, "suid_scan 空路径被拒");
    CHECK(pr_suid_scan("/nonexistent/dir", NULL, NULL, &n) == PR_ERR_IO,
          "suid_scan 目录不存在返 IO");

    printf("\n==== 18_privilege: total=%d pass=%d fail=%d ====\n",
           g_pass + g_fail, g_pass, g_fail);
    return g_fail ? 1 : 0;
}
