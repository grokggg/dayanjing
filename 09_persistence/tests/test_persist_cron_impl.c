/*
 * cron 落点形态守卫：能力探测 + /etc/crontab 回退。
 *
 * 为什么单独立一个文件
 * --------------------
 * 既有 test_persist.c / test_persist_partial.c / test_enum.c 的 cron 断言
 * 全部硬编码 "%s/etc/cron.d/dayanjing"，它们覆盖的是**独占文件**那条路径。
 * 而 /etc/crontab 是**共享文件**：写入语义根本不同（按 marker 追加 / 按
 * marker 移除，绝不整体覆写），卸载语义也不同（删行，不删文件）。两者互不
 * 覆盖，混在一个文件里只会互相迁就。
 *
 * 要证的事
 * --------
 * /etc/cron.d 不是通用特性，而是 Debian/RHEL 的发行版补丁。上游真 Vixie
 * cron 不扫描它。实测对照（21_exfil/tests/verify_cron_impl.py）：
 *     /etc/cron.d/probe_d（契约全合规、0600）→ 从未执行
 *     /etc/crontab（同内容、0600）          → 真触发
 * 所以驻留必须按目标选落点，写错了就是"条目在、永不执行、部署全绿"。
 *
 * 反向验证（缺一不可）
 * --------------------
 * 本文件的判据若在某些实现下恒为真，全绿就没有意义。故配套
 * tests/verify_persist_cron_impl.py 做源码变异：把"未知 -> 回退"改回
 * "未知 -> cron.d"、把回退分支的 chmod 0600 去掉，守卫必须变红。
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "persist.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_fail = 0, g_pass = 0;
static void ck(const char *what, int cond) {
    if (cond) { g_pass++; printf("  ok  : %s\n", what); }
    else      { g_fail++; printf("  FAIL: %s\n", what); }
}

static int exists(const char *p) { struct stat st; return stat(p, &st) == 0; }

static int file_has(const char *p, const char *s) {
    FILE *f = fopen(p, "r");
    if (!f) return 0;
    char buf[65536]; size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f); buf[n] = '\0';
    return strstr(buf, s) != NULL;
}

static int count_substr(const char *p, const char *s) {
    FILE *f = fopen(p, "r");
    if (!f) return -1;
    char buf[65536]; size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f); buf[n] = '\0';
    int c = 0; const char *q = buf;
    size_t sl = strlen(s);
    while ((q = strstr(q, s)) != NULL) { c++; q += sl; }
    return c;
}

static mode_t mode_of(const char *p) {
    struct stat st;
    if (stat(p, &st) != 0) return (mode_t)-1;
    return st.st_mode & 07777;
}

/* 建一个空假根（无任何发行版特征文件） */
static const char *new_root(char *tpl) {
    const char *r = mkdtemp(tpl);
    if (!r) return NULL;
    char sub[512];
    snprintf(sub, sizeof sub, "%s/etc", r);
    mkdir(sub, 0755);
    return r;
}

static void put(const char *root, const char *rel, const char *content) {
    char p[512];
    snprintf(p, sizeof p, "%s/%s", root, rel);
    FILE *f = fopen(p, "w");
    if (!f) return;
    fputs(content, f);
    fclose(f);
}

int main(void) {
    printf("=== 09_persistence cron 落点形态测试 ===\n");

    /* 复位，避免任何残留 override 影响本轮探测断言 */
    persist_set_cron_impl(-1);
    unsetenv("PERSIST_CRON_IMPL");

    /* ---- A. 能力探测 ---- */
    {
        char t[] = "/tmp/t_cronimpl_blank_XXXXXX";
        const char *root = new_root(t);
        ck("空假根(无特征) -> 回退到 /etc/crontab（未知按通用路径处理）",
           persist_cron_impl(root) == PERSIST_CRON_IMPL_SYSCRONTAB);
    }
    {
        char t[] = "/tmp/t_cronimpl_deb_XXXXXX";
        const char *root = new_root(t);
        put(root, "etc/debian_version", "12.4\n");
        ck("有 /etc/debian_version -> cron.d（该发行版支持）",
           persist_cron_impl(root) == PERSIST_CRON_IMPL_CROND);
    }
    {
        char t[] = "/tmp/t_cronimpl_alp_XXXXXX";
        const char *root = new_root(t);
        put(root, "etc/alpine-release", "3.19.0\n");
        ck("有 /etc/alpine-release -> 回退（busybox crond 不扫描 cron.d）",
           persist_cron_impl(root) == PERSIST_CRON_IMPL_SYSCRONTAB);
    }
    {
        char t[] = "/tmp/t_cronimpl_osr_XXXXXX";
        const char *root = new_root(t);
        put(root, "etc/os-release", "ID=\"ubuntu\"\nVERSION_ID=\"22.04\"\n");
        ck("os-release ID=ubuntu -> cron.d（带引号可解析）",
           persist_cron_impl(root) == PERSIST_CRON_IMPL_CROND);
    }
    {
        char t[] = "/tmp/t_cronimpl_osa_XXXXXX";
        const char *root = new_root(t);
        put(root, "etc/os-release", "ID=alpine\n");
        ck("os-release ID=alpine -> 回退",
           persist_cron_impl(root) == PERSIST_CRON_IMPL_SYSCRONTAB);
    }
    /* 显式覆盖位：生产从不设置，但守卫必须能强制进入"不支持 cron.d"分支，
     * 否则该分支在 Debian 系机器上永远走不到，等于没写。 */
    {
        char t[] = "/tmp/t_cronimpl_env_XXXXXX";
        const char *root = new_root(t);
        put(root, "etc/alpine-release", "3.19.0\n");
        setenv("PERSIST_CRON_IMPL", "crond", 1);
        ck("环境变量 PERSIST_CRON_IMPL=crond 覆盖探测结果",
           persist_cron_impl(root) == PERSIST_CRON_IMPL_CROND);
        unsetenv("PERSIST_CRON_IMPL");
        ck("unsetenv 后恢复自动探测",
           persist_cron_impl(root) == PERSIST_CRON_IMPL_SYSCRONTAB);
    }
    {
        char t[] = "/tmp/t_cronimpl_api_XXXXXX";
        const char *root = new_root(t);
        put(root, "etc/debian_version", "12.4\n");
        ck("persist_set_cron_impl(SYSCRONTAB) 覆盖探测结果",
           persist_set_cron_impl(PERSIST_CRON_IMPL_SYSCRONTAB) == 0 &&
           persist_cron_impl(root) == PERSIST_CRON_IMPL_SYSCRONTAB);
        persist_set_cron_impl(-1);
        ck("persist_set_cron_impl(-1) 复位为自动探测",
           persist_cron_impl(root) == PERSIST_CRON_IMPL_CROND);
    }
    {
        ck("真实根(NULL) 查询返回合法形态",
           persist_cron_impl(NULL) == PERSIST_CRON_IMPL_CROND ||
           persist_cron_impl(NULL) == PERSIST_CRON_IMPL_SYSCRONTAB);
    }

    /* ---- B. /etc/crontab 回退形态的写入语义 ---- */
    char t2[] = "/tmp/t_cronimpl_w_XXXXXX";
    const char *root = new_root(t2);
    persist_set_cron_impl(PERSIST_CRON_IMPL_SYSCRONTAB);

    char binp[512] = {0};
    ck("drop self", persist_drop_self(root, "/var/tmp/.system-cache",
                                      binp, sizeof binp) == 0);

    ck("回退形态 install 成功", persist_install(PERSIST_CRON, root, binp) == 0);
    char ct[512];
    snprintf(ct, sizeof ct, "%s/etc/crontab", root);
    ck("落点是 /etc/crontab", exists(ct));
    ck("条目含 @reboot 与命令路径", file_has(ct, "@reboot") && file_has(ct, binp));
    /* /etc/crontab 的语法与 cron.d 不同：必须带 user 字段，否则被当成
     * user="/path/cmd" 报 bad username。 */
    ck("条目含 user 字段(root)", file_has(ct, "@reboot root"));
    ck("条目含 marker（卸载靠它定位）", file_has(ct, "do-not-edit:managed"));
    /* 真 Vixie cron 的加载判据：(st_mode & 07777) != 0600 即拒绝加载。
     * 多数系统 /etc/crontab 默认 0644，不修同样静默失效。 */
    ck("/etc/crontab 权限为 0600", mode_of(ct) == 0600);
    ck("installed(cron)==1", persist_installed(root, PERSIST_CRON) == 1);
    ck("落点不是 cron.d", !file_has(ct, "/etc/cron.d"));

    /* 共享文件：绝不能整体覆写，否则会删掉运维自己的条目 */
    put(root, "etc/crontab", "SHELL=/bin/sh\n0 3 * * * root /usr/local/bin/backup.sh\n");
    ck("回退形态 install 不覆写已有内容（保护运维条目）",
       persist_install(PERSIST_CRON, root, binp) == 0 &&
       file_has(ct, "/usr/local/bin/backup.sh"));
    ck("追加后仍只有 1 处 marker（幂等）",
       count_substr(ct, "do-not-edit:managed") == 1);
    ck("幂等二次 install 后 installed 仍为 1",
       persist_install(PERSIST_CRON, root, binp) == 0 &&
       persist_installed(root, PERSIST_CRON) == 1 &&
       count_substr(ct, "do-not-edit:managed") == 1);

    /* 卸载：删行不删文件 */
    ck("uninstall cron 成功", persist_uninstall(PERSIST_CRON, root, NULL) == 0);
    ck("卸载后 marker 已移除", !file_has(ct, "do-not-edit:managed"));
    ck("卸载后 /etc/crontab 文件仍存在（不删共享文件）", exists(ct));
    ck("卸载后运维条目仍在（未误删）", file_has(ct, "/usr/local/bin/backup.sh"));
    ck("卸载后 installed==0", persist_installed(root, PERSIST_CRON) == 0);

    /* ---- C. 形态切换后不留痕 ---- */
    {
        char t3[] = "/tmp/t_cronimpl_sw_XXXXXX";
        const char *r3 = new_root(t3);
        char cd[512];
        snprintf(cd, sizeof cd, "%s/etc/cron.d/dayanjing", r3);

        persist_set_cron_impl(PERSIST_CRON_IMPL_CROND);
        ck("先以 cron.d 形态安装", persist_install(PERSIST_CRON, r3, binp) == 0 &&
                                    exists(cd));
        /* 切到回退形态：旧的 cron.d 条目在本实现下无执行可能，留着是纯痕迹 */
        persist_set_cron_impl(PERSIST_CRON_IMPL_SYSCRONTAB);
        ck("切回退形态后安装成功", persist_install(PERSIST_CRON, r3, binp) == 0);
        ck("切换后旧 cron.d 条目已被清除", !exists(cd));
        char ct3[512];
        snprintf(ct3, sizeof ct3, "%s/etc/crontab", r3);
        ck("切换后 /etc/crontab 有条目", file_has(ct3, "do-not-edit:managed"));

        /* 反向断言场景：以 cron.d 形态卸载，必须把 crontab 里的行也清掉。
         * 只清当前形态会留下"重启后自启"的那一条，等于没卸。 */
        persist_set_cron_impl(PERSIST_CRON_IMPL_CROND);
        ck("以 cron.d 形态卸载也清掉 crontab 里的条目",
           persist_uninstall(PERSIST_CRON, r3, NULL) == 0 &&
           !file_has(ct3, "do-not-edit:managed"));
        persist_set_cron_impl(-1);
    }

    printf("--- total=%d pass=%d fail=%d ---\n", g_pass + g_fail, g_pass, g_fail);
    return g_fail ? 1 : 0;
}
