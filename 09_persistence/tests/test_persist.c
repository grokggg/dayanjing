#include "persist.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

static int fails = 0, total = 0;
static void ck(const char *name, int cond) {
    total++;
    if (!cond) { fails++; printf("  FAIL: %s\n", name); }
    else printf("  ok  : %s\n", name);
}

static int file_has(const char *root, const char *fn, const char *needle) {
    char path[512]; snprintf(path, sizeof path, "%s/%s", root, fn);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char buf[4096]; size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}

int main(void) {
    printf("=== 09_persistence 测试 ===\n");
    char buf[4096];

    /* --- generate（原最小单元 + 新增） --- */
    ck("cron line", persist_generate(PERSIST_CRON, "/bin/agent", buf, sizeof buf) > 0 &&
                    strncmp(buf, "* * * * *", 9) == 0 && strstr(buf, "/bin/agent") != NULL);
    ck("systemd unit", persist_generate(PERSIST_SYSTEMD, "/bin/agent", buf, sizeof buf) > 0 &&
                       strstr(buf, "[Unit]") != NULL && strstr(buf, "ExecStart=/bin/agent") != NULL);
    ck("launchagent", persist_generate(PERSIST_LAUNCHAGENT, "/bin/agent", buf, sizeof buf) > 0 &&
                      strstr(buf, "<plist") != NULL && strstr(buf, "com.dayanjing.agent") != NULL);
    ck("ld_preload", persist_generate(PERSIST_LDPRELOAD, "/tmp/.x.so", buf, sizeof buf) > 0 &&
                     strstr(buf, "/tmp/.x.so") != NULL);
    ck("ssh_key forced cmd", persist_generate(PERSIST_SSHKEY, "id", buf, sizeof buf) > 0 &&
                             strstr(buf, "command=\"id\"") != NULL);
    ck("registry_run", persist_generate(PERSIST_REGISTRY, "agent.exe", buf, sizeof buf) > 0 &&
                       strstr(buf, "CurrentVersion\\Run") != NULL);
    ck("schtask", persist_generate(PERSIST_SCHTASK, "agent.exe", buf, sizeof buf) > 0 &&
                  strstr(buf, "schtasks") != NULL);
    ck("wmi_event", persist_generate(PERSIST_WMI, "agent.exe", buf, sizeof buf) > 0 &&
                    strstr(buf, "__EventFilter") != NULL);
    ck("win_service", persist_generate(PERSIST_SERVICE, "agent.exe", buf, sizeof buf) > 0 &&
                      strstr(buf, "sc create") != NULL);
    ck("lkm generate", persist_generate(PERSIST_LKM, NULL, buf, sizeof buf) > 0);

    /* --- 方法表 --- */
    ck("method count == 10", persist_method_count() == 10);
    ck("method_at(0) cron", persist_method_at(0) != NULL && persist_method_at(0)->id == PERSIST_CRON);
    ck("method_at(99) NULL", persist_method_at(99) == NULL);

    /* --- install / uninstall（假根，安全） --- */
    const char *root = "/tmp/persist_test_root";
    char rmcmd[256]; snprintf(rmcmd, sizeof rmcmd, "rm -rf %s", root);
    (void)system(rmcmd);
    mkdir(root, 0755);

    ck("install cron", persist_install(PERSIST_CRON, root, "/bin/agent") == 0);
    ck("cron file content", file_has(root, "cron", "/bin/agent"));
    ck("uninstall cron", persist_uninstall(PERSIST_CRON, root, NULL) == 0);
    ck("cron file gone", !file_has(root, "cron", "/bin/agent"));

    ck("install ld_preload", persist_install(PERSIST_LDPRELOAD, root, "/tmp/.x.so") == 0);
    ck("ld.so.preload content", file_has(root, "ld.so.preload", "/tmp/.x.so"));

    ck("install ssh_key", persist_install(PERSIST_SSHKEY, root, "id") == 0);
    ck("authorized_keys content", file_has(root, "authorized_keys", "command=\"id\""));

    ck("install systemd", persist_install(PERSIST_SYSTEMD, root, "/bin/agent") == 0);
    ck("systemd file content", file_has(root, "systemd", "ExecStart=/bin/agent"));

    /* Windows 专用方法在 Linux 构建上应返回 -2（不支持），不静默写盘 */
    ck("registry unsupported", persist_install(PERSIST_REGISTRY, root, "a.exe") == -2);
    ck("schtask unsupported", persist_install(PERSIST_SCHTASK, root, "a.exe") == -2);
    ck("wmi unsupported", persist_install(PERSIST_WMI, root, "a.exe") == -2);
    ck("service unsupported", persist_install(PERSIST_SERVICE, root, "a.exe") == -2);
    ck("lkm unsupported", persist_install(PERSIST_LKM, root, NULL) == -2);
    ck("uninstall registry unsupported", persist_uninstall(PERSIST_REGISTRY, root, NULL) == -2);

    /* --- 内核源码 --- */
    const char *src = persist_kernel_source();
    ck("kernel source non-empty", src != NULL && strlen(src) > 50 &&
                                  strstr(src, "module_init") != NULL);

    (void)system(rmcmd);
    printf("--- total=%d pass=%d fail=%d ---\n", total, total - fails, fails);
    return fails ? 1 : 0;
}
