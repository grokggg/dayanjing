#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "defense.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

/* DMI / sys_vendor 中的虚拟化厂商串 */
/* 注意：QEMU 默认 DMI 是 "Standard PC (Q35 + ICH9, 2009)" 或
 * "(i440FX + PIIX, 1996)"，并不含 "QEMU" 字样，只匹配厂商名会漏判。 */
static const char *k_vm_dmi[] = {
    "VMware", "VirtualBox", "QEMU", "Q35", "i440FX", "Standard PC",
    "KVM", "Xen", "Bochs", "Parallels", "Hyper-V",
    "Microsoft Corporation", "innotek", "OpenStack", "CloudStack",
    NULL
};

/* 虚拟网卡 OUI 前缀（前 3 字节） */
static const char *k_vm_oui[] = {
    "00:05:69", "00:0c:29", "00:1c:14", "00:50:56",  /* VMware   */
    "08:00:27",                                       /* VirtualBox */
    "00:16:3e",                                       /* Xen       */
    "00:15:5d",                                       /* Hyper-V   */
    "00:1c:42",                                       /* Parallels */
    "52:54:00",                                       /* QEMU/KVM  */
    NULL
};

static void chomp(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) s[--n] = '\0';
}

/* 读 DMI 产品名/厂商并匹配。path 可注入以便确定性测试。 */
int df_vm_dmi_file(const char *path, char *out, size_t cap)
{
    FILE *f;
    char  buf[512];
    size_t n;
    int   i;

    if (!path) return DF_ERR_ARGS;
    if (out && cap == 0) return DF_ERR_ARGS;
    if (out) out[0] = '\0';

    f = fopen(path, "r");
    if (!f) return DF_ERR_IO;
    if (!fgets(buf, (int)sizeof buf, f)) {
        fclose(f);
        return DF_ERR_NOTFOUND;
    }
    fclose(f);

    chomp(buf);
    n = strlen(buf);

    if (out) {
        if (n + 1 > cap) return DF_ERR_BUFSMALL;
        memcpy(out, buf, n + 1);
    }

    for (i = 0; k_vm_dmi[i]; i++) {
        if (strstr(buf, k_vm_dmi[i])) return DF_HOSTILE;
    }
    return DF_CLEAN;
}

int df_vm_dmi(char *out, size_t cap)
{
    int r = df_vm_dmi_file("/sys/class/dmi/id/product_name", out, cap);
    if (r == DF_ERR_IO || r == DF_ERR_NOTFOUND) {
        r = df_vm_dmi_file("/sys/class/dmi/id/sys_vendor", out, cap);
    }
    return r;
}

/* /proc/cpuinfo：hypervisor 标志位 或 型号串含虚拟厂商 */
int df_vm_cpuinfo(void)
{
    FILE *f;
    char  line[512];
    int   verdict = DF_CLEAN;

    f = fopen("/proc/cpuinfo", "r");
    if (!f) return DF_ERR_IO;

    while (fgets(line, (int)sizeof line, f)) {
        if (strncmp(line, "flags", 5) == 0 && strstr(line, "hypervisor")) {
            verdict = DF_HOSTILE;
        }
        if (strncmp(line, "model name", 10) == 0 &&
            (strstr(line, "QEMU") || strstr(line, "VMware") || strstr(line, "VirtualBox"))) {
            verdict = DF_HOSTILE;
        }
    }
    fclose(f);
    return verdict;
}

/* 遍历网卡 MAC 的 OUI。dir 可注入（默认 /sys/class/net）。 */
int df_vm_mac(const char *dir, char *out, size_t cap)
{
    DIR           *d;
    struct dirent *e;

    if (!dir) dir = "/sys/class/net";
    if (out && cap == 0) return DF_ERR_ARGS;
    if (out) out[0] = '\0';

    d = opendir(dir);
    if (!d) return DF_ERR_IO;

    while ((e = readdir(d)) != NULL) {
        char  path[DF_PATH_MAX];
        char  addr[64];
        FILE *f;
        size_t n, dl, nl;
        int    i;

        if (e->d_name[0] == '.') continue;

        /* 手工拼接，避开 snprintf 在 -Wformat-truncation 下的告警 */
        dl = strlen(dir);
        nl = strlen(e->d_name);
        if (dl + 1 + nl + 9 > sizeof path) continue;   /* "/address\0" = 9 */
        memcpy(path, dir, dl);
        path[dl] = '/';
        memcpy(path + dl + 1, e->d_name, nl);
        memcpy(path + dl + 1 + nl, "/address", 9);

        f = fopen(path, "r");
        if (!f) continue;
        if (!fgets(addr, (int)sizeof addr, f)) {
            fclose(f);
            continue;
        }
        fclose(f);

        chomp(addr);
        n = strlen(addr);

        for (i = 0; k_vm_oui[i]; i++) {
            if (strncasecmp(addr, k_vm_oui[i], 8) == 0) {
                if (out && n + 1 <= cap) memcpy(out, addr, n + 1);
                closedir(d);
                return DF_HOSTILE;
            }
        }
    }

    closedir(d);
    return DF_CLEAN;
}

/* /dev/kvm 存在说明宿主支持或身处 KVM 客户机 */
int df_vm_kvmdev(void)
{
    if (access("/dev/kvm", F_OK) == 0) return DF_SUSPECT;
    return DF_CLEAN;
}

int df_vm_aggregate(void)
{
    int v = DF_CLEAN;

    v = df_verdict_or(v, df_vm_dmi(NULL, 0));
    v = df_verdict_or(v, df_vm_cpuinfo());
    v = df_verdict_or(v, df_vm_mac(NULL, NULL, 0));
    v = df_verdict_or(v, df_vm_kvmdev());

    return v;
}
