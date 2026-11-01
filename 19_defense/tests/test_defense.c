#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "defense.h"

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

static int write_file(const char *path, const char *body)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs(body, f);
    fclose(f);
    return 0;
}

static char *mk_tmpdir(char *tmpl, size_t cap)
{
    snprintf(tmpl, cap, "/tmp/dfXXXXXX");
    return mkdtemp(tmpl);
}

/* 手工拼接路径，避免 -Wformat-truncation */
static int join3(char *out, size_t cap, const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b);
    if (la + 1 + lb + 1 > cap) return -1;
    memcpy(out, a, la);
    out[la] = '/';
    memcpy(out + la + 1, b, lb + 1);
    return 0;
}

int main(void)
{
    char  d1[64], d2[64], d3[64];
    char *td1, *td2, *td3;
    char  marker[64], comm[128], mac[64];
    int   verdict = -99, pid = -99;
    unsigned long ex = 0, tot = 0;
    uint64_t ns = 0;
    int r;

    /* ---- errstr / 聚合 ---- */
    CHECK(strcmp(df_errstr(DF_OK), "ok") == 0, "errstr(OK)");
    CHECK(strcmp(df_errstr(DF_ERR_ARGS), "invalid argument") == 0, "errstr(ARGS)");
    CHECK(strcmp(df_errstr(DF_ERR_RANGE), "out of range") == 0, "errstr(RANGE)");
    CHECK(strcmp(df_errstr(-999), "unknown") == 0, "errstr(未知码)");
    CHECK(df_verdict_or(DF_CLEAN, DF_HOSTILE) == DF_HOSTILE, "verdict_or 取更可疑");
    CHECK(df_verdict_or(DF_ERR_IO, DF_SUSPECT) == DF_SUSPECT, "verdict_or 忽略错误码");
    CHECK(df_verdict_or(DF_ERR_IO, DF_ERR_ARGS) == DF_ERR_ARGS, "verdict_or 双错误");

    /* ---- 反调试：TracerPid ---- */
    r = df_debug_tracerpid(&pid);
    CHECK(r == DF_CLEAN || r == DF_HOSTILE, "tracerpid 返回合法判定");
    CHECK(pid >= 0, "tracerpid 回填 pid");
    CHECK(df_debug_tracerpid(NULL) == DF_ERR_ARGS, "tracerpid 空参被拒");

    /* ---- 反调试：PTRACE_TRACEME ---- */
    r = df_debug_ptrace_traceme();
    CHECK(r == DF_CLEAN || r == DF_SUSPECT || r == DF_HOSTILE, "ptrace_traceme 合法判定");

    /* ---- 反调试：时序 ---- */
    r = df_debug_timing(100000000000ULL, &ns);
    CHECK(r == DF_CLEAN, "timing 大阈值判干净");
    CHECK(ns > 0, "timing 回填耗时");
    CHECK(df_debug_timing(0ULL, &ns) == DF_SUSPECT, "timing 阈值0判可疑");
    CHECK(df_debug_timing(100000000000ULL, NULL) == DF_CLEAN, "timing 空 out 可调用");

    /* ---- 反沙箱：cgroup 注入文件 ---- */
    td1 = mk_tmpdir(d1, sizeof d1);
    CHECK(td1 != NULL, "创建临时目录1");
    if (td1) {
        char p[256];
        snprintf(p, sizeof p, "%s/docker", td1);
        write_file(p, "12:pids:/docker/abc123\n");
        verdict = -99; marker[0] = '\0';
        r = df_sandbox_cgroup_file(p, marker, sizeof marker, &verdict);
        CHECK(r == DF_OK && verdict == DF_HOSTILE, "cgroup 含 docker 判敌对");
        CHECK(strcmp(marker, "docker") == 0, "cgroup 回填标记名");

        snprintf(p, sizeof p, "%s/clean", td1);
        write_file(p, "12:pids:/\n11:hugetlb:/\n");
        verdict = -99; marker[0] = '\0';
        CHECK(df_sandbox_cgroup_file(p, marker, sizeof marker, &verdict) == DF_OK &&
              verdict == DF_CLEAN, "cgroup 无标记判干净");

        snprintf(p, sizeof p, "%s/kube", td1);
        write_file(p, "10:net:/kubepods/besteffort\n");
        verdict = -99;
        CHECK(df_sandbox_cgroup_file(p, NULL, 0, &verdict) == DF_OK &&
              verdict == DF_HOSTILE, "cgroup kubepods 判敌对(空 marker)");
    }
    CHECK(df_sandbox_cgroup_file("/nonexistent/x/y", NULL, 0, &verdict) == DF_ERR_IO,
          "cgroup 文件不存在返 IO");
    CHECK(df_sandbox_cgroup_file(NULL, NULL, 0, &verdict) == DF_ERR_ARGS,
          "cgroup 空路径被拒");

    verdict = -99;
    CHECK(df_sandbox_cgroup(marker, sizeof marker, &verdict) == DF_OK, "cgroup 真实路径可读");
    printf("       (真实 /proc/1/cgroup 判定=%d 标记=%s)\n", verdict,
           marker[0] ? marker : "-");

    /* ---- 反沙箱：dockerenv / env / pid1 ---- */
    r = df_sandbox_dockerenv();
    CHECK(r == DF_CLEAN || r == DF_HOSTILE, "dockerenv 合法判定");
    r = df_sandbox_env();
    CHECK(r == DF_CLEAN || r == DF_HOSTILE, "env 合法判定");

    CHECK(df_sandbox_pid1(comm, sizeof comm) == DF_OK, "pid1 读取成功");
    CHECK(strlen(comm) > 0, "pid1 comm 非空");
    printf("       (PID1 comm=%s)\n", comm);
    CHECK(df_sandbox_pid1(NULL, 0) == DF_ERR_ARGS, "pid1 空参被拒");
    CHECK(df_sandbox_pid1(comm, 1) == DF_ERR_BUFSMALL, "pid1 缓冲不足返 BUFSMALL");

    /* ---- 反虚拟机：DMI ---- */
    td2 = mk_tmpdir(d2, sizeof d2);
    CHECK(td2 != NULL, "创建临时目录2");
    if (td2) {
        char p[256], out[128];
        snprintf(p, sizeof p, "%s/vmware", td2);
        write_file(p, "VMware Virtual Platform\n");
        CHECK(df_vm_dmi_file(p, out, sizeof out) == DF_HOSTILE, "DMI VMware 判敌对");
        CHECK(strcmp(out, "VMware Virtual Platform") == 0, "DMI 回填产品名");

        snprintf(p, sizeof p, "%s/thinkpad", td2);
        write_file(p, "20QD0001CD\n");
        CHECK(df_vm_dmi_file(p, out, sizeof out) == DF_CLEAN, "DMI 物理机判干净");

        snprintf(p, sizeof p, "%s/qemu", td2);
        write_file(p, "Standard PC (Q35 + ICH9, 2009)\n");
        CHECK(df_vm_dmi_file(p, out, sizeof out) == DF_HOSTILE, "DMI QEMU 判敌对");

        CHECK(df_vm_dmi_file(p, out, 4) == DF_ERR_BUFSMALL, "DMI 缓冲不足返 BUFSMALL");
        CHECK(df_vm_dmi_file("/nonexistent/dmi", NULL, 0) == DF_ERR_IO, "DMI 不存在返 IO");
        CHECK(df_vm_dmi_file(NULL, NULL, 0) == DF_ERR_ARGS, "DMI 空路径被拒");
    }
    r = df_vm_dmi(NULL, 0);
    CHECK(r != DF_ERR_ARGS, "真实 DMI 探测可调用");

    /* ---- 反虚拟机：cpuinfo ---- */
    r = df_vm_cpuinfo();
    CHECK(r == DF_CLEAN || r == DF_HOSTILE, "cpuinfo 合法判定");

    /* ---- 反虚拟机：MAC OUI ---- */
    td3 = mk_tmpdir(d3, sizeof d3);
    CHECK(td3 != NULL, "创建临时目录3");
    if (td3) {
        char ifd[256], af[256];
        CHECK(join3(ifd, sizeof ifd, td3, "eth0") == 0, "拼接网卡目录路径");
        mkdir(ifd, 0755);
        CHECK(join3(af, sizeof af, ifd, "address") == 0, "拼接 address 路径");
        write_file(af, "08:00:27:ab:cd:ef\n");
        mac[0] = '\0';
        CHECK(df_vm_mac(td3, mac, sizeof mac) == DF_HOSTILE, "MAC VirtualBox OUI 判敌对");
        CHECK(strcmp(mac, "08:00:27:ab:cd:ef") == 0, "MAC 回填地址");

        write_file(af, "52:54:00:11:22:33\n");
        CHECK(df_vm_mac(td3, NULL, 0) == DF_HOSTILE, "MAC QEMU OUI 判敌对");

        write_file(af, "aa:bb:cc:11:22:33\n");
        CHECK(df_vm_mac(td3, NULL, 0) == DF_CLEAN, "MAC 非虚拟 OUI 判干净");
    }
    CHECK(df_vm_mac("/nonexistent/net", NULL, 0) == DF_ERR_IO, "MAC 目录不存在返 IO");
    r = df_vm_mac(NULL, NULL, 0);
    CHECK(r == DF_CLEAN || r == DF_HOSTILE, "MAC 真实目录可扫描");

    CHECK(df_vm_kvmdev() == DF_CLEAN || df_vm_kvmdev() == DF_SUSPECT, "kvmdev 合法判定");
    r = df_vm_aggregate();
    CHECK(r >= DF_CLEAN && r <= DF_HOSTILE, "vm 聚合返回合法判定");

    /* ---- 钩子检测：maps ---- */
    td1 = (char *)d1;
    if (td1) {
        char p[256];
        snprintf(p, sizeof p, "%s/maps", td1);
        write_file(p,
            "55e0-55e4 r-xp 00000000 08:01 1  /usr/bin/app\n"
            "7f00-7f40 r--p 00000000 08:01 2  /lib/libc.so\n"
            "7f40-7f80 r-xp 00000000 08:01 2  /lib/libc.so\n"
            "7ffd-7ffe rw-p 00000000 00:00 0  [stack]\n");
        ex = tot = 0;
        CHECK(df_hook_maps_file(p, &ex, &tot) == DF_OK, "maps 文件解析成功");
        CHECK(tot == 4, "maps 总区数为 4");
        CHECK(ex == 2, "maps 可执行区数为 2");
        CHECK(df_hook_maps_file(p, NULL, NULL) == DF_OK, "maps 空 out 可调用");
    }
    ex = tot = 0;
    CHECK(df_hook_maps(&ex, &tot) == DF_OK, "真实 maps 可读");
    CHECK(ex > 0 && tot > 0, "真实 maps 有可执行区");
    CHECK(df_hook_maps_file(NULL, NULL, NULL) == DF_ERR_ARGS, "maps 空路径被拒");
    CHECK(df_hook_maps_file("/nonexistent/maps", NULL, NULL) == DF_ERR_IO, "maps 不存在返 IO");

    /* ---- 钩子检测：prologue ---- */
    {
        const uint8_t good[] = { 0x48, 0x89, 0x5c, 0x24, 0x08 };
        const uint8_t bpt[]  = { 0xCC, 0x89, 0x5c, 0x24, 0x08 };
        const uint8_t hooked[] = { 0xE9, 0x89, 0x5c, 0x24, 0x08 };

        CHECK(df_hook_prologue(good, sizeof good, good, sizeof good) == DF_CLEAN,
              "prologue 一致判干净");
        CHECK(df_hook_prologue(bpt, sizeof bpt, good, sizeof good) == DF_HOSTILE,
              "prologue int3 判敌对");
        CHECK(df_hook_prologue(hooked, sizeof hooked, good, sizeof good) == DF_SUSPECT,
              "prologue 被改判可疑");
        CHECK(df_hook_prologue(NULL, 5, good, 5) == DF_ERR_ARGS, "prologue 空 code 被拒");
        CHECK(df_hook_prologue(good, 5, NULL, 5) == DF_ERR_ARGS, "prologue 空 expect 被拒");
        CHECK(df_hook_prologue(good, 3, good, 5) == DF_ERR_RANGE, "prologue 长度不足返 RANGE");
    }

    /* ---- evade：查找与修补 ---- */
    {
        uint8_t buf[32];
        const uint8_t pat[] = { 0x4c, 0x8b, 0xdc };
        size_t off = 999;

        memset(buf, 0x90, sizeof buf);          /* nop 填充 */
        memcpy(buf + 10, pat, sizeof pat);

        CHECK(df_evade_find(buf, sizeof buf, pat, sizeof pat, &off) == DF_OK,
              "evade_find 命中");
        CHECK(off == 10, "evade_find 偏移正确");
        CHECK(df_evade_find(buf, sizeof buf, pat, sizeof pat, NULL) == DF_OK,
              "evade_find 空 out 可调用");

        off = 999;
        /* len(2) < plen(3) 才是参数错误；len(5)>=plen(3) 应走搜索路径返 NOTFOUND */
        CHECK(df_evade_find(buf, 2, pat, sizeof pat, &off) == DF_ERR_ARGS,
              "evade_find 长度不足返 ARGS");
        CHECK(df_evade_find(buf, 5, pat, sizeof pat, &off) == DF_ERR_NOTFOUND,
              "evade_find 长度足够但未命中返 NOTFOUND");
        CHECK(df_evade_find(buf, sizeof buf, pat, 0, &off) == DF_ERR_ARGS,
              "evade_find 空 pattern 被拒");
        CHECK(df_evade_find(NULL, sizeof buf, pat, sizeof pat, &off) == DF_ERR_ARGS,
              "evade_find 空 buf 被拒");
        {
            uint8_t none[8];
            memset(none, 0x00, sizeof none);
            CHECK(df_evade_find(none, sizeof none, pat, sizeof pat, &off) == DF_ERR_NOTFOUND,
                  "evade_find 未命中返 NOTFOUND");
        }

        /* patch_at */
        memset(buf, 0x90, sizeof buf);
        CHECK(df_evade_patch_at(buf, sizeof buf, 10, pat, sizeof pat) == DF_OK,
              "patch_at 成功");
        CHECK(memcmp(buf + 10, pat, sizeof pat) == 0, "patch_at 字节已写入");
        CHECK(df_evade_patch_at(buf, sizeof buf, 30, pat, sizeof pat) == DF_ERR_RANGE,
              "patch_at 越界返 RANGE");
        CHECK(df_evade_patch_at(buf, sizeof buf, 999, pat, sizeof pat) == DF_ERR_RANGE,
              "patch_at 偏移超长返 RANGE");
        CHECK(df_evade_patch_at(NULL, 10, 0, pat, sizeof pat) == DF_ERR_ARGS,
              "patch_at 空 buf 被拒");

        /* patch_first */
        memset(buf, 0x90, sizeof buf);
        memcpy(buf + 7, pat, sizeof pat);
        off = 999;
        CHECK(df_evade_patch_first(buf, sizeof buf, pat, sizeof pat, pat, sizeof pat, &off)
              == DF_OK, "patch_first 成功");
        CHECK(off == 7, "patch_first 偏移正确");

        /* ETW 桩 */
        memset(buf, 0x90, sizeof buf);
        CHECK(df_evade_etw(buf, sizeof buf, 4) == DF_OK, "etw 补丁写入成功");
        CHECK(buf[4] == 0x33 && buf[5] == 0xc0 && buf[6] == 0xc3,
              "etw 桩字节为 xor eax,eax; ret");
        CHECK(buf[3] == 0x90 && buf[7] == 0x90, "etw 仅覆盖 3 字节不越界");
        CHECK(df_evade_etw(buf, sizeof buf, sizeof buf - 1) == DF_ERR_RANGE,
              "etw 尾部空间不足返 RANGE");

        /* AMSI 桩 */
        memset(buf, 0x90, sizeof buf);
        CHECK(df_evade_amsi(buf, sizeof buf, 0) == DF_OK, "amsi 补丁写入成功");
        CHECK(buf[0] == 0xb8 && buf[1] == 0x57 && buf[2] == 0x00 &&
              buf[3] == 0x07 && buf[4] == 0x80 && buf[5] == 0xc3,
              "amsi 桩字节为 mov eax,0x80070057; ret");
        CHECK(buf[6] == 0x90, "amsi 仅覆盖 6 字节不越界");
        CHECK(df_evade_amsi(buf, 3, 0) == DF_ERR_RANGE, "amsi 缓冲过短返 RANGE");
    }

    printf("\n==== 19_defense: total=%d pass=%d fail=%d ====\n",
           g_pass + g_fail, g_pass, g_fail);
    return g_fail ? 1 : 0;
}
