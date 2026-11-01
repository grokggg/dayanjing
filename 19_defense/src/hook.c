#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "defense.h"

#include <stdio.h>
#include <string.h>

/* 统计 maps 中可执行映射区数量。
 * 注入型 EDR 常把 DLL 映射进目标进程，exec 区数量异常是重要信号。 */
int df_hook_maps_file(const char *path, unsigned long *out_exec, unsigned long *out_total)
{
    FILE         *f;
    char          line[512];
    unsigned long exec_r = 0;
    unsigned long total  = 0;

    if (!path) return DF_ERR_ARGS;

    f = fopen(path, "r");
    if (!f) return DF_ERR_IO;

    while (fgets(line, (int)sizeof line, f)) {
        char perms[8];
        total++;
        if (sscanf(line, "%*x-%*x %7s", perms) == 1) {
            if (perms[2] == 'x') exec_r++;      /* r-x / rwx */
        }
    }
    fclose(f);

    if (out_exec)  *out_exec  = exec_r;
    if (out_total) *out_total = total;
    return DF_OK;
}

int df_hook_maps(unsigned long *out_exec, unsigned long *out_total)
{
    return df_hook_maps_file("/proc/self/maps", out_exec, out_total);
}

/* 比对函数入口字节与预期 prologue。
 * 0xCC(int3) → 软件断点已下；其他差异 → 疑似被 inline hook。 */
int df_hook_prologue(const uint8_t *code, size_t len, const uint8_t *expect, size_t elen)
{
    size_t i;

    if (!code || !expect) return DF_ERR_ARGS;
    if (elen == 0)        return DF_ERR_ARGS;
    if (len < elen)       return DF_ERR_RANGE;

    for (i = 0; i < elen; i++) {
        if (code[i] != expect[i]) {
            if (code[i] == 0xCC) return DF_HOSTILE;
            return DF_SUSPECT;
        }
    }
    return DF_CLEAN;
}
