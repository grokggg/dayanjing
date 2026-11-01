/*
 * agent_windows/src/reflect_run.c
 *
 * 反射加载执行驱动：补齐 reflect.c 留给平台层的三步。
 *
 * 本层不做 PE 解析、不做重定位、不做 IAT 绑定 —— 全部复用 17_loader。
 * 直接调用 reflect 的子步骤而非 reflect_load，是为了只解析一次 PE：
 * 权限推导需要节区表，而 reflect_load 内部会再解析一遍并丢弃结果。
 */

#include "reflect_run.h"

#include <string.h>

/* COFF 节区 Characteristics（内存属性位） */
#define SCN_MEM_DISCARDABLE 0x02000000u
#define SCN_MEM_EXECUTE     0x20000000u
#define SCN_MEM_READ        0x40000000u
#define SCN_MEM_WRITE       0x80000000u

/* COFF 文件 Characteristics */
#define FILE_DLL            0x2000u

/* 页粒度：节区对齐小于页时，多个节区会落在同一页上，逐节设权必然互相覆盖 */
#define RR_PAGE_GRAN        4096u

#define DLL_PROCESS_ATTACH  1u

int rr_protect_for(uint32_t chars, int *prot)
{
    int p = RR_P_NONE;

    if (!prot) return RR_ERR_PARAM;
    *prot = RR_P_NONE;

    if (chars & SCN_MEM_EXECUTE) p |= RR_P_X;
    if (chars & SCN_MEM_READ)    p |= RR_P_R;
    if (chars & SCN_MEM_WRITE)   p |= RR_P_W;

    /* 可写且可执行：拒绝。给 RWX 开绿灯等于接受加壳/异常映像，
       且必然在目标机上留下 RWX 页（EDR 强特征）。 */
    if ((p & RR_P_X) && (p & RR_P_W)) return RR_ERR_WX;

    /* 可执行必须可读：x86-64 上取指即读，纯执行页不可得 */
    if (p & RR_P_X) p |= RR_P_R;

    /* 无内存属性位（如部分丢弃节区）至少给只读，避免出现 NONE 页 */
    if (p == RR_P_NONE) p = RR_P_R;

    *prot = p;
    return RR_OK;
}

const char *rr_errstr(int rc)
{
    switch (rc) {
    case RR_OK:            return "OK";
    case RR_ERR_PARAM:     return "param";
    case RR_ERR_NOHOOK:    return "missing hook (refuse to fall back to RWX)";
    case RR_ERR_PROT:      return "section protect failed";
    case RR_ERR_WX:        return "section is both writable and executable";
    case RR_ERR_TLS:       return "TLS callback invocation failed";
    case RR_ERR_ENTRY:     return "entry point invocation failed";
    case RR_ERR_NOENTRY:   return "no entry point and no TLS callback";
    case LD_ERR_ARG:       return "arg";
    case LD_ERR_TRUNC:     return "truncated";
    case LD_ERR_FORMAT:    return "malformed";
    case LD_ERR_NOTFOUND:  return "not found";
    case LD_ERR_NOSPACE:   return "no space";
    case LD_ERR_AUTH:      return "auth";
    default:               return "unknown";
    }
}

int rr_load_run(const uint8_t *pe, size_t pe_len,
                uint8_t *region, size_t region_size,
                const rr_hooks_t *h, rr_result_t *out)
{
    pe_image_t       img;
    reflect_image_t  rim;
    uint32_t         vsz;
    int64_t          delta;
    uint32_t         i;
    size_t           k;
    int              r;

    if (out) {
        memset(out, 0, sizeof(*out));
        out->prot_fail_at = -1;
        out->tls_fail_at  = -1;
    }
    if (!pe || pe_len == 0 || !region || region_size == 0) return RR_ERR_PARAM;
    if (!h) return RR_ERR_PARAM;
    if (!h->protect || !h->call || !h->resolve) return RR_ERR_NOHOOK;

    r = pe_parse(pe, pe_len, &img);
    if (r != LD_OK) return r;

    vsz = pe_virtual_size(&img);
    if (region_size < vsz) return LD_ERR_NOSPACE;

    /* 节区对齐小于页粒度：逐节设权会互相覆盖，产生静默的错误权限 */
    if (img.sect_align != 0 && img.sect_align < RR_PAGE_GRAN) return RR_ERR_PROT;

    delta = (int64_t)((uintptr_t)region) - (int64_t)img.image_base;

    memset(&rim, 0, sizeof(rim));
    rim.base        = region;
    rim.region_size = region_size;
    rim.delta       = delta;

    r = reflect_map_sections(&img, region, region_size);
    if (r != LD_OK) return r;

    r = reflect_relocate(&img, region, region_size, delta, &rim.n_reloc);
    if (r != LD_OK) return r;

    r = reflect_bind_imports(&img, region, region_size, h->resolve, h->res_ud,
                             &rim.n_import);
    if (r != LD_OK) return r;

    r = reflect_collect_tls(&img, region, region_size,
                            rim.tls_cb, REFLECT_MAX_TLS, &rim.n_tls);
    if (r != LD_OK) return r;

    rim.entry_va = img.entry_rva
                 ? (uint64_t)(uintptr_t)(region + img.entry_rva)
                 : 0;

    /* ---- 权限：必须在任何执行之前完成 ---- */

    /* 头部区（不属于任何节区）按只读处理，避免整块区域残留可写 */
    {
        uint32_t hdr_end = img.size_headers;
        uint32_t first_va = 0;
        int have_first = 0;

        for (i = 0; i < img.sec_count; i++) {
            if (img.secs[i].vaddr == 0) continue;
            if (!have_first || img.secs[i].vaddr < first_va) {
                first_va = img.secs[i].vaddr;
                have_first = 1;
            }
        }
        if (have_first && hdr_end > first_va) hdr_end = first_va;
        if (hdr_end > region_size) hdr_end = (uint32_t)region_size;

        if (hdr_end > 0) {
            r = h->protect(h->ud, region, (size_t)hdr_end, RR_P_R);
            if (r != 0) {
                if (out) out->prot_fail_at = -2;   /* -2 = 头部区 */
                return RR_ERR_PROT;
            }
        }
    }

    for (i = 0; i < img.sec_count; i++) {
        const pe_sec_t *s = &img.secs[i];
        uint32_t vsize = s->vsize ? s->vsize : s->raw_size;
        int prot = RR_P_NONE;

        if (s->vaddr == 0 || vsize == 0) continue;
        if ((size_t)s->vaddr >= region_size) return LD_ERR_NOSPACE;
        if ((size_t)vsize > region_size - (size_t)s->vaddr)
            vsize = (uint32_t)(region_size - (size_t)s->vaddr);
        if (vsize == 0) continue;

        r = rr_protect_for(s->chars, &prot);
        if (r != RR_OK) {
            if (out) out->prot_fail_at = (int)i;
            return r;
        }
        r = h->protect(h->ud, region + s->vaddr, (size_t)vsize, prot);
        if (r != 0) {
            if (out) out->prot_fail_at = (int)i;
            return RR_ERR_PROT;
        }
        if (out) out->n_sections_prot++;
    }

    /* ---- TLS 回调：先于入口点 ---- */
    for (k = 0; k < rim.n_tls; k++) {
        uint64_t ret = 0;
        r = h->call(h->ud, rim.tls_cb[k],
                    (uint64_t)(uintptr_t)region, DLL_PROCESS_ATTACH, 0, &ret);
        if (r != 0) {
            if (out) out->tls_fail_at = (int)k;
            return RR_ERR_TLS;
        }
        if (out) { out->tls_ret = ret; out->n_tls = k + 1; }
    }

    /* ---- 入口点 ---- */
    if (rim.entry_va == 0) {
        /* 资源型 DLL 无入口是合法的，但必须有 TLS 回调证明"确实执行了"；
           两者皆无则不允许静默空跑（上层会误判成已落地生效）。 */
        if (rim.n_tls == 0) return RR_ERR_NOENTRY;
        if (out) {
            out->base = region; out->size = region_size; out->delta = delta;
            out->n_reloc = rim.n_reloc; out->n_import = rim.n_import;
            out->is_dll = (img.chars & FILE_DLL) ? 1 : 0;
        }
        return RR_OK;
    }

    {
        uint64_t a1 = (img.chars & FILE_DLL)
                    ? (uint64_t)(uintptr_t)region : 0;
        uint64_t a2 = (img.chars & FILE_DLL) ? DLL_PROCESS_ATTACH : 0;
        uint64_t ret = 0;

        r = h->call(h->ud, rim.entry_va, a1, a2, 0, &ret);
        if (r != 0) return RR_ERR_ENTRY;

        /* DllMain 在 PROCESS_ATTACH 返回 FALSE 即初始化失败。
           EXE 入口的返回值是退出码，0 表示成功，故只对 DLL 判定。 */
        if ((img.chars & FILE_DLL) && ret == 0) return RR_ERR_ENTRY;

        if (out) {
            out->entry_ret     = ret;
            out->entry_invoked = 1;
        }
    }

    if (out) {
        out->base    = region;
        out->size    = region_size;
        out->delta   = delta;
        out->entry_va = rim.entry_va;
        out->n_reloc = rim.n_reloc;
        out->n_import = rim.n_import;
        if (out->n_tls == 0) out->n_tls = rim.n_tls;
        out->is_dll  = (img.chars & FILE_DLL) ? 1 : 0;
    }
    (void)SCN_MEM_DISCARDABLE;
    return RR_OK;
}
