#include "kern.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

struct kern_ctx {
    ksym_tab *syms;
    kcore    *mem;
    kver      ver;
    uint64_t  sys_call_table;
    int       have_sct;
};

/* ------------------------------ kver ------------------------------ */

int kver_parse(const char *release, kver *out)
{
    if (!release || !out) return KERN_ERR_PARAM;
    memset(out, 0, sizeof(*out));
    int maj = -1, min = -1, pat = -1;
    int got = sscanf(release, "%d.%d.%d", &maj, &min, &pat);
    if (got < 1) return KERN_ERR_FORMAT;
    if (got < 2) min = 0;
    if (got < 3) pat = 0;
    out->major = maj; out->minor = min; out->patch = pat;
    size_t l = strlen(release);
    if (l >= sizeof(out->raw)) l = sizeof(out->raw) - 1;
    memcpy(out->raw, release, l);
    out->raw[l] = '\0';
    return KERN_OK;
}

int kver_from_proc(kver *out)
{
    if (!out) return KERN_ERR_PARAM;
    FILE *f = fopen("/proc/sys/kernel/osrelease", "r");
    if (!f) return KERN_ERR_OPEN;
    char buf[256];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return KERN_ERR_IO; }
    fclose(f);
    buf[strcspn(buf, "\r\n")] = '\0';
    return kver_parse(buf, out);
}

int kver_at_least(const kver *v, int maj, int min, int pat)
{
    if (!v) return 0;
    if (v->major != maj) return v->major > maj;
    if (v->minor != min) return v->minor > min;
    return v->patch >= pat;
}

/* ---------------------------- kern ctx ---------------------------- */

int kern_open(kern_ctx **out)
{
    if (!out) return KERN_ERR_PARAM;
    *out = NULL;

    kern_ctx *c = (kern_ctx *)calloc(1, sizeof(*c));
    if (!c) return KERN_ERR_MEM;

    int rc = ksym_load(&c->syms, NULL);
    if (rc != KERN_OK) { free(c); return rc; }

    rc = kcore_open(&c->mem, NULL);
    if (rc != KERN_OK) { ksym_free(c->syms); free(c); return rc; }

    if (kver_from_proc(&c->ver) != KERN_OK) {
        c->ver.major = c->ver.minor = c->ver.patch = 0;
        snprintf(c->ver.raw, sizeof(c->ver.raw), "unknown");
    }

    uint64_t a;
    if (ksym_lookup(c->syms, "sys_call_table", &a, NULL) == KERN_OK) {
        c->sys_call_table = a;
        c->have_sct = 1;
    }

    *out = c;
    return KERN_OK;
}

void kern_close(kern_ctx *c)
{
    if (!c) return;
    ksym_free(c->syms);
    kcore_close(c->mem);
    free(c);
}

ksym_tab *kern_syms(kern_ctx *c)      { return c ? c->syms     : NULL; }
kcore    *kern_mem(kern_ctx *c)       { return c ? c->mem      : NULL; }
const kver *kern_ver(kern_ctx *c)     { return c ? &c->ver     : NULL; }

int kern_symbol(kern_ctx *c, const char *name, uint64_t *addr)
{
    if (!c || !name) return KERN_ERR_PARAM;
    return ksym_lookup(c->syms, name, addr, NULL);
}

int kern_read_u64(kern_ctx *c, uint64_t va, uint64_t *v)
{
    if (!c) return KERN_ERR_PARAM;
    return kcore_read_u64(c->mem, va, v);
}

int kern_read(kern_ctx *c, uint64_t va, void *buf, size_t n)
{
    if (!c) return KERN_ERR_PARAM;
    return kcore_read(c->mem, va, buf, n);
}

int kern_in_text(kern_ctx *c, uint64_t addr)
{
    if (!c) return 0;
    uint64_t s = ksym_stext(c->syms), e = ksym_etext(c->syms);
    if (s == 0 || e == 0) return 0;      /* 记号缺失时不做无根据的判断 */
    return (addr >= s && addr < e) ? 1 : 0;
}

int kern_syscall_slot(kern_ctx *c, int nr, uint64_t *slot)
{
    if (!c || !slot || nr < 0) return KERN_ERR_PARAM;
    if (!c->have_sct) return KERN_ERR_NOTFOUND;
    *slot = c->sys_call_table + (uint64_t)nr * 8u;
    return KERN_OK;
}

int kern_syscall_impl(kern_ctx *c, int nr, uint64_t *addr)
{
    uint64_t slot;
    int rc = kern_syscall_slot(c, nr, &slot);
    if (rc != KERN_OK) return rc;
    return kern_read_u64(c, slot, addr);
}

/* ------------------------- 运行时布局探测 ------------------------- */

static int is_lowbits_full(uint64_t v)
{
    /* v 形如 2^n - 1：低位连续 1。全 F 的 capability 集合即此形态 */
    return v != 0 && ((v & (v + 1)) == 0);
}

int klayout_cred_probe(kern_ctx *c, const char *cred_sym, klayout_cred *out)
{
    if (!c || !out) return KERN_ERR_PARAM;
    memset(out, 0, sizeof(*out));

    const char *sym = cred_sym ? cred_sym : "init_cred";
    uint64_t base;
    if (kern_symbol(c, sym, &base) != KERN_OK) return KERN_ERR_NOTFOUND;

    unsigned char raw[256];
    if (kern_read(c, base, raw, sizeof(raw)) != KERN_OK) return KERN_ERR_IO;

    /* 头部：root cred 的 uid..fsgid 恒为 0。先确认这段确实全是 0，
     * 否则目标 cred 不是 root 的，后续推断不成立。 */
    int head_zero = 1;
    for (int i = 4; i < 36; i++) if (raw[i] != 0) { head_zero = 0; break; }
    if (!head_zero) return KERN_ERR_LAYOUT;

    uint64_t usage = 0;
    for (int i = 3; i >= 0; i--) usage = (usage << 8) | (uint64_t)raw[i];
    if (usage == 0) return KERN_ERR_LAYOUT;

    out->usage       = 0;
    out->uid         = 4;
    out->gid         = 8;
    out->suid        = 12;
    out->sgid        = 16;
    out->euid        = 20;
    out->egid        = 24;
    out->fsuid       = 28;
    out->fsgid       = 32;
    out->securebits  = 36;

    /* caps：找 0, F, F, F, 0 形态（inheritable=空, permitted/effective/bset=全集,
     * ambient=空）。init_cred 正是这个形态，且它随版本漂移，故必须运行时定位。 */
    int found = -1;
    uint64_t fullmask = 0;
    for (size_t i = 0; i + 40 <= sizeof(raw); i += 8) {
        uint64_t v0, v1, v2, v3, v4;
        memcpy(&v0, raw + i,      8);
        memcpy(&v1, raw + i + 8,  8);
        memcpy(&v2, raw + i + 16, 8);
        memcpy(&v3, raw + i + 24, 8);
        memcpy(&v4, raw + i + 32, 8);
        if (v0 == 0 && v4 == 0 && is_lowbits_full(v1) &&
            v2 == v1 && v3 == v1) {
            found = (int)i;
            fullmask = v1;
            break;
        }
    }
    if (found < 0) return KERN_ERR_LAYOUT;

    out->cap_inheritable = (size_t)found;
    out->cap_permitted   = (size_t)found + 8;
    out->cap_effective   = (size_t)found + 16;
    out->cap_bset        = (size_t)found + 24;
    out->cap_ambient     = (size_t)found + 32;
    out->cap_full_mask   = fullmask;
    out->probed          = 1;
    return KERN_OK;
}

/* ---------------------------- hook 方案 ---------------------------- */

struct nr_entry { khook_target t; int nr; const char *sym; };
static const struct nr_entry NR_TABLE[] = {
    { KHOOK_READ,       0,   "__x64_sys_read"        },
    { KHOOK_GETDENTS,   78,  "__x64_sys_getdents"    },
    { KHOOK_GETDENTS64, 217, "__x64_sys_getdents64"  },
    { KHOOK_KILL,       62,  "__x64_sys_kill"        },
};

int khook_target_name(khook_target t, const char **name)
{
    if (!name) return KERN_ERR_PARAM;
    switch (t) {
    case KHOOK_READ:       *name = "read";       return KERN_OK;
    case KHOOK_GETDENTS:   *name = "getdents";   return KERN_OK;
    case KHOOK_GETDENTS64: *name = "getdents64"; return KERN_OK;
    case KHOOK_KILL:       *name = "kill";       return KERN_OK;
    default: return KERN_ERR_PARAM;
    }
}

int khook_target_nr(khook_target t, int *nr)
{
    if (!nr) return KERN_ERR_PARAM;
    for (size_t i = 0; i < sizeof(NR_TABLE)/sizeof(NR_TABLE[0]); i++)
        if (NR_TABLE[i].t == t) { *nr = NR_TABLE[i].nr; return KERN_OK; }
    return KERN_ERR_NOTFOUND;
}

int khook_plan_build(kern_ctx *c, khook_target t, khook_plan *out)
{
    if (!c || !out) return KERN_ERR_PARAM;
    memset(out, 0, sizeof(*out));
    out->target = t;

    const struct nr_entry *e = NULL;
    for (size_t i = 0; i < sizeof(NR_TABLE)/sizeof(NR_TABLE[0]); i++)
        if (NR_TABLE[i].t == t) { e = &NR_TABLE[i]; break; }
    if (!e) return KERN_ERR_NOTFOUND;

    out->syscall_nr = e->nr;

    uint64_t slot;
    if (kern_syscall_slot(c, e->nr, &slot) != KERN_OK) return KERN_ERR_NOTFOUND;
    out->slot = slot;

    uint64_t got;
    if (kern_read_u64(c, slot, &got) != KERN_OK) return KERN_ERR_IO;
    out->orig = got;

    /* 期望值独立取自符号表——不经 sys_call_table，两条路径互相印证 */
    if (kern_symbol(c, e->sym, &out->expect) != KERN_OK) {
        out->intact = -1;             /* 无法独立求值：不做判断 */
        return KERN_OK;
    }
    out->intact = (got == out->expect) ? 1 : 0;
    return KERN_OK;
}

int khook_scan_hooked(kern_ctx *c, int nr_from, int nr_to,
                      int (*cb)(int nr, uint64_t slot, uint64_t got,
                                uint64_t expect, void *ud), void *ud)
{
    if (!c || !cb || nr_from < 0 || nr_to < nr_from) return KERN_ERR_PARAM;

    for (int nr = nr_from; nr <= nr_to; nr++) {
        uint64_t slot, got;
        if (kern_syscall_slot(c, nr, &slot) != KERN_OK) continue;
        if (kern_read_u64(c, slot, &got) != KERN_OK) continue;

        uint64_t expect = 0;
        int suspicious = 0;

        if (!kern_in_text(c, got)) {
            suspicious = 1;                       /* 落在 text 之外：非原始实现 */
        } else {
            char nm[256];
            if (ksym_rev(c->syms, got, nm, sizeof(nm), NULL) == KERN_OK) {
                if (strncmp(nm, "__x64_sys_", 10) == 0) {
                    /* 反查到的名字与槽位一致，视为正常；期望值即反查所得地址 */
                    expect = got;
                } else if (strncmp(nm, "sys_", 4) == 0) {
                    expect = got;
                } else {
                    suspicious = 1;               /* 落在别人函数体内：已被替换 */
                }
            } else {
                suspicious = 1;                   /* 无符号覆盖该地址 */
            }
        }
        if (!suspicious) continue;
        int r = cb(nr, slot, got, expect, ud);
        if (r != 0) return KERN_OK;
    }
    return KERN_OK;
}
