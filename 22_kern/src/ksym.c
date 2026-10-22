#include "kern.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define KSYM_DEFAULT   "/proc/kallsyms"
#define KSYM_BUCKETS   65536u
#define KSYM_CHUNK     (1u<<20)

typedef struct ksym_ent {
    uint64_t           addr;
    char               type;
    char              *name;
    struct ksym_ent   *next;
} ksym_ent;

struct ksym_tab {
    ksym_ent *buckets[KSYM_BUCKETS];
    size_t    count;
    uint64_t  stext, etext;
    int       have_text;
};

const char *kern_strerror(int rc)
{
    switch (rc) {
    case KERN_OK:             return "ok";
    case KERN_ERR_PARAM:      return "invalid parameter";
    case KERN_ERR_MEM:        return "out of memory";
    case KERN_ERR_IO:         return "io error";
    case KERN_ERR_OPEN:       return "cannot open";
    case KERN_ERR_FORMAT:     return "malformed input";
    case KERN_ERR_NOTFOUND:   return "not found";
    case KERN_ERR_UNMAPPED:   return "address not mapped in kcore";
    case KERN_ERR_TRUNC:      return "read truncated at segment boundary";
    case KERN_ERR_LAYOUT:     return "layout probe failed";
    default:                  return "unknown error";
    }
}

static size_t fnv1a(const char *s)
{
    size_t h = (size_t)1469598103934665603ULL;
    while (*s) { h ^= (unsigned char)*s++; h *= (size_t)1099511628211ULL; }
    return h;
}

/* kallsyms 行: "ffffffff81000000 T _stext\n" */
static int parse_line(char *line, uint64_t *addr, char *type, const char **name)
{
    char *p = line;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(p, &end, 16);
    if (end == p || errno == ERANGE) return -1;
    while (*end == ' ' || *end == '\t') end++;
    if (!*end) return -1;
    char t = *end++;
    while (*end == ' ' || *end == '\t') end++;
    if (!*end) return -1;
    char *nl = end;
    while (*nl && *nl != '\n' && *nl != '\r') nl++;
    *nl = '\0';
    if (nl == end) return -1;
    *addr = (uint64_t)v;
    *type = t;
    *name = end;
    return 0;
}

static int tab_insert(ksym_tab *t, uint64_t addr, char type, const char *name)
{
    ksym_ent *e = (ksym_ent *)malloc(sizeof(*e));
    if (!e) return KERN_ERR_MEM;
    size_t nlen = strlen(name);
    e->name = (char *)malloc(nlen + 1);
    if (!e->name) { free(e); return KERN_ERR_MEM; }
    memcpy(e->name, name, nlen + 1);
    e->addr = addr;
    e->type = type;
    size_t b = fnv1a(name) & (KSYM_BUCKETS - 1);
    e->next = t->buckets[b];
    t->buckets[b] = e;
    t->count++;
    return KERN_OK;
}

int ksym_load(ksym_tab **out, const char *path)
{
    if (!out) return KERN_ERR_PARAM;
    *out = NULL;
    const char *p = path ? path : KSYM_DEFAULT;

    FILE *f = fopen(p, "r");
    if (!f) return KERN_ERR_OPEN;

    ksym_tab *t = (ksym_tab *)calloc(1, sizeof(*t));
    if (!t) { fclose(f); return KERN_ERR_MEM; }

    char *buf = (char *)malloc(KSYM_CHUNK);
    if (!buf) { free(t); fclose(f); return KERN_ERR_MEM; }

    int rc = KERN_OK;
    while (fgets(buf, (int)KSYM_CHUNK, f)) {
        uint64_t addr; char type; const char *name;
        if (parse_line(buf, &addr, &type, &name) != 0) continue;
        rc = tab_insert(t, addr, type, name);
        if (rc != KERN_OK) break;
    }
    free(buf);
    fclose(f);

    if (rc != KERN_OK) { ksym_free(t); return rc; }
    if (t->count == 0) { ksym_free(t); return KERN_ERR_FORMAT; }

    /* text 段边界：缺失时记号保持 0，调用方用 kern_in_text 前应先确认 */
    uint64_t a;
    if (ksym_lookup(t, "_stext", &a, NULL) == KERN_OK) { t->stext = a; t->have_text = 1; }
    if (ksym_lookup(t, "_etext", &a, NULL) == KERN_OK) t->etext = a;

    *out = t;
    return KERN_OK;
}

void ksym_free(ksym_tab *t)
{
    if (!t) return;
    for (size_t i = 0; i < KSYM_BUCKETS; i++) {
        ksym_ent *e = t->buckets[i];
        while (e) { ksym_ent *n = e->next; free(e->name); free(e); e = n; }
    }
    free(t);
}

int ksym_lookup(const ksym_tab *t, const char *name, uint64_t *addr, char *type)
{
    if (!t || !name) return KERN_ERR_PARAM;
    size_t b = fnv1a(name) & (KSYM_BUCKETS - 1);
    for (ksym_ent *e = t->buckets[b]; e; e = e->next) {
        if (strcmp(e->name, name) == 0) {
            if (addr) *addr = e->addr;
            if (type) *type = e->type;
            return KERN_OK;
        }
    }
    return KERN_ERR_NOTFOUND;
}

int ksym_has(const ksym_tab *t, const char *name)
{
    uint64_t a;
    return ksym_lookup(t, name, &a, NULL);
}

size_t ksym_count(const ksym_tab *t)   { return t ? t->count : 0; }
uint64_t ksym_stext(const ksym_tab *t) { return t ? t->stext : 0; }
uint64_t ksym_etext(const ksym_tab *t) { return t ? t->etext : 0; }

int ksym_enum_prefix(const ksym_tab *t, const char *pfx, ksym_cb cb, void *ud)
{
    if (!t || !cb) return KERN_ERR_PARAM;
    size_t pl = pfx ? strlen(pfx) : 0;
    for (size_t i = 0; i < KSYM_BUCKETS; i++) {
        for (ksym_ent *e = t->buckets[i]; e; e = e->next) {
            if (pl && strncmp(e->name, pfx, pl) != 0) continue;
            int r = cb(e->name, e->addr, e->type, ud);
            if (r != 0) return KERN_OK;
        }
    }
    return KERN_OK;
}

/* 同一地址在 kallsyms 里常有多个别名：
 *   ffffffff81038070 t __do_sys_rt_sigreturn
 *   ffffffff81038070 T __ia32_sys_rt_sigreturn
 *   ffffffff81038070 T __x64_sys_rt_sigreturn
 * 若按哈希表遍历序取"最后一个"，选中的会是内部包装名（__do_sys_ / __ia32_），
 * 进而被完整性检测误判成"已被 hook"。故定义规范名偏好序：越大越优先。 */
static int sym_pref(const char *n)
{
    if (strncmp(n, "__pfx_", 6)     == 0) return 0;   /* CFI 前缀桩 */
    if (strncmp(n, "__do_sys_", 9)  == 0) return 1;   /* 实现体内部名 */
    if (strncmp(n, "__se_sys_", 9)  == 0) return 1;
    if (strncmp(n, "__ia32_sys_", 11) == 0) return 2; /* 32 位兼容入口 */
    return 3;                                          /* 规范名 */
}

/* 反查：地址 -> 覆盖该地址的最近符号（addr <= target 中地址最大者）；
 * 同地址多别名时取规范名，偏好相同时取字典序最小以保证结果确定。 */
int ksym_rev(const ksym_tab *t, uint64_t addr, char *name, size_t n, char *type)
{
    if (!t || !name || n == 0) return KERN_ERR_PARAM;

    /* 线性扫描：20 万符号，反查非热路径，正确性优先于速度 */
    int ok = 0;
    uint64_t best = 0;
    const char *nm = NULL;
    char ty = 0;
    int best_pref = -1;

    for (size_t i = 0; i < KSYM_BUCKETS; i++) {
        for (ksym_ent *e = t->buckets[i]; e; e = e->next) {
            if (e->addr > addr) continue;
            int pr = sym_pref(e->name);
            if (!ok || e->addr > best) {
                best = e->addr; nm = e->name; ty = e->type; ok = 1; best_pref = pr;
            } else if (e->addr == best) {
                if (pr > best_pref ||
                    (pr == best_pref && strcmp(e->name, nm) < 0)) {
                    nm = e->name; ty = e->type; best_pref = pr;
                }
            }
        }
    }
    if (!ok) return KERN_ERR_NOTFOUND;
    size_t l = strlen(nm);
    if (l >= n) return KERN_ERR_TRUNC;
    memcpy(name, nm, l + 1);
    if (type) *type = ty;
    return KERN_OK;
}
