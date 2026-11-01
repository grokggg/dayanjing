#ifndef KERN_H
#define KERN_H

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ *
 * 22_kern — 内核符号解析 / 内核内存读取 / 运行时布局探测 / hook 方案
 *
 * 本层运行在用户态，经 /proc/kallsyms 与 /proc/kcore 访问内核。
 * 它不加载模块、不修改内核。它回答的是 LKM 能否跨版本工作所必须
 * 先解决的问题：符号在哪、内存怎么读、结构体字段在哪、hook 点是否被占。
 *
 * 读原语：/proc/kcore（只读）
 * 写原语：不在本层（需 LKM / 驱动 / 漏洞），本层只提供定位与校验。
 * ------------------------------------------------------------------ */

#define KERN_OK            0
#define KERN_ERR_PARAM    -1
#define KERN_ERR_MEM      -2
#define KERN_ERR_IO       -3
#define KERN_ERR_OPEN     -4
#define KERN_ERR_FORMAT   -5
#define KERN_ERR_NOTFOUND -6
#define KERN_ERR_UNMAPPED -7
#define KERN_ERR_TRUNC    -8
#define KERN_ERR_LAYOUT   -9

const char *kern_strerror(int rc);

/* ============================ kallsyms ============================ */

typedef struct ksym_tab ksym_tab;

int  ksym_load(ksym_tab **out, const char *path);   /* path=NULL -> /proc/kallsyms */
void ksym_free(ksym_tab *t);

int  ksym_lookup(const ksym_tab *t, const char *name, uint64_t *addr, char *type);
int  ksym_rev(const ksym_tab *t, uint64_t addr, char *name, size_t n, char *type);
int  ksym_has(const ksym_tab *t, const char *name);

size_t   ksym_count(const ksym_tab *t);
uint64_t ksym_stext(const ksym_tab *t);
uint64_t ksym_etext(const ksym_tab *t);

/* 回调枚举：返回 0 继续，非 0 提前终止 */
typedef int (*ksym_cb)(const char *name, uint64_t addr, char type, void *ud);
int ksym_enum_prefix(const ksym_tab *t, const char *pfx, ksym_cb cb, void *ud);

/* ============================== kcore ============================= */

typedef struct kcore kcore;

int  kcore_open(kcore **out, const char *path);     /* path=NULL -> /proc/kcore */
void kcore_close(kcore *k);

int  kcore_mapped(const kcore *k, uint64_t va, size_t n);
int  kcore_read(const kcore *k, uint64_t va, void *buf, size_t n);
int  kcore_read_u64(const kcore *k, uint64_t va, uint64_t *v);

size_t kcore_nload(const kcore *k);

/* ============================== kver ============================== */

typedef struct {
    int  major, minor, patch;
    char raw[256];
} kver;

int kver_from_proc(kver *out);
int kver_parse(const char *release, kver *out);
int kver_at_least(const kver *v, int maj, int min, int pat);

/* ============================ kern ctx ============================ */

typedef struct kern_ctx kern_ctx;

int  kern_open(kern_ctx **out);
void kern_close(kern_ctx *c);

ksym_tab *kern_syms(kern_ctx *c);
kcore    *kern_mem(kern_ctx *c);
const kver *kern_ver(kern_ctx *c);

/* 符号 -> 地址 */
int kern_symbol(kern_ctx *c, const char *name, uint64_t *addr);

/* syscall 号 -> 内核实现地址（经 sys_call_table 读出，非直接取符号名） */
int kern_syscall_impl(kern_ctx *c, int nr, uint64_t *addr);
/* syscall 号 -> 该表项自身的地址（hook 写入点） */
int kern_syscall_slot(kern_ctx *c, int nr, uint64_t *slot);

/* 读内核内存（8 字节 / 任意长度） */
int kern_read_u64(kern_ctx *c, uint64_t va, uint64_t *v);
int kern_read(kern_ctx *c, uint64_t va, void *buf, size_t n);

/* 地址是否落在内核 text 段内 */
int kern_in_text(kern_ctx *c, uint64_t addr);

/* ======================== 运行时布局探测 ========================== */

typedef struct {
    size_t usage;
    size_t uid, gid, suid, sgid, euid, egid, fsuid, fsgid;
    size_t securebits;
    size_t cap_inheritable, cap_permitted, cap_effective;
    size_t cap_bset, cap_ambient;
    uint64_t cap_full_mask;     /* 探测到的"权限全集"位模式 */
    int      probed;            /* 1 = 由运行时探测得出，0 = 未探测 */
} klayout_cred;

/* 从 init_cred（或任意 root cred）运行时探测 cred 字段偏移。
 * 不用编译期常量——内核版本间布局会变（本层实测 6.6 与教科书差 8 字节）。 */
int klayout_cred_probe(kern_ctx *c, const char *cred_sym, klayout_cred *out);

/* ============================ hook 方案 =========================== */

typedef enum {
    KHOOK_READ = 0,
    KHOOK_GETDENTS,
    KHOOK_GETDENTS64,
    KHOOK_KILL,
    KHOOK_MAX
} khook_target;

typedef struct {
    khook_target target;
    int          syscall_nr;
    uint64_t     slot;      /* sys_call_table 表项地址：hook 写入点 */
    uint64_t     orig;      /* 表项当前值 */
    uint64_t     expect;    /* 由符号表独立解析出的期望值 */
    int          intact;    /* 1 = slot 值 == 期望值（未被第三方 hook） */
} khook_plan;

int khook_plan_build(kern_ctx *c, khook_target t, khook_plan *out);
int khook_target_name(khook_target t, const char **name);
int khook_target_nr(khook_target t, int *nr);

/* 全表完整性扫描：找出所有已被篡改（或已 hook）的表项 */
int khook_scan_hooked(kern_ctx *c, int nr_from, int nr_to,
                      int (*cb)(int nr, uint64_t slot, uint64_t got,
                                uint64_t expect, void *ud), void *ud);

#endif /* KERN_H */
