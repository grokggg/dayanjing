/*
 * DAYANJING v4 — 20_packer / mexec.c
 *
 * 无磁盘执行：把 ELF 映像写入匿名内存文件，再以 execveat(AT_EMPTY_PATH)
 * 直接执行该文件描述符。全程不产生任何磁盘节点，不经过 /proc/self/fd。
 *
 * 为什么用 execveat 而不是 fexecve：
 *   fexecve(3) 在 glibc 中的实现依赖 /proc/self/fd/N 路径，
 *   在 /proc 未挂载或被 hidepid 限制的容器里会失败。
 *   execveat(fd, "", argv, envp, AT_EMPTY_PATH) 让内核直接以 fd 指向的
 *   inode 作为被执行对象，无路径解析，无 /proc 依赖。
 *
 * 内核常量（x86_64 / aarch64）：
 *   SYS_memfd_create  319 / 323
 *   SYS_execveat      322 / 281
 *   MFD_CLOEXEC       0x0001U
 *   MFD_ALLOW_SEALING 0x0002U
 *   AT_EMPTY_PATH     0x1000
 */

#include "packer.h"

#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__)
#  define PK_SYS_MEMFD_CREATE 319
#  define PK_SYS_EXECVEAT     322
#elif defined(__aarch64__)
#  define PK_SYS_MEMFD_CREATE 323
#  define PK_SYS_EXECVEAT     281
#elif defined(__i386__)
#  define PK_SYS_MEMFD_CREATE 356
#  define PK_SYS_EXECVEAT     358
#else
#  define PK_SYS_MEMFD_CREATE 0
#  define PK_SYS_EXECVEAT     0
#endif

#ifndef MFD_CLOEXEC
#  define MFD_CLOEXEC 0x0001U
#endif
#ifndef MFD_ALLOW_SEALING
#  define MFD_ALLOW_SEALING 0x0002U
#endif
#ifndef AT_EMPTY_PATH
#  define AT_EMPTY_PATH 0x1000
#endif

int pk_memfd_write(const uint8_t *data, size_t len)
{
    long fd;
    size_t off = 0;

    if (!data || len == 0) return PK_ERR_ARG;
#if PK_SYS_MEMFD_CREATE == 0
    return PK_ERR_SYS;
#else
    fd = syscall(PK_SYS_MEMFD_CREATE, "", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) {
        /* 老内核不支持 sealing 标志，退回不带该标志 */
        fd = syscall(PK_SYS_MEMFD_CREATE, "", MFD_CLOEXEC);
    }
    if (fd < 0) return PK_ERR_SYS;

    while (off < len) {
        ssize_t n = write((int)fd, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            close((int)fd);
            return PK_ERR_SYS;
        }
        if (n == 0) { close((int)fd); return PK_ERR_SYS; }
        off += (size_t)n;
    }
    return (int)fd;
#endif
}

int pk_mexec(const uint8_t *elf, size_t len,
             char *const argv[], char *const envp[])
{
    int fd;

    if (!elf || len == 0 || !argv) return PK_ERR_ARG;

    fd = pk_memfd_write(elf, len);
    if (fd < 0) return fd;

#if PK_SYS_EXECVEAT != 0
    syscall(PK_SYS_EXECVEAT, fd, "", argv, envp, AT_EMPTY_PATH);
#endif
    /* 走到这里说明 execveat 失败 */
    {
        int e = errno;
        close(fd);
        (void)e;
    }
    return PK_ERR_SYS;
}
