#include "kern.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>

#define KCORE_DEFAULT "/proc/kcore"
#define KCORE_MAXPH   256

struct kcore {
    int         fd;
    Elf64_Phdr  ph[KCORE_MAXPH];
    int         nph;
    size_t      nload;
};

int kcore_open(kcore **out, const char *path)
{
    if (!out) return KERN_ERR_PARAM;
    *out = NULL;
    const char *p = path ? path : KCORE_DEFAULT;

    int fd = open(p, O_RDONLY);
    if (fd < 0) return KERN_ERR_OPEN;

    Elf64_Ehdr eh;
    ssize_t r = pread(fd, &eh, sizeof(eh), 0);
    if (r != (ssize_t)sizeof(eh)) { close(fd); return KERN_ERR_IO; }
    /* SEC-CMP:PUBLIC: 双方均为公开数据（传输中可见或可自行计算），无秘密可泄露 */
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) { close(fd); return KERN_ERR_FORMAT; }
    if (eh.e_ident[EI_CLASS] != ELFCLASS64) { close(fd); return KERN_ERR_FORMAT; }

    int n = eh.e_phnum;
    if (n <= 0 || n > KCORE_MAXPH) { close(fd); return KERN_ERR_FORMAT; }

    kcore *k = (kcore *)calloc(1, sizeof(*k));
    if (!k) { close(fd); return KERN_ERR_MEM; }
    k->fd = fd;

    size_t need = sizeof(Elf64_Phdr) * (size_t)n;
    r = pread(fd, k->ph, need, (off_t)eh.e_phoff);
    if (r != (ssize_t)need) { free(k); close(fd); return KERN_ERR_IO; }
    k->nph = n;
    for (int i = 0; i < n; i++) if (k->ph[i].p_type == PT_LOAD) k->nload++;

    *out = k;
    return KERN_OK;
}

void kcore_close(kcore *k)
{
    if (!k) return;
    if (k->fd >= 0) close(k->fd);
    free(k);
}

size_t kcore_nload(const kcore *k) { return k ? k->nload : 0; }

/* 找到覆盖 [va, va+n) 起点的 PT_LOAD；返回索引，未覆盖返回 -1 */
static int find_seg(const kcore *k, uint64_t va, size_t n)
{
    if (!k) return -1;
    for (int i = 0; i < k->nph; i++) {
        if (k->ph[i].p_type != PT_LOAD) continue;
        uint64_t s = k->ph[i].p_vaddr;
        uint64_t e = s + k->ph[i].p_memsz;
        if (va >= s && va + n <= e) return i;
    }
    return -1;
}

int kcore_mapped(const kcore *k, uint64_t va, size_t n)
{
    return find_seg(k, va, n) >= 0 ? 1 : 0;
}

int kcore_read(const kcore *k, uint64_t va, void *buf, size_t n)
{
    if (!k || !buf) return KERN_ERR_PARAM;
    if (n == 0) return KERN_OK;

    unsigned char *dst = (unsigned char *)buf;
    size_t done = 0;
    while (done < n) {
        uint64_t cur = va + done;
        int si = find_seg(k, cur, 1);
        if (si < 0) return KERN_ERR_UNMAPPED;
        uint64_t s = k->ph[si].p_vaddr;
        uint64_t e = s + k->ph[si].p_memsz;
        size_t avail = (size_t)(e - cur);
        size_t want = n - done;
        if (want > avail) want = avail;      /* 跨段：本段读完，下轮换段 */
        off_t off = (off_t)(k->ph[si].p_offset + (cur - s));
        ssize_t r = pread(k->fd, dst + done, want, off);
        if (r < 0) return KERN_ERR_IO;
        if (r == 0) return KERN_ERR_TRUNC;
        done += (size_t)r;
    }
    return KERN_OK;
}

int kcore_read_u64(const kcore *k, uint64_t va, uint64_t *v)
{
    if (!v) return KERN_ERR_PARAM;
    unsigned char b[8];
    int rc = kcore_read(k, va, b, sizeof(b));
    if (rc != KERN_OK) return rc;
    uint64_t out = 0;
    for (int i = 7; i >= 0; i--) out = (out << 8) | (uint64_t)b[i];   /* 小端显式解码 */
    *v = out;
    return KERN_OK;
}
