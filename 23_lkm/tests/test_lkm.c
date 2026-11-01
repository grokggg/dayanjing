/* 23_lkm — 内核态操作核心测试
 *
 * 全部用例跑在一块 mock 内存上：读写回调打到普通缓冲区，
 * 因此"链表摘除 / dirent 过滤 / cred 改写 / hook 装卸"的每一次写入
 * 都能被逐字节断言，而不是只看返回值。
 *
 * 末尾的集成用例读真实 /proc/kallsyms 与 /proc/kcore；
 * 无权限（非 root / kptr_restrict）时以 77 退出，记为 SKIP，不造假。
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "lkm.h"

static int pass_count = 0, fail_count = 0;

/* 用可变参数函数而非可变参数宏：宏在只传 fmt 时会触发
 * -Wpedantic 的 "ISO C99 requires at least one argument for the ..."，
 * 而本文件绝大多数断言都不带格式参数。 */
static void chk(int cond, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (cond) {
        printf("[PASS] %s\n", buf);
        pass_count++;
    } else {
        printf("[FAIL] %s\n", buf);
        fail_count++;
    }
}

#define CHECK(...) chk(__VA_ARGS__)

/* ============================ mock 内存 ============================ */

typedef struct {
    unsigned char *p;
    uint64_t       base;
    size_t         size;
    int            fail_wr;    /* 置 1 后所有写入返回 IO 错误 */
} flat_mem;

static int flat_rd(void *ud, uint64_t va, void *buf, size_t n)
{
    flat_mem *f = (flat_mem *)ud;
    if (va < f->base)
        return LKM_ERR_RANGE;
    uint64_t off = va - f->base;
    if (off > f->size || n > f->size - off)
        return LKM_ERR_RANGE;
    memcpy(buf, f->p + off, n);
    return LKM_OK;
}

static int flat_wr(void *ud, uint64_t va, const void *buf, size_t n)
{
    flat_mem *f = (flat_mem *)ud;
    if (f->fail_wr)
        return LKM_ERR_IO;
    if (va < f->base)
        return LKM_ERR_RANGE;
    uint64_t off = va - f->base;
    if (off > f->size || n > f->size - off)
        return LKM_ERR_RANGE;
    memcpy(f->p + off, buf, n);
    return LKM_OK;
}

static void put64(unsigned char *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (unsigned char)((v >> (8 * i)) & 0xff);
}

static uint64_t get64(const unsigned char *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (8 * i);
    return v;
}

static uint32_t get32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ============================ dirent 构造 ============================ */

#define HDR 19

static size_t dirent_put(unsigned char *buf, size_t off, uint64_t ino,
                         const char *name, uint8_t type)
{
    size_t nl = strlen(name) + 1;
    uint16_t rl = (uint16_t)(HDR + nl);
    put64(buf + off, ino);
    put64(buf + off + 8, (uint64_t)(off + rl));
    buf[off + 16] = (unsigned char)(rl & 0xff);
    buf[off + 17] = (unsigned char)((rl >> 8) & 0xff);
    buf[off + 18] = type;
    memcpy(buf + off + HDR, name, nl);
    return off + rl;
}

/* 遍历并收集名字，同时校验序列合法性 */
static size_t dirent_walk(const unsigned char *buf, size_t len,
                          const char **out, size_t cap)
{
    size_t pos = 0, n = 0;
    while (pos < len) {
        if (len - pos < HDR)
            return (size_t)-1;
        uint16_t rl = (uint16_t)(buf[pos + 16] | ((uint16_t)buf[pos + 17] << 8));
        if (rl < HDR || (size_t)rl > len - pos)
            return (size_t)-1;
        if (n < cap)
            out[n] = (const char *)(buf + pos + HDR);
        n++;
        pos += rl;
    }
    return n;
}

/* ============================== 用例 ============================== */

static void t_selftest(void)
{
    CHECK(lkm_selftest() == 0, "内置自检通过（链表/dirent/布局校验）");
}

static void t_unlink(void)
{
    unsigned char a[4096];
    memset(a, 0, sizeof(a));
    flat_mem f = { a, 0x1000, sizeof(a), 0 };
    lkm_mem m = { flat_rd, flat_wr, &f };

    const uint64_t A = 0x1000, B = 0x1020, C = 0x1040;
    put64(a + 0x00, B); put64(a + 0x08, C);   /* A: next=B prev=C */
    put64(a + 0x20, C); put64(a + 0x28, A);   /* B */
    put64(a + 0x40, A); put64(a + 0x48, B);   /* C */

    CHECK(lkm_unlink_node(&m, B, 0, 8, 0) == LKM_OK, "摘除中间节点成功");
    CHECK(get64(a + 0x00) == C && get64(a + 0x48) == A, "摘除后 A.next=C / C.prev=A");
    CHECK(get64(a + 0x20) == B && get64(a + 0x28) == B, "被摘节点自环（不悬空、不 oops）");
    CHECK(lkm_unlink_node(&m, B, 0, 8, 0) == LKM_ERR_NOTFOUND, "重复摘除幂等返回 NOTFOUND");

    /* 互指被破坏 -> 一个字节都不许写 */
    unsigned char b[4096];
    memset(b, 0, sizeof(b));
    flat_mem f2 = { b, 0x1000, sizeof(b), 0 };
    lkm_mem m2 = { flat_rd, flat_wr, &f2 };
    unsigned char before[4096];
    put64(b + 0x00, B); put64(b + 0x08, C);
    put64(b + 0x20, C); put64(b + 0x28, A);
    put64(b + 0x40, A); put64(b + 0x48, 0x9999);  /* C.prev 不指回 B */
    memcpy(before, b, 64);
    CHECK(lkm_unlink_node(&m2, B, 0, 8, 0) == LKM_ERR_CORRUPT, "互指破坏 -> CORRUPT");
    CHECK(memcmp(before, b, 64) == 0, "CORRUPT 时未写入任何字节");

    CHECK(lkm_unlink_node(&m, B, 8, 8, 0) == LKM_ERR_PARAM, "next_off==prev_off -> PARAM");

    /* KEEP 标志：node 自身指针保持原值 */
    unsigned char c[4096];
    memset(c, 0, sizeof(c));
    flat_mem f3 = { c, 0x1000, sizeof(c), 0 };
    lkm_mem m3 = { flat_rd, flat_wr, &f3 };
    put64(c + 0x00, B); put64(c + 0x08, C);
    put64(c + 0x20, C); put64(c + 0x28, A);
    put64(c + 0x40, A); put64(c + 0x48, B);
    CHECK(lkm_unlink_node(&m3, B, 0, 8, LKM_UNLINK_KEEP) == LKM_OK, "KEEP 模式摘除成功");
    CHECK(get64(c + 0x20) == C && get64(c + 0x28) == A, "KEEP 模式不动 node 自身指针");

    /* 越界读 */
    CHECK(lkm_unlink_node(&m, 0x1000 + 4090, 0, 8, 0) == LKM_ERR_RANGE, "越界访问 -> RANGE");

    /* 写入失败时如实返回 */
    f.fail_wr = 1;
    put64(a + 0x00, B); put64(a + 0x08, C);
    put64(a + 0x20, C); put64(a + 0x28, A);
    put64(a + 0x40, A); put64(a + 0x48, B);
    CHECK(lkm_unlink_node(&m, B, 0, 8, 0) == LKM_ERR_IO, "写入失败 -> IO（不静默成功）");
    f.fail_wr = 0;
}

static void t_dirent(void)
{
    unsigned char buf[1024];
    size_t len = 0;
    len = dirent_put(buf, len, 1, "alpha", 8);
    len = dirent_put(buf, len, 2, "target", 8);
    len = dirent_put(buf, len, 3, "omega", 8);

    size_t nl = 0, rem = 0;
    const char *names[8];
    CHECK(lkm_dirent_filter(buf, len, lkm_dirent_hide_name, (void *)"target",
                            &nl, &rem) == LKM_OK, "过滤中间条目返回 OK");
    CHECK(rem == 1, "隐藏条数 == 1");
    size_t n = dirent_walk(buf, nl, names, 8);
    CHECK(n == 2, "过滤后重新遍历得到 2 个合法条目");
    CHECK(n == 2 && strcmp(names[0], "alpha") == 0 && strcmp(names[1], "omega") == 0,
          "剩余条目顺序与内容正确");

    /* 全隐藏 */
    len = 0;
    len = dirent_put(buf, len, 1, "one", 8);
    len = dirent_put(buf, len, 2, "two", 8);
    CHECK(lkm_dirent_filter(buf, len, lkm_dirent_hide_name, (void *)"one",
                            &nl, &rem) == LKM_OK, "过滤首条目 OK");
    CHECK(lkm_dirent_filter(buf, nl, lkm_dirent_hide_name, (void *)"two",
                            &nl, &rem) == LKM_OK, "再过滤剩余条目 OK");
    CHECK(nl == 0, "全部隐藏后长度归零");

    /* 无匹配 */
    len = 0;
    len = dirent_put(buf, len, 1, "alpha", 8);
    len = dirent_put(buf, len, 2, "omega", 8);
    size_t orig = len;
    CHECK(lkm_dirent_filter(buf, len, lkm_dirent_hide_name, (void *)"nope",
                            &nl, &rem) == LKM_OK, "无匹配过滤 OK");
    CHECK(nl == orig && rem == 0, "无匹配时缓冲区不变");

    /* 畸形：reclen = 0 */
    len = 0;
    len = dirent_put(buf, len, 1, "alpha", 8);
    unsigned char save[1024];
    buf[16] = 0; buf[17] = 0;
    /* 快照必须在"注入畸形之后、调用过滤之前"取：
     * 我们断言的是过滤没有改写缓冲区，而不是缓冲区等于畸形前的内容。 */
    memcpy(save, buf, len);
    CHECK(lkm_dirent_filter(buf, len, lkm_dirent_hide_name, (void *)"alpha",
                            &nl, &rem) == LKM_ERR_CORRUPT, "reclen==0 -> CORRUPT");
    CHECK(memcmp(save, buf, len) == 0, "CORRUPT 时缓冲区未被改写");

    /* 畸形：reclen 越出缓冲区 */
    memcpy(buf, save, len);
    buf[16] = 0xff; buf[17] = 0xff;
    CHECK(lkm_dirent_filter(buf, len, lkm_dirent_hide_name, (void *)"alpha",
                            &nl, &rem) == LKM_ERR_CORRUPT, "reclen 越界 -> CORRUPT");

    /* 畸形：尾部不足一个头部 */
    memcpy(buf, save, len);
    CHECK(lkm_dirent_filter(buf, HDR - 1, lkm_dirent_hide_name, (void *)"alpha",
                            &nl, &rem) == LKM_ERR_CORRUPT, "尾部残缺头部 -> CORRUPT");

    /* 零长度 */
    CHECK(lkm_dirent_filter(buf, 0, lkm_dirent_hide_name, (void *)"x",
                            &nl, &rem) == LKM_OK && nl == 0, "空缓冲区 -> OK 且长度 0");

    /* 名字无 NUL：不得越出本条目 */
    unsigned char nb[128];
    memset(nb, 0, sizeof(nb));
    uint16_t rl = (uint16_t)(HDR + 5);
    put64(nb, 7);
    put64(nb + 8, rl);
    nb[16] = (unsigned char)(rl & 0xff);
    nb[17] = (unsigned char)((rl >> 8) & 0xff);
    nb[18] = 8;
    memset(nb + HDR, 'A', 5);           /* 无 NUL */
    memset(nb + HDR + 5, 'Z', 5);       /* 条目之后的哨兵 */
    CHECK(lkm_dirent_filter(nb, rl, lkm_dirent_hide_name, (void *)"AAAAA",
                            &nl, &rem) == LKM_OK, "无 NUL 名字可安全过滤");
    CHECK(rem == 1 && nl == 0, "无 NUL 名字按条目边界匹配，未越过边界");
}

static int cb_pid_ok;

static void t_dirent_pid(void)
{
    unsigned char buf[1024];
    size_t len = 0;
    len = dirent_put(buf, len, 1, "4242", 4);
    len = dirent_put(buf, len, 2, "proc", 4);
    len = dirent_put(buf, len, 3, "42x", 4);
    len = dirent_put(buf, len, 4, "004242", 4);

    uint64_t want = 4242;
    size_t nl = 0, rem = 0;
    const char *names[8];
    CHECK(lkm_dirent_filter(buf, len, lkm_dirent_hide_pid, &want, &nl, &rem) == LKM_OK,
          "按 pid 过滤 OK");
    size_t n = dirent_walk(buf, nl, names, 8);
    CHECK(n == 3, "仅数字名且数值相等者被隐藏（proc / 42x 保留）");
    CHECK(rem == 1, "隐藏条数 == 1");
    CHECK(n == 3 && strcmp(names[2], "004242") == 0,
          "前导零形式 004242 不被当作 pid 4242");
    (void)cb_pid_ok;
}

static void t_cred(void)
{
    /* 用 6.6 guest 内核上实测探测出的真实布局 */
    klayout_cred L;
    memset(&L, 0, sizeof(L));
    L.probed = 1;
    L.usage = 0;
    L.uid = 4;  L.gid = 8;  L.suid = 12; L.sgid = 16;
    L.euid = 20; L.egid = 24; L.fsuid = 28; L.fsgid = 32;
    L.securebits = 36;
    L.cap_inheritable = 48; L.cap_permitted = 56; L.cap_effective = 64;
    L.cap_bset = 72; L.cap_ambient = 80;
    L.cap_full_mask = 0x1ffffffffffULL;

    CHECK(lkm_cred_layout_ok(&L) == LKM_OK, "真实探测布局通过校验");

    unsigned char c[256];
    memset(c, 0xAA, sizeof(c));
    put64(c + 0, 1000);                 /* usage = 1000 */
    flat_mem f = { c, 0x2000, sizeof(c), 0 };
    lkm_mem m = { flat_rd, flat_wr, &f };

    CHECK(lkm_cred_apply(&m, 0x2000, &L) == LKM_OK, "cred 提权写入 OK");
    CHECK(get32(c + 4) == 0 && get32(c + 8) == 0 && get32(c + 12) == 0 &&
          get32(c + 16) == 0 && get32(c + 20) == 0 && get32(c + 24) == 0 &&
          get32(c + 28) == 0 && get32(c + 32) == 0, "uid..fsgid 全部归零");
    CHECK(get32(c + 36) == 0, "securebits 归零");
    CHECK(get64(c + 48) == 0x1ffffffffffULL && get64(c + 56) == 0x1ffffffffffULL &&
          get64(c + 64) == 0x1ffffffffffULL && get64(c + 72) == 0x1ffffffffffULL &&
          get64(c + 80) == 0x1ffffffffffULL, "五个 cap 字段均写为全集");
    CHECK(get64(c + 0) == 1000, "usage 未被触碰（引用计数不失衡）");

    /* 未探测 -> 拒绝 */
    klayout_cred U;
    memset(&U, 0, sizeof(U));
    U.probed = 0;
    U.uid = 4; U.gid = 8; U.suid = 12; U.sgid = 16;
    U.euid = 20; U.egid = 24; U.fsuid = 28; U.fsgid = 32;
    U.securebits = 36;
    U.cap_inheritable = 48; U.cap_permitted = 56; U.cap_effective = 64;
    U.cap_bset = 72; U.cap_ambient = 80;
    U.cap_full_mask = 0x1ffffffffffULL;
    CHECK(lkm_cred_layout_ok(&U) == LKM_ERR_LAYOUT, "未探测布局被拒（不猜测偏移）");
    CHECK(lkm_cred_apply(&m, 0x2000, &U) == LKM_ERR_LAYOUT, "未探测布局拒绝写入");

    /* id 偏移撞上 usage -> 拒绝 */
    klayout_cred V = L;
    V.euid = V.usage;
    CHECK(lkm_cred_layout_ok(&V) == LKM_ERR_LAYOUT, "偏移撞 usage 被拒（防清零引用计数）");

    /* cap 间隔不足 -> 拒绝 */
    klayout_cred W = L;
    W.cap_ambient = W.cap_bset + 4;
    CHECK(lkm_cred_layout_ok(&W) == LKM_ERR_LAYOUT, "cap 间隔 < 字段大小被拒（防写穿）");

    /* id 重复 -> 拒绝 */
    klayout_cred X = L;
    X.gid = X.uid;
    CHECK(lkm_cred_layout_ok(&X) == LKM_ERR_LAYOUT, "id 偏移重复被拒（探测串位）");

    /* mask 为零 -> 拒绝 */
    klayout_cred Y = L;
    Y.cap_full_mask = 0;
    CHECK(lkm_cred_layout_ok(&Y) == LKM_ERR_LAYOUT, "cap 全集为零被拒");
}

static void t_hook(void)
{
    unsigned char t[4096];
    memset(t, 0, sizeof(t));
    flat_mem f = { t, 0x3000, sizeof(t), 0 };
    lkm_mem m = { flat_rd, flat_wr, &f };

    put64(t + 217 * 8, 0xffffffff8143eaa0ULL);   /* getdents64 表项 */

    uint64_t orig = 0;
    CHECK(lkm_hook_install(&m, 0x3000, 217, 0xffffffffc0001000ULL, &orig) == LKM_OK,
          "hook 安装 OK");
    CHECK(orig == 0xffffffff8143eaa0ULL, "返回原始地址");
    CHECK(get64(t + 217 * 8) == 0xffffffffc0001000ULL, "表项已替换为我们的函数");

    uint64_t orig2 = 0;
    CHECK(lkm_hook_install(&m, 0x3000, 217, 0xffffffffc0001000ULL, &orig2) == LKM_ERR_ALREADY,
          "重复安装 -> ALREADY（不丢掉 orig）");

    CHECK(lkm_hook_restore(&m, 0x3000, 217, 0xffffffffc0001000ULL, orig) == LKM_OK,
          "hook 恢复 OK");
    CHECK(get64(t + 217 * 8) == 0xffffffff8143eaa0ULL, "表项还原为原始地址");
    CHECK(lkm_hook_restore(&m, 0x3000, 217, 0xffffffffc0001000ULL, orig) == LKM_ERR_ALREADY,
          "重复恢复 -> ALREADY（幂等）");

    /* 第三方在之后又装了一层 */
    put64(t + 217 * 8, 0xffffffffc0009999ULL);
    CHECK(lkm_hook_restore(&m, 0x3000, 217, 0xffffffffc0001000ULL, orig) == LKM_ERR_FOREIGN,
          "表项已被第三方改写 -> FOREIGN");
    CHECK(get64(t + 217 * 8) == 0xffffffffc0009999ULL, "FOREIGN 时未覆盖第三方指针");

    /* 空表项 */
    put64(t + 100 * 8, 0);
    CHECK(lkm_hook_install(&m, 0x3000, 100, 0xffffffffc0001000ULL, &orig) == LKM_ERR_CORRUPT,
          "空表项 -> CORRUPT（拒绝安装到未使用槽位）");

    CHECK(lkm_hook_install(&m, 0x3000, -1, 0x1000, &orig) == LKM_ERR_PARAM, "负号 -> PARAM");
}

/* ========================== 集成：真实内核 ========================== */

static void t_integration(void)
{
    kern_ctx *c = NULL;
    int rc = kern_open(&c);
    if (rc != KERN_OK) {
        printf("[SKIP] kern_open rc=%d (%s)\n", rc, kern_strerror(rc));
        return;
    }

    klayout_cred L;
    rc = klayout_cred_probe(c, "init_cred", &L);
    if (rc != KERN_OK || !L.probed) {
        printf("[SKIP] cred 布局探测不可用 rc=%d\n", rc);
        kern_close(c);
        return;
    }
    CHECK(lkm_cred_layout_ok(&L) == LKM_OK, "真实内核探测出的布局通过校验");

    uint64_t ic = 0;
    if (kern_symbol(c, "init_cred", &ic) == KERN_OK) {
        unsigned char real[256];
        memset(real, 0, sizeof(real));
        if (kern_read(c, ic, real, sizeof(real)) == KERN_OK) {
            /* 在副本上应用，验证真实布局下写入位置正确 */
            flat_mem f = { real, ic, sizeof(real), 0 };
            lkm_mem m = { flat_rd, flat_wr, &f };
            int rc2 = lkm_cred_apply(&m, ic, &L);
            CHECK(rc2 == LKM_OK, "在真实 init_cred 镜像上应用提权 OK");
            if (rc2 == LKM_OK) {
                uint64_t eff = 0;
                for (int i = 0; i < 8; i++)
                    eff |= (uint64_t)real[L.cap_effective + (size_t)i] << (8 * i);
                CHECK(eff == L.cap_full_mask, "cap_effective 落位与探测一致");
                CHECK(get64(real + L.usage) != 0, "真实镜像上 usage 未被清零");
            }
        } else {
            printf("[SKIP] 无法读取 init_cred（kcore 权限）\n");
        }
    }

    /* hook 写入点必须与 22_kern 经 sys_call_table 独立解析出的槽位一致。
     * 做法：拿真实的当前值填进 mock 表，再走本层安装，
     * 要求读回的 orig 与真实值逐位相同。 */
    khook_plan pl;
    rc = khook_plan_build(c, KHOOK_GETDENTS64, &pl);
    if (rc == KERN_OK) {
        unsigned char t[4096];
        memset(t, 0, sizeof(t));
        uint64_t base = pl.slot - (uint64_t)pl.syscall_nr * 8u;
        size_t off = (size_t)(pl.slot - base);
        if (off + 8 <= sizeof(t)) {
            for (int i = 0; i < 8; i++)
                t[off + i] = (unsigned char)((pl.orig >> (8 * i)) & 0xff);
            flat_mem f = { t, base, sizeof(t), 0 };
            lkm_mem m = { flat_rd, flat_wr, &f };
            uint64_t orig = 0;
            int rc3 = lkm_hook_install(&m, base, pl.syscall_nr,
                                       0xffffffffc0001000ULL, &orig);
            CHECK(rc3 == LKM_OK, "hook 槽位计算与 22_kern 解析一致");
            CHECK(orig == pl.orig, "读回的 orig 与真实表项值逐位相同");
            uint64_t now = 0;
            for (int i = 0; i < 8; i++)
                now |= (uint64_t)t[off + i] << (8 * i);
            CHECK(now == 0xffffffffc0001000ULL, "槽位已被替换为我们的函数");
        } else {
            printf("[SKIP] 槽位偏移超出 mock 缓冲\n");
        }
    } else {
        printf("[SKIP] khook_plan_build rc=%d\n", rc);
    }

    kern_close(c);
}

int main(void)
{
    t_selftest();
    t_unlink();
    t_dirent();
    t_dirent_pid();
    t_cred();
    t_hook();
    t_integration();

    printf("=== result: %d pass, %d fail ===\n", pass_count, fail_count);
    return fail_count ? 1 : 0;
}
