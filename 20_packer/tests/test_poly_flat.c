/*
 * DAYANJING v4 — 20_packer / test_poly_flat.c
 *
 * 扁平化存根的真机验证。
 *
 * 为什么必须有这个文件：
 *   扁平化引擎单独测过（test_flatten 28/28），但它测的是"给进去的块"。
 *   块是 poly 生成的，块与块之间的值传递、栈位移修正、delta 回填任何一处
 *   出错，都不会让 fl_build 报错——它只会产出一份能跑但解错的存根。
 *
 * 本文件因此只信一件事：把制品 mmap 成可执行页并真的调用它，看载荷有没有
 * 被正确解密并跳过去执行。"地址摆对了"不算数，"跑出结果"才算数。
 *
 * 关键断言与其反证：
 *   - fired == 1              ：解密正确 + 控制流走通
 *   - 非易失寄存器保持        ：prologue/epilogue 的保存恢复配对
 *   - 载荷入口 rsp == 前-8    ：两处栈帧（poly 帧 + flatten 帧）都平衡
 *   - 扁平化后长度显著增加    ：证明扁平化代码真的被插入，不是空转
 *   - 跨 200 构建恒定游程 0   ：引入扁平化后仍无静态签名
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#include "poly.h"

static int g_pass, g_fail;
#define CHECK(c, msg) do { \
    if (c) { g_pass++; printf("[PASS] %s\n", msg); } \
    else   { g_fail++; printf("[FAIL] %s\n", msg); } \
} while (0)

/* ------------------------------------------------------------------ */
/* 哨兵与捕获                                                          */
/* ------------------------------------------------------------------ */

#define SN_3  0xA5A5A5A5A5A5A501ull
#define SN_6  0xA5A5A5A5A5A5A502ull
#define SN_7  0xA5A5A5A5A5A5A503ull
#define SN_12 0xA5A5A5A5A5A5A504ull
#define SN_13 0xA5A5A5A5A5A5A505ull
#define SN_14 0xA5A5A5A5A5A5A506ull
#define SN_15 0xA5A5A5A5A5A5A507ull

uint64_t g_cap[9] __attribute__((used));
void *g_fn __attribute__((used));
uint64_t g_sv[5] __attribute__((used));
uint64_t g_rsp_before __attribute__((used));

static void call_with_sentinels(void *fn)
{
    g_fn = fn;
    __asm__ __volatile__(
        "leaq g_sv(%%rip), %%rax\n\t"
        "movq %%rbx, 0(%%rax)\n\t"
        "movq %%r12, 8(%%rax)\n\t"
        "movq %%r13, 16(%%rax)\n\t"
        "movq %%r14, 24(%%rax)\n\t"
        "movq %%r15, 32(%%rax)\n\t"
        "movabsq $0xA5A5A5A5A5A5A501, %%rbx\n\t"
        "movabsq $0xA5A5A5A5A5A5A502, %%rsi\n\t"
        "movabsq $0xA5A5A5A5A5A5A503, %%rdi\n\t"
        "movabsq $0xA5A5A5A5A5A5A504, %%r12\n\t"
        "movabsq $0xA5A5A5A5A5A5A505, %%r13\n\t"
        "movabsq $0xA5A5A5A5A5A5A506, %%r14\n\t"
        "movabsq $0xA5A5A5A5A5A5A507, %%r15\n\t"
        "leaq g_rsp_before(%%rip), %%rax\n\t"
        "movq %%rsp, 0(%%rax)\n\t"
        "movq g_fn(%%rip), %%rax\n\t"
        "call *%%rax\n\t"
        "leaq g_sv(%%rip), %%rax\n\t"
        "movq 0(%%rax), %%rbx\n\t"
        "movq 8(%%rax), %%r12\n\t"
        "movq 16(%%rax), %%r13\n\t"
        "movq 24(%%rax), %%r14\n\t"
        "movq 32(%%rax), %%r15\n\t"
        :
        :
        : "memory", "cc", "rax", "rcx", "rdx",
          "rsi", "rdi", "r8", "r9", "r10", "r11"
    );
}

/* 载荷：把 7 个非易失寄存器 + rsp 写进 g_cap，置 fired=1，ret */
static size_t build_cap_payload(uint8_t *buf)
{
    uint64_t a = (uint64_t)(uintptr_t)&g_cap[0];
    size_t n = 0;

    buf[n++] = 0x48; buf[n++] = 0xB8;
    for (int k = 0; k < 8; k++) buf[n++] = (uint8_t)(a >> (8 * k));

    static const struct { uint8_t rex; uint8_t reg; int disp; } S[8] = {
        { 0x48, 3,  0 }, { 0x48, 6,  8 }, { 0x48, 7, 16 }, { 0x4C, 4, 24 },
        { 0x4C, 5, 32 }, { 0x4C, 6, 40 }, { 0x4C, 7, 48 }, { 0x48, 4, 56 },
    };
    for (int k = 0; k < 8; k++) {
        buf[n++] = S[k].rex;
        buf[n++] = 0x89u;
        buf[n++] = (uint8_t)(0x40u | ((S[k].reg & 7) << 3));
        buf[n++] = (uint8_t)S[k].disp;
    }
    buf[n++] = 0xC7u; buf[n++] = 0x40u; buf[n++] = 64;
    buf[n++] = 1; buf[n++] = 0; buf[n++] = 0; buf[n++] = 0;
    buf[n++] = 0xC3u;
    return n;
}

static void *exec_artifact(const uint8_t *art, size_t len)
{
    long ps = sysconf(_SC_PAGESIZE);
    size_t map = ((len + (size_t)ps - 1) / (size_t)ps) * (size_t)ps;
    void *m = mmap(NULL, map, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return NULL;
    memcpy(m, art, len);
    return m;
}

/* ------------------------------------------------------------------ */
/* 单次执行验证                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    int fired, nv, sp, rsp_ok;
} runres;

static runres run_one(uint64_t seed, int abi, int flat, size_t pay_len)
{
    runres R = { 0, 0, 0, 0 };
    uint8_t pay[4096];
    size_t plen = build_cap_payload(pay);
    if (pay_len > plen && pay_len <= sizeof(pay)) plen = pay_len;
    for (size_t k = plen; k < sizeof(pay) && k < pay_len; k++) pay[k] = 0x90;

    poly_ctx *p = poly_new_abi(seed, abi);
    if (!p) return R;
    poly_set_flatten(p, flat);

    uint8_t *art = NULL; size_t alen = 0;
    if (poly_build(p, pay, plen, &art, &alen) != POLY_OK) { poly_free(p); return R; }

    memset(g_cap, 0, sizeof g_cap);
    void *m = exec_artifact(art, alen);
    if (!m) { free(art); poly_free(p); return R; }
    call_with_sentinels(m);

    /*
     * SysV 下 rsi/rdi 是易失的：存根没有义务保持它们，调用方也不该期望。
     * 断言它们保持是一个假阳性断言——它会把正确行为判成失败（实测 300 种子
     * 里 150 个 SysV 种子全部"失败"，而线性存根同样如此）。
     * Win64 下 rsi/rdi 是非易失的，必须保持，故纳入检查。
     */
    int base_ok = (g_cap[0] == SN_3  && g_cap[3] == SN_12 && g_cap[4] == SN_13 &&
                   g_cap[5] == SN_14 && g_cap[6] == SN_15);
    int sidf_ok = (g_cap[1] == SN_6 && g_cap[2] == SN_7);

    R.fired  = (g_cap[8] == 1);
    R.nv     = (abi == POLY_ABI_WIN64) ? (base_ok && sidf_ok) : base_ok;
    R.rsp_ok = (g_cap[7] == g_rsp_before - 8);
    R.sp     = R.rsp_ok;

    munmap(m, ((alen + 4095) / 4096) * 4096);
    free(art);
    poly_free(p);
    return R;
}

/* ------------------------------------------------------------------ */
/* 用例                                                                */
/* ------------------------------------------------------------------ */

static void t_exec_sysv(void)
{
    runres R = run_one(0xC0FFEE01ULL, POLY_ABI_SYSV, 1, 0);
    CHECK(R.fired,  "扁平化存根真机执行：解密并跳到载荷");
    CHECK(R.nv,     "  非易失寄存器全部保持（保存/恢复配对）");
    CHECK(R.sp,     "  载荷入口 rsp == 调用前-8（两层栈帧都平衡）");
}

static void t_exec_win64(void)
{
    runres R = run_one(0xC0FFEE01ULL, POLY_ABI_WIN64, 1, 0);
    CHECK(R.fired,  "Win64 ABI 扁平化存根真机执行");
    CHECK(R.nv,     "  Win64 非易失寄存器保持（含 rsi/rdi）");
    CHECK(R.sp,     "  Win64 栈平衡");
}

static void t_many_seeds(void)
{
    int bad_fire = 0, bad_nv = 0, bad_sp = 0;
    for (int i = 0; i < 300; i++) {
        uint64_t seed = 0x5EED0000ULL + (uint64_t)i * 2654435761u;
        runres R = run_one(seed, (i & 1) ? POLY_ABI_WIN64 : POLY_ABI_SYSV, 1, 0);
        if (!R.fired) bad_fire++;
        if (!R.nv)    bad_nv++;
        if (!R.sp)    bad_sp++;
    }
    printf("[INFO] 300 种子扁平化：fired失败=%d 寄存器=%d 栈=%d\n",
           bad_fire, bad_nv, bad_sp);
    CHECK(bad_fire == 0, "300 个种子扁平化存根全部执行成功");
    CHECK(bad_nv   == 0, "300 个种子寄存器全部保持");
    CHECK(bad_sp   == 0, "300 个种子栈全部平衡");
}

static void t_long_payload(void)
{
    runres R = run_one(0xABCDEF01ULL, POLY_ABI_SYSV, 1, 2048);
    CHECK(R.fired,  "长载荷（2048B）扁平化存根执行成功");
    CHECK(R.sp,     "  长载荷栈平衡");
}

static void t_flatten_is_real(void)
{
    /*
     * 反证：若扁平化是空转（fl_build 没被调用 / 回退到线性布局），
     * 长度不会显著变化。故对比同批种子的两种存根长度。
     */
    double sum_flat = 0, sum_plain = 0;
    int n = 0;
    for (int i = 0; i < 50; i++) {
        uint64_t seed = 0x11AA0000ULL + (uint64_t)i * 7919u;
        uint8_t pay[512]; size_t plen = build_cap_payload(pay);

        poly_ctx *a = poly_new_abi(seed, POLY_ABI_SYSV);
        poly_set_flatten(a, 1);
        size_t sa = 0, ga = 0, ca = 0;
        uint8_t *arta = NULL; size_t alen = 0;
        if (poly_build(a, pay, plen, &arta, &alen) == POLY_OK) {
            poly_last_span(a, &sa, &ga, &ca);
            sum_flat += (double)sa; n++;
            free(arta);
        }
        poly_free(a);

        poly_ctx *b = poly_new_abi(seed, POLY_ABI_SYSV);
        size_t sb = 0, gb = 0, cb = 0;
        uint8_t *artb = NULL; size_t blen = 0;
        if (poly_build(b, pay, plen, &artb, &blen) == POLY_OK) {
            poly_last_span(b, &sb, &gb, &cb);
            sum_plain += (double)sb;
            free(artb);
        }
        poly_free(b);
    }
    double af = n ? sum_flat / n : 0, ap = n ? sum_plain / n : 0;
    printf("[INFO] 平均存根长度：扁平化 %.0f / 线性 %.0f\n", af, ap);
    CHECK(af > ap + 200.0, "扁平化使存根显著变长（证明引擎真的被调用，非回退）");
}

static void t_no_signature(void)
{
    /*
     * 逐偏移统计取值种类。只查"公共前缀"的那种测试看不见短签名，
     * 必须逐字节统计 distinct 值。
     */
    uint8_t *arts[200];
    size_t  lens[200];
    int built = 0;
    for (int i = 0; i < 200; i++) {
        uint64_t seed = 0xA5A50000ULL + (uint64_t)i * 40503u;
        poly_ctx *p = poly_new_abi(seed, (i & 1) ? POLY_ABI_WIN64 : POLY_ABI_SYSV);
        poly_set_flatten(p, 1);
        uint8_t pay[512]; size_t plen = build_cap_payload(pay);
        arts[i] = NULL; lens[i] = 0;
        if (poly_build(p, pay, plen, &arts[i], &lens[i]) == POLY_OK) built++;
        poly_free(p);
    }
    CHECK(built == 200, "200 份扁平化制品全部构建成功");

    size_t minlen = (size_t)-1;
    for (int i = 0; i < 200; i++) if (lens[i] < minlen) minlen = lens[i];
    size_t win = minlen > 288 ? 288 : minlen;

    int maxrun = 0, cur = 0;
    for (size_t off = 0; off < win; off++) {
        int seen[256]; memset(seen, 0, sizeof seen);
        int kinds = 0;
        for (int i = 0; i < 200; i++) {
            uint8_t v = arts[i][off];
            if (!seen[v]) { seen[v] = 1; kinds++; }
        }
        if (kinds == 1) { cur++; if (cur > maxrun) maxrun = cur; }
        else cur = 0;
    }
    printf("[INFO] 扁平化制品跨 200 构建最长恒定游程 = %d\n", maxrun);
    CHECK(maxrun == 0, "跨 200 构建无恒定字节（扁平化未引入静态签名）");

    int firstkinds = 0; int seenf[256]; memset(seenf, 0, sizeof seenf);
    for (int i = 0; i < 200; i++) {
        uint8_t v = arts[i][0];
        if (!seenf[v]) { seenf[v] = 1; firstkinds++; }
    }
    printf("[INFO] 首字节取值数 = %d\n", firstkinds);
    CHECK(firstkinds >= 3, "首字节取值数 >= 3（nop 垫与取 RIP 变体生效）");

    for (int i = 0; i < 200; i++) free(arts[i]);
}

static void t_plain_still_ok(void)
{
    /* 关闭开关时行为不变——防止本次改动把原路径改坏 */
    runres R = run_one(0xC0FFEE01ULL, POLY_ABI_SYSV, 0, 0);
    CHECK(R.fired && R.nv && R.sp, "关闭扁平化时线性存根仍然正确（未回归）");
    poly_ctx *p = poly_new(7);
    CHECK(poly_flatten(p) == 0, "默认关闭扁平化");
    poly_set_flatten(p, 1);
    CHECK(poly_flatten(p) == 1, "poly_set_flatten 生效");
    CHECK(poly_set_flatten(NULL, 1) == POLY_ERR_PARAM, "空指针 -> PARAM");
    poly_free(p);
}

int main(void)
{
    t_exec_sysv();
    t_exec_win64();
    t_many_seeds();
    t_long_payload();
    t_flatten_is_real();
    t_no_signature();
    t_plain_still_ok();
    printf("\n=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
