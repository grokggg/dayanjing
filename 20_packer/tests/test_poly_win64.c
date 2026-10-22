/*
 * DAYANJING v4 — 20_packer / tests/test_poly_win64.c
 *
 * Windows x64（MS x64 ABI）多态存根验证。
 *
 * 为什么能在本机（Linux x86-64）真跑验证 MS x64 存根：
 *   MS x64 与 SysV 使用同一套 x86-64 指令集，差别只在 ABI 约定——
 *   MS x64 的非易失寄存器集合额外包含 RSI 与 RDI。存根在本机执行时
 *   "多保存了两个寄存器"是无害的（保存易失寄存器不违反 SysV），
 *   因此同一份机器码既可以在 Windows 上正确运行，也可以在本机被真实执行。
 *
 * 核心验证项：
 *   - 真机执行：mmap RWX，载入哨兵后调用，验证存根解密并跳转
 *   - 非易失寄存器保持：RBX/RSI/RDI/R12-R15 全部原样返回（MS x64 要求）
 *   - 栈卫生：载荷入口 RSP 恰为调用前 RSP - 8（尾调用语义，帧完全恢复）
 *   - ABI 差异非空：SysV 模式确实会破坏 RSI/RDI，否则 Win64 模式无意义
 *   - 多态性：跨构建逐字节取证，不存在恒定偏移
 */

#include "poly.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "本测试需要 x86-64"
#endif

static int g_pass = 0, g_fail = 0;

static void chk(int cond, const char *name)
{
    if (cond) { printf("[PASS] %s\n", name); g_pass++; }
    else      { printf("[FAIL] %s\n", name); g_fail++; }
}

static void info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf("[INFO] ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}

/* ------------------------------------------------------------------ */
/* 哨兵                                                                */
/* ------------------------------------------------------------------ */

#define SN_BX  0xA5A5A5A5A5A5A501ull
#define SN_SI  0xA5A5A5A5A5A5A502ull
#define SN_DI  0xA5A5A5A5A5A5A503ull
#define SN_12  0xA5A5A5A5A5A5A504ull
#define SN_13  0xA5A5A5A5A5A5A505ull
#define SN_14  0xA5A5A5A5A5A5A506ull
#define SN_15  0xA5A5A5A5A5A5A507ull

/* 存根返回前把非易失寄存器与 RSP 存到这里。
   必须用绝对地址（movabs），因为载荷被搬到 mmap 区执行，RIP 相对寻址失效。 */
uint64_t g_cap[9] __attribute__((used));      /* rbx rsi rdi r12 r13 r14 r15 rsp fired */
void *g_fn __attribute__((used));
uint64_t g_sv[5] __attribute__((used));       /* 保存本函数自己的被调用者保存寄存器 */
uint64_t g_rsp_before __attribute__((used));

/*
 * 载入哨兵 -> 调用存根 -> 恢复。
 *
 * 不设输出操作数、不引用任何内存操作数：全部经由静态全局 + RIP 相对寻址
 * 访问，避免编译器为形成操作数地址而占用我们正在设置的寄存器。
 */
static void call_with_sentinels(void *fn)
{
    g_fn = fn;
    __asm__ __volatile__(
        /* 保存本函数自己的被调用者保存寄存器（SysV 下 rsi/rdi 无需保存） */
        "leaq g_sv(%%rip), %%rax\n\t"
        "movq %%rbx, 0(%%rax)\n\t"
        "movq %%r12, 8(%%rax)\n\t"
        "movq %%r13, 16(%%rax)\n\t"
        "movq %%r14, 24(%%rax)\n\t"
        "movq %%r15, 32(%%rax)\n\t"
        /* 载入哨兵 */
        "movabsq $0xA5A5A5A5A5A5A501, %%rbx\n\t"
        "movabsq $0xA5A5A5A5A5A5A502, %%rsi\n\t"
        "movabsq $0xA5A5A5A5A5A5A503, %%rdi\n\t"
        "movabsq $0xA5A5A5A5A5A5A504, %%r12\n\t"
        "movabsq $0xA5A5A5A5A5A5A505, %%r13\n\t"
        "movabsq $0xA5A5A5A5A5A5A506, %%r14\n\t"
        "movabsq $0xA5A5A5A5A5A5A507, %%r15\n\t"
        "leaq g_rsp_before(%%rip), %%rax\n\t"
        "movq %%rsp, 0(%%rax)\n\t"
        /* 调用存根（存根末尾 jmp 到载荷，载荷 ret 回到这里） */
        "movq g_fn(%%rip), %%rax\n\t"
        "call *%%rax\n\t"
        /* 恢复 */
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

/* ------------------------------------------------------------------ */
/* 载荷构造：movabs rax,cap; 存 8 个寄存器; fired=1; ret               */
/* ------------------------------------------------------------------ */

typedef struct { const uint8_t *b; size_t n; int disp; } store_t;

static size_t build_cap_payload(uint8_t *buf)
{
    uint64_t a = (uint64_t)(uintptr_t)&g_cap[0];
    size_t n = 0;

    buf[n++] = 0x48; buf[n++] = 0xB8;                 /* movabs rax, imm64 */
    for (int k = 0; k < 8; k++) buf[n++] = (uint8_t)(a >> (8 * k));

    /*
     * mov [rax + disp8], r64
     *   rbx(3) rsi(6) rdi(7) rsp(4) -> REX 0x48
     *   r12..r15                    -> REX 0x4C（reg 字段高位靠 REX.R）
     * 一律用 mod=01 + disp8，偏移为 0 时也成立，避免 mod=00 的特例分支。
     */
    static const struct { uint8_t rex; uint8_t reg; int disp; } S[8] = {
        { 0x48, 3,  0 },   /* rbx */
        { 0x48, 6,  8 },   /* rsi */
        { 0x48, 7, 16 },   /* rdi */
        { 0x4C, 4, 24 },   /* r12 */
        { 0x4C, 5, 32 },   /* r13 */
        { 0x4C, 6, 40 },   /* r14 */
        { 0x4C, 7, 48 },   /* r15 */
        { 0x48, 4, 56 },   /* rsp */
    };
    for (int k = 0; k < 8; k++) {
        buf[n++] = S[k].rex;
        buf[n++] = 0x89u;
        buf[n++] = (uint8_t)(0x40u | ((S[k].reg & 7) << 3));
        buf[n++] = (uint8_t)S[k].disp;
    }

    buf[n++] = 0xC7u; buf[n++] = 0x40u; buf[n++] = 64;  /* movl $1, 64(%rax) */
    buf[n++] = 1; buf[n++] = 0; buf[n++] = 0; buf[n++] = 0;
    buf[n++] = 0xC3u;                                    /* ret */
    return n;
}

/* ------------------------------------------------------------------ */
/* 真机执行                                                            */
/* ------------------------------------------------------------------ */

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

/*
 * 逐项返回结果，不合并成单一布尔——否则 SysV 模式下 "rsi/rdi 被破坏"
 * 会与真 bug 混在一起，无法分辨。
 *   r[0] fired  r[1] RBX/R12-R15 保持  r[2] RSI/RDI 保持  r[3] 栈恢复
 *   r[4] 独立解密一致
 */
static void run_one(int abi, uint64_t seed, int r[5])
{
    r[0] = r[1] = r[2] = r[3] = r[4] = 0;
    uint8_t pay[128];
    size_t pay_len = build_cap_payload(pay);

    poly_ctx *p = poly_new_abi(seed, abi);
    if (!p) return;

    uint8_t *art = NULL; size_t alen = 0;
    if (poly_build(p, pay, pay_len, &art, &alen) != POLY_OK) {
        poly_free(p); return;
    }

    /* 独立解密校验：密文段用参考 RC4 解出后必须等于原载荷 */
    size_t sl, gl, co;
    uint8_t key[POLY_KEY_LEN];
    poly_last_span(p, &sl, &gl, &co);
    poly_last_key(p, key);
    uint8_t *chk = (uint8_t *)malloc(alen - co);
    memcpy(chk, art + co, alen - co);
    poly_rc4(key, chk, alen - co);
    int dec_ok = (memcmp(chk, pay, pay_len) == 0);
    free(chk);

    void *m = exec_artifact(art, alen);
    if (!m) { free(art); poly_free(p); return; }

    memset(g_cap, 0, sizeof(g_cap));
    call_with_sentinels(m);
    munmap(m, ((alen + 4095) / 4096) * 4096);

    r[0] = (g_cap[8] == 1);
    r[1] = (g_cap[0] == SN_BX && g_cap[3] == SN_12 &&
            g_cap[4] == SN_13 && g_cap[5] == SN_14 && g_cap[6] == SN_15);
    r[2] = (g_cap[1] == SN_SI && g_cap[2] == SN_DI);
    r[3] = (g_cap[7] == g_rsp_before - 8);
    r[4] = dec_ok;

    free(art);
    poly_free(p);
}

/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== test_poly_win64 ===\n");

    /* 1. Win64 单发：真执行 + 非易失寄存器 + 栈卫生 + 独立解密 */
    {
        int r[5];
        run_one(POLY_ABI_WIN64, 0x1234ULL, r);
        chk(r[0], "Win64 存根真机执行：解密并跳转到载荷");
        chk(r[4], "  密文段用参考 RC4 独立解出 == 原载荷");
        chk(r[1] && r[2] && r[3], "Win64 存根寄存器与栈均正确");
        chk(g_cap[0] == SN_BX, "  RBX 保持");
        chk(g_cap[1] == SN_SI, "  RSI 保持（MS x64 非易失，SysV 下是易失）");
        chk(g_cap[2] == SN_DI, "  RDI 保持（MS x64 非易失，SysV 下是易失）");
        chk(g_cap[3] == SN_12 && g_cap[4] == SN_13 &&
            g_cap[5] == SN_14 && g_cap[6] == SN_15, "  R12-R15 保持");
        chk(g_cap[7] == g_rsp_before - 8, "  载荷入口 RSP == 调用前 RSP-8（尾调用）");
    }

    /* 2. 大批量 Win64：每一次都必须保持全部 7 个 */
    {
        uint64_t seeds[300];
        for (int k = 0; k < 300; k++) seeds[k] = 0x9E3779B1ull * (uint64_t)(k + 1);
        int bad_fire = 0, bad_nv = 0, bad_si = 0, bad_sp = 0, bad_dec = 0;
        for (int k = 0; k < 300; k++) {
            int r[5];
            run_one(POLY_ABI_WIN64, seeds[k], r);
            if (!r[0]) bad_fire++;
            if (!r[1]) bad_nv++;
            if (!r[2]) bad_si++;
            if (!r[3]) bad_sp++;
            if (!r[4]) bad_dec++;
        }
        chk(bad_fire == 0 && bad_nv == 0 && bad_si == 0 && bad_sp == 0 &&
            bad_dec == 0, "Win64 300 个种子：执行/寄存器/栈/解密全部正确");
        info("Win64 失败计数 fired=%d nv=%d si_di=%d sp=%d dec=%d（须全 0）",
             bad_fire, bad_nv, bad_si, bad_sp, bad_dec);
    }

    /* 3. 反证：SysV 模式确实会破坏 RSI/RDI —— 否则 Win64 模式毫无意义 */
    {
        uint64_t seeds[300];
        for (int k = 0; k < 300; k++) seeds[k] = 0x9E3779B1ull * (uint64_t)(k + 1);
        int cl = 0, bad_nv = 0, bad_sp = 0, bad_fire = 0;
        for (int k = 0; k < 300; k++) {
            int r[5];
            run_one(POLY_ABI_SYSV, seeds[k], r);
            if (!r[2]) cl++;          /* SysV 允许破坏 rsi/rdi */
            if (!r[1]) bad_nv++;
            if (!r[3]) bad_sp++;
            if (!r[0]) bad_fire++;
        }
        info("SysV 破坏 RSI/RDI 的种子数 = %d / 300", cl);
        chk(cl > 0, "ABI 差异非空：SysV 模式确实会破坏 RSI/RDI");
        chk(bad_nv == 0, "SysV 模式仍保持 RBX/R12-R15");
        chk(bad_sp == 0 && bad_fire == 0, "SysV 模式栈恢复且执行成功");
    }

    /* 4. 确定性 + 两 ABI 必然不同 */
    {
        poly_ctx *a = poly_new_abi(0xABCD, POLY_ABI_SYSV);
        poly_ctx *b = poly_new_abi(0xABCD, POLY_ABI_WIN64);
        poly_ctx *c = poly_new_abi(0xABCD, POLY_ABI_WIN64);
        uint8_t pay[64];
        size_t pl = build_cap_payload(pay);
        uint8_t *x = NULL, *y = NULL, *z = NULL;
        size_t xl = 0, yl = 0, zl = 0;
        poly_build(a, pay, pl, &x, &xl);
        poly_build(b, pay, pl, &y, &yl);
        poly_build(c, pay, pl, &z, &zl);
        /*
         * 只要求字节不同，不要求等长：Win64 比 SysV 多保存 0..2 个寄存器，
         * 存/取指令条数随之变化，长度本就不同（实测差 0..20 字节）。
         */
        size_t mn2 = xl < yl ? xl : yl;
        chk(memcmp(x, y, mn2) != 0, "同种子下两 ABI 产出不同字节");
        chk(yl == zl && memcmp(y, z, yl) == 0, "同 ABI 同种子逐字节可复现");
        info("同种子两 ABI 长度: SysV=%zu Win64=%zu（差 %zd）",
             xl, yl, (ptrdiff_t)yl - (ptrdiff_t)xl);
        chk(poly_abi(a) == POLY_ABI_SYSV && poly_abi(b) == POLY_ABI_WIN64,
            "poly_abi 正确回报模式");
        chk(poly_new_abi(1, 99) == NULL, "非法 ABI 返回 NULL");
        free(x); free(y); free(z);
        poly_free(a); poly_free(b); poly_free(c);
    }

    /* 5. 跨构建逐字节取证：Win64 不存在恒定偏移 */
    {
        uint8_t pay[64];
        size_t pl = build_cap_payload(pay);
        poly_ctx *p = poly_new_abi(0x5EED, POLY_ABI_WIN64);
        enum { N = 200 };
        uint8_t *arts[N]; size_t lens[N];
        size_t mn = (size_t)-1;
        for (int k = 0; k < N; k++) {
            poly_build(p, pay, pl, &arts[k], &lens[k]);
            if (lens[k] < mn) mn = lens[k];
        }
        size_t run = 0, worst = 0;
        for (size_t o = 0; o + pl < mn; o++) {
            uint8_t v0 = arts[0][o];
            int same = 1;
            for (int k = 1; k < N; k++) if (arts[k][o] != v0) { same = 0; break; }
            if (same) { run++; if (run > worst) worst = run; }
            else run = 0;
        }
        chk(worst == 0, "Win64 跨 200 构建无恒定字节（最长恒定游程=0）");
        info("Win64 最长恒定游程 = %zu，公共前缀长度 %zu", worst, mn);
        for (int k = 0; k < N; k++) free(arts[k]);
        poly_free(p);
    }

    printf("=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
