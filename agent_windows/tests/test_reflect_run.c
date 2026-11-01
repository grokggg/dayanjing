/*
 * agent_windows/tests/test_reflect_run.c
 *
 * 反射加载执行验证。验证方式是"真执行"，不是"地址摆对了"：
 *
 *   合成一个 PE32+，其入口点与 TLS 回调是**真实 x86-64 机器码**，
 *   按 Windows x64 约定取参（rcx/rdx），并跳转到一个 C 记录函数。
 *   测试进程把它 mmap 成可执行页后真实调用，断言记录到的参数。
 *
 *   最关键的一条：入口点代码会**解引用一个经过基址重定位的指针**
 *   （.text 内的 DIR64 槽位）。若重定位未生效，该槽位仍是 ImageBase
 *   基址，解引用会落到非法地址或读到错误内容 —— 因此"能读到正确数据"
 *   直接证明重定位在真实执行路径上生效，而不只是字节比对通过。
 *
 * Linux 上能真跑 x86-64 Windows 机器码，是因为该桩代码只做寄存器搬运
 * 与跳转，不含任何系统调用；它把 rcx/rdx 转成 SysV 的 rdi/rsi 后再跳转。
 *
 * 不覆盖：真实 Windows 上 VirtualProtect 的页粒度行为、真实 DllMain
 * 的加载器锁语义、真实 Media Foundation / Win32 依赖。
 */

#define _DEFAULT_SOURCE 1

#include "reflect_run.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "synth_pe.h"

/*
 * 旧名别名：本文件此前自带一份合成 PE 构造器。抽出共享文件后保留这些别名，
 * 使用例代码无需批量改名 —— 但布局常量只有一处定义，不会再次分叉。
 */
#define IMAGE_BASE   SYNTH_IMAGE_BASE
#define SECT_ALIGN   SYNTH_SECT_ALIGN
#define FILE_ALIGN   SYNTH_FILE_ALIGN
#define HDR_SIZE     SYNTH_HDR_SIZE
#define TEXT_RVA     SYNTH_TEXT_RVA
#define TEXT_RAW     SYNTH_TEXT_RAW
#define RDATA_RVA    SYNTH_RDATA_RVA
#define RDATA_RAW    SYNTH_RDATA_RAW
#define SIZE_IMAGE   SYNTH_SIZE_IMAGE
#define FILE_SIZE    SYNTH_FILE_SIZE
#define STUB_ENTRY   SYNTH_STUB_ENTRY
#define STUB_TLS     SYNTH_STUB_TLS
#define SLOT_RVA     SYNTH_SLOT_RVA
#define MARK_RVA     SYNTH_MARK_RVA
#define RELOC_RVA    SYNTH_RELOC_RVA
#define DLLNAME_RVA  SYNTH_DLLNAME_RVA
#define IMPDESC_RVA  SYNTH_IMPDESC_RVA
#define ILT_RVA      SYNTH_ILT_RVA
#define IAT_RVA      SYNTH_IAT_RVA
#define HINTNM_RVA   SYNTH_HINTNM_RVA
#define TLSDIR_RVA   SYNTH_TLSDIR_RVA
#define TLSCB_RVA    SYNTH_TLSCB_RVA
#define REC_ENTRY_RVA SYNTH_REC_ENTRY_RVA
#define REC_TLS_RVA   SYNTH_REC_TLS_RVA
#define REC_COUNT     SYNTH_REC_COUNT
#define REC_BASE      SYNTH_REC_BASE
#define REC_REASON    SYNTH_REC_REASON
#define REC_PTR       SYNTH_REC_PTR
#define REC_SEQ       SYNTH_REC_SEQ
#define TF(rva) ((rva) - SYNTH_TEXT_RVA + SYNTH_TEXT_RAW)
#define RF(rva) ((rva) - SYNTH_RDATA_RVA + SYNTH_RDATA_RAW)

/* 局部字节写辅助（仅用例内部改字节用；PE 构造本身在 synth_pe.c） */
static void wr16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void wr32(uint8_t *p, uint32_t v)
{ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }

static int g_pass, g_fail;

#define CHECK(name, cond)                                              \
    do {                                                               \
        if (cond) { g_pass++; printf("[PASS] %s\n", (name)); }         \
        else      { g_fail++; printf("[FAIL] %s\n", (name)); }         \
    } while (0)

/* ---------------- 记录区（PE 映像内，由桩代码直接写入） ---------------- */

/*
 * 桩代码刻意不调用任何 C 函数、不触碰 rsp：
 *   此前用 `movabs rax, <C 函数>; jmp rax` 的尾调用写法，桩里为了对齐做了
 *   and rsp,-16，结果把 call 压入的返回地址移走了 —— callee 的 ret 弹到垃圾
 *   地址，进程 SIGSEGV。改为纯内存写入后，栈与对齐都不再是变量。
 */

typedef struct { uint64_t off; size_t len; int prot; } prot_rec_t;

static uint8_t   *g_region;
static prot_rec_t g_prot[16];
static int        g_nprot;
static int        g_prot_calls;
static int        g_prot_fail_at = -1000;
static int        g_resolve_calls;

static int t_protect(void *ud, uint8_t *addr, size_t len, int prot)
{
    (void)ud;
    int idx = g_prot_calls++;
    if (idx == g_prot_fail_at) return -1;
    if (g_nprot < 16 && g_region) {
        g_prot[g_nprot].off  = (uint64_t)(size_t)(addr - g_region);
        g_prot[g_nprot].len  = len;
        g_prot[g_nprot].prot = prot;
        g_nprot++;
    }
    return 0;
}

static int t_resolve(const char *dll, const char *func, uint16_t ord,
                     int by_ord, void *ud, uint64_t *out)
{
    (void)ud;
    g_resolve_calls++;
    if (by_ord) { *out = 0x1000u + ord; return LD_OK; }
    {
        const char *p;
        uint64_t h = 0xcbf29ce484222325ULL;
        for (p = dll; *p; p++) { h ^= (uint64_t)(unsigned char)*p; h *= 0x100000001b3ULL; }
        h ^= (uint64_t)':'; h *= 0x100000001b3ULL;
        for (p = func; *p; p++) { h ^= (uint64_t)(unsigned char)*p; h *= 0x100000001b3ULL; }
        *out = 0x700000000000ULL + (h & 0xFFFFFFULL);
    }
    return LD_OK;
}

/* 以 Windows x64 约定调用：rcx/rdx/r8 置参后 call */
static int t_call(void *ud, uint64_t va, uint64_t a1, uint64_t a2, uint64_t a3,
                  uint64_t *ret)
{
    (void)ud;
    register uint64_t rc __asm__("rcx") = a1;
    register uint64_t rd __asm__("rdx") = a2;
    register uint64_t r8 __asm__("r8")  = a3;
    uint64_t v = va;
    uint64_t r = 0;

    /*
     * 刻意不在这里调整 rsp：%[v] 是内存操作数，GCC 常把它放在 rsp 相对槽位，
     * 若在 call 前先 sub rsp，该引用的地址就失效了（会跳到垃圾地址）。
     * 栈对齐由桩代码自身的 `and rsp,-16; sub rsp,8` 负责。
     */
    __asm__ __volatile__(
        "call *%[v]\n\t"
        : "=a"(r), "+r"(rc), "+r"(rd), "+r"(r8)
        : [v] "m"(v)
        : "memory", "cc"
    );
    if (ret) *ret = r;
    return 0;
}

#define ECOUNT(reg) synth_pe_rec((reg), REC_ENTRY_RVA, REC_COUNT)
#define TCOUNT(reg) synth_pe_rec((reg), REC_TLS_RVA,   REC_COUNT)
#define EBASE(reg)  synth_pe_rec((reg), REC_ENTRY_RVA, REC_BASE)
#define TBASE(reg)  synth_pe_rec((reg), REC_TLS_RVA,   REC_BASE)
#define EREASON(rg) synth_pe_rec((rg),  REC_ENTRY_RVA, REC_REASON)
#define TREASON(rg) synth_pe_rec((rg),  REC_TLS_RVA,   REC_REASON)
#define EPTR(reg)   synth_pe_rec((reg), REC_ENTRY_RVA, REC_PTR)
#define ESEQ(reg)   synth_pe_rec((reg), REC_ENTRY_RVA, REC_SEQ)
#define TSEQ(reg)   synth_pe_rec((reg), REC_TLS_RVA,   REC_SEQ)

static void reset_recs(void)
{
    synth_pe_seq_reset();
    g_nprot = 0; g_prot_calls = 0; g_prot_fail_at = -1000;
    g_resolve_calls = 0;
}

/* ---------------- 用例 ---------------- */

static uint8_t *g_pe;

static void t_prot_derive(void)
{
    int p = -1;
    CHECK("CODE|EXECUTE|READ -> R|X（无 W）",
          rr_protect_for(0x60000020u, &p) == RR_OK && p == (RR_P_R | RR_P_X));
    p = -1;
    CHECK("DATA|READ|WRITE -> R|W（无 X）",
          rr_protect_for(0xC0000040u, &p) == RR_OK && p == (RR_P_R | RR_P_W));
    p = -1;
    CHECK("INITIALIZED_DATA|READ -> 只读",
          rr_protect_for(0x40000040u, &p) == RR_OK && p == RR_P_R);
    p = -1;
    CHECK("无内存属性位 -> 只读（不产生 NONE 页）",
          rr_protect_for(0x00000000u, &p) == RR_OK && p == RR_P_R);
    p = -1;
    CHECK("EXECUTE|WRITE -> 拒绝（不给 RWX）",
          rr_protect_for(0xE0000020u, &p) == RR_ERR_WX && p == RR_P_NONE);
    CHECK("NULL 输出 -> PARAM", rr_protect_for(0x60000020u, NULL) == RR_ERR_PARAM);
}

static void t_run_ok(void)
{
    rr_hooks_t  h;
    rr_result_t r;
    size_t      rsz = SIZE_IMAGE;
    int         rc;
    uint8_t    *region;

    region = (uint8_t *)mmap(NULL, rsz, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { printf("[FAIL] mmap\n"); g_fail++; return; }
    g_region = region;
    reset_recs();

    memset(&h, 0, sizeof(h));
    h.protect = t_protect;
    h.call    = t_call;
    h.resolve = t_resolve;

    rc = rr_load_run(g_pe, FILE_SIZE, region, rsz, &h, &r);

    CHECK("反射加载并执行返回 OK", rc == RR_OK);
    if (rc != RR_OK) printf("[INFO] rc=%d (%s)\n", rc, rr_errstr(rc));
    CHECK("重定位项数 == 1", r.n_reloc == 1);
    CHECK("IAT 绑定项数 == 1", r.n_import == 1 && g_resolve_calls == 1);
    CHECK("TLS 回调数 == 1", r.n_tls == 1);
    CHECK("入口点确已被调用", r.entry_invoked == 1);
    CHECK("识别为 DLL", r.is_dll == 1);

    CHECK("TLS 回调真执行了一次", TCOUNT(region) == 1);
    CHECK("TLS 参数 base==region", TBASE(region) == (uint64_t)(uintptr_t)region);
    CHECK("TLS 参数 reason==DLL_PROCESS_ATTACH", TREASON(region) == 1);
    CHECK("入口点真执行了一次", ECOUNT(region) == 1);
    CHECK("入口参数 base==region", EBASE(region) == (uint64_t)(uintptr_t)region);
    CHECK("入口参数 reason==DLL_PROCESS_ATTACH", EREASON(region) == 1);

    CHECK("基址重定位在真实执行路径上生效（读到 region+0x1300，不是 ImageBase 基址）",
          EPTR(region) == (uint64_t)(uintptr_t)(region + MARK_RVA));
    CHECK("经重定位的指针可解引用到真实数据 'MARK'",
          EPTR(region) != 0 && memcmp((const void *)(uintptr_t)EPTR(region), "MARK", 4) == 0);
    CHECK("delta != 0（确实不在 ImageBase 上加载）", r.delta != 0);
    CHECK("TLS 先于入口点执行", TSEQ(region) != 0 && ESEQ(region) != 0 && TSEQ(region) < ESEQ(region));

    /* 权限 */
    CHECK("完成设权的节区数 == 3（含 .data）", r.n_sections_prot == 3);
    CHECK("头部区按只读设权",
          g_nprot >= 1 && g_prot[0].off == 0 && g_prot[0].len == HDR_SIZE
          && g_prot[0].prot == RR_P_R);
    CHECK(".text 为 R|X 且不含 W",
          g_nprot >= 2 && g_prot[1].off == TEXT_RVA
          && g_prot[1].prot == (RR_P_R | RR_P_X));
    CHECK(".rdata 为只读且不含 X/W",
          g_nprot >= 3 && g_prot[2].off == RDATA_RVA && g_prot[2].prot == RR_P_R);
    CHECK("无任何节区被授予 W|X 同存",
          !(g_prot[1].prot == (RR_P_R | RR_P_W | RR_P_X)));

    munmap(region, rsz);
    g_region = NULL;
}

static void t_missing_hooks(void)
{
    rr_hooks_t  h;
    rr_result_t r;
    size_t      rsz = SIZE_IMAGE;
    uint8_t    *region;

    region = (uint8_t *)mmap(NULL, rsz, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { printf("[FAIL] mmap\n"); g_fail++; return; }
    g_region = region;

    reset_recs();
    memset(&h, 0, sizeof(h));
    h.call = t_call; h.resolve = t_resolve;          /* 缺 protect */
    CHECK("缺 protect -> NOHOOK（不回落 RWX）",
          rr_load_run(g_pe, FILE_SIZE, region, rsz, &h, &r) == RR_ERR_NOHOOK);
    CHECK("缺 protect 时入口未被调用", ECOUNT(region) == 0 && TCOUNT(region) == 0);

    reset_recs();
    memset(&h, 0, sizeof(h));
    h.protect = t_protect; h.resolve = t_resolve;    /* 缺 call */
    CHECK("缺 call -> NOHOOK",
          rr_load_run(g_pe, FILE_SIZE, region, rsz, &h, &r) == RR_ERR_NOHOOK);

    reset_recs();
    memset(&h, 0, sizeof(h));
    h.protect = t_protect; h.call = t_call;          /* 缺 resolve */
    CHECK("缺 resolve -> NOHOOK",
          rr_load_run(g_pe, FILE_SIZE, region, rsz, &h, &r) == RR_ERR_NOHOOK);
    CHECK("缺 resolve 时入口未被调用", ECOUNT(region) == 0);

    munmap(region, rsz);
    g_region = NULL;
}

static void t_prot_fail(void)
{
    rr_hooks_t  h;
    rr_result_t r;
    size_t      rsz = SIZE_IMAGE;
    int         rc;
    uint8_t    *region;

    region = (uint8_t *)mmap(NULL, rsz, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { printf("[FAIL] mmap\n"); g_fail++; return; }
    g_region = region;

    memset(&h, 0, sizeof(h));
    h.protect = t_protect; h.call = t_call; h.resolve = t_resolve;

    /* 第 0 次（头部区）即失败 -> 不得有任何执行 */
    reset_recs();
    g_prot_fail_at = 0;
    rc = rr_load_run(g_pe, FILE_SIZE, region, rsz, &h, &r);
    CHECK("头部区设权失败 -> PROT", rc == RR_ERR_PROT);
    CHECK("头部区设权失败时不执行任何代码", ECOUNT(region) == 0 && TCOUNT(region) == 0);
    CHECK("prot_fail_at 标记为 -2（头部区）", r.prot_fail_at == -2);

    /* 第 1 次（.text）失败 -> 同样不得执行 */
    reset_recs();
    g_prot_fail_at = 1;
    rc = rr_load_run(g_pe, FILE_SIZE, region, rsz, &h, &r);
    CHECK(".text 设权失败 -> PROT", rc == RR_ERR_PROT);
    CHECK(".text 设权失败时不执行任何代码（无部分执行）",
          ECOUNT(region) == 0 && TCOUNT(region) == 0);
    CHECK("prot_fail_at 标记为 0（第一个节区）", r.prot_fail_at == 0);

    munmap(region, rsz);
    g_region = NULL;
}

static void t_wx_section(void)
{
    uint8_t     pe2[FILE_SIZE];
    rr_hooks_t  h;
    rr_result_t r;
    size_t      rsz = SIZE_IMAGE;
    uint8_t    *region;

    memcpy(pe2, g_pe, FILE_SIZE);
    wr32(pe2 + 0x148 + 36, 0xE0000020u);   /* .text 改为 WRITE|EXECUTE */

    region = (uint8_t *)mmap(NULL, rsz, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { printf("[FAIL] mmap\n"); g_fail++; return; }
    g_region = region;

    memset(&h, 0, sizeof(h));
    h.protect = t_protect; h.call = t_call; h.resolve = t_resolve;

    reset_recs();
    CHECK("可写且可执行的节区 -> WX（拒绝加载）",
          rr_load_run(pe2, FILE_SIZE, region, rsz, &h, &r) == RR_ERR_WX);
    CHECK("W+X 时绝不执行任何代码", ECOUNT(region) == 0 && TCOUNT(region) == 0);

    munmap(region, rsz);
    g_region = NULL;
}

static void t_bad_input(void)
{
    uint8_t     pe2[FILE_SIZE];
    rr_hooks_t  h;
    rr_result_t r;
    size_t      rsz = SIZE_IMAGE;
    uint8_t    *region;

    region = (uint8_t *)mmap(NULL, rsz, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { printf("[FAIL] mmap\n"); g_fail++; return; }
    g_region = region;

    memset(&h, 0, sizeof(h));
    h.protect = t_protect; h.call = t_call; h.resolve = t_resolve;

    /* 坏 DOS magic */
    memcpy(pe2, g_pe, FILE_SIZE);
    wr16(pe2 + 0, 0x4D5A ^ 0xFFFF);
    reset_recs();
    CHECK("坏 DOS magic -> FORMAT（透传 17_loader）",
          rr_load_run(pe2, FILE_SIZE, region, rsz, &h, &r) == LD_ERR_FORMAT);

    /* region 太小 */
    reset_recs();
    CHECK("region 不足 -> NOSPACE",
          rr_load_run(g_pe, FILE_SIZE, region, 0x800u, &h, &r) == LD_ERR_NOSPACE);

    /* 空参数 */
    CHECK("NULL PE -> PARAM", rr_load_run(NULL, 0, region, rsz, &h, &r) == RR_ERR_PARAM);
    CHECK("NULL region -> PARAM", rr_load_run(g_pe, FILE_SIZE, NULL, rsz, &h, &r) == RR_ERR_PARAM);
    CHECK("NULL hooks -> PARAM", rr_load_run(g_pe, FILE_SIZE, region, rsz, NULL, &r) == RR_ERR_PARAM);

    munmap(region, rsz);
    g_region = NULL;
}

static void t_entry_false(void)
{
    uint8_t     pe2[FILE_SIZE];
    rr_hooks_t  h;
    rr_result_t r;
    size_t      rsz = SIZE_IMAGE;
    uint8_t    *region;

    /*
     * 入口桩改为返回 0（DllMain FALSE）。
     * 只改写 imm32 的最低位字节 —— 原实现是整段重建桩（emit_stub_false），
     * 若在这里先 memset 清零再改字节，桩体会变成一串 0x00，执行即崩溃，
     * 而崩溃点距用例意图极远。
     */
    memcpy(pe2, g_pe, FILE_SIZE);
    synth_pe_set_entry_ret(pe2, 0);

    region = (uint8_t *)mmap(NULL, rsz, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { printf("[FAIL] mmap\n"); g_fail++; return; }
    g_region = region;

    memset(&h, 0, sizeof(h));
    h.protect = t_protect; h.call = t_call; h.resolve = t_resolve;

    reset_recs();
    CHECK("DllMain 返回 FALSE -> ENTRY",
          rr_load_run(pe2, FILE_SIZE, region, rsz, &h, &r) == RR_ERR_ENTRY);
    CHECK("FALSE 分支确实执行了入口", ECOUNT(region) == 1);

    munmap(region, rsz);
    g_region = NULL;
}

static void t_noentry(void)
{
    uint8_t     pe2[FILE_SIZE];
    rr_hooks_t  h;
    rr_result_t r;
    size_t      rsz = SIZE_IMAGE;
    uint8_t    *region;

    /* 无入口点（AddressOfEntryPoint=0）且无 TLS 目录 */
    synth_pe_build(pe2, sizeof(pe2), 0, 0);

    region = (uint8_t *)mmap(NULL, rsz, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { printf("[FAIL] mmap\n"); g_fail++; return; }
    g_region = region;

    memset(&h, 0, sizeof(h));
    h.protect = t_protect; h.call = t_call; h.resolve = t_resolve;

    reset_recs();
    CHECK("无入口且无 TLS -> NOENTRY（不允许静默空跑）",
          rr_load_run(pe2, FILE_SIZE, region, rsz, &h, &r) == RR_ERR_NOENTRY);

    munmap(region, rsz);
    g_region = NULL;
}

int main(void)
{
    g_pe = (uint8_t *)malloc(FILE_SIZE);
    if (!g_pe) { printf("[FAIL] malloc\n"); return 1; }
    synth_pe_build(g_pe, FILE_SIZE, 1, 1);

    t_prot_derive();
    t_run_ok();
    t_missing_hooks();
    t_prot_fail();
    t_wx_section();
    t_bad_input();
    t_entry_false();
    t_noentry();

    printf("\n=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    free(g_pe);
    return g_fail ? 1 : 0;
}
