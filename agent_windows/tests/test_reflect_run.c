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

/* ---------------- 合成 PE 布局 ---------------- */

#define IMAGE_BASE   0x140000000ULL
#define SECT_ALIGN   0x1000u
#define FILE_ALIGN   0x200u
#define HDR_SIZE     0x400u

#define TEXT_RVA     0x1000u
#define TEXT_RAW     0x400u
#define RDATA_RVA    0x2000u
#define RDATA_RAW    0x1400u

#define SIZE_IMAGE   0x3000u
#define FILE_SIZE    0x2400u

/* .text 内部布局 */
#define STUB_ENTRY   0x1000u   /* 入口点桩 */
#define STUB_TLS     0x1100u   /* TLS 回调桩 */
#define SLOT_RVA     0x1200u   /* DIR64 重定位槽，初值 = IMAGE_BASE + MARK_RVA */
#define MARK_RVA     0x1300u   /* 标记数据 "MARK" */
#define RELOC_RVA    0x1400u   /* 重定位块 */

/* .rdata 内部布局 */
#define DLLNAME_RVA  0x2000u
#define IMPDESC_RVA  0x2010u
#define ILT_RVA      0x2040u
#define IAT_RVA      0x2050u
#define HINTNM_RVA   0x2060u
#define TLSDIR_RVA   0x2100u
#define TLSCB_RVA    0x2200u

#define TF(rva) ((rva) - TEXT_RVA + TEXT_RAW)
#define RF(rva) ((rva) - RDATA_RVA + RDATA_RAW)

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
#define REC_ENTRY_RVA  0x1500u   /* 入口点记录区 */
#define REC_TLS_RVA    0x1540u   /* TLS 回调记录区 */
#define REC_COUNT      0x00u
#define REC_BASE       0x08u
#define REC_REASON     0x10u
#define REC_PTR        0x18u
#define REC_SEQ        0x20u

static volatile uint64_t g_seq;

static uint64_t rec_get(uint8_t *region, uint32_t rec_rva, uint32_t field)
{
    uint64_t v;
    memcpy(&v, region + rec_rva + field, 8);
    return v;
}

/* ---------------- 桩代码生成 ---------------- */

/*
 * 桩（66 字节），入参按 Windows x64 约定为 rcx=base / rdx=reason：
 *   mov [rcx+rec+0x08], rcx            ; 记录 base
 *   mov [rcx+rec+0x10], rdx            ; 记录 reason
 *   mov rax, [rcx+SLOT_RVA]            ; 读取经重定位的指针
 *   mov [rcx+rec+0x18], rax            ; 记录该指针
 *   movabs rax, &g_seq
 *   inc qword [rax]
 *   mov rdx, [rax]
 *   mov [rcx+rec+0x20], rdx            ; 记录全局序号（用于判定执行顺序）
 *   inc qword [rcx+rec+0x00]           ; 记录执行次数
 *   mov rax, imm32(1)                  ; 返回值（DllMain TRUE）
 *   ret
 */
static void emit_stub(uint8_t *b, uint32_t file_off, uint32_t rec_rva, int ret_true)
{
    uint8_t *p = b + file_off;
    uint64_t seq_addr = (uint64_t)(uintptr_t)&g_seq;
    uint32_t d;

    memset(p, 0, 66);

    d = rec_rva + REC_BASE;
    p[0]=0x48; p[1]=0x89; p[2]=0x89; memcpy(p+3, &d, 4);          /* [rcx+d], rcx */
    d = rec_rva + REC_REASON;
    p[7]=0x48; p[8]=0x89; p[9]=0x91; memcpy(p+10, &d, 4);         /* [rcx+d], rdx */
    d = SLOT_RVA;
    p[14]=0x48; p[15]=0x8b; p[16]=0x81; memcpy(p+17, &d, 4);      /* rax, [rcx+d] */
    d = rec_rva + REC_PTR;
    p[21]=0x48; p[22]=0x89; p[23]=0x81; memcpy(p+24, &d, 4);      /* [rcx+d], rax */
    p[28]=0x48; p[29]=0xb8; memcpy(p+30, &seq_addr, 8);           /* movabs rax */
    p[38]=0x48; p[39]=0xff; p[40]=0x00;                           /* inc qword [rax] */
    p[41]=0x48; p[42]=0x8b; p[43]=0x10;                           /* mov rdx,[rax] */
    d = rec_rva + REC_SEQ;
    p[44]=0x48; p[45]=0x89; p[46]=0x91; memcpy(p+47, &d, 4);      /* [rcx+d], rdx */
    d = rec_rva + REC_COUNT;
    p[51]=0x48; p[52]=0xff; p[53]=0x81; memcpy(p+54, &d, 4);      /* inc qword */
    p[58]=0x48; p[59]=0xc7; p[60]=0xc0;
    p[61]= (uint8_t)(ret_true ? 1 : 0); p[62]=0; p[63]=0; p[64]=0; /* mov rax, imm32 */
    p[65]=0xc3;                                                   /* ret */
}

/* 入口点返回 FALSE 的桩：仅把返回值改为 0 */
static void emit_stub_false(uint8_t *b, uint32_t file_off)
{
    emit_stub(b, file_off, REC_ENTRY_RVA, 0);
}

/* ---------------- PE 构造 ---------------- */

static void wr16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void wr32(uint8_t *p, uint32_t v)
{ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }
static void wr64(uint8_t *p, uint64_t v)
{ uint32_t i; for (i=0;i<8;i++) p[i]=(uint8_t)(v >> (8*i)); }

static void build_pe(uint8_t *b, size_t cap, int with_entry, int with_tls)
{
    uint8_t *opt, *dd, *sh;

    if (cap < FILE_SIZE) return;
    memset(b, 0, cap);

    wr16(b + 0, 0x5A4D);
    wr32(b + 0x3C, 0x40);

    b[0x40]='P'; b[0x41]='E'; b[0x42]=0; b[0x43]=0;
    wr16(b + 0x44, 0x8664);          /* AMD64 */
    wr16(b + 0x46, 2);               /* NumberOfSections */
    wr16(b + 0x54, 240);             /* SizeOfOptionalHeader */
    wr16(b + 0x56, 0x2022);          /* EXECUTABLE_IMAGE|LARGE_ADDRESS_AWARE|DLL */

    opt = b + 0x58;
    wr16(opt + 0,  0x020B);          /* PE32+ */
    wr32(opt + 16, with_entry ? STUB_ENTRY : 0);   /* AddressOfEntryPoint */
    wr64(opt + 24, IMAGE_BASE);
    wr32(opt + 32, SECT_ALIGN);
    wr32(opt + 36, FILE_ALIGN);
    wr32(opt + 56, SIZE_IMAGE);
    wr32(opt + 60, HDR_SIZE);
    wr16(opt + 68, 3);               /* Subsystem = CUI */
    wr16(opt + 70, 0x8160);
    wr32(opt + 108, 16);             /* NumberOfRvaAndSizes */

    dd = opt + 112;
    wr32(dd + 1*8,     IMPDESC_RVA); wr32(dd + 1*8 + 4, 40);   /* Import */
    wr32(dd + 5*8,     RELOC_RVA);   wr32(dd + 5*8 + 4, 12);   /* BaseReloc */
    if (with_tls) {
        wr32(dd + 9*8, TLSDIR_RVA);  wr32(dd + 9*8 + 4, 40);   /* TLS */
    }

    sh = b + 0x148;
    memcpy(sh + 0, ".text\0\0\0", 8);
    wr32(sh + 8,  0x1000);           /* VirtualSize */
    wr32(sh + 12, TEXT_RVA);
    wr32(sh + 16, 0x1000);           /* SizeOfRawData */
    wr32(sh + 20, TEXT_RAW);
    wr32(sh + 36, 0x60000020);       /* CODE|EXECUTE|READ */

    memcpy(sh + 40, ".rdata\0\0", 8);
    wr32(sh + 48, 0x1000);
    wr32(sh + 52, RDATA_RVA);
    wr32(sh + 56, 0x1000);
    wr32(sh + 60, RDATA_RAW);
    wr32(sh + 76, 0x40000040);       /* INITIALIZED_DATA|READ */

    /* .text 内容 */
    emit_stub(b, TF(STUB_ENTRY), REC_ENTRY_RVA, 1);
    emit_stub(b, TF(STUB_TLS),   REC_TLS_RVA,   1);
    wr64(b + TF(SLOT_RVA), IMAGE_BASE + MARK_RVA);
    memcpy(b + TF(MARK_RVA), "MARK", 4);
    wr32(b + TF(RELOC_RVA), TEXT_RVA);                        /* PageRVA */
    wr32(b + TF(RELOC_RVA) + 4, 12);                          /* BlockSize */
    wr16(b + TF(RELOC_RVA) + 8, (uint16_t)((10u << 12) | 0x200u));  /* DIR64 @0x1200 */

    /* .rdata 内容 */
    memcpy(b + RF(DLLNAME_RVA), "TESTLIB.DLL", 12);
    wr32(b + RF(IMPDESC_RVA) + 0,  ILT_RVA);
    wr32(b + RF(IMPDESC_RVA) + 12, DLLNAME_RVA);
    wr32(b + RF(IMPDESC_RVA) + 16, IAT_RVA);
    wr64(b + RF(ILT_RVA), HINTNM_RVA);
    wr64(b + RF(IAT_RVA), HINTNM_RVA);
    wr16(b + RF(HINTNM_RVA), 0);
    memcpy(b + RF(HINTNM_RVA) + 2, "TestFunc", 9);

    if (with_tls) {
        wr64(b + RF(TLSDIR_RVA) + 24, IMAGE_BASE + TLSCB_RVA);
        wr64(b + RF(TLSCB_RVA), IMAGE_BASE + STUB_TLS);
    }
}

/* ---------------- 回调 ---------------- */

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

#define ECOUNT(reg) rec_get((reg), REC_ENTRY_RVA, REC_COUNT)
#define TCOUNT(reg) rec_get((reg), REC_TLS_RVA,   REC_COUNT)
#define EBASE(reg)  rec_get((reg), REC_ENTRY_RVA, REC_BASE)
#define TBASE(reg)  rec_get((reg), REC_TLS_RVA,   REC_BASE)
#define EREASON(rg) rec_get((rg),  REC_ENTRY_RVA, REC_REASON)
#define TREASON(rg) rec_get((rg),  REC_TLS_RVA,   REC_REASON)
#define EPTR(reg)   rec_get((reg), REC_ENTRY_RVA, REC_PTR)
#define ESEQ(reg)   rec_get((reg), REC_ENTRY_RVA, REC_SEQ)
#define TSEQ(reg)   rec_get((reg), REC_TLS_RVA,   REC_SEQ)

static void reset_recs(void)
{
    g_seq = 0;
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
    CHECK("完成设权的节区数 == 2", r.n_sections_prot == 2);
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

    /* 入口桩改为返回 0（DllMain FALSE） */
    memcpy(pe2, g_pe, FILE_SIZE);
    memset(pe2 + TF(STUB_ENTRY), 0, 33);
    emit_stub_false(pe2, TF(STUB_ENTRY));

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
    build_pe(pe2, sizeof(pe2), 0, 0);

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
    build_pe(g_pe, FILE_SIZE, 1, 1);

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
