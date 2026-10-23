/* tests/synth_pe.c — 合成 PE32+ 构造器实现（见 synth_pe.h 说明） */

#include "synth_pe.h"

#include <string.h>

/* 桩代码把本变量的地址硬编码进机器码，故必须是全局且非 static 不可优化掉 */
volatile uint64_t g_synth_seq;

void synth_pe_seq_reset(void) { g_synth_seq = 0; }
uint64_t synth_pe_seq(void)   { return g_synth_seq; }

uint64_t synth_pe_rec(const uint8_t *region, uint32_t rec_rva, uint32_t field)
{
    uint64_t v;
    memcpy(&v, region + rec_rva + field, 8);
    return v;
}

/* ---------------- 桩代码生成 ---------------- */

#define TF(rva) ((rva) - SYNTH_TEXT_RVA + SYNTH_TEXT_RAW)
#define RF(rva) ((rva) - SYNTH_RDATA_RVA + SYNTH_RDATA_RAW)
#define DF(rva) ((rva) - SYNTH_DATA_RVA + SYNTH_DATA_RAW)

/*
 * 桩（66 字节），入参按 Windows x64 约定为 rcx=base / rdx=reason：
 *   mov [rcx+rec+0x08], rcx            ; 记录 base
 *   mov [rcx+rec+0x10], rdx            ; 记录 reason
 *   mov rax, [rcx+SLOT_RVA]            ; 读取经重定位的指针
 *   mov [rcx+rec+0x18], rax            ; 记录该指针
 *   movabs rax, &g_synth_seq
 *   inc qword [rax]
 *   mov rdx, [rax]
 *   mov [rcx+rec+0x20], rdx            ; 记录全局序号（判定执行顺序）
 *   inc qword [rcx+rec+0x00]           ; 记录执行次数
 *   mov rax, imm32(1)                  ; 返回值（DllMain TRUE）
 *   ret
 *
 * 刻意不调用任何 C 函数、不触碰 rsp：此前用尾调用 + and rsp,-16 对齐的写法
 * 会把 call 压入的返回地址移走，callee 的 ret 弹到垃圾地址 -> SIGSEGV。
 */
static void emit_stub(uint8_t *b, uint32_t file_off, uint32_t rec_rva,
                      int ret_true)
{
    uint8_t *p = b + file_off;
    uint64_t seq_addr = (uint64_t)(uintptr_t)&g_synth_seq;
    uint32_t d;

    memset(p, 0, 66);

    d = rec_rva + SYNTH_REC_BASE;
    p[0]=0x48; p[1]=0x89; p[2]=0x89; memcpy(p+3, &d, 4);
    d = rec_rva + SYNTH_REC_REASON;
    p[7]=0x48; p[8]=0x89; p[9]=0x91; memcpy(p+10, &d, 4);
    d = SYNTH_SLOT_RVA;
    p[14]=0x48; p[15]=0x8b; p[16]=0x81; memcpy(p+17, &d, 4);
    d = rec_rva + SYNTH_REC_PTR;
    p[21]=0x48; p[22]=0x89; p[23]=0x81; memcpy(p+24, &d, 4);
    p[28]=0x48; p[29]=0xb8; memcpy(p+30, &seq_addr, 8);
    p[38]=0x48; p[39]=0xff; p[40]=0x00;
    p[41]=0x48; p[42]=0x8b; p[43]=0x10;
    d = rec_rva + SYNTH_REC_SEQ;
    p[44]=0x48; p[45]=0x89; p[46]=0x91; memcpy(p+47, &d, 4);
    d = rec_rva + SYNTH_REC_COUNT;
    p[51]=0x48; p[52]=0xff; p[53]=0x81; memcpy(p+54, &d, 4);
    p[58]=0x48; p[59]=0xc7; p[60]=0xc0;
    p[61]=(uint8_t)(ret_true ? 1 : 0); p[62]=0; p[63]=0; p[64]=0;
    p[65]=0xc3;
}

void synth_pe_set_entry_ret(uint8_t *b, int ret_true)
{
    if (!b) return;
    /* 桩内 `mov rax, imm32` 位于 +58..+64，立即数最低字节在 +61 */
    b[TF(SYNTH_STUB_ENTRY) + 61] = (uint8_t)(ret_true ? 1 : 0);
}

/* ---------------- 小工具 ---------------- */

static void wr16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void wr32(uint8_t *p, uint32_t v)
{ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }
static void wr64(uint8_t *p, uint64_t v)
{ uint32_t i; for (i=0;i<8;i++) p[i]=(uint8_t)(v >> (8*i)); }

void synth_pe_build(uint8_t *b, size_t cap, int with_entry, int with_tls)
{
    uint8_t *opt, *dd, *sh;

    if (!b || cap < SYNTH_FILE_SIZE) return;
    memset(b, 0, cap);

    wr16(b + 0, 0x5A4D);                 /* "MZ" */
    wr32(b + 0x3C, 0x40);                /* e_lfanew */

    b[0x40]='P'; b[0x41]='E'; b[0x42]=0; b[0x43]=0;
    wr16(b + 0x44, 0x8664);              /* Machine = AMD64 */
    wr16(b + 0x46, 3);                   /* NumberOfSections */
    wr16(b + 0x54, 240);                 /* SizeOfOptionalHeader @ +0x54 */
    wr16(b + 0x56, 0x2022);              /* Characteristics: EXECUTABLE|
                                            LARGE_ADDRESS_AWARE|DLL */

    opt = b + 0x58;
    wr16(opt + 0,  0x020B);              /* PE32+ */
    wr32(opt + 16, with_entry ? SYNTH_STUB_ENTRY : 0);
    wr64(opt + 24, SYNTH_IMAGE_BASE);
    wr32(opt + 32, SYNTH_SECT_ALIGN);
    wr32(opt + 36, SYNTH_FILE_ALIGN);
    wr32(opt + 56, SYNTH_SIZE_IMAGE);
    wr32(opt + 60, SYNTH_HDR_SIZE);
    wr16(opt + 68, 3);                   /* Subsystem = CUI */
    wr16(opt + 70, 0x8160);
    wr32(opt + 108, 16);                 /* NumberOfRvaAndSizes */

    dd = opt + 112;
    wr32(dd + 1*8,     SYNTH_IMPDESC_RVA); wr32(dd + 1*8 + 4, 40);   /* Import */
    wr32(dd + 5*8,     SYNTH_RELOC_RVA);   wr32(dd + 5*8 + 4, 12);   /* BaseReloc */
    if (with_tls) {
        wr32(dd + 9*8, SYNTH_TLSDIR_RVA); wr32(dd + 9*8 + 4, 40);    /* TLS */
    }

    sh = b + 0x148;
    memcpy(sh + 0, ".text\0\0\0", 8);
    wr32(sh + 8,  0x1000);               /* VirtualSize */
    wr32(sh + 12, SYNTH_TEXT_RVA);
    wr32(sh + 16, 0x1000);               /* SizeOfRawData */
    wr32(sh + 20, SYNTH_TEXT_RAW);
    wr32(sh + 36, 0x60000020);           /* CODE|EXECUTE|READ */

    memcpy(sh + 40, ".rdata\0\0", 8);
    wr32(sh + 48, 0x1000);
    wr32(sh + 52, SYNTH_RDATA_RVA);
    wr32(sh + 56, 0x1000);
    wr32(sh + 60, SYNTH_RDATA_RAW);
    wr32(sh + 76, 0x40000040);           /* INITIALIZED_DATA|READ */

    memcpy(sh + 80, ".data\0\0\0", 8);
    wr32(sh + 88,  0x1000);              /* VirtualSize */
    wr32(sh + 92,  SYNTH_DATA_RVA);
    wr32(sh + 96,  0x1000);              /* SizeOfRawData */
    wr32(sh + 100, SYNTH_DATA_RAW);
    wr32(sh + 116, 0xC0000040);          /* INITIALIZED_DATA|READ|WRITE */

    /* .text 内容 */
    if (with_entry) emit_stub(b, TF(SYNTH_STUB_ENTRY), SYNTH_REC_ENTRY_RVA, 1);
    if (with_tls)   emit_stub(b, TF(SYNTH_STUB_TLS),   SYNTH_REC_TLS_RVA,   1);
    wr64(b + TF(SYNTH_SLOT_RVA), SYNTH_IMAGE_BASE + SYNTH_MARK_RVA);
    memcpy(b + TF(SYNTH_MARK_RVA), "MARK", 4);
    wr32(b + TF(SYNTH_RELOC_RVA), SYNTH_TEXT_RVA);
    wr32(b + TF(SYNTH_RELOC_RVA) + 4, 12);
    wr16(b + TF(SYNTH_RELOC_RVA) + 8,
         (uint16_t)((10u << 12) | 0x200u));   /* DIR64 @0x1200 */

    /* .rdata 内容 */
    memcpy(b + RF(SYNTH_DLLNAME_RVA), "TESTLIB.DLL", 12);
    wr32(b + RF(SYNTH_IMPDESC_RVA) + 0,  SYNTH_ILT_RVA);
    wr32(b + RF(SYNTH_IMPDESC_RVA) + 12, SYNTH_DLLNAME_RVA);
    wr32(b + RF(SYNTH_IMPDESC_RVA) + 16, SYNTH_IAT_RVA);
    wr64(b + RF(SYNTH_ILT_RVA), SYNTH_HINTNM_RVA);
    wr64(b + RF(SYNTH_IAT_RVA), SYNTH_HINTNM_RVA);
    wr16(b + RF(SYNTH_HINTNM_RVA), 0);
    memcpy(b + RF(SYNTH_HINTNM_RVA) + 2, "TestFunc", 9);

    if (with_tls) {
        /* AddressOfCallBacks 在 IMAGE_TLS_DIRECTORY64 中位于 +24（8 字节）。
           此前按 +20/4 字节读，取到的是 SizeOfZeroFill（恒 0），于是
           "无 TLS 回调"被静默判定 —— 任何带 TLS 的现代 PE 都不会执行回调。 */
        wr64(b + RF(SYNTH_TLSDIR_RVA) + 24, SYNTH_IMAGE_BASE + SYNTH_TLSCB_RVA);
        wr64(b + RF(SYNTH_TLSCB_RVA), SYNTH_IMAGE_BASE + SYNTH_STUB_TLS);
    }
}
