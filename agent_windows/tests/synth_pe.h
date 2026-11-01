/* tests/synth_pe.h — 合成 PE32+ 构造器（test_reflect_run 与 test_stager_win 共用）
 *
 * 为什么抽成共享文件而不是复制：
 *   合成 PE 里的桩代码把 `&g_seq` 的绝对地址硬编码进机器码，重定位槽位、
 *   记录区 RVA 与桩的字节布局必须逐位对齐。复制一份就意味着将来改一处
 *   而漏另一处，而两处测试都会"通过"—— 因为它们各自的假设都自洽。
 *   这种双份自洽正是此前 PE32+ TLS 偏移缺陷（+20 vs +24）潜伏的原因。
 *
 * 桩代码是真实 x86-64 机器码，按 Windows x64 约定取参（rcx/rdx），
 * 在 Linux 上可直接执行 —— 它只做寄存器搬运与跳转，不含系统调用。
 */
#ifndef DAYANJING_TESTS_SYNTH_PE_H
#define DAYANJING_TESTS_SYNTH_PE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 布局常量 ---- */
#define SYNTH_IMAGE_BASE   0x140000000ULL
#define SYNTH_SECT_ALIGN   0x1000u
#define SYNTH_FILE_ALIGN   0x200u
#define SYNTH_HDR_SIZE     0x400u

#define SYNTH_TEXT_RVA     0x1000u
#define SYNTH_TEXT_RAW     0x400u
#define SYNTH_RDATA_RVA    0x2000u
#define SYNTH_RDATA_RAW    0x1400u
#define SYNTH_DATA_RVA     0x3000u   /* 可写节区：记录区必须在这里 */
#define SYNTH_DATA_RAW     0x2400u

#define SYNTH_SIZE_IMAGE   0x4000u
#define SYNTH_FILE_SIZE    0x3400u

#define SYNTH_STUB_ENTRY   0x1000u
#define SYNTH_STUB_TLS     0x1100u
#define SYNTH_SLOT_RVA     0x1200u   /* DIR64 重定位槽，初值 = BASE + MARK_RVA */
#define SYNTH_MARK_RVA     0x1300u   /* 标记数据 "MARK" */
#define SYNTH_RELOC_RVA    0x1400u

#define SYNTH_DLLNAME_RVA  0x2000u
#define SYNTH_IMPDESC_RVA  0x2010u
#define SYNTH_ILT_RVA      0x2040u
#define SYNTH_IAT_RVA      0x2050u
#define SYNTH_HINTNM_RVA   0x2060u
#define SYNTH_TLSDIR_RVA   0x2100u
#define SYNTH_TLSCB_RVA    0x2200u

/*
 * 记录区（由桩代码直接写）。
 *
 * 必须落在**可写**节区：反射装载的流程是 映射->重定位->IAT->逐节设权->
 * TLS->入口，设权发生在调用之前。若记录区在 .text，设权后它是 R|X，
 * 桩代码写入即刻 SIGSEGV —— 而 .text 是代码节，本来就不该可写。
 *
 * 此前放在 .text 且未被发现，是因为 test_reflect_run 用 RWX 的 mmap 区，
 * 绕过了真实设权语义。故把记录区移进 .data，让严格设权下也能真跑。
 */
#define SYNTH_REC_ENTRY_RVA 0x3000u
#define SYNTH_REC_TLS_RVA   0x3040u
#define SYNTH_REC_COUNT     0x00u
#define SYNTH_REC_BASE      0x08u
#define SYNTH_REC_REASON    0x10u
#define SYNTH_REC_PTR       0x18u
#define SYNTH_REC_SEQ       0x20u

/*
 * 构造一个 PE32+。
 *   with_entry=1 写入口点桩，with_tls=1 写 TLS 目录与回调桩。
 *   两者皆 0 时产出的映像既无入口也无 TLS —— 用于验证"拒绝静默空跑"。
 */
void synth_pe_build(uint8_t *b, size_t cap, int with_entry, int with_tls);

/* 读取映像内记录区字段 */
uint64_t synth_pe_rec(const uint8_t *region, uint32_t rec_rva, uint32_t field);

/*
 * 改写入口点桩的返回值（imm32 的最低位字节）。
 * 用于验证"DllMain 返回 FALSE 时上报 RR_ERR_ENTRY"这条路径 ——
 * 若没有它，"装载成功"会把失败初始化也吞掉。
 */
void synth_pe_set_entry_ret(uint8_t *b, int ret_true);

/* 全局执行序号（桩代码每执行一次自增），用于判定 TLS/入口的先后顺序 */
void     synth_pe_seq_reset(void);
uint64_t synth_pe_seq(void);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_TESTS_SYNTH_PE_H */
