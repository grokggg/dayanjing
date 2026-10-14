/*
 * 11_edr_bypass/tests/test_direct_syscall.c
 *
 * 单元测试。覆盖：
 *   1. DJB2 哈希确定性 + 大小写不敏感
 *   2. 边界：空参数、空路径、不存在文件、空文件
 *   3. mock PE 解析：伪造 ntdll 结构，验证 SSN 提取
 *   4. ds_syscall 占位执行与非法 SSN 拒绝
 *   5. ds_invoke 按哈希查表执行
 *   6. ds_anti_debug / ds_anti_sandbox 不崩溃
 *
 * 布局原则：
 *   所有偏移由结构体真实 sizeof 推导，不做手算假设。
 *   mock PE 只含一个节 .text（VA=0x1000, RAW=0x400），导出目录及全部
 *   辅助表均落在 .text 节内，RVA <-> 偏移换算统一为 off = RAW + (RVA - VA)。
 */

#include "direct_syscall.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

/* ==================================================================
 * 结构定义（与 direct_syscall.c 保持一致，字节对齐 1）
 * ================================================================== */

#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;
    uint8_t  _pad1[0x3A];
    uint32_t e_lfanew;
} m_dos_hdr_t;

typedef struct {
    uint16_t m_machine;
    uint16_t m_num_sections;
    uint32_t m_timedatestamp;
    uint32_t m_ptr_sym_table;
    uint32_t m_num_symbols;
    uint16_t m_size_optional;
    uint16_t m_characteristics;
} m_file_hdr_t;

typedef struct {
    /* 固定 28 字节 */
    uint16_t o_magic;                              /* 0x00 */
    uint8_t  o_major_linker;                       /* 0x02 */
    uint8_t  o_minor_linker;                       /* 0x03 */
    uint32_t o_size_of_code;                       /* 0x04 */
    uint32_t o_size_of_init_data;                  /* 0x08 */
    uint32_t o_size_of_uninit_data;                /* 0x0C */
    uint32_t o_address_of_entry_point;             /* 0x10 */
    uint32_t o_base_of_code;                       /* 0x14 */
    /* Windows 特有字段 92 字节（0x18 ~ 0x73） */
    uint64_t o_image_base;                         /* 0x18 */
    uint32_t o_section_alignment;                  /* 0x20 */
    uint32_t o_file_alignment;                     /* 0x24 */
    uint16_t o_major_os_ver;                       /* 0x28 */
    uint16_t o_minor_os_ver;                       /* 0x2A */
    uint16_t o_major_image_ver;                    /* 0x2C */
    uint16_t o_minor_image_ver;                    /* 0x2E */
    uint16_t o_major_subsys_ver;                   /* 0x30 */
    uint16_t o_minor_subsys_ver;                   /* 0x32 */
    uint32_t o_win32_ver;                          /* 0x34 */
    uint32_t o_size_of_image;                      /* 0x38 */
    uint32_t o_size_of_headers;                    /* 0x3C */
    uint32_t o_checksum;                           /* 0x40 */
    uint16_t o_subsystem;                          /* 0x44 */
    uint16_t o_dll_characteristics;                /* 0x46 */
    uint64_t o_size_of_stack_reserve;              /* 0x48 */
    uint64_t o_size_of_stack_commit;               /* 0x50 */
    uint64_t o_size_of_heap_reserve;               /* 0x58 */
    uint64_t o_size_of_heap_commit;                /* 0x60 */
    uint32_t o_loader_flags;                       /* 0x68 */
    uint32_t o_number_of_rva_and_sizes;            /* 0x6C */
    /* 合计 = 28 + 84 = 112 字节（0x00 ~ 0x6F） */
} m_opt_hdr_t;

typedef struct {
    uint32_t rva;
    uint32_t size;
} m_data_dir_t;

typedef struct {
    char     s_name[8];
    uint32_t s_virtual_size;
    uint32_t s_virtual_address;
    uint32_t s_size_raw_data;
    uint32_t s_ptr_raw_data;
    uint32_t s_ptr_relocations;
    uint32_t s_ptr_linenums;
    uint16_t s_num_relocations;
    uint16_t s_num_linenums;
    uint32_t s_characteristics;
} m_section_hdr_t;

typedef struct {
    uint32_t e_characteristics;
    uint32_t e_timedatestamp;
    uint16_t e_major_ver;
    uint16_t e_minor_ver;
    uint32_t e_name;
    uint32_t e_base;
    uint32_t e_num_functions;
    uint32_t e_num_names;
    uint32_t e_ptr_functions;
    uint32_t e_ptr_names;
    uint32_t e_ptr_name_ordinals;
} m_export_dir_t;

#pragma pack(pop)

/* 校验：结构大小必须符合 PE 规范 */
_Static_assert(sizeof(m_dos_hdr_t) == 64,  "DOS header must be 64 bytes");
_Static_assert(sizeof(m_file_hdr_t) == 20, "FILE header must be 20 bytes");
_Static_assert(sizeof(m_opt_hdr_t) == 112, "Optional header (to data dir) must be 112 bytes (28 fixed + 84 windows)");
_Static_assert(sizeof(m_data_dir_t) == 8,  "Data directory entry must be 8 bytes");
_Static_assert(sizeof(m_section_hdr_t) == 40, "Section header must be 40 bytes");
_Static_assert(sizeof(m_export_dir_t) == 40,  "Export directory must be 40 bytes");

/* ==================================================================
 * 布局常量（由真实结构体 sizeof 推导）
 * ================================================================== */

#define MZ_OFS          0x000
#define NT_SIG_OFS      (MZ_OFS + sizeof(m_dos_hdr_t))          /* = 0x040 */
#define FILE_HDR_OFS    (NT_SIG_OFS + 4)                        /* = 0x044 */
#define OPT_HDR_OFS     (FILE_HDR_OFS + sizeof(m_file_hdr_t))   /* = 0x058 */
#define DATA_DIR_OFS    (OPT_HDR_OFS + sizeof(m_opt_hdr_t))     /* = 0x0D0 */
#define NUM_DATA_DIR    16
#define SEC_TBL_OFS     (DATA_DIR_OFS + NUM_DATA_DIR * sizeof(m_data_dir_t))
                                                            /* = 0x170 */

#define SEC_VA          0x1000     /* 节 VirtualAddress */
#define SEC_RAW         0x0400     /* 节 PointerToRawData */
#define SEC_VSIZE       0x0600     /* 节 VirtualSize（足够容纳导出表） */

/* 导出表及辅助表落在 .text 节内，用相对节首的偏移定位 */
#define EXP_RVA         (SEC_VA + 0x000)   /* 导出目录 @ RVA 0x1000 */
#define AF_RVA          (SEC_VA + 0x040)   /* AddressOfFunctions */
#define AN_RVA          (SEC_VA + 0x048)   /* AddressOfNames */
#define AO_RVA          (SEC_VA + 0x050)   /* AddressOfNameOrdinals */
#define NAME_RVA        (SEC_VA + 0x060)   /* 函数名 "ZwQuerySystemInformation" */
#define BODY_RVA        (SEC_VA + 0x080)   /* Zw* 函数体 */

#define MOCK_SIZE       0x2000
static unsigned char g_mock[MOCK_SIZE] = {0};
static const char   *g_mock_path = "/tmp/ds_mock_ntdll.dll";

/* RVA -> 文件偏移 */
static uint32_t rva2off(uint32_t rva) {
    assert(rva >= SEC_VA && rva < SEC_VA + SEC_VSIZE);
    return (uint32_t)(SEC_RAW + (rva - SEC_VA));
}

static void build_mock_pe(void) {
    memset(g_mock, 0, sizeof(g_mock));

    /* ---------- DOS 头 ---------- */
    g_mock[0] = 'M';
    g_mock[1] = 'Z';
    memcpy(g_mock + 0x3C, &(uint32_t){NT_SIG_OFS}, 4);

    /* ---------- NT 签名 ---------- */
    memcpy(g_mock + NT_SIG_OFS, "PE\0\0", 4);

    /* ---------- IMAGE_FILE_HEADER ---------- */
    m_file_hdr_t fh;
    memset(&fh, 0, sizeof(fh));
    fh.m_machine = 0x8664;                      /* AMD64 */
    fh.m_num_sections = 1;
    fh.m_size_optional = (uint16_t)(sizeof(m_opt_hdr_t) + NUM_DATA_DIR * sizeof(m_data_dir_t));
    fh.m_characteristics = 0x0022;              /* EXECUTABLE_IMAGE */
    memcpy(g_mock + FILE_HDR_OFS, &fh, sizeof(fh));

    /* ---------- IMAGE_OPTIONAL_HEADER64（仅填到数据目录为止） ---------- */
    m_opt_hdr_t opt;
    memset(&opt, 0, sizeof(opt));
    opt.o_magic = 0x20B;                        /* PE32+ */
    opt.o_image_base = 0x100000000ULL;
    opt.o_number_of_rva_and_sizes = NUM_DATA_DIR;
    memcpy(g_mock + OPT_HDR_OFS, &opt, sizeof(opt));

    /* ---------- 数据目录（16 项） ---------- */
    m_data_dir_t dirs[NUM_DATA_DIR];
    memset(dirs, 0, sizeof(dirs));
    dirs[0].rva  = EXP_RVA;                     /* 导出表 */
    dirs[0].size = sizeof(m_export_dir_t);
    memcpy(g_mock + DATA_DIR_OFS, dirs, sizeof(dirs));

    /* ---------- 节表 ---------- */
    m_section_hdr_t sec;
    memset(&sec, 0, sizeof(sec));
    memcpy(sec.s_name, ".text", 5);
    sec.s_virtual_size   = SEC_VSIZE;
    sec.s_virtual_address = SEC_VA;
    sec.s_size_raw_data  = SEC_VSIZE;
    sec.s_ptr_raw_data   = SEC_RAW;
    memcpy(g_mock + SEC_TBL_OFS, &sec, sizeof(sec));

    /* ---------- 导出目录 ---------- */
    m_export_dir_t ed;
    memset(&ed, 0, sizeof(ed));
    ed.e_base        = 1;                       /* OrdinalBase = 1 */
    ed.e_num_functions = 1;                     /* NumberOfFunctions */
    ed.e_num_names     = 1;                     /* NumberOfNames */
    ed.e_ptr_functions = AF_RVA;
    ed.e_ptr_names     = AN_RVA;
    ed.e_ptr_name_ordinals = AO_RVA;
    memcpy(g_mock + rva2off(EXP_RVA), &ed, sizeof(ed));

    /* ---------- AddressOfFunctions ---------- */
    memcpy(g_mock + rva2off(AF_RVA), &(uint32_t){BODY_RVA}, 4);

    /* ---------- AddressOfNames ---------- */
    memcpy(g_mock + rva2off(AN_RVA), &(uint32_t){NAME_RVA}, 4);

    /* ---------- AddressOfNameOrdinals ---------- */
    uint16_t ord = 0;                           /* 0 基序数 */
    memcpy(g_mock + rva2off(AO_RVA), &ord, 2);

    /* ---------- 函数名 ---------- */
    memcpy(g_mock + rva2off(NAME_RVA), "ZwQuerySystemInformation", 24);

    /* ---------- Zw* 函数体 ---------- */
    uint8_t *body = g_mock + rva2off(BODY_RVA);
    body[0] = 0xB8;     /* mov eax, 0x36 */
    body[1] = 0x36;
    body[2] = 0x00;
    body[3] = 0x00;
    body[4] = 0x00;
    body[5] = 0xC3;     /* ret */
}

/* ==================================================================
 * 测试框架
 * ================================================================== */

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(name, cond) do { \
    if (cond) { g_pass++; printf("  \033[32m[PASS]\033[0m %s\n", name); } \
    else      { g_fail++; printf("  \033[31m[FAIL]\033[0m %s\n", name); } \
} while (0)

int main(void) {
    printf("=== direct_syscall 单元测试 ===\n\n");

    /* ---------- 1. 哈希 ---------- */
    printf("[1] DJB2 哈希\n");
    CHECK("hash 确定性",   ds_hash("ZwQuerySystemInformation") == ds_hash("ZwQuerySystemInformation"));
    CHECK("hash 大小写不敏感", ds_hash("ZwXxx") == ds_hash("ZWXXX"));
    CHECK("hash NULL 返回 0", ds_hash(NULL) == 0);
    CHECK("hash 不同串不同", ds_hash("a") != ds_hash("b"));
    ds_hash_t h_qsi = ds_hash("ZwQuerySystemInformation");
    printf("    ZwQuerySystemInformation hash = 0x%08" PRIx32 "\n\n", h_qsi);

    /* ---------- 2. 边界 ---------- */
    printf("[2] 边界条件\n");
    ds_entry_t table[8];
    size_t cnt = 0;
    CHECK("空路径返回错误",      ds_resolve(NULL, table, 8, &cnt) == DS_ERR_INVALID_ARG);
    CHECK("空输出表返回错误",    ds_resolve("/dev/null", NULL, 8, &cnt) == DS_ERR_INVALID_ARG);
    CHECK("cap=0 返回错误",      ds_resolve("/dev/null", table, 0, &cnt) == DS_ERR_INVALID_ARG);
    CHECK("不存在文件返回错误",  ds_resolve("/nonexistent/xxx.dll", table, 8, &cnt) == DS_ERR_OPEN_FAILED);
    CHECK("空文件返回错误",      ds_resolve("/dev/null", table, 8, &cnt) == DS_ERR_OPEN_FAILED);

    uint32_t ssn = 0;
    CHECK("空 name 查询返回错误", ds_resolve_by_name("/dev/null", NULL, &ssn) == DS_ERR_INVALID_ARG);
    CHECK("空 ssn 输出返回错误",  ds_resolve_by_name("/dev/null", "ZwXxx", NULL) == DS_ERR_INVALID_ARG);
    printf("\n");

    /* ---------- 3. mock PE 解析 ---------- */
    printf("[3] mock PE 解析\n");
    build_mock_pe();
    FILE *fp = fopen(g_mock_path, "wb");
    assert(fp);
    fwrite(g_mock, 1, MOCK_SIZE, fp);
    fclose(fp);

    ds_status_t rc = ds_resolve(g_mock_path, table, 8, &cnt);
    printf("    ds_resolve rc = %s, count = %zu\n", ds_status_str(rc), cnt);
    CHECK("mock PE 解析成功", rc == DS_OK);
    CHECK("解析到 1 条 Zw*",  cnt == 1);
    if (cnt >= 1) {
#ifdef DS_DEBUG
        printf("    [%s] ssn=0x%02" PRIx32 " ordinal=%u hash=0x%08" PRIx32 "\n",
               table[0].name, table[0].ssn, table[0].ordinal, table[0].name_hash);
        CHECK("名称字符串正确", strcmp(table[0].name, "ZwQuerySystemInformation") == 0);
#else
        printf("    [<hashed>] ssn=0x%02" PRIx32 " ordinal=%u hash=0x%08" PRIx32 "\n",
               table[0].ssn, table[0].ordinal, table[0].name_hash);
#endif
        CHECK("SSN 等于 0x36", table[0].ssn == 0x36);
        CHECK("哈希匹配",      table[0].name_hash == h_qsi);
        CHECK("序号正确",      table[0].ordinal == 1);
    }

    /* ds_resolve_by_name */
    uint32_t ssn2 = 0;
    ds_status_t rc2 = ds_resolve_by_name(g_mock_path, "ZwQuerySystemInformation", &ssn2);
    CHECK("按名解析成功", rc2 == DS_OK);
    CHECK("按名 SSN=0x36",  ssn2 == 0x36);

    ds_status_t rc3 = ds_resolve_by_name(g_mock_path, "ZwNonexistent", &ssn2);
    CHECK("不存在函数返回 NO_SSN_TABLE", rc3 == DS_ERR_NO_SSN_TABLE);

    ds_status_t rc4 = ds_resolve_by_name(g_mock_path, "ZWQUERYSYSTEMINFORMATION", &ssn2);
    CHECK("大小写不敏感查询成功", rc4 == DS_OK);
    CHECK("大小写不敏感 SSN 正确", ssn2 == 0x36);

    remove(g_mock_path);
    printf("\n");

    /* ---------- 4. ds_syscall ---------- */
    printf("[4] 系统调用执行\n");
    uintptr_t r = ds_syscall(0, 0, 0, 0, 0x36);
    printf("    ds_syscall(0x36) 返回 0x%016" PRIxPTR "\n", r);
    CHECK("syscall 占位返回 SSN 高 32 位", ((uint32_t)(r >> 32)) == 0x36);
    CHECK("syscall 占位返回魔数",     (uint32_t)(r & 0xFFFFFFFF) == 0xDEADC0DE);

    uintptr_t r2 = ds_syscall(0, 0, 0, 0, 0x2000);   /* 非法 SSN > 0x1000 */
    CHECK("非法 SSN 被拒绝", r2 == (uintptr_t)-1);

    uintptr_t r3 = ds_invoke(NULL, 0, h_qsi, 0, 0, 0, 0);
    CHECK("空表 invoke 返回 -1", r3 == (uintptr_t)-1);

    uintptr_t r4 = ds_invoke(table, cnt, 0xDEADBEEF, 0, 0, 0, 0);
    CHECK("未找到 invoke 返回 -2", r4 == (uintptr_t)-2);

    if (cnt >= 1) {
        uintptr_t r5 = ds_invoke(table, cnt, h_qsi, 0, 0, 0, 0);
        CHECK("按哈希 invoke 执行成功", ((uint32_t)(r5 >> 32)) == 0x36);
    }
    printf("\n");

    /* ---------- 5. 反调试 / 反沙箱 ---------- */
    printf("[5] 反调试 / 反沙箱\n");
    bool dbg = ds_anti_debug();
    printf("    ds_anti_debug = %s\n", dbg ? "true (debugger detected)" : "false");
    CHECK("anti_debug 不崩溃", true);

    bool sb = ds_anti_sandbox();
    printf("    ds_anti_sandbox = %s\n", sb ? "suspicious" : "clean");
    CHECK("anti_sandbox 不崩溃", true);
    printf("\n");

    /* ---------- 汇总 ---------- */
    printf("=== 结果: \033[32m%d 通过\033[0m, \033[%s%d 失败\033[0m ===\n",
           g_pass, g_fail > 0 ? "31m" : "32m", g_fail);
    return g_fail == 0 ? 0 : 1;
}
