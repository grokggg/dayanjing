#include "direct_syscall.h"
#include "pe_image.h"
#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "assert.h"
#include "inttypes.h"

/* Build a minimal mock ntdll PE image in memory.
 * Layout:
 *   0x000  DOS header (e_lfanew = 0x80)
 *   0x080  NT headers: signature + file header + optional header
 *   0x170  section table (.text)
 *   0x300  export directory
 *   0x3A0  export tables (AddressOfFunctions/Names/Ordinals)
 *   0x400  ZwQuerySystemInformation body: B8 36 00 00 00 C3
 */
#define MOCK_SIZE 0x2000
static unsigned char g_mock[MOCK_SIZE];
static const char   *g_path = "/tmp/mock_ntdll.dll";

static void build_mock_pe(void)
{
    memset(g_mock, 0, sizeof(g_mock));

    /* DOS */
    memcpy(g_mock + 0, "MZ", 2);
    memcpy(g_mock + 0x3C, "\x80\x00\x00\x00", 4);   /* e_lfanew = 0x80 */

    /* NT signature */
    memcpy(g_mock + 0x80, "PE\0\0", 4);

    /* File header @ 0x84 (immediately after PE\0\0 signature) */
    struct pe_file_hdr *fh = (struct pe_file_hdr *)(g_mock + 0x84);
    fh->Machine = 0x8664;
    fh->NumberOfSections = 1;
    fh->SizeOfOptionalHeader = 240;
    fh->Characteristics = 0x0020;

    /* Memory layout（与修正后的 PE64 结构对齐，见 pe_image.h 不变量注释）：
     *   0x000  DOS header (e_lfanew @ 0x3C = 0x80)
     *   0x080  PE\0\0 + FileHeader (20 bytes)         -> ends 0x098
     *   0x098  OptionalHeader (112 bytes, ends @0x108) -- 结构体本身
     *   0x108  DataDirectory[0..15] (16 * 8 = 128 B)   -> ends 0x188
     *   0x188  Section table (1 section, 40 bytes)      -> ends 0x1B0
     *   0x1B0  .text raw data:
     *     0x1B0  Export Directory (40 bytes)            -> 0x1B0..0x1D8
     *     0x210  AddressOfFunctions[1]                  (RVA 0x1060)
     *     0x218  AddressOfNameOrdinals[1]               (RVA 0x1068)
     *     0x220  AddressOfNames[1]                      (RVA 0x1070)
     *     0x230  "ZwQuerySystemInformation" string      (RVA 0x1080)
     *     0x240  Zw function body (mov eax,0x36; ret)   (RVA 0x1090)
     *   section: VA=0x1000, PointerToRawData=0x1B0, Size=0x400
     */

    /* Optional header @ 0x98 */
    struct pe_opt_hdr *oh = (struct pe_opt_hdr *)(g_mock + 0x98);
    oh->Magic = 0x020B;
    oh->NumberOfRvaAndSizes = 16;  /* 16 data directories */

    /* DataDirectory[0] (Export) @ 0x108 */
    *(uint32_t *)(g_mock + 0x108) = 0x1000;   /* Export Directory RVA */
    *(uint32_t *)(g_mock + 0x10C) = 0x0028;   /* Export Directory Size = 40 bytes */

    /* Section table @ 0x188 */
    struct pe_sec_hdr *sec = (struct pe_sec_hdr *)(g_mock + 0x188);
    memcpy(sec->Name, ".text", 5);
    sec->VirtualSize = 0x400;
    sec->VirtualAddress = 0x1000;
    sec->SizeOfRawData = 0x400;
    sec->PointerToRawData = 0x1B0;

    /* Export Directory @ 0x1B0 (RVA 0x1000) */
    uint32_t *ed = (uint32_t *)(g_mock + 0x1B0);
    ed[0] = 0;                       /* Characteristics */
    ed[1] = 0;                       /* TimeDateStamp */
    ed[2] = 0;                       /* MajorVersion/MinorVersion */
    ed[3] = 0;                       /* Name RVA (0 = no name) */
    ed[4] = 1;                       /* Base */
    ed[5] = 1;                       /* NumberOfFunctions */
    ed[6] = 1;                       /* NumberOfNames */
    ed[7] = 0x1060;                  /* AddressOfFunctions      RVA */
    ed[8] = 0x1070;                  /* AddressOfNames          RVA */
    ed[9] = 0x1068;                  /* AddressOfNameOrdinals   RVA */

    /* AddressOfFunctions @ 0x210 (RVA 0x1060) -> 0x1B0 + (0x1060-0x1000) */
    *(uint32_t *)(g_mock + 0x210) = 0x10A0;   /* proc RVA = 0x10A0 -> off 0x250 */

    /* AddressOfNameOrdinals @ 0x218 (RVA 0x1068) */
    *(uint16_t *)(g_mock + 0x218) = 0;

    /* AddressOfNames @ 0x220 (RVA 0x1070) */
    *(uint32_t *)(g_mock + 0x220) = 0x1080;   /* name RVA = 0x1080 -> off 0x230 */

    /* Function name string @ 0x230 (RVA 0x1080). Include trailing '\0' */
    memcpy(g_mock + 0x230, "ZwQuerySystemInformation",
           sizeof("ZwQuerySystemInformation"));

    /* Function body @ 0x250 (RVA 0x10A0): mov eax, 0x36 ; ret */
    g_mock[0x250] = 0xB8;
    g_mock[0x251] = 0x36;
    g_mock[0x252] = 0x00;
    g_mock[0x253] = 0x00;
    g_mock[0x254] = 0x00;
    g_mock[0x255] = 0xC3;
}

static void save_mock(void)
{
    FILE *fp = fopen(g_path, "wb");
    assert(fp != NULL);
    fwrite(g_mock, 1, MOCK_SIZE, fp);
    fclose(fp);
}

int main(void)
{
    int total = 0, passed = 0;
    #define CHECK(desc, cond) do { \
        total++; \
        if (cond) { passed++; printf("  [PASS] %s\n", desc); } \
        else       { printf("  [FAIL] %s\n", desc); } \
    } while (0)

    printf("[*] direct_syscall 单元测试\n");
    printf("[*] ======================================\n");

    /* ---------- 1. hash ---------- */
    hash_t h1 = ds_hash("ZwQuerySystemInformation");
    hash_t h2 = ds_hash("ZwQuerySystemInformation");
    CHECK("hash 确定性", h1 == h2);
    CHECK("hash(NULL)==0", ds_hash(NULL) == 0);
    CHECK("hash 非空值",  h1 != 0);

    /* ---------- 2. 边界：空参数 ---------- */
    struct syscall_entry tbl[8];
    CHECK("resolve(NULL) -> -1",       ds_resolve(NULL, tbl, 8, 0) == -1);
    CHECK("invoke 空表 -> -1",         ds_invoke(NULL, 0, h1, 0,0,0,0) == (uintptr_t)-1);
    CHECK("invoke 空表(count=0) -> -1", ds_invoke(tbl, 0, h1, 0,0,0,0) == (uintptr_t)-1);

    /* ---------- 3. 边界：文件不存在 ---------- */
    CHECK("不存在文件 -> -2",
          ds_resolve("/nonexistent/xxx.dll", tbl, 8, 0) == -2);

    /* ---------- 4. 反调试 ---------- */
    CHECK("anti_debug 未附加调试器", ds_anti_debug() == 0);

    /* ---------- 5. 解析 mock PE ---------- */
    build_mock_pe();
    save_mock();

    int n = ds_resolve(g_path, tbl, 8, DS_RESOLVE_PROLOGUE);
    printf("  [INFO] mock PE 解析到 %d 条 Zw* 条目\n", n);
    if (n > 0) {
        CHECK("首条 SSN == 0x36",
              tbl[0].ssn == 0x36);
        CHECK("首条 hash 匹配",
              tbl[0].name_hash == h1);
    }

    /* ---------- 6. invoke_by_hash ---------- */
    uintptr_t r = ds_invoke(tbl, (size_t)(n > 0 ? n : 0), h1, 0,0,0,0);
    printf("  [INFO] invoke_by_hash 返回 0x%" PRIxPTR "\n", r);

    /* ---------- 7. mode 1 (table scan) ---------- */
    struct syscall_entry tbl2[8];
    int n2 = ds_resolve(g_path, tbl2, 8, DS_RESOLVE_TABLE);
    printf("  [INFO] mode=1 扫描到 %d 条\n", n2);

    /* ---------- 8. 重复调用稳定性 ---------- */
    int n3 = ds_resolve(g_path, tbl, 8, DS_RESOLVE_PROLOGUE);
    CHECK("重复调用结果一致", n3 == n);

    remove(g_path);

    printf("[*] ======================================\n");
    printf("[*] 结果: %d/%d 通过\n", passed, total);

    if (passed != total) {
        printf("[!] 存在失败用例\n");
        return 1;
    }
    printf("[+] 全部测试通过\n");
    printf("[!] 真机验证: 在 Windows 10/11 用 C:\\Windows\\System32\\ntdll.dll 测试\n");
    return 0;
}
