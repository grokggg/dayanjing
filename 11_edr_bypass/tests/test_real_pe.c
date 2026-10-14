/*
 * 11_edr_bypass/tests/test_real_pe.c
 *
 * 真实 PE 验证测试。
 *
 * 目的：验证 ds_resolve() 在"真实感足够强"的 PE32+ DLL 上，
 *       输出是否与构造时的已知值字节级一致。
 *
 * 与 test_direct_syscall.c（手造 mock PE）的区别：
 *   - 本测试使用 tools/build_real_pe.py 构造的多节、多导出 DLL
 *   - 含 Nt+ 别名（验证去重逻辑）和前向导出（验证跳过逻辑）
 *   - 每个字段的期望值由 Python 脚本在构造时确定，本测试逐项比对
 *
 * 用法：make realtest
 */

#include "direct_syscall.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

/* ==================================================================
 * 预期值（与 build_real_pe.py 构造时一致）
 * ================================================================== */

#define PE_PATH "tools/test_ntdll.dll"

typedef struct {
    const char *name;
    uint16_t    ordinal;
    uint32_t    ssn;
} expected_t;

/* 注意：Nt+ 别名与 Zw+ 共享 SSN，解析器应去重只保留其一；
 * 前向导出应被跳过。所以预期只有 4 条 Zw+。 */
static const expected_t EXPECTED[] = {
    { "ZwQuerySystemInformation", 1, 0x36 },
    { "ZwOpenProcess",            2, 0x26 },
    { "ZwClose",                  3, 0x0F },
    { "ZwAllocateVirtualMemory",  4, 0x18 },
};
static const size_t NEXP = sizeof(EXPECTED) / sizeof(EXPECTED[0]);

/* ==================================================================
 * 测试框架
 * ================================================================== */

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(name, cond) do { \
    if (cond) { g_pass++; printf("  \033[32m[PASS]\033[0m %s\n", name); } \
    else      { g_fail++; printf("  \033[31m[FAIL]\033[0m %s\n", name); } \
} while (0)

/* DJB2 哈希（与 direct_syscall.c 完全一致，用于本地验证） */
static ds_hash_t local_hash(const char *s) {
    ds_hash_t h = 5381;
    int c;
    while ((c = (unsigned char)*s++) != 0) {
        if (c >= 'A' && c <= 'Z') c += 32;
        h = ((h << 5) + h) + (ds_hash_t)c;
    }
    return h;
}

int main(void) {
    printf("=== direct_syscall 真实 PE 验证测试 ===\n");
    printf("    PE 文件: %s\n\n", PE_PATH);

    /* 文件存在性检查 */
    {
        FILE *f = fopen(PE_PATH, "rb");
        if (!f) {
            printf("  \033[31m[ERROR]\033[0m 找不到 %s\n", PE_PATH);
            printf("          请先运行: python3 tools/build_real_pe.py %s\n", PE_PATH);
            return 2;
        }
        fclose(f);
    }

    /* ---------- 1. 基础解析 ---------- */
    printf("[1] ds_resolve() 基础解析\n");
    ds_entry_t table[64];
    size_t count = 0;
    ds_status_t rc = ds_resolve(PE_PATH, table, 64, &count);
    printf("    rc = %s, count = %zu\n", ds_status_str(rc), count);
    CHECK("解析成功 (DS_OK)", rc == DS_OK);
    CHECK("提取条数 == 4",     count == NEXP);

    /* ---------- 2. 逐条比对 ---------- */
    printf("\n[2] 逐条比对 (name_hash / ordinal / ssn)\n");
    if (rc == DS_OK && count == NEXP) {
        for (size_t i = 0; i < NEXP; i++) {
            const expected_t *e = &EXPECTED[i];
            bool found = false;
            for (size_t j = 0; j < count; j++) {
                ds_hash_t h = local_hash(e->name);
                if (table[j].name_hash == h) {
                    found = true;
                    char tag[80];
                    snprintf(tag, sizeof(tag),
                             "%s: ssn=0x%02x", e->name, e->ssn);
                    CHECK(tag, table[j].ssn == e->ssn);

                    snprintf(tag, sizeof(tag),
                             "%s: ordinal=%u", e->name, e->ordinal);
                    CHECK(tag, table[j].ordinal == e->ordinal);
                    break;
                }
            }
            if (!found) {
                char tag[80];
                snprintf(tag, sizeof(tag), "%s: 在结果中找到", e->name);
                CHECK(tag, false);
            }
        }
    }

    /* ---------- 3. 去重逻辑验证 ---------- */
    printf("\n[3] 去重逻辑 (Nt+ 别名不应重复出现)\n");
    {
        ds_hash_t qsi = local_hash("ZwQuerySystemInformation");
        int hits = 0;
        for (size_t i = 0; i < count; i++) {
            if (table[i].name_hash == qsi) hits++;
        }
        CHECK("ZwQuerySystemInformation 只出现 1 次", hits == 1);
        /* Nt+ 别名应被跳过（其 SSN 与 Zw 相同，去重逻辑生效） */
        ds_hash_t nqsi = local_hash("NtQuerySystemInformation");
        bool nt_found = false;
        for (size_t i = 0; i < count; i++) {
            if (table[i].name_hash == nqsi) { nt_found = true; break; }
        }
        CHECK("Nt+ 别名被去重跳过", !nt_found);
    }

    /* ---------- 4. 前向导出验证 ---------- */
    printf("\n[4] 前向导出验证\n");
    {
        ds_hash_t fwd = local_hash("ZwForwarder");
        bool fwd_found = false;
        for (size_t i = 0; i < count; i++) {
            if (table[i].name_hash == fwd) { fwd_found = true; break; }
        }
        CHECK("前向导出 ZwForwarder 被跳过", !fwd_found);
    }

    /* ---------- 5. ds_resolve_by_name ---------- */
    printf("\n[5] ds_resolve_by_name()\n");
    uint32_t ssn = 0;
    CHECK("ZwOpenProcess -> 0x26",
          ds_resolve_by_name(PE_PATH, "ZwOpenProcess", &ssn) == DS_OK && ssn == 0x26);
    CHECK("ZwClose -> 0xF",
          ds_resolve_by_name(PE_PATH, "ZwClose", &ssn) == DS_OK && ssn == 0x0F);
    CHECK("ZwAllocateVirtualMemory -> 0x18",
          ds_resolve_by_name(PE_PATH, "ZwAllocateVirtualMemory", &ssn) == DS_OK && ssn == 0x18);
    /* 不存在的函数 */
    CHECK("不存在函数返回 NO_SSN_TABLE",
          ds_resolve_by_name(PE_PATH, "ZwNotExists", &ssn) == DS_ERR_NO_SSN_TABLE);

    /* ---------- 6. ds_invoke 端到端 ---------- */
    printf("\n[6] ds_invoke 端到端\n");
    if (count > 0) {
        uintptr_t r = ds_invoke(table, count, local_hash("ZwOpenProcess"), 0,0,0,0);
        CHECK("invoke ZwOpenProcess 返回 SSN 高 32 位",
              ((uint32_t)(r >> 32)) == 0x26);
    }

    /* ---------- 汇总 ---------- */
    printf("\n=== 结果: \033[32m%d 通过\033[0m, \033[%s%d 失败\033[0m ===\n",
           g_pass, g_fail > 0 ? "31m" : "32m", g_fail);
    return g_fail == 0 ? 0 : 1;
}
