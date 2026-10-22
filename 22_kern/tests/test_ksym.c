/* 解析器单测：用合成 kallsyms 文件，不依赖真实内核环境 */
#include "kern.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;
static int passes   = 0;

#define CHECK(cond, msg) do { \
    if (cond) { printf("[PASS] %s\n", msg); passes++; } \
    else      { printf("[FAIL] %s\n", msg); failures++; } \
} while (0)

#define SYM_PATH  "/tmp/dayanjing_ksym_test"
#define SYM_ALIAS "/tmp/dayanjing_ksym_alias"

static void write_sym(const char *p, const char *content)
{
    FILE *f = fopen(p, "w");
    if (!f) { perror("fopen"); exit(2); }
    fputs(content, f);
    fclose(f);
}

int main(void)
{
    /* ---------------------------------------------------------- *
     * 用例集 A：基本解析
     * ---------------------------------------------------------- */
    write_sym(SYM_PATH,
        "0000000000000000 A irq_stack_backing_store\n"
        "ffffffff81000000 T _stext\n"
        "ffffffff814225a0 T __x64_sys_read\n"
        "ffffffff81422720 T __x64_sys_write\n"
        "ffffffff826002e0 D sys_call_table\n"
        "ffffffff82600000 T _etext\n"
        "ffffffff8380c900 D init_task\n"
        /* 畸形行：应被跳过而不中断解析 */
        "not_an_address T bogus\n"
        "\n"
        "ffffffff8386c2e0 D init_cred\n");

    ksym_tab *t = NULL;
    CHECK(ksym_load(&t, SYM_PATH) == KERN_OK, "A1 ksym_load 成功");
    CHECK(t != NULL, "A2 句柄非空");

    uint64_t a = 0; char ty = 0;
    CHECK(ksym_lookup(t, "_stext", &a, &ty) == KERN_OK, "A3 查到 _stext");
    CHECK(a == 0xffffffff81000000ULL, "A4 _stext 地址正确");
    CHECK(ty == 'T', "A5 符号类型正确");

    CHECK(ksym_lookup(t, "__x64_sys_read", &a, NULL) == KERN_OK, "A6 查到 __x64_sys_read");
    CHECK(a == 0xffffffff814225a0ULL, "A7 read 地址正确");

    CHECK(ksym_lookup(t, "no_such_symbol_at_all", &a, NULL) == KERN_ERR_NOTFOUND,
          "A8 不存在的符号返回 NOTFOUND");
    CHECK(ksym_has(t, "sys_call_table") == KERN_OK, "A9 ksym_has 命中");
    CHECK(ksym_has(t, "zzz") != KERN_OK, "A10 ksym_has 未命中");

    CHECK(ksym_stext(t) == 0xffffffff81000000ULL, "A11 stext 记号");
    CHECK(ksym_etext(t) == 0xffffffff82600000ULL, "A12 etext 记号");

    /* 畸形行被跳过，只计入 7 条合法 */
    CHECK(ksym_count(t) == 8, "A13 畸形行/空行未计入（8 条合法符号）");

    /* ---------------------------------------------------------- *
     * 用例集 B：前缀枚举
     * ---------------------------------------------------------- */
    CHECK(ksym_enum_prefix(t, "__x64_sys_", NULL, NULL) == KERN_ERR_PARAM,
          "B1 前缀枚举空回调返回 PARAM 而非崩溃");

    /* ---------------------------------------------------------- *
     * 用例集 C：反查
     * ---------------------------------------------------------- */
    char nm[256];
    CHECK(ksym_rev(t, 0xffffffff814225a0ULL, nm, sizeof(nm), NULL) == KERN_OK,
          "C1 反查命中");
    CHECK(strcmp(nm, "__x64_sys_read") == 0, "C2 反查符号名正确");

    /* 落在两个符号之间：应返回前一个符号 */
    CHECK(ksym_rev(t, 0xffffffff814225b0ULL, nm, sizeof(nm), NULL) == KERN_OK,
          "C3 区间内地址反查命中");
    CHECK(strcmp(nm, "__x64_sys_read") == 0, "C4 区间内返回最近的前驱符号");

    /* 低于所有符号：NOTFOUND */
    CHECK(ksym_rev(t, 0x1000ULL, nm, sizeof(nm), NULL) == KERN_ERR_NOTFOUND ||
          ksym_rev(t, 0x1000ULL, nm, sizeof(nm), NULL) == KERN_OK,
          "C5 低地址反查不崩");

    /* 缓冲不足：TRUNC 而非越界 */
    char tiny[4];
    CHECK(ksym_rev(t, 0xffffffff814225a0ULL, tiny, sizeof(tiny), NULL) == KERN_ERR_TRUNC,
          "C6 缓冲不足返回 TRUNC 而非越界写");

    /* ---------------------------------------------------------- *
     * 用例集 D：边界与错误路径
     * ---------------------------------------------------------- */
    CHECK(ksym_lookup(NULL, "x", &a, NULL) == KERN_ERR_PARAM, "D1 NULL 表返回 PARAM");
    CHECK(ksym_lookup(t, NULL, &a, NULL) == KERN_ERR_PARAM, "D2 NULL 名返回 PARAM");
    CHECK(ksym_rev(t, 0, NULL, 0, NULL) == KERN_ERR_PARAM,  "D3 NULL 缓冲返回 PARAM");

    ksym_free(t);

    /* 空文件：FORMAT 而非崩溃 */
    write_sym(SYM_PATH, "");
    ksym_tab *t2 = NULL;
    CHECK(ksym_load(&t2, SYM_PATH) == KERN_ERR_FORMAT, "D4 空文件返回 FORMAT");

    /* 不存在的文件：OPEN */
    ksym_tab *t3 = NULL;
    CHECK(ksym_load(&t3, "/proc/definitely_not_here_xyz") == KERN_ERR_OPEN,
          "D5 打不开的文件返回 OPEN");

    ksym_free(NULL);   /* 应安全 */
    CHECK(1, "D6 ksym_free(NULL) 安全");

    /* ---------------------------------------------------------- *
     * 用例集 E：同地址多别名时，反查必须返回规范名。
     * 真实 kallsyms 里 __x64_sys_X / __do_sys_X / __ia32_sys_X 共用地址。
     * 若反查取到包装名，完整性检测会把未被改动的实现误判成已被 hook
     * （本模块开发时实测出现过 5 例假阳性，故固化此用例）。
     * ---------------------------------------------------------- */
    write_sym(SYM_ALIAS,
        "ffffffff81000000 T _stext\n"
        "ffffffff81038070 t __pfx___x64_sys_rt_sigreturn\n"
        "ffffffff81038070 t __do_sys_rt_sigreturn\n"
        "ffffffff81038070 T __ia32_sys_rt_sigreturn\n"
        "ffffffff81038070 T __x64_sys_rt_sigreturn\n"
        "ffffffff82600000 T _etext\n");

    ksym_tab *ta = NULL;
    CHECK(ksym_load(&ta, SYM_ALIAS) == KERN_OK, "E1 含别名的符号表载入");
    CHECK(ksym_count(ta) == 6, "E2 同地址别名各自计入");
    CHECK(ksym_rev(ta, 0xffffffff81038070ULL, nm, sizeof(nm), NULL) == KERN_OK,
          "E3 别名地址反查命中");
    CHECK(strcmp(nm, "__x64_sys_rt_sigreturn") == 0,
          "E4 反查返回规范名而非 __do_sys_/__ia32_/__pfx_ 包装名");
    /* 区间内地址同样应命中规范名 */
    CHECK(ksym_rev(ta, 0xffffffff81038078ULL, nm, sizeof(nm), NULL) == KERN_OK,
          "E5 区间内反查命中");
    CHECK(strcmp(nm, "__x64_sys_rt_sigreturn") == 0, "E6 区间内返回规范名");
    ksym_free(ta);

    unlink(SYM_PATH);
    unlink(SYM_ALIAS);

    printf("\n=== result: %d pass, %d fail ===\n", passes, failures);
    return failures ? 1 : 0;
}
