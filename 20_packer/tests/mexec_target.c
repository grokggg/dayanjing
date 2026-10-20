/*
 * DAYANJING v4 — 20_packer / mexec_target.c
 *
 * mexec 真机验证的目标程序：静态链接，打印固定标记与其 argv[1]。
 * 由 Makefile 编译为 build/mexec_target，test_packer 读取其字节并执行。
 */

#include <stdio.h>

int main(int argc, char **argv)
{
    printf("MEXEC_OK argv1=%s\n", (argc > 1) ? argv[1] : "(none)");
    fflush(stdout);
    return 0;
}
