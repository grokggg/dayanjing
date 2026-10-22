/*
 * DAYANJING v4 — 20_packer / flatten.h
 *
 * 控制流扁平化（Control Flow Flattening, x86-64）。
 *
 * 作用对象是一组"基本块"，输出一段语义等价、但控制流图已被压平的机器码：
 *
 *         state = V_entry                       ; 加密态初值
 *     dispatcher:                               ; 每块一个 cmp/je，顺序随机
 *         cmp state, V_i   -> je block_i
 *         cmp state, G_j   -> je garbage_j      ; G_j 永不产生（不透明）
 *         jmp exit                              ; 兜底
 *     block_i:                                  ; 物理排列顺序随机，与执行序无关
 *         <块体>
 *         state ^= (V_i ^ V_next)               ; 转移是 xor 计算，不是立即数
 *         jmp dispatcher
 *     garbage_j:
 *         <不透明谓词守卫：x*(x+1) 恒偶 -> jz 恒跳>   ; 垃圾体不可达
 *         <垃圾体>
 *         state ^= (G_j ^ V_k)
 *         jmp dispatcher
 *     exit:
 *         <拆帧> ret
 *
 * 为什么状态用"加密态 + xor 转移"而不是 0/1/2 立即数：
 *   若块 i 末尾写 `state = i+1`，静态工具做一遍常量传播就能重建原始 CFG，
 *   扁平化等于白做。改为 `state ^= V_i ^ V_next` 后，要确定后继必须解出
 *   状态的值域——分发器比较的也是密文态，静态看不到 0,1,2 序列。
 *
 * 为什么垃圾块不可达但仍有价值：
 *   分发器里存在 `cmp state, G_j` 分支，而 G_j 是否可达需要值域分析才能
 *   判定（因为状态是算出来的）。它同时把分发器的出边数量翻倍，显著抬高
 *   静态重建 CFG 的成本。垃圾体永不被执行，运行时开销为零。
 *
 * 块体约定（违反即未定义行为）：
 *   1. 位置无关：不得使用 RIP 相对寻址（本层会搬动块的位置）。
 *      需要绝对地址请用 `movabs r64, imm64`。
 *   2. rsp 平衡：块体结束时 rsp 必须与进入时相同（不得留 push 未配 pop）。
 *      本层在帧内为块体保留空间，块体可自由使用 [rsp+X]。
 *   3. 不得用 eax/ecx 传递跨块的值：分发器用 eax 做比较，垃圾块守卫会
 *      破坏 eax/ecx（守卫不可达，但静态上看起来会）。其余寄存器跨块保持。
 *   4. 非易失寄存器（SysV: RBX/RBP/R12-R15）若被块体改写必须自行保存恢复。
 *
 * 不依赖 OpenSSL / zlib，仅 libc。仅支持 x86-64。
 */

#ifndef DAYANJING_FLATTEN_H
#define DAYANJING_FLATTEN_H

#include <stddef.h>
#include <stdint.h>

#define FL_MAX_BLOCKS  64
#define FL_MAX_GARBAGE 64

/* 返回码 */
#define FL_OK         0
#define FL_ERR_PARAM  -1
#define FL_ERR_MEM    -2
#define FL_ERR_TOOBIG -3
#define FL_ERR_NOEXIT -4

typedef struct {
    const uint8_t *code; /* 块体机器码（位置无关、rsp 平衡） */
    size_t         len;  /* 允许为 0 */
    int            next; /* 后继块下标；-1 表示该块之后进入出口 */
} fl_block;

/*
 * 生成扁平化代码。返回值 FL_OK 或负错误码。
 *   blocks / nblk   : 真块数组，1 <= nblk <= FL_MAX_BLOCKS
 *   ngarbage        : 垃圾块数量，0 <= ngarbage <= FL_MAX_GARBAGE
 *   out / out_len   : 出参，malloc 分配，调用方 free
 *   frame_out       : 出参，可为 NULL。回填本层为自己分配的栈帧字节数。
 *
 * frame_out 的用途：本层在 prologue 里会 `sub rsp, frame`，块体运行时
 * rsp 已经比调用方进入时低了 frame 字节。若块体需要用 [rsp+X] 访问调用方
 * 自己分配的栈帧，就必须把 X 加上 frame——而这个值在 fl_build 返回前无法
 * 得知（帧大小是随机的）。调用方据此在构建后回填块体内的位移立即数。
 *
 * 出口是所有 next == -1 的块之后的公共收尾点。若没有任何块以 -1 结束，
 * 返回 FL_ERR_NOEXIT（否则生成的代码永不返回，必崩）。
 *
 * 注意：出口段末尾是一条 ret。若调用方需要"跳走"而非"返回"，必须在
 * next == -1 的那个块体内自己发射 jmp——块体内的 jmp 先执行，出口段
 * 的 ret 永远不会到达。
 *
 * 同一种子的输出逐字节可复现（帧大小也随之可复现）。
 */
int fl_build(uint64_t seed, const fl_block *blocks, size_t nblk,
             size_t ngarbage, uint8_t **out, size_t *out_len,
             uint32_t *frame_out);

const char *fl_strerror(int rc);

#endif /* DAYANJING_FLATTEN_H */
