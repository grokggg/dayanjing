/*
 * DAYANJING v4 — 20_packer / flatten.c
 *
 * 控制流扁平化核心。设计依据见 include/flatten.h。
 *
 * 发射的每条指令都在此文件内联编码，不依赖外部汇编器与任何库。
 */

#include "flatten.h"

#include <stdlib.h>
#include <string.h>

/* ============================ 伪随机 ============================ */
/*
 * 自带 xorshift64，不用 rand()：rand() 是进程全局状态，会被调用方其它
 * 代码推进，同种子不可复现，分布也就无法断言。
 */
static uint64_t xs64(uint64_t *s)
{
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    return x;
}

static uint32_t rnd(uint64_t *s, uint32_t n)
{
    return n ? (uint32_t)(xs64(s) % n) : 0;
}

/* ============================ 发射缓冲 ============================ */

#define EB_MIN 4096

typedef struct {
    uint8_t *b;
    size_t   n;
    size_t   cap;
    int      oom;
} eb;

static void eb_init(eb *e)
{
    e->cap = EB_MIN;
    e->n   = 0;
    e->oom = 0;
    e->b   = (uint8_t *)malloc(e->cap);
    if (!e->b) { e->oom = 1; e->cap = 0; }
}

static void eb_free(eb *e)
{
    free(e->b);
    e->b = NULL;
    e->n = e->cap = 0;
}

static int eb_need(eb *e, size_t k)
{
    if (e->oom) return 0;
    if (e->n + k <= e->cap) return 1;
    size_t nc = e->cap ? e->cap : EB_MIN;
    while (nc < e->n + k) {
        if (nc > (size_t)-1 / 2) { e->oom = 1; return 0; }
        nc *= 2;
    }
    uint8_t *nb = (uint8_t *)realloc(e->b, nc);
    if (!nb) { e->oom = 1; return 0; }
    e->b   = nb;
    e->cap = nc;
    return 1;
}

static void eb_bytes(eb *e, const uint8_t *p, size_t k)
{
    if (!eb_need(e, k)) return;
    memcpy(e->b + e->n, p, k);
    e->n += k;
}

static void eb1(eb *e, uint8_t v)
{
    if (!eb_need(e, 1)) return;
    e->b[e->n++] = v;
}

static void eb32(eb *e, uint32_t v)
{
    if (!eb_need(e, 4)) return;
    e->b[e->n + 0] = (uint8_t)(v & 0xff);
    e->b[e->n + 1] = (uint8_t)((v >> 8) & 0xff);
    e->b[e->n + 2] = (uint8_t)((v >> 16) & 0xff);
    e->b[e->n + 3] = (uint8_t)((v >> 24) & 0xff);
    e->n += 4;
}

static void patch32(eb *e, size_t off, uint32_t v)
{
    if (e->oom || off + 4 > e->n) return;
    e->b[off + 0] = (uint8_t)(v & 0xff);
    e->b[off + 1] = (uint8_t)((v >> 8) & 0xff);
    e->b[off + 2] = (uint8_t)((v >> 16) & 0xff);
    e->b[off + 3] = (uint8_t)((v >> 24) & 0xff);
}

/* ============================ 指令发射 ============================ */

/* sub rsp, imm8 / imm32 ; add rsp, imm8 / imm32 */
static void i_sub_rsp_i8(eb *e, uint8_t imm)  { eb1(e,0x48); eb1(e,0x83); eb1(e,0xec); eb1(e,imm); }
static void i_add_rsp_i8(eb *e, uint8_t imm)  { eb1(e,0x48); eb1(e,0x83); eb1(e,0xc4); eb1(e,imm); }
static void i_sub_rsp_i32(eb *e, uint32_t imm){ eb1(e,0x48); eb1(e,0x81); eb1(e,0xec); eb32(e,imm); }
static void i_add_rsp_i32(eb *e, uint32_t imm){ eb1(e,0x48); eb1(e,0x81); eb1(e,0xc4); eb32(e,imm); }
/* lea rsp, [rsp + d8] */
static void i_lea_rsp_d8(eb *e, int8_t d)     { eb1(e,0x48); eb1(e,0x8d); eb1(e,0x64); eb1(e,0x24); eb1(e,(uint8_t)d); }
static void i_ret(eb *e)                      { eb1(e,0xc3); }

/* mov eax, [rsp+d8] / mov [rsp+d8], eax / mov dword [rsp+d8], imm32 */
static void i_mov_eax_mrsp(eb *e, uint8_t d)
{ eb1(e,0x8b); eb1(e,0x44); eb1(e,0x24); eb1(e,d); }
static void i_mov_mrsp_eax(eb *e, uint8_t d)
{ eb1(e,0x89); eb1(e,0x44); eb1(e,0x24); eb1(e,d); }
static void i_mov_mrsp_imm32(eb *e, uint8_t d, uint32_t imm)
{ eb1(e,0xc7); eb1(e,0x44); eb1(e,0x24); eb1(e,d); eb32(e,imm); }

/* cmp eax, imm32 / xor eax, imm32 / add eax, imm32 / mov eax, imm32 */
static void i_cmp_eax_imm32(eb *e, uint32_t imm) { eb1(e,0x3d); eb32(e,imm); }
static void i_xor_eax_imm32(eb *e, uint32_t imm) { eb1(e,0x35); eb32(e,imm); }
static void i_add_eax_imm32(eb *e, uint32_t imm) { eb1(e,0x05); eb32(e,imm); }
static void i_mov_eax_imm32(eb *e, uint32_t imm) { eb1(e,0xb8); eb32(e,imm); }

/* not eax / bswap eax / imul eax, imm32 */
static void i_not_eax(eb *e)   { eb1(e,0xf7); eb1(e,0xd0); }
static void i_bswap_eax(eb *e) { eb1(e,0x0f); eb1(e,0xc8); }
static void i_imul_eax_imm32(eb *e, uint32_t imm)
{ eb1(e,0x69); eb1(e,0xc0); eb32(e,imm); }

/*
 * je/jz rel32 (0f 84) ; jmp rel32 (e9)。
 * 返回的是 rel32 字段自身的偏移，不是指令起始偏移——回填公式一律按
 * "rel32 字段结束 == 指令结束" 计算 rel = target - (at + 4)。
 * 若返回指令起始，jcc 会差 2 字节、jmp 会差 1 字节，跳转目标全部错位。
 */
static size_t i_jcc32(eb *e, uint8_t op2)
{
    eb1(e, 0x0f);
    eb1(e, op2);
    size_t at = e->n;   /* rel32 字段 */
    eb32(e, 0);
    return at;
}

static size_t i_jmp32(eb *e)
{
    eb1(e, 0xe9);
    size_t at = e->n;   /* rel32 字段 */
    eb32(e, 0);
    return at;
}

/* lea ecx, [rax+1] */
static void i_lea_ecx_rax1(eb *e)
{ eb1(e,0x8d); eb1(e,0x48); eb1(e,0x01); }

/* imul eax, ecx */
static void i_imul_eax_ecx(eb *e)
{ eb1(e,0x0f); eb1(e,0xaf); eb1(e,0xc1); }

/* test eax, 1 */
static void i_test_eax_1(eb *e)
{ eb1(e,0xa8); eb1(e,0x01); }

/* 多字节 nop 垫：0f 1f 44 00 00 */
static void i_nop5(eb *e)
{ eb1(e,0x0f); eb1(e,0x1f); eb1(e,0x44); eb1(e,0x00); eb1(e,0x00); }

/*
 * 入口 nop 垫。三种拆帧变体都以 REX.W(0x48) 开头，不垫的话首字节在所有
 * 构建中恒定——那就是一条可直接匹配制品入口的签名。垫之后首字节取值数 >= 3。
 */
static void i_nop_pad(eb *e, uint64_t *s)
{
    switch (rnd(s, 4)) {
    case 0: eb1(e,0x90); break;                                        /* nop */
    case 1: eb1(e,0x0f); eb1(e,0x1f); eb1(e,0x00); break;              /* nop dword [rax] */
    case 2: eb1(e,0x66); eb1(e,0x0f); eb1(e,0x1f);
            eb1(e,0x44); eb1(e,0x00); eb1(e,0x00); break;
    default: eb1(e,0x0f); eb1(e,0x1f); eb1(e,0x40); eb1(e,0x00); break;
    }
}

/* ============================ 内部布局 ============================ */

#define FIX_DISP  0
#define FIX_BLK   1
#define FIX_GARB  2
#define FIX_EXIT  3

typedef struct {
    size_t at;   /* rel32 立即数在缓冲中的偏移 */
    int    kind;
    int    idx;
} fix_t;

#define FRAME_SLOTS 8

typedef struct {
    uint8_t  frame;      /* 帧大小（8 的倍数，>= 32） */
    uint8_t  state_d;    /* 状态槽位移（相对 rsp） */
    uint8_t  tmp_d;      /* 临时槽位移 */
    int      prolog_kind;/* 0: sub i8, 1: sub i32, 2: lea d8 */
} layout_t;

/* 生成垃圾体：只碰 eax 与自己的临时槽，不改变任何跨块可见状态 */
static void gen_garbage_body(uint64_t *s, eb *e, const layout_t *L)
{
    switch (rnd(s, 4)) {
    case 0:
        i_mov_eax_imm32(e, (uint32_t)xs64(s));
        i_xor_eax_imm32(e, (uint32_t)xs64(s));
        i_mov_mrsp_eax(e, L->tmp_d);
        break;
    case 1:
        i_mov_eax_imm32(e, (uint32_t)xs64(s));
        i_add_eax_imm32(e, (uint32_t)xs64(s));
        i_not_eax(e);
        i_mov_mrsp_eax(e, L->tmp_d);
        break;
    case 2:
        i_mov_eax_imm32(e, (uint32_t)xs64(s));
        i_imul_eax_imm32(e, (uint32_t)xs64(s));
        i_mov_mrsp_eax(e, L->tmp_d);
        break;
    default:
        i_mov_eax_mrsp(e, L->tmp_d);
        i_bswap_eax(e);
        i_mov_mrsp_eax(e, L->tmp_d);
        break;
    }
    if (rnd(s, 2)) i_nop5(e);
}

/*
 * 不透明谓词守卫：x*(x+1) 对所有整数 x 恒为偶数（x 与 x+1 必有一偶），
 * 故 test eax,1 后 ZF 恒为 1，jz 恒跳转，垃圾体不可达。
 * 32 位溢出不影响最低位，奇偶性保持。
 */
static size_t gen_opaque_guard(uint64_t *s, eb *e)
{
    i_mov_eax_imm32(e, (uint32_t)xs64(s)); /* mov eax, X */
    i_lea_ecx_rax1(e);                     /* lea ecx, [rax+1] */
    i_imul_eax_ecx(e);                     /* imul eax, ecx */
    i_test_eax_1(e);                       /* test eax, 1 */
    return i_jcc32(e, 0x84);               /* jz rel32 -> 真块 */
}

/* ============================ 构建 ============================ */

int fl_build(uint64_t seed, const fl_block *blocks, size_t nblk,
             size_t ngarbage, uint8_t **out, size_t *out_len,
             uint32_t *frame_out)
{
    if (!out || !out_len) return FL_ERR_PARAM;
    *out = NULL;
    *out_len = 0;
    if (frame_out) *frame_out = 0;

    if (!blocks || nblk == 0 || nblk > FL_MAX_BLOCKS) return FL_ERR_PARAM;
    if (ngarbage > FL_MAX_GARBAGE) return FL_ERR_PARAM;

    /* 校验块体与后继；至少需要一个出口 */
    int have_exit = 0;
    for (size_t i = 0; i < nblk; i++) {
        if (blocks[i].len && !blocks[i].code) return FL_ERR_PARAM;
        if (blocks[i].next < -1 || (int64_t)blocks[i].next >= (int64_t)nblk)
            return FL_ERR_PARAM;
        if (blocks[i].next == -1) have_exit = 1;
    }
    if (!have_exit) return FL_ERR_NOEXIT;

    uint64_t s = seed ? seed : 0x9e3779b97f4a7c15ULL;

    /* 真块状态值：互不相同 */
    uint32_t V[FL_MAX_BLOCKS];
    for (size_t i = 0; i < nblk; i++) {
        uint32_t v;
        int ok;
        do {
            v  = (uint32_t)xs64(&s);
            ok = 1;
            for (size_t k = 0; k < i; k++) if (V[k] == v) { ok = 0; break; }
        } while (!ok);
        V[i] = v;
    }

    /* 垃圾块状态值：与所有真块值不同（保证分发器分支不可达），且互不相同 */
    uint32_t G[FL_MAX_GARBAGE];
    for (size_t j = 0; j < ngarbage; j++) {
        uint32_t g;
        int ok;
        do {
            g  = (uint32_t)xs64(&s);
            ok = 1;
            if (g == 0) ok = 0;
            for (size_t k = 0; k < nblk && ok; k++) if (V[k] == g) ok = 0;
            for (size_t k = 0; k < j && ok; k++)    if (G[k] == g) ok = 0;
        } while (!ok);
        G[j] = g;
    }

    /* 帧布局与 prologue 变体（避免前几字节跨构建恒定） */
    layout_t L;
    L.frame       = (uint8_t)(32 + 8 * (int)rnd(&s, FRAME_SLOTS));
    L.prolog_kind = (int)rnd(&s, 3);
    /* 状态槽与临时槽在帧内随机取值，二者不重叠，均 4 对齐且留出余量 */
    uint32_t smax = (uint32_t)(L.frame - 8);
    L.state_d = (uint8_t)(8 + 4 * (int)rnd(&s, (smax - 8) / 4 + 1));
    do {
        L.tmp_d = (uint8_t)(8 + 4 * (int)rnd(&s, (smax - 8) / 4 + 1));
    } while (L.tmp_d == L.state_d);

    /* 物理排列顺序：真块与垃圾块混合后随机打乱 */
    int    nitem = (int)(nblk + ngarbage);
    int    ord[FL_MAX_BLOCKS + FL_MAX_GARBAGE];
    int    isg[FL_MAX_BLOCKS + FL_MAX_GARBAGE];
    for (int i = 0; i < nitem; i++) {
        ord[i] = i;
        isg[i] = (i >= (int)nblk) ? 1 : 0;
    }
    for (int i = nitem - 1; i > 0; i--) {           /* Fisher-Yates */
        int j = (int)rnd(&s, (uint32_t)(i + 1));
        int t = ord[i]; ord[i] = ord[j]; ord[j] = t;
        t = isg[i]; isg[i] = isg[j]; isg[j] = t;
    }

    /* 分发器比较顺序随机 */
    int    dord[FL_MAX_BLOCKS + FL_MAX_GARBAGE];
    int    disg[FL_MAX_BLOCKS + FL_MAX_GARBAGE];
    for (int i = 0; i < nitem; i++) { dord[i] = i; disg[i] = (i >= (int)nblk) ? 1 : 0; }
    for (int i = nitem - 1; i > 0; i--) {
        int j = (int)rnd(&s, (uint32_t)(i + 1));
        int t = dord[i]; dord[i] = dord[j]; dord[j] = t;
        t = disg[i]; disg[i] = disg[j]; disg[j] = t;
    }

    eb e;
    eb_init(&e);
    if (e.oom) return FL_ERR_MEM;

    size_t maxfix = 2 * (size_t)nitem + nblk + ngarbage + 4;
    fix_t *fix = (fix_t *)calloc(maxfix ? maxfix : 1, sizeof(fix_t));
    if (!fix) { eb_free(&e); return FL_ERR_MEM; }
    size_t nfix = 0;

    size_t blk_off[FL_MAX_BLOCKS];
    size_t garb_off[FL_MAX_GARBAGE];
    memset(blk_off, 0, sizeof(blk_off));
    memset(garb_off, 0, sizeof(garb_off));

    /* ---- prologue ---- */
    {
        int npad = (int)rnd(&s, 4);
        for (int i = 0; i < npad; i++) i_nop_pad(&e, &s);
    }
    switch (L.prolog_kind) {
    case 0: i_sub_rsp_i8(&e, L.frame); break;
    case 1: i_sub_rsp_i32(&e, L.frame); break;
    default: i_lea_rsp_d8(&e, (int8_t)(-(int)L.frame)); break;
    }
    i_mov_mrsp_imm32(&e, L.state_d, V[0]);   /* state = V_entry */

    /* ---- dispatcher ---- */
    size_t disp_off = e.n;
    for (int k = 0; k < nitem; k++) {
        int    idx = dord[k];
        uint32_t val = disg[k] ? G[idx - (int)nblk] : V[idx];
        i_mov_eax_mrsp(&e, L.state_d);
        i_cmp_eax_imm32(&e, val);
        fix[nfix].at   = i_jcc32(&e, 0x84);
        fix[nfix].kind = disg[k] ? FIX_GARB : FIX_BLK;
        fix[nfix].idx  = disg[k] ? idx - (int)nblk : idx;
        nfix++;
    }
    fix[nfix].at = i_jmp32(&e);
    fix[nfix].kind = FIX_EXIT;
    fix[nfix].idx  = 0;
    nfix++;

    /* ---- 块体（物理顺序随机） ---- */
    for (int k = 0; k < nitem; k++) {
        int idx = ord[k];
        if (!isg[k]) {
            blk_off[idx] = e.n;
            if (blocks[idx].len)
                eb_bytes(&e, blocks[idx].code, blocks[idx].len);
            if (blocks[idx].next == -1) {
                fix[nfix].at = i_jmp32(&e);
                fix[nfix].kind = FIX_EXIT;
                fix[nfix].idx  = 0;
                nfix++;
            } else {
                /* state ^= V[idx] ^ V[next] */
                i_mov_eax_mrsp(&e, L.state_d);
                i_xor_eax_imm32(&e, V[idx] ^ V[blocks[idx].next]);
                i_mov_mrsp_eax(&e, L.state_d);
                fix[nfix].at = i_jmp32(&e);
                fix[nfix].kind = FIX_DISP;
                fix[nfix].idx  = 0;
                nfix++;
            }
        } else {
            int gi = idx - (int)nblk;
            garb_off[gi] = e.n;
            /* 不透明谓词：恒真跳转到一个随机真块，垃圾体不可达 */
            fix[nfix].at   = gen_opaque_guard(&s, &e);
            fix[nfix].kind = FIX_BLK;
            fix[nfix].idx  = (int)rnd(&s, (uint32_t)nblk);
            nfix++;
            gen_garbage_body(&s, &e, &L);
            i_mov_eax_mrsp(&e, L.state_d);
            i_xor_eax_imm32(&e, G[gi] ^ V[(int)rnd(&s, (uint32_t)nblk)]);
            i_mov_mrsp_eax(&e, L.state_d);
            fix[nfix].at = i_jmp32(&e);
            fix[nfix].kind = FIX_DISP;
            fix[nfix].idx  = 0;
            nfix++;
        }
    }

    /* ---- exit ---- */
    size_t exit_off = e.n;
    switch (L.prolog_kind) {
    case 0: i_add_rsp_i8(&e, L.frame); break;
    case 1: i_add_rsp_i32(&e, L.frame); break;
    default: i_lea_rsp_d8(&e, (int8_t)L.frame); break;
    }
    i_ret(&e);

    if (e.oom) { free(fix); eb_free(&e); return FL_ERR_MEM; }

    /* ---- 回填所有 rel32 ---- */
    for (size_t k = 0; k < nfix; k++) {
        size_t target;
        switch (fix[k].kind) {
        case FIX_DISP: target = disp_off; break;
        case FIX_BLK:  target = blk_off[fix[k].idx]; break;
        case FIX_GARB: target = garb_off[fix[k].idx]; break;
        default:       target = exit_off; break;
        }
        int64_t rel = (int64_t)target - (int64_t)(fix[k].at + 4);
        if (rel < INT32_MIN || rel > INT32_MAX) {
            free(fix); eb_free(&e); return FL_ERR_TOOBIG;
        }
        patch32(&e, fix[k].at, (uint32_t)(int32_t)rel);
    }
    free(fix);

    *out     = e.b;
    *out_len = e.n;
    if (frame_out) *frame_out = (uint32_t)L.frame;
    e.b = NULL;
    eb_free(&e);
    return FL_OK;
}

const char *fl_strerror(int rc)
{
    switch (rc) {
    case FL_OK:          return "ok";
    case FL_ERR_PARAM:   return "bad parameter";
    case FL_ERR_MEM:     return "out of memory";
    case FL_ERR_TOOBIG:  return "code too large for rel32";
    case FL_ERR_NOEXIT:  return "no block terminates at exit";
    default:             return "unknown";
    }
}
