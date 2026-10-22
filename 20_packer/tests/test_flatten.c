/*
 * DAYANJING v4 — 20_packer / test_flatten.c
 *
 * 控制流扁平化验证。核心是"真机执行"：把生成的代码放进可执行页真实调用，
 * 断言控制流语义、栈平衡、垃圾块不可达。只校验字节的测试证明不了扁平化
 * 是对的——它证明不了生成的东西能跑。
 */

#include "flatten.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(c, msg) do { \
    if (c) { g_pass++; printf("[PASS] %s\n", msg); } \
    else   { g_fail++; printf("[FAIL] %s\n", msg); } \
} while (0)

/* 真机可观测副作用 */
static volatile long g_seq      = 0;   /* 执行序：块 i 执行则 seq = seq*10+(i+1) */
static volatile long g_counter  = 0;   /* 每块 +1 */

static uint64_t g_ptr_seq;
static uint64_t g_ptr_cnt;

/* ============ 块体构造 ============ */

/* seq = seq*10 + (idx+1) */
static size_t emit_seq(uint8_t *b, int idx)
{
    size_t n = 0;
    b[n++] = 0x48; b[n++] = 0xb8;
    memcpy(b + n, &g_ptr_seq, 8); n += 8;        /* movabs rax, &g_seq */
    b[n++] = 0x48; b[n++] = 0x8b; b[n++] = 0x08; /* mov rcx, [rax] */
    b[n++] = 0x48; b[n++] = 0x6b; b[n++] = 0xc9; /* imul rcx, rcx, */
    b[n++] = 0x0a;
    b[n++] = 0x48; b[n++] = 0x83; b[n++] = 0xc1; /* add rcx, */
    b[n++] = (uint8_t)(idx + 1);
    b[n++] = 0x48; b[n++] = 0x89; b[n++] = 0x08; /* mov [rax], rcx */
    return n;
}

/* counter++ */
static size_t emit_inc(uint8_t *b)
{
    size_t n = 0;
    b[n++] = 0x48; b[n++] = 0xb8;
    memcpy(b + n, &g_ptr_cnt, 8); n += 8;        /* movabs rax, &g_counter */
    b[n++] = 0x48; b[n++] = 0x83; b[n++] = 0x00; /* add qword [rax], */
    b[n++] = 0x01;
    return n;
}

/* 块 i：seq 追加 + counter++ */
static size_t emit_block(uint8_t *b, int idx)
{
    size_t n = emit_seq(b, idx);
    n += emit_inc(b + n);
    return n;
}

/* ============ 执行 ============ */

typedef void (*fn_t)(void);

static void *code_load(const uint8_t *code, size_t len)
{
    long ps = sysconf(_SC_PAGESIZE);
    size_t need = ((len + (size_t)ps - 1) / (size_t)ps) * (size_t)ps;
    void *p = mmap(NULL, need, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    memcpy(p, code, len);
    if (mprotect(p, need, PROT_READ | PROT_EXEC) != 0) {
        munmap(p, need);
        return NULL;
    }
    return p;
}

/*
 * 在 W^X 页面上打断点：临时加 PROT_WRITE，写完立刻收回。
 * 直接写会因为页面已切到 READ|EXEC 而 SIGSEGV。
 */
static int code_patch8(void *p, size_t len, size_t off, uint8_t v)
{
    long ps = sysconf(_SC_PAGESIZE);
    size_t need = ((len + (size_t)ps - 1) / (size_t)ps) * (size_t)ps;
    if (mprotect(p, need, PROT_READ | PROT_WRITE) != 0) return -1;
    ((uint8_t *)p)[off] = v;
    if (mprotect(p, need, PROT_READ | PROT_EXEC) != 0) return -1;
    return 0;
}

static uint64_t get_rsp(void)
{
    uint64_t v;
    __asm__ volatile("mov %%rsp, %0" : "=r"(v));
    return v;
}

/*
 * void* -> 函数指针。直接强转在 -Wpedantic 下是 ISO C 禁止的转换；
 * 用 memcpy 搬运位模式，既不触发告警也不违反严格别名。
 */
static void code_call(void *p)
{
    fn_t f;
    memcpy(&f, &p, sizeof(f));
    f();
}

/* ============ 用例 ============ */

static void t_param(void)
{
    uint8_t *out = NULL; size_t olen = 0;
    uint8_t body[32];
    size_t  bl = emit_block(body, 0);
    fl_block b1 = { body, bl, -1 };

    CHECK(fl_build(1, NULL, 1, 0, &out, &olen, NULL) == FL_ERR_PARAM, "NULL blocks -> PARAM");
    CHECK(fl_build(1, &b1, 0, 0, &out, &olen, NULL) == FL_ERR_PARAM, "nblk=0 -> PARAM");
    CHECK(fl_build(1, &b1, FL_MAX_BLOCKS + 1, 0, &out, &olen, NULL) == FL_ERR_PARAM,
          "nblk 超上限 -> PARAM");
    CHECK(fl_build(1, &b1, 1, FL_MAX_GARBAGE + 1, &out, &olen, NULL) == FL_ERR_PARAM,
          "ngarbage 超上限 -> PARAM");
    CHECK(fl_build(1, &b1, 1, 0, NULL, &olen, NULL) == FL_ERR_PARAM, "NULL out -> PARAM");

    fl_block bad = { body, bl, 5 };           /* next 越界 */
    CHECK(fl_build(1, &bad, 1, 0, &out, &olen, NULL) == FL_ERR_PARAM, "next 越界 -> PARAM");

    fl_block loop = { body, bl, 0 };          /* 自环，无出口 */
    CHECK(fl_build(1, &loop, 1, 0, &out, &olen, NULL) == FL_ERR_NOEXIT, "无出口 -> NOEXIT");

    fl_block nocode = { NULL, 16, -1 };       /* len>0 但 code 为空 */
    CHECK(fl_build(1, &nocode, 1, 0, &out, &olen, NULL) == FL_ERR_PARAM, "code 空 -> PARAM");
}

/* 非物理顺序：0 -> 2 -> 1 -> exit，seq 应为 132 */
static void t_reorder(void)
{
    uint8_t b0[64], b1[64], b2[64];
    size_t  l0 = emit_block(b0, 0), l1 = emit_block(b1, 1), l2 = emit_block(b2, 2);
    fl_block blocks[3] = {
        { b0, l0, 2 },
        { b1, l1, -1 },
        { b2, l2, 1 },
    };

    uint8_t *out = NULL; size_t olen = 0;
    int rc = fl_build(0xC0FFEE01ULL, blocks, 3, 4, &out, &olen, NULL);
    CHECK(rc == FL_OK && out && olen > 0, "构建成功（3 真块 + 4 垃圾块）");
    if (rc != FL_OK) return;

    void *p = code_load(out, olen);
    CHECK(p != NULL, "代码页可执行映射成功");
    if (!p) { free(out); return; }

    g_seq = 0; g_counter = 0;
    uint64_t before = get_rsp();
    code_call(p);
    uint64_t after = get_rsp();

    CHECK(before == after, "rsp 平衡（进入前后相同）");
    CHECK(g_seq == 132, "执行序 == 132（0->2->1，非物理顺序）");
    CHECK(g_counter == 3, "每块各执行一次（counter==3）");

    munmap(p, ((olen + 4095) / 4096) * 4096);
    free(out);
}

/* 线性顺序 + 空块体 */
static void t_linear(void)
{
    uint8_t b0[64], b2[64];
    size_t  l0 = emit_block(b0, 0), l2 = emit_block(b2, 2);
    fl_block blocks[3] = {
        { b0, l0, 1 },
        { NULL, 0, 2 },        /* 空块体 */
        { b2, l2, -1 },
    };

    uint8_t *out = NULL; size_t olen = 0;
    int rc = fl_build(0x1234ABCDULL, blocks, 3, 0, &out, &olen, NULL);
    CHECK(rc == FL_OK, "构建成功（含空块体、无垃圾块）");
    if (rc != FL_OK) return;

    void *p = code_load(out, olen);
    if (!p) { free(out); return; }

    g_seq = 0; g_counter = 0;
    code_call(p);

    CHECK(g_seq == 13, "执行序 == 13（空块体不产生副作用）");
    CHECK(g_counter == 2, "counter == 2（空块无自增）");
    CHECK(1, "无垃圾块构建可正常执行到底");

    munmap(p, ((olen + 4095) / 4096) * 4096);
    free(out);
}

/* 多种子真机执行：不崩、语义正确、栈平衡 */
static void t_many_seeds(void)
{
    uint8_t b0[64], b1[64], b2[64], b3[64];
    size_t l0 = emit_block(b0, 0), l1 = emit_block(b1, 1);
    size_t l2 = emit_block(b2, 2), l3 = emit_block(b3, 3);
    fl_block blocks[4] = {
        { b0, l0, 3 },
        { b1, l1, 0 },
        { b2, l2, 1 },
        { b3, l3, -1 },
    };
    /* 期望序：0 -> 3 -> exit ? 不：0->3, 3->exit。故 seq = 14 */
    int bad_seq = 0, bad_sp = 0, bad_rc = 0;

    for (int t = 0; t < 300; t++) {
        uint8_t *out = NULL; size_t olen = 0;
        int rc = fl_build(0x5EED0000ULL + (uint64_t)t * 2654435761u,
                          blocks, 4, 6, &out, &olen, NULL);
        if (rc != FL_OK) { bad_rc++; continue; }
        void *p = code_load(out, olen);
        if (!p) { bad_rc++; free(out); continue; }

        g_seq = 0; g_counter = 0;
        uint64_t before = get_rsp();
        code_call(p);
        uint64_t after = get_rsp();

        if (g_seq != 14)     bad_seq++;
        if (before != after) bad_sp++;

        munmap(p, ((olen + 4095) / 4096) * 4096);
        free(out);
    }
    CHECK(bad_rc  == 0, "300 种子全部构建成功");
    CHECK(bad_seq == 0, "300 种子执行序全部正确");
    CHECK(bad_sp  == 0, "300 种子栈全部平衡");
}

/*
 * 垃圾块不可达的真证明。
 *
 * 不能靠"计数器没加"来证明——垃圾体的代码由 flatten 内部生成，根本不含
 * 计数指令，那种断言平凡成立，等于没测。这里改为在垃圾块入口（不透明谓词
 * 守卫首字节）写入 int3，任何一次到达都会触发 SIGTRAP 并被 siglongjmp 捕获。
 */
static sigjmp_buf g_jb;
static void trap_handler(int sig) { (void)sig; siglongjmp(g_jb, 1); }

/* 守卫模式: b8 imm32 | 8d 48 01 | 0f af c1 | a8 01 | 0f 84 rel32 （共 19 字节） */
static int find_guards(uint8_t *c, size_t n, size_t *out, int cap)
{
    int cnt = 0;
    for (size_t i = 0; i + 19 <= n && cnt < cap; i++) {
        if (c[i] == 0xb8 && c[i + 5] == 0x8d && c[i + 6] == 0x48 && c[i + 7] == 0x01 &&
            c[i + 8] == 0x0f && c[i + 9] == 0xaf && c[i + 10] == 0xc1 &&
            c[i + 11] == 0xa8 && c[i + 12] == 0x01 &&
            c[i + 13] == 0x0f && c[i + 14] == 0x84) {
            out[cnt++] = i;
            i += 18;
        }
    }
    return cnt;
}

static void t_garbage_unreachable(void)
{
    uint8_t b0[64], b1[64];
    size_t  l0 = emit_block(b0, 0), l1 = emit_block(b1, 1);
    fl_block blocks[2] = { { b0, l0, 1 }, { b1, l1, -1 } };

    struct sigaction sa, old;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = trap_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGTRAP, &sa, &old);

    int trapped = 0, checked = 0, found_total = 0, bad_nguard = 0;

    for (int t = 0; t < 40; t++) {
        uint8_t *out = NULL; size_t olen = 0;
        if (fl_build(0x9A9A0000ULL + (uint64_t)t * 7919u, blocks, 2, 5,
                     &out, &olen, NULL) != FL_OK) continue;
        void *p = code_load(out, olen);
        if (!p) { free(out); continue; }

        size_t g[16];
        int ng = find_guards((uint8_t *)p, olen, g, 16);
        if (ng != 5) bad_nguard++;      /* 每个垃圾块一个守卫 */
        found_total += ng;

        for (int i = 0; i < ng; i++) code_patch8(p, olen, g[i], 0xcc);  /* int3 */

        g_seq = 0; g_counter = 0;
        if (sigsetjmp(g_jb, 1) == 0) {
            code_call(p);
        } else {
            trapped = 1;               /* 有垃圾块被真正执行 */
        }
        checked++;
        if (g_seq != 12) { g_fail++; printf("[FAIL] 打断点后执行序异常 seq=%ld\n", (long)g_seq); }

        munmap(p, ((olen + 4095) / 4096) * 4096);
        free(out);
    }

    sigaction(SIGTRAP, &old, NULL);

    CHECK(checked == 40, "40 份构建全部完成 int3 插桩执行");
    CHECK(bad_nguard == 0, "每份构建的守卫数 == 垃圾块数（5）");
    CHECK(found_total == 200, "共定位到 200 个垃圾块入口");
    CHECK(trapped == 0, "全部 int3 均未触发：垃圾块不可达（非平凡证明）");
}

/* 跨构建无恒定字节：扁平化若留签名就白做 */
static void t_no_signature(void)
{
    enum { NS = 200 };
    uint8_t b0[64], b1[64], b2[64];
    size_t l0 = emit_block(b0, 0), l1 = emit_block(b1, 1), l2 = emit_block(b2, 2);
    fl_block blocks[3] = { { b0, l0, 2 }, { b1, l1, -1 }, { b2, l2, 1 } };

    uint8_t *s[NS]; size_t sl[NS];
    size_t minlen = (size_t)-1;
    int built = 0;
    for (int i = 0; i < NS; i++) {
        s[i] = NULL; sl[i] = 0;
        if (fl_build(0xA5A50000ULL + (uint64_t)i * 40503u,
                     blocks, 3, 5, &s[i], &sl[i], NULL) != FL_OK) continue;
        built++;
        if (sl[i] < minlen) minlen = sl[i];
    }
    CHECK(built == NS, "200 份构建全部成功");
    if (built != NS) goto done;

    /* 最长"全构建相同"游程 */
    int maxrun = 0, run = 0;
    for (size_t off = 0; off < minlen; off++) {
        uint8_t v0 = s[0][off];
        int diff = 0;
        for (int i = 1; i < NS; i++) if (s[i][off] != v0) { diff = 1; break; }
        if (!diff) { run++; if (run > maxrun) maxrun = run; }
        else       { run = 0; }
    }
    CHECK(maxrun == 0, "跨 200 构建最长恒定游程 == 0");

    /* 首字节多样性：三种拆帧变体都以 REX.W(48) 开头，靠 nop 垫打散 */
    int distinct0 = 0;
    uint8_t seen[256];
    memset(seen, 0, sizeof(seen));
    for (int i = 0; i < NS; i++) if (!seen[s[i][0]]) { seen[s[i][0]] = 1; distinct0++; }
    CHECK(distinct0 >= 3, "首字节取值数 >= 3（nop 垫生效）");

    /* 长度也要抖动，否则长度本身就是签名 */
    int dlen = 0;
    memset(seen, 0, sizeof(seen));
    for (int i = 0; i < NS; i++) {
        uint8_t k = (uint8_t)(sl[i] & 0xff);
        if (!seen[k]) { seen[k] = 1; dlen++; }
    }
    CHECK(dlen >= 3, "产物长度取值数 >= 3");

done:
    for (int i = 0; i < NS; i++) free(s[i]);
}

int main(void)
{
    g_ptr_seq  = (uint64_t)(uintptr_t)&g_seq;
    g_ptr_cnt  = (uint64_t)(uintptr_t)&g_counter;

    t_param();
    t_reorder();
    t_linear();
    t_many_seeds();
    t_garbage_unreachable();
    t_no_signature();

    printf("=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
