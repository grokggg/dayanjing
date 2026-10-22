/* DAYANJING v4 — 25_deploy / tests/test_pic.c
 *
 * PIC 载荷投递路径的端到端验证。
 *
 * 验证的不是一个函数能跑，而是整条链：
 *   PIC 载荷 → poly 存根包裹（扁平化开启）→ 分块 → 内存组装 → 映射执行
 *
 * 载荷做成"可观测"的，而不是只返回一个退出码：
 *   它向 stdout 写 "OK\n" 再 exit(42)。父进程同时校验字节内容与退出码。
 *   只验退出码是不够的——万一存根本没跳、进程因别的原因以 42 退出，
 *   单看退出码会把"没执行"误判成"执行成功"。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "drop.h"
#include "poly.h"

static int pass_cnt = 0, fail_cnt = 0;

#define CHECK(cond, ...) do {                       \
    if (cond) { printf("[PASS] "); pass_cnt++; }    \
    else      { printf("[FAIL] "); fail_cnt++; }    \
    printf(__VA_ARGS__); printf("\n");              \
} while (0)

/*
 * PIC 载荷（位置无关，17 字节 syscall write 段 + exit）：
 *     sub  rsp, 16
 *     mov  dword [rsp], "OK\n"
 *     mov  rax, 1            ; SYS_write
 *     mov  rdi, 1            ; fd = stdout
 *     mov  rsi, rsp
 *     mov  rdx, 3
 *     syscall
 *     mov  rax, 60           ; SYS_exit
 *     mov  rdi, 42
 *     syscall
 */
static const uint8_t PIC_PAYLOAD[] = {
    0x48, 0x83, 0xec, 0x10,                   /* sub rsp,16            */
    0xc7, 0x04, 0x24, 0x4f, 0x4b, 0x0a, 0x00, /* mov dword[rsp],"OK\n" */
    0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, /* mov rax,1             */
    0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, /* mov rdi,1             */
    0x48, 0x89, 0xe6,                         /* mov rsi,rsp           */
    0x48, 0xc7, 0xc2, 0x03, 0x00, 0x00, 0x00, /* mov rdx,3             */
    0x0f, 0x05,                               /* syscall               */
    0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, /* mov rax,60            */
    0x48, 0xc7, 0xc7, 0x2a, 0x00, 0x00, 0x00, /* mov rdi,42            */
    0x0f, 0x05                                /* syscall               */
};

/* 用一条管道接住子进程 stdout，返回退出码。
   管道必须在此处创建并由父进程读；若让子进程继承调用方的 stdout，
   调用方会一直等到所有写端关闭才返回 EOF——那正是"命令莫名挂起"的来源。 */
typedef struct { int code; char out[256]; size_t olen; } runres;

static runres run_in_child(const uint8_t *blob, size_t blen, uint32_t csize)
{
    runres r; memset(&r, 0, sizeof(r)); r.code = -999;

    int pfd[2];
    if (pipe(pfd) != 0) return r;

    dp_manifest_t m;
    if (dp_manifest_build(blob, blen, csize, &m) != DP_OK) {
        close(pfd[0]); close(pfd[1]); return r;
    }

    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return r; }

    if (pid == 0) {
        close(pfd[0]);
        dup2(pfd[1], STDOUT_FILENO);
        close(pfd[1]);

        dp_asm_t a;
        if (dp_asm_init(&a, &m) != DP_OK) _exit(200);
        for (uint32_t i = 0; i < m.nchunks; i++) {
            const uint8_t *c; size_t cl;
            if (dp_chunk_get(blob, blen, &m, i, &c, &cl) != DP_OK) _exit(201);
            int rc = dp_asm_put(&a, i, c, cl);
            if (rc != DP_OK && rc != DP_ERR_DUP) _exit(202);
        }
        if (dp_asm_seal(&a) != DP_OK) _exit(203);
        dp_asm_exec_pic(&a);          /* 载荷终结进程时不返回 */
        dp_asm_free(&a);
        _exit(204);                    /* 走到这里说明载荷没终结进程 */
    }

    close(pfd[1]);
    ssize_t n;
    while ((n = read(pfd[0], r.out + r.olen, sizeof(r.out) - 1 - r.olen)) > 0)
        r.olen += (size_t)n;
    r.out[r.olen] = '\0';
    close(pfd[0]);

    int st = 0;
    if (waitpid(pid, &st, 0) == pid) {
        if (WIFEXITED(st)) r.code = WEXITSTATUS(st);
        else               r.code = -WTERMSIG(st);   /* 被信号终结记为负 */
    }
    return r;
}

int main(void)
{
    /* ---- 1. 扁平化真的被启用（否则后面全是在测线性存根） ---- */
    {
        poly_ctx *p0 = poly_new(0x1111);
        poly_ctx *p1 = poly_new(0x1111);
        poly_set_flatten(p1, 1);
        CHECK(poly_flatten(p0) == 0 && poly_flatten(p1) == 1,
              "扁平化开关：默认关闭 / 显式开启");

        uint8_t *o0 = NULL, *o1 = NULL; size_t l0 = 0, l1 = 0;
        int rc0 = poly_build(p0, PIC_PAYLOAD, sizeof(PIC_PAYLOAD), &o0, &l0);
        int rc1 = poly_build(p1, PIC_PAYLOAD, sizeof(PIC_PAYLOAD), &o1, &l1);
        CHECK(rc0 == POLY_OK && rc1 == POLY_OK, "两种模式均构建成功");
        CHECK(l1 > l0, "扁平化存根更大：%zu > %zu（证明引擎真被调用）", l1, l0);
        free(o0); free(o1);
        poly_free(p0); poly_free(p1);
    }

    /* ---- 2. 完整链路：包裹 → 分块 → 组装 → 执行 ---- */
    {
        poly_ctx *p = poly_new(0x2222);
        poly_set_flatten(p, 1);
        uint8_t *blob = NULL; size_t blen = 0;
        int rc = poly_build(p, PIC_PAYLOAD, sizeof(PIC_PAYLOAD), &blob, &blen);
        CHECK(rc == POLY_OK, "PIC 载荷包裹成功（%zu 字节）", blen);

        runres r = run_in_child(blob, blen, 4096);
        CHECK(r.code == 42, "PIC 载荷经分块投递后执行：退出码 %d（期望 42）", r.code);
        CHECK(r.olen >= 3 && memcmp(r.out, "OK\n", 3) == 0,
              "载荷向 stdout 写入了 \"OK\\n\"（实测 %zu 字节）", r.olen);

        free(blob); poly_free(p);
    }

    /* ---- 3. 负向对照：篡改密文一字节后不得再跑出正确结果 ---- */
    {
        poly_ctx *p = poly_new(0x3333);
        uint8_t *blob = NULL; size_t blen = 0;
        poly_build(p, PIC_PAYLOAD, sizeof(PIC_PAYLOAD), &blob, &blen);

        size_t stub_len = 0, gap_len = 0, ct_off = 0;
        poly_last_span(p, &stub_len, &gap_len, &ct_off);
        CHECK(ct_off > 0 && ct_off < blen, "密文偏移定位：%zu（总长 %zu）",
              ct_off, blen);

        blob[ct_off] ^= 0xff;   /* 传输损坏 / 投毒的最典型形态 */

        runres r = run_in_child(blob, blen, 4096);
        int ok_out = (r.olen >= 3 && memcmp(r.out, "OK\n", 3) == 0);
        CHECK(!(r.code == 42 && ok_out),
              "篡改一字节后不再跑出正确结果（退出码 %d，输出 %zu 字节）",
              r.code, r.olen);

        free(blob); poly_free(p);
    }

    /* ---- 4. 未 seal 绝不执行 ---- */
    {
        dp_asm_t a;
        dp_manifest_t m;
        uint8_t blob[100];
        memset(blob, 0x41, sizeof(blob));
        dp_manifest_build(blob, sizeof(blob), 32, &m);
        dp_asm_init(&a, &m);
        dp_asm_put(&a, 0, blob, 32);
        int rc = dp_asm_exec_pic(&a);
        CHECK(rc == DP_ERR_INCOMPLETE, "未收齐时拒绝执行（rc=%d）", rc);
        dp_asm_free(&a);
    }

    /* ---- 5. 跨构建无恒定字节（制品级签名） ---- */
    {
        int nconst = 0, best = 0, run = 0;
        const int N = 20;
        size_t win = 256;
        uint8_t **s = calloc(N, sizeof(*s));
        size_t *sl = calloc(N, sizeof(size_t));
        size_t minlen = (size_t)-1;

        for (int i = 0; i < N; i++) {
            poly_ctx *p = poly_new(0x1000 + (uint64_t)i * 7919u);
            poly_set_flatten(p, 1);
            poly_build(p, PIC_PAYLOAD, sizeof(PIC_PAYLOAD), &s[i], &sl[i]);
            if (sl[i] < minlen) minlen = sl[i];
            poly_free(p);
        }
        if (win > minlen) win = minlen;

        for (size_t o = 0; o < win; o++) {
            int k = 0, seen[256]; memset(seen, 0, sizeof(seen));
            for (int i = 0; i < N; i++)
                if (!seen[s[i][o]]) { seen[s[i][o]] = 1; k++; }
            if (k == 1) { nconst++; run++; if (run > best) best = run; }
            else run = 0;
        }
        CHECK(nconst == 0, "跨 %d 构建前 %zu 字节无恒定偏移（恒定=%d，最长游程=%d）",
              N, win, nconst, best);

        for (int i = 0; i < N; i++) free(s[i]);
        free(s); free(sl);
    }

    printf("\n=== result: %d pass, %d fail ===\n", pass_cnt, fail_cnt);
    return fail_cnt ? 1 : 0;
}
