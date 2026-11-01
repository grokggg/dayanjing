/* DAYANJING v4 — 25_deploy / tests/test_deploy_pack.c
 *
 * 验证「产出路径」而不是「库」。
 *
 * 此前 poly_set_flatten 只在测试里被调用过，deploy_pack 从未使用它 ——
 * 已建好的能力不进产出物，等于没有。这个测试把产出工具本身当被测对象：
 *   fork/exec deploy_pack 产出制品 → 读回 → 真实映射执行 → 校验结果
 *
 * 校验的是可观测行为，不是退出码：载荷向 stdout 写 "OK\n" 再 exit(42)。
 * 只验退出码不够——存根若没跳转，进程也可能因别的原因以 42 退出。
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
 * PIC 载荷：向 stdout 写 "OK\n" 后 exit(42)。
 * 与 test_pic.c 中的载荷相同（两者独立维护，避免共用头带来耦合）。
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

typedef struct { int code; size_t olen; char out[256]; } runres;

/* 走完整投递链：manifest → 逐块组装 → seal → 映射执行。
   在子进程执行：载荷会 exit(42) 终结进程。
   用管道接住 stdout —— 若让子进程继承调用方的 stdout，调用方会等到
   所有写端关闭才返回 EOF，那正是"命令莫名挂起"的来源。

   tamper >= 0 表示"第 tamper 块在传输中被改"。注意 manifest 必须按原始
   blob 计算：若先篡改再算 manifest，digest 是对篡改后内容算的，必然自洽，
   seal 会顺利通过 —— 那样测出来的是"篡改无影响"的假结论。 */
static runres run_blob(const uint8_t *blob, size_t blen, int tamper)
{
    runres r; memset(&r, 0, sizeof(r)); r.code = -999;

    dp_manifest_t m;
    if (dp_manifest_build(blob, blen, 4096, &m) != DP_OK) return r;

    int fds[2];
    if (pipe(fds) != 0) return r;

    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return r; }

    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        close(fds[1]);

        dp_asm_t a;
        if (dp_asm_init(&a, &m) != DP_OK) _exit(200);
        for (uint32_t i = 0; i < m.nchunks; i++) {
            const uint8_t *c; size_t cl;
            if (dp_chunk_get(blob, blen, &m, i, &c, &cl) != DP_OK) _exit(201);

            if (tamper >= 0 && (int)i == tamper && cl > 0) {
                uint8_t *t = malloc(cl);
                if (!t) _exit(205);
                memcpy(t, c, cl);
                t[cl / 2] ^= 0x40;              /* 传输中被改了一个字节 */
                int rc = dp_asm_put(&a, i, t, cl);
                free(t);
                if (rc != DP_OK && rc != DP_ERR_DUP) _exit(202);
                continue;
            }

            int rc = dp_asm_put(&a, i, c, cl);
            if (rc != DP_OK && rc != DP_ERR_DUP) _exit(202);
        }
        if (dp_asm_seal(&a) != DP_OK) _exit(203);
        dp_asm_exec_pic(&a);          /* 载荷终结进程时不返回 */
        dp_asm_free(&a);
        _exit(204);                   /* 走到这里说明载荷没终结进程 */
    }

    close(fds[1]);
    ssize_t n;
    while ((n = read(fds[0], r.out + r.olen, sizeof(r.out) - 1 - r.olen)) > 0)
        r.olen += (size_t)n;
    r.out[r.olen] = '\0';
    close(fds[0]);

    int st = 0;
    if (waitpid(pid, &st, 0) == pid) {
        if (WIFEXITED(st)) r.code = WEXITSTATUS(st);
        else               r.code = -WTERMSIG(st);
    }
    return r;
}

/* 调用产出工具本身。返回 0 表示工具成功退出。 */
static int run_pack(const char *in, const char *out, const char *extra)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "./build/deploy_pack %s %s %s > /dev/null 2>&1",
             in, out, extra ? extra : "");
    return system(cmd) == 0 ? 0 : -1;
}

static int write_tmp(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t w = fwrite(buf, 1, len, f);
    fclose(f);
    return w == len ? 0 : -1;
}

static uint8_t *read_tmp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return NULL; }
    rewind(f);
    uint8_t *b = malloc((size_t)sz);
    if (!b) { fclose(f); return NULL; }
    if (fread(b, 1, (size_t)sz, f) != (size_t)sz) { fclose(f); free(b); return NULL; }
    fclose(f);
    *len = (size_t)sz;
    return b;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);   /* 崩溃时也能看到已输出内容 */

    const char *pay  = "/tmp/tdp_payload.bin";
    const char *fl   = "/tmp/tdp_flat.poly";
    const char *lin  = "/tmp/tdp_lin.poly";

    if (write_tmp(pay, PIC_PAYLOAD, sizeof(PIC_PAYLOAD)) != 0) {
        printf("[FAIL] 无法写入临时载荷\n");
        return 2;
    }

    /* ---- 1. 扁平化真的进了产出物 ---- */
    size_t flen = 0, llen = 0;
    {
        CHECK(run_pack(pay, fl, "--pic") == 0, "产出 PIC 制品（扁平化开启）");
        CHECK(run_pack(pay, lin, "--pic --no-flatten") == 0, "产出 PIC 制品（扁平化关闭）");

        uint8_t *fb = read_tmp(fl, &flen);
        uint8_t *lb = read_tmp(lin, &llen);
        CHECK(fb != NULL && lb != NULL, "两份制品均可读回");
        if (fb && lb) {
            CHECK(flen > llen, "扁平化存根更大：%zu > %zu（证明引擎真被调用，"
                  "而非开关返回成功）", flen, llen);
            CHECK(memcmp(fb, lb, flen < llen ? flen : llen) != 0,
                  "两种模式产出不同字节");
        }
        free(fb); free(lb);
    }

    /* ---- 2. 产出物真的能执行 ---- */
    {
        uint8_t *fb = read_tmp(fl, &flen);
        if (fb) {
            runres r = run_blob(fb, flen, -1);
            CHECK(r.code == 42, "扁平化制品执行：退出码 %d（期望 42）", r.code);
            CHECK(r.olen >= 3 && memcmp(r.out, "OK\n", 3) == 0,
                  "载荷写出 \"OK\\n\"（实测 %zu 字节）", r.olen);
        }
        free(fb);

        uint8_t *lb = read_tmp(lin, &llen);
        if (lb) {
            runres r = run_blob(lb, llen, -1);
            CHECK(r.code == 42, "线性存根制品执行：退出码 %d（期望 42）", r.code);
        }
        free(lb);
    }

    /* ---- 3. 负向：篡改一字节后不得再跑出正确结果 ---- */
    {
        uint8_t *fb = read_tmp(fl, &flen);
        if (fb && flen > 8) {
            runres r = run_blob(fb, flen, 0);
            CHECK(!(r.code == 42 && r.olen >= 3 && memcmp(r.out, "OK\n", 3) == 0),
                  "传输中篡改第 0 块后不再跑出正确结果（code=%d out=%zu）",
                  r.code, r.olen);
        }
        free(fb);
    }

    /* ---- 4. 参数校验：错误 ABI 必须失败，不静默回落 ---- */
    {
        CHECK(run_pack(pay, "/tmp/tdp_bad.poly", "--pic --abi bogus") != 0,
              "错误 ABI -> 工具非零退出（不静默回落）");
    }

    printf("\n=== result: %d pass, %d fail ===\n", pass_cnt, fail_cnt);
    return fail_cnt ? 1 : 0;
}
