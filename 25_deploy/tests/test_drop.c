/* DAYANJING v4 — 25_deploy / tests/test_drop.c
 *
 * 分块投递通道测试。
 *
 * 分两部分：
 *   A. 核心与 HTTP 层单测（无网络、无进程）
 *   B. 端到端真跑：真实 fork 出 drop_serve 与 drop_stager 两个进程，
 *      经真实回环 TCP 完成"制品分块投递 → 内存组装 → memfd 执行"。
 *
 * 端到端里最关键的一条是执行验证：stager 若成功执行，进程映像被
 * mexec_target 替换，我们会读到 MEXEC_OK；若失败，stager 自己会打印
 * "exec rc=" 并返回 1。两者互斥，不会把"没执行"误判成"执行了"。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "drop.h"
#include "drop_http.h"
#include "packer.h"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, name)                                   \
    do {                                                    \
        if (cond) { printf("[PASS] %s\n", name); g_pass++; } \
        else      { printf("[FAIL] %s\n", name); g_fail++; } \
    } while (0)

static const uint8_t SEED[32] = {
    0x44, 0x41, 0x59, 0x41, 0x4e, 0x4a, 0x49, 0x4e,
    0x47, 0x2d, 0x44, 0x45, 0x50, 0x4c, 0x4f, 0x59,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

/* ================================================================== */
/* A. 核心层                                                          */
/* ================================================================== */

static int gate_allow(uint32_t idx, void *ud) { (void)idx; (void)ud; return 1; }
static int gate_deny(uint32_t idx, void *ud)  { (void)idx; (void)ud; return 0; }

static void test_manifest(void)
{
    uint8_t blob[40000];
    for (size_t i = 0; i < sizeof(blob); i++)
        blob[i] = (uint8_t)(i * 7u + 3u);

    dp_manifest_t m;
    CHECK(dp_manifest_build(blob, sizeof(blob), 16384, &m) == DP_OK,
          "manifest_build 正常");
    CHECK(m.nchunks == 3 && m.total == 40000,
          "块数=3 总长=40000");
    CHECK(dp_manifest_check(&m) == DP_OK, "manifest_check 自洽");

    /* 块数与 total/chunk_size 不自洽 -> 拒绝。
       不自洽会让组装器开出与实际写入量不符的缓冲。 */
    dp_manifest_t bad = m;
    bad.nchunks = 5;
    CHECK(dp_manifest_check(&bad) == DP_ERR_ARG, "块数不自洽 -> ARG");

    CHECK(dp_manifest_build(NULL, 100, 16384, &m) == DP_ERR_ARG, "blob=NULL -> ARG");
    CHECK(dp_manifest_build(blob, 0, 16384, &m) == DP_ERR_ARG, "len=0 -> ARG");
    CHECK(dp_manifest_build(blob, sizeof(blob), 0, &m) == DP_ERR_ARG, "chunk=0 -> ARG");
    CHECK(dp_manifest_build(blob, sizeof(blob), DP_CHUNK_MAX + 1, &m) == DP_ERR_ARG,
          "chunk 超上限 -> ARG");

    /* 超小 chunk 导致块数超上限 -> 拒绝，不静默截断 */
    CHECK(dp_manifest_build(blob, sizeof(blob), 1, &m) == DP_ERR_ARG,
          "块数超上限 -> ARG");
}

static void test_chunk(void)
{
    uint8_t blob[40000];
    memset(blob, 0xAB, sizeof(blob));

    dp_manifest_t m;
    dp_manifest_build(blob, sizeof(blob), 16384, &m);

    const uint8_t *p = NULL;
    size_t len = 0;
    CHECK(dp_chunk_get(blob, sizeof(blob), &m, 0, &p, &len) == DP_OK && len == 16384,
          "取块 0 长度=16384");
    CHECK(dp_chunk_get(blob, sizeof(blob), &m, 2, &p, &len) == DP_OK &&
          len == 40000 - 32768, "末块可短");
    CHECK(dp_chunk_get(blob, sizeof(blob), &m, 3, &p, &len) == DP_ERR_RANGE,
          "块索引越界 -> RANGE");

    /* manifest 与 blob 长度不符 -> 拒绝。
       不校验的话，恶意 manifest 可让服务端读越界。 */
    CHECK(dp_chunk_get(blob, sizeof(blob) - 1, &m, 0, &p, &len) == DP_ERR_ARG,
          "manifest 与 blob 长度不符 -> ARG");
}

static void test_asm(void)
{
    uint8_t blob[40000];
    for (size_t i = 0; i < sizeof(blob); i++) blob[i] = (uint8_t)(i * 31u + 5u);

    dp_manifest_t m;
    dp_manifest_build(blob, sizeof(blob), 16384, &m);

    dp_asm_t a;
    CHECK(dp_asm_init(&a, &m) == DP_OK, "asm_init");

    const uint8_t *p; size_t len;
    dp_chunk_get(blob, sizeof(blob), &m, 0, &p, &len);
    CHECK(dp_asm_put(&a, 0, p, len) == DP_OK, "放入块 0");

    /* 重复块：幂等，不写入不计 got */
    CHECK(dp_asm_put(&a, 0, p, len) == DP_ERR_DUP, "重复块 -> DUP");
    CHECK(a.dup_count == 1 && a.got_count == 1, "重复块不重复计数");

    /* 长度不符 -> LEN */
    CHECK(dp_asm_put(&a, 1, p, len - 1) == DP_ERR_LEN, "块长不符 -> LEN");

    /* 越界 -> RANGE */
    CHECK(dp_asm_put(&a, 99, p, len) == DP_ERR_RANGE, "块索引越界 -> RANGE");

    /* 未收齐 -> INCOMPLETE */
    CHECK(dp_asm_seal(&a) == DP_ERR_INCOMPLETE, "未收齐 -> INCOMPLETE");
    CHECK(dp_asm_is_complete(&a) == 0, "未收齐 is_complete=0");
    CHECK(dp_asm_missing(&a) == 2, "missing=2");

    /* 乱序收齐 */
    dp_chunk_get(blob, sizeof(blob), &m, 2, &p, &len);
    CHECK(dp_asm_put(&a, 2, p, len) == DP_OK, "乱序放入块 2");
    dp_chunk_get(blob, sizeof(blob), &m, 1, &p, &len);
    CHECK(dp_asm_put(&a, 1, p, len) == DP_OK, "乱序放入块 1");
    CHECK(dp_asm_seal(&a) == DP_OK, "乱序收齐后 seal 成功");
    CHECK(memcmp(a.buf, blob, sizeof(blob)) == 0, "组装结果与原文逐字节一致");

    /* seal 后禁止再写 */
    CHECK(dp_asm_put(&a, 0, p, len) == DP_ERR_STATE, "seal 后再写 -> STATE");

    dp_asm_free(&a);
}

static void test_asm_digest(void)
{
    uint8_t blob[40000];
    memset(blob, 0x5A, sizeof(blob));

    dp_manifest_t m;
    dp_manifest_build(blob, sizeof(blob), 16384, &m);

    dp_asm_t a;
    dp_asm_init(&a, &m);

    const uint8_t *p; size_t len;
    for (uint32_t i = 0; i < m.nchunks; i++) {
        dp_chunk_get(blob, sizeof(blob), &m, i, &p, &len);
        dp_asm_put(&a, i, p, len);
    }
    /* 收齐后篡改缓冲区内容：摘要必须不符 */
    a.buf[100] ^= 0xFF;
    CHECK(dp_asm_seal(&a) == DP_ERR_DIGEST, "内容被改 -> DIGEST");
    CHECK(a.sealed == 0, "摘要不符不置 sealed");

    dp_asm_free(&a);
}

static void test_asm_exec_guard(void)
{
    uint8_t blob[4096];
    memset(blob, 0x11, sizeof(blob));

    dp_manifest_t m;
    dp_manifest_build(blob, sizeof(blob), 1024, &m);

    dp_asm_t a;
    dp_asm_init(&a, &m);
    const uint8_t *p; size_t len;
    dp_chunk_get(blob, sizeof(blob), &m, 0, &p, &len);
    dp_asm_put(&a, 0, p, len);

    /* 硬规则 2 的落点：未 seal 绝不执行。
       缺块却执行会让制品随机跑飞。 */
    CHECK(dp_asm_exec(&a, SEED, sizeof(SEED)) == DP_ERR_INCOMPLETE,
          "未 seal 调用 exec -> INCOMPLETE（不执行）");

    dp_asm_free(&a);
}

static void test_gate(void)
{
    uint8_t blob[8192];
    memset(blob, 0x33, sizeof(blob));
    dp_manifest_t m;
    dp_manifest_build(blob, sizeof(blob), 4096, &m);

    const uint8_t *p = NULL; size_t len = 0;
    CHECK(dp_serve_chunk(blob, sizeof(blob), &m, 0, gate_deny, NULL, &p, &len)
          == DP_ERR_GATE, "门控拒绝 -> GATE");
    CHECK(p == NULL && len == 0, "门控拒绝时不写 out/olen");
    CHECK(dp_serve_chunk(blob, sizeof(blob), &m, 0, gate_allow, NULL, &p, &len)
          == DP_OK, "门控放行 -> OK");
    CHECK(dp_serve_chunk(blob, sizeof(blob), &m, 99, gate_allow, NULL, &p, &len)
          == DP_ERR_RANGE, "放行后越界 -> RANGE");
    CHECK(dp_serve_chunk(blob, sizeof(blob), &m, 0, NULL, NULL, &p, &len)
          == DP_ERR_ARG, "门控为 NULL -> ARG");
}

/* ================================================================== */
/* B. HTTP 层                                                         */
/* ================================================================== */

static void test_http(void)
{
    char req[256];
    size_t rlen = 0;
    CHECK(dp_http_build_request(7, NULL, req, sizeof(req), &rlen) == DP_OK,
          "构造请求");
    CHECK(strstr(req, "/static/img/7.png") != NULL, "路径含块号 7");

    /* 多个 %u 的模板必须拒绝：第二个会被栈垃圾填充 */
    CHECK(dp_http_build_request(7, "/a/%u/b/%u", req, sizeof(req), &rlen)
          == DP_ERR_ARG, "模板含两个 %u -> ARG");

    uint32_t idx = 0;
    CHECK(dp_http_parse_request(req, rlen, &idx) == DP_OK && idx == 7,
          "从请求解析块号=7");

    const char *noreq = "GET /static/img/logo.png HTTP/1.1\r\nHost: x\r\n\r\n";
    CHECK(dp_http_parse_request(noreq, strlen(noreq), &idx) == DP_ERR_ARG,
          "路径无数字 -> ARG");

    /* 响应往返 */
    uint8_t body[300];
    for (size_t i = 0; i < sizeof(body); i++) body[i] = (uint8_t)(i * 13u);
    uint8_t resp[1024];
    size_t olen = 0;
    CHECK(dp_http_build_response(body, sizeof(body), NULL, resp, sizeof(resp), &olen)
          == DP_OK, "构造 200 响应");

    const uint8_t *got = NULL; size_t glen = 0;
    CHECK(dp_http_parse_response(resp, olen, &got, &glen) == DP_OK &&
          glen == sizeof(body) && memcmp(got, body, sizeof(body)) == 0,
          "响应往返一致");

    /* 非 200 必须拒绝：把诱饵页当块收下会污染组装缓冲 */
    uint8_t decoy[512]; size_t dlen = 0;
    dp_http_build_decoy(decoy, sizeof(decoy), &dlen);
    CHECK(dp_http_parse_response(decoy, dlen, &got, &glen) == DP_ERR_ARG,
          "诱饵 404 响应 -> 拒绝（不当块收下）");
    CHECK(memcmp(decoy, "HTTP/1.1 404", 12) == 0, "诱饵是 404 而非 403");

    /* Content-Length 与实际不符 -> LEN */
    uint8_t bad[1024];
    size_t blen = (size_t)snprintf((char *)bad, sizeof(bad),
        "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n"
        "Content-Length: 999\r\nConnection: close\r\n\r\nxy");
    CHECK(dp_http_parse_response(bad, blen, &got, &glen) == DP_ERR_ARG,
          "声明长度超实际 -> 拒绝");
}

/* ================================================================== */
/* C. 端到端真跑                                                       */
/* ================================================================== */

#define TMPDIR "/tmp/drop_e2e"
#define TARGET "../20_packer/build/mexec_target"

static void must_system(const char *cmd)
{
    int rc = system(cmd);
    (void)rc;
}

static int write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = fwrite(buf, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : -1;
}

static int read_file(const char *path, uint8_t **out, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);
    uint8_t *b = malloc((size_t)sz);
    if (!b) { fclose(f); return -1; }
    if (fread(b, 1, (size_t)sz, f) != (size_t)sz) { free(b); fclose(f); return -1; }
    fclose(f);
    *out = b; *len = (size_t)sz;
    return 0;
}

/* 起一个子进程，stderr 接到管道，返回读端 fd 与 pid */
static pid_t spawn(const char **argv, int *read_fd)
{
    int pfd[2];
    if (pipe(pfd) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        close(pfd[0]);
        /* stdout 与 stderr 都要接：执行目标的输出走 stdout，
           只接 stderr 会让"制品真执行了"这条断言永远读不到证据，
           从而把成功误判成失败。 */
        dup2(pfd[1], STDOUT_FILENO);
        dup2(pfd[1], STDERR_FILENO);
        close(pfd[1]);
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(pfd[1]);
    *read_fd = pfd[0];
    return pid;
}

static size_t slurp(int fd, char *buf, size_t cap)
{
    size_t off = 0;
    for (;;) {
        if (off >= cap - 1) break;
        ssize_t n = read(fd, buf + off, cap - 1 - off);
        if (n < 0) break;
        if (n == 0) break;
        off += (size_t)n;
    }
    buf[off] = '\0';
    return off;
}

/* 端到端：deny_after=0 正常投递并真执行；deny_after>0 门控断供后不得执行 */
static void e2e(int deny_after, int expect_exec)
{
    uint8_t *raw = NULL; size_t raw_len = 0;
    if (read_file(TARGET, &raw, &raw_len) != 0) {
        printf("[FAIL] e2e: 读 %s 失败\n", TARGET);
        g_fail++;
        return;
    }

    size_t cap = pk_size_bound_v4(raw_len);
    uint8_t *dj = malloc(cap);
    if (!dj) { free(raw); g_fail++; return; }
    uint8_t bind_id[PK_BIND_ID_LEN], eph_pub[PK_EPH_PUB_LEN];
    memset(bind_id, 0, sizeof(bind_id));
    memset(eph_pub, 0, sizeof(eph_pub));
    size_t dj_len = cap;
    if (pk_pack_shaped(raw, raw_len, SEED, sizeof(SEED), bind_id, 1u, eph_pub,
                       dj, &dj_len) != 0) {
        printf("[FAIL] e2e: 打包失败\n");
        free(raw); free(dj); g_fail++;
        return;
    }
    free(raw);

    dp_manifest_t m;
    if (dp_manifest_build(dj, dj_len, DP_CHUNK_MAX, &m) != DP_OK) {
        printf("[FAIL] e2e: manifest 构建失败\n");
        free(dj); g_fail++;
        return;
    }

    must_system("mkdir -p " TMPDIR);
    if (write_file(TMPDIR "/a.dj", dj, dj_len) != 0 ||
        write_file(TMPDIR "/a.mf", (const uint8_t *)&m, sizeof(m)) != 0 ||
        write_file(TMPDIR "/a.seed", SEED, sizeof(SEED)) != 0) {
        printf("[FAIL] e2e: 写临时文件失败\n");
        free(dj); g_fail++;
        return;
    }
    free(dj);

    char deny_str[32];
    snprintf(deny_str, sizeof(deny_str), "%d", deny_after);

    const char *sargv[] = { "./build/drop_serve", "127.0.0.1", "0",
                            TMPDIR "/a.dj", TMPDIR "/a.mf", deny_str, "30", NULL };
    int sfd = -1;
    pid_t spid = spawn(sargv, &sfd);
    if (spid < 0) { printf("[FAIL] e2e: 起服务端失败\n"); g_fail++; return; }

    /* 读 PORT 行。服务端输出短，不会填满管道。 */
    char sbuf[4096];
    size_t n = 0;
    for (;;) {
        char c;
        ssize_t r = read(sfd, &c, 1);
        if (r <= 0) break;
        if (n < sizeof(sbuf) - 1) sbuf[n++] = c;
        if (n >= 5 && strncmp(sbuf, "PORT ", 5) == 0 && c == '\n') break;
    }
    sbuf[n] = '\0';

    unsigned port = 0;
    if (sscanf(sbuf, "PORT %u", &port) != 1 || port == 0) {
        printf("[FAIL] e2e: 未取得服务端端口 (buf=%.40s)\n", sbuf);
        kill(spid, SIGKILL); waitpid(spid, NULL, 0);
        close(sfd); g_fail++;
        return;
    }

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", port);
    const char *targv[] = { "./build/drop_stager", "127.0.0.1", port_str,
                            TMPDIR "/a.mf", TMPDIR "/a.seed", NULL };
    int tfd = -1;
    pid_t tpid = spawn(targv, &tfd);
    if (tpid < 0) {
        printf("[FAIL] e2e: 起 stager 失败\n");
        kill(spid, SIGKILL); waitpid(spid, NULL, 0);
        close(sfd); g_fail++;
        return;
    }

    /* 先 waitpid 再读管道：stager 输出很短，不会填满管道而阻塞。 */
    int st = 0;
    waitpid(tpid, &st, 0);
    char tbuf[8192];
    slurp(tfd, tbuf, sizeof(tbuf));
    close(tfd);

    if (expect_exec) {
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "e2e: stager 退出码 0");
        CHECK(strstr(tbuf, "MEXEC_OK") != NULL,
              "e2e: 制品真执行（读到 MEXEC_OK，映像被替换）");
        CHECK(strstr(tbuf, "exec rc=") == NULL, "e2e: 未走失败分支");
    } else {
        CHECK(!(WIFEXITED(st) && WEXITSTATUS(st) == 0),
              "e2e: 门控断供后 stager 非零退出");
        CHECK(strstr(tbuf, "MEXEC_OK") == NULL,
              "e2e: 门控断供后绝不执行（无 MEXEC_OK）");
    }

    kill(spid, SIGKILL);
    waitpid(spid, NULL, 0);
    close(sfd);
}

int main(void)
{
    printf("=== test_drop ===\n");
    test_manifest();
    test_chunk();
    test_asm();
    test_asm_digest();
    test_asm_exec_guard();
    test_gate();
    test_http();

    printf("--- e2e: 完整投递并真执行 ---\n");
    e2e(0, 1);
    printf("--- e2e: 门控断供（deny_after=2）---\n");
    e2e(2, 0);

    printf("=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
