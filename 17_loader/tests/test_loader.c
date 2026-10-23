/*
 * DAYANJING v4 — 17_loader/tests/test_loader.c
 *
 * 合成一个结构完整的 PE32+ 映像（含导入表 / 导出表 / 重定位表 / TLS 回调），
 * 对 PE 解析、反射加载、shellcode 编解码做真实断言。
 *
 * 说明：反射加载在 Linux 上验证的是"内存映像构造正确"这一层（纯逻辑），
 * 不执行 x86 代码——那需要 Windows 目标平台。
 */

#include "loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int g_pass = 0, g_fail = 0;

#define CHECK(name, cond) do { \
    if (cond) { printf("[PASS] %s\n", (name)); g_pass++; } \
    else      { printf("[FAIL] %s  (line %d)\n", (name), __LINE__); g_fail++; } \
} while (0)

#define FILE_ALIGN   0x200u
#define SECT_ALIGN   0x1000u
#define IMAGE_BASE   0x10000000u
#define SIZE_IMAGE   0x3000u
#define TEXT_RVA     0x1000u
#define TEXT_RAW     0x200u
#define RDATA_RVA    0x2000u
#define RDATA_RAW    0x400u
#define FILE_SIZE    0x600u

static void wr16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)(v&0xFF); p[1]=(uint8_t)(v>>8); }
static void wr32(uint8_t *p, uint32_t v) { ld_wr32(p, v); }
static void wr64(uint8_t *p, uint64_t v) { ld_wr64(p, v); }

/* rdata RVA -> 文件偏移 */
#define RF(rva) ((rva) - RDATA_RVA + RDATA_RAW)
/* text  RVA -> 文件偏移 */
#define TF(rva) ((rva) - TEXT_RVA + TEXT_RAW)

static void build_synth_pe(uint8_t *b, size_t cap)
{
    uint8_t *opt, *dd, *sh;
    size_t i;

    if (cap < FILE_SIZE) return;
    memset(b, 0, cap);

    /* ---- DOS header ---- */
    wr16(b + 0, 0x5A4D);            /* 'MZ' */
    wr32(b + 0x3C, 0x40);           /* e_lfanew */

    /* ---- PE signature + COFF ---- */
    b[0x40]='P'; b[0x41]='E'; b[0x42]=0; b[0x43]=0;
    wr16(b + 0x44, 0x8664);         /* Machine = AMD64 */
    wr16(b + 0x46, 2);              /* NumberOfSections */
    wr32(b + 0x48, 0);              /* TimeDateStamp */
    wr32(b + 0x4C, 0);              /* PointerToSymbolTable */
    wr32(b + 0x50, 0);              /* NumberOfSymbols */
    wr16(b + 0x54, 240);            /* SizeOfOptionalHeader */
    wr16(b + 0x56, 0x2022);         /* Characteristics = EXECUTABLE_IMAGE|DLL */

    /* ---- Optional header (PE32+) ---- */
    opt = b + 0x58;
    wr16(opt + 0,  0x020B);         /* Magic = PE32+ */
    wr32(opt + 16, 0x1000);         /* AddressOfEntryPoint */
    wr64(opt + 24, IMAGE_BASE);     /* ImageBase */
    wr32(opt + 32, SECT_ALIGN);     /* SectionAlignment */
    wr32(opt + 36, FILE_ALIGN);     /* FileAlignment */
    wr32(opt + 56, SIZE_IMAGE);     /* SizeOfImage */
    wr32(opt + 60, 0x200);          /* SizeOfHeaders */
    wr16(opt + 68, 3);              /* Subsystem = CUI */
    wr16(opt + 70, 0x8160);         /* DllCharacteristics */
    wr32(opt + 108, 16);            /* NumberOfRvaAndSizes */

    dd = opt + 112;
    wr32(dd + 0*8,     0x2070); wr32(dd + 0*8 + 4, 40);   /* Export */
    wr32(dd + 1*8,     0x2010); wr32(dd + 1*8 + 4, 40);   /* Import */
    wr32(dd + 5*8,     0x1180); wr32(dd + 5*8 + 4, 12);   /* BaseReloc */
    wr32(dd + 9*8,     0x20F0); wr32(dd + 9*8 + 4, 40);   /* TLS */

    /* ---- Section headers ---- */
    sh = b + 0x148;
    memcpy(sh + 0,      ".text\0\0\0", 8);
    wr32(sh + 8,  0x200);           /* VirtualSize */
    wr32(sh + 12, TEXT_RVA);
    wr32(sh + 16, 0x200);           /* SizeOfRawData */
    wr32(sh + 20, TEXT_RAW);
    wr32(sh + 36, 0x60000020);      /* CODE|EXECUTE|READ */

    memcpy(sh + 40,     ".rdata\0\0", 8);
    wr32(sh + 48, 0x140);           /* VirtualSize */
    wr32(sh + 52, RDATA_RVA);
    wr32(sh + 56, 0x200);           /* SizeOfRawData */
    wr32(sh + 60, RDATA_RAW);
    wr32(sh + 76, 0x40000040);      /* INITIALIZED_DATA|READ */

    /* ---- .text 内容 ---- */
    wr32(b + TF(0x1100), 0x2000);           /* HIGHLOW 重定位目标 */
    wr64(b + TF(0x1108), 0x2000);           /* DIR64  重定位目标 */
    /* 重定位块 @ RVA 0x1180 */
    wr32(b + TF(0x1180), TEXT_RVA);         /* PageRVA */
    wr32(b + TF(0x1184), 12);               /* BlockSize */
    wr16(b + TF(0x1188), (uint16_t)((3u  << 12) | 0x100u));  /* HIGHLOW @0x1100 */
    wr16(b + TF(0x118A), (uint16_t)((10u << 12) | 0x108u));  /* DIR64   @0x1108 */

    /* ---- .rdata 内容 ---- */
    memcpy(b + RF(0x2000), "TESTLIB.DLL", 12);

    /* 导入描述符 @0x2010 */
    wr32(b + RF(0x2010), 0x2040);           /* +0  OriginalFirstThunk */
    wr32(b + RF(0x2014), 0);                /* +4  TimeDateStamp */
    wr32(b + RF(0x2018), 0);                /* +8  ForwarderChain */
    wr32(b + RF(0x201C), 0x2000);           /* +12 Name */
    wr32(b + RF(0x2020), 0x2050);           /* +16 FirstThunk */
    /* 终止描述符 @0x2024 全零 */

    wr64(b + RF(0x2040), 0x2060);           /* ILT[0] -> Hint/Name */
    wr64(b + RF(0x2048), 0);                /* ILT 终止 */
    wr64(b + RF(0x2050), 0x2060);           /* IAT[0]（加载前同 ILT） */
    wr64(b + RF(0x2058), 0);                /* IAT 终止 */

    wr16(b + RF(0x2060), 0);                /* Hint */
    memcpy(b + RF(0x2062), "TestFunc", 9);

    /* 导出目录 @0x2070 */
    wr32(b + RF(0x207C), 0x20A0);           /* Name */
    wr32(b + RF(0x2080), 1);                /* Base */
    wr32(b + RF(0x2084), 1);                /* NumberOfFunctions */
    wr32(b + RF(0x2088), 1);                /* NumberOfNames */
    wr32(b + RF(0x208C), 0x20C0);           /* AddressOfFunctions */
    wr32(b + RF(0x2090), 0x20C8);           /* AddressOfNames */
    wr32(b + RF(0x2094), 0x20D0);           /* AddressOfNameOrdinals */
    memcpy(b + RF(0x20A0), "SYNTH.DLL", 10);
    wr32(b + RF(0x20C0), 0x1100);           /* EAT[0] */
    wr32(b + RF(0x20C8), 0x20E0);           /* ENames[0] */
    wr16(b + RF(0x20D0), 0);                /* EOrd[0] */
    memcpy(b + RF(0x20E0), "SynthExport", 12);

    /* TLS 目录 @0x20F0，AddressOfCallBacks(VA) @ +20 */
    wr64(b + RF(0x20F0) + 24, IMAGE_BASE + 0x2120);   /* AddressOfCallBacks: PE32+ @+24 */
    wr64(b + RF(0x2120), IMAGE_BASE + 0x1200);   /* 回调[0] */
    wr64(b + RF(0x2128), 0);                     /* 回调终止 */

    (void)i;
}

/* ---------------- 解析器回调 ---------------- */
static int test_resolver(const char *dll, const char *func,
                         uint16_t ordinal, int by_ordinal,
                         void *ud, uint64_t *out)
{
    int *calls = (int *)ud;
    if (calls) (*calls)++;
    if (by_ordinal) { *out = 0x1000u + ordinal; return LD_OK; }
    /* 确定性伪地址：由 dll/func 名派生，便于断言 */
    {
        uint64_t h = 0xDEAD0000u;
        const char *p;
        for (p = dll; *p; p++) h = h * 131u + (uint8_t)*p;
        for (p = func; *p; p++) h = h * 131u + (uint8_t)*p;
        *out = h;
        return LD_OK;
    }
}

int main(void)
{
    uint8_t pe[FILE_SIZE];
    pe_image_t img;
    uint8_t *region;
    size_t region_size = SIZE_IMAGE;
    reflect_image_t ri;
    int rc, calls = 0;
    int64_t delta;

    build_synth_pe(pe, sizeof(pe));

    printf("=== 17_loader: PE 解析 ===\n");

    rc = pe_parse(pe, sizeof(pe), &img);
    CHECK("pe_parse 成功", rc == LD_OK);
    CHECK("识别为 PE32+", img.is64 == 1);
    CHECK("machine == 0x8664", img.machine == 0x8664);
    CHECK("NumberOfSections == 2", img.nsec == 2 && img.sec_count == 2);
    CHECK("ImageBase == 0x10000000", img.image_base == IMAGE_BASE);
    CHECK("AddressOfEntryPoint == 0x1000", img.entry_rva == 0x1000);
    CHECK("SizeOfImage == 0x3000", img.size_image == SIZE_IMAGE);
    CHECK("NumberOfRvaAndSizes == 16", img.nrva == 16);
    CHECK("导出目录 RVA == 0x2070", img.dir[PE_DIR_EXPORT].rva == 0x2070);
    CHECK("导入目录 RVA == 0x2010", img.dir[PE_DIR_IMPORT].rva == 0x2010);
    CHECK("重定位目录 RVA == 0x1180", img.dir[PE_DIR_RELOC].rva == 0x1180);
    CHECK("TLS 目录 RVA == 0x20F0", img.dir[PE_DIR_TLS].rva == 0x20F0);

    {
        uint32_t off = 0;
        CHECK("RVA 0x2070 -> 文件 0x470", pe_rva_to_file(&img, 0x2070, &off) == LD_OK && off == 0x470);
    }
    {
        uint32_t off = 0;
        CHECK("RVA 0x1180 -> 文件 0x380", pe_rva_to_file(&img, 0x1180, &off) == LD_OK && off == 0x380);
    }
    {
        uint32_t off = 0;
        CHECK("未映射 RVA 返回 NOTFOUND", pe_rva_to_file(&img, 0x99999, &off) == LD_ERR_NOTFOUND);
    }
    {
        const pe_sec_t *s = pe_sec_by_rva(&img, 0x2100);
        CHECK("RVA 0x2100 落在 .rdata", s && memcmp(s->name, ".rdata", 6) == 0);
    }
    {
        const pe_sec_t *s = pe_sec_by_rva(&img, 0x1100);
        CHECK("RVA 0x1100 落在 .text", s && memcmp(s->name, ".text", 5) == 0);
    }

    printf("=== 17_loader: 导入表 ===\n");
    {
        pe_import_iter_t it;
        int got = 0, n = 0;
        CHECK("pe_import_begin", pe_import_begin(&img, &it) == LD_OK);
        for (;;) {
            rc = pe_import_next(&it);
            if (rc < 0) { printf("[FAIL] 导入迭代错误 %d\n", rc); g_fail++; break; }
            if (rc == 0) break;
            n++;
            if (strcmp(it.dll, "TESTLIB.DLL") == 0 && strcmp(it.func, "TestFunc") == 0) got = 1;
        }
        CHECK("导入项数 == 1", n == 1);
        CHECK("导入项 = TESTLIB.DLL!TestFunc", got == 1);
    }

    printf("=== 17_loader: 导出表 ===\n");
    {
        uint32_t nf = 0, nn = 0, rva = 0;
        char nm[64]; uint32_t ord = 99;
        CHECK("pe_export_count", pe_export_count(&img, &nf, &nn) == LD_OK);
        CHECK("NumberOfFunctions == 1", nf == 1);
        CHECK("NumberOfNames == 1", nn == 1);
        CHECK("按名查 SynthExport -> 0x1100",
              pe_export_by_name(&img, "SynthExport", &rva) == LD_OK && rva == 0x1100);
        CHECK("按名查不存在的符号 -> NOTFOUND",
              pe_export_by_name(&img, "NoSuchFunc", &rva) == LD_ERR_NOTFOUND);
        CHECK("按索引取名 -> SynthExport",
              pe_export_name_by_index(&img, 0, nm, sizeof(nm), &ord) == LD_OK
              && strcmp(nm, "SynthExport") == 0);
        CHECK("索引 0 的序号 == 0", ord == 0);
        CHECK("按索引取 RVA -> 0x1100",
              pe_export_rva_by_index(&img, 0, &rva) == LD_OK && rva == 0x1100);
        CHECK("越界索引 -> NOTFOUND", pe_export_rva_by_index(&img, 5, &rva) == LD_ERR_NOTFOUND);
    }

    printf("=== 17_loader: 反射加载 ===\n");
    region = (uint8_t *)malloc(region_size);
    if (!region) { printf("[FAIL] malloc\n"); return 1; }

    rc = reflect_load(pe, sizeof(pe), region, region_size, test_resolver, &calls, &ri);
    CHECK("reflect_load 成功", rc == LD_OK);
    delta = (int64_t)((uintptr_t)region) - (int64_t)IMAGE_BASE;

    CHECK("头部已映射（'MZ'）", region[0] == 'M' && region[1] == 'Z');
    CHECK(".text 已映射", memcmp(region + 0x1000, pe + TEXT_RAW, 0x200) == 0
                          || ri.n_reloc > 0);   /* 重定位会改写 0x1100/0x1108 */
    CHECK("重定位项数 == 2", ri.n_reloc == 2);
    CHECK("IAT 绑定项数 == 1", ri.n_import == 1);
    CHECK("解析器被调用 1 次", calls == 1);
    CHECK("TLS 回调数 == 1", ri.n_tls == 1);
    CHECK("TLS 回调地址 == region+0x1200",
          ri.n_tls == 1 && ri.tls_cb[0] == (uint64_t)(uintptr_t)(region + 0x1200));
    CHECK("入口点 VA == region+0x1000",
          ri.entry_va == (uint64_t)(uintptr_t)(region + 0x1000));
    CHECK("delta == region - ImageBase", ri.delta == delta);

    {
        uint32_t got = ld_rd32(region + 0x1100);
        uint32_t want = (uint32_t)(0x2000u + (uint32_t)(int32_t)delta);
        CHECK("HIGHLOW 重定位值正确", got == want);
    }
    {
        uint64_t got = ld_rd64(region + 0x1108);
        uint64_t want = (uint64_t)0x2000u + (uint64_t)delta;
        CHECK("DIR64 重定位值正确", got == want);
    }
    {
        uint64_t got = ld_rd64(region + 0x2050);
        uint64_t want;
        test_resolver("TESTLIB.DLL", "TestFunc", 0, 0, NULL, &want);
        CHECK("IAT 槽位写入解析结果", got == want);
    }

    /* 空间不足应被拒绝 */
    {
        reflect_image_t ri2;
        rc = reflect_load(pe, sizeof(pe), region, 0x100, test_resolver, &calls, &ri2);
        CHECK("region 过小 -> NOSPACE", rc == LD_ERR_NOSPACE);
    }
    /*
     * 回归：ImageBase >= 4GiB（MSVC 默认 0x140000000）时 TLS 回调必须仍能收集。
     * 此前 AddressOfCallBacks 按 +20 偏移、4 字节读取：+20 在 64 位 TLS 目录里
     * 是 SizeOfZeroFill（恒 0），于是"无回调"被静默判定；即便偏移对了，4 字节
     * 读取也会把高位截掉得到 < ImageBase 的值而报 FORMAT。两者都不报错。
     */
    {
        uint8_t pehb[FILE_SIZE];
        reflect_image_t rihb;
        const uint64_t HB = 0x140000000ULL;
        memcpy(pehb, pe, sizeof(pehb));
        wr64(pehb + 0x58 + 24, HB);                       /* ImageBase */
        wr64(pehb + RF(0x20F0) + 24, HB + 0x2120);        /* AddressOfCallBacks */
        wr64(pehb + RF(0x2120),      HB + 0x1200);        /* 回调[0] */
        rc = reflect_load(pehb, sizeof(pehb), region, region_size,
                          test_resolver, &calls, &rihb);
        CHECK("ImageBase >= 4GiB 时反射加载成功", rc == LD_OK);
        CHECK("ImageBase >= 4GiB 时 TLS 回调数 == 1", rihb.n_tls == 1);
        CHECK("ImageBase >= 4GiB 时 TLS 回调地址 == region+0x1200",
              rihb.n_tls == 1
              && rihb.tls_cb[0] == (uint64_t)(uintptr_t)(region + 0x1200));
    }
    /* 不支持的重定位类型应显式报错，而不是静默跳过 */
    {
        uint8_t pe2[FILE_SIZE];
        reflect_image_t ri3;
        memcpy(pe2, pe, sizeof(pe2));
        wr16(pe2 + TF(0x1188), (uint16_t)((1u << 12) | 0x100u));  /* type=1 HIGH */
        rc = reflect_load(pe2, sizeof(pe2), region, region_size, test_resolver, &calls, &ri3);
        CHECK("不支持的重定位类型 -> FORMAT", rc == LD_ERR_FORMAT);
    }
    free(region);

    printf("=== 17_loader: 负向输入 ===\n");
    {
        pe_image_t bad;
        uint8_t small[32];
        uint8_t big[128];
        memset(small, 0, sizeof(small));
        memset(big, 0, sizeof(big));
        CHECK("空指针 -> ARG", pe_parse(NULL, 0, &bad) == LD_ERR_ARG);
        CHECK("过短缓冲 -> TRUNC", pe_parse(small, sizeof(small), &bad) == LD_ERR_TRUNC);
        /* magic 校验必须给足 64 字节：否则会先被长度检查拦下，测不到 magic 分支 */
        big[0]='X'; big[1]='X';
        CHECK("错误 DOS magic -> FORMAT", pe_parse(big, sizeof(big), &bad) == LD_ERR_FORMAT);
        big[0]='M'; big[1]='Z';
        wr32(big + 0x3C, 0x40);
        big[0x40]='X'; big[0x41]='X'; big[0x42]='X'; big[0x43]='X';
        CHECK("错误 PE 签名 -> FORMAT", pe_parse(big, sizeof(big), &bad) == LD_ERR_FORMAT);
    }

    printf("=== 17_loader: shellcode 编解码 ===\n");
    {
        static const uint8_t seed[16] = {
            0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
            0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
        };
        static const uint8_t iv[SC_IV_LEN] = {
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,
            0x77,0x88,0x99,0xAA,0xBB
        };
        size_t lens[] = { 0, 1, 15, 16, 17, 255, 1000 };
        size_t li;
        int all_ok = 1;

        for (li = 0; li < sizeof(lens)/sizeof(lens[0]); li++) {
            size_t n = lens[li];
            uint8_t *pt = (uint8_t *)malloc(n ? n : 1);
            uint8_t *enc = (uint8_t *)malloc(sc_encode_size(n));
            uint8_t *dec = (uint8_t *)malloc(sc_encode_size(n));
            size_t enc_len = sc_encode_size(n);
            size_t dec_len = sc_encode_size(n);
            size_t k;
            int r;

            for (k = 0; k < n; k++) pt[k] = (uint8_t)((k * 7u + 3u) & 0xFF);

            r = sc_encode(pt, n, seed, sizeof(seed), iv, enc, &enc_len);
            if (r != LD_OK || enc_len != sc_encode_size(n)) {
                printf("  [diag] len=%zu encode r=%d enc_len=%zu want=%zu\n",
                       n, r, enc_len, sc_encode_size(n));
                all_ok = 0;
            } else {
                if (n > 0 && memcmp(enc + SC_HDR_LEN, pt, n) == 0) {
                    printf("  [diag] len=%zu 密文等于明文\n", n);
                    all_ok = 0;
                }
                r = sc_decode(enc, enc_len, seed, sizeof(seed), dec, &dec_len);
                if (r != LD_OK || dec_len != n) {
                    printf("  [diag] len=%zu decode r=%d dec_len=%zu want=%zu\n",
                           n, r, dec_len, n);
                    all_ok = 0;
                } else if (n > 0 && memcmp(dec, pt, n) != 0) {
                    printf("  [diag] len=%zu 明文不一致\n", n);
                    all_ok = 0;
                }
            }
            free(pt); free(enc); free(dec);
        }
        CHECK("多长度往返一致 (0/1/15/16/17/255/1000)", all_ok);

        /* 错误种子 */
        {
            uint8_t pt[32], enc[128], dec[128];
            uint8_t bad_seed[16];
            size_t el = sizeof(enc), dl = sizeof(dec);
            memset(pt, 0x5A, sizeof(pt));
            memset(bad_seed, 0x77, sizeof(bad_seed));
            CHECK("encode 成功(错误种子用例)",
                  sc_encode(pt, sizeof(pt), seed, sizeof(seed), iv, enc, &el) == LD_OK);
            CHECK("错误种子 -> AUTH",
                  sc_decode(enc, el, bad_seed, sizeof(bad_seed), dec, &dl) == LD_ERR_AUTH);
        }
        /* 篡改密文 */
        {
            uint8_t pt[32], enc[128], dec[128];
            size_t el = sizeof(enc), dl = sizeof(dec);
            memset(pt, 0x3C, sizeof(pt));
            CHECK("encode 成功(篡改密文用例)",
                  sc_encode(pt, sizeof(pt), seed, sizeof(seed), iv, enc, &el) == LD_OK);
            enc[SC_HDR_LEN + 4] ^= 0x01;
            CHECK("篡改密文 -> AUTH",
                  sc_decode(enc, el, seed, sizeof(seed), dec, &dl) == LD_ERR_AUTH);
        }
        /* 篡改 IV */
        {
            uint8_t pt[32], enc[128], dec[128];
            size_t el = sizeof(enc), dl = sizeof(dec);
            memset(pt, 0x9E, sizeof(pt));
            CHECK("encode 成功(篡改 IV 用例)",
                  sc_encode(pt, sizeof(pt), seed, sizeof(seed), iv, enc, &el) == LD_OK);
            enc[12] ^= 0x80;
            CHECK("篡改 IV -> AUTH",
                  sc_decode(enc, el, seed, sizeof(seed), dec, &dl) == LD_ERR_AUTH);
        }
        /* magic 校验 */
        {
            uint8_t pt[16], enc[128], dec[128];
            size_t el = sizeof(enc), dl = sizeof(dec);
            memset(pt, 1, sizeof(pt));
            CHECK("encode 成功(magic 用例)",
                  sc_encode(pt, sizeof(pt), seed, sizeof(seed), iv, enc, &el) == LD_OK);
            enc[0] = 'X';
            CHECK("错误 magic -> FORMAT",
                  sc_decode(enc, el, seed, sizeof(seed), dec, &dl) == LD_ERR_FORMAT);
        }
        /* 篡改头部 flags（位于 AAD 内，且不影响长度校验）——验证 AAD 绑定 */
        {
            uint8_t pt[32], enc[128], dec[128];
            size_t el = sizeof(enc), dl = sizeof(dec);
            memset(pt, 0x77, sizeof(pt));
            CHECK("encode 成功(篡改 flags 用例)",
                  sc_encode(pt, sizeof(pt), seed, sizeof(seed), iv, enc, &el) == LD_OK);
            enc[5] ^= 0x01;
            CHECK("篡改 flags -> AUTH",
                  sc_decode(enc, el, seed, sizeof(seed), dec, &dl) == LD_ERR_AUTH);
        }
        /* 篡改 orig_len：长度自校验先于 AEAD，应判为格式错误 */
        {
            uint8_t pt[32], enc[128], dec[128];
            size_t el = sizeof(enc), dl = sizeof(dec);
            memset(pt, 0x77, sizeof(pt));
            sc_encode(pt, sizeof(pt), seed, sizeof(seed), iv, enc, &el);
            enc[9] ^= 0x01;
            CHECK("篡改 orig_len -> FORMAT",
                  sc_decode(enc, el, seed, sizeof(seed), dec, &dl) == LD_ERR_FORMAT);
        }
        /* 输出缓冲不足 */
        {
            uint8_t pt[32], enc[128], dec[8];
            size_t el = sizeof(enc), dl = sizeof(dec);
            memset(pt, 0x11, sizeof(pt));
            CHECK("encode 成功(缓冲不足用例)",
                  sc_encode(pt, sizeof(pt), seed, sizeof(seed), iv, enc, &el) == LD_OK);
            CHECK("输出缓冲不足 -> NOSPACE",
                  sc_decode(enc, el, seed, sizeof(seed), dec, &dl) == LD_ERR_NOSPACE);
        }
        /* 编码缓冲不足 */
        {
            uint8_t pt[32], enc[16];
            size_t el = sizeof(enc);
            memset(pt, 0x22, sizeof(pt));
            CHECK("编码缓冲不足 -> NOSPACE",
                  sc_encode(pt, sizeof(pt), seed, sizeof(seed), iv, enc, &el) == LD_ERR_NOSPACE);
        }
        /* 同一明文 + 不同 IV => 不同密文（避免稳定静态特征） */
        {
            uint8_t pt[32], e1[64], e2[64];
            uint8_t iv2[SC_IV_LEN];
            size_t l1 = sizeof(e1), l2 = sizeof(e2);
            memset(pt, 0xAB, sizeof(pt));
            memcpy(iv2, iv, SC_IV_LEN); iv2[0] ^= 0xFF;
            sc_encode(pt, sizeof(pt), seed, sizeof(seed), iv,  e1, &l1);
            sc_encode(pt, sizeof(pt), seed, sizeof(seed), iv2, e2, &l2);
            CHECK("不同 IV 产生不同密文", memcmp(e1, e2, l1) != 0);
        }
    }

    printf("\n=== 17_loader 结果: %d/%d 通过 ===\n", g_pass, g_pass + g_fail);
    return g_fail ? 1 : 0;
}
