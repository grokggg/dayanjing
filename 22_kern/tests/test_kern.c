/* 集成测试：读真实 /proc/kallsyms 与 /proc/kcore。
 * 无 root 或 kcore 不可读时，相关用例打印 [SKIP] 并说明原因——
 * 不把"没验证"记成"通过"。 */
#include "kern.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0, passes = 0, skips = 0;

#define CHECK(cond, msg) do { \
    if (cond) { printf("[PASS] %s\n", msg); passes++; } \
    else      { printf("[FAIL] %s\n", msg); failures++; } \
} while (0)
#define SKIP(msg) do { printf("[SKIP] %s\n", msg); skips++; } while (0)
#define INFO(...) do { printf("[INFO] "); printf(__VA_ARGS__); printf("\n"); } while (0)

/* 交叉验证：sys_call_table[nr] 的实际内容 == 符号表独立解析的 __x64_sys_X。
 * 两条路径（符号解析 / 内存读取）互不依赖，一致才说明两者都可信。 */
static int xverify(kern_ctx *c, int nr, const char *sym)
{
    uint64_t got = 0, expect = 0;
    if (kern_syscall_impl(c, nr, &got) != KERN_OK) return -1;
    if (kern_symbol(c, sym, &expect) != KERN_OK) return -2;
    if (got == expect) {
        INFO("%-20s nr=%-4d got=%016llx == %s", sym, nr,
             (unsigned long long)got, sym);
        return 0;
    }
    INFO("MISMATCH %s nr=%d got=%016llx expect=%016llx", sym, nr,
         (unsigned long long)got, (unsigned long long)expect);
    return 1;
}

struct scan_ctx { kern_ctx *c; int n; };

static int cb_suspicious(int nr, uint64_t slot, uint64_t got, uint64_t expect, void *ud)
{
    struct scan_ctx *sc = (struct scan_ctx *)ud;
    (void)slot; (void)expect;
    if (!sc) return 0;
    if (sc->c) {
        char nm[256] = "?";
        char ty = 0;
        if (ksym_rev(kern_syms(sc->c), got, nm, sizeof(nm), &ty) == KERN_OK)
            INFO("  可疑 nr=%-4d 值=%016llx 反查=%s (%c)",
                 nr, (unsigned long long)got, nm, ty);
        else
            INFO("  可疑 nr=%-4d 值=%016llx 反查=无符号覆盖",
                 nr, (unsigned long long)got);
    }
    sc->n++;
    return 0;
}

int main(void)
{
    kern_ctx *c = NULL;
    int rc = kern_open(&c);
    if (rc != KERN_OK) {
        /* 需要 root 或 CAP_SYS_RAWIO 才能读 /proc/kcore。
         * 退出码 77 表示"环境不具备"——回归脚本据此记为 SKIP，
         * 既不冒认为通过，也不把它算成代码缺陷。 */
        printf("[SKIP] kern_open 失败 rc=%d (%s)\n", rc, kern_strerror(rc));
        printf("[SKIP] 本用例需要 root 且 /proc/kcore 可读；环境不具备，未验证。\n");
        return 77;
    }
    CHECK(1, "A1 kern_open 成功");

    const kver *v = kern_ver(c);
    INFO("内核版本: %s (解析为 %d.%d.%d)", v->raw, v->major, v->minor, v->patch);
    CHECK(v->major > 0, "A2 内核版本解析成功");
    CHECK(kver_at_least(v, 3, 0, 0), "A3 版本比较可用");

    size_t nsym = ksym_count(kern_syms(c));
    INFO("符号总数: %zu", nsym);
    CHECK(nsym > 1000, "A4 符号表规模合理");

    /* ---------------- 交叉验证（本模块可信度基石） ---------------- */
    int xv[4];
    xv[0] = xverify(c, 0,   "__x64_sys_read");
    xv[1] = xverify(c, 1,   "__x64_sys_write");
    xv[2] = xverify(c, 2,   "__x64_sys_open");
    xv[3] = xverify(c, 217, "__x64_sys_getdents64");
    int xvok = 0;
    for (int i = 0; i < 4; i++) if (xv[i] == 0) xvok++;
    CHECK(xvok >= 3, "B1 符号解析与内存读取交叉一致（>=3/4）");
    CHECK(xv[0] == 0, "B2 read 表项 == __x64_sys_read");
    CHECK(xv[3] == 0, "B3 getdents64 表项 == __x64_sys_getdents64");

    /* ---------------- kcore 读能力与边界 ---------------- */
    uint64_t sct = 0;
    if (kern_symbol(c, "sys_call_table", &sct) == KERN_OK) {
        uint64_t first = 0;
        CHECK(kern_read_u64(c, sct, &first) == KERN_OK, "C1 读 sys_call_table[0]");
        CHECK(kern_in_text(c, first), "C2 表项指向内核 text 段内");
    } else {
        SKIP("sys_call_table 未导出，跳过 C1/C2");
    }

    uint64_t bad = 0;
    CHECK(kern_read_u64(c, 0x1000ULL, &bad) == KERN_ERR_UNMAPPED,
          "C3 未映射地址返回 UNMAPPED 而非崩");

    CHECK(kcore_nload(kern_mem(c)) > 0, "C4 kcore 存在 PT_LOAD 段");

    /* 跨段读取：起点在某段尾、终点在下一段内 */
    unsigned char buf[4096];
    if (sct) {
        CHECK(kern_read(c, sct, buf, sizeof(buf)) == KERN_OK, "C5 连续读 4096 字节");
    } else {
        SKIP("无 sys_call_table，跳过 C5");
    }

    /* ---------------- 运行时布局探测 ---------------- */
    klayout_cred lc;
    uint64_t init_cred = 0;
    int rc_l = klayout_cred_probe(c, "init_cred", &lc);
    if (rc_l == KERN_OK && kern_symbol(c, "init_cred", &init_cred) == KERN_OK) {
        CHECK(lc.probed == 1, "D1 cred 布局由运行时探测得出");
        CHECK(lc.cap_full_mask != 0, "D2 探测到非空的权限全集掩码");
        CHECK((lc.cap_full_mask & (lc.cap_full_mask + 1)) == 0,
              "D3 权限全集掩码为低位连续 1");
        CHECK(lc.cap_permitted - lc.cap_inheritable == 8,  "D4 caps 字段间距 8");
        CHECK(lc.cap_ambient   - lc.cap_inheritable == 32, "D5 caps 区跨 5 个字段");

        /* 自洽验证：用探测出的偏移回读 init_cred */
        uint64_t v_eff = 0, v_amb = 0;
        kern_read_u64(c, init_cred + lc.cap_effective, &v_eff);
        kern_read_u64(c, init_cred + lc.cap_ambient,   &v_amb);
        CHECK(v_eff == lc.cap_full_mask, "D6 探测偏移处 cap_effective 确为全集");
        CHECK(v_amb == 0,                "D7 探测偏移处 cap_ambient 确为空集");

        INFO("探测结果: inheritable=+0x%zx permitted=+0x%zx effective=+0x%zx "
             "bset=+0x%zx ambient=+0x%zx mask=0x%llx",
             lc.cap_inheritable, lc.cap_permitted, lc.cap_effective,
             lc.cap_bset, lc.cap_ambient, (unsigned long long)lc.cap_full_mask);

        /* 反证：教科书布局（cap 起点 0x28）在本内核是否成立。
         * init_cred 的 cap_ambient 在内核源码中是 CAP_EMPTY_SET(=0)，
         * 与版本无关，因此可作为判据。 */
        uint64_t tb_amb = 0;
        kern_read_u64(c, init_cred + 0x48, &tb_amb);
        if (lc.cap_ambient != 0x48) {
            CHECK(tb_amb != 0,
                  "D8 反证：教科书偏移 0x48 处非 0，硬编码会读错 ambient");
            INFO("教科书 0x48=%016llx（应为 0 才对），探测得 ambient 在 +0x%zx",
                 (unsigned long long)tb_amb, lc.cap_ambient);
        } else {
            INFO("本内核 cap 起点恰为 0x28，教科书布局成立");
        }
    } else {
        SKIP("init_cred 不可用，跳过 D 组布局探测");
    }

    /* ---------------- hook 方案 ---------------- */
    khook_plan p;
    rc = khook_plan_build(c, KHOOK_GETDENTS64, &p);
    if (rc == KERN_OK) {
        CHECK(p.syscall_nr == 217, "E1 getdents64 的 syscall 号为 217");
        CHECK(p.slot != 0,         "E2 hook 写入点（表项地址）已解出");
        CHECK(p.orig != 0,         "E3 表项当前值已读出");
        CHECK(p.intact == 1,       "E4 表项未被篡改（两条路径一致）");
        INFO("getdents64 slot=%016llx orig=%016llx",
             (unsigned long long)p.slot, (unsigned long long)p.orig);
    } else {
        SKIP("hook 方案构建失败，跳过 E 组");
    }

    khook_plan p2;
    rc = khook_plan_build(c, KHOOK_READ, &p2);
    if (rc == KERN_OK) {
        CHECK(p2.intact == 1, "E5 read 表项未被篡改");
    } else {
        SKIP("read hook 方案失败");
    }

    /* ---------------- 完整性扫描 ---------------- */
    struct scan_ctx sc = { c, 0 };
    khook_scan_hooked(c, 0, 80, cb_suspicious, &sc);
    INFO("0..80 号 syscall 扫描完成，可疑 %d 项", sc.n);
    CHECK(1, "F1 完整性扫描未崩溃");
    /* 干净内核上不应有假阳性。kallsyms 中同一地址常有多个别名
     * （__do_sys_X / __ia32_sys_X / __x64_sys_X），反查必须取规范名，
     * 否则原始实现会被误判成已被 hook。 */
    CHECK(sc.n == 0, "F2 干净内核无假阳性（别名反查取规范名）");

    /* ---------------- 边界与错误路径 ---------------- */
    uint64_t dummy = 0;
    CHECK(kern_syscall_impl(c, -1, &dummy) == KERN_ERR_PARAM, "G1 负数 syscall 号返回 PARAM");
    CHECK(kern_symbol(c, NULL, &dummy) == KERN_ERR_PARAM,     "G2 NULL 符号名返回 PARAM");
    CHECK(kern_read_u64(c, 0, NULL) == KERN_ERR_PARAM,        "G3 NULL 输出返回 PARAM");
    CHECK(khook_target_nr(KHOOK_MAX, (int *)&dummy) == KERN_ERR_NOTFOUND ||
          khook_target_nr(KHOOK_MAX, (int *)&dummy) == KERN_ERR_PARAM,
          "G4 非法 hook 目标不返回 OK");

    kern_close(c);
    CHECK(1, "G5 kern_close 安全");

    printf("\n=== result: %d pass, %d fail, %d skip ===\n", passes, failures, skips);
    return failures ? 1 : 0;
}
