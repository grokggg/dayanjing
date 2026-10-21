/*
 * DAYANJING v4 — 20_packer / test_packer.c
 *
 * 覆盖：LZSS 往返 / 打包解包往返 / 篡改检测 / 头部校验 / 边界 /
 *       memfd 写入 / mexec 真机执行（fork + 管道取回 stdout）。
 */

#include "packer.h"
#include "../src/pack_int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int g_total = 0;
static int g_fail  = 0;

#define CHECK(cond, name)                                                  \
    do {                                                                   \
        g_total++;                                                         \
        if (cond) {                                                        \
            printf("[PASS] %s\n", name);                                   \
        } else {                                                           \
            printf("[FAIL] %s  (%s:%d)\n", name, __FILE__, __LINE__);      \
            g_fail++;                                                      \
        }                                                                  \
    } while (0)

/* 确定性 PRNG（xorshift32），避免依赖 rand() 与系统熵 */
static uint32_t xs = 0x12345678u;
static uint32_t xs_next(void)
{
    xs ^= xs << 13;
    xs ^= xs >> 17;
    xs ^= xs << 5;
    return xs;
}

static void fill_random(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(xs_next() & 0xffu);
}

/* ---------- 读文件全部字节 ---------- */
static uint8_t *slurp(const char *path, size_t *len)
{
    FILE *f;
    uint8_t *buf;
    long sz;

    f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    sz = ftell(f);
    if (sz <= 0) { fclose(f); return NULL; }
    rewind(f);
    buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    *len = (size_t)sz;
    return buf;
}

/* ==================================================================== */
/* LZSS                                                                  */
/* ==================================================================== */

static void test_lzss(void)
{
    uint8_t raw[4096];
    uint8_t *comp, *dec;
    size_t   comp_len, dec_len;
    int      rc;

    comp = (uint8_t *)malloc(sizeof(raw) * 2 + 64);
    dec  = (uint8_t *)malloc(sizeof(raw) + 64);
    if (!comp || !dec) { printf("malloc failed\n"); exit(1); }

    /* 1. 全零：高可压缩 */
    memset(raw, 0, sizeof(raw));
    comp_len = sizeof(raw) * 2 + 64;
    rc = pk_lzss_compress(raw, sizeof(raw), comp, &comp_len);
    CHECK(rc == PK_OK, "lzss compress zeros ok");
    CHECK(comp_len < sizeof(raw) / 8, "lzss zeros 压缩率 > 8x");
    dec_len = sizeof(raw) + 64;
    rc = pk_lzss_decompress(comp, comp_len, dec, &dec_len);
    CHECK(rc == PK_OK && dec_len == sizeof(raw) &&
          memcmp(dec, raw, sizeof(raw)) == 0, "lzss zeros 往返一致");

    /* 2. 重复文本 */
    {
        size_t n = 0;
        while (n + 16 <= sizeof(raw)) { memcpy(raw + n, "ABCDABCDABCDABCD", 16); n += 16; }
        comp_len = sizeof(raw) * 2 + 64;
        rc = pk_lzss_compress(raw, n, comp, &comp_len);
        CHECK(rc == PK_OK && comp_len < n, "lzss 重复文本可压缩");
        dec_len = sizeof(raw) + 64;
        rc = pk_lzss_decompress(comp, comp_len, dec, &dec_len);
        CHECK(rc == PK_OK && dec_len == n && memcmp(dec, raw, n) == 0,
              "lzss 重复文本往返一致");
    }

    /* 3. 单字节 */
    raw[0] = 0xA5u;
    comp_len = 64;
    rc = pk_lzss_compress(raw, 1, comp, &comp_len);
    CHECK(rc == PK_OK, "lzss 单字节压缩 ok");
    dec_len = 64;
    rc = pk_lzss_decompress(comp, comp_len, dec, &dec_len);
    CHECK(rc == PK_OK && dec_len == 1 && dec[0] == 0xA5u, "lzss 单字节往返一致");

    /* 3b. 全字面量流（无长度>=3 的重复），专测字面量字节的位序
     *     取 0x5A 而非回文值，位反转会立刻暴露 */
    {
        size_t n = 0;
        while (n + 64 <= sizeof(raw)) {
            for (size_t k = 0; k < 64; k++) raw[n + k] = (uint8_t)((k * 7u + 3u) & 0xffu);
            n += 64;
        }
        comp_len = sizeof(raw) * 2 + 64;
        rc = pk_lzss_compress(raw, n, comp, &comp_len);
        CHECK(rc == PK_OK, "lzss 全字面量压缩 ok");
        dec_len = sizeof(raw) + 64;
        rc = pk_lzss_decompress(comp, comp_len, dec, &dec_len);
        CHECK(rc == PK_OK && dec_len == n && memcmp(dec, raw, n) == 0,
              "lzss 全字面量往返一致（位序）");
    }

    /* 4. 不可压缩数据：往返仍须成立（由 pack 层决定是否回退） */
    fill_random(raw, sizeof(raw));
    comp_len = sizeof(raw) * 2 + 64;
    rc = pk_lzss_compress(raw, sizeof(raw), comp, &comp_len);
    CHECK(rc == PK_OK, "lzss 随机数据压缩不报错");

    /* 5. 解压缓冲不足 */
    memset(raw, 0, sizeof(raw));
    comp_len = sizeof(raw) * 2 + 64;
    (void)pk_lzss_compress(raw, sizeof(raw), comp, &comp_len);
    dec_len = 8;
    rc = pk_lzss_decompress(comp, comp_len, dec, &dec_len);
    CHECK(rc == PK_ERR_NOMEM, "lzss 解压缓冲不足 -> NOMEM");

    /* 6. 损坏流：首个匹配项距离越界
     *    位流(LSB-first): flag=0, off=0xFFF(12bit), extra=0
     *    byte0 = 0xFE, byte1 = 0x1F */
    {
        uint8_t bad[2];
        bad[0] = 0xFEu; bad[1] = 0x1Fu;
        dec_len = 64;
        rc = pk_lzss_decompress(bad, 2, dec, &dec_len);
        CHECK(rc == PK_ERR_CORRUPT, "lzss 距离越界 -> CORRUPT");
    }

    /* 7. 参数校验 */
    dec_len = 64;
    CHECK(pk_lzss_compress(NULL, 10, comp, &comp_len) == PK_ERR_ARG,
          "lzss compress NULL -> ARG");
    CHECK(pk_lzss_decompress(NULL, 10, dec, &dec_len) == PK_ERR_ARG,
          "lzss decompress NULL -> ARG");

    free(comp); free(dec);
}

/* ==================================================================== */
/* pack / unpack                                                         */
/* ==================================================================== */

static const uint8_t SEED[32] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
    0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,
    0x0F,0x1E,0x2D,0x3C,0x4B,0x5A,0x69,0x78,
    0x87,0x96,0xA5,0xB4,0xC3,0xD2,0xE1,0xF0
};
static const uint8_t SEED2[32] = {
    0xF0,0xE1,0xD2,0xC3,0xB4,0xA5,0x96,0x87,
    0x78,0x69,0x5A,0x4B,0x3C,0x2D,0x1E,0x0F,
    0x00,0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,
    0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11
};

static void test_pack(void)
{
    uint8_t  raw[65536];
    uint8_t *blob, *out;
    size_t   raw_len, blob_len, out_len;
    pk_hdr   h;
    int      rc;

    blob = (uint8_t *)malloc(pk_size_bound(sizeof(raw)) + 256);
    out  = (uint8_t *)malloc(sizeof(raw) + 256);
    if (!blob || !out) { printf("malloc failed\n"); exit(1); }

    /* 8. 小载荷 */
    raw_len = 37;
    fill_random(raw, raw_len);
    blob_len = pk_size_bound(raw_len) + 256;
    rc = pk_pack(raw, raw_len, SEED, sizeof(SEED), blob, &blob_len);
    CHECK(rc == PK_OK, "pack 小载荷 ok");
    out_len = sizeof(raw) + 256;
    rc = pk_unpack_core(blob, blob_len, SEED, sizeof(SEED), out, &out_len);
    CHECK(rc == PK_OK && out_len == raw_len && memcmp(out, raw, raw_len) == 0,
          "unpack 小载荷往返一致");

    /* 9. 64KB 高可压缩：应启用压缩标志 */
    memset(raw, 0x5Au, sizeof(raw));
    raw_len = sizeof(raw);
    blob_len = pk_size_bound(raw_len) + 256;
    rc = pk_pack(raw, raw_len, SEED, sizeof(SEED), blob, &blob_len);
    CHECK(rc == PK_OK, "pack 64KB ok");
    rc = pk_header_parse(blob, blob_len, &h);
    CHECK(rc == PK_OK && (h.flags & PK_FLAG_COMPRESSED), "可压缩载荷置 COMPRESSED 标志");
    CHECK(blob_len < raw_len, "压缩后制品小于原始载荷");
    out_len = sizeof(raw) + 256;
    rc = pk_unpack_core(blob, blob_len, SEED, sizeof(SEED), out, &out_len);
    CHECK(rc == PK_OK && out_len == raw_len && memcmp(out, raw, raw_len) == 0,
          "unpack 64KB 往返一致");

    /* 10. 不可压缩：应回退原样，不置标志 */
    fill_random(raw, 8192);
    raw_len = 8192;
    blob_len = pk_size_bound(raw_len) + 256;
    rc = pk_pack(raw, raw_len, SEED, sizeof(SEED), blob, &blob_len);
    rc |= pk_header_parse(blob, blob_len, &h);
    CHECK(rc == PK_OK && !(h.flags & PK_FLAG_COMPRESSED), "随机载荷回退原样不压缩");
    out_len = sizeof(raw) + 256;
    rc = pk_unpack_core(blob, blob_len, SEED, sizeof(SEED), out, &out_len);
    CHECK(rc == PK_OK && out_len == raw_len && memcmp(out, raw, raw_len) == 0,
          "unpack 随机载荷往返一致");

    /* 11. 错误 seed */
    rc = pk_unpack_core(blob, blob_len, SEED2, sizeof(SEED2), out, &out_len);
    CHECK(rc == PK_ERR_AUTH, "错误 seed -> AUTH");

    /* 12. 篡改密文 */
    fill_random(raw, 512);
    blob_len = pk_size_bound(512) + 256;
    (void)pk_pack(raw, 512, SEED, sizeof(SEED), blob, &blob_len);
    {
        uint8_t save = blob[PK_HDR_LEN + 10];
        blob[PK_HDR_LEN + 10] ^= 0x01u;
        out_len = sizeof(raw) + 256;
        rc = pk_unpack_core(blob, blob_len, SEED, sizeof(SEED), out, &out_len);
        CHECK(rc == PK_ERR_AUTH, "篡改密文 -> AUTH");
        blob[PK_HDR_LEN + 10] = save;
        out_len = sizeof(raw) + 256;
        rc = pk_unpack_core(blob, blob_len, SEED, sizeof(SEED), out, &out_len);
        CHECK(rc == PK_OK, "还原密文 -> 恢复可用");
    }

    /* 13. 篡改 tag */
    blob[60 + 3] ^= 0x80u;
    out_len = sizeof(raw) + 256;
    rc = pk_unpack_core(blob, blob_len, SEED, sizeof(SEED), out, &out_len);
    CHECK(rc == PK_ERR_AUTH, "篡改 tag -> AUTH");

    /* 14~17. 篡改头部（全部进 AAD，必须被拒） */
    fill_random(raw, 512);
    blob_len = pk_size_bound(512) + 256;
    (void)pk_pack(raw, 512, SEED, sizeof(SEED), blob, &blob_len);

    {
        uint8_t sv = blob[0];
        blob[0] ^= 0xFFu;
        rc = pk_header_parse(blob, blob_len, &h);
        CHECK(rc == PK_ERR_MAGIC, "篡改 magic -> MAGIC");
        blob[0] = sv;
    }
    {
        uint8_t sv = blob[8];
        blob[8] ^= 0x01u;
        rc = pk_header_parse(blob, blob_len, &h);
        CHECK(rc == PK_ERR_VERSION, "篡改 version -> VERSION");
        blob[8] = sv;
    }
    {
        uint8_t sv = blob[24];
        blob[24] ^= 0x08u;
        rc = pk_header_parse(blob, blob_len, &h);
        CHECK(rc == PK_ERR_LEN, "篡改 pay_len -> LEN");
        blob[24] = sv;
    }
    {
        uint8_t sv = blob[32];
        blob[32] ^= 0x01u;
        out_len = sizeof(raw) + 256;
        rc = pk_unpack_core(blob, blob_len, SEED, sizeof(SEED), out, &out_len);
        CHECK(rc == PK_ERR_AUTH, "篡改 salt -> AUTH（salt 在 AAD 内）");
        blob[32] = sv;
    }
    {
        uint8_t sv = blob[12];
        blob[12] ^= 0x01u;   /* flags 位 */
        out_len = sizeof(raw) + 256;
        rc = pk_unpack_core(blob, blob_len, SEED, sizeof(SEED), out, &out_len);
        CHECK(rc == PK_ERR_AUTH, "篡改 flags -> AUTH（flags 在 AAD 内）");
        blob[12] = sv;
    }

    /* 18. 制品过短 */
    rc = pk_header_parse(blob, PK_HDR_LEN - 1, &h);
    CHECK(rc == PK_ERR_SMALL, "制品短于头 -> SMALL");

    /* 19. 输出缓冲不足 */
    out_len = 8;
    rc = pk_unpack_core(blob, blob_len, SEED, sizeof(SEED), out, &out_len);
    CHECK(rc == PK_ERR_NOMEM, "解包缓冲不足 -> NOMEM");

    /* 20/21. 参数校验 */
    blob_len = pk_size_bound(16) + 256;
    CHECK(pk_pack(NULL, 16, SEED, sizeof(SEED), blob, &blob_len) == PK_ERR_ARG,
          "pack NULL 载荷 -> ARG");
    CHECK(pk_pack(raw, 0, SEED, sizeof(SEED), blob, &blob_len) == PK_ERR_ARG,
          "pack 零长度 -> ARG");
    CHECK(pk_pack(raw, 16, NULL, 0, blob, &blob_len) == PK_ERR_ARG,
          "pack 空 seed -> ARG");
    {
        size_t small = 16;
        CHECK(pk_pack(raw, 4096, SEED, sizeof(SEED), blob, &small) == PK_ERR_NOMEM,
              "pack 缓冲不足 -> NOMEM");
    }

    /* 22. size_bound 单调性 */
    CHECK(pk_size_bound(1000) >= PK_HDR_LEN + 1000, "size_bound 覆盖最坏情形");

    free(blob); free(out);
}

/* ==================================================================== */
/* memfd / mexec                                                         */
/* ==================================================================== */

static void test_mexec(void)
{
    uint8_t *elf = NULL;
    size_t   elf_len = 0;
    int      fd;
    uint8_t  rbuf[64];
    ssize_t  n;

    elf = slurp("build/mexec_target", &elf_len);
    if (!elf) {
        printf("[SKIP] mexec: 未找到 build/mexec_target\n");
        return;
    }

    /* 23. memfd 写入可读回 */
    fd = pk_memfd_write(elf, elf_len);
    CHECK(fd >= 0, "memfd_write 返回有效 fd");
    if (fd >= 0) {
        memset(rbuf, 0, sizeof(rbuf));
        n = pread(fd, rbuf, sizeof(rbuf), 0);
        CHECK(n == (ssize_t)sizeof(rbuf) && memcmp(rbuf, elf, sizeof(rbuf)) == 0,
              "memfd 内容可读回一致");
        close(fd);
    }
    CHECK(pk_memfd_write(NULL, 10) == PK_ERR_ARG, "memfd NULL -> ARG");

    /* 24. mexec 真机执行：fork + 管道取回 stdout */
    {
        int pfd[2];
        pid_t pid;
        char  buf[256];

        if (pipe(pfd) != 0) { CHECK(0, "pipe 建立"); free(elf); return; }
        pid = fork();
        if (pid == 0) {
            char *argv[3];
            char *envp[2];
            close(pfd[0]);
            dup2(pfd[1], STDOUT_FILENO);
            close(pfd[1]);
            argv[0] = (char *)"mexec_target";
            argv[1] = (char *)"FROM_MEMFD";
            argv[2] = NULL;
            envp[0] = (char *)"PATH=/usr/bin:/bin";
            envp[1] = NULL;
            pk_mexec(elf, elf_len, argv, envp);
            _exit(127);   /* 只有 execveat 失败才会到这里 */
        }
        close(pfd[1]);
        memset(buf, 0, sizeof(buf));
        {
            ssize_t got = read(pfd[0], buf, sizeof(buf) - 1);
            if (got < 0) got = 0;
            buf[got] = '\0';
        }
        close(pfd[0]);
        {
            int st = 0;
            waitpid(pid, &st, 0);
            CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
                  "mexec 子进程退出码 0");
        }
        CHECK(strncmp(buf, "MEXEC_OK argv1=FROM_MEMFD", 25) == 0,
              "mexec 真机执行取回预期输出");
        if (strncmp(buf, "MEXEC_OK argv1=FROM_MEMFD", 25) != 0)
            printf("       实际输出: %s\n", buf);
    }

    /* 25. 打包后的 ELF 经解包再执行：完整链路 */
    {
        uint8_t *blob, *out;
        size_t   blob_len, out_len;
        int      pfd[2];
        pid_t    pid;
        char     buf[256];

        blob = (uint8_t *)malloc(pk_size_bound(elf_len) + 256);
        out  = (uint8_t *)malloc(elf_len + 256);
        if (!blob || !out) { free(elf); return; }

        blob_len = pk_size_bound(elf_len) + 256;
        CHECK(pk_pack(elf, elf_len, SEED, sizeof(SEED), blob, &blob_len) == PK_OK,
              "ELF 打包 ok");
        out_len = elf_len + 256;
        CHECK(pk_unpack_core(blob, blob_len, SEED, sizeof(SEED), out, &out_len) == PK_OK &&
              out_len == elf_len && memcmp(out, elf, elf_len) == 0,
              "ELF 解包字节级一致");

        if (pipe(pfd) != 0) { free(blob); free(out); free(elf); return; }
        pid = fork();
        if (pid == 0) {
            char *argv[3];
            char *envp[2];
            close(pfd[0]);
            dup2(pfd[1], STDOUT_FILENO);
            close(pfd[1]);
            argv[0] = (char *)"unpacked";
            argv[1] = (char *)"AFTER_UNPACK";
            argv[2] = NULL;
            envp[0] = (char *)"PATH=/usr/bin:/bin";
            envp[1] = NULL;
            pk_mexec(out, out_len, argv, envp);
            _exit(127);
        }
        close(pfd[1]);
        memset(buf, 0, sizeof(buf));
        {
            ssize_t got = read(pfd[0], buf, sizeof(buf) - 1);
            if (got < 0) got = 0;
            buf[got] = '\0';
        }
        close(pfd[0]);
        {
            int st = 0;
            waitpid(pid, &st, 0);
        }
        CHECK(strncmp(buf, "MEXEC_OK argv1=AFTER_UNPACK", 27) == 0,
              "解包后 ELF 无磁盘执行取回预期输出");
        if (strncmp(buf, "MEXEC_OK argv1=AFTER_UNPACK", 27) != 0)
            printf("       实际输出: %s\n", buf);

        free(blob); free(out);
    }

    free(elf);
}

int main(void)
{
    printf("\n=== 20_packer: 压缩 / 打包 / 内存执行 ===\n\n");
    test_lzss();
    test_pack();
    test_mexec();
    printf("\ntotal=%d pass=%d fail=%d\n",
           g_total, g_total - g_fail, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
