/* DAYANJING v4 — monolith/tools/embedcfg.c
 *
 * 生成待烧录的配置块（.mono_cfg 段内容）。
 *
 * 用法：
 *   embedcfg <out.bin> [--host H] [--port N] [--id STR] [--psk-hex HEX]
 *            [--persist-root DIR] [--run-ms N] [--period N] [--budget N]
 *            [--check <elf>]
 *
 * --check：读目标 ELF，定位 .mono_cfg 段并比对大小。
 *   这一项是必须的：objcopy --update-section 要求输入文件与段大小
 *   精确相等，否则直接失败。而"段不存在"与"大小不符"若不做检查，
 *   会在构建脚本里表现为一个含糊的 objcopy 错误。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mono_embed.h"

static int hexparse(const char *h, uint8_t *out, size_t cap, size_t *n)
{
    size_t i = 0;
    while (h[2 * i] && h[2 * i + 1] && i < cap) {
        unsigned b = 0;
        if (sscanf(h + 2 * i, "%2x", &b) != 1) break;
        out[i++] = (uint8_t)b;
    }
    *n = i;
    return (i > 0 && i <= cap) ? 0 : -1;
}

/* 定位 .mono_cfg 段（64 位 ELF）。只做大小核对，不做完整解析 ——
   段头表项固定 64 字节，名称靠 shstrtab 索引。*/
static int check_elf(const char *path, size_t want)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "check: cannot open %s\n", path); return -1; }
    unsigned char e[64];
    if (fread(e, 1, 64, f) != 64) { fclose(f); return -1; }
    if (memcmp(e, "\177ELF", 4) != 0) { fclose(f); fprintf(stderr, "check: not ELF\n"); return -1; }

    uint64_t shoff = 0; uint16_t shentsize = 0, shnum = 0, shstrndx = 0;
    memcpy(&shoff, e + 0x28, 8);
    memcpy(&shentsize, e + 0x3a, 2);
    memcpy(&shnum, e + 0x3c, 2);
    memcpy(&shstrndx, e + 0x3e, 2);
    if (shentsize != 64 || shnum == 0 || shstrndx >= shnum) { fclose(f); fprintf(stderr, "check: bad shdr\n"); return -1; }

    fseek(f, (long)shoff, SEEK_SET);
    unsigned char *sh = malloc((size_t)shnum * shentsize);
    if (!sh) { fclose(f); return -1; }
    if (fread(sh, 1, (size_t)shnum * shentsize, f) != (size_t)shnum * shentsize) { free(sh); fclose(f); return -1; }

    uint64_t stroff = 0, strsz = 0;
    memcpy(&stroff, sh + (size_t)shstrndx * 64 + 24, 8);
    memcpy(&strsz, sh + (size_t)shstrndx * 64 + 32, 8);
    char *str = malloc(strsz ? (size_t)strsz : 1);
    if (!str) { free(sh); fclose(f); return -1; }
    fseek(f, (long)stroff, SEEK_SET);
    if (fread(str, 1, (size_t)strsz, f) != (size_t)strsz) { free(str); free(sh); fclose(f); return -1; }

    for (uint16_t i = 0; i < shnum; i++) {
        uint32_t nm = 0; uint64_t sz = 0;
        memcpy(&nm, sh + (size_t)i * 64 + 0, 4);
        memcpy(&sz, sh + (size_t)i * 64 + 32, 8);
        if (nm >= strsz) continue;
        if (!strcmp(str + nm, ".mono_cfg")) {
            int ok = (sz == want);
            printf("check: .mono_cfg size=%llu want=%zu -> %s\n",
                   (unsigned long long)sz, want, ok ? "OK" : "MISMATCH");
            free(str); free(sh); fclose(f);
            return ok ? 0 : -1;
        }
    }
    fprintf(stderr, "check: .mono_cfg not found (embed section missing)\n");
    free(str); free(sh); fclose(f);
    return -1;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <out.bin> [options]\n", argv[0]);
        return 2;
    }
    mono_embed_t e;
    memset(&e, 0, sizeof e);
    e.magic = MONO_EMBED_MAGIC;
    e.ver = MONO_EMBED_VER;

    const char *ck = NULL;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--host") && i + 1 < argc)
            snprintf(e.host, sizeof e.host, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--id") && i + 1 < argc)
            snprintf(e.id, sizeof e.id, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--persist-root") && i + 1 < argc)
            snprintf(e.persist_root, sizeof e.persist_root, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--port") && i + 1 < argc)
            e.port = (uint16_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--run-ms") && i + 1 < argc)
            e.run_ms = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--period") && i + 1 < argc)
            e.period_ms = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--budget") && i + 1 < argc)
            e.budget_bpm = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--psk-hex") && i + 1 < argc) {
            size_t n = 0;
            if (hexparse(argv[++i], e.psk, sizeof e.psk, &n) != 0) {
                fprintf(stderr, "bad psk hex\n"); return 2;
            }
            e.psk_len = (uint8_t)n;
        } else if (!strcmp(argv[i], "--allow-sandbox"))
            e.flags |= MONO_EMBED_FLAG_ALLOW_SANDBOX;
        else if (!strcmp(argv[i], "--check") && i + 1 < argc)
            ck = argv[++i];
        else { fprintf(stderr, "bad arg: %s\n", argv[i]); return 2; }
    }

    if (ck && check_elf(ck, sizeof e) != 0) return 1;

    FILE *f = fopen(argv[1], "wb");
    if (!f) { fprintf(stderr, "cannot write %s\n", argv[1]); return 1; }
    size_t w = fwrite(&e, 1, sizeof e, f);
    fclose(f);
    if (w != sizeof e) return 1;
    printf("embedcfg: wrote %zu bytes host=%s port=%u id=%s persist_root=%s\n",
           sizeof e, e.host, e.port, e.id, e.persist_root);
    return 0;
}
