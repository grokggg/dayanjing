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
    PERSIST_LKM
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

size_t persist_method_count(void);
const persist_desc_t *persist_method_at(size_t i);

/* 安装/卸载：以 root_prefix 作为假根，仅对文件型方法生效。
 * 成功 0；平台不支持返回 -2；IO 失败返回 -1 */
int persist_install(persist_method_t m, const char *root_prefix, const char *arg);
int persist_uninstall(persist_method_t m, const char *root_prefix, const char *arg);

/* 内核态 LKM 模板源码（沙盒无内核头，不可编译验证，仅作交付物） */
const char *persist_kernel_source(void);


/* ---- 枚举（完整能力） ---- */
typedef void (*persist_cb_t)(persist_method_t m, const char *fname,
                             const char *fpath, void *ud);

/* 扫描假根下已安装的持久化项，逐项回调。返回回调次数；-1 参数错误 */
int persist_enumerate(const char *root_prefix, persist_cb_t cb, void *ud);

/* 查询某一方法在假根下是否已安装：1=已装 0=未装 -1=非文件型/参数错误 */
int persist_installed(const char *root_prefix, persist_method_t m);

#endif
