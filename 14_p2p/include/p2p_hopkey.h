/*
 * DAYANJING v4 — p2p_hopkey.h
 *
 * 跳静态密钥轮换（Hop Static Key Rotation）—— 把 ephemeral-static 补成真 PFS。
 *
 * ====================================================================
 * 解决的问题（原限制的精确表述）
 * ====================================================================
 * 洋葱层密钥是 X25519 ephemeral-static（Tor ntor 同构）：
 *   建电路方生成临时密钥对 (e, E)
 *   ss = X25519(e, pk_hop) = X25519(sk_hop, E)
 * 这保证了"不知道 sk_hop 就解不开该跳的层"，但**不保证前向保密**：
 *   若某跳静态私钥 sk_hop 日后泄露，且攻击者完整录制了当时的电路建立报文
 *   （报文里有明文 E），则可离线重算 ss -> 还原该跳那一层。
 *
 * ====================================================================
 * 轮换如何补上 PFS
 * ====================================================================
 * 每一"纪元(epoch)"重新生成跳静态密钥对，并把**上一纪元的私钥安全擦除**：
 *
 *   epoch 0: (sk0, pk0)
 *   epoch 1: (sk1, pk1)   sk0 仍保留（在途电路可能还没走完）
 *   epoch 2: (sk2, pk2)   sk0 已被安全擦除 -> epoch 0 的录制报文永久解不开
 *
 * 保留槽位 P2P_HOPKEY_RETAIN = 2（当前 + 上一个）。超出保留窗口的私钥
 * 用 secure_zero 擦除（volatile 逐字节写，防编译器优化掉）。
 *
 * 结果：攻击者必须在"电路建立"到"纪元滚出保留窗口"这段时间内拿到私钥，
 * 才能解开那一层；之后录制再多报文也没用 —— 这就是前向保密。
 *
 * ====================================================================
 * 为什么不需要改线上格式
 * ====================================================================
 * 剥层侧依次用保留窗口内的每个 epoch 私钥尝试，第一个验签通过的即为正确
 * epoch（GCM tag 会拒绝错误密钥，不存在"猜错但解出"的情况）。
 * 因此**层明文里不必携带 epoch 字段**，与既有 v2 层格式完全兼容。
 *
 * 代价：剥层最多试 P2P_HOPKEY_RETAIN 次 GCM_open，即最坏 2 次。
 *
 * 密码学复用 00_crypto 的 X25519，不自研第二套。
 */

#ifndef DAYANJING_P2P_HOPKEY_H
#define DAYANJING_P2P_HOPKEY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 保留的纪元数：当前 + 上一个。改大=更长的在途容忍期，PFS 生效更慢；
 * 改小=PFS 更快生效，但在途电路可能剥不开。2 是工程折中。 */
#define P2P_HOPKEY_RETAIN   2
#define P2P_HOPKEY_KEY_LEN  32

#define P2P_HOPKEY_OK        0
#define P2P_HOPKEY_ERR_ARG  -1
#define P2P_HOPKEY_ERR_AUTH -3   /* 所有保留 epoch 都验签失败 */

typedef struct {
    uint32_t epoch;
    uint8_t  sk[P2P_HOPKEY_KEY_LEN];
    uint8_t  pk[P2P_HOPKEY_KEY_LEN];
} p2p_hopkey_slot_t;

typedef struct {
    p2p_hopkey_slot_t slots[P2P_HOPKEY_RETAIN];
    int      n;            /* 有效槽位数，slots[0] 为最新 */
    uint32_t next_epoch;
} p2p_hopkey_t;

/* 初始生成 epoch 0 密钥对。 */
int  p2p_hopkey_init(p2p_hopkey_t *h);

/* 安全擦除全部槽位（含所有私钥）。 */
void p2p_hopkey_wipe(p2p_hopkey_t *h);

/*
 * 轮换到新纪元：slots 整体后移，最老的槽位私钥先安全擦除再复用。
 * new_epoch 返回新纪元号（可为 NULL）。
 */
int  p2p_hopkey_rotate(p2p_hopkey_t *h, uint32_t *new_epoch);

/* 当前（最新）纪元号与公钥。 */
uint32_t p2p_hopkey_epoch(const p2p_hopkey_t *h);
int      p2p_hopkey_pub(const p2p_hopkey_t *h, uint8_t out[P2P_HOPKEY_KEY_LEN]);

/* 该 epoch 的私钥是否仍在保留窗口内（能剥开对应层）。 */
int  p2p_hopkey_has_epoch(const p2p_hopkey_t *h, uint32_t epoch);

/*
 * 轮换感知的剥层：依次用保留窗口内的私钥尝试 p2p_onion_peel。
 * used_epoch 返回实际解开所用的 epoch（可为 NULL）。
 *
 * 全部失败返回 P2P_HOPKEY_ERR_AUTH —— "不是给我的 / 被篡改 / 纪元已滚出窗口"
 * 三者统一表现，不给攻击者区分信号。
 */
int  p2p_hopkey_peel(const p2p_hopkey_t *h,
                     const uint8_t salt[16],
                     const uint8_t my_id[16],
                     const uint8_t *onion, size_t onion_len,
                     int *final_flag,
                     uint8_t next_id[16],
                     char *final_host, size_t host_cap, uint16_t *final_port,
                     uint8_t *inner, size_t inner_cap, size_t *inner_len,
                     uint32_t *used_epoch);

/*
 * 主动遗忘指定纪元（不等轮换就擦除其私钥）。
 * 用于"已知某电路已结束，立即销毁其层密钥"的场景。
 * 返回 P2P_HOPKEY_OK / P2P_HOPKEY_ERR_ARG（纪元不在窗口内）。
 */
int  p2p_hopkey_forget(p2p_hopkey_t *h, uint32_t epoch);

const char *p2p_hopkey_errstr(int e);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_P2P_HOPKEY_H */
