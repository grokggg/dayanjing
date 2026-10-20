/*
 * DAYANJING v4 — p2p_crypto.h
 *
 * 14_p2p 的端到端加密（E2EE）隧道层。
 *
 * 分层约定：
 *   本层     = 端点侧 AEAD 封装（sealed wire），密钥只在通信两端存在
 *   中间跳   = 只转发不透明密文字节，永不调用 unwrap
 *   数据面   = 08_lateral/proxy.c 的 poll 双工中继，不重复实现
 *
 * E2EE 性质（可验证）：
 *   1. 逐跳转发的是密文，中间节点无密钥 -> 无法读取载荷
 *   2. 中间节点篡改任一字节 -> 端点侧验签失败（AEAD 完整性覆盖全跳）
 *   3. 重放同一帧 -> 接收侧滑动窗口拒绝
 *
 * 底层 AEAD 复用 02_c2 的 c2_frame（AES-128-GCM，与 Python 侧逐字节对齐），
 * 不自研第二套密码学——密码学只应有一处实现。
 */

#ifndef DAYANJING_P2P_CRYPTO_H
#define DAYANJING_P2P_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define P2P_KEY_LEN        16
#define P2P_NONCE_PFX_LEN   8
#define P2P_REPLAY_WINDOW  64   /* 滑动窗口宽度（按 seq 计） */
#define P2P_C_ID_LEN       16   /* 节点 ID 长度，须与 p2p.h 的 P2P_NODE_ID_LEN 一致 */

/* ---- 返回值 ---- */
#define P2P_C_OK        0
#define P2P_C_ERR_ARG  -1   /* 参数非法 */
#define P2P_C_ERR_LEN  -2   /* 长度非法 / 缓冲区不足 */
#define P2P_C_ERR_AUTH -3   /* 验签失败（篡改或密钥错误） */
#define P2P_C_ERR_FMT  -4   /* 格式错误 */
#define P2P_C_ERR_REPLAY -5 /* 重放或过旧 */

typedef struct {
    uint8_t  k_send[P2P_KEY_LEN];       /* 本端 -> 对端 */
    uint8_t  k_recv[P2P_KEY_LEN];       /* 对端 -> 本端 */
    uint8_t  nonce_pfx[P2P_NONCE_PFX_LEN];

    uint64_t send_seq;                  /* 单调递增，每帧 +1 */
    uint32_t send_counter;              /* IV 计数器，每帧 +1，不可复用 */

    /* 接收侧重放窗口 */
    int      recv_init;                 /* 是否已收到首帧 */
    uint64_t highest;                   /* 已见最大 seq */
    uint64_t bitmap;                    /* bit0 = highest，bit i = highest - i */
} p2p_tunnel_t;

/*
 * 初始化隧道。k_send/k_recv 必须 16 字节且互不相同（单向密钥分离）。
 * nonce_pfx 必须 8 字节；两端方向相反：A 的 k_send 即 B 的 k_recv。
 */
int p2p_tunnel_init(p2p_tunnel_t *t,
                    const uint8_t k_send[P2P_KEY_LEN],
                    const uint8_t k_recv[P2P_KEY_LEN],
                    const uint8_t nonce_pfx[P2P_NONCE_PFX_LEN]);

/*
 * 从 02_c2 会话密钥派生隧道密钥（生产路径）。
 *
 * 与 p2p_tunnel_init 的区别：
 *   p2p_tunnel_init           —— 直接传入 16 字节裸密钥（测试/外部 KMS 场景）
 *   p2p_tunnel_init_from_session —— 由握手产出的会话密钥派生（生产路径）
 *
 * 派生方式：HKDF-SHA256（RFC 5869，复用 00_crypto，不自研第二套）
 *   salt = "dayanjing:p2p:tunnel:v1"
 *   IKM  = k_c2s || k_s2c            （32 字节，两个方向密钥共同贡献熵）
 *   info = "p2p:tunnel:keys:v1" || local_id || peer_id
 *   OKM  = k_forward(16) || k_reverse(16) || nonce_pfx(8)
 *
 * 方向由两端 ID 的规范序（memcmp）决定，而不是由"谁先发起"决定：
 *   local_id < peer_id  -> k_send = k_forward, k_recv = k_reverse
 *   local_id > peer_id  -> k_send = k_reverse, k_recv = k_forward
 *
 * 这样双方各自独立计算即可得出同一组方向密钥，无需额外交换角色字节，
 * 也避免"两端都认为自己是 initiator"导致的密钥方向错位。
 *
 * local_id == peer_id 返回 P2P_C_ERR_ARG（禁止与自身建隧道）。
 * k_c2s == k_s2c 返回 P2P_C_ERR_ARG（会话密钥已退化，不派生）。
 */
int p2p_tunnel_init_from_session(p2p_tunnel_t *t,
                                 const uint8_t k_c2s[P2P_KEY_LEN],
                                 const uint8_t k_s2c[P2P_KEY_LEN],
                                 const uint8_t local_id[P2P_C_ID_LEN],
                                 const uint8_t peer_id[P2P_C_ID_LEN]);

/* 清零密钥材料（进程退出前调用，避免密钥滞留内存/核心转储） */
void p2p_tunnel_wipe(p2p_tunnel_t *t);

/*
 * 封装：payload -> sealed wire。
 * out 可为 NULL（仅探测所需长度）。成功后 send_seq/send_counter 各 +1。
 */
int p2p_tunnel_wrap(p2p_tunnel_t *t, uint32_t msg_type,
                    const uint8_t *payload, size_t plen,
                    uint8_t *out, size_t cap, size_t *out_len);

/*
 * 解封：sealed wire -> payload，并做重放窗口检查。
 * 验签通过后才更新窗口，篡改帧不会污染窗口状态。
 * payload 可为 NULL（仅探测所需长度）。
 */
int p2p_tunnel_unwrap(p2p_tunnel_t *t,
                      const uint8_t *wire, size_t wire_len,
                      uint64_t *seq, uint32_t *msg_type,
                      uint8_t *payload, size_t cap, size_t *plen);

/* 给定 payload 长度，返回 sealed wire 长度 */
size_t p2p_tunnel_wire_len(size_t plen);

/*
 * 从 sealed wire 头解析出整帧长度（含 4 字节长度前缀本身）。
 * 供中继/抓包端按帧切分——wire 自带长度前缀，无需额外分帧。
 * 返回 P2P_C_OK 或 P2P_C_ERR_FMT（不足 4 字节）。
 */
int p2p_tunnel_frame_len(const uint8_t *wire, size_t wire_len, size_t *frame_len);

/*
 * 在已建立的电路 fd 上收发一帧（E2EE 与动态路由的叠加点）。
 *
 * wire 自带 4 字节长度前缀，故 recv 可精确切帧，无需额外分帧层。
 * send 内部 wrap 后整帧写出；recv 读满一帧后 unwrap（含重放窗口检查）。
 * 返回 P2P_C_OK 或负错误码；对端关闭返回 P2P_C_ERR_FMT。
 */
int p2p_tunnel_send(p2p_tunnel_t *t, int fd, uint32_t msg_type,
                    const uint8_t *payload, size_t plen);
int p2p_tunnel_recv(p2p_tunnel_t *t, int fd,
                    uint64_t *seq, uint32_t *msg_type,
                    uint8_t *payload, size_t cap, size_t *plen);

const char *p2p_c_errstr(int e);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_P2P_CRYPTO_H */
