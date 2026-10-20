#include "p2p.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

const char *p2p_errstr(int e) {
    switch (e) {
        case P2P_OK:           return "ok";
        case P2P_ERR_ARGS:     return "invalid argument";
        case P2P_ERR_NOTFOUND: return "node not found";
        case P2P_ERR_FULL:     return "table full";
        case P2P_ERR_EXISTS:   return "already exists";
        case P2P_ERR_NOLINK:   return "no such link";
        case P2P_ERR_NOROUTE:  return "no route";
        case P2P_ERR_UNREACH:  return "endpoint unreachable";
        default:               return "unknown";
    }
}

static int node_idx(const p2p_mesh_t *m, const uint8_t *id) {
    for (int i = 0; i < m->n_nodes; i++)
        if (memcmp(m->nodes[i].id, id, P2P_NODE_ID_LEN) == 0)
            return i;
    return -1;
}

/* 在节点 ia 的邻居表中定位 b 的下标；未连返回 -1。
 * 度量数组与邻居数组同下标，靠这个函数保持三者对齐。 */
static int nbr_index(const p2p_mesh_t *m, int ia, const uint8_t *b) {
    const p2p_node_t *A = &m->nodes[ia];
    for (int j = 0; j < A->n_neighbors; j++)
        if (memcmp(A->neighbors[j], b, P2P_NODE_ID_LEN) == 0) return j;
    return -1;
}

int p2p_mesh_init(p2p_mesh_t *m) {
    if (!m) return P2P_ERR_ARGS;
    memset(m, 0, sizeof(*m));
    return P2P_OK;
}

int p2p_node_add(p2p_mesh_t *m, const uint8_t *id, p2p_role_t role,
                 const char *alias, const char *host, uint16_t port) {
    if (!m || !id || !alias || !host) return P2P_ERR_ARGS;
    if (role != P2P_ROLE_ENDPOINT && role != P2P_ROLE_EDGE && role != P2P_ROLE_CORE)
        return P2P_ERR_ARGS;
    if (m->n_nodes >= P2P_MAX_NODES) return P2P_ERR_FULL;
    if (node_idx(m, id) >= 0)        return P2P_ERR_EXISTS;

    p2p_node_t *n = &m->nodes[m->n_nodes];
    memcpy(n->id, id, P2P_NODE_ID_LEN);
    n->role = role;

    /* 定长缓冲必须显式截断并保证 NUL 终止，snprintf 已保证 */
    size_t k;
    for (k = 0; k + 1 < P2P_ALIAS_LEN && alias[k]; k++) n->alias[k] = alias[k];
    n->alias[k] = '\0';
    for (k = 0; k + 1 < P2P_HOST_LEN && host[k]; k++) n->host[k] = host[k];
    n->host[k] = '\0';

    n->port        = port;
    n->alive       = 1;
    n->n_neighbors = 0;
    m->n_nodes++;
    return P2P_OK;
}

int p2p_node_del(p2p_mesh_t *m, const uint8_t *id) {
    int i = (!m || !id) ? -1 : node_idx(m, id);
    if (i < 0) return P2P_ERR_NOTFOUND;

    /* 先摘掉所有邻居表中的该节点，避免删除后留下悬空 ID */
    for (int k = 0; k < m->n_nodes; k++) {
        if (k == i) continue;
        p2p_node_t *o = &m->nodes[k];
        for (int j = 0; j < o->n_neighbors; j++) {
            if (memcmp(o->neighbors[j], id, P2P_NODE_ID_LEN) == 0) {
                /* 与末位交换后收缩，j 回退以重新检查换上来的元素；
                 * 度量数组必须与邻居数组同下标 swap，否则会错位 */
                int last = o->n_neighbors - 1;
                memcpy(o->neighbors[j], o->neighbors[last], P2P_NODE_ID_LEN);
                o->nbr_rtt[j]      = o->nbr_rtt[last];
                o->nbr_rtt_ewma[j] = o->nbr_rtt_ewma[last];
                o->nbr_jitter[j]   = o->nbr_jitter[last];
                o->nbr_bw[j]       = o->nbr_bw[last];
                o->nbr_ok[j]       = o->nbr_ok[last];
                o->nbr_fail[j]     = o->nbr_fail[last];
                o->nbr_lastprobe[j] = o->nbr_lastprobe[last];
                o->nbr_pbackoff[j]  = o->nbr_pbackoff[last];
                o->n_neighbors--;
                j--;
            }
        }
    }
    /* 末位补位；n_nodes 为 1 时是自我覆盖，安全 */
    m->nodes[i] = m->nodes[m->n_nodes - 1];
    memset(&m->nodes[m->n_nodes - 1], 0, sizeof(p2p_node_t));
    m->n_nodes--;
    return P2P_OK;
}

/* 注意：不能返回 -1 表示未找到——-1 已被 P2P_ERR_ARGS 占用，
 * 而 -1 也可能被误当成合法下标。统一用 P2P_ERR_NOTFOUND(-3)。 */
int p2p_node_find(const p2p_mesh_t *m, const uint8_t *id) {
    if (!m || !id) return P2P_ERR_ARGS;
    int i = node_idx(m, id);
    return i < 0 ? P2P_ERR_NOTFOUND : i;
}

int p2p_node_mark_dead(p2p_mesh_t *m, const uint8_t *id) {
    if (!m || !id) return P2P_ERR_ARGS;
    int i = node_idx(m, id);
    if (i < 0) return P2P_ERR_NOTFOUND;
    m->nodes[i].alive = 0;
    return P2P_OK;
}

int p2p_node_mark_alive(p2p_mesh_t *m, const uint8_t *id) {
    if (!m || !id) return P2P_ERR_ARGS;
    int i = node_idx(m, id);
    if (i < 0) return P2P_ERR_NOTFOUND;
    m->nodes[i].alive = 1;
    return P2P_OK;
}

int p2p_node_count(const p2p_mesh_t *m, p2p_role_t role) {
    if (!m) return P2P_ERR_ARGS;
    int c = 0;
    for (int i = 0; i < m->n_nodes; i++)
        if (m->nodes[i].role == role) c++;
    return c;
}

int p2p_node_set_pub(p2p_mesh_t *m, const uint8_t *id,
                     const uint8_t pub[P2P_PUBKEY_LEN]) {
    if (!m || !id || !pub) return P2P_ERR_ARGS;
    int i = node_idx(m, id);
    if (i < 0) return P2P_ERR_NOTFOUND;
    memcpy(m->nodes[i].pub, pub, P2P_PUBKEY_LEN);
    m->nodes[i].has_pub = 1;
    return P2P_OK;
}

int p2p_node_get_pub(const p2p_mesh_t *m, const uint8_t *id,
                     uint8_t out[P2P_PUBKEY_LEN]) {
    if (!m || !id || !out) return P2P_ERR_ARGS;
    int i = node_idx(m, id);
    if (i < 0) return P2P_ERR_NOTFOUND;
    if (!m->nodes[i].has_pub) return P2P_ERR_NOTFOUND;
    memcpy(out, m->nodes[i].pub, P2P_PUBKEY_LEN);
    return P2P_OK;
}

int p2p_neighbor_link(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b) {
    if (!m || !a || !b) return P2P_ERR_ARGS;
    int ia = node_idx(m, a), ib = node_idx(m, b);
    if (ia < 0 || ib < 0) return P2P_ERR_NOTFOUND;
    if (ia == ib)         return P2P_ERR_ARGS;

    p2p_node_t *A = &m->nodes[ia], *B = &m->nodes[ib];
    if (A->n_neighbors >= P2P_MAX_NEIGHBORS ||
        B->n_neighbors >= P2P_MAX_NEIGHBORS) return P2P_ERR_FULL;
    if (p2p_neighbor_has(m, a, b)) return P2P_ERR_EXISTS;

    int ka = A->n_neighbors;
    memcpy(A->neighbors[A->n_neighbors++], b, P2P_NODE_ID_LEN);
    A->nbr_rtt[ka]      = 0;
    A->nbr_rtt_ewma[ka] = 0;
    A->nbr_jitter[ka]   = 0;
    A->nbr_bw[ka]       = 0;
    A->nbr_ok[ka]       = 0;
    A->nbr_fail[ka]     = 0;
    A->nbr_lastprobe[ka] = 0;
    A->nbr_pbackoff[ka]  = 0;

    int kb = B->n_neighbors;
    memcpy(B->neighbors[B->n_neighbors++], a, P2P_NODE_ID_LEN);
    B->nbr_rtt[kb]      = 0;
    B->nbr_rtt_ewma[kb] = 0;
    B->nbr_jitter[kb]   = 0;
    B->nbr_bw[kb]       = 0;
    B->nbr_ok[kb]       = 0;
    B->nbr_fail[kb]     = 0;
    B->nbr_lastprobe[kb] = 0;
    B->nbr_pbackoff[kb]  = 0;
    return P2P_OK;
}

int p2p_neighbor_unlink(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b) {
    if (!m || !a || !b) return P2P_ERR_ARGS;
    int ia = node_idx(m, a), ib = node_idx(m, b);
    if (ia < 0 || ib < 0) return P2P_ERR_NOTFOUND;

    p2p_node_t *A = &m->nodes[ia], *B = &m->nodes[ib];
    int found = 0;
    for (int i = 0; i < A->n_neighbors; i++) {
        if (memcmp(A->neighbors[i], b, P2P_NODE_ID_LEN) == 0) {
            int last = A->n_neighbors - 1;
            memcpy(A->neighbors[i], A->neighbors[last], P2P_NODE_ID_LEN);
            A->nbr_rtt[i]      = A->nbr_rtt[last];
            A->nbr_rtt_ewma[i] = A->nbr_rtt_ewma[last];
            A->nbr_jitter[i]   = A->nbr_jitter[last];
            A->nbr_bw[i]       = A->nbr_bw[last];
            A->nbr_ok[i]       = A->nbr_ok[last];
            A->nbr_fail[i]     = A->nbr_fail[last];
            A->nbr_lastprobe[i] = A->nbr_lastprobe[last];
            A->nbr_pbackoff[i]  = A->nbr_pbackoff[last];
            A->n_neighbors--; found = 1; break;
        }
    }
    for (int i = 0; i < B->n_neighbors; i++) {
        if (memcmp(B->neighbors[i], a, P2P_NODE_ID_LEN) == 0) {
            int last = B->n_neighbors - 1;
            memcpy(B->neighbors[i], B->neighbors[last], P2P_NODE_ID_LEN);
            B->nbr_rtt[i]      = B->nbr_rtt[last];
            B->nbr_rtt_ewma[i] = B->nbr_rtt_ewma[last];
            B->nbr_jitter[i]   = B->nbr_jitter[last];
            B->nbr_bw[i]       = B->nbr_bw[last];
            B->nbr_ok[i]       = B->nbr_ok[last];
            B->nbr_fail[i]     = B->nbr_fail[last];
            B->nbr_lastprobe[i] = B->nbr_lastprobe[last];
            B->nbr_pbackoff[i]  = B->nbr_pbackoff[last];
            B->n_neighbors--; break;
        }
    }
    return found ? P2P_OK : P2P_ERR_NOLINK;
}

int p2p_neighbor_has(const p2p_mesh_t *m, const uint8_t *a, const uint8_t *b) {
    int ia = (!m || !a || !b) ? -1 : node_idx(m, a);
    if (ia < 0) return 0;
    const p2p_node_t *A = &m->nodes[ia];
    for (int i = 0; i < A->n_neighbors; i++)
        if (memcmp(A->neighbors[i], b, P2P_NODE_ID_LEN) == 0) return 1;
    return 0;
}

/* ====================================================================
 * 链路质量度量
 * ==================================================================== */

/*
 * 边代价：每跳基础开销 + RTT(ms) + 失败惩罚。
 *   - 基础 100：保证"跳数"仍是主项，代价相同时 QoS 退化成最少跳
 *   - RTT 直接按毫秒计入：10ms 与 500ms 能拉开差距
 *   - 失败一次计 500（约 5 跳）：高丢包链路被强惩罚，优先规避
 * 未测量（rtt=0, fail=0）时退化为纯跳数代价。
 */
static uint32_t qos_cost_local(uint32_t rtt_ewma_x16, uint32_t jitter_x16,
                               uint32_t bw_kbps, uint32_t fail_count);

static uint64_t edge_cost(const p2p_node_t *n, int k) {
    /* 代价模型：跳基础 + EWMA RTT + 抖动 + 失败惩罚 + 带宽项 */
    return (uint64_t)qos_cost_local(n->nbr_rtt_ewma[k], n->nbr_jitter[k],
                                    n->nbr_bw[k], n->nbr_fail[k]);
}


int p2p_link_set_rtt(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b, uint32_t rtt_ms) {
    if (!m || !a || !b) return P2P_ERR_ARGS;
    int ia = node_idx(m, a), ib = node_idx(m, b);
    if (ia < 0 || ib < 0) return P2P_ERR_NOTFOUND;
    int ka = nbr_index(m, ia, b);
    int kb = nbr_index(m, ib, a);
    if (ka < 0 || kb < 0) return P2P_ERR_NOLINK;
    m->nodes[ia].nbr_rtt[ka] = rtt_ms;
    m->nodes[ib].nbr_rtt[kb] = rtt_ms;   /* 无向边：双向一致 */
    /* 硬置 EWMA 与抖动，使"设 500ms 就按 500ms 计费"的语义成立 */
    m->nodes[ia].nbr_rtt_ewma[ka] = rtt_ms << 4;
    m->nodes[ib].nbr_rtt_ewma[kb] = rtt_ms << 4;
    m->nodes[ia].nbr_jitter[ka] = 0;
    m->nodes[ib].nbr_jitter[kb] = 0;
    return P2P_OK;
}

int p2p_link_note(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b, int ok) {
    if (!m || !a || !b) return P2P_ERR_ARGS;
    int ia = node_idx(m, a), ib = node_idx(m, b);
    if (ia < 0 || ib < 0) return P2P_ERR_NOTFOUND;
    int ka = nbr_index(m, ia, b);
    int kb = nbr_index(m, ib, a);
    if (ka < 0 || kb < 0) return P2P_ERR_NOLINK;
    if (ok) { m->nodes[ia].nbr_ok[ka]++;   m->nodes[ib].nbr_ok[kb]++; }
    else    { m->nodes[ia].nbr_fail[ka]++; m->nodes[ib].nbr_fail[kb]++; }
    return P2P_OK;
}

int p2p_link_metrics(const p2p_mesh_t *m, const uint8_t *a, const uint8_t *b,
                     uint32_t *rtt_ms, uint32_t *ok, uint32_t *fail) {
    if (!m || !a || !b) return P2P_ERR_ARGS;
    int ia = node_idx(m, a);
    if (ia < 0) return P2P_ERR_NOTFOUND;
    int ib = node_idx(m, b);
    if (ib < 0) return P2P_ERR_NOTFOUND;   /* 对端节点根本不存在 */
    int ka = nbr_index(m, ia, b);
    if (ka < 0) return P2P_ERR_NOLINK;     /* 节点存在但未连边 */
    const p2p_node_t *A = &m->nodes[ia];
    if (rtt_ms) *rtt_ms = A->nbr_rtt[ka];
    if (ok)     *ok     = A->nbr_ok[ka];
    if (fail)   *fail   = A->nbr_fail[ka];
    return P2P_OK;
}

/* ====================================================================
 * 路由：Dijkstra 按链路质量选路
 * ==================================================================== */

/*
 * 节点数 <= 64，用 O(n^2) 选最小 dist 即可，不必上堆。
 * 故障节点不参与中转（可作起点/终点，但自身必须 alive）。
 */
int p2p_route_path_qos(const p2p_mesh_t *m, const uint8_t *from, const uint8_t *dst,
                       uint8_t path[][P2P_NODE_ID_LEN], int max_hops, int *n_hop) {
    if (!m || !from || !dst || !path || !n_hop || max_hops <= 0)
        return P2P_ERR_ARGS;
    *n_hop = 0;

    int s = node_idx(m, from), t = node_idx(m, dst);
    if (s < 0 || t < 0) return P2P_ERR_NOTFOUND;
    if (s == t) return P2P_OK;                       /* 自身即终点，0 跳 */
    if (!m->nodes[s].alive || !m->nodes[t].alive) return P2P_ERR_UNREACH;

    uint64_t dist[P2P_MAX_NODES];
    int prev[P2P_MAX_NODES], done[P2P_MAX_NODES];
    for (int i = 0; i < P2P_MAX_NODES; i++) {
        dist[i] = UINT64_MAX;
        prev[i] = -1;
        done[i] = 0;
    }
    dist[s] = 0;

    for (int iter = 0; iter < m->n_nodes; iter++) {
        int u = -1;
        uint64_t best = UINT64_MAX;
        for (int i = 0; i < m->n_nodes; i++) {
            if (!done[i] && dist[i] < best) { best = dist[i]; u = i; }
        }
        if (u < 0) break;          /* 剩余不可达 */
        if (u == t) break;         /* 已确定最短路 */
        done[u] = 1;

        const p2p_node_t *nu = &m->nodes[u];
        for (int k = 0; k < nu->n_neighbors; k++) {
            int v = node_idx(m, nu->neighbors[k]);
            if (v < 0 || done[v]) continue;
            if (!m->nodes[v].alive) continue;        /* 故障节点不中转 */
            uint64_t nd = dist[u] + edge_cost(nu, k);
            if (nd < dist[v]) { dist[v] = nd; prev[v] = u; }
        }
    }
    if (dist[t] == UINT64_MAX) return P2P_ERR_NOROUTE;

    /* 回溯 t -> ... -> s，逆序收集（不含起点 s） */
    uint8_t rev[P2P_MAX_HOPS][P2P_NODE_ID_LEN];
    int rn = 0;
    for (int cur = t; cur != s && cur >= 0; cur = prev[cur]) {
        if (rn >= P2P_MAX_HOPS || rn >= max_hops) return P2P_ERR_NOROUTE;
        memcpy(rev[rn++], m->nodes[cur].id, P2P_NODE_ID_LEN);
    }
    if (rn == 0) return P2P_ERR_NOROUTE;

    for (int i = 0; i < rn; i++)
        memcpy(path[i], rev[rn - 1 - i], P2P_NODE_ID_LEN);
    *n_hop = rn;
    return P2P_OK;
}

/* BFS 最短路径。故障节点不参与中转，但起点/终点自身必须是 alive。 */
int p2p_route_path(const p2p_mesh_t *m, const uint8_t *from, const uint8_t *dst,
                   uint8_t path[][P2P_NODE_ID_LEN], int max_hops, int *n_hop) {
    if (!m || !from || !dst || !path || !n_hop || max_hops <= 0)
        return P2P_ERR_ARGS;
    *n_hop = 0;

    int s = node_idx(m, from), t = node_idx(m, dst);
    if (s < 0 || t < 0) return P2P_ERR_NOTFOUND;
    if (s == t) return P2P_OK;                       /* 自身即终点，0 跳 */
    if (!m->nodes[s].alive || !m->nodes[t].alive) return P2P_ERR_UNREACH;

    int parent[P2P_MAX_NODES], visited[P2P_MAX_NODES], queue[P2P_MAX_NODES];
    for (int i = 0; i < P2P_MAX_NODES; i++) { parent[i] = -1; visited[i] = 0; queue[i] = -1; }

    int qh = 0, qt = 0, hit = 0;
    queue[qt++] = s;
    visited[s] = 1;

    while (qh < qt && !hit) {
        int u = queue[qh++];
        const p2p_node_t *nu = &m->nodes[u];
        for (int k = 0; k < nu->n_neighbors; k++) {
            int v = node_idx(m, nu->neighbors[k]);
            if (v < 0 || visited[v]) continue;
            if (!m->nodes[v].alive) continue;        /* 故障节点不中转 */
            visited[v] = 1;
            parent[v]  = u;
            if (v == t) { hit = 1; break; }
            queue[qt++] = v;
        }
    }
    if (!hit) return P2P_ERR_NOROUTE;

    /* 回溯 t -> ... -> s，逆序收集（不含起点 s） */
    uint8_t rev[P2P_MAX_HOPS][P2P_NODE_ID_LEN];
    int rn = 0;
    for (int cur = t; cur != s && cur >= 0; cur = parent[cur]) {
        if (rn >= P2P_MAX_HOPS || rn >= max_hops) return P2P_ERR_NOROUTE;
        memcpy(rev[rn++], m->nodes[cur].id, P2P_NODE_ID_LEN);
    }
    if (rn == 0) return P2P_ERR_NOROUTE;

    for (int i = 0; i < rn; i++)
        memcpy(path[i], rev[rn - 1 - i], P2P_NODE_ID_LEN);
    *n_hop = rn;
    return P2P_OK;
}


/* ====================================================================
 * QoS 代价模型 + EWMA / 抖动 / 带宽 / 主动探测
 * ==================================================================== */

static uint32_t qos_cost_local(uint32_t rtt_ewma_x16, uint32_t jitter_x16,
                               uint32_t bw_kbps, uint32_t fail_count) {
    uint64_t c = P2P_QOS_HOP_BASE;
    c += (uint64_t)rtt_ewma_x16 >> 4;                        /* EWMA RTT (ms) */
    c += ((uint64_t)jitter_x16 >> 4) * P2P_QOS_JITTER_W;     /* 抖动 */
    c += (uint64_t)fail_count * P2P_QOS_FAIL_PENALTY;        /* 丢包惩罚 */
    if (bw_kbps > 0) c += ((uint64_t)P2P_QOS_BW_REF_BYTES * 8ull) / bw_kbps;
    else             c += P2P_QOS_BW_UNKNOWN;
    if (c > 0xffffffffu) c = 0xffffffffu;
    return (uint32_t)c;
}

uint32_t p2p_qos_cost(uint32_t rtt_ewma_x16, uint32_t jitter_x16,
                      uint32_t bw_kbps, uint32_t fail_count) {
    return qos_cost_local(rtt_ewma_x16, jitter_x16, bw_kbps, fail_count);
}

/* 推进 EWMA 与 RFC3550 抖动估计。首次测量时直接置值，不做平滑。 */
static void advance_metrics(p2p_node_t *n, int k, uint32_t rtt_ms) {
    uint32_t prev = n->nbr_rtt[k];
    n->nbr_rtt[k] = rtt_ms;

    int fresh = (n->nbr_rtt_ewma[k] == 0 && n->nbr_ok[k] == 0 &&
                 n->nbr_fail[k] == 0 && n->nbr_jitter[k] == 0);
    if (fresh) {
        n->nbr_rtt_ewma[k] = rtt_ms << 4;
        n->nbr_jitter[k]   = 0;
        return;
    }
    /* EWMA alpha=1/8，定点 x16： e = e - (e>>3) + (rtt<<4>>3) */
    uint64_t e = n->nbr_rtt_ewma[k];
    e = e - (e >> P2P_QOS_EWMA_SHIFT)
        + (((uint64_t)rtt_ms << 4) >> P2P_QOS_EWMA_SHIFT);
    n->nbr_rtt_ewma[k] = (e > 0xffffffffu) ? 0xffffffffu : (uint32_t)e;

    /* RFC 3550: J += (|D| - J) / 16，D 为相邻两次 RTT 之差（定点 x16） */
    uint32_t d = (rtt_ms > prev) ? (rtt_ms - prev) : (prev - rtt_ms);
    uint64_t j = n->nbr_jitter[k];
    j = j - (j >> 4) + (uint64_t)d;
    n->nbr_jitter[k] = (j > 0xffffffffu) ? 0xffffffffu : (uint32_t)j;
}

/* 定位边 (a,b) 在两侧的下标 */
static int find_edge(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b,
                     int *ia, int *ka, int *ib, int *kb) {
    int x = p2p_node_find(m, a), y = p2p_node_find(m, b);
    if (x < 0 || y < 0) return P2P_ERR_NOTFOUND;
    *ia = x; *ib = y;
    *ka = -1; *kb = -1;
    for (int i = 0; i < m->nodes[x].n_neighbors; i++)
        if (memcmp(m->nodes[x].neighbors[i], b, P2P_NODE_ID_LEN) == 0) { *ka = i; break; }
    for (int i = 0; i < m->nodes[y].n_neighbors; i++)
        if (memcmp(m->nodes[y].neighbors[i], a, P2P_NODE_ID_LEN) == 0) { *kb = i; break; }
    if (*ka < 0 || *kb < 0) return P2P_ERR_NOLINK;
    return P2P_OK;
}

int p2p_link_update_rtt(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b,
                        uint32_t rtt_ms) {
    if (!m || !a || !b) return P2P_ERR_ARGS;
    int ia, ka, ib, kb;
    int rc = find_edge(m, a, b, &ia, &ka, &ib, &kb);
    if (rc != P2P_OK) return rc;
    advance_metrics(&m->nodes[ia], ka, rtt_ms);
    advance_metrics(&m->nodes[ib], kb, rtt_ms);   /* 无向边：双向一致 */
    m->nodes[ia].nbr_ok[ka]++;
    m->nodes[ib].nbr_ok[kb]++;
    return P2P_OK;
}

int p2p_link_set_bw(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b,
                    uint32_t bw_kbps) {
    if (!m || !a || !b) return P2P_ERR_ARGS;
    int ia, ka, ib, kb;
    int rc = find_edge(m, a, b, &ia, &ka, &ib, &kb);
    if (rc != P2P_OK) return rc;
    m->nodes[ia].nbr_bw[ka] = bw_kbps;
    m->nodes[ib].nbr_bw[kb] = bw_kbps;
    return P2P_OK;
}

int p2p_link_get_qos(const p2p_mesh_t *m, const uint8_t *a, const uint8_t *b,
                     uint32_t *rtt_ewma, uint32_t *jitter,
                     uint32_t *bw_kbps, uint32_t *ok, uint32_t *fail) {
    if (!m || !a || !b) return P2P_ERR_ARGS;
    int x = p2p_node_find(m, a);
    if (x < 0) return P2P_ERR_NOTFOUND;
    int k = -1;
    for (int i = 0; i < m->nodes[x].n_neighbors; i++)
        if (memcmp(m->nodes[x].neighbors[i], b, P2P_NODE_ID_LEN) == 0) { k = i; break; }
    if (k < 0) return P2P_ERR_NOLINK;
    const p2p_node_t *n = &m->nodes[x];
    if (rtt_ewma) *rtt_ewma = n->nbr_rtt_ewma[k];
    if (jitter)   *jitter   = n->nbr_jitter[k];
    if (bw_kbps)  *bw_kbps  = n->nbr_bw[k];
    if (ok)       *ok       = n->nbr_ok[k];
    if (fail)     *fail     = n->nbr_fail[k];
    return P2P_OK;
}

static uint32_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint32_t)((uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull);
}

/* 真实 TCP connect 计时探测 */
static int tcp_probe(const char *host, uint16_t port, uint32_t *rtt_ms) {
    if (!host || !port) return -1;
    struct addrinfo hints, *res = NULL;
    char portstr[8];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%u", (unsigned)port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;

    uint32_t t0 = now_ms();
    int fd = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;
    close(fd);
    uint32_t t1 = now_ms();
    if (rtt_ms) *rtt_ms = (t1 >= t0) ? (t1 - t0) : 1;
    return 0;
}

/* 带宽探测：连上 -> 写满 bytes -> 半关闭 -> 等对端回执 -> 计时 */
static int bw_probe(const char *host, uint16_t port, size_t bytes,
                    uint32_t *bw_kbps, int *acked) {
    if (!host || !port || bytes == 0) return -1;

    struct addrinfo hints, *res = NULL;
    char portstr[8];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%u", (unsigned)port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;

    int fd = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;

    /* 收回执最多等 5 秒 */
    struct timeval tv;
    tv.tv_sec = 5; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    uint8_t chunk[4096];
    memset(chunk, 0xa5, sizeof chunk);

    uint32_t t0 = now_ms();
    size_t sent = 0;
    while (sent < bytes) {
        size_t n = bytes - sent;
        if (n > sizeof chunk) n = sizeof chunk;
        ssize_t w = send(fd, chunk, n, MSG_NOSIGNAL);
        if (w <= 0) break;
        sent += (size_t)w;
    }
    if (sent == 0) { close(fd); return -1; }

    shutdown(fd, SHUT_WR);
    uint8_t ack = 0;
    ssize_t r = recv(fd, &ack, 1, 0);
    uint32_t t1 = now_ms();
    close(fd);

    uint32_t elapsed = (t1 > t0) ? (t1 - t0) : 1;
    if (elapsed == 0) elapsed = 1;
    /* kbit/s = bytes * 8 / ms */
    uint64_t kbps = ((uint64_t)sent * 8ull) / (uint64_t)elapsed;
    if (kbps > 0xffffffffull) kbps = 0xffffffffull;
    if (bw_kbps) *bw_kbps = (uint32_t)kbps;
    if (acked)   *acked   = (r == 1) ? 1 : 0;
    return 0;
}

int p2p_probe_bandwidth(const char *host, uint16_t port, size_t bytes,
                        uint32_t *bw_kbps, int *acked) {
    if (!host || !port || bytes == 0) return P2P_ERR_ARGS;
    if (bw_probe(host, port, bytes, bw_kbps, acked) != 0) return P2P_ERR_UNREACH;
    return P2P_OK;
}

int p2p_link_probe_bw(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b,
                      size_t bytes, uint32_t *bw_kbps) {
    if (!m || !a || !b || bytes == 0) return P2P_ERR_ARGS;
    int y = p2p_node_find(m, b);
    if (y < 0) return P2P_ERR_NOTFOUND;
    if (p2p_node_find(m, a) < 0) return P2P_ERR_NOTFOUND;
    if (!p2p_neighbor_has(m, a, b)) return P2P_ERR_NOLINK;

    uint32_t bw = 0;
    int acked = 0;
    if (bw_probe(m->nodes[y].host, m->nodes[y].port, bytes, &bw, &acked) != 0) {
        p2p_link_note(m, a, b, 0);
        return P2P_ERR_UNREACH;
    }
    if (bw == 0) bw = 1;
    int rc = p2p_link_set_bw(m, a, b, bw);
    if (rc != P2P_OK) return rc;
    if (bw_kbps) *bw_kbps = bw;
    return P2P_OK;
}

int p2p_link_probe(p2p_mesh_t *m, const uint8_t *a, const uint8_t *b,
                   uint32_t *rtt_ms) {
    if (!m || !a || !b) return P2P_ERR_ARGS;
    int y = p2p_node_find(m, b);
    if (y < 0) return P2P_ERR_NOTFOUND;
    int x = p2p_node_find(m, a);
    if (x < 0) return P2P_ERR_NOTFOUND;
    if (!p2p_neighbor_has(m, a, b)) return P2P_ERR_NOLINK;

    uint32_t rtt = 0;
    if (tcp_probe(m->nodes[y].host, m->nodes[y].port, &rtt) != 0) {
        /* 探测失败：累加失败计数（丢包惩罚生效） */
        p2p_link_note(m, a, b, 0);
        return P2P_ERR_UNREACH;
    }
    /* 回环 TCP 握手常 <1ms，取 1 避免 0 值被当作"未测量" */
    if (rtt == 0) rtt = 1;
    int rc = p2p_link_update_rtt(m, a, b, rtt);
    if (rc != P2P_OK) return rc;
    if (rtt_ms) *rtt_ms = rtt;
    return P2P_OK;
}

int p2p_link_probe_all(p2p_mesh_t *m, const uint8_t *a, int *n_probed) {
    if (!m || !a) return P2P_ERR_ARGS;
    int x = p2p_node_find(m, a);
    if (x < 0) return P2P_ERR_NOTFOUND;
    int ok = 0;
    int nn = m->nodes[x].n_neighbors;
    uint8_t snapshot[P2P_MAX_NEIGHBORS][P2P_NODE_ID_LEN];
    for (int i = 0; i < nn; i++)
        memcpy(snapshot[i], m->nodes[x].neighbors[i], P2P_NODE_ID_LEN);
    for (int i = 0; i < nn; i++) {
        if (p2p_link_probe(m, a, snapshot[i], NULL) == P2P_OK) ok++;
    }
    if (n_probed) *n_probed = ok;
    return P2P_OK;
}

/* ====================================================================
 * 探测调度：低频 + 抖动 + 错峰 + 失败退避
 * ====================================================================
 * 主动探测本身要发包，若周期性全图扫描，这些包就是可识别指纹。
 * 调度器把探测从"每轮全扫"改成"到期才探、随机顺序、失败退避"。
 */

/* 取 a->b 在 a 的邻居表中的下标 */
static int edge_idx_a(const p2p_mesh_t *m, const uint8_t *a, const uint8_t *b,
                      int *ia, int *ka) {
    int x = p2p_node_find(m, a);
    if (x < 0) return P2P_ERR_NOTFOUND;
    for (int i = 0; i < m->nodes[x].n_neighbors; i++) {
        if (memcmp(m->nodes[x].neighbors[i], b, P2P_NODE_ID_LEN) == 0) {
            if (ia) *ia = x;
            if (ka) *ka = i;
            return P2P_OK;
        }
    }
    return P2P_ERR_NOLINK;
}

int p2p_probesched_init(p2p_probesched_t *ps, uint32_t seed,
                        uint32_t base_ms, uint32_t jitter_ms,
                        uint32_t max_backoff_ms) {
    if (!ps) return P2P_ERR_ARGS;
    memset(ps, 0, sizeof *ps);
    ps->s = seed ? seed : 0x9e3779b9u;
    ps->base_ms        = base_ms;
    ps->jitter_ms      = jitter_ms;
    ps->max_backoff_ms = max_backoff_ms;
    return P2P_OK;
}

static uint32_t ps_rand(p2p_probesched_t *ps) {
    uint32_t x = ps->s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    ps->s = x;
    return x;
}

int p2p_probe_due(p2p_probesched_t *ps, const p2p_mesh_t *m,
                  const uint8_t *a, const uint8_t *b, uint32_t now_ms) {
    if (!ps || !m || !a || !b) return P2P_ERR_ARGS;
    int x = 0, k = 0;
    int rc = edge_idx_a(m, a, b, &x, &k);
    if (rc != P2P_OK) return rc;

    uint32_t last = m->nodes[x].nbr_lastprobe[k];
    if (last == 0) return 1;                 /* 从未探测过 */
    if (now_ms < last) return 1;              /* 时钟异常回绕：宁可多探不可卡死 */

    uint32_t jitter = 0;
    if (ps->jitter_ms) jitter = ps_rand(ps) % ps->jitter_ms;
    uint32_t need = ps->base_ms + m->nodes[x].nbr_pbackoff[k] + jitter;
    return ((now_ms - last) >= need) ? 1 : 0;
}

int p2p_probe_mark(p2p_probesched_t *ps, p2p_mesh_t *m,
                   const uint8_t *a, const uint8_t *b,
                   uint32_t now_ms, int ok) {
    if (!ps || !m || !a || !b) return P2P_ERR_ARGS;
    int x = 0, k = 0, y = 0, k2 = 0;
    int rc = edge_idx_a(m, a, b, &x, &k);
    if (rc != P2P_OK) return rc;
    rc = edge_idx_a(m, b, a, &y, &k2);
    if (rc != P2P_OK) return rc;

    m->nodes[x].nbr_lastprobe[k]   = now_ms;
    m->nodes[y].nbr_lastprobe[k2]  = now_ms;   /* 无向边：双向一致 */

    uint32_t nb;
    if (ok) {
        nb = 0;
    } else {
        uint32_t cur = m->nodes[x].nbr_pbackoff[k];
        nb = (cur == 0) ? ps->base_ms : cur * 2;
        if (nb < cur) nb = cur;                 /* 溢出保护：停在 uint32 上限 */
        if (ps->max_backoff_ms && nb > ps->max_backoff_ms)
            nb = ps->max_backoff_ms;
    }
    m->nodes[x].nbr_pbackoff[k]  = nb;
    m->nodes[y].nbr_pbackoff[k2] = nb;
    return P2P_OK;
}

int p2p_probe_all_staggered(p2p_probesched_t *ps, p2p_mesh_t *m,
                            const uint8_t *a, uint32_t now_ms,
                            int *n_probed, int *n_skipped) {
    if (!ps || !m || !a) return P2P_ERR_ARGS;
    int x = p2p_node_find(m, a);
    if (x < 0) return P2P_ERR_NOTFOUND;

    int nn = m->nodes[x].n_neighbors;
    uint8_t snap[P2P_MAX_NEIGHBORS][P2P_NODE_ID_LEN];
    for (int i = 0; i < nn; i++)
        memcpy(snap[i], m->nodes[x].neighbors[i], P2P_NODE_ID_LEN);

    /*
     * 错峰：Fisher-Yates 打乱遍历顺序。
     * 不打乱的话每轮都是同一固定序列，探测时刻虽抖动但**顺序固定**，
     * 观察者仍可对邻居身份做关联。打乱后顺序本身不可预测。
     */
    for (int i = nn - 1; i > 0; i--) {
        int j = (int)(ps_rand(ps) % (uint32_t)(i + 1));
        if (i != j) {
            uint8_t t[P2P_NODE_ID_LEN];
            memcpy(t, snap[i], P2P_NODE_ID_LEN);
            memcpy(snap[i], snap[j], P2P_NODE_ID_LEN);
            memcpy(snap[j], t, P2P_NODE_ID_LEN);
        }
    }

    int probed = 0, skipped = 0;
    for (int i = 0; i < nn; i++) {
        if (p2p_probe_due(ps, m, a, snap[i], now_ms) != 1) { skipped++; continue; }
        uint32_t rtt = 0;
        int rc = p2p_link_probe(m, a, snap[i], &rtt);
        p2p_probe_mark(ps, m, a, snap[i], now_ms, rc == P2P_OK);
        if (rc == P2P_OK) probed++;
    }
    if (n_probed)  *n_probed  = probed;
    if (n_skipped) *n_skipped = skipped;
    return P2P_OK;
}
