#include "p2p.h"
#include <string.h>

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
                o->nbr_rtt[j]  = o->nbr_rtt[last];
                o->nbr_ok[j]   = o->nbr_ok[last];
                o->nbr_fail[j] = o->nbr_fail[last];
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
    A->nbr_rtt[ka]  = 0;
    A->nbr_ok[ka]   = 0;
    A->nbr_fail[ka] = 0;

    int kb = B->n_neighbors;
    memcpy(B->neighbors[B->n_neighbors++], a, P2P_NODE_ID_LEN);
    B->nbr_rtt[kb]  = 0;
    B->nbr_ok[kb]   = 0;
    B->nbr_fail[kb] = 0;
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
            A->nbr_rtt[i]  = A->nbr_rtt[last];
            A->nbr_ok[i]   = A->nbr_ok[last];
            A->nbr_fail[i] = A->nbr_fail[last];
            A->n_neighbors--; found = 1; break;
        }
    }
    for (int i = 0; i < B->n_neighbors; i++) {
        if (memcmp(B->neighbors[i], a, P2P_NODE_ID_LEN) == 0) {
            int last = B->n_neighbors - 1;
            memcpy(B->neighbors[i], B->neighbors[last], P2P_NODE_ID_LEN);
            B->nbr_rtt[i]  = B->nbr_rtt[last];
            B->nbr_ok[i]   = B->nbr_ok[last];
            B->nbr_fail[i] = B->nbr_fail[last];
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
static uint64_t edge_cost(const p2p_node_t *n, int k) {
    uint64_t c = 100u;                          /* 每跳基础 */
    c += (uint64_t)n->nbr_rtt[k];               /* RTT 毫秒 */
    c += (uint64_t)n->nbr_fail[k] * 500u;       /* 失败惩罚 */
    return c;
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
