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
                /* 与末位交换后收缩，j 回退以重新检查换上来的元素 */
                memcpy(o->neighbors[j], o->neighbors[o->n_neighbors - 1], P2P_NODE_ID_LEN);
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

    memcpy(A->neighbors[A->n_neighbors++], b, P2P_NODE_ID_LEN);
    memcpy(B->neighbors[B->n_neighbors++], a, P2P_NODE_ID_LEN);
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
            memcpy(A->neighbors[i], A->neighbors[A->n_neighbors - 1], P2P_NODE_ID_LEN);
            A->n_neighbors--; found = 1; break;
        }
    }
    for (int i = 0; i < B->n_neighbors; i++) {
        if (memcmp(B->neighbors[i], a, P2P_NODE_ID_LEN) == 0) {
            memcpy(B->neighbors[i], B->neighbors[B->n_neighbors - 1], P2P_NODE_ID_LEN);
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
