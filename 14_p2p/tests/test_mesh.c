#include "p2p.h"
#include <stdio.h>
#include <string.h>

static int pass = 0, fail = 0;
#define CK(c, m) do { if (c) { pass++; printf("[PASS] %s\n", m); } \
                      else { fail++; printf("[FAIL] %s\n", m); } } while (0)

/* 节点 ID 必须统一填充方式：先清零再拷字符串，
 * 否则尾部随机字节会让 memcmp 匹配失败，产生"明明加了却 find 不到"的假失败。 */
static void mkid(uint8_t *out, const char *s) {
    memset(out, 0, P2P_NODE_ID_LEN);
    size_t n = strlen(s);
    if (n > P2P_NODE_ID_LEN) n = P2P_NODE_ID_LEN;
    memcpy(out, s, n);
}

int main(void) {
    printf("=== 14_p2p mesh 测试 ===\n");
    p2p_mesh_t m;
    uint8_t A[P2P_NODE_ID_LEN], B[P2P_NODE_ID_LEN], C[P2P_NODE_ID_LEN], D[P2P_NODE_ID_LEN];
    mkid(A, "edge0"); mkid(B, "edge1"); mkid(C, "core0"); mkid(D, "impl0");

    CK(p2p_mesh_init(&m) == P2P_OK, "mesh init 成功");
    CK(m.n_nodes == 0, "初始无节点");
    CK(p2p_mesh_init(NULL) == P2P_ERR_ARGS, "NULL mesh 返回 ARGS");

    /* --- CRUD --- */
    CK(p2p_node_add(&m, A, P2P_ROLE_EDGE, "edge0", "10.0.0.1", 443) == P2P_OK, "add edge0 成功");
    CK(p2p_node_add(&m, B, P2P_ROLE_EDGE, "edge1", "10.0.0.2", 443) == P2P_OK, "add edge1 成功");
    CK(p2p_node_add(&m, C, P2P_ROLE_CORE, "core0", "10.0.0.9", 9443) == P2P_OK, "add core0 成功");
    CK(p2p_node_add(&m, D, P2P_ROLE_ENDPOINT, "impl0", "0.0.0.0", 0) == P2P_OK, "add impl0 成功");
    CK(m.n_nodes == 4, "共 4 个节点");

    CK(p2p_node_add(&m, A, P2P_ROLE_EDGE, "dup", "1.1.1.1", 1) == P2P_ERR_EXISTS, "重复 add 返回 EXISTS");
    CK(p2p_node_add(&m, A, (p2p_role_t)99, "bad", "1.1.1.1", 1) == P2P_ERR_ARGS, "非法 role 返回 ARGS");
    CK(p2p_node_add(&m, NULL, P2P_ROLE_EDGE, "x", "1.1.1.1", 1) == P2P_ERR_ARGS, "NULL id 返回 ARGS");

    CK(p2p_node_find(&m, B) == 1, "find edge1 命中下标 1");
    uint8_t Z[P2P_NODE_ID_LEN]; mkid(Z, "nope");
    CK(p2p_node_find(&m, Z) == P2P_ERR_NOTFOUND, "find 未命中返回 NOTFOUND");
    CK(p2p_node_count(&m, P2P_ROLE_EDGE) == 2, "EDGE 角色计数 2");
    CK(p2p_node_count(&m, P2P_ROLE_CORE) == 1, "CORE 角色计数 1");
    CK(p2p_node_count(&m, P2P_ROLE_ENDPOINT) == 1, "ENDPOINT 角色计数 1");

    /* --- 邻居（无向双向） --- */
    CK(p2p_neighbor_link(&m, A, B) == P2P_OK, "link edge0-edge1 成功");
    CK(p2p_neighbor_has(&m, A, B) == 1, "A->B 有向可见");
    CK(p2p_neighbor_has(&m, B, A) == 1, "B->A 有向可见（无向双向写入）");
    CK(p2p_neighbor_link(&m, A, B) == P2P_ERR_EXISTS, "重复 link 返回 EXISTS");
    CK(p2p_neighbor_link(&m, A, A) == P2P_ERR_ARGS, "自环 link 返回 ARGS");
    CK(p2p_neighbor_link(&m, A, (const uint8_t *)"zz") == P2P_ERR_NOTFOUND, "link 未知节点返回 NOTFOUND");

    p2p_neighbor_link(&m, B, C);
    p2p_neighbor_link(&m, A, C);            /* A-C 直连，构成另一条更短路径 */

    /* --- 路由 BFS --- */
    uint8_t path[P2P_MAX_HOPS][P2P_NODE_ID_LEN];
    int nh = -1;
    CK(p2p_route_path(&m, A, C, path, P2P_MAX_HOPS, &nh) == P2P_OK, "A->C 有路径");
    CK(nh == 1, "A->C 直连为 1 跳");
    CK(memcmp(path[0], C, P2P_NODE_ID_LEN) == 0, "首跳为 core0");

    nh = -1;
    CK(p2p_route_path(&m, D, C, path, P2P_MAX_HOPS, &nh) == P2P_ERR_NOROUTE, "孤立 impl0 到 core0 无路径");
    CK(nh == 0, "无路径时 n_hop 置 0");

    p2p_neighbor_link(&m, D, A);
    nh = -1;
    CK(p2p_route_path(&m, D, C, path, P2P_MAX_HOPS, &nh) == P2P_OK, "接入后 impl0->core0 有路径");
    CK(nh == 2, "impl0->edge0->core0 为 2 跳");
    CK(memcmp(path[0], A, P2P_NODE_ID_LEN) == 0 && memcmp(path[1], C, P2P_NODE_ID_LEN) == 0,
       "两跳顺序为 edge0 再 core0");

    nh = -1;
    CK(p2p_route_path(&m, A, A, path, P2P_MAX_HOPS, &nh) == P2P_OK, "起点即终点返回 OK");
    CK(nh == 0, "起点即终点为 0 跳");

    /* --- 故障检测与绕行 --- */
    CK(p2p_node_mark_dead(&m, C) == P2P_OK, "标记 core0 故障");
    nh = -1;
    CK(p2p_route_path(&m, D, C, path, P2P_MAX_HOPS, &nh) == P2P_ERR_UNREACH, "终点故障返回 UNREACH");
    CK(p2p_node_mark_alive(&m, C) == P2P_OK, "恢复 core0");

    /* 构造菱形：A-B-C 与 A-C；断开 A-C 后应绕行 B */
    p2p_neighbor_unlink(&m, A, C);
    nh = -1;
    CK(p2p_route_path(&m, A, C, path, P2P_MAX_HOPS, &nh) == P2P_OK, "断开直连后仍可达");
    CK(nh == 2, "绕行 edge1 变 2 跳");
    CK(memcmp(path[0], B, P2P_NODE_ID_LEN) == 0, "首跳改走 edge1");

    CK(p2p_node_mark_dead(&m, B) == P2P_OK, "标记 edge1 故障");
    nh = -1;
    CK(p2p_route_path(&m, A, C, path, P2P_MAX_HOPS, &nh) == P2P_ERR_NOROUTE, "唯一中间节点故障则无路径");
    CK(p2p_node_mark_alive(&m, B) == P2P_OK, "恢复 edge1");

    /* --- 删除与悬空清理 --- */
    CK(p2p_node_del(&m, B) == P2P_OK, "删除 edge1 成功");
    CK(m.n_nodes == 3, "删除后剩 3 个节点");
    CK(p2p_neighbor_has(&m, A, B) == 0, "删除后 A 的邻居表已清掉 edge1");
    CK(p2p_neighbor_has(&m, C, B) == 0, "删除后 C 的邻居表已清掉 edge1");
    CK(p2p_node_del(&m, B) == P2P_ERR_NOTFOUND, "重复删除返回 NOTFOUND");

    /* --- 边界 --- */
    CK(p2p_route_path(&m, A, C, path, 0, &nh) == P2P_ERR_ARGS, "max_hops=0 返回 ARGS");
    CK(p2p_route_path(NULL, A, C, path, P2P_MAX_HOPS, &nh) == P2P_ERR_ARGS, "NULL mesh 路由返回 ARGS");
    CK(p2p_neighbor_unlink(&m, A, C) == P2P_ERR_NOLINK, "解不存在的链返回 NOLINK");

    /* --- 容量 --- */
    p2p_mesh_t big; p2p_mesh_init(&big);
    uint8_t id[P2P_NODE_ID_LEN]; char nm[16];
    int i = 0;
    for (; i < P2P_MAX_NODES; i++) {
        snprintf(nm, sizeof nm, "n%d", i);
        mkid(id, nm);
        if (p2p_node_add(&big, id, P2P_ROLE_EDGE, nm, "127.0.0.1", 1) != P2P_OK) break;
    }
    CK(i == P2P_MAX_NODES, "填满 64 个节点");
    snprintf(nm, sizeof nm, "n%d", P2P_MAX_NODES);
    mkid(id, nm);
    CK(p2p_node_add(&big, id, P2P_ROLE_EDGE, nm, "127.0.0.1", 1) == P2P_ERR_FULL, "超出容量返回 FULL");

    printf("total=%d pass=%d fail=%d\n", pass + fail, pass, fail);
    return fail ? 1 : 0;
}
