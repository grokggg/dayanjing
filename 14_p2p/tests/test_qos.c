/*
 * DAYANJING v4 — 14_p2p/tests/test_qos.c
 *
 * 链路质量选路（Dijkstra，按 RTT + 失败惩罚）与边度量 API 验证。
 *
 * 覆盖：
 *   1. 同等跳数下，QoS 选低时延路径，而 BFS（对照）不受时延影响
 *   2. 高丢包（失败计数）链路被惩罚，QoS 改走备用路径
 *   3. 度量 API：设置/累加/读回，双向一致，参数校验
 *   4. 故障节点不中转、孤立节点 NOROUTE、max_hops 生效
 *   5. 删除节点后，其他节点邻居表中的度量项一并清除（防悬挂）
 *
 * 全部为内存内计算，不依赖网络。
 */

#include "p2p.h"

#include <stdio.h>
#include <string.h>

static int pass = 0, fail = 0;
#define CK(c, m) do { if (c) { pass++; printf("[PASS] %s\n", m); } \
                      else { fail++; printf("[FAIL] %s\n", m); } } while (0)

static void mkid(uint8_t *id, uint8_t v) { memset(id, v, P2P_NODE_ID_LEN); }

int main(void) {
    printf("=== 14_p2p 链路质量选路测试 ===\n");

    p2p_mesh_t m;
    p2p_mesh_init(&m);

    uint8_t a[16], b[16], c[16], d[16];
    mkid(a, 0x01); mkid(b, 0x02); mkid(c, 0x03); mkid(d, 0x04);

    CK(p2p_node_add(&m, a, P2P_ROLE_ENDPOINT, "A", "127.0.0.1", 1) == P2P_OK, "add A");
    CK(p2p_node_add(&m, b, P2P_ROLE_EDGE,     "B", "127.0.0.1", 2) == P2P_OK, "add B");
    CK(p2p_node_add(&m, c, P2P_ROLE_EDGE,     "C", "127.0.0.1", 3) == P2P_OK, "add C");
    CK(p2p_node_add(&m, d, P2P_ROLE_CORE,     "D", "127.0.0.1", 4) == P2P_OK, "add D");

    /* 拓扑：A-B-D 与 A-C-D，两条都是 2 跳 */
    CK(p2p_neighbor_link(&m, a, b) == P2P_OK, "link A-B");
    CK(p2p_neighbor_link(&m, b, d) == P2P_OK, "link B-D");
    CK(p2p_neighbor_link(&m, a, c) == P2P_OK, "link A-C");
    CK(p2p_neighbor_link(&m, c, d) == P2P_OK, "link C-D");

    uint8_t path[16][P2P_NODE_ID_LEN];
    int nh = 0;

    /* 未测量时两端代价相同，QoS 仍可达且 2 跳 */
    CK(p2p_route_path_qos(&m, a, d, path, 16, &nh) == P2P_OK && nh == 2,
       "QoS 默认可达且 2 跳");

    /* B 路径高时延(500ms)，C 路径低时延(10ms)：QoS 应走 C */
    CK(p2p_link_set_rtt(&m, a, b, 500) == P2P_OK, "set A-B rtt=500");
    CK(p2p_link_set_rtt(&m, b, d, 500) == P2P_OK, "set B-D rtt=500");
    CK(p2p_link_set_rtt(&m, a, c,  10) == P2P_OK, "set A-C rtt=10");
    CK(p2p_link_set_rtt(&m, c, d,  10) == P2P_OK, "set C-D rtt=10");
    nh = 0;
    CK(p2p_route_path_qos(&m, a, d, path, 16, &nh) == P2P_OK && nh == 2,
       "QoS 仍 2 跳");
    CK(memcmp(path[0], c, P2P_NODE_ID_LEN) == 0,
       "QoS 首选低时延下一跳 C（而非高时延 B）");
    CK(memcmp(path[1], d, P2P_NODE_ID_LEN) == 0, "QoS 终跳为 D");

    /* 对照：BFS 按最少跳数，与时延无关，仍走先入队的 B */
    nh = 0;
    CK(p2p_route_path(&m, a, d, path, 16, &nh) == P2P_OK && nh == 2,
       "BFS（对照）最少跳数仍 2 跳");
    CK(memcmp(path[0], b, P2P_NODE_ID_LEN) == 0,
       "BFS（对照）走先入队的 B，不受 RTT 影响");

    /* 失败惩罚：C 链路记 3 次失败 -> QoS 改走 B（即使 B 时延高） */
    for (int i = 0; i < 3; i++) p2p_link_note(&m, a, c, 0);
    nh = 0;
    CK(p2p_route_path_qos(&m, a, d, path, 16, &nh) == P2P_OK,
       "失败惩罚后 QoS 仍可达");
    CK(memcmp(path[0], b, P2P_NODE_ID_LEN) == 0,
       "高丢包链路被规避，QoS 改走 B");

    /* 度量读回 */
    uint32_t rtt = 0, ok = 0, fl = 0;
    CK(p2p_link_metrics(&m, a, c, &rtt, &ok, &fl) == P2P_OK && rtt == 10 && fl == 3,
       "metrics 读回 A-C: rtt=10, fail=3");
    CK(p2p_link_metrics(&m, c, a, &rtt, &ok, &fl) == P2P_OK && rtt == 10 && fl == 3,
       "metrics 双向一致（无向边同步写入）");
    CK(p2p_link_note(&m, a, c, 1) == P2P_OK, "note 成功一次");
    CK(p2p_link_metrics(&m, a, c, &rtt, &ok, &fl) == P2P_OK && ok == 1,
       "metrics ok 计数累加正确");

    /* 参数校验 */
    CK(p2p_link_set_rtt(NULL, a, b, 1) == P2P_ERR_ARGS, "set_rtt NULL mesh -> ARG");
    CK(p2p_link_metrics(NULL, a, b, &rtt, &ok, &fl) == P2P_ERR_ARGS, "metrics NULL mesh -> ARG");
    uint8_t z[16]; mkid(z, 0x77);
    CK(p2p_link_set_rtt(&m, a, z, 1) == P2P_ERR_NOTFOUND, "set_rtt 不存在节点 -> NOTFOUND");
    CK(p2p_link_metrics(&m, a, z, &rtt, &ok, &fl) == P2P_ERR_NOTFOUND, "metrics 不存在节点 -> NOTFOUND");
    CK(p2p_link_note(&m, a, z, 1) == P2P_ERR_NOTFOUND, "note 不存在节点 -> NOTFOUND");
    uint8_t e[16]; mkid(e, 0x88);
    p2p_node_add(&m, e, P2P_ROLE_ENDPOINT, "E", "127.0.0.1", 5);
    CK(p2p_link_set_rtt(&m, a, e, 1) == P2P_ERR_NOLINK, "set_rtt 有节点但未连边 -> NOLINK");
    CK(p2p_link_metrics(&m, a, e, &rtt, &ok, &fl) == P2P_ERR_NOLINK, "metrics 未连边 -> NOLINK");

    /* 故障节点不中转 */
    p2p_node_mark_dead(&m, c);
    nh = 0;
    CK(p2p_route_path_qos(&m, a, d, path, 16, &nh) == P2P_OK &&
       memcmp(path[0], b, P2P_NODE_ID_LEN) == 0, "C 故障后 QoS 走 B");
    p2p_node_mark_alive(&m, c);

    /* 孤立节点不可达 */
    uint8_t iso[16]; mkid(iso, 0x99);
    p2p_node_add(&m, iso, P2P_ROLE_ENDPOINT, "ISO", "127.0.0.1", 9);
    nh = 0;
    CK(p2p_route_path_qos(&m, a, iso, path, 16, &nh) == P2P_ERR_NOROUTE,
       "孤立节点 -> NOROUTE");

    /* max_hops 限制 */
    nh = 0;
    CK(p2p_route_path_qos(&m, a, d, path, 1, &nh) == P2P_ERR_NOROUTE,
       "max_hops=1 装不下 2 跳 -> NOROUTE");
    CK(p2p_route_path_qos(&m, a, d, path, 0, &nh) == P2P_ERR_ARGS,
       "max_hops=0 -> ARG");

    /* 删除节点后清除其他节点上的度量项 */
    CK(p2p_node_del(&m, c) == P2P_OK, "del C");
    CK(p2p_link_metrics(&m, a, c, &rtt, &ok, &fl) == P2P_ERR_NOTFOUND,
       "删除 C 后 C 节点已不存在 -> NOTFOUND（度量项随之清除）");
    CK(p2p_neighbor_has(&m, a, c) == 0, "删除 C 后 A 的邻居表中已无 C");
    nh = 0;
    CK(p2p_route_path_qos(&m, a, d, path, 16, &nh) == P2P_OK &&
       memcmp(path[0], b, P2P_NODE_ID_LEN) == 0, "删除 C 后只能走 B");

    printf("\ntotal=%d pass=%d fail=%d\n", pass + fail, pass, fail);
    return fail ? 1 : 0;
}
