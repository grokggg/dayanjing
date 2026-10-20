/*
 * DAYANJING v4 — 14_p2p/tests/test_probesched.c
 *
 * 探测调度验证：低频（最小间隔）、抖动（非等间距）、错峰（随机顺序）、
 * 失败退避（不可达边不再高频重试）。
 *
 * 涉及真实探测的用例会起本地回环 listener 做真实 TCP connect。
 */

#include "p2p.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int g_pass = 0, g_fail = 0;
static void check(int cond, const char *name) {
    if (cond) { g_pass++; printf("[PASS] %s\n", name); }
    else      { g_fail++; printf("[FAIL] %s\n", name); }
}

static void mkid(uint8_t *id, uint8_t b) {
    memset(id, 0, P2P_NODE_ID_LEN);
    id[0] = b;
}

/* 起一个回环 listener，返回 fd 与端口 */
static int start_listener(uint16_t *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    if (listen(fd, 16) != 0) { close(fd); return -1; }

    struct sockaddr_in got;
    socklen_t gl = sizeof got;
    if (getsockname(fd, (struct sockaddr *)&got, &gl) != 0) { close(fd); return -1; }
    *port = ntohs(got.sin_port);
    return fd;
}

/* 取一个当前未被占用的端口（绑定后立刻关闭） */
static uint16_t free_port(void) {
    uint16_t p = 0;
    int fd = start_listener(&p);
    if (fd >= 0) close(fd);
    return p;
}

int main(void) {
    uint8_t idA[16], idB[16];
    mkid(idA, 0x01);
    mkid(idB, 0x02);

    /* ---- 1. 参数与初始状态 ---- */
    p2p_probesched_t ps;
    check(p2p_probesched_init(&ps, 1, 1000, 0, 8000) == P2P_OK, "init");
    check(p2p_probesched_init(NULL, 1, 1000, 0, 8000) == P2P_ERR_ARGS, "NULL 被拒");

    p2p_mesh_t m;
    p2p_mesh_init(&m);
    uint16_t lp = 0;
    int lfd = start_listener(&lp);
    check(lfd >= 0 && lp != 0, "起回环 listener");

    p2p_node_add(&m, idA, P2P_ROLE_EDGE, "A", "127.0.0.1", lp);
    p2p_node_add(&m, idB, P2P_ROLE_EDGE, "B", "127.0.0.1", lp);
    check(p2p_neighbor_link(&m, idA, idB) == P2P_OK, "建边 A-B");
    check(p2p_probe_due(&ps, &m, idA, idB, 1000) == 1, "从未探测 -> 到期");

    /* ---- 2. 低频：最小间隔内不到期 ---- */
    p2p_probe_mark(&ps, &m, idA, idB, 1000, 1);
    check(p2p_probe_due(&ps, &m, idA, idB, 1000) == 0, "刚探测完 -> 不到期");
    check(p2p_probe_due(&ps, &m, idA, idB, 1999) == 0, "间隔内 -> 不到期");
    check(p2p_probe_due(&ps, &m, idA, idB, 2000) == 1, "满 base 间隔 -> 到期");

    /* ---- 3. 抖动：边界处因 seed 不同而异 ---- */
    {
        int due_cnt = 0, not_cnt = 0;
        for (uint32_t sd = 1; sd <= 40; sd++) {
            p2p_probesched_t js;
            p2p_probesched_init(&js, sd, 1000, 500, 8000);
            /* 距上次 1200ms：base=1000 已满足，是否到期取决于 jitter 落点 */
            int d = p2p_probe_due(&js, &m, idA, idB, 2200);
            if (d == 1) due_cnt++; else not_cnt++;
        }
        printf("[INFO] 距上次 1200ms(base=1000)、jitter=500：40 个 seed 中 %d 到期 / %d 未到期\n",
               due_cnt, not_cnt);
        check(due_cnt > 0 && not_cnt > 0, "抖动使到期时刻不再是等间距");
    }

    /* ---- 4. 失败退避 ---- */
    {
        p2p_probesched_t bs;
        p2p_probesched_init(&bs, 9, 1000, 0, 8000);
        p2p_mesh_t m2;
        p2p_mesh_init(&m2);
        uint8_t c[16], d[16];
        mkid(c, 0x0C); mkid(d, 0x0D);
        p2p_node_add(&m2, c, P2P_ROLE_EDGE, "C", "127.0.0.1", lp);
        p2p_node_add(&m2, d, P2P_ROLE_EDGE, "D", "127.0.0.1", lp);
        p2p_neighbor_link(&m2, c, d);

        p2p_probe_mark(&bs, &m2, c, d, 5000, 0);   /* 失败 */
        check(p2p_probe_due(&bs, &m2, c, d, 6000) == 0, "失败后退避生效(base 内不到期)");
        check(p2p_probe_due(&bs, &m2, c, d, 6999) == 0, "base+退避 前仍不到期");
        check(p2p_probe_due(&bs, &m2, c, d, 7000) == 1, "base+退避 满 -> 到期");

        /* 成功清零退避 */
        p2p_probe_mark(&bs, &m2, c, d, 7000, 1);
        check(p2p_probe_due(&bs, &m2, c, d, 8000) == 1, "成功后退避清零，仅受 base 约束");

        /* 连续失败 -> 退避翻倍并封顶 */
        p2p_probe_mark(&bs, &m2, c, d, 10000, 0);   /* 1000 */
        p2p_probe_mark(&bs, &m2, c, d, 10001, 0);   /* 2000 */
        p2p_probe_mark(&bs, &m2, c, d, 10002, 0);   /* 4000 */
        p2p_probe_mark(&bs, &m2, c, d, 10003, 0);   /* 8000 (封顶) */
        p2p_probe_mark(&bs, &m2, c, d, 10004, 0);   /* 仍 8000 */
        check(p2p_probe_due(&bs, &m2, c, d, 10004 + 1000 + 8000 - 1) == 0,
              "退避封顶后仍不到期");
        check(p2p_probe_due(&bs, &m2, c, d, 10004 + 1000 + 8000) == 1,
              "退避封顶值可到期");
    }

    /* ---- 5. 错峰全图探测：首轮全探，次轮全跳过 ---- */
    {
        p2p_mesh_t m3;
        p2p_mesh_init(&m3);
        uint8_t root[16];
        mkid(root, 0xF0);
        p2p_node_add(&m3, root, P2P_ROLE_ENDPOINT, "root", "127.0.0.1", lp);

        uint8_t ids[3][16];
        for (int i = 0; i < 3; i++) {
            mkid(ids[i], (uint8_t)(0x10 + i));
            p2p_node_add(&m3, ids[i], P2P_ROLE_EDGE, "n", "127.0.0.1", lp);
            p2p_neighbor_link(&m3, root, ids[i]);
        }

        p2p_probesched_t ss;
        p2p_probesched_init(&ss, 42, 60000, 0, 300000);

        int probed = -1, skipped = -1;
        check(p2p_probe_all_staggered(&ss, &m3, root, 20000, &probed, &skipped)
              == P2P_OK, "首轮错峰探测");
        printf("[INFO] 首轮: probed=%d skipped=%d\n", probed, skipped);
        check(probed == 3, "首轮 3 条边全部探测");
        check(skipped == 0, "首轮无跳过");

        probed = -1; skipped = -1;
        p2p_probe_all_staggered(&ss, &m3, root, 20001, &probed, &skipped);
        printf("[INFO] 次轮(1ms 后): probed=%d skipped=%d\n", probed, skipped);
        check(probed == 0 && skipped == 3, "次轮因低频全部跳过（不再周期性全扫）");
    }

    /* ---- 6. 不可达边：探一次后退避，不再高频重试 ---- */
    {
        uint16_t dead = free_port();
        p2p_mesh_t m4;
        p2p_mesh_init(&m4);
        uint8_t root[16], dn[16];
        mkid(root, 0xE0); mkid(dn, 0xE1);
        p2p_node_add(&m4, root, P2P_ROLE_ENDPOINT, "root", "127.0.0.1", lp);
        p2p_node_add(&m4, dn, P2P_ROLE_EDGE, "dead", "127.0.0.1", dead);
        p2p_neighbor_link(&m4, root, dn);

        p2p_probesched_t ds;
        p2p_probesched_init(&ds, 7, 1000, 0, 60000);

        int p1 = -1, s1 = -1, p2 = -1, s2 = -1;
        p2p_probe_all_staggered(&ds, &m4, root, 30000, &p1, &s1);
        p2p_probe_all_staggered(&ds, &m4, root, 30001, &p2, &s2);
        printf("[INFO] 不可达边: 首轮 probed=%d skipped=%d, 次轮 probed=%d skipped=%d\n",
               p1, s1, p2, s2);
        check(p1 == 0 && s1 == 0, "不可达边首轮仍会被尝试（未探测过）");
        check(p2 == 0 && s2 == 1, "失败后退避，次轮被跳过");
    }

    /* ---- 7. 边界：不存在的边 / 无效参数 ---- */
    {
        uint8_t ghost[16];
        mkid(ghost, 0x77);
        check(p2p_probe_due(&ps, &m, idA, ghost, 1000) == P2P_ERR_NOLINK,
              "未连边的节点返回 NOLINK");
        check(p2p_probe_mark(&ps, &m, idA, ghost, 1000, 1) == P2P_ERR_NOLINK,
              "mark 未连边返回 NOLINK");
        check(p2p_probe_due(&ps, &m, idA, NULL, 1000) == P2P_ERR_ARGS, "NULL 被拒");
    }

    if (lfd >= 0) close(lfd);
    printf("\ntotal=%d pass=%d fail=%d\n", g_pass + g_fail, g_pass, g_fail);
    return g_fail ? 1 : 0;
}
