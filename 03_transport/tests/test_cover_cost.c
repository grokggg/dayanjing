/*
 * DAYANJING v4 — 03_transport/tests/test_cover_cost.c
 *
 * 用**真实隧道编码**测出"一个 512 字节信元在各类信道上实际消耗多少线上字节"，
 * 并回填给 14_p2p 的自适应覆盖流量模块。
 *
 * ====================================================================
 * 为什么要测，而不是查常量
 * ====================================================================
 * p2p_cover.h 里的 P2P_COVER_COST_DNS / COST_ICMP 是量级估计（2040 / 1112）。
 * 它们够用来做"换信道要缩速率"的定性判断，但不够用来做预算控制 ——
 * 真实成本取决于：
 *   - base32 编码膨胀（100 字节净荷 -> 160 字符）
 *   - 每个标签 <=63 的切分与点号
 *   - session + domain 后缀的固定开销
 *   - QTYPE（TXT 查询比 A 查询的应答更大）
 *   - UDP/IP 头
 * 这些只有跑真实编码函数才拿得到准数。
 *
 * 本测试用 tx_dnstun_label_build / tx_dns_build_query_ex 等**产品代码**
 * 逐片编码一个真实信元，累加出线上字节数，再交给 p2p_cover 验证：
 * 用实测成本算出的覆盖速率，与用画像默认值算出的速率确实不同。
 *
 * 注意：本测试不做网络收发（公网下行需自有权威域，环境不具备），
 * 它测的是**编码后的线上字节数**，这是成本模型需要的量。
 */

#include <stdio.h>
#include <string.h>

#include "dnstun.h"
#include "tx_icmtun.h"
#include "p2p_cell.h"
#include "p2p_cover.h"

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, name) do {                          \
    if (cond) { printf("[PASS] %s\n", name); g_pass++; } \
    else      { printf("[FAIL] %s\n", name); g_fail++; } \
} while (0)

/* UDP 8 + IPv4 20 */
#define UDP_IP_OVERHEAD   28u
/* IPv4 20 */
#define IP_OVERHEAD       20u

#define SESSION  "s7f3a9c2"
#define DOMAIN   "tun.example.net"

/*
 * 实测：一个 512 字节信元走 DNS 隧道要多少线上字节。
 * 逐片 label_build -> build_query(TXT) -> 累加；应答按最小 TXT 应答计。
 */
static uint32_t measure_dns_bytes_per_cell(void) {
    uint8_t cell[P2P_CELL_WIRE];
    for (size_t i = 0; i < sizeof(cell); i++) cell[i] = (uint8_t)(i * 7u + 3u);

    const size_t chunk = TX_DNSTUN_CHUNK;   /* 100 */
    size_t nchunks = (P2P_CELL_WIRE + chunk - 1) / chunk;
    uint32_t total = 0;
    uint32_t seq = 0;

    for (size_t off = 0; off < P2P_CELL_WIRE; off += chunk) {
        size_t clen = P2P_CELL_WIRE - off;
        if (clen > chunk) clen = chunk;
        int fin = (off + clen >= P2P_CELL_WIRE) ? 1 : 0;

        char qname[512];
        int rc = tx_dnstun_label_build(seq, 0, fin, cell + off, clen,
                                       SESSION, DOMAIN, qname, sizeof(qname));
        if (rc != 0) { printf("      label_build 失败 rc=%d\n", rc); return 0; }

        uint8_t q[1024];
        size_t qlen = tx_dns_build_query_ex(qname, (uint16_t)(seq & 0xFFFF),
                                            16 /* TXT */, q, sizeof(q));
        if (qlen == 0) { printf("      build_query 失败\n"); return 0; }

        /* 最小下行应答（无下行数据） */
        uint8_t r[1024];
        size_t rlen = tx_dns_build_txt_reply(q, qlen, (const uint8_t *)"", 0,
                                             r, sizeof(r));

        total += (uint32_t)qlen + UDP_IP_OVERHEAD;
        if (rlen) total += (uint32_t)rlen + UDP_IP_OVERHEAD;
        seq++;
    }

    printf("      DNS: %zu 个查询承载 1 个信元，线上 %u 字节\n",
           nchunks, total);
    return total;
}

/*
 * 实测：一个 512 字节信元走 ICMP 隧道要多少线上字节。
 * 请求与应答各一份（ECHO 必有回显），故 ×2。
 */
static uint32_t measure_icmp_bytes_per_cell(void) {
    size_t chunk = TX_ICMTUN_CHUNK;   /* 1000 > 512，故 1 片即可 */
    size_t nfrag = (P2P_CELL_WIRE + chunk - 1) / chunk;
    /* 每片线上 = IP + ICMP 头 + 隧道头 + 净荷 */
    uint32_t per_pkt = IP_OVERHEAD + TX_ICMP_HDR + TX_ICMTUN_HDR + P2P_CELL_WIRE;
    uint32_t total = (uint32_t)nfrag * per_pkt * 2u;   /* 请求 + 应答 */
    printf("      ICMP: %zu 个报文承载 1 个信元，线上 %u 字节\n", nfrag, total);
    return total;
}

int main(void) {
    printf("=== test_cover_cost ===\n");

    uint32_t dns_cost  = measure_dns_bytes_per_cell();
    uint32_t icmp_cost = measure_icmp_bytes_per_cell();

    CHECK(dns_cost > 0, "DNS 每信元成本实测成功");
    CHECK(icmp_cost > 0, "ICMP 每信元成本实测成功");

    /* 直连基线：信元本身 + TCP/IP 头 */
    uint32_t direct_cost = P2P_CELL_WIRE + 40u;
    printf("      直连: 线上 %u 字节\n", direct_cost);

    /*
     * 核心断言：DNS 隧道的成本显著高于直连。
     * 这正是"固定覆盖速率会把 DNS 信道打满"的根因。
     */
    printf("      成本比: DNS/直连 = %.2f, ICMP/直连 = %.2f\n",
           (double)dns_cost / direct_cost, (double)icmp_cost / direct_cost);
    CHECK(dns_cost > direct_cost * 2, "DNS 隧道成本 > 直连 2 倍（编码膨胀真实存在）");
    CHECK(icmp_cost > direct_cost, "ICMP 隧道成本 > 直连（请求+应答双向）");
    CHECK(dns_cost > icmp_cost, "DNS 成本高于 ICMP（base32 膨胀 + 多查询）");

    /* ---- 回填自适应覆盖模型，验证速率确实按实测成本缩放 ---- */
    uint32_t budget = 1000000u;   /* 1 MB/min 字节预算 */

    p2p_cover_t c_direct, c_dns, c_icmp;
    p2p_cover_init(&c_direct, P2P_COVER_PROFILE_DIRECT, budget, 0);
    p2p_cover_init(&c_dns,    P2P_COVER_PROFILE_DNS,    budget, 0);
    p2p_cover_init(&c_icmp,   P2P_COVER_PROFILE_ICMP,   budget, 0);

    uint32_t t_direct = p2p_cover_target_total(&c_direct);
    uint32_t t_dns_def = p2p_cover_target_total(&c_dns);

    /* 用真实实测值覆盖画像默认值 */
    CHECK(p2p_cover_set_measured_cost(&c_dns, dns_cost) == 0,
          "DNS 实测成本回填成功");
    CHECK(p2p_cover_set_measured_cost(&c_icmp, icmp_cost) == 0,
          "ICMP 实测成本回填成功");

    uint32_t t_dns  = p2p_cover_target_total(&c_dns);
    uint32_t t_icmp = p2p_cover_target_total(&c_icmp);

    printf("      同预算(%u B/min)目标速率: 直连=%u ICMP=%u DNS=%u (画像默认 DNS=%u)\n",
           budget, t_direct, t_icmp, t_dns, t_dns_def);

    CHECK(t_dns < t_direct, "DNS 目标速率低于直连");
    CHECK(t_icmp < t_direct, "ICMP 目标速率低于直连");
    CHECK(t_dns < t_icmp, "DNS 目标速率最低（成本最高）");

    /*
     * 关键：画像默认值 2040 只是量级估计，实测值可能与之有偏差。
     * 部署前必须用实测值回填 —— 这里证明两者确实不同（否则回填无意义）。
     */
    printf("      画像默认 DNS=%u vs 实测 DNS=%u 字节/信元\n",
           P2P_COVER_COST_DNS, dns_cost);
    CHECK(dns_cost != P2P_COVER_COST_DNS,
          "实测成本与画像默认值不同（证明部署前必须实测回填）");

    /* 预算约束：任何信道下预计开销都不超预算 */
    p2p_cover_rate(&c_dns);
    CHECK(p2p_cover_projected_bytes_per_min(&c_dns) <= budget,
          "DNS 实测成本下预计开销不超预算");
    p2p_cover_rate(&c_icmp);
    CHECK(p2p_cover_projected_bytes_per_min(&c_icmp) <= budget,
          "ICMP 实测成本下预计开销不超预算");

    /* 极端小预算：DNS 下应直接降到 0（一个信元都发不起） */
    p2p_cover_set_budget(&c_dns, dns_cost / 2u);
    CHECK(p2p_cover_target_total(&c_dns) == 0,
          "预算不足一个信元时目标速率为 0");

    printf("=== result: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
