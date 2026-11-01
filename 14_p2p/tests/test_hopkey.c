/*
 * DAYANJING v4 — 14_p2p/tests/test_hopkey.c
 *
 * 跳静态密钥轮换 / 前向保密验证。
 *
 * 核心命题（PFS）：
 *   用 epoch N 的公钥构建的洋葱，在 epoch N 滚出保留窗口后**永久解不开**，
 *   即使攻击者完整录制了当时的电路建立报文。
 */

#include "p2p_hopkey.h"
#include "p2p_onion.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;
static void check(int cond, const char *name) {
    if (cond) { g_pass++; printf("[PASS] %s\n", name); }
    else      { g_fail++; printf("[FAIL] %s\n", name); }
}

static void mkid(uint8_t *id, uint8_t b) {
    memset(id, 0, 16);
    id[0] = b;
}

int main(void) {
    uint8_t  id[16];
    uint8_t  salt[16];
    mkid(id, 0x11);
    memset(salt, 0x5a, sizeof salt);

    p2p_hopkey_t h;
    uint8_t pub0[32], pub1[32];

    /* ---- 基本生成 ---- */
    check(p2p_hopkey_init(&h) == P2P_HOPKEY_OK, "init");
    check(p2p_hopkey_epoch(&h) == 0, "epoch 起始为 0");
    check(p2p_hopkey_pub(&h, pub0) == P2P_HOPKEY_OK, "取当前公钥");
    check(p2p_hopkey_has_epoch(&h, 0), "窗口内含 epoch0");

    /* ---- 用 epoch0 公钥建洋葱，当前能剥开 ---- */
    uint8_t onion[4096];
    size_t  olen = 0;
    int rc = p2p_onion_build(id, 1, pub0, salt,
                             "target.example", 443,
                             onion, sizeof onion, &olen);
    check(rc == P2P_ONION_OK && olen > 0, "建洋葱(1跳,final)");

    uint32_t used = 0xffffffffu;
    int      ff = -1;
    char     host[128];
    uint16_t port = 0;
    size_t   ilen = 999;
    rc = p2p_hopkey_peel(&h, salt, id, onion, olen,
                         &ff, NULL, host, sizeof host, &port,
                         NULL, 0, &ilen, &used);
    check(rc == P2P_HOPKEY_OK, "epoch0 可剥开");
    check(used == 0, "used_epoch == 0");
    check(ff == 1 && port == 443 && strcmp(host, "target.example") == 0,
          "final 的 host/port 正确");

    /* ---- 轮换一次：epoch0 仍在窗口，在途电路仍可剥开 ---- */
    uint32_t ne = 0;
    check(p2p_hopkey_rotate(&h, &ne) == P2P_HOPKEY_OK, "轮换 1 次");
    check(ne == 1 && p2p_hopkey_epoch(&h) == 1, "epoch -> 1");
    check(p2p_hopkey_has_epoch(&h, 0) && p2p_hopkey_has_epoch(&h, 1),
          "窗口同时含 epoch0/1");
    check(p2p_hopkey_pub(&h, pub1) == P2P_HOPKEY_OK, "取新公钥");
    check(memcmp(pub0, pub1, 32) != 0, "轮换后公钥已变");

    used = 0xffffffffu;
    rc = p2p_hopkey_peel(&h, salt, id, onion, olen,
                         &ff, NULL, host, sizeof host, &port,
                         NULL, 0, &ilen, &used);
    check(rc == P2P_HOPKEY_OK, "在途电路(epoch0)轮换1次后仍可剥开");
    check(used == 0, "确实是用 epoch0 的私钥剥开的");

    /* ---- 再轮换一次：epoch0 滚出窗口 —— 这就是 PFS ---- */
    check(p2p_hopkey_rotate(&h, NULL) == P2P_HOPKEY_OK, "轮换 2 次");
    check(!p2p_hopkey_has_epoch(&h, 0), "epoch0 已滚出保留窗口");
    check(p2p_hopkey_has_epoch(&h, 1) && p2p_hopkey_has_epoch(&h, 2),
          "窗口含 epoch1/2");

    rc = p2p_hopkey_peel(&h, salt, id, onion, olen,
                         &ff, NULL, host, sizeof host, &port,
                         NULL, 0, &ilen, NULL);
    check(rc == P2P_HOPKEY_ERR_AUTH,
          "PFS: 录制的 epoch0 电路永久解不开");

    /* ---- 新电路用新公钥仍可用 ---- */
    uint8_t pub2[32], onion2[4096];
    size_t  olen2 = 0;
    p2p_hopkey_pub(&h, pub2);
    rc = p2p_onion_build(id, 1, pub2, salt, "new.example", 8443,
                         onion2, sizeof onion2, &olen2);
    check(rc == P2P_ONION_OK, "用 epoch2 公钥建新洋葱");
    used = 0xffffffffu;
    rc = p2p_hopkey_peel(&h, salt, id, onion2, olen2,
                         &ff, NULL, host, sizeof host, &port,
                         NULL, 0, &ilen, &used);
    check(rc == P2P_HOPKEY_OK && used == 2, "新电路用 epoch2 剥开");

    /* ---- 主动遗忘 ---- */
    p2p_hopkey_t g;
    uint8_t gpub[32], gonion[4096];
    size_t  golen = 0;
    p2p_hopkey_init(&g);
    p2p_hopkey_pub(&g, gpub);
    p2p_onion_build(id, 1, gpub, salt, "forget.example", 1,
                    gonion, sizeof gonion, &golen);
    check(p2p_hopkey_peel(&g, salt, id, gonion, golen,
                          &ff, NULL, host, sizeof host, &port,
                          NULL, 0, &ilen, NULL) == P2P_HOPKEY_OK,
          "遗忘前可剥开");
    check(p2p_hopkey_forget(&g, 0) == P2P_HOPKEY_OK, "主动遗忘 epoch0");
    check(p2p_hopkey_peel(&g, salt, id, gonion, golen,
                          &ff, NULL, host, sizeof host, &port,
                          NULL, 0, &ilen, NULL) == P2P_HOPKEY_ERR_AUTH,
          "遗忘后立刻解不开");
    check(p2p_hopkey_forget(&g, 7) == P2P_HOPKEY_ERR_ARG,
          "遗忘不存在的 epoch 返回 ARG");

    /* ---- 多跳：中间跳轮换不影响其他跳 ---- */
    uint8_t idA[16], idB[16], idC[16];
    mkid(idA, 0xA1); mkid(idB, 0xB2); mkid(idC, 0xC3);
    p2p_hopkey_t hA, hB, hC;
    p2p_hopkey_init(&hA); p2p_hopkey_init(&hB); p2p_hopkey_init(&hC);
    uint8_t pA[32], pB[32], pC[32];
    p2p_hopkey_pub(&hA, pA); p2p_hopkey_pub(&hB, pB); p2p_hopkey_pub(&hC, pC);

    uint8_t hops[48], pubs[96];
    memcpy(hops,      idA, 16);
    memcpy(hops + 16, idB, 16);
    memcpy(hops + 32, idC, 16);
    memcpy(pubs,      pA,  32);
    memcpy(pubs + 32, pB,  32);
    memcpy(pubs + 64, pC,  32);

    uint8_t on3[4096];
    size_t  on3len = 0;
    check(p2p_onion_build(hops, 3, pubs, salt, "deep.example", 9000,
                          on3, sizeof on3, &on3len) == P2P_ONION_OK,
          "建 3 跳洋葱");

    uint8_t inner1[4096];
    uint8_t nextid[16];
    size_t  inner1len = 0;
    check(p2p_hopkey_peel(&hA, salt, idA, on3, on3len, &ff, nextid,
                          host, sizeof host, &port,
                          inner1, sizeof inner1, &inner1len, NULL) == P2P_HOPKEY_OK,
          "A 剥开第一层");
    check(ff == 0 && memcmp(nextid, idB, 16) == 0, "A 只得知下一跳是 B");

    uint8_t inner2[4096];
    size_t  inner2len = 0;
    check(p2p_hopkey_peel(&hB, salt, idB, inner1, inner1len, &ff, nextid,
                          host, sizeof host, &port,
                          inner2, sizeof inner2, &inner2len, NULL) == P2P_HOPKEY_OK,
          "B 剥开第二层");

    /* B 轮换两次 -> B 的 epoch0 滚出窗口 */
    p2p_hopkey_rotate(&hB, NULL);
    p2p_hopkey_rotate(&hB, NULL);
    check(p2p_hopkey_peel(&hB, salt, idB, inner1, inner1len, &ff, nextid,
                          host, sizeof host, &port,
                          NULL, 0, &ilen, NULL) == P2P_HOPKEY_ERR_AUTH,
          "B 轮换2次后解不开自己的旧层");
    check(p2p_hopkey_peel(&hC, salt, idC, inner2, inner2len, &ff, nextid,
                          host, sizeof host, &port,
                          NULL, 0, &ilen, NULL) == P2P_HOPKEY_OK,
          "C 未轮换，最后一跳正常");

    /* ---- 错误的节点 ID 应失败 ---- */
    uint8_t wrong[16];
    mkid(wrong, 0x99);
    check(p2p_hopkey_peel(&hC, salt, wrong, inner2, inner2len, &ff, nextid,
                          host, sizeof host, &port,
                          NULL, 0, &ilen, NULL) == P2P_HOPKEY_ERR_AUTH,
          "用错 ID 剥层失败");

    /* ---- wipe 后彻底不可用 ---- */
    p2p_hopkey_wipe(&hC);
    check(p2p_hopkey_peel(&hC, salt, idC, inner2, inner2len, &ff, nextid,
                          host, sizeof host, &port,
                          NULL, 0, &ilen, NULL) == P2P_HOPKEY_ERR_AUTH,
          "wipe 后剥层失败");
    check(p2p_hopkey_epoch(&hC) == 0xffffffffu, "wipe 后无有效 epoch");

    printf("\ntotal=%d pass=%d fail=%d\n", g_pass + g_fail, g_pass, g_fail);
    return g_fail ? 1 : 0;
}
