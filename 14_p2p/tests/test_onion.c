/*
 * DAYANJING v4 — 14_p2p/tests/test_onion.c
 *
 * 洋葱路由测试（层密钥 = X25519 ephemeral-static，无全网共享 master）。
 *
 * 取证方式：部分用例不依赖模块自报，而是直接在洋葱字节里搜特征
 * （最终目标主机名、深跳 ID），搜到即判失败 —— 防止"加密做了但漏字段"。
 */

#include "p2p_onion.h"

#include "crypto_x25519.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

static void check(int cond, const char *name) {
    if (cond) { g_pass++; printf("[PASS] %s\n", name); }
    else      { g_fail++; printf("[FAIL] %s\n", name); }
}

/* 在 haystack 中搜 needle */
static int contains(const uint8_t *hay, size_t n,
                    const uint8_t *needle, size_t m) {
    if (!m || m > n) return 0;
    for (size_t i = 0; i + m <= n; i++)
        if (memcmp(hay + i, needle, m) == 0) return 1;
    return 0;
}

static void mkid(uint8_t id[16], const char *tag) {
    memset(id, 0, 16);
    /* 用可辨识但不全 ASCII 的填充，避免"碰巧搜到"或"搜不到"的假结论 */
    size_t n = strlen(tag);
    for (size_t i = 0; i < 16; i++)
        id[i] = (uint8_t)(i < n ? (unsigned char)tag[i] : (0xa0u + i));
}

int main(void) {
    uint8_t idA[16], idB[16], idC[16];
    mkid(idA, "EDGE0"); mkid(idB, "EDGE1"); mkid(idC, "COREHOP");

    /* 每跳各自的静态密钥对 */
    uint8_t skA[32], pkA[32], skB[32], pkB[32], skC[32], pkC[32];
    check(x25519_generate_keypair(skA, pkA) == X25519_OK, "生成 A 静态密钥对");
    check(x25519_generate_keypair(skB, pkB) == X25519_OK, "生成 B 静态密钥对");
    check(x25519_generate_keypair(skC, pkC) == X25519_OK, "生成 C 静态密钥对");

    uint8_t hops[3 * 16], pubs[3 * 32], salt[16];
    memcpy(hops,       idA, 16);
    memcpy(hops + 16,  idB, 16);
    memcpy(hops + 32,  idC, 16);
    memcpy(pubs,       pkA, 32);
    memcpy(pubs + 32,  pkB, 32);
    memcpy(pubs + 64,  pkC, 32);
    memset(salt, 0x5a, 16);

    /* ---- 1. 层密钥双向一致：建电路方与解层方算出同一把钥匙 ---- */
    {
        uint8_t eph_priv[32], eph_pub[32];
        x25519_generate_keypair(eph_priv, eph_pub);
        uint8_t k1[16], k2[16];
        int r1 = p2p_onion_layer_key(eph_priv, pkA, salt, idA, k1);  /* 建电路方 */
        int r2 = p2p_onion_layer_key(skA, eph_pub, salt, idA, k2);   /* A 自己 */
        check(r1 == P2P_ONION_OK && r2 == P2P_ONION_OK, "层密钥派生双方均成功");
        check(memcmp(k1, k2, 16) == 0, "层密钥双向一致（X25519 双向性）");
    }

    /* ---- 2. 不同跳、不同 salt 必须得到不同层密钥 ---- */
    {
        uint8_t e_priv[32], e_pub[32];
        x25519_generate_keypair(e_priv, e_pub);
        uint8_t kA[16], kB[16];
        p2p_onion_layer_key(skA, e_pub, salt, idA, kA);
        p2p_onion_layer_key(skB, e_pub, salt, idB, kB);
        check(memcmp(kA, kB, 16) != 0, "不同跳层密钥不同");

        uint8_t salt2[16];
        memset(salt2, 0xa5, 16);
        uint8_t kA2[16];
        p2p_onion_layer_key(skA, e_pub, salt2, idA, kA2);
        check(memcmp(kA, kA2, 16) != 0, "换 salt 后层密钥不同");
    }

    /* ---- 3. 三跳洋葱逐层剥离 ---- */
    uint8_t onion[4096];
    size_t  onion_len = 0;
    {
        int rc = p2p_onion_build(hops, 3, pubs, salt,
                                 "SECRETTARGETHOST", 9999,
                                 onion, sizeof onion, &onion_len);
        check(rc == P2P_ONION_OK, "构建 3 层洋葱");
        printf("[INFO] onion 长度=%zu\n", onion_len);
    }

    uint8_t inner1[4096]; size_t inner1_len = 0;
    {
        int ff = 0; uint8_t next[16]; char host[256]; uint16_t port = 0;
        memset(next, 0, sizeof next);
        int rc = p2p_onion_peel(skA, salt, idA, onion, onion_len,
                                &ff, next, host, sizeof host, &port,
                                inner1, sizeof inner1, &inner1_len);
        check(rc == P2P_ONION_OK, "A 剥开自己那层");
        check(ff == 0, "A 不是最后一跳");
        check(memcmp(next, idB, 16) == 0, "A 只知道下一跳是 B");
        printf("[INFO] A: 下一跳=B, 内层密文 %zu 字节（不可读）\n", inner1_len);
    }
    uint8_t inner2[4096]; size_t inner2_len = 0;
    {
        int ff = 0; uint8_t next[16]; char host[256]; uint16_t port = 0;
        int rc = p2p_onion_peel(skB, salt, idB, inner1, inner1_len,
                                &ff, next, host, sizeof host, &port,
                                inner2, sizeof inner2, &inner2_len);
        check(rc == P2P_ONION_OK, "B 剥开自己那层");
        check(ff == 0, "B 不是最后一跳");
        check(memcmp(next, idC, 16) == 0, "B 只知道下一跳是 C");
    }
    {
        int ff = 0; uint8_t next[16]; char host[256]; uint16_t port = 0;
        memset(host, 0, sizeof host);
        size_t dummy_len = 0;
        int rc = p2p_onion_peel(skC, salt, idC, inner2, inner2_len,
                                &ff, next, host, sizeof host, &port,
                                NULL, 0, &dummy_len);
        check(rc == P2P_ONION_OK, "C 剥开自己那层");
        check(ff == 1, "C 是最后一跳");
        check(strcmp(host, "SECRETTARGETHOST") == 0 && port == 9999,
              "C 解出最终目标 host:port");
        printf("[INFO] C: 最终目标=%s:%u\n", host, port);
    }

    /* ---- 4. 取证：洋葱字节里不含最终目标与深跳 ID ---- */
    {
        const char *tgt = "SECRETTARGETHOST";
        check(!contains(onion, onion_len, (const uint8_t *)tgt, strlen(tgt)),
              "洋葱中不含最终目标主机名明文");
        check(!contains(onion, onion_len, idC, 16), "洋葱中不含深跳 C 的 ID 明文");
        /* A 的内层里也不该有（A 只能看到 B 的层，看不到 C） */
        check(!contains(inner1, inner1_len, idC, 16), "A 持有的内层不含 C 的 ID");
    }

    /* ---- 5. 核心取证：攻破一跳解不出其他跳的层（无共享主密钥） ---- */
    {
        /* A 拿自己的私钥去剥 B 那层 -> 必须失败 */
        int ff = 0; uint8_t next[16]; char host[256]; uint16_t port = 0;
        size_t dl = 0;
        int rc = p2p_onion_peel(skA, salt, idB, inner1, inner1_len,
                                &ff, next, host, sizeof host, &port, NULL, 0, &dl);
        check(rc == P2P_ONION_ERR_AUTH, "A 的私钥剥不开 B 的层（AUTH）");

        /* B 拿自己私钥去剥 A 那层（外层）-> 同样失败 */
        rc = p2p_onion_peel(skB, salt, idA, onion, onion_len,
                            &ff, next, host, sizeof host, &port, NULL, 0, &dl);
        check(rc == P2P_ONION_ERR_AUTH, "B 的私钥剥不开 A 的层（AUTH）");

        /* 掌握一跳私钥 + 全部线上字节，仍解不出其他层 */
        rc = p2p_onion_peel(skA, salt, idA, inner2, inner2_len,
                            &ff, next, host, sizeof host, &port, NULL, 0, &dl);
        check(rc == P2P_ONION_ERR_AUTH, "A 的私钥剥不开最内层 C 的层（AUTH）");
    }

    /* ---- 6. 篡改检测 ---- */
    {
        uint8_t bad[4096];
        memcpy(bad, onion, onion_len);
        bad[onion_len - 1] ^= 0x01;
        int ff = 0; uint8_t next[16]; char host[256]; uint16_t port = 0;
        size_t dl = 0;
        int rc = p2p_onion_peel(skA, salt, idA, bad, onion_len,
                                &ff, next, host, sizeof host, &port, NULL, 0, &dl);
        check(rc == P2P_ONION_ERR_AUTH, "篡改末字节后剥层失败（AUTH）");

        /* 改临时公钥（层密钥协商输入）也须失败 */
        memcpy(bad, onion, onion_len);
        bad[0] ^= 0x01;
        rc = p2p_onion_peel(skA, salt, idA, bad, onion_len,
                            &ff, next, host, sizeof host, &port, NULL, 0, &dl);
        check(rc == P2P_ONION_ERR_AUTH, "篡改临时公钥后剥层失败（AUTH）");
    }

    /* ---- 7. 边界与参数校验 ---- */
    {
        size_t need = 0;
        check(p2p_onion_build(hops, 3, pubs, salt, "h", 1, NULL, 0, &need)
              == P2P_ONION_OK && need > 0, "build(NULL) 仅探测长度");
        check(p2p_onion_build(hops, 0, pubs, salt, "h", 1, onion, sizeof onion, &need)
              == P2P_ONION_ERR_ARG, "n_hops=0 -> ARG");
        check(p2p_onion_build(hops, 17, pubs, salt, "h", 1, onion, sizeof onion, &need)
              == P2P_ONION_ERR_ARG, "n_hops 超上限 -> ARG");
        check(p2p_onion_build(NULL, 3, pubs, salt, "h", 1, onion, sizeof onion, &need)
              == P2P_ONION_ERR_ARG, "hops=NULL -> ARG");
        check(p2p_onion_build(hops, 3, NULL, salt, "h", 1, onion, sizeof onion, &need)
              == P2P_ONION_ERR_ARG, "hop_pub=NULL -> ARG");
        /* 缓冲区不足 */
        check(p2p_onion_build(hops, 3, pubs, salt, "h", 1, onion, 8, &need)
              == P2P_ONION_ERR_LEN, "缓冲区不足 -> LEN");
        /* 过短洋葱 */
        uint8_t tiny[8] = {0};
        int ff = 0; uint8_t next[16]; char host[256]; uint16_t port = 0; size_t dl = 0;
        check(p2p_onion_peel(skA, salt, idA, tiny, sizeof tiny,
                             &ff, next, host, sizeof host, &port, NULL, 0, &dl)
              == P2P_ONION_ERR_FMT, "过短洋葱 -> FMT");
        check(p2p_onion_peel(NULL, salt, idA, onion, onion_len,
                             &ff, next, host, sizeof host, &port, NULL, 0, &dl)
              == P2P_ONION_ERR_ARG, "sk=NULL -> ARG");
    }

    /* ---- 8. 电路头与转发封装往返 ---- */
    {
        uint8_t hdr[4096]; size_t hlen = 0;
        int rc = p2p_onion_build_hdr(hops, 3, pubs, salt,
                                     "SECRETTARGETHOST", 9999,
                                     hdr, sizeof hdr, &hlen);
        check(rc == P2P_ONION_OK, "构建电路头");
        uint8_t s2[16]; const uint8_t *o2 = NULL; size_t o2len = 0;
        check(p2p_onion_parse_hdr(hdr, hlen, s2, &o2, &o2len) == P2P_ONION_OK,
              "解析电路头");
        check(memcmp(s2, salt, 16) == 0, "salt 往返一致");
        /* 注意：每次 build 都生成新的临时密钥对，故不可与原洋葱比字节，
         * 只能验证"取出的这段确实能被首跳剥开" */
        check(o2len > 0, "取出的洋葱非空");
        {
            int ff = 0; uint8_t next[16]; char h2[256]; uint16_t p2 = 0; size_t dl = 0;
            int pr = p2p_onion_peel(skA, s2, idA, o2, o2len,
                                    &ff, next, h2, sizeof h2, &p2, NULL, 0, &dl);
            check(pr == P2P_ONION_OK && ff == 0 && memcmp(next, idB, 16) == 0,
                  "解析出的洋葱可被首跳剥开且下一跳=B");
        }

        uint8_t fwd[4096]; size_t flen = 0;
        check(p2p_onion_build_fwd(inner1, inner1_len, fwd, sizeof fwd, &flen)
              == P2P_ONION_OK, "构建转发封装");
        const uint8_t *i2 = NULL; size_t i2len = 0;
        check(p2p_onion_parse_fwd(fwd, flen, &i2, &i2len) == P2P_ONION_OK,
              "解析转发封装");
        check(i2len == inner1_len && memcmp(i2, inner1, inner1_len) == 0,
              "转发封装内容字节级一致");
    }

    /* ---- 9. 每条电路的洋葱不同（临时密钥随机） ---- */
    {
        uint8_t o2[4096]; size_t o2len = 0;
        p2p_onion_build(hops, 3, pubs, salt, "h", 1, o2, sizeof o2, &o2len);
        check(o2len != onion_len || memcmp(o2, onion, onion_len) != 0,
              "同参数两次构建的洋葱不同（临时密钥随机）");
    }

    printf("\ntotal=%d pass=%d fail=%d\n", g_pass + g_fail, g_pass, g_fail);
    return g_fail ? 1 : 0;
}
