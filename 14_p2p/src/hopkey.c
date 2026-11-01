/*
 * DAYANJING v4 — 14_p2p/src/hopkey.c
 *
 * 跳静态密钥轮换：把 ephemeral-static 补成真前向保密。
 * 设计说明见 include/p2p_hopkey.h。
 *
 * 密钥生成复用 00_crypto 的 X25519，不自研第二套。
 */

#include "p2p_hopkey.h"
#include "p2p_onion.h"

#include "crypto_x25519.h"

#include <string.h>

/*
 * 安全擦除：volatile 逐字节写，防止编译器把"写完再也没读"的 memset 优化掉。
 * 这是 PFS 的关键一环 —— 如果擦除被优化掉，轮换就只是形式。
 */
static void secure_zero(void *p, size_t n) {
    if (!p) return;
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

const char *p2p_hopkey_errstr(int e) {
    switch (e) {
        case P2P_HOPKEY_OK:        return "ok";
        case P2P_HOPKEY_ERR_ARG:   return "invalid argument";
        case P2P_HOPKEY_ERR_AUTH:  return "no retained epoch could peel this layer";
        default:                   return "unknown";
    }
}

int p2p_hopkey_init(p2p_hopkey_t *h) {
    if (!h) return P2P_HOPKEY_ERR_ARG;
    memset(h, 0, sizeof *h);
    if (x25519_generate_keypair(h->slots[0].sk, h->slots[0].pk) != X25519_OK) {
        secure_zero(h, sizeof *h);
        return P2P_HOPKEY_ERR_ARG;
    }
    h->slots[0].epoch = 0;
    h->n = 1;
    h->next_epoch = 1;
    return P2P_HOPKEY_OK;
}

void p2p_hopkey_wipe(p2p_hopkey_t *h) {
    if (!h) return;
    for (int i = 0; i < P2P_HOPKEY_RETAIN; i++)
        secure_zero(h->slots[i].sk, P2P_HOPKEY_KEY_LEN);
    secure_zero(h, sizeof *h);
}

int p2p_hopkey_rotate(p2p_hopkey_t *h, uint32_t *new_epoch) {
    if (!h || h->n == 0) return P2P_HOPKEY_ERR_ARG;

    /* 先擦除最老的槽位私钥 —— 这一步就是 PFS 的兑现点 */
    if (h->n >= P2P_HOPKEY_RETAIN) {
        int last = P2P_HOPKEY_RETAIN - 1;
        secure_zero(h->slots[last].sk, P2P_HOPKEY_KEY_LEN);
        secure_zero(&h->slots[last], sizeof h->slots[last]);
        /* 整体后移：slots[i] = slots[i-1]，最新槽位腾空 */
        for (int i = last; i > 0; i--)
            h->slots[i] = h->slots[i - 1];
    } else {
        for (int i = h->n; i > 0; i--)
            h->slots[i] = h->slots[i - 1];
        h->n++;
    }

    memset(&h->slots[0], 0, sizeof h->slots[0]);
    if (x25519_generate_keypair(h->slots[0].sk, h->slots[0].pk) != X25519_OK)
        return P2P_HOPKEY_ERR_ARG;
    h->slots[0].epoch = h->next_epoch;
    h->next_epoch++;
    if (new_epoch) *new_epoch = h->slots[0].epoch;
    return P2P_HOPKEY_OK;
}

uint32_t p2p_hopkey_epoch(const p2p_hopkey_t *h) {
    return (h && h->n > 0) ? h->slots[0].epoch : 0xffffffffu;
}

int p2p_hopkey_pub(const p2p_hopkey_t *h, uint8_t out[P2P_HOPKEY_KEY_LEN]) {
    if (!h || !out || h->n == 0) return P2P_HOPKEY_ERR_ARG;
    memcpy(out, h->slots[0].pk, P2P_HOPKEY_KEY_LEN);
    return P2P_HOPKEY_OK;
}

int p2p_hopkey_has_epoch(const p2p_hopkey_t *h, uint32_t epoch) {
    if (!h) return 0;
    for (int i = 0; i < h->n; i++)
        if (h->slots[i].epoch == epoch) return 1;
    return 0;
}

int p2p_hopkey_forget(p2p_hopkey_t *h, uint32_t epoch) {
    if (!h) return P2P_HOPKEY_ERR_ARG;
    for (int i = 0; i < h->n; i++) {
        if (h->slots[i].epoch == epoch) {
            secure_zero(h->slots[i].sk, P2P_HOPKEY_KEY_LEN);
            /* 直接把该槽位标记为无效：后续整体前移 */
            for (int j = i; j + 1 < h->n; j++)
                h->slots[j] = h->slots[j + 1];
            memset(&h->slots[h->n - 1], 0, sizeof h->slots[h->n - 1]);
            h->n--;
            return P2P_HOPKEY_OK;
        }
    }
    return P2P_HOPKEY_ERR_ARG;
}

int p2p_hopkey_peel(const p2p_hopkey_t *h,
                    const uint8_t salt[16],
                    const uint8_t my_id[16],
                    const uint8_t *onion, size_t onion_len,
                    int *final_flag,
                    uint8_t next_id[16],
                    char *final_host, size_t host_cap, uint16_t *final_port,
                    uint8_t *inner, size_t inner_cap, size_t *inner_len,
                    uint32_t *used_epoch) {
    if (!h) return P2P_HOPKEY_ERR_ARG;

    /*
     * GCM tag 保证"密钥错 -> 必失败"，不存在猜错 epoch 却解出明文的情况，
     * 因此可以安全地逐个试。
     * 注意：p2p_onion_peel 失败时可能已经写了部分输出参数，
     * 所以每次尝试都传完整参数集，只有成功那次的结果才生效。
     */
    for (int i = 0; i < h->n; i++) {
        uint8_t  nid[16];
        char     host[256];
        uint16_t port = 0;
        int      fflag = 0;
        size_t   ilen = 0;

        uint8_t  ibuf[4096];
        size_t   icap = sizeof ibuf;

        int rc = p2p_onion_peel(h->slots[i].sk, salt, my_id,
                                onion, onion_len,
                                &fflag, nid, host, sizeof host, &port,
                                ibuf, icap, &ilen);
        if (rc != P2P_ONION_OK) continue;

        /* 成功：回填调用方 */
        if (final_flag) *final_flag = fflag;
        if (fflag) {
            if (final_port) *final_port = port;
            if (final_host && host_cap > 0) {
                size_t hl = strlen(host);
                if (host_cap < hl + 1) return P2P_HOPKEY_ERR_ARG;
                memcpy(final_host, host, hl + 1);
            }
        } else {
            if (next_id) memcpy(next_id, nid, 16);
        }
        if (inner_len) *inner_len = ilen;
        if (inner) {
            if (inner_cap < ilen) return P2P_HOPKEY_ERR_ARG;
            if (ilen) memcpy(inner, ibuf, ilen);
        }
        if (used_epoch) *used_epoch = h->slots[i].epoch;
        return P2P_HOPKEY_OK;
    }
    return P2P_HOPKEY_ERR_AUTH;
}
