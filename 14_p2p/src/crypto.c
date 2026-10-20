/*
 * DAYANJING v4 — 14_p2p/src/crypto.c
 *
 * P2P 端到端加密隧道：端点侧 AEAD 封装 + 接收侧重放窗口。
 *
 * 密码学复用 02_c2/c2_frame（AES-128-GCM），不自研第二套。
 * 本文件只做两件事：会话态管理（seq/counter/窗口）与方向性密钥绑定。
 */

#include "p2p_crypto.h"
#include "c2_frame.h"

#include <string.h>

const char *p2p_c_errstr(int e) {
    switch (e) {
        case P2P_C_OK:        return "ok";
        case P2P_C_ERR_ARG:   return "invalid argument";
        case P2P_C_ERR_LEN:   return "length invalid";
        case P2P_C_ERR_AUTH:  return "authentication failed";
        case P2P_C_ERR_FMT:   return "format error";
        case P2P_C_ERR_REPLAY:return "replay or too old";
        default:              return "unknown";
    }
}

size_t p2p_tunnel_wire_len(size_t plen) {
    return C2_FRAME_WIRE_LEN(plen);
}

int p2p_tunnel_init(p2p_tunnel_t *t,
                    const uint8_t k_send[P2P_KEY_LEN],
                    const uint8_t k_recv[P2P_KEY_LEN],
                    const uint8_t nonce_pfx[P2P_NONCE_PFX_LEN]) {
    if (!t || !k_send || !k_recv || !nonce_pfx) return P2P_C_ERR_ARG;
    /* 单向密钥分离：两方向密钥相同意味着单密钥退化，直接拒绝 */
    if (memcmp(k_send, k_recv, P2P_KEY_LEN) == 0) return P2P_C_ERR_ARG;

    memset(t, 0, sizeof(*t));
    memcpy(t->k_send, k_send, P2P_KEY_LEN);
    memcpy(t->k_recv, k_recv, P2P_KEY_LEN);
    memcpy(t->nonce_pfx, nonce_pfx, P2P_NONCE_PFX_LEN);
    t->send_seq = 0;
    t->send_counter = 0;
    t->recv_init = 0;
    t->highest = 0;
    t->bitmap = 0;
    return P2P_C_OK;
}

void p2p_tunnel_wipe(p2p_tunnel_t *t) {
    if (!t) return;
    memset(t->k_send, 0, P2P_KEY_LEN);
    memset(t->k_recv, 0, P2P_KEY_LEN);
    memset(t->nonce_pfx, 0, P2P_NONCE_PFX_LEN);
}

int p2p_tunnel_frame_len(const uint8_t *wire, size_t wire_len, size_t *frame_len) {
    if (!wire || !frame_len || wire_len < 4) return P2P_C_ERR_FMT;
    uint32_t total = (uint32_t)wire[0]
                   | ((uint32_t)wire[1] << 8)
                   | ((uint32_t)wire[2] << 16)
                   | ((uint32_t)wire[3] << 24);
    /* total = 4(msg_type) + 12(iv) + ct + 16(tag)，最小 4+12+20+16 = 52 */
    if (total < 52) return P2P_C_ERR_FMT;
    size_t fl = (size_t)total + 4u;
    if (fl > wire_len) return P2P_C_ERR_FMT;
    *frame_len = fl;
    return P2P_C_OK;
}

int p2p_tunnel_wrap(p2p_tunnel_t *t, uint32_t msg_type,
                    const uint8_t *payload, size_t plen,
                    uint8_t *out, size_t cap, size_t *out_len) {
    if (!t || !out_len) return P2P_C_ERR_ARG;
    if (plen > 0 && !payload) return P2P_C_ERR_ARG;

    int rc = c2_frame_seal(t->k_send, t->nonce_pfx, t->send_counter,
                           t->send_seq, msg_type,
                           payload, plen, out, cap, out_len);
    if (rc != C2_FRAME_OK) {
        /* 映射底层错误码，保持本模块错误语义一致 */
        if (rc == C2_FRAME_ERR_ARG) return P2P_C_ERR_ARG;
        if (rc == C2_FRAME_ERR_LEN) return P2P_C_ERR_LEN;
        return P2P_C_ERR_FMT;
    }
    /* 仅在实际封装成功后推进状态，避免探测调用污染 seq/counter */
    if (out != NULL) {
        t->send_seq++;
        t->send_counter++;
    }
    return P2P_C_OK;
}

/* 重放窗口：返回 P2P_C_OK 表示可接受（内部已更新窗口） */
static int replay_check(p2p_tunnel_t *t, uint64_t seq) {
    if (!t->recv_init) {
        t->recv_init = 1;
        t->highest = seq;
        t->bitmap = 1;                 /* bit0 = highest 自身 */
        return P2P_C_OK;
    }
    if (seq > t->highest) {
        uint64_t shift = seq - t->highest;
        if (shift >= P2P_REPLAY_WINDOW) {
            t->bitmap = 1;             /* 窗口整体跳过，旧位全部作废 */
        } else {
            t->bitmap = (t->bitmap << shift) | 1ULL;
        }
        t->highest = seq;
        return P2P_C_OK;
    }
    /* seq <= highest */
    uint64_t diff = t->highest - seq;
    if (diff >= P2P_REPLAY_WINDOW) return P2P_C_ERR_REPLAY;  /* 过旧，已滑出窗口 */
    if ((t->bitmap >> diff) & 1ULL)  return P2P_C_ERR_REPLAY; /* 已收过 */
    t->bitmap |= (1ULL << diff);
    return P2P_C_OK;
}

int p2p_tunnel_unwrap(p2p_tunnel_t *t,
                      const uint8_t *wire, size_t wire_len,
                      uint64_t *seq, uint32_t *msg_type,
                      uint8_t *payload, size_t cap, size_t *plen) {
    if (!t || !wire) return P2P_C_ERR_ARG;

    size_t fl = 0;
    int rc = p2p_tunnel_frame_len(wire, wire_len, &fl);
    if (rc != P2P_C_OK) return P2P_C_ERR_FMT;
    if (fl != wire_len) return P2P_C_ERR_FMT;   /* 长度前缀与实际不符 */

    uint64_t s = 0;
    uint32_t mt = 0;
    rc = c2_frame_open(t->k_recv, wire, wire_len, &s, &mt, payload, cap, plen);
    if (rc == C2_FRAME_ERR_AUTH) return P2P_C_ERR_AUTH;
    if (rc == C2_FRAME_ERR_ARG)  return P2P_C_ERR_ARG;
    if (rc == C2_FRAME_ERR_LEN)  return P2P_C_ERR_LEN;
    if (rc != C2_FRAME_OK)       return P2P_C_ERR_FMT;

    /* 先验签后查重放：篡改帧不会推进窗口，避免攻击者用伪造帧把窗口推飞 */
    int rr = replay_check(t, s);
    if (rr != P2P_C_OK) return rr;

    if (seq)      *seq = s;
    if (msg_type) *msg_type = mt;
    return P2P_C_OK;
}
