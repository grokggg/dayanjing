/*
 * DAYANJING v4 — 14_p2p/src/crypto.c
 *
 * P2P 端到端加密隧道：端点侧 AEAD 封装 + 接收侧重放窗口。
 *
 * 密码学复用 02_c2/c2_frame（AES-128-GCM），不自研第二套。
 * 本文件只做两件事：会话态管理（seq/counter/窗口）与方向性密钥绑定。
 */

#include "p2p_crypto.h"
#include "p2p.h"
#include "c2_frame.h"
#include "crypto_hash.h"

#include <string.h>

/* 两个 ID 长度常量必须一致，否则方向判定与 info 拼接会错位 */
_Static_assert(P2P_C_ID_LEN == P2P_NODE_ID_LEN,
               "P2P_C_ID_LEN must match P2P_NODE_ID_LEN");

/* 派生标签：改动即视为协议版本变更，会破坏与既有对端的互通 */
static const uint8_t P2P_TUNNEL_SALT[] = "dayanjing:p2p:tunnel:v1";
static const uint8_t P2P_TUNNEL_LABEL[] = "p2p:tunnel:keys:v1";

#define P2P_TUNNEL_OKM_LEN  (P2P_KEY_LEN * 2 + P2P_NONCE_PFX_LEN)  /* 40 */

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

int p2p_tunnel_init_from_session(p2p_tunnel_t *t,
                                 const uint8_t k_c2s[P2P_KEY_LEN],
                                 const uint8_t k_s2c[P2P_KEY_LEN],
                                 const uint8_t local_id[P2P_C_ID_LEN],
                                 const uint8_t peer_id[P2P_C_ID_LEN]) {
    if (!t || !k_c2s || !k_s2c || !local_id || !peer_id) return P2P_C_ERR_ARG;
    /* 与自身建隧道没有意义，且会让方向判定退化 */
    if (memcmp(local_id, peer_id, P2P_C_ID_LEN) == 0) return P2P_C_ERR_ARG;
    /* 会话密钥退化（单向分离失效）时不应派生出隧道密钥 */
    if (memcmp(k_c2s, k_s2c, P2P_KEY_LEN) == 0) return P2P_C_ERR_ARG;

    /* IKM = k_c2s || k_s2c，两个方向共同贡献熵 */
    uint8_t ikm[P2P_KEY_LEN * 2];
    memcpy(ikm, k_c2s, P2P_KEY_LEN);
    memcpy(ikm + P2P_KEY_LEN, k_s2c, P2P_KEY_LEN);

    /*
     * info 必须用规范序（min || max）拼接。
     * 若用 local || peer，两端得到的 info 不同 -> OKM 不同 -> 密钥对不上。
     */
    const uint8_t *lo = local_id, *hi = peer_id;
    if (memcmp(local_id, peer_id, P2P_C_ID_LEN) > 0) { lo = peer_id; hi = local_id; }

    uint8_t info[sizeof(P2P_TUNNEL_LABEL) - 1 + P2P_C_ID_LEN * 2];
    size_t off = 0;
    memcpy(info + off, P2P_TUNNEL_LABEL, sizeof(P2P_TUNNEL_LABEL) - 1);
    off += sizeof(P2P_TUNNEL_LABEL) - 1;
    memcpy(info + off, lo, P2P_C_ID_LEN); off += P2P_C_ID_LEN;
    memcpy(info + off, hi, P2P_C_ID_LEN); off += P2P_C_ID_LEN;

    uint8_t okm[P2P_TUNNEL_OKM_LEN];
    if (hkdf(P2P_TUNNEL_SALT, sizeof(P2P_TUNNEL_SALT) - 1,
             ikm, sizeof(ikm),
             info, sizeof(info),
             okm, sizeof(okm)) != 0) {
        memset(ikm, 0, sizeof(ikm));
        return P2P_C_ERR_ARG;
    }

    const uint8_t *k_forward = okm;                       /* lo -> hi */
    const uint8_t *k_reverse = okm + P2P_KEY_LEN;         /* hi -> lo */
    const uint8_t *np        = okm + P2P_KEY_LEN * 2;

    const uint8_t *k_send, *k_recv;
    if (memcmp(local_id, peer_id, P2P_C_ID_LEN) < 0) {
        k_send = k_forward; k_recv = k_reverse;   /* local 是 lo */
    } else {
        k_send = k_reverse; k_recv = k_forward;   /* local 是 hi */
    }

    int rc = p2p_tunnel_init(t, k_send, k_recv, np);

    /* 擦除栈上的临时密钥材料 */
    memset(ikm, 0, sizeof(ikm));
    memset(okm, 0, sizeof(okm));
    memset(info, 0, sizeof(info));
    return rc;
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
