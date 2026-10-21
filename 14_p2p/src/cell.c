/*
 * DAYANJING v4 — 14_p2p/src/cell.c
 *
 * 定长信元层。设计说明见 include/p2p_cell.h。
 * 密码学原语复用 00_crypto 的 AES-128-GCM，不重新实现任何算法。
 */

#include "p2p_cell.h"

#include "crypto_gcm.h"

#include <stdio.h>
#include <string.h>

const char *p2p_cell_errstr(int e) {
    switch (e) {
        case P2P_CELL_OK:        return "ok";
        case P2P_CELL_ERR_ARG:   return "invalid argument";
        case P2P_CELL_ERR_LEN:   return "payload too large / buffer too small";
        case P2P_CELL_ERR_AUTH:  return "cell auth failed (tampered / wrong key)";
        case P2P_CELL_ERR_FMT:   return "malformed cell";
        case P2P_CELL_ERR_REPLAY:return "replay / out-of-order cell";
        default:                 return "unknown";
    }
}

int p2p_cell_init(p2p_cell_ctx_t *c,
                  const uint8_t k_send[P2P_CELL_KEY_LEN],
                  const uint8_t k_recv[P2P_CELL_KEY_LEN],
                  const uint8_t pfx[P2P_CELL_PFX_LEN]) {
    if (!c || !k_send || !k_recv || !pfx) return P2P_CELL_ERR_ARG;
    if (memcmp(k_send, k_recv, P2P_CELL_KEY_LEN) == 0) return P2P_CELL_ERR_ARG;
    memcpy(c->k_send, k_send, P2P_CELL_KEY_LEN);
    memcpy(c->k_recv, k_recv, P2P_CELL_KEY_LEN);
    memcpy(c->pfx, pfx, P2P_CELL_PFX_LEN);
    c->send_counter = 0;
    c->recv_counter = 0;
    c->recv_init = 0;
    return P2P_CELL_OK;
}

void p2p_cell_wipe(p2p_cell_ctx_t *c) {
    if (!c) return;
    memset(c, 0, sizeof *c);
}

/* IV = AAD = pfx(8) || counter(4 LE) —— 信元绑定到自己的位置 */
static void make_iv(const uint8_t pfx[P2P_CELL_PFX_LEN], uint32_t counter,
                    uint8_t iv[12]) {
    memcpy(iv, pfx, P2P_CELL_PFX_LEN);
    iv[8]  = (uint8_t)(counter & 0xff);
    iv[9]  = (uint8_t)((counter >> 8) & 0xff);
    iv[10] = (uint8_t)((counter >> 16) & 0xff);
    iv[11] = (uint8_t)((counter >> 24) & 0xff);
}

static void random_bytes(uint8_t *b, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(b, 1, n, f) == n) { fclose(f); return; }
        fclose(f);
    }
    memset(b, 0, n);
}

/* 明文 = cmd || len(2 LE) || data || pad(随机) */
static size_t build_pt(uint8_t cmd, const uint8_t *data, size_t len,
                       uint8_t pt[P2P_CELL_PT_LEN]) {
    pt[0] = cmd;
    pt[1] = (uint8_t)(len & 0xff);
    pt[2] = (uint8_t)((len >> 8) & 0xff);
    if (len) memcpy(pt + P2P_CELL_HDR_LEN, data, len);
    size_t pad = P2P_CELL_PT_LEN - P2P_CELL_HDR_LEN - len;
    if (pad) random_bytes(pt + P2P_CELL_HDR_LEN + len, pad);
    return P2P_CELL_PT_LEN;
}

int p2p_cell_pack(p2p_cell_ctx_t *c, uint8_t cmd,
                  const uint8_t *data, size_t len,
                  uint8_t out[P2P_CELL_WIRE]) {
    if (!c || !out) return P2P_CELL_ERR_ARG;
    if (len > 0 && !data) return P2P_CELL_ERR_ARG;
    if (len > P2P_CELL_DATA_MAX) return P2P_CELL_ERR_LEN;

    uint8_t pt[P2P_CELL_PT_LEN];
    build_pt(cmd, data, len, pt);

    uint8_t iv[12];
    make_iv(c->pfx, c->send_counter, iv);

    uint8_t tag[P2P_CELL_TAG_LEN];
    /* 输出到 out 的前 496 字节，tag 写入后 16 字节 —— 合计恒 512 */
    if (gcm_seal(c->k_send, iv, iv, 12, pt, P2P_CELL_PT_LEN, out, tag) != GCM_OK)
        return P2P_CELL_ERR_ARG;
    memcpy(out + P2P_CELL_PT_LEN, tag, P2P_CELL_TAG_LEN);

    c->send_counter++;
    memset(pt, 0, sizeof pt);
    return P2P_CELL_OK;
}

int p2p_cell_unpack(p2p_cell_ctx_t *c, const uint8_t in[P2P_CELL_WIRE],
                    uint8_t *cmd, uint8_t *data, size_t cap, size_t *len) {
    if (!c || !in || !len) return P2P_CELL_ERR_ARG;

    uint8_t iv[12];
    make_iv(c->pfx, c->recv_counter, iv);

    uint8_t pt[P2P_CELL_PT_LEN];
    if (gcm_open(c->k_recv, iv, iv, 12,
                 in, P2P_CELL_PT_LEN, in + P2P_CELL_PT_LEN, pt) != GCM_OK) {
        /*
         * 关键：验签失败也必须推进 recv_counter。
         *
         * IV = pfx || recv_counter 是**位置相关**的：计数器代表"我在流
         * 上的第几个信元"。线上恒 512 字节，吃掉一个坏信元后流位置仍然
         * 前进了 1。若此处不推进，对端下一个信元用 IV(N+1) 封装、本端
         * 仍按 IV(N) 解 —— 之后**每一个**都失败，链路被单个坏字节永久
         * 打死且不可恢复。这正是注入攻击的致命放大点。
         *
         * 推进后：单个被篡改的信元只损失它自己，下一个信元立刻恢复正常。
         *
         * 安全性不受影响：重放仍然失败（旧信元的 IV 是当前位置之前的值，
         * 位置已前进即不匹配）；乱序同样失败。
         */
        c->recv_counter++;
        return P2P_CELL_ERR_AUTH;
    }

    size_t dlen = (size_t)pt[1] | ((size_t)pt[2] << 8);
    if (dlen > P2P_CELL_DATA_MAX) return P2P_CELL_ERR_FMT;

    /*
     * 重放防护来自 IV 构造本身：IV = pfx || recv_counter，
     * 收到一个信元后计数器即 +1。攻击者重放旧信元时计数器已前进，
     * IV 对不上 -> 上面 gcm_open 返回 AUTH。
     * 代价是信元必须按序到达（流式语义），乱序同样表现为 AUTH。
     */
    c->recv_init = 1;
    c->recv_counter++;

    if (cmd) *cmd = pt[0];
    *len = dlen;
    if (!data) return P2P_CELL_OK;
    if (cap < dlen) { memset(pt, 0, sizeof pt); return P2P_CELL_ERR_LEN; }
    if (dlen) memcpy(data, pt + P2P_CELL_HDR_LEN, dlen);
    memset(pt, 0, sizeof pt);
    return P2P_CELL_OK;
}

int p2p_cell_pack_cover(p2p_cell_ctx_t *c, uint8_t out[P2P_CELL_WIRE]) {
    return p2p_cell_pack(c, P2P_CELL_CMD_PAD, NULL, 0, out);
}

int p2p_cell_fragment(size_t len, size_t *n_cells) {
    if (!n_cells) return P2P_CELL_ERR_ARG;
    size_t n = len / P2P_CELL_DATA_MAX;
    if (len % P2P_CELL_DATA_MAX) n++;
    if (n == 0) n = 1;              /* 空消息也要一个信元 */
    *n_cells = n;
    return P2P_CELL_OK;
}

int p2p_cell_pack_stream(p2p_cell_ctx_t *c,
                         const uint8_t *data, size_t len,
                         uint8_t *out, size_t cap, size_t *out_cells) {
    if (!c || !out_cells) return P2P_CELL_ERR_ARG;
    if (len > 0 && !data) return P2P_CELL_ERR_ARG;

    size_t n = 0;
    int rc = p2p_cell_fragment(len, &n);
    if (rc != P2P_CELL_OK) return rc;
    if (cap < n * P2P_CELL_WIRE) return P2P_CELL_ERR_LEN;

    size_t off = 0;
    for (size_t i = 0; i < n; i++) {
        size_t chunk = len - off;
        if (chunk > P2P_CELL_DATA_MAX) chunk = P2P_CELL_DATA_MAX;
        uint8_t cmd = (i + 1 == n) ? P2P_CELL_CMD_FIN : P2P_CELL_CMD_DATA;
        rc = p2p_cell_pack(c, cmd, data ? data + off : NULL, chunk,
                           out + i * P2P_CELL_WIRE);
        if (rc != P2P_CELL_OK) return rc;
        off += chunk;
    }
    *out_cells = n;
    return P2P_CELL_OK;
}

int p2p_cell_unpack_stream(p2p_cell_ctx_t *c,
                           const uint8_t *in, size_t n_cells,
                           uint8_t *data, size_t cap, size_t *len) {
    if (!c || !len) return P2P_CELL_ERR_ARG;
    if (n_cells > 0 && !in) return P2P_CELL_ERR_ARG;

    size_t off = 0;
    *len = 0;
    for (size_t i = 0; i < n_cells; i++) {
        uint8_t cmd = 0;
        size_t dlen = 0;
        int rc = p2p_cell_unpack(c, in + i * P2P_CELL_WIRE,
                                 &cmd, data ? data + off : NULL,
                                 cap - off, &dlen);
        if (rc != P2P_CELL_OK) return rc;
        if (cmd == P2P_CELL_CMD_PAD) continue;   /* 覆盖信元不携带数据 */
        off += dlen;
        if (cmd == P2P_CELL_CMD_FIN) break;
    }
    *len = off;
    return P2P_CELL_OK;
}

/* ---- 调度：xorshift32 ---- */
void p2p_cell_sched_seed(p2p_cell_sched_t *sc, uint32_t seed) {
    if (!sc) return;
    sc->s = seed ? seed : 0x9e3779b9u;
}

static uint32_t xorshift32(p2p_cell_sched_t *sc) {
    uint32_t x = sc->s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    sc->s = x;
    return x;
}

uint32_t p2p_cell_next_delay_ms(p2p_cell_sched_t *sc,
                                uint32_t min_ms, uint32_t max_ms) {
    if (!sc) return 0;
    if (max_ms <= min_ms) return min_ms;
    uint32_t span = max_ms - min_ms + 1;
    return min_ms + (xorshift32(sc) % span);
}

int p2p_cell_cover_due(p2p_cell_sched_t *sc, uint32_t idle_ms,
                       uint32_t rate_per_min, uint32_t *out_delay) {
    if (!sc) return 0;
    if (rate_per_min == 0) return 0;
    /* 期望间隔 = 60000 / rate；空闲超过期望间隔后按概率发一个含随机因子 */
    uint32_t expected = 60000u / rate_per_min;
    if (expected == 0) expected = 1;
    if (idle_ms < expected) return 0;
    uint32_t roll = xorshift32(sc) % 100u;
    /* 空闲越久发覆盖信元的概率越高，但永不达到 100% —— 保持不可预测 */
    uint32_t excess = idle_ms / expected;
    uint32_t prob = excess > 4 ? 80u : 20u * (excess > 0 ? excess : 1);
    if (out_delay) *out_delay = p2p_cell_next_delay_ms(sc, 1, expected / 2 + 1);
    return roll < prob ? 1 : 0;
}
