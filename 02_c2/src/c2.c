#include "c2.h"
#include "proto.h"
#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

const char *c2_strerror(c2_err_t e) {
    switch (e) {
        case C2_OK:            return "ok";
        case C2_ERR_HANDSHAKE: return "handshake failed";
        case C2_ERR_AUTH:      return "auth failed";
        case C2_ERR_ENCRYPT:   return "encrypt failed";
        case C2_ERR_DECRYPT:   return "decrypt failed";
        case C2_ERR_TIMEOUT:   return "timeout";
        case C2_ERR_TRANSPORT: return "transport error";
        case C2_ERR_NOMEM:     return "no memory";
        case C2_ERR_PROTO:     return "protocol error";
        default:               return "unknown";
    }
}

c2_err_t c2_session_init(struct c2_session *s, struct c2_transport *t) {
    if (!s || !t) return C2_ERR;
    memset(s, 0, sizeof(*s));
    s->state = C2_STATE_IDLE;
    s->transport = t;
    s->nonce_send = 0;
    s->nonce_recv = 0;
    crypto_rng((uint8_t *)&s->id, sizeof(s->id));
    return C2_OK;
}

void c2_session_free(struct c2_session *s) {
    if (!s) return;
    crypto_wipe(s->key_send, 32);
    crypto_wipe(s->key_recv, 32);
    crypto_wipe(s->token, C2_SESSION_TOKEN_LEN);
    memset(s, 0, sizeof(*s));
}

/*
 * 用 proto_seal 加密一帧并发送。
 * 方向：agent->server 用 ROLE_CLIENT 编码，server->agent 用 ROLE_SERVER 编码。
 */
c2_err_t c2_seal_and_send(struct c2_session *s,
                                 uint8_t msg_type,
                                 const uint8_t *data, size_t len,
                                 uint8_t role) {
    (void)role;  /* role 决定 AAD 编码方向，proto_seal 内部处理 */
    if (!s || !s->transport || !s->transport->send)
        return C2_ERR_TRANSPORT;

    /* 构造 nonce：8 字节随机前缀 + 4 字节计数器 */
    uint8_t nonce_prefix[8];
    crypto_rng(nonce_prefix, 8);
    uint8_t nonce_buf[12];
    memcpy(nonce_buf, nonce_prefix, 8);
    uint32_t ctr = (uint32_t)(++s->nonce_send);
    memcpy(nonce_buf + 8, &ctr, 4);

    /* seq = counter（用于重放窗口） */
    uint64_t seq = s->nonce_send;

    /* 加密 */
    size_t out_cap = len + 128;  /* proto_seal 会加头部和 tag，留足余量 */
    uint8_t *out = malloc(out_cap);
    if (!out) return C2_ERR_NOMEM;

    size_t out_len = 0;
    proto_err_t pe = proto_seal(s->key_send, nonce_prefix, &ctr, nonce_buf,
                                seq, (uint32_t)msg_type,
                                data, (uint32_t)len,
                                out, out_cap, &out_len);
    if (pe != PROTO_OK) {
        free(out);
        return C2_ERR_ENCRYPT;
    }

    c2_err_t e = s->transport->send(s->transport->ctx, out, out_len);
    free(out);
    return e;
}

/*
 * 接收一帧并用 proto_open 验签解密。
 * role 是接收方角色（用于 AAD 编码）。
 */
c2_err_t c2_recv_and_open_internal(struct c2_session *s,
                                          uint8_t *msg_type_out,
                                          uint8_t *buf, size_t *len,
                                          uint8_t role) {
    if (!s || !s->transport || !s->transport->recv)
        return C2_ERR_TRANSPORT;

    /* 先探知长度：收一个足够大的缓冲 */
    size_t got = *len + 4096;
    uint8_t *wire = malloc(got);
    if (!wire) return C2_ERR_NOMEM;

    c2_err_t e = s->transport->recv(s->transport->ctx, wire, &got,
                                    C2_TIMEOUT_SEC * 1000);
    if (e != C2_OK) { free(wire); return e; }

    uint64_t seq = 0;
    uint32_t mtype = 0;
    size_t payload_len = 0;

    proto_err_t pe = proto_open(s->key_recv, role, wire, got,
                                &seq, &mtype,
                                buf, *len, &payload_len);
    free(wire);

    if (pe != PROTO_OK) {
        if (pe == PROTO_TAG_FAIL) return C2_ERR_DECRYPT;
        if (pe == PROTO_SEQ_REPLAY) return C2_ERR_PROTO;
        return C2_ERR_PROTO;
    }

    /* 更新接收计数器（严格递增） */
    if (seq > s->nonce_recv) s->nonce_recv = seq;

    *len = payload_len;
    *msg_type_out = (uint8_t)mtype;
    return C2_OK;
}

c2_err_t c2_send(struct c2_session *s, uint8_t msg_type,
                 const uint8_t *data, size_t len) {
    if (!s || s->state != C2_STATE_ACTIVE) return C2_ERR_PROTO;
    if (len > C2_MAX_PAYLOAD) return C2_ERR_NOMEM;
    return c2_seal_and_send(s, msg_type, data, len, PROTO_ROLE_CLIENT);
}

c2_err_t c2_recv(struct c2_session *s, uint8_t *msg_type_out,
                 uint8_t *buf, size_t *len) {
    if (!s || s->state != C2_STATE_ACTIVE) return C2_ERR_PROTO;
    return c2_recv_and_open_internal(s, msg_type_out, buf, len, PROTO_ROLE_SERVER);
}

c2_err_t c2_heartbeat(struct c2_session *s) {
    if (!s || s->state != C2_STATE_ACTIVE) return C2_ERR_PROTO;
    uint8_t hb[8];
    crypto_rng(hb, 8);
    c2_err_t e = c2_seal_and_send(s, C2_MSG_HEARTBEAT, hb, 8, PROTO_ROLE_CLIENT);
    if (e == C2_OK) s->last_heartbeat = (uint64_t)time(NULL);
    return e;
}

c2_err_t c2_poll(struct c2_session *s, int timeout_ms) {
    (void)timeout_ms;
    if (!s) return C2_ERR;
    if (s->state != C2_STATE_ACTIVE) return C2_ERR_PROTO;
    uint64_t now = (uint64_t)time(NULL);
    if (now - s->last_heartbeat > C2_TIMEOUT_SEC) return C2_ERR_TIMEOUT;
    return C2_OK;
}
