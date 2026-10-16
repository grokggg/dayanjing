#include "c2.h"
#include "proto.h"
#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Server 侧单 Agent 会话（测试用）。生产环境应使用哈希表管理多 Agent。
 */

struct c2_server_agent {
    uint64_t  agent_id;
    uint8_t   send_key[32];   /* 发给 agent（agent 用 key_recv 解） */
    uint8_t   recv_key[32];   /* 收 agent（agent 用 key_send 封） */
    uint8_t   token[32];
    uint8_t   challenge[64];  /* 本次握手发出的 challenge，待比对 HMAC */
    uint64_t  last_seen;
    bool      authenticated;
};

static struct c2_server_agent g_agent;

c2_err_t c2_server_accept(struct c2_session *s, const uint8_t *auth_key) {
    if (!s || !auth_key) return C2_ERR;
    /* key_recv 暂存 PSK，握手完成后替换为派生密钥 */
    memcpy(s->key_recv, auth_key, 32);
    s->state = C2_STATE_AUTH;
    s->last_heartbeat = (uint64_t)time(NULL);
    return C2_OK;
}

static c2_err_t handle_register(struct c2_session *s,
                                const uint8_t *reg, size_t reg_len) {
    if (reg_len != 24) return C2_ERR_PROTO;

    uint64_t agent_id = 0;
    memcpy(&agent_id, reg, 8);
    const uint8_t *nonce_prefix = reg + 16;

    g_agent.agent_id = agent_id;
    g_agent.authenticated = false;
    g_agent.last_seen = (uint64_t)time(NULL);

    /* 派生密钥（与 Agent 完全一致，方向互换） */
    uint8_t ikm[40];
    memcpy(ikm, s->key_recv, 32);   /* 此时存放 PSK */
    memcpy(ikm + 32, nonce_prefix, 8);

    crypto_kdf_derive(g_agent.send_key, 32, ikm, sizeof(ikm),
                      (const uint8_t *)"c2-recv-key", 12);
    crypto_kdf_derive(g_agent.recv_key, 32, ikm, sizeof(ikm),
                      (const uint8_t *)"c2-send-key", 12);
    crypto_kdf_derive(g_agent.token, 32, ikm, sizeof(ikm),
                      (const uint8_t *)"c2-token", 8);
    crypto_wipe(ikm, sizeof(ikm));

    /* 生成 challenge 并保存，待 AUTH 阶段比对 HMAC */
    uint8_t challenge[64];
    crypto_rng(challenge, sizeof(challenge));
    memcpy(g_agent.challenge, challenge, sizeof(challenge));

    s->state = C2_STATE_HANDSHAKE;
    return c2_seal_and_send(s, C2_MSG_TASK, challenge, sizeof(challenge),
                            PROTO_ROLE_SERVER);
}

static c2_err_t handle_auth_response(struct c2_session *s,
                                     const uint8_t *response, size_t rlen) {
    if (rlen != 32) return C2_ERR_PROTO;

    /* crypto_hmac_verify 内部常量时间比对，不泄漏时序 */
    crypto_err_t rc = crypto_hmac_verify(response, g_agent.send_key, 32,
                                         g_agent.challenge, 64);
    if (rc != CRYPTO_OK) return C2_ERR_AUTH;

    /* 认证通过，切换 session 密钥 */
    memcpy(s->key_send, g_agent.send_key, 32);
    memcpy(s->key_recv, g_agent.recv_key, 32);

    g_agent.authenticated = true;
    s->state = C2_STATE_ACTIVE;

    const char *ok = "OK";
    return c2_seal_and_send(s, C2_MSG_CONFIRM, (const uint8_t *)ok, 2,
                            PROTO_ROLE_SERVER);
}

c2_err_t c2_server_loop(struct c2_session *s, c2_task_cb on_task) {
    if (!s || !on_task) return C2_ERR;

    uint8_t buf[C2_MAX_PAYLOAD];
    size_t len = sizeof(buf);
    uint8_t mtype = 0;

    c2_err_t e = c2_recv(s, &mtype, buf, &len);
    if (e != C2_OK) return e;

    switch (mtype) {
        case C2_MSG_REGISTER:
            return handle_register(s, buf, len);

        case C2_MSG_AUTH:
            return handle_auth_response(s, buf, len);

        case C2_MSG_RESULT: {
            if (!g_agent.authenticated) return C2_ERR_AUTH;
            g_agent.last_seen = (uint64_t)time(NULL);
            uint8_t *resp = NULL;
            size_t resp_len = 0;
            on_task(s, buf, len, &resp, &resp_len);
            if (resp && resp_len > 0) {
                c2_err_t se = c2_send(s, C2_MSG_ACK, resp, resp_len);
                free(resp);
                return se;
            }
            return C2_OK;
        }

        case C2_MSG_HEARTBEAT:
            if (!g_agent.authenticated) return C2_ERR_AUTH;
            g_agent.last_seen = (uint64_t)time(NULL);
            return c2_send(s, C2_MSG_ACK, (const uint8_t *)"pong", 4);

        default:
            return C2_ERR_PROTO;
    }
}

c2_err_t c2_server_dispatch(struct c2_session *s,
                            const uint8_t *task, size_t task_len) {
    if (!s || s->state != C2_STATE_ACTIVE) return C2_ERR_PROTO;
    if (!g_agent.authenticated) return C2_ERR_AUTH;
    return c2_send(s, C2_MSG_TASK, task, task_len);
}
