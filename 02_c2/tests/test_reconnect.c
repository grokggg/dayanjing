#include "c2.h"
#include "crypto.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 简单 mock：send 计数，recv 返回超时（模拟对端不响应） */
struct mock_ctx {
    int send_calls;
    int fail_next;
};

static c2_err_t m_connect(void *ctx, const char *ep) {
    (void)ctx; (void)ep; return C2_OK;
}
static c2_err_t m_close(void *ctx) { (void)ctx; return C2_OK; }

static c2_err_t m_send(void *ctx, const uint8_t *d, size_t l) {
    struct mock_ctx *m = (struct mock_ctx *)ctx;
    m->send_calls++;
    if (m->fail_next > 0) { m->fail_next--; return C2_ERR_TRANSPORT; }
    (void)d; (void)l;
    return C2_OK;
}

static c2_err_t m_recv(void *ctx, uint8_t *b, size_t *l, int t) {
    (void)ctx; (void)b; (void)t;
    *l = 0;
    return C2_ERR_TIMEOUT;  /* 对端无响应 */
}

int main(void) {
    printf("[*] test_reconnect\n");

    struct mock_ctx mc;
    memset(&mc, 0, sizeof(mc));

    struct c2_transport ta;
    ta.name = "mock"; ta.ctx = &mc;
    ta.connect = m_connect; ta.send = m_send; ta.recv = m_recv; ta.close = m_close;

    struct c2_session agent;
    c2_session_init(&agent, &ta);

    /* 模拟已建立的会话 */
    uint8_t psk[32]; crypto_rng(psk, 32);
    memcpy(agent.key_send, psk, 32);
    memcpy(agent.key_recv, psk, 32);
    crypto_rng(agent.token, C2_SESSION_TOKEN_LEN);
    agent.nonce_send = 100;
    agent.nonce_recv = 100;
    agent.state = C2_STATE_ACTIVE;
    agent.last_heartbeat = 1000;

    /* 模拟断线 */
    mc.fail_next = 1;
    c2_err_t r = c2_send(&agent, C2_MSG_TASK, (const uint8_t *)"x", 1);
    assert(r == C2_ERR_TRANSPORT);
    printf("    simulated disconnect\n");

    /* 重连：token 恢复路径
       由于 mock recv 永远超时，重连的 ACK 收不到，应退回 handshake
       但 handshake 也会因 recv 超时失败，最终返回错误 */
    mc.fail_next = 0;
    r = c2_reconnect(&agent, "127.0.0.1:8443");
    /* 无论成功或失败，状态应合法（不崩溃） */
    assert(r == C2_OK || r == C2_ERR_HANDSHAKE || r == C2_ERR_TRANSPORT);
    printf("    reconnect returned: %s\n", c2_strerror(r));

    /* 验证 session 结构体完整性未损坏 */
    assert(agent.transport == &ta);
    assert(agent.user_ctx == NULL);

    /* 重置状态后发心跳应成功（send 能成功） */
    agent.state = C2_STATE_ACTIVE;
    agent.nonce_send = 0;
    agent.nonce_recv = 0;
    assert(c2_heartbeat(&agent) == C2_OK);
    assert(mc.send_calls > 0);
    printf("    heartbeat after reset: %d sends\n", mc.send_calls);

    /* token 不应被意外清零 */
    int tok_zero = 1;
    for (int i = 0; i < C2_SESSION_TOKEN_LEN; i++)
        if (agent.token[i]) tok_zero = 0;
    assert(!tok_zero);

    c2_session_free(&agent);
    printf("[+] reconnect OK\n");
    return 0;
}
