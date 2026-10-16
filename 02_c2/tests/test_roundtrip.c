#include "c2.h"
#include "c2_http.h"
#include "crypto.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ==================== 内存管道传输（测试用）==================== */
struct pipe_ctx {
    uint8_t a2s[65536];   /* agent -> server */
    uint8_t s2a[65536];   /* server -> agent */
    size_t  a2s_len, s2a_len;
    size_t  a2s_rd, s2a_rd;
    int     fail_next;    /* 模拟断线 */
    int     calls;
};

static c2_err_t p_connect(void *ctx, const char *ep) {
    (void)ctx; (void)ep;
    return C2_OK;
}

static c2_err_t p_close(void *ctx) {
    (void)ctx;
    return C2_OK;
}

/* Agent 视角的 send：写入 a2s 管道 */
static c2_err_t a_send(void *ctx, const uint8_t *d, size_t l) {
    struct pipe_ctx *p = (struct pipe_ctx *)ctx;
    p->calls++;
    if (p->fail_next > 0) { p->fail_next--; return C2_ERR_TRANSPORT; }
    if (l > sizeof(p->a2s)) return C2_ERR_NOMEM;
    memcpy(p->a2s, d, l); p->a2s_len = l; p->a2s_rd = 0;
    return C2_OK;
}

/* Agent 视角的 recv：从 s2a 管道读 */
static c2_err_t a_recv(void *ctx, uint8_t *b, size_t *l, int to) {
    (void)to;
    struct pipe_ctx *p = (struct pipe_ctx *)ctx;
    if (p->s2a_rd >= p->s2a_len) return C2_ERR_TIMEOUT;
    size_t n = p->s2a_len - p->s2a_rd;
    if (n > *l) n = *l;
    memcpy(b, p->s2a + p->s2a_rd, n); p->s2a_rd += n; *l = n;
    return C2_OK;
}

/* Server 视角的 send：写入 s2a 管道 */
static c2_err_t s_send(void *ctx, const uint8_t *d, size_t l) {
    struct pipe_ctx *p = (struct pipe_ctx *)ctx;
    if (l > sizeof(p->s2a)) return C2_ERR_NOMEM;
    memcpy(p->s2a, d, l); p->s2a_len = l; p->s2a_rd = 0;
    return C2_OK;
}

/* Server 视角的 recv：从 a2s 管道读 */
static c2_err_t s_recv(void *ctx, uint8_t *b, size_t *l, int to) {
    (void)to;
    struct pipe_ctx *p = (struct pipe_ctx *)ctx;
    if (p->a2s_rd >= p->a2s_len) return C2_ERR_TIMEOUT;
    size_t n = p->a2s_len - p->a2s_rd;
    if (n > *l) n = *l;
    memcpy(b, p->a2s + p->a2s_rd, n); p->a2s_rd += n; *l = n;
    return C2_OK;
}

static void make_transports(struct pipe_ctx *pc,
                            struct c2_transport *ta,
                            struct c2_transport *ts) {
    memset(pc, 0, sizeof(*pc));
    ta->name = "pipe-a"; ta->ctx = pc;
    ta->connect = p_connect; ta->send = a_send; ta->recv = a_recv; ta->close = p_close;
    ts->name = "pipe-s"; ts->ctx = pc;
    ts->connect = p_connect; ts->send = s_send; ts->recv = s_recv; ts->close = p_close;
}

/* 共享 PSK */
static uint8_t g_shared_psk[32];

/* 模拟完整握手：双方独立派生相同密钥 */
static void do_handshake(struct c2_session *agent, struct c2_session *server) {
    uint8_t nonce_prefix[8];
    crypto_rng(nonce_prefix, 8);

    uint8_t ikm[40];
    memcpy(ikm, g_shared_psk, 32);
    memcpy(ikm + 32, nonce_prefix, 8);

    /* Agent 密钥 */
    crypto_kdf_derive(agent->key_send, 32, ikm, sizeof(ikm),
                      (const uint8_t *)"c2-send-key", 12);
    crypto_kdf_derive(agent->key_recv, 32, ikm, sizeof(ikm),
                      (const uint8_t *)"c2-recv-key", 12);
    crypto_kdf_derive(agent->token, 32, ikm, sizeof(ikm),
                      (const uint8_t *)"c2-token", 8);

    /* Server 密钥（方向互换） */
    crypto_kdf_derive(server->key_send, 32, ikm, sizeof(ikm),
                      (const uint8_t *)"c2-recv-key", 12);
    crypto_kdf_derive(server->key_recv, 32, ikm, sizeof(ikm),
                      (const uint8_t *)"c2-send-key", 12);
    crypto_kdf_derive(server->token, 32, ikm, sizeof(ikm),
                      (const uint8_t *)"c2-token", 8);

    agent->state = C2_STATE_ACTIVE;
    server->state = C2_STATE_ACTIVE;
    crypto_wipe(ikm, sizeof(ikm));
    crypto_wipe(nonce_prefix, 8);
}

int main(void) {
    printf("[*] test_roundtrip\n");
    crypto_rng(g_shared_psk, 32);

    struct pipe_ctx pc;
    struct c2_transport ta, ts;
    make_transports(&pc, &ta, &ts);

    struct c2_session agent, server;
    assert(c2_session_init(&agent, &ta) == C2_OK);
    assert(c2_session_init(&server, &ts) == C2_OK);

    do_handshake(&agent, &server);

    /* === Agent -> Server 发送任务 === */
    const char *task = "ls -la /etc";
    assert(c2_send(&agent, C2_MSG_TASK,
                   (const uint8_t *)task, strlen(task)) == C2_OK);

    uint8_t buf[4096];
    size_t blen = sizeof(buf);
    uint8_t mtype = 0;
    assert(c2_recv(&server, &mtype, buf, &blen) == C2_OK);
    assert(mtype == C2_MSG_TASK);
    assert(blen == strlen(task));
    assert(memcmp(buf, task, strlen(task)) == 0);
    printf("    agent->server: [%s]\n", task);

    /* === Server -> Agent 回传结果 === */
    const char *resp = "total 128\ndrwxr-xr-x ...";
    assert(c2_send(&server, C2_MSG_RESULT,
                   (const uint8_t *)resp, strlen(resp)) == C2_OK);

    blen = sizeof(buf);
    assert(c2_recv(&agent, &mtype, buf, &blen) == C2_OK);
    assert(mtype == C2_MSG_RESULT);
    assert(blen == strlen(resp));
    assert(memcmp(buf, resp, strlen(resp)) == 0);
    printf("    server->agent: [%s]\n", resp);

    /* === 密钥非全零校验 === */
    int allzero = 1;
    for (int i = 0; i < 32; i++)
        if (agent.key_send[i] || agent.key_recv[i]) allzero = 0;
    assert(!allzero);
    int tokzero = 1;
    for (int i = 0; i < 32; i++) if (agent.token[i]) tokzero = 0;
    assert(!tokzero);

    /* === 加密语义：密文不应等于明文 === */
    const uint8_t secret[] = "SECRET_PAYLOAD_12345";
    assert(c2_send(&agent, C2_MSG_TASK, secret, sizeof(secret) - 1) == C2_OK);
    blen = sizeof(buf);
    assert(c2_recv(&server, &mtype, buf, &blen) == C2_OK);
    /* 管道里装的是密文，不应直接等于明文（说明加密生效） */
    assert(blen == sizeof(secret) - 1);
    assert(memcmp(pc.a2s, secret, sizeof(secret) - 1) != 0);

    c2_session_free(&agent);
    c2_session_free(&server);
    printf("[+] roundtrip OK\n");
    return 0;
}
