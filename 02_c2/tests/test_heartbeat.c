#include "c2.h"
#include "crypto.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* 复用 pipe mock */
struct pipe_ctx {
    uint8_t a2s[65536], s2a[65536];
    size_t  a2s_len, s2a_len, a2s_rd, s2a_rd;
    int     fail_next;
};

static c2_err_t p_connect(void *c, const char *e){ (void)c;(void)e; return C2_OK; }
static c2_err_t p_close(void *c){ (void)c; return C2_OK; }
static c2_err_t a_send(void *c, const uint8_t *d, size_t l){
    struct pipe_ctx *p=(struct pipe_ctx*)c;
    if(p->fail_next>0){p->fail_next--;return C2_ERR_TRANSPORT;}
    if(l>sizeof(p->a2s))return C2_ERR_NOMEM;
    memcpy(p->a2s,d,l);p->a2s_len=l;p->a2s_rd=0;return C2_OK; }
static c2_err_t s_send(void *c, const uint8_t *d, size_t l){
    struct pipe_ctx *p=(struct pipe_ctx*)c;
    if(l>sizeof(p->s2a))return C2_ERR_NOMEM;
    memcpy(p->s2a,d,l);p->s2a_len=l;p->s2a_rd=0;return C2_OK; }
static c2_err_t a_recv(void *c, uint8_t *b, size_t *l, int t){
    (void)t; struct pipe_ctx *p=(struct pipe_ctx*)c;
    if(p->s2a_rd>=p->s2a_len)return C2_ERR_TIMEOUT;
    size_t n=p->s2a_len-p->s2a_rd; if(n>*l)n=*l;
    memcpy(b,p->s2a+p->s2a_rd,n); p->s2a_rd+=n; *l=n; return C2_OK; }
static c2_err_t s_recv(void *c, uint8_t *b, size_t *l, int t){
    (void)t; struct pipe_ctx *p=(struct pipe_ctx*)c;
    if(p->a2s_rd>=p->a2s_len)return C2_ERR_TIMEOUT;
    size_t n=p->a2s_len-p->a2s_rd; if(n>*l)n=*l;
    memcpy(b,p->a2s+p->a2s_rd,n); p->a2s_rd+=n; *l=n; return C2_OK; }

static void setup(struct pipe_ctx *pc, struct c2_transport *ta,
                  struct c2_transport *ts, uint8_t psk[32]) {
    memset(pc, 0, sizeof(*pc));
    ta->name="a"; ta->ctx=pc; ta->connect=p_connect; ta->send=a_send; ta->recv=a_recv; ta->close=p_close;
    ts->name="s"; ts->ctx=pc; ts->connect=p_connect; ts->send=s_send; ts->recv=s_recv; ts->close=p_close;
    crypto_rng(psk, 32);
}

static void activate(struct c2_session *a, struct c2_session *s, uint8_t psk[32]) {
    uint8_t np[8]; crypto_rng(np, 8);
    uint8_t ikm[40]; memcpy(ikm, psk, 32); memcpy(ikm+32, np, 8);
    crypto_kdf_derive(a->key_send,32,ikm,40,(const uint8_t*)"c2-send-key",12);
    crypto_kdf_derive(a->key_recv,32,ikm,40,(const uint8_t*)"c2-recv-key",12);
    crypto_kdf_derive(s->key_send,32,ikm,40,(const uint8_t*)"c2-recv-key",12);
    crypto_kdf_derive(s->key_recv,32,ikm,40,(const uint8_t*)"c2-send-key",12);
    a->state = s->state = C2_STATE_ACTIVE;
    crypto_wipe(ikm, sizeof(ikm)); crypto_wipe(np, 8);
}

int main(void) {
    printf("[*] test_heartbeat\n");
    struct pipe_ctx pc;
    struct c2_transport ta, ts;
    uint8_t psk[32];
    setup(&pc, &ta, &ts, psk);

    struct c2_session agent, server;
    c2_session_init(&agent, &ta);
    c2_session_init(&server, &ts);
    activate(&agent, &server, psk);

    /* 发送心跳 */
    assert(c2_heartbeat(&agent) == C2_OK);
    assert(agent.last_heartbeat > 0);
    printf("    heartbeat sent, last=%llu\n", (unsigned long long)agent.last_heartbeat);

    /* Server 接收心跳帧 */
    uint8_t buf[1024]; size_t blen = sizeof(buf); uint8_t mt = 0;
    assert(c2_recv(&server, &mt, buf, &blen) == C2_OK);
    assert(mt == C2_MSG_HEARTBEAT);
    printf("    server received heartbeat frame (%zu bytes)\n", blen);

    /* Server 回 ACK */
    assert(c2_send(&server, C2_MSG_ACK, (const uint8_t *)"pong", 4) == C2_OK);

    /* Agent 收到 ACK */
    blen = sizeof(buf);
    assert(c2_recv(&agent, &mt, buf, &blen) == C2_OK);
    assert(mt == C2_MSG_ACK);
    assert(blen == 4 && memcmp(buf, "pong", 4) == 0);
    printf("    agent received ACK: pong\n");

    /* poll：心跳新鲜，不应超时 */
    assert(c2_poll(&agent, 100) == C2_OK);

    /* 模拟心跳过期 */
    agent.last_heartbeat = (uint64_t)time(NULL) - C2_TIMEOUT_SEC - 5;
    assert(c2_poll(&agent, 100) == C2_ERR_TIMEOUT);
    printf("    timeout detected after stale heartbeat\n");

    /* IDLE 状态不能发心跳 */
    struct c2_session idle;
    c2_session_init(&idle, &ta);
    assert(c2_heartbeat(&idle) == C2_ERR_PROTO);
    c2_session_free(&idle);

    c2_session_free(&agent);
    c2_session_free(&server);
    printf("[+] heartbeat OK\n");
    return 0;
}
