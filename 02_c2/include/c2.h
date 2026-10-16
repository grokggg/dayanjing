#ifndef C2_H
#define C2_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define C2_MAX_PAYLOAD         (16 * 1024)
#define C2_HEARTBEAT_SEC       30
#define C2_TIMEOUT_SEC         90
#define C2_MAX_RETRY           5
#define C2_SESSION_TOKEN_LEN   32
#define C2_NONCE_LEN           12

/* 消息类型（msg_type 是 uint32_t，由 C2 层定义语义） */
typedef enum {
    C2_MSG_HEARTBEAT = 0,
    C2_MSG_REGISTER  = 1,
    C2_MSG_CHALLENGE = 2,
    C2_MSG_AUTH      = 3,
    C2_MSG_CONFIRM   = 4,
    C2_MSG_TASK      = 5,
    C2_MSG_RESULT    = 6,
    C2_MSG_ACK       = 7,
} c2_msg_type_t;

/* 错误码 */
typedef enum {
    C2_OK              = 0,
    C2_ERR             = -1,
    C2_ERR_HANDSHAKE   = -2,
    C2_ERR_AUTH        = -3,
    C2_ERR_ENCRYPT     = -4,
    C2_ERR_DECRYPT     = -5,
    C2_ERR_TIMEOUT     = -6,
    C2_ERR_TRANSPORT   = -7,
    C2_ERR_NOMEM       = -8,
    C2_ERR_PROTO       = -9,
} c2_err_t;

const char *c2_strerror(c2_err_t e);

/* 传输层抽象 */
struct c2_transport {
    const char          *name;
    void                *ctx;
    c2_err_t (*connect)(void *ctx, const char *endpoint);
    c2_err_t (*send)   (void *ctx, const uint8_t *data, size_t len);
    c2_err_t (*recv)   (void *ctx, uint8_t *buf, size_t *len, int timeout_ms);
    c2_err_t (*close)  (void *ctx);
};

/* C2 会话状态 */
typedef enum {
    C2_STATE_IDLE       = 0,
    C2_STATE_HANDSHAKE  = 1,
    C2_STATE_AUTH       = 2,
    C2_STATE_ACTIVE     = 3,
    C2_STATE_RECONNECT  = 4,
    C2_STATE_CLOSED     = 5,
} c2_state_t;

/* 会话结构 */
struct c2_session {
    c2_state_t            state;
    uint64_t              id;
    uint8_t               token[C2_SESSION_TOKEN_LEN];
    uint8_t               key_send[32];
    uint8_t               key_recv[32];
    uint64_t              nonce_send;
    uint64_t              nonce_recv;
    uint64_t              last_heartbeat;
    struct c2_transport  *transport;
    void                 *user_ctx;
};

/* 任务回调 */
typedef void (*c2_task_cb)(struct c2_session *s,
                           const uint8_t *task_data, size_t task_len,
                           uint8_t **result, size_t *result_len);

/* 会话生命周期 */
c2_err_t  c2_session_init(struct c2_session *s, struct c2_transport *t);
void       c2_session_free(struct c2_session *s);

/* Agent 端 */
c2_err_t  c2_agent_start(struct c2_session *s, const char *endpoint,
                         const uint8_t *identity_key, size_t key_len);
c2_err_t  c2_agent_handshake(struct c2_session *s);

/* Server 端 */
c2_err_t  c2_server_accept(struct c2_session *s, const uint8_t *auth_key);
c2_err_t  c2_server_loop(struct c2_session *s, c2_task_cb on_task);
c2_err_t  c2_server_dispatch(struct c2_session *s,
                            const uint8_t *task, size_t task_len);

/* 数据通道 */
c2_err_t  c2_send(struct c2_session *s, uint8_t msg_type,
                  const uint8_t *data, size_t len);
c2_err_t  c2_recv(struct c2_session *s, uint8_t *msg_type_out,
                  uint8_t *buf, size_t *len);

/* 心跳 + 保活 */
c2_err_t  c2_heartbeat(struct c2_session *s);
c2_err_t  c2_poll(struct c2_session *s, int timeout_ms);

/* 重连 */
c2_err_t  c2_reconnect(struct c2_session *s, const char *endpoint);

/* ===== 内部 API（agent / server 共用）===== */
c2_err_t c2_seal_and_send(struct c2_session *s,
                          uint8_t msg_type,
                          const uint8_t *data, size_t len,
                          uint8_t role);

c2_err_t c2_recv_and_open_internal(struct c2_session *s,
                                   uint8_t *msg_type_out,
                                   uint8_t *buf, size_t *len,
                                   uint8_t role);

#ifdef __cplusplus
}
#endif

#endif /* C2_H */
