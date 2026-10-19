#ifndef C2_H
#define C2_H

#include <stdint.h>
#include <stddef.h>
#include "proto.h"

#define C2_OK          0
#define C2_ERR         (-1)
#define C2_ERR_FORMAT  (-2)
#define C2_ERR_AUTH    (-3)

/* session states */
typedef enum {
    C2_STATE_IDLE = 0,
    C2_STATE_HANDSHAKE,
    C2_STATE_AUTH,
    C2_STATE_ACTIVE,
    C2_STATE_RECONNECT,
    C2_STATE_CLOSED
} c2_state_t;

/* transport interface (compatible with 03_transport) */
typedef struct {
    void *ctx;
    int (*connect)(void *ctx, const char *host, uint16_t port);
    int (*send)(void *ctx, const uint8_t *data, size_t len);
    int (*recv)(void *ctx, uint8_t *data, size_t *len, int timeout_ms);
    int (*close)(void *ctx);
} c2_transport_t;

/* session */
typedef struct {
    c2_state_t state;
    uint8_t session_id[6];
    uint32_t nonce_counter;
    uint8_t key[32];          /* session key */
    c2_transport_t *transport;
    uint64_t last_heartbeat;
    int heartbeat_interval;    /* seconds */
    int heartbeat_timeout;     /* seconds */
} c2_session_t;

/* callbacks */
typedef void (*c2_task_cb)(const uint8_t *data, size_t len, void *user);
typedef void (*c2_event_cb)(c2_session_t *s, void *user);

/* callbacks structure */
typedef struct {
    c2_task_cb on_task;
    c2_event_cb on_state_change;
    void *user;
} c2_callbacks_t;

/* API */
int c2_session_init(c2_session_t *s, c2_transport_t *t);
int c2_session_handshake(c2_session_t *s);
int c2_session_auth(c2_session_t *s, const uint8_t *hmac_key, size_t key_len);
int c2_session_send(c2_session_t *s, uint8_t msg_type, const uint8_t *data, size_t len);
int c2_session_recv(c2_session_t *s, proto_frame_t *frame, int timeout_ms);
int c2_session_heartbeat(c2_session_t *s);
int c2_session_close(c2_session_t *s);
c2_state_t c2_session_state(const c2_session_t *s);
const char *c2_state_name(c2_state_t state);
const char *c2_strerror(int err);

/* server-side */
int c2_server_handle_message(c2_session_t *s, const proto_frame_t *frame);

#endif
