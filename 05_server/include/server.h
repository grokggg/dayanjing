#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include <stddef.h>
#include "c2.h"

#define SERVER_OK          0
#define SERVER_ERR         (-1)
#define SERVER_ERR_FORMAT  (-2)
#define SERVER_ERR_NOMEM   (-3)
#define SERVER_ERR_FULL    (-4)

#define SERVER_MAX_SESSIONS   256
#define SERVER_MAX_TASKS      512
#define SERVER_BACKLOG        64
#define SERVER_READ_BUF       (16 * 1024)
#define SERVER_WRITE_BUF      (64 * 1024)

/* task priority */
typedef enum {
    SERVER_TASK_LOW = 0,
    SERVER_TASK_NORMAL = 1,
    SERVER_TASK_HIGH = 2,
    SERVER_TASK_CRITICAL = 3
} server_task_prio_t;

/* server-side session: hash + doubly-linked LRU */
typedef struct server_session {
    struct server_session *prev;
    struct server_session *next;

    c2_session_t c2;                 /* C2 state machine */
    int          fd;                 /* socket fd (epoll target) */
    uint8_t      id[6];              /* session table key */
    uint64_t     last_seen;          /* monotonic ts, for LRU */
    uint8_t      read_buf[SERVER_READ_BUF];
    size_t       read_len;
    uint8_t      write_buf[SERVER_WRITE_BUF];
    size_t       write_len;
    int          write_pos;
    int          want_write;         /* has pending write */
    int          closing;

    /* hash chain (separate from LRU prev/next) */
    struct server_session *next_table;
} server_session_t;

/* task: queued command for an agent */
typedef struct {
    uint8_t               session_id[6];
    server_task_prio_t    priority;
    uint8_t               msg_type;
    uint64_t              created_at;
    uint64_t              deadline;
    size_t                payload_len;
    uint8_t               payload[];  /* flexible */
} server_task_t;

/* task queue node */
typedef struct task_node {
    struct task_node *next;
    server_task_t    *task;
} task_node_t;

/* callback: invoked when a frame is dispatched to server logic */
typedef void (*server_dispatch_cb)(server_session_t *s, const proto_frame_t *frame, void *user);

/* callback: session lifecycle */
typedef void (*server_session_cb)(server_session_t *s, int event, void *user);

#define SERVER_EVT_CONNECT    1
#define SERVER_EVT_ACTIVE     2
#define SERVER_EVT_DISCONNECT 3
#define SERVER_EVT_TIMEOUT    4

typedef struct {
    server_dispatch_cb on_dispatch;
    server_session_cb  on_session;
    void              *user;
} server_callbacks_t;

/* opaque server handle */
typedef struct server server_t;

/* create / destroy */
server_t *server_new(void);
void      server_free(server_t *sv);

/* configure listen address (default 0.0.0.0:8443) */
int server_listen(server_t *sv, const char *host, uint16_t port);

/* register callbacks */
int server_set_callbacks(server_t *sv, const server_callbacks_t *cb);

/* set master key for session key derivation */
int server_set_master_key(server_t *sv, const uint8_t *key, size_t key_len);

/* enqueue a task for a session; payload may be NULL if payload_len==0 */
int server_enqueue_task(server_t *sv, const uint8_t *session_id,
                        server_task_prio_t prio, uint8_t msg_type,
                        const uint8_t *payload, size_t payload_len,
                        uint64_t timeout_ms);

/* poll loop; runs until stop is requested or timeout_ms elapses (0 = forever) */
int server_run(server_t *sv, int timeout_ms);
int server_stop(server_t *sv);

/* stats */
int  server_session_count(const server_t *sv);
void server_sessions_foreach(server_t *sv,
                             void (*fn)(server_session_t *s, void *user),
                             void *user);

const char *server_strerror(int err);

#endif
