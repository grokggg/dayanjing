#ifndef SERVER_INTERNAL_H
#define SERVER_INTERNAL_H

#include "server.h"
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#define SERVER_EPOLL_MAX_EVENTS  64
#define SERVER_HEARTBEAT_TIMEOUT 90000  /* ms (90s) */

/* hash table bucket (separate chaining) */
typedef struct session_bucket {
    server_session_t *head;
} session_bucket_t;

struct server {
    int                  epfd;
    int                  lfd;
    struct sockaddr_in   addr;
    uint8_t              master_key[32];
    int                  has_key;

    session_bucket_t     ht[SERVER_MAX_SESSIONS];  /* power-of-two size */

    /* LRU: sentinel doubly-linked list, most-recently-used at head->next */
    server_session_t     lru_sentinel;

    server_callbacks_t   cb;

    task_node_t         *task_head;   /* priority queue (simple list, insert sorted) */
    task_node_t         *task_tail;

    volatile int         running;
    int                  session_count;
};

/* hash: 6-byte session id -> bucket index */
static inline uint32_t session_hash(const uint8_t *id) {
    /* FNV-1a on 6 bytes */
    uint32_t h = 2166136261u;
    for (int i = 0; i < 6; i++) {
        h ^= id[i];
        h *= 16777619u;
    }
    return h;
}

/* LRU list ops */
void lru_init(server_t *sv);
void lru_touch(server_t *sv, server_session_t *s);
void lru_unlink(server_session_t *s);
server_session_t *lru_evict_oldest(server_t *sv);

/* session table */
server_session_t *session_table_find(server_t *sv, const uint8_t *id);
server_session_t *session_table_add(server_t *sv, server_session_t *s);
void              session_table_remove(server_t *sv, server_session_t *s);
void              session_table_foreach(server_t *sv,
                                       void (*fn)(server_session_t *s, void *user),
                                       void *user);

/* task queue */
int  task_enqueue(server_t *sv, server_task_t *task);
void task_free_node(task_node_t *n);

/* fd / IO helpers (timeout via poll+SO_RCVTIMEO) */
int  accept_client(server_t *sv);
void close_session(server_t *sv, server_session_t *s, int event);
int  try_read(server_t *sv, server_session_t *s);
int  try_write(server_t *sv, server_session_t *s);
int  flush_pending(server_t *sv);

/* frame processing */
int  process_frames(server_t *sv, server_session_t *s);
int  handle_server_frame(server_t *sv, server_session_t *s, const proto_frame_t *frame);

/* time */
uint64_t now_ms(void);

#endif
