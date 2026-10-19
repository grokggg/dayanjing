#define _GNU_SOURCE
#include "server_internal.h"
#include "proto.h"
#include "crypto.h"
#include <fcntl.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <poll.h>
#include <signal.h>

/* ============ time ============ */
uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* ============ LRU ============ */
void lru_init(server_t *sv) {
    sv->lru_sentinel.prev = &sv->lru_sentinel;
    sv->lru_sentinel.next = &sv->lru_sentinel;
}

void lru_unlink(server_session_t *s) {
    if (s->prev == NULL && s->next == NULL) return;  /* not linked */
    s->prev->next = s->next;
    s->next->prev = s->prev;
    s->prev = s->next = NULL;
}

void lru_touch(server_t *sv, server_session_t *s) {
    lru_unlink(s);
    /* insert after sentinel = MRU head */
    s->next = sv->lru_sentinel.next;
    s->prev = &sv->lru_sentinel;
    sv->lru_sentinel.next->prev = s;
    sv->lru_sentinel.next = s;
    s->last_seen = now_ms();
}

server_session_t *lru_evict_oldest(server_t *sv) {
    server_session_t *old = sv->lru_sentinel.prev;
    if (old == &sv->lru_sentinel) return NULL;
    /*
     * Eviction must keep hash chain and session_count consistent with the LRU
     * unlink: remove from the hash bucket and decrement the counter, otherwise
     * callers (test_session_table, session_table_add) observe stale counts.
     */
    {
        uint32_t idx = session_hash(old->id) & (SERVER_MAX_SESSIONS - 1);
        server_session_t **pp = &sv->ht[idx].head;
        while (*pp && *pp != old) pp = &(*pp)->next_table;
        if (*pp) *pp = old->next_table;
    }
    lru_unlink(old);
    if (sv->session_count > 0) sv->session_count--;
    return old;
}

/* ============ session table ============ */
server_session_t *session_table_find(server_t *sv, const uint8_t *id) {
    uint32_t idx = session_hash(id) & (SERVER_MAX_SESSIONS - 1);
    for (server_session_t *s = sv->ht[idx].head; s; s = s->next_table) {
        if (memcmp(s->id, id, 6) == 0) return s;
    }
    return NULL;
}

server_session_t *session_table_add(server_t *sv, server_session_t *s) {
    /* evict oldest if full.  Let close_session() do the hash removal and
     * session_count accounting in one place; doing it here AND inside
     * close_session() would double-decrement and double-unlink. */
    if (sv->session_count >= SERVER_MAX_SESSIONS) {
        server_session_t *old = lru_evict_oldest(sv);
        if (old) close_session(sv, old, SERVER_EVT_TIMEOUT);
    }
    uint32_t idx = session_hash(s->id) & (SERVER_MAX_SESSIONS - 1);
    s->next_table = sv->ht[idx].head;
    sv->ht[idx].head = s;
    lru_touch(sv, s);
    sv->session_count++;
    return s;
}

void session_table_remove(server_t *sv, server_session_t *s) {
    uint32_t idx = session_hash(s->id) & (SERVER_MAX_SESSIONS - 1);
    server_session_t **pp = &sv->ht[idx].head;
    while (*pp && *pp != s) pp = &(*pp)->next_table;
    if (*pp) *pp = s->next_table;
    lru_unlink(s);
    sv->session_count--;
}

void session_table_foreach(server_t *sv,
                           void (*fn)(server_session_t *s, void *user),
                           void *user) {
    for (int i = 0; i < SERVER_MAX_SESSIONS; i++) {
        for (server_session_t *s = sv->ht[i].head; s; s = s->next_table) {
            fn(s, user);
        }
    }
}

/* ============ task queue (priority, FIFO within priority) ============ */
void task_free_node(task_node_t *n) {
    if (!n) return;
    free(n->task);
    free(n);
}

int task_enqueue(server_t *sv, server_task_t *task) {
    task_node_t *n = calloc(1, sizeof(*n));
    if (!n) { free(task); return SERVER_ERR_NOMEM; }
    n->task = task;

    /* insert sorted by priority desc, then by created_at asc */
    task_node_t *cur = sv->task_head, *prev = NULL;
    while (cur &&
           (cur->task->priority > task->priority ||
            (cur->task->priority == task->priority &&
             cur->task->created_at < task->created_at))) {
        prev = cur;
        cur = cur->next;
    }
    n->next = cur;
    if (prev) prev->next = n;
    else sv->task_head = n;
    return SERVER_OK;
}

/* ============ server lifecycle ============ */
server_t *server_new(void) {
    server_t *sv = calloc(1, sizeof(*sv));
    if (!sv) return NULL;
    sv->epfd = -1;
    sv->lfd = -1;
    lru_init(sv);
    return sv;
}

void server_free(server_t *sv) {
    if (!sv) return;
    if (sv->running) server_stop(sv);
    if (sv->lfd >= 0) close(sv->lfd);
    if (sv->epfd >= 0) close(sv->epfd);
    /*
     * Drain sessions through close_session() so both the hash chain and the
     * LRU doubly-linked list are kept consistent.  Walking the table with a
     * bare free() after an lru_evict_oldest()/lru_unlink() would dereference
     * already-relinked prev/next pointers (use-after-free).
     */
    for (int i = 0; i < SERVER_MAX_SESSIONS; i++) {
        while (sv->ht[i].head) {
            close_session(sv, sv->ht[i].head, SERVER_EVT_DISCONNECT);
        }
    }
    /* free tasks */
    while (sv->task_head) {
        task_node_t *n = sv->task_head;
        sv->task_head = n->next;
        task_free_node(n);
    }
    fprintf(stderr, "[FREE-DBG] about to free sv=%p size=%zu\n", (void *)sv, sizeof(*sv));
    fflush(stderr);
    free(sv);
    fprintf(stderr, "[FREE-DBG] free returned\n");
    fflush(stderr);
}

int server_listen(server_t *sv, const char *host, uint16_t port) {
    if (!sv || !host) return SERVER_ERR_FORMAT;
    sv->lfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sv->lfd < 0) return SERVER_ERR;

    int yes = 1;
    setsockopt(sv->lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    memset(&sv->addr, 0, sizeof(sv->addr));
    sv->addr.sin_family = AF_INET;
    sv->addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &sv->addr.sin_addr) != 1) {
        close(sv->lfd); sv->lfd = -1; return SERVER_ERR_FORMAT;
    }

    if (bind(sv->lfd, (struct sockaddr *)&sv->addr, sizeof(sv->addr)) < 0) {
        close(sv->lfd); sv->lfd = -1; return SERVER_ERR;
    }
    if (listen(sv->lfd, SERVER_BACKLOG) < 0) {
        close(sv->lfd); sv->lfd = -1; return SERVER_ERR;
    }
    return SERVER_OK;
}

int server_set_callbacks(server_t *sv, const server_callbacks_t *cb) {
    if (!sv || !cb) return SERVER_ERR_FORMAT;
    sv->cb = *cb;
    return SERVER_OK;
}

int server_set_master_key(server_t *sv, const uint8_t *key, size_t key_len) {
    if (!sv || !key || key_len != 32) return SERVER_ERR_FORMAT;
    memcpy(sv->master_key, key, 32);
    sv->has_key = 1;
    return SERVER_OK;
}

int server_enqueue_task(server_t *sv, const uint8_t *sid, server_task_prio_t prio,
                        uint8_t msg_type, const uint8_t *payload, size_t payload_len,
                        uint64_t timeout_ms) {
    if (!sv || !sid) return SERVER_ERR_FORMAT;
    if (payload_len > 0 && !payload) return SERVER_ERR_FORMAT;

    size_t total = sizeof(server_task_t) + payload_len;
    server_task_t *t = malloc(total);
    if (!t) return SERVER_ERR_NOMEM;
    memset(t, 0, total);
    memcpy(t->session_id, sid, 6);
    t->priority = prio;
    t->msg_type = msg_type;
    t->created_at = now_ms();
    t->deadline = t->created_at + timeout_ms;
    t->payload_len = payload_len;
    if (payload_len > 0) memcpy(t->payload, payload, payload_len);

    return task_enqueue(sv, t);
}


static int fd_timeout(int fd, int ms) {
    struct timeval tv = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

int accept_client(server_t *sv) {
    struct sockaddr_in caddr;
    socklen_t clen = sizeof(caddr);
    int cfd = accept4(sv->lfd, (struct sockaddr *)&caddr, &clen, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (cfd < 0) return SERVER_ERR;

    fd_timeout(cfd, 30000);

    server_session_t *s = calloc(1, sizeof(*s));
    if (!s) { close(cfd); return SERVER_ERR_NOMEM; }
    s->fd = cfd;
    c2_session_init(&s->c2, NULL);
    crypto_rng(s->id, 6);
    memcpy(s->c2.session_id, s->id, 6);
    s->c2.heartbeat_interval = 30;
    s->c2.heartbeat_timeout = 90;
    s->want_write = 0;
    s->closing = 0;

    if (sv->epfd >= 0) {
        struct epoll_event ev = { .events = EPOLLIN | EPOLLET, .data.ptr = s };
        epoll_ctl(sv->epfd, EPOLL_CTL_ADD, cfd, &ev);
    }

    session_table_add(sv, s);
    if (sv->cb.on_session) sv->cb.on_session(s, SERVER_EVT_CONNECT, sv->cb.user);
    return SERVER_OK;
}

void close_session(server_t *sv, server_session_t *s, int event) {
    if (!s) return;
    if (s->fd >= 0) {
        if (sv->epfd >= 0) epoll_ctl(sv->epfd, EPOLL_CTL_DEL, s->fd, NULL);
        close(s->fd);
        s->fd = -1;
    }
    session_table_remove(sv, s);
    if (sv->cb.on_session) sv->cb.on_session(s, event, sv->cb.user);
    free(s);
}

/* ============ read / write ============ */
int try_read(server_t *sv __attribute__((unused)), server_session_t *s) {
    while (1) {
        if (s->read_len >= SERVER_READ_BUF) {
            /* overflow: reset */
            s->read_len = 0;
            return SERVER_ERR_FORMAT;
        }
        ssize_t n = recv(s->fd, s->read_buf + s->read_len,
                         SERVER_READ_BUF - s->read_len, 0);
        if (n > 0) {
            s->read_len += (size_t)n;
            continue;
        }
        if (n == 0) { s->closing = 1; return SERVER_ERR; }
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        if (errno == EINTR) continue;
        return SERVER_ERR;
    }
    return SERVER_OK;
}

int try_write(server_t *sv __attribute__((unused)), server_session_t *s) {
    while (s->write_pos < (int)s->write_len) {
        ssize_t n = send(s->fd, s->write_buf + s->write_pos,
                         s->write_len - s->write_pos, MSG_NOSIGNAL);
        if (n > 0) { s->write_pos += (int)n; continue; }
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        if (errno == EINTR) continue;
        return SERVER_ERR;
    }
    if (s->write_pos >= (int)s->write_len) {
        s->write_len = 0;
        s->write_pos = 0;
        s->want_write = 0;
    } else {
        s->want_write = 1;
    }
    return SERVER_OK;
}

/* enqueue bytes for sending (copies into write_buf) */
static int queue_write(server_t *sv __attribute__((unused)), server_session_t *s, const uint8_t *data, size_t len) {
    if (s->write_len + len > SERVER_WRITE_BUF) return SERVER_ERR_FULL;
    memcpy(s->write_buf + s->write_len, data, len);
    s->write_len += len;
    s->want_write = 1;
    return SERVER_OK;
}

/* ============ frame processing ============ */
int process_frames(server_t *sv, server_session_t *s) {
    uint8_t *buf = s->read_buf;
    size_t   len = s->read_len;
    size_t   consumed = 0;

    /*
     * Wire format here is the AEAD-sealed blob, NOT a plaintext frame:
     *   [ 12-byte AEAD nonce ][ ciphertext (>= PROTO_HEADER_LEN) ][ 16-byte tag ]
     * Minimum on-wire size = 12 + PROTO_HEADER_LEN + PROTO_TAG_LEN = 55 bytes.
     * We do NOT peek at plaintext header fields (they are encrypted); the whole
     * blob is handed to proto_open() which authenticates and decrypts it.
     */
    const size_t onwire_min = 12 + PROTO_HEADER_LEN + PROTO_TAG_LEN;

    while (consumed + onwire_min <= len) {
        const uint8_t *blob = buf + consumed;
        size_t blob_len = len - consumed;

        /* blob_len may contain more than one frame; find the exact boundary by
         * attempting decode of the largest possible prefix, but the AEAD output
         * is length-prefixed only by the frame header inside the ciphertext.
         * Simplest correct approach: the frame was sealed as a single blob of
         * known total length 12 + (PROTO_HEADER_LEN + payload_len) + 16.
         * Without an outer length prefix we rely on the producer sealing one
         * frame per send(); consume the whole pending buffer as one blob.
         * (For streamed multiplexing, an outer length prefix is required.) */
        size_t frame_len = blob_len;  /* treat entire pending blob as one frame */

        if (frame_len > SERVER_READ_BUF) break;  /* malformed */

        proto_frame_t frame;
        memset(&frame, 0, sizeof(frame));

        int rc = PROTO_ERR;
        if (sv->has_key) {
            rc = proto_open(sv->master_key, blob, frame_len, &frame);
        } else {
            rc = PROTO_ERR;
        }

        fprintf(stderr, "  [DBG] proto_open rc=%d blob_len=%zu has_key=%d frame_len_field=%u\n",
                rc, frame_len, sv->has_key, (unsigned)frame.payload_len);

        if (rc == PROTO_OK) {
            handle_server_frame(sv, s, &frame);
            consumed += frame_len;
        } else {
            consumed = len;
            proto_frame_free(&frame);
            return SERVER_ERR;
        }
        proto_frame_free(&frame);
    }

    /* shift remaining */
    if (consumed > 0) {
        size_t rem = len - consumed;
        memmove(buf, buf + consumed, rem);
        s->read_len = rem;
    }
    return SERVER_OK;
}

int handle_server_frame(server_t *sv, server_session_t *s, const proto_frame_t *frame) {
    s->last_seen = now_ms();
    lru_touch(sv, s);

    switch (frame->msg_type) {
    case PROTO_MSG_HANDSHAKE: {
        /* agent -> server: derive session, send back CONFIRM */
        if (!sv->has_key) return SERVER_ERR;
        /* build response frame */
        proto_frame_t resp;
        memset(&resp, 0, sizeof(resp));
        memcpy(resp.session_id, s->id, 6);
        resp.msg_type = PROTO_MSG_CONFIRM;
        resp.payload_len = 0;
        resp.payload = NULL;
        size_t outlen = 0;
        uint8_t *out = malloc(PROTO_HEADER_LEN + PROTO_TAG_LEN);
        if (!out) return SERVER_ERR_NOMEM;
        int rc = proto_seal(sv->master_key, &resp, out, &outlen);
        if (rc == PROTO_OK) queue_write(sv, s, out, outlen);
        free(out);
        s->c2.state = C2_STATE_ACTIVE;
        if (sv->cb.on_session) sv->cb.on_session(s, SERVER_EVT_ACTIVE, sv->cb.user);
        break;
    }
    case PROTO_MSG_HEARTBEAT: {
        /* respond with heartbeat */
        proto_frame_t resp;
        memset(&resp, 0, sizeof(resp));
        memcpy(resp.session_id, s->id, 6);
        resp.msg_type = PROTO_MSG_HEARTBEAT;
        resp.payload_len = 0;
        resp.payload = NULL;
        /* total = nonce(12) + header(27) + payload(0) + tag(16) = 55 */
        size_t outlen = 12 + PROTO_HEADER_LEN + resp.payload_len + PROTO_TAG_LEN;
        uint8_t *out = malloc(outlen);
        if (!out) return SERVER_ERR_NOMEM;
        if (proto_seal(sv->master_key, &resp, out, &outlen) != PROTO_OK) {
            free(out);
            return SERVER_ERR;
        }
        queue_write(sv, s, out, outlen);
        free(out);
        break;
    }
    case PROTO_MSG_RESULT:
    case PROTO_MSG_DATA:
    case PROTO_MSG_TASK:
    default:
        if (sv->cb.on_dispatch) {
            sv->cb.on_dispatch(s, frame, sv->cb.user);
        }
        break;
    }
    return SERVER_OK;
}

/* ============ main loop ============ */
int server_run(server_t *sv, int timeout_ms) {
    if (!sv || sv->lfd < 0) return SERVER_ERR;
    if (!sv->has_key) return SERVER_ERR;

    sv->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (sv->epfd < 0) return SERVER_ERR;

    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = NULL };
    ev.data.fd = sv->lfd;
    ev.events = EPOLLIN;
    epoll_ctl(sv->epfd, EPOLL_CTL_ADD, sv->lfd, &ev);

    sv->running = 1;

    int rc = SERVER_OK;
    uint64_t start = now_ms();
    int nevents;

    while (sv->running) {
        if (timeout_ms > 0 && (int)(now_ms() - start) >= timeout_ms) break;

        struct epoll_event events[SERVER_EPOLL_MAX_EVENTS];
        nevents = epoll_wait(sv->epfd, events, SERVER_EPOLL_MAX_EVENTS, 100);
        if (nevents < 0) {
            if (errno == EINTR) continue;
            rc = SERVER_ERR;
            break;
        }

        for (int i = 0; i < nevents; i++) {
            struct epoll_event *e = &events[i];

            /* listener */
            if (e->data.fd == sv->lfd) {
                if (e->events & EPOLLIN) accept_client(sv);
                continue;
            }

            server_session_t *s = e->data.ptr;
            if (!s) continue;

            if (e->events & (EPOLLERR | EPOLLHUP)) {
                close_session(sv, s, SERVER_EVT_DISCONNECT);
                continue;
            }

            if (e->events & EPOLLIN) {
                if (try_read(sv, s) == SERVER_OK) {
                    process_frames(sv, s);
                }
                if (s->closing) { close_session(sv, s, SERVER_EVT_DISCONNECT); continue; }
            }

            if (e->events & EPOLLOUT) {
                try_write(sv, s);
            }

            /* re-arm writable if has pending */
            if (s->fd >= 0 && s->want_write) {
                struct epoll_event nev = { .events = EPOLLIN | EPOLLOUT | EPOLLET, .data.ptr = s };
                epoll_ctl(sv->epfd, EPOLL_CTL_MOD, s->fd, &nev);
            }
        }

        /* dispatch queued tasks whose session is ACTIVE */
        task_node_t *cur = sv->task_head, *prev = NULL;
        while (cur) {
            server_session_t *s = session_table_find(sv, cur->task->session_id);
            if (s && s->c2.state == C2_STATE_ACTIVE) {
                proto_frame_t resp;
                memset(&resp, 0, sizeof(resp));
                memcpy(resp.session_id, s->id, 6);
                resp.msg_type = cur->task->msg_type;
                resp.payload_len = cur->task->payload_len;
                resp.payload = cur->task->payload;
                size_t outlen = 0;
                uint8_t *out = malloc(PROTO_HEADER_LEN + cur->task->payload_len + PROTO_TAG_LEN);
                if (out) {
                    if (proto_seal(sv->master_key, &resp, out, &outlen) == PROTO_OK) {
                        queue_write(sv, s, out, outlen);
                    }
                    free(out);
                }
                task_node_t *n = cur;
                if (prev) prev->next = cur->next;
                else sv->task_head = cur->next;
                if (cur == sv->task_tail) sv->task_tail = prev;
                task_free_node(n);
                cur = prev ? prev->next : sv->task_head;
            } else {
                prev = cur;
                cur = cur->next;
            }
        }

        /* expire deadlined tasks */
        {
            task_node_t *c = sv->task_head, *p = NULL;
            while (c) {
                if (c->task->deadline > 0 && now_ms() > c->task->deadline) {
                    task_node_t *n = c;
                    if (p) p->next = c->next;
                    else sv->task_head = c->next;
                    if (c == sv->task_tail) sv->task_tail = p;
                    task_free_node(n);
                    c = p ? p->next : sv->task_head;
                } else {
                    p = c; c = c->next;
                }
            }
        }

        /* heartbeat / timeout sweep */
        uint64_t nm = now_ms();
        for (int bi = 0; bi < SERVER_MAX_SESSIONS; bi++) {
            for (server_session_t *s = sv->ht[bi].head; s; ) {
                server_session_t *nxt = s->next_table;
                if (s->c2.state == C2_STATE_ACTIVE) {
                    if (nm - s->last_seen > (uint64_t)s->c2.heartbeat_timeout * 1000) {
                        close_session(sv, s, SERVER_EVT_TIMEOUT);
                    }
                }
                s = nxt;
            }
        }
    }

    close(sv->epfd);
    sv->epfd = -1;
    sv->running = 0;
    return rc;
}

int server_stop(server_t *sv) {
    if (sv) sv->running = 0;
    return SERVER_OK;
}

int server_session_count(const server_t *sv) {
    return sv ? sv->session_count : 0;
}

void server_sessions_foreach(server_t *sv,
                             void (*fn)(server_session_t *s, void *user),
                             void *user) {
    if (sv && fn) session_table_foreach(sv, fn, user);
}

const char *server_strerror(int err) {
    switch (err) {
    case SERVER_OK: return "ok";
    case SERVER_ERR: return "error";
    case SERVER_ERR_FORMAT: return "format error";
    case SERVER_ERR_NOMEM: return "no memory";
    case SERVER_ERR_FULL: return "queue/buffer full";
    default: return "unknown";
    }
}
