#define _GNU_SOURCE
#include "server.h"
#include "server_internal.h"
#include "proto.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <assert.h>

static int g_dispatch_count = 0;
static int g_session_events = 0;

static void on_dispatch(server_session_t *s, const proto_frame_t *f, void *user) {
    (void)s; (void)f; (void)user;
    g_dispatch_count++;
}

static void on_session(server_session_t *s, int event, void *user) {
    (void)s; (void)event; (void)user;
    g_session_events++;
}

static int check_eq(const char *name, int cond) {
    if (cond) { printf("  [PASS] %s\n", name); return 0; }
    printf("  [FAIL] %s\n", name);
    return 1;
}

/* test 1: create/free lifecycle */
static int test_lifecycle(void) {
    server_t *sv = server_new();
    fprintf(stderr, "[LIFE-DBG] sv=%p\n", (void*)sv);
    fflush(stderr);
    if (sv == NULL) {
        printf("  [FAIL] server_new returns non-NULL (got NULL)\n");
        return 1;
    }
    printf("  [PASS] server_new returns non-NULL\n");
    server_free(sv);
    fprintf(stderr, "[LIFE-DBG] after server_free\n");
    fflush(stderr);
    printf("test_lifecycle ok\n");
    return 0;
}

/* test 2: master key config + callbacks */
static int test_config(void) {
    server_t *sv = server_new();
    uint8_t key[32];
    crypto_rng(key, 32);

    int rc = server_set_master_key(sv, key, 32);
    if (check_eq("set_master_key ok", rc == SERVER_OK)) return 1;

    server_callbacks_t cb = { .on_dispatch = on_dispatch, .on_session = on_session, .user = NULL };
    rc = server_set_callbacks(sv, &cb);
    if (check_eq("set_callbacks ok", rc == SERVER_OK)) return 1;

    server_free(sv);
    printf("test_config ok\n");
    return 0;
}

/* test 3: bind to random port (bind(0) pattern) */
static int test_bind_random_port(void) {
    server_t *sv = server_new();
    uint8_t key[32]; crypto_rng(key, 32);
    server_set_master_key(sv, key, 32);

    int rc = server_listen(sv, "127.0.0.1", 0);  /* kernel assigns port */
    if (check_eq("bind(0) succeeds", rc == SERVER_OK)) return 1;

    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    getsockname(sv->lfd, (struct sockaddr *)&addr, &alen);
    int port = ntohs(addr.sin_port);
    if (check_eq("random port assigned (>0)", port > 0)) return 1;

    server_free(sv);
    printf("test_bind_random_port ok (port=%d)\n", port);
    return 0;
}

/* test 4: session table add/find/remove + LRU ordering */
static int test_session_table(void) {
    server_t *sv = server_new();
    int rc = 0;

    server_session_t *s1 = calloc(1, sizeof(*s1));
    server_session_t *s2 = calloc(1, sizeof(*s2));
    crypto_rng(s1->id, 6);
    crypto_rng(s2->id, 6);
    s1->fd = 10; s2->fd = 11;
    s1->c2.state = C2_STATE_ACTIVE;
    s2->c2.state = C2_STATE_ACTIVE;

    session_table_add(sv, s1);
    session_table_add(sv, s2);
    rc |= check_eq("count==2", sv->session_count == 2);

    rc |= check_eq("find s1", session_table_find(sv, s1->id) == s1);
    rc |= check_eq("find s2", session_table_find(sv, s2->id) == s2);

    /* touch s1 -> becomes MRU */
    lru_touch(sv, s1);
    server_session_t *mru = sv->lru_sentinel.next;
    rc |= check_eq("s1 is MRU after touch", mru == s1);

    /* evict oldest = s2 (lru_evict_oldest unlinks LRU + hash + decrements count) */
    server_session_t *old = lru_evict_oldest(sv);
    rc |= check_eq("evict oldest == s2", old == s2);
    /* evict returns ownership of s2; free it (not in hash, not in LRU) */
    free(s2);
    rc |= check_eq("count==1 after evict", sv->session_count == 1);

    session_table_remove(sv, s1);
    rc |= check_eq("count==0 after remove", sv->session_count == 0);

    /* ownership of s1 transferred to server_free; do not double-free */
    server_free(sv);
    printf("test_session_table ok\n");
    return rc;
}

/* test 5: task queue priority ordering */
static int test_task_queue(void) {
    server_t *sv = server_new();
    int rc = 0;
    uint8_t sid[6] = {1,2,3,4,5,6};

    /* enqueue out of order */
    server_enqueue_task(sv, sid, SERVER_TASK_LOW, PROTO_MSG_TASK, NULL, 0, 5000);
    server_enqueue_task(sv, sid, SERVER_TASK_CRITICAL, PROTO_MSG_TASK, NULL, 0, 5000);
    server_enqueue_task(sv, sid, SERVER_TASK_NORMAL, PROTO_MSG_TASK, NULL, 0, 5000);
    server_enqueue_task(sv, sid, SERVER_TASK_HIGH, PROTO_MSG_TASK, NULL, 0, 5000);

    task_node_t *n = sv->task_head;
    rc |= check_eq("head is CRITICAL", n && n->task->priority == SERVER_TASK_CRITICAL);
    n = n->next;
    rc |= check_eq("second is HIGH", n && n->task->priority == SERVER_TASK_HIGH);
    n = n->next;
    rc |= check_eq("third is NORMAL", n && n->task->priority == SERVER_TASK_NORMAL);
    n = n->next;
    rc |= check_eq("fourth is LOW", n && n->task->priority == SERVER_TASK_LOW);

    server_free(sv);
    printf("test_task_queue ok\n");
    return rc;
}

/* global for test_e2e_frame */
static server_t *g_sv = NULL;

/* test 6: end-to-end via socketpair: client sends frame, server processes */
static int test_e2e_frame(void) {
    g_sv = server_new();
    uint8_t key[32]; crypto_rng(key, 32);
    server_set_master_key(g_sv, key, 32);
    server_callbacks_t cb = { .on_dispatch = on_dispatch, .on_session = on_session, .user = NULL };
    server_set_callbacks(g_sv, &cb);

    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) { perror("socketpair"); return 1; }
    int client_fd = sp[0];
    int server_fd = sp[1];

    server_session_t *s = calloc(1, sizeof(*s));
    s->fd = server_fd;
    crypto_rng(s->id, 6);
    s->c2.state = C2_STATE_ACTIVE;
    s->c2.heartbeat_timeout = 90;
    session_table_add(g_sv, s);

    proto_frame_t f;
    memset(&f, 0, sizeof(f));
    memcpy(f.session_id, s->id, 6);
    f.msg_type = PROTO_MSG_HEARTBEAT;
    f.payload_len = 0;

    uint8_t buf[1024];
    size_t outlen = sizeof(buf);
    int rc = proto_seal(key, &f, buf, &outlen);
    if (check_eq("proto_seal ok", rc == PROTO_OK)) return 1;

    memcpy(s->read_buf, buf, outlen);
    s->read_len = outlen;

    printf("  [DBG] calling process_frames\n"); fflush(stdout);
    process_frames(g_sv, s);

    /* process_frames only queues; drain the queue into the socketpair */
    int had_queued = (s->write_len > 0);
    try_write(g_sv, s);

    rc = check_eq("heartbeat response sent (queued or drained)", had_queued);

    /* drain: read response on client side to avoid SIGPIPE */
    printf("  [DBG] draining client_fd=%d\n", client_fd); fflush(stdout);
    uint8_t drain[1024];
    struct pollfd pfd = { .fd = client_fd, .events = POLLIN };
    if (poll(&pfd, 1, 2000) > 0) {
        recv(client_fd, drain, sizeof(drain), 0);
        printf("  [DBG] drained response from client_fd\n");
    }

    close(client_fd);
    close(server_fd);
    printf("  [DBG] calling server_free\n"); fflush(stdout);
    server_free(g_sv);
    g_sv = NULL;
    printf("test_e2e_frame ok\n");
    return rc;
}

int main(void) {
    int r, f=0;
    int failed = 0;
    r=test_lifecycle(); printf("[RC] lifecycle=%d\n",r); f|=r;
    r=test_config(); printf("[RC] config=%d\n",r); f|=r;
    r=test_bind_random_port(); printf("[RC] bind=%d\n",r); f|=r;
    r=test_session_table(); printf("[RC] table=%d\n",r); f|=r;
    r=test_task_queue(); printf("[RC] queue=%d\n",r); f|=r;
    r=test_e2e_frame(); printf("[RC] e2e=%d\n",r); f|=r;

    if (f) { printf("[RC] FINAL f=%d\n", f); printf("\n*** SOME TESTS FAILED ***\n"); return 1; }
    printf("\nALL TESTS PASS\n");
    return 0;
}
