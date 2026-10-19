#include "c2.h"
#include "crypto.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* in-memory transport using socketpair for testing */
typedef struct {
    int fd;
} mem_transport_ctx_t;

static int mem_connect(void *ctx, const char *host, uint16_t port) {
    (void)host; (void)port;
    mem_transport_ctx_t *m = (mem_transport_ctx_t*)ctx;
    return m->fd >= 0 ? 0 : -1;
}

static int mem_send(void *ctx, const uint8_t *data, size_t len) {
    mem_transport_ctx_t *m = (mem_transport_ctx_t*)ctx;
    ssize_t w = write(m->fd, data, len);
    return w == (ssize_t)len ? 0 : -1;
}

static int mem_recv(void *ctx, uint8_t *data, size_t *len, int timeout_ms) {
    mem_transport_ctx_t *m = (mem_transport_ctx_t*)ctx;
    struct pollfd pfd = { .fd = m->fd, .events = POLLIN };
    int pr = poll(&pfd, 1, timeout_ms);
    if (pr <= 0) return -1;
    ssize_t r = read(m->fd, data, *len);
    if (r <= 0) return -1;
    *len = (size_t)r;
    return 0;
}

static int mem_close(void *ctx) {
    mem_transport_ctx_t *m = (mem_transport_ctx_t*)ctx;
    close(m->fd);
    m->fd = -1;
    return 0;
}

static c2_transport_t make_transport(int fd) {
    static mem_transport_ctx_t ctx;
    ctx.fd = fd;
    c2_transport_t t = {
        .ctx = &ctx,
        .connect = mem_connect,
        .send = mem_send,
        .recv = mem_recv,
        .close = mem_close,
    };
    return t;
}

static int test_state_machine(void) {
    c2_session_t s;
    memset(&s, 0, sizeof(s));
    s.state = C2_STATE_HANDSHAKE;

    proto_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.msg_type = PROTO_MSG_AUTH;

    int rc = c2_server_handle_message(&s, &frame);
    if (rc != C2_OK) { printf("state transition fail\n"); return 1; }
    if (s.state != C2_STATE_ACTIVE) { printf("state not ACTIVE\n"); return 1; }

    /* now in ACTIVE, send heartbeat */
    frame.msg_type = PROTO_MSG_HEARTBEAT;
    rc = c2_server_handle_message(&s, &frame);
    if (rc != C2_OK) { printf("heartbeat handle fail\n"); return 1; }

    printf("state_machine ok\n");
    return 0;
}

static int test_session_init(void) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) { printf("socketpair fail\n"); return 1; }

    c2_transport_t t = make_transport(fds[0]);
    c2_session_t s;
    if (c2_session_init(&s, &t) != C2_OK) { printf("init fail\n"); return 1; }
    if (s.state != C2_STATE_IDLE) { printf("state not IDLE\n"); return 1; }
    if (s.transport != &t) { printf("transport not set\n"); return 1; }

    close(fds[0]);
    close(fds[1]);
    printf("session_init ok\n");
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_session_init();
    rc |= test_state_machine();
    printf("ALL TESTS %s\n", rc == 0 ? "PASS" : "FAIL");
    return rc;
}
