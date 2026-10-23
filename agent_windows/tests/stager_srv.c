/* tests/stager_srv.c — 测试用投递服务端实现（见 stager_srv.h 说明） */

#include "stager_srv.h"

#include "drop.h"
#include "drop_http.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <winsock2.h>

#define SRV_IOBUF (DP_CHUNK_MAX + 1024)

struct srv_ctx {
    stager_srv_t *s;
    uint64_t      ls;
};

static void *srv_thread(void *arg)
{
    stager_srv_t *s = ((struct srv_ctx *)arg)->s;
    uint64_t      ls = ((struct srv_ctx *)arg)->ls;
    const dp_manifest_t *m = (const dp_manifest_t *)s->manifest;

    free(arg);

    for (;;) {
        SOCKADDR_IN ca;
        int calen = (int)sizeof(ca);
        SOCKET c = accept(ls, (SOCKADDR *)&ca, &calen);
        if (c == INVALID_SOCKET) break;
        if (s->stop) { closesocket(c); break; }

        char req[512];
        int n = recv(c, req, (int)sizeof(req) - 1, 0);
        if (n <= 0) { closesocket(c); continue; }
        req[n] = '\0';

        uint32_t idx = 0;
        uint8_t resp[SRV_IOBUF];
        size_t  rlen = 0;

        if (dp_http_parse_request(req, (size_t)n, &idx) != DP_OK) {
            dp_http_build_decoy(resp, sizeof(resp), &rlen);
            send(c, (const char *)resp, (int)rlen, 0);
            closesocket(c);
            continue;
        }

        /* 断供：超过上限的块一律回诱饵，让 stager 收不齐 */
        if (s->serve_limit >= 0 && s->served >= s->serve_limit) {
            dp_http_build_decoy(resp, sizeof(resp), &rlen);
            send(c, (const char *)resp, (int)rlen, 0);
            closesocket(c);
            continue;
        }

        const uint8_t *chunk = NULL;
        size_t clen = 0;
        if (dp_chunk_get(s->blob, s->blob_len, m, idx, &chunk, &clen) != DP_OK) {
            dp_http_build_decoy(resp, sizeof(resp), &rlen);
            send(c, (const char *)resp, (int)rlen, 0);
            closesocket(c);
            continue;
        }

        if (s->tamper_idx >= 0 && (int)idx == s->tamper_idx && clen > 0) {
            uint8_t *tmp = (uint8_t *)malloc(clen);
            if (tmp) {
                memcpy(tmp, chunk, clen);
                tmp[clen - 1] ^= 0xFF;          /* 改末字节 -> 摘要不符 */
                dp_http_build_response(tmp, clen, NULL, resp, sizeof(resp), &rlen);
                send(c, (const char *)resp, (int)rlen, 0);
                free(tmp);
                closesocket(c);
                s->served++;
                continue;
            }
        }

        dp_http_build_response(chunk, clen, NULL, resp, sizeof(resp), &rlen);
        send(c, (const char *)resp, (int)rlen, 0);
        closesocket(c);
        s->served++;
    }
    return NULL;
}

int stager_srv_start(stager_srv_t *s)
{
    if (!s || !s->blob || !s->manifest) return -1;

    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) return -1;

    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) return -1;

    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, (int)sizeof(one));

    SOCKADDR_IN sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = (unsigned short)AF_INET;
    sa.sin_port   = 0;                    /* 让内核分配，避免端口竞争 */
    sa.sin_addr   = INADDR_ANY;
    if (bind(ls, (const SOCKADDR *)&sa, (int)sizeof(sa)) == SOCKET_ERROR) {
        closesocket(ls);
        return -1;
    }
    if (listen(ls, 16) == SOCKET_ERROR) { closesocket(ls); return -1; }

    SOCKADDR_IN bound;
    int blen = (int)sizeof(bound);
    memset(&bound, 0, sizeof(bound));
    if (getsockname(ls, (SOCKADDR *)&bound, &blen) == SOCKET_ERROR) {
        closesocket(ls); return -1;
    }
    s->port  = ntohs(bound.sin_port);
    s->lsock = ls;
    s->served = 0;
    s->stop = 0;
    s->ready = 1;

    struct srv_ctx *ctx = (struct srv_ctx *)malloc(sizeof(*ctx));
    if (!ctx) { closesocket(ls); return -1; }
    ctx->s = s;
    ctx->ls = ls;

    pthread_t *th = (pthread_t *)malloc(sizeof(pthread_t));
    if (!th) { free(ctx); closesocket(ls); return -1; }
    if (pthread_create(th, NULL, srv_thread, ctx) != 0) {
        free(ctx); free(th); closesocket(ls); return -1;
    }
    s->th = th;
    return 0;
}

void stager_srv_stop(stager_srv_t *s)
{
    if (!s) return;
    s->stop = 1;
    if (s->lsock != INVALID_SOCKET) {
        shutdown((SOCKET)s->lsock, SD_BOTH);
        closesocket((SOCKET)s->lsock);
        s->lsock = INVALID_SOCKET;
    }
    if (s->th) {
        pthread_join(*(pthread_t *)s->th, NULL);
        free(s->th);
        s->th = NULL;
    }
    WSACleanup();
}
