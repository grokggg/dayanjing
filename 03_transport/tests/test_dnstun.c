#define _DEFAULT_SOURCE
#include "dnstun.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int g_total = 0, g_pass = 0, g_fail = 0;

#define CHECK(cond, name) do {                                    \
    g_total++;                                                    \
    if (cond) { g_pass++; printf("[PASS] %s\n", name); }          \
    else      { g_fail++; printf("[FAIL] %s\n", name); }          \
} while (0)

typedef struct {
    uint8_t  buf[8192];
    size_t   len;
    int      drop_first;
    int      seen;
    int      got_fin;
    const uint8_t *down;
    size_t   downlen;
} srv_ctx_t;

static int srv_cb(uint32_t seq, int fin, const uint8_t *chunk, size_t clen,
                  uint8_t *down, size_t cap, size_t *downlen, void *arg) {
    srv_ctx_t *c = (srv_ctx_t *)arg;
    (void)seq;
    if (c->drop_first && c->seen == 0) { c->seen++; return -1; }
    if (c->len + clen <= sizeof(c->buf)) {
        memcpy(c->buf + c->len, chunk, clen);
        c->len += clen;
    }
    if (fin) c->got_fin = 1;
    if (c->downlen && c->downlen <= cap) {
        memcpy(down, c->down, c->downlen);
        *downlen = c->downlen;
        c->downlen = 0;
    } else {
        *downlen = 0;
    }
    return 0;
}

/* 起真实权威端子进程，跑完整隧道，返回权威端收到的上行字节数 */
static int run_case(const uint8_t *data, size_t len, int drop_first,
                    const uint8_t *down, size_t downlen,
                    uint8_t *got_up, size_t cap_up, size_t *got_up_len,
                    uint8_t *got_down, size_t cap_down, size_t *got_down_len,
                    int *send_rc) {
    int port = 0;
    int srv = tx_dnsauth_listen(0, &port);
    int fds[2];
    pid_t pid;
    tx_dnstun_t *t = NULL;
    size_t acked = 0;
    int rc;

    if (srv < 0) return -1;
    if (pipe(fds) < 0) { close(srv); return -1; }

    pid = fork();
    if (pid < 0) { close(srv); close(fds[0]); close(fds[1]); return -1; }

    if (pid == 0) {
        srv_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.drop_first = drop_first;
        ctx.down = down;
        ctx.downlen = downlen;
        close(fds[0]);
        for (;;) {
            int r = tx_dnsauth_serve_once(srv, srv_cb, &ctx, 3000);
            if (r == TX_DNSTUN_OK && ctx.got_fin) break;
            if (r == TX_DNSTUN_ERR_TIMEOUT) break;
        }
        {
            ssize_t w = write(fds[1], ctx.buf, ctx.len);
            (void)w;
        }
        close(fds[1]);
        close(srv);
        _exit(0);
    }

    close(fds[1]);
    close(srv);

    rc = tx_dnstun_open(&t, "127.0.0.1", port, "tun.example.com", "sess1234", 800, 4);
    if (rc != TX_DNSTUN_OK) {
        close(fds[0]);
        waitpid(pid, NULL, 0);
        return -1;
    }
    *send_rc = tx_dnstun_send(t, data, len, &acked);

    {
        size_t n = 0;
        *got_up_len = 0;
        for (;;) {
            ssize_t r = read(fds[0], got_up + n, cap_up - n);
            if (r <= 0) break;
            n += (size_t)r;
            if (n >= cap_up) break;
        }
        *got_up_len = n;
    }
    close(fds[0]);
    waitpid(pid, NULL, 0);

    tx_dnstun_poll(t, got_down, cap_down, got_down_len);
    tx_dnstun_close(t);
    return 0;
}

int main(void) {
    uint8_t small[10];
    uint8_t big[1000];
    uint8_t exact[TX_DNSTUN_CHUNK * 3];
    uint8_t got_up[8192], got_down[512];
    size_t ulen = 0, dlen = 0;
    int rc = 0;
    size_t i;

    for (i = 0; i < sizeof(small); i++) small[i] = (uint8_t)(i * 7 + 1);
    for (i = 0; i < sizeof(big); i++)   big[i]   = (uint8_t)(i * 13 + 5);
    for (i = 0; i < sizeof(exact); i++) exact[i] = (uint8_t)(i * 3 + 2);

    printf("=== DNS 隧道可靠传输层（真实 UDP + fork 权威端）===\n\n");

    /* 1. 小数据上行 */
    if (run_case(small, sizeof(small), 0, NULL, 0,
                 got_up, sizeof(got_up), &ulen,
                 got_down, sizeof(got_down), &dlen, &rc) == 0) {
        CHECK(rc == TX_DNSTUN_OK, "小数据上行 send 返回 OK");
        CHECK(ulen == sizeof(small) && memcmp(got_up, small, ulen) == 0,
              "小数据上行字节级一致");
    } else { CHECK(0, "小数据上行用例启动"); }

    /* 2. 大数据分片上行 */
    if (run_case(big, sizeof(big), 0, NULL, 0,
                 got_up, sizeof(got_up), &ulen,
                 got_down, sizeof(got_down), &dlen, &rc) == 0) {
        CHECK(rc == TX_DNSTUN_OK, "1000 字节分片上行 send 返回 OK");
        CHECK(ulen == sizeof(big) && memcmp(got_up, big, ulen) == 0,
              "1000 字节分片上行字节级一致");
    } else { CHECK(0, "大数据上行用例启动"); }

    /* 3. 恰好 CHUNK 整数倍 */
    if (run_case(exact, sizeof(exact), 0, NULL, 0,
                 got_up, sizeof(got_up), &ulen,
                 got_down, sizeof(got_down), &dlen, &rc) == 0) {
        CHECK(rc == TX_DNSTUN_OK, "CHUNK 整数倍(300B)上行 OK");
        CHECK(ulen == sizeof(exact) && memcmp(got_up, exact, ulen) == 0,
              "CHUNK 整数倍上行字节级一致");
    } else { CHECK(0, "CHUNK 整数倍用例启动"); }

    /* 4. 下行数据回传 */
    {
        const uint8_t down[] = "CMD:COLLECT_CAMERA";
        if (run_case(small, sizeof(small), 0, down, sizeof(down),
                     got_up, sizeof(got_up), &ulen,
                     got_down, sizeof(got_down), &dlen, &rc) == 0) {
            CHECK(dlen == sizeof(down) && memcmp(got_down, down, dlen) == 0,
                  "下行数据经 TXT 捎带回传字节级一致");
        } else { CHECK(0, "下行回传用例启动"); }
    }

    /* 5. 丢包重传：权威端丢弃首次查询 */
    if (run_case(small, sizeof(small), 1, NULL, 0,
                 got_up, sizeof(got_up), &ulen,
                 got_down, sizeof(got_down), &dlen, &rc) == 0) {
        CHECK(rc == TX_DNSTUN_OK, "首片被丢弃后重传仍成功");
        CHECK(ulen == sizeof(small) && memcmp(got_up, small, ulen) == 0,
              "重传后上行仍字节级一致（无重复、无缺片）");
    } else { CHECK(0, "重传用例启动"); }

    /* 6. 空载荷 */
    if (run_case(NULL, 0, 0, NULL, 0,
                 got_up, sizeof(got_up), &ulen,
                 got_down, sizeof(got_down), &dlen, &rc) == 0) {
        CHECK(rc == TX_DNSTUN_OK, "空载荷上行 send 返回 OK");
        CHECK(ulen == 0, "空载荷上行权威端收到 0 字节");
    } else { CHECK(0, "空载荷用例启动"); }

    /* 7. 标签编解码属性（纯计算） */
    {
        char name[TX_DNSTUN_MAXNAME + 8];
        uint8_t chunk[TX_DNSTUN_CHUNK];
        uint8_t out[TX_DNSTUN_CHUNK + 8];
        uint32_t s = 0, a = 0;
        int fin = 0;
        size_t olen = 0;
        for (i = 0; i < sizeof(chunk); i++) chunk[i] = (uint8_t)(i ^ 0x5A);

        rc = tx_dnstun_label_build(0x1234, 0x5678, 1, chunk, sizeof(chunk),
                                   "sess1234", "tun.example.com", name, sizeof(name));
        CHECK(rc == TX_DNSTUN_OK, "满片(100B)标签构造成功");
        CHECK(strlen(name) <= TX_DNSTUN_MAXNAME, "QNAME 总长 <= 253");
        {
            /* 每个标签 <= 63 */
            const char *p = name;
            int ok = 1;
            while (*p) {
                const char *e = strchr(p, '.');
                size_t n = e ? (size_t)(e - p) : strlen(p);
                if (n > 63) { ok = 0; break; }
                if (!e) break;
                p = e + 1;
            }
            CHECK(ok, "所有标签长度 <= 63");
        }
        rc = tx_dnstun_label_parse(name, &s, &a, &fin, out, sizeof(out), &olen);
        CHECK(rc == TX_DNSTUN_OK && s == 0x1234 && a == 0x5678 && fin == 1,
              "标签解析 seq/ack/fin 正确");
        CHECK(olen == sizeof(chunk) && memcmp(out, chunk, olen) == 0,
              "标签解析净荷字节级一致");
    }

    /* 8. 边界：超长净荷应被拒绝 */
    {
        char name[TX_DNSTUN_MAXNAME + 8];
        uint8_t chunk[TX_DNSTUN_CHUNK + 1];
        memset(chunk, 'A', sizeof(chunk));
        rc = tx_dnstun_label_build(1, 1, 0, chunk, sizeof(chunk),
                                   "sess1234", "tun.example.com", name, sizeof(name));
        CHECK(rc == TX_DNSTUN_ERR_TOOBIG, "超过 CHUNK 上限被拒(TOOBIG)");
    }

    /* 9. 参数校验 */
    {
        char name[64];
        uint8_t out[16];
        size_t olen = 0;
        uint32_t s = 0, a = 0;
        int fin = 0;
        CHECK(tx_dnstun_label_build(1, 1, 0, NULL, 0, NULL, "d", name, sizeof(name))
              == TX_DNSTUN_ERR_ARGS, "label_build 拒绝 NULL session");
        CHECK(tx_dnstun_label_parse(NULL, &s, &a, &fin, out, sizeof(out), &olen)
              == TX_DNSTUN_ERR_ARGS, "label_parse 拒绝 NULL name");
        CHECK(tx_dns_build_query(NULL, 1, (uint8_t *)name, sizeof(name)) == 0,
              "build_query 拒绝 NULL qname");
    }

    printf("\ntotal=%d pass=%d fail=%d\n", g_total, g_pass, g_fail);
    return g_fail ? 1 : 0;
}
