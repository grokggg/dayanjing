/* test_front_real.c — 域前置 × 真 TLS 闭环
 *
 * 此前的"明文字节不含真实域名"是在 mock 隧道上验的：TLS 记录层根本没参与，
 * 所以那条断言证明不了"加密外看不见真实目标"，只证明"字节没被拼错"。
 *
 * 本文件把真实的自研 TLS 服务端（25_tls/src/tls_server.c）放到链路另一端，
 * 于是可以同时断言三件事，且三者互不冗余：
 *   1. 服务端（站在 TLS 终结点上）观察到的 SNI == 前置域      -> 外部可见的只有前置域
 *   2. 真实主机出现在服务端解密后的请求里                      -> Host 确实在内层生效
 *   3. 链路上的全部字节（密文 + 握手明文）不含真实主机          -> 观察者拿不到真实目标
 * 第 3 条必须带正向对照：若扫描器根本没记录到字节，"未命中"就是假象。
 *
 * 同时闭合两个长期无人覆盖的失败分支：
 *   front_send 的 tls_write 失败、front_recv 的 tls_read 失败。
 *   此前无法覆盖，是因为 front_connect 必须真成功才能走到这两行，
 *   而 25_tls 没有服务端，握手只能靠 mock 假装成功 —— 那是把断言变成恒绿。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* MAP_ANONYMOUS 在 -std=c11 严格模式下默认不可见 */
#endif
#include "front.h"
#include "tls_server.h"
#include "x509.h"
#include "rsa.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

static int pass = 0, fail = 0;

#define CHECK(cond, ...)                                        \
    do {                                                        \
        if (cond) { pass++; printf("[PASS] "); }                \
        else      { fail++; printf("[FAIL] "); }                \
        printf(__VA_ARGS__);                                    \
        printf("\n");                                           \
    } while (0)

#define FRONT_DOMAIN "front.test"
#define REAL_HOST    "c2.real.example"

/* 父子共享：子进程把"服务端这一侧看到的事实"写进来 */
struct shared {
    char sni[256];
    int  req_len;
    int  req_has_host;      /* 解密后的请求里是否有 Host: 真实主机 */
    int  req_has_front;     /* 请求里是否意外出现前置域（不该有） */
    int  resp_written;
};

/* 链路取证：记录客户端实际写到线路上的每一个字节 */
#define WIRE_CAP (1 << 18)
struct wire {
    uint8_t  b[WIRE_CAP];
    size_t   n;
    int      ovf;
    int      fail_send;     /* 注入：发送回调开始失败 */
    int      fail_recv;     /* 注入：接收回调开始失败 */
    int      fd;
};

static void wire_log(struct wire *w, const uint8_t *d, size_t n) {
    if (w->n + n > WIRE_CAP) { w->ovf = 1; return; }
    memcpy(w->b + w->n, d, n);
    w->n += n;
}

static int snd_cb(void *arg, const uint8_t *d, size_t n) {
    struct wire *w = (struct wire *)arg;
    if (w->fail_send) return -1;
    for (;;) {
        ssize_t r = write(w->fd, d, n);
        if (r < 0 && errno == EINTR) continue;
        if (r > 0) wire_log(w, d, (size_t)r);
        return (int)r;
    }
}

static int rcv_cb(void *arg, uint8_t *b, size_t cap) {
    struct wire *w = (struct wire *)arg;
    if (w->fail_recv) return -1;
    for (;;) {
        ssize_t r = read(w->fd, b, cap);
        if (r < 0 && errno == EINTR) continue;
        return (int)r;
    }
}

static const char *RESP =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/octet-stream\r\n"
    "Content-Length: 5\r\n"
    "\r\n"
    "HELLO";

static int run_server(int fd, struct shared *sh) {
    rsa_privkey key;
    x509_store  st;
    memset(&key, 0, sizeof(key));
    memset(&st, 0, sizeof(st));

    if (rsa_privkey_load_pem(FRONT_TLS_DATA "/leaf.key", &key) != RSA_OK) {
        fprintf(stderr, "[srv] 私钥加载失败\n");
        return 90;
    }
    if (x509_store_load_pem(&st, FRONT_TLS_DATA "/leaf.pem") != X509_OK || st.n == 0) {
        fprintf(stderr, "[srv] 证书加载失败\n");
        rsa_privkey_clear(&key);
        return 91;
    }

    tls_server_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.chain[0]     = st.e[0].der;
    cfg.chain_len[0] = st.e[0].der_len;
    cfg.chain_n      = 1;
    cfg.key          = &key;

    tls_server_ctx *s = NULL;
    struct wire w;
    memset(&w, 0, sizeof(w));
    w.fd = fd;
    tls_err e = tls_server_init(&s, &cfg, snd_cb, rcv_cb, &w);
    if (e != TLS_OK) { fprintf(stderr, "[srv] init: %s\n", tls_errstr(e)); return 92; }

    e = tls_server_accept(s);
    if (e != TLS_OK) {
        fprintf(stderr, "[srv] accept: %s\n", tls_errstr(e));
        tls_server_free(s);
        rsa_privkey_clear(&key);
        x509_store_free(&st);
        return 93;
    }

    tls_server_sni(s, sh->sni, sizeof(sh->sni));

    uint8_t req[8192];
    size_t  n = 0;
    e = tls_server_read(s, req, sizeof(req), &n);
    if (e != TLS_OK) {
        fprintf(stderr, "[srv] read: %s\n", tls_errstr(e));
        tls_server_free(s);
        rsa_privkey_clear(&key);
        x509_store_free(&st);
        return 94;
    }
    sh->req_len = (int)n;
    {
        /* 在解密后的明文里找 Host: 头 */
        char tmp[8192];
        size_t cp = n < sizeof(tmp) - 1 ? n : sizeof(tmp) - 1;
        memcpy(tmp, req, cp);
        tmp[cp] = '\0';
        sh->req_has_host  = (strstr(tmp, "Host: " REAL_HOST) != NULL) ? 1 : 0;
        sh->req_has_front = (strstr(tmp, "Host: " FRONT_DOMAIN) != NULL) ? 1 : 0;
    }

    e = tls_server_write(s, (const uint8_t *)RESP, strlen(RESP));
    if (e == TLS_OK) sh->resp_written = 1;

    tls_server_free(s);
    rsa_privkey_clear(&key);
    x509_store_free(&st);
    return e == TLS_OK ? 0 : 95;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);

    struct shared *sh = (struct shared *)mmap(NULL, sizeof(struct shared),
                                              PROT_READ | PROT_WRITE,
                                              MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (sh == MAP_FAILED) { printf("[FAIL] mmap\n"); return 1; }
    memset(sh, 0, sizeof(struct shared));

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { printf("[FAIL] socketpair\n"); return 1; }

    pid_t pid = fork();
    if (pid < 0) { printf("[FAIL] fork\n"); return 1; }
    if (pid == 0) {
        close(sv[0]);
        int rc = run_server(sv[1], sh);
        close(sv[1]);
        _exit(rc);
    }
    close(sv[1]);

    struct wire w;
    memset(&w, 0, sizeof(w));
    w.fd = sv[0];

    front_config fc;
    memset(&fc, 0, sizeof(fc));
    fc.front_domain = FRONT_DOMAIN;
    fc.real_host    = REAL_HOST;
    fc.path_prefix  = "/api/v1/";
    fc.ca_path      = FRONT_TLS_DATA "/ca.pem";
    fc.verify       = 1;
    fc.rng_seed     = 0x1234abcd;
    fc.http2        = 0;

    front_ctx *f = NULL;
    front_err fe = front_init(&f, &fc, snd_cb, rcv_cb, &w);
    CHECK(fe == FRONT_OK, "front_init 成功（%s）", front_errstr(fe));
    if (fe != FRONT_OK) { close(sv[0]); waitpid(pid, NULL, 0); return 1; }

    fe = front_connect(f);
    CHECK(fe == FRONT_OK, "front_connect 在真 TLS 上握手成功（%s）", front_errstr(fe));

    static const uint8_t frame[8] = { 0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4 };
    if (fe == FRONT_OK) {
        fe = front_send(f, frame, sizeof(frame));
        CHECK(fe == FRONT_OK, "front_send 成功（%s）", front_errstr(fe));

        uint8_t body[4096];
        size_t  blen = 0;
        front_err re = front_recv(f, body, sizeof(body), &blen);
        CHECK(re == FRONT_OK, "front_recv 成功（%s）", front_errstr(re));
        CHECK(blen == 5 && memcmp(body, "HELLO", 5) == 0,
              "回传帧经真 TLS 无损（%zu 字节）", blen);

        /* ---- 注入失败：这两条此前无人覆盖 ---- */
        w.fail_send = 1;
        fe = front_send(f, frame, sizeof(frame));
        CHECK(fe == FRONT_ERR_TLS, "tls_write 失败 -> FRONT_ERR_TLS（%s）", front_errstr(fe));
        w.fail_send = 0;

        w.fail_recv = 1;
        uint8_t b2[64];
        size_t  n2 = 0;
        re = front_recv(f, b2, sizeof(b2), &n2);
        CHECK(re == FRONT_ERR_TLS, "tls_read 失败 -> FRONT_ERR_TLS（%s）", front_errstr(re));
        w.fail_recv = 0;
    }

    front_free(f);
    close(sv[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    int rc = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    CHECK(rc == 0, "服务端全程无错（rc=%d）", rc);

    /* ---- 取证三条 ---- */
    CHECK(strcmp(sh->sni, FRONT_DOMAIN) == 0,
          "① 服务端观察到的 SNI == 前置域（'%s'）", sh->sni);
    CHECK(sh->req_has_host == 1,
          "② 真实主机出现在服务端解密后的 Host 头里（req=%d 字节）", sh->req_len);
    CHECK(sh->req_has_front == 0, "②' 请求里没有把前置域写成 Host（两者未串味）");

    {
        /* ③ 线路字节不含真实主机 —— 必须带正向对照 */
        CHECK(w.n > 0 && !w.ovf, "取证缓冲已记录线路字节（%zu 字节，ovf=%d）", w.n, w.ovf);
        int found_real = 0, found_front = 0;
        for (size_t i = 0; i + sizeof(REAL_HOST) - 1 <= w.n; i++) {
            /* SEC-CMP:PUBLIC: 在抓取的线路字节流里搜索已知域名串，用于取证断言 */
            if (memcmp(w.b + i, REAL_HOST, sizeof(REAL_HOST) - 1) == 0) { found_real = 1; break; }
        }
        for (size_t i = 0; i + sizeof(FRONT_DOMAIN) - 1 <= w.n; i++) {
            /* SEC-CMP:PUBLIC: 同上，正向对照：前置域应当可见（SNI 以明文携带） */
            if (memcmp(w.b + i, FRONT_DOMAIN, sizeof(FRONT_DOMAIN) - 1) == 0) { found_front = 1; break; }
        }
        CHECK(found_real == 0, "③ 线路字节中不含真实主机（域前置成立）");
        CHECK(found_front == 1, "③' 正向对照：前置域在线路上可见（证明扫描有效，非假阴性）");
    }

    printf("\n=== result: %d pass, %d fail ===\n", pass, fail);
    return fail ? 1 : 0;
}
