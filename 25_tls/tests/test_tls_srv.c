/* test_tls_srv.c — 自研 TLS 服务端：与自家客户端的闭环互操作 + 取证
 *
 * 为什么必须是 fork + socketpair 而不是内存管道：
 *   两端都是阻塞式实现，握手是严格的一问一答。内存管道要模拟"对端还没
 *   写"只能返回 0，而 0 在本层的语义是 IO 失败 —— 会把"还没到"误判成
 *   "连接断了"。真实的 socket 才有"阻塞等待"这个语义。
 *
 * 取证断言（本文件最重要的部分）：
 *   服务端报出的 SNI 必须是前置域，而不是真实目标。域前置的全部价值就
 *   在这一条上；它只能由"站在 TLS 终结点上的观察者"来断言。
 */
#include "tls.h"
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
#include <sys/wait.h>

static int pass = 0, fail = 0;

#define CHECK(cond, ...)                                        \
    do {                                                        \
        if (cond) { pass++; printf("[PASS] "); }                \
        else      { fail++; printf("[FAIL] "); }                \
        printf(__VA_ARGS__);                                    \
        printf("\n");                                           \
    } while (0)

/* 回调：EINTR 必须重试。不重试的话，被信号打断的一次 read 会被当成
   连接断开，表现为偶发的握手失败，且与信号时机相关，极难复现。 */
static int snd_cb(void *arg, const uint8_t *d, size_t n) {
    int fd = *(int *)arg;
    for (;;) {
        ssize_t r = write(fd, d, n);
        if (r < 0 && errno == EINTR) continue;
        return (int)r;
    }
}

static int rcv_cb(void *arg, uint8_t *b, size_t cap) {
    int fd = *(int *)arg;
    for (;;) {
        ssize_t r = read(fd, b, cap);
        if (r < 0 && errno == EINTR) continue;
        return (int)r;
    }
}

/* ---- 服务端子进程 ----
 * 返回值直接用退出码：0 成功，非 0 区分失败阶段。父进程据此判断
 * "服务端是怎么死的"，而不只是"连接断了"。 */
static int run_server(int fd, rsa_privkey *key,
                      const uint8_t *der, size_t der_len, const char *alpn) {
    tls_server_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.chain[0]      = der;
    cfg.chain_len[0]  = der_len;
    cfg.chain_n       = 1;
    cfg.key           = key;
    cfg.alpn          = alpn;

    tls_server_ctx *s = NULL;
    tls_err e = tls_server_init(&s, &cfg, snd_cb, rcv_cb, &fd);
    if (e != TLS_OK) { fprintf(stderr, "[srv] init: %s\n", tls_errstr(e)); return 10; }

    e = tls_server_accept(s);
    if (e != TLS_OK) {
        fprintf(stderr, "[srv] accept: %s\n", tls_errstr(e));
        tls_server_free(s);
        return 20 + (int)e;
    }

    /* 先把自己观察到的 SNI 发出去 —— 这是域前置取证的观测点 */
    char sni[256];
    if (tls_server_sni(s, sni, sizeof(sni)) < 0) sni[0] = '\0';
    e = tls_server_write(s, (const uint8_t *)sni, strlen(sni));
    if (e != TLS_OK) { fprintf(stderr, "[srv] write sni: %s\n", tls_errstr(e)); tls_server_free(s); return 30; }

    uint8_t buf[4096];
    size_t  n = 0;
    e = tls_server_read(s, buf, sizeof(buf), &n);
    if (e != TLS_OK) { fprintf(stderr, "[srv] read: %s\n", tls_errstr(e)); tls_server_free(s); return 40; }

    e = tls_server_write(s, buf, n);
    if (e != TLS_OK) { fprintf(stderr, "[srv] write echo: %s\n", tls_errstr(e)); tls_server_free(s); return 50; }

    tls_server_free(s);
    return 0;
}

/* 跑一对（客户端=父，服务端=子）。返回客户端握手错误码，退出码写 *srv_rc。 */
static tls_err run_pair(const char *sni, const char *verify_host, const char *ca,
                        const char *cli_alpn, const char *srv_alpn,
                        int *srv_rc, char *got_sni, size_t got_cap) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return TLS_ERR_IO;
    pid_t pid = fork();
    if (pid < 0) return TLS_ERR_IO;

    if (pid == 0) {
        close(sv[0]);
        rsa_privkey key;
        x509_store st;
        memset(&st, 0, sizeof(st));
        int rc = 90;
        if (rsa_privkey_load_pem(TLS_TESTDATA "/leaf.key", &key) == RSA_OK &&
            x509_store_load_pem(&st, TLS_TESTDATA "/leaf.pem") == X509_OK && st.n > 0) {
            rc = run_server(sv[1], &key, st.e[0].der, st.e[0].der_len, srv_alpn);
            rsa_privkey_clear(&key);
        } else {
            fprintf(stderr, "[srv] 素材加载失败（先跑 make testdata）\n");
        }
        x509_store_free(&st);
        close(sv[1]);
        _exit(rc);
    }

    close(sv[1]);
    tls_config tc;
    memset(&tc, 0, sizeof(tc));
    tc.sni         = sni;
    tc.verify_host = verify_host;
    tc.alpn        = cli_alpn;
    tc.ca_path     = ca;
    tc.verify      = ca ? 1 : 0;

    tls_ctx *c = NULL;
    tls_err e  = tls_client_init(&c, &tc, snd_cb, rcv_cb, &sv[0]);
    if (e != TLS_OK) { close(sv[0]); waitpid(pid, NULL, 0); return e; }

    e = tls_handshake(c);
    if (e == TLS_OK) {
        uint8_t b[4096];
        size_t  n = 0;
        /* 服务端先发它观察到的 SNI */
        if (tls_read(c, b, sizeof(b), &n) == TLS_OK) {
            if (n < got_cap) { memcpy(got_sni, b, n); got_sni[n] = '\0'; }
        }
        const char *msg = "PING";
        if (tls_write(c, (const uint8_t *)msg, strlen(msg)) == TLS_OK) {
            n = 0;
            if (tls_read(c, b, sizeof(b), &n) == TLS_OK) {
                CHECK(n == 4 && memcmp(b, "PING", 4) == 0,
                      "应用数据双向通达（回显一致，n=%zu）", n);
            } else {
                CHECK(0, "应用数据回显读取失败");
            }
        } else {
            CHECK(0, "应用数据写出失败");
        }
    }
    tls_free(c);
    close(sv[0]);

    int st2 = 0;
    waitpid(pid, &st2, 0);
    *srv_rc = WIFEXITED(st2) ? WEXITSTATUS(st2) : -1;
    return e;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);

    /* 0. 私钥自测：解析与签名是否自洽（不需要网络） */
    {
        rsa_privkey key;
        memset(&key, 0, sizeof(key));
        rsa_err re = rsa_privkey_load_pem(TLS_TESTDATA "/leaf.key", &key);
        CHECK(re == RSA_OK, "PKCS#8 私钥解析（%s）", rsa_errstr(re));
        if (re == RSA_OK) {
            CHECK(tls_server_selftest_key(&key) == TLS_OK, "私钥签名->验签自洽");
            CHECK(bn_bitlen(&key.n) == 2048, "模数为 2048 位（%d）", bn_bitlen(&key.n));
            CHECK(key.e == 65537, "公钥指数 e=65537（%u）", key.e);
            rsa_privkey_clear(&key);
        } else {
            printf("[INFO] 素材缺失，先跑 make testdata\n");
            return 77;
        }
    }

    /* 1. 正向：完整互操作 + 证书校验 + 应用数据 + SNI 取证 */
    {
        int srv_rc = -1;
        char sni[256] = {0};
        tls_err e = run_pair("front.test", NULL, TLS_TESTDATA "/ca.pem",
                             NULL, NULL, &srv_rc, sni, sizeof(sni));
        CHECK(e == TLS_OK, "闭环握手成功（客户端 %s）", tls_errstr(e));
        CHECK(srv_rc == 0, "服务端全程无错（rc=%d）", srv_rc);
        CHECK(strcmp(sni, "front.test") == 0, "服务端观察到的 SNI == 前置域（'%s'）", sni);
        /* 域前置的正面证据：终结点看到的是前置域，不是真实目标 */
        CHECK(strcmp(sni, "c2.real.example") != 0, "SNI 不是真实目标（未泄露真实主机）");
    }

    /* 2. 证书主机名不符：必须失败，且失败原因可区分 */
    {
        int srv_rc = -1;
        tls_err e = run_pair("not.in.cert", NULL, TLS_TESTDATA "/ca.pem",
                             NULL, NULL, &srv_rc, NULL, 0);
        CHECK(e == TLS_ERR_CERT, "主机名不在 SAN 中 -> TLS_ERR_CERT（%s）", tls_errstr(e));
    }

    /* 3. 信任锚不对（拿叶子当 CA）：必须失败 */
    {
        int srv_rc = -1;
        tls_err e = run_pair("front.test", NULL, TLS_TESTDATA "/leaf.pem",
                             NULL, NULL, &srv_rc, NULL, 0);
        CHECK(e == TLS_ERR_CERT, "信任锚非 CA -> TLS_ERR_CERT（%s）", tls_errstr(e));
    }

    /* 4. 不校验证书时可连（verify=0 路径），且仍能正常收发 */
    {
        int srv_rc = -1;
        char sni[256] = {0};
        tls_err e = run_pair("anything.test", NULL, NULL,
                             NULL, NULL, &srv_rc, sni, sizeof(sni));
        CHECK(e == TLS_OK, "verify=0 时不校验证书也能握手（%s）", tls_errstr(e));
        CHECK(strcmp(sni, "anything.test") == 0, "verify=0 下 SNI 仍如实上报（'%s'）", sni);
    }

    /* 5. ALPN：服务端要求 h2 而客户端未通告 -> 必须显式失败。
       不做这条检查的话，客户端会以为协商成功，之后发 h2 preface 却等来
       HTTP/1.1 的响应，表现为"握手成功但第一个请求必失败"。 */
    {
        int srv_rc = -1;
        tls_err e = run_pair("front.test", NULL, TLS_TESTDATA "/ca.pem",
                             NULL, "h2", &srv_rc, NULL, 0);
        CHECK(e != TLS_OK, "服务端要求 h2 但客户端未通告 -> 握手失败（%s）", tls_errstr(e));
        CHECK(srv_rc != 0, "服务端在该情形下确实报错退出（rc=%d）", srv_rc);
        CHECK(srv_rc >= 20, "服务端失败点落在握手阶段（rc=%d，>=20 表示 accept 失败）", srv_rc);
    }

    /* 6. ALPN 一致：双方都 h2 -> 握手成功 */
    {
        int srv_rc = -1;
        char sni[256] = {0};
        tls_err e = run_pair("front.test", NULL, TLS_TESTDATA "/ca.pem",
                             "h2", "h2", &srv_rc, sni, sizeof(sni));
        CHECK(e == TLS_OK, "ALPN h2 双方一致 -> 握手成功（%s）", tls_errstr(e));
        CHECK(srv_rc == 0, "h2 情形下服务端无错（rc=%d）", srv_rc);
    }

    printf("\n=== result: %d pass, %d fail ===\n", pass, fail);
    return fail ? 1 : 0;
}
