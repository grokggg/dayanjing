/* tls_srv_tcp.c — 把自研 TLS 服务端挂到真实 TCP 端口上
 *
 * 为什么需要它：
 *   test_tls_srv.c 只做"自家客户端 <-> 自家服务端"的闭环。闭环证明的是
 *   "两端一致"，不证明"符合协议"。真实部署里回源之后接的是真实世界
 *   的客户端（浏览器、curl、OpenSSL），它们发的 ClientHello 带着几十个
 *   扩展。只有在真实端口上对连一次，才能证明我们的解析器不会在真实
 *   ClientHello 上崩掉。
 *
 * 用法：tls_srv_tcp <port> <chain.pem> <key.pem> [alpn]
 *   握手完成后：写出服务端观察到的 SNI 与 ALPN，随后回显客户端发来的
 *   全部字节。退出码区分失败阶段，便于驱动脚本判断"死在哪一步"。
 */
#include "tls.h"
#include "tls_server.h"
#include "x509.h"
#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 4) {
        fprintf(stderr, "usage: %s <port> <chain.pem> <key.pem> [alpn]\n", argv[0]);
        return 2;
    }
    int port = atoi(argv[1]);
    const char *chain_pem = argv[2], *key_pem = argv[3];
    const char *alpn = (argc > 4 && strcmp(argv[4], "-") != 0) ? argv[4] : NULL;

    rsa_privkey key;
    x509_store st;
    memset(&st, 0, sizeof(st));

    if (rsa_privkey_load_pem(key_pem, &key) != RSA_OK) {
        fprintf(stderr, "SRV-FAIL key\n"); return 3;
    }
    if (x509_store_load_pem(&st, chain_pem) != X509_OK || st.n == 0) {
        fprintf(stderr, "SRV-FAIL cert\n"); return 4;
    }

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) { fprintf(stderr, "SRV-FAIL socket\n"); return 5; }
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    if (bind(ls, (struct sockaddr *)&a, sizeof(a)) != 0) {
        fprintf(stderr, "SRV-FAIL bind\n"); return 6;
    }
    if (listen(ls, 4) != 0) { fprintf(stderr, "SRV-FAIL listen\n"); return 7; }

    /* 端口就绪信号：驱动脚本等到这一行再启动客户端，消除连接时序竞争 */
    printf("SRV-LISTEN %d\n", port);
    fflush(stdout);

    int fd = accept(ls, NULL, NULL);
    if (fd < 0) { fprintf(stderr, "SRV-FAIL accept\n"); return 8; }
    close(ls);

    tls_server_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    for (int i = 0; i < st.n && i < X509_CHAIN_MAX; i++) {
        cfg.chain[i]     = st.e[i].der;
        cfg.chain_len[i] = st.e[i].der_len;
    }
    cfg.chain_n = st.n > X509_CHAIN_MAX ? X509_CHAIN_MAX : st.n;
    cfg.key     = &key;
    cfg.alpn    = alpn;

    tls_server_ctx *s = NULL;
    tls_err e = tls_server_init(&s, &cfg, snd_cb, rcv_cb, &fd);
    if (e != TLS_OK) { fprintf(stderr, "SRV-FAIL init %s\n", tls_errstr(e)); return 10; }

    e = tls_server_accept(s);
    if (e != TLS_OK) {
        fprintf(stderr, "SRV-FAIL accept-tls %s\n", tls_errstr(e));
        tls_server_free(s); return 20;
    }
    printf("SRV-HANDSHAKE OK\n");
    fflush(stdout);

    char sni[256], neg[64];
    if (tls_server_sni(s, sni, sizeof(sni)) < 0) sni[0] = '\0';
    if (tls_server_alpn(s, neg, sizeof(neg)) < 0) neg[0] = '\0';
    printf("SRV-SNI %s\n", sni);
    printf("SRV-ALPN %s\n", neg[0] ? neg : "(none)");
    fflush(stdout);

    /* 回显：把收到的每一批字节原样写回，让对端能独立验证往返 */
    uint8_t buf[8192];
    size_t  n = 0;
    e = tls_server_read(s, buf, sizeof(buf), &n);
    if (e != TLS_OK) {
        fprintf(stderr, "SRV-FAIL read %s\n", tls_errstr(e));
        tls_server_free(s); return 30;
    }
    printf("SRV-READ %zu\n", n);
    fflush(stdout);
    if (n > 0) {
        e = tls_server_write(s, buf, n);
        if (e != TLS_OK) {
            fprintf(stderr, "SRV-FAIL write %s\n", tls_errstr(e));
            tls_server_free(s); return 40;
        }
    }
    printf("SRV-ECHO OK\n");
    fflush(stdout);

    /* 必须显式 close_notify：不发的话 OpenSSL 一侧报 unexpected eof，
       把一次完全正确的会话判成异常结束 */
    e = tls_server_close(s);
    if (e != TLS_OK) { fprintf(stderr, "SRV-FAIL close %s\n", tls_errstr(e)); tls_server_free(s); return 50; }
    printf("SRV-CLOSE OK\n");
    fflush(stdout);

    tls_server_free(s);
    rsa_privkey_clear(&key);
    x509_store_free(&st);
    close(fd);
    printf("SRV-DONE 0\n");
    fflush(stdout);
    return 0;
}
