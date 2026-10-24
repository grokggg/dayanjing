/* tls_cli_tcp.c — 把自研 TLS 客户端挂到真实 TCP 上
 *
 * 为什么需要它：
 *   与 tls_srv_tcp.c 对称，用于把自家客户端接到 OpenSSL 的 s_server 上。
 *   闭环互操作只证明"两端一致"；对连 OpenSSL 才能证明"符合协议"。
 *
 * 用法：tls_cli_tcp <host> <port> <sni> [verify_host|-] [ca.pem|-] [alpn|-] [mode]
 *   mode = echo（默认）：发送 PAYLOAD，期待原样回显。
 *   mode = rev         ：发送 PAYLOAD+"\n"，期待"倒序"回显。
 *
 * 为什么需要 rev：OpenSSL 的 s_server 默认并不回显，它只把收到的数据打印到
 * 自己的 stdout。要用它验证"我们的读方向能解开 OpenSSL 加密的记录"，必须
 * 让它把数据发回来 —— -rev 是它唯一会回写的模式。倒序比对一样能证明往返
 * 逐字节正确，而且顺便排除了"把发送缓冲直接当接收结果"这类假通过。
 */
#include "tls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

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

static const char PAYLOAD[] = "dayanjing-interop-payload-0123456789";

/* 注意循环上界必须是 n/2。
 * 踩过的坑：写成 "i + 1 < n" 时，前后两半会各交换同一对一次，互相抵消，
 * 只剩首尾两个字节被换了一下 —— 看起来"倒序生效了"，实际上几乎没动。
 * 它是靠对端（真实 OpenSSL -rev）的返回值比对才暴露的：期望值算错时
 * 两边都在错，自己跟自己比永远比不出来。 */
static void rev_bytes(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n / 2; i++) {
        uint8_t t = p[i]; p[i] = p[n - 1 - i]; p[n - 1 - i] = t;
    }
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 4) {
        fprintf(stderr, "usage: %s <host> <port> <sni> [verify_host|-] [ca.pem|-] [alpn|-]\n", argv[0]);
        return 2;
    }
    const char *host = argv[1];
    int port = atoi(argv[2]);
    const char *sni = argv[3];
    const char *vh  = (argc > 4 && strcmp(argv[4], "-") != 0) ? argv[4] : NULL;
    const char *ca  = (argc > 5 && strcmp(argv[5], "-") != 0) ? argv[5] : NULL;
    const char *alpn= (argc > 6 && strcmp(argv[6], "-") != 0) ? argv[6] : NULL;
    const char *mode= (argc > 7) ? argv[7] : "echo";
    int        rev  = (strcmp(mode, "rev") == 0);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { fprintf(stderr, "CLI-FAIL socket\n"); return 3; }

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    /* 只接受字面 IPv4：工具不引入 gethostbyname，避免把 NSS 拖进来 */
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1) {
        fprintf(stderr, "CLI-FAIL addr\n"); return 4;
    }
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        fprintf(stderr, "CLI-FAIL connect\n"); return 5;
    }

    tls_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.sni         = sni;
    cfg.verify_host = vh;
    cfg.alpn        = alpn;
    cfg.ca_path     = ca;
    cfg.verify      = ca ? 1 : 0;

    tls_ctx *c = NULL;
    tls_err e = tls_client_init(&c, &cfg, snd_cb, rcv_cb, &fd);
    if (e != TLS_OK) { fprintf(stderr, "CLI-FAIL init %s\n", tls_errstr(e)); return 10; }

    e = tls_handshake(c);
    if (e != TLS_OK) {
        fprintf(stderr, "CLI-FAIL handshake %s\n", tls_errstr(e));
        tls_free(c); return 20;
    }
    printf("CLI-HANDSHAKE OK\n");
    fflush(stdout);

    char echoed[256];
    if (tls_sni_echo(c, echoed, sizeof(echoed)) >= 0) {
        printf("CLI-SNI-ECHO %s\n", echoed);
        fflush(stdout);
    }

    uint8_t sent[128];
    size_t  sent_len = strlen(PAYLOAD);
    memcpy(sent, PAYLOAD, sent_len);
    if (rev) { sent[sent_len++] = (uint8_t)'\n'; }
    /* OpenSSL 的 -rev 是"逐行倒序"：行尾换行符留在末尾，不参与倒序。
       实测确认：发 "abc\n" 回来是 "cba\n" 而不是 "\ncba"。 */
    size_t want_len = sent_len;
    uint8_t want[128];
    memcpy(want, sent, sent_len);
    if (rev) {
        size_t tl = sent_len - 1;          /* 去掉行尾换行 */
        rev_bytes(want, tl);
        want[tl] = (uint8_t)'\n';
    }

    e = tls_write(c, sent, sent_len);
    if (e != TLS_OK) { fprintf(stderr, "CLI-FAIL write %s\n", tls_errstr(e)); tls_free(c); return 30; }
    printf("CLI-WRITE %zu\n", sent_len);
    fflush(stdout);

    uint8_t buf[8192];
    size_t  n = 0;
    e = tls_read(c, buf, sizeof(buf), &n);
    if (e != TLS_OK) { fprintf(stderr, "CLI-FAIL read %s\n", tls_errstr(e)); tls_free(c); return 40; }

    int ok = (n == want_len) && memcmp(buf, want, n) == 0;
    if (!ok && n > 0) {
        printf("CLI-WANT ");
        for (size_t i = 0; i < want_len && i < 64; i++) {
            unsigned char ch = want[i];
            if (ch >= 32 && ch < 127) putchar(ch); else printf("\\x%02x", ch);
        }
        printf("\n");
        printf("CLI-GOT ");
        for (size_t i = 0; i < n && i < 64; i++) {
            unsigned char ch = buf[i];
            if (ch >= 32 && ch < 127) putchar(ch); else printf("\\x%02x", ch);
        }
        printf("\n");
        fflush(stdout);
    }
    printf("CLI-READ %zu %s\n", n, ok ? "MATCH" : "MISMATCH");
    fflush(stdout);

    e = tls_close(c);
    if (e != TLS_OK) { fprintf(stderr, "CLI-FAIL close %s\n", tls_errstr(e)); tls_free(c); return 50; }
    printf("CLI-CLOSE OK\n");
    fflush(stdout);

    tls_free(c);
    close(fd);
    printf("CLI-DONE %d\n", ok ? 0 : 1);
    fflush(stdout);
    return ok ? 0 : 1;
}
