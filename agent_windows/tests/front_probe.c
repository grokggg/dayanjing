/* front_probe.c — 前置节点观测器（域前置端到端验证的服务端侧）
 *
 * 用途：站在一个**真实 TLS 终结点**上，观测 camd 以 front:// 出口发来的
 * 流量，并输出可被外部断言读取的事实。它扮演的是"前置节点"，因此能同时
 * 看到两样东西：
 *   —— 加密外的：SNI、证书校验用的主机名、线路上每一个字节
 *   —— 加密内的：解密后的 HTTP 请求（含 Host 头与请求体）
 *
 * 为什么要独立成一个进程而不是单进程内 mock：
 *   用 mock 传输层验"线路上不含真实主机"是自证——TLS 记录层根本没参与，
 *   那条断言只能证明字节没拼错，证明不了加密生效。这里放真实服务端，
 *   SNI 由服务端在握手阶段实际读出。
 *
 * 输出（stdout，供守卫脚本解析）：
 *   SNI=<v>          服务端在 TLS 终结点上看到的主机名（应当=前置域）
 *   HOST_REAL=0/1    解密后请求里是否出现 "Host: <real_host>"
 *   HOST_FRONT=0/1   解密后请求里是否出现 "Host: <front_domain>"（应当=0）
 *   BODY=<n>         HTTP 请求体字节数（应当>0，否则等于没收到画面）
 *   WIRE_REAL=0/1    线路全部字节中是否出现真实主机（应当=0）
 *   WIRE_FRONT=0/1   线路全部字节中是否出现前置域（应当=1，正向对照）
 *
 * 最后一条不可省：若扫描压根没记录到字节，"未命中"就是假阴性。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "tls_server.h"
#include "x509.h"
#include "rsa.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define WIRE_CAP (1 << 20)

struct wire {
    int     fd;
    uint8_t b[WIRE_CAP];
    size_t  n;
    int     ovf;
};

static void wire_log(struct wire *w, const uint8_t *d, size_t n)
{
    if (w->n + n > WIRE_CAP) { w->ovf = 1; return; }
    memcpy(w->b + w->n, d, n);
    w->n += n;
}

static int snd_cb(void *arg, const uint8_t *d, size_t n)
{
    struct wire *w = (struct wire *)arg;
    ssize_t r = send(w->fd, d, n, MSG_NOSIGNAL);
    if (r < 0) return -1;
    wire_log(w, d, (size_t)r);
    return (int)r;
}

static int rcv_cb(void *arg, uint8_t *b, size_t cap)
{
    struct wire *w = (struct wire *)arg;
    ssize_t r = recv(w->fd, b, cap, 0);
    if (r < 0) return -1;
    wire_log(w, b, (size_t)r);
    return (int)r;
}

static const char *RESP =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/octet-stream\r\n"
    "Content-Length: 2\r\n"
    "\r\n"
    "ok";

static int in_wire(const struct wire *w, const char *s)
{
    size_t sl = strlen(s);
    if (sl == 0 || w->n < sl) return 0;
    for (size_t i = 0; i + sl <= w->n; i++)
        if (memcmp(w->b + i, s, sl) == 0) return 1;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr, "用法: %s <port> <real_host> <front_domain> <data_dir>\n", argv[0]);
        return 2;
    }
    int         port   = atoi(argv[1]);
    const char *real   = argv[2];
    const char *front  = argv[3];
    const char *ddir   = argv[4];

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) { perror("socket"); return 3; }
    int one = 1;
    (void)setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port        = htons((uint16_t)port);
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) != 0) { perror("bind"); return 4; }
    if (listen(ls, 4) != 0) { perror("listen"); return 5; }

    /* 就绪即输出，供驱动脚本判断可以启动 camd */
    printf("READY\n");
    fflush(stdout);

    int fd = accept(ls, NULL, NULL);
    if (fd < 0) { perror("accept"); return 6; }

    char key_path[4096], cert_path[4096];
    snprintf(key_path,  sizeof key_path,  "%s/leaf.key", ddir);
    snprintf(cert_path, sizeof cert_path, "%s/leaf.pem", ddir);

    rsa_privkey key;
    x509_store  st;
    memset(&key, 0, sizeof key);
    memset(&st,  0, sizeof st);

    if (rsa_privkey_load_pem(key_path, &key) != RSA_OK) {
        fprintf(stderr, "[probe] 私钥加载失败: %s\n", key_path); return 90;
    }
    if (x509_store_load_pem(&st, cert_path) != X509_OK || st.n == 0) {
        fprintf(stderr, "[probe] 证书加载失败: %s\n", cert_path); return 91;
    }

    tls_server_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.chain[0]     = st.e[0].der;
    cfg.chain_len[0] = st.e[0].der_len;
    cfg.chain_n      = 1;
    cfg.key          = &key;

    struct wire w;
    memset(&w, 0, sizeof w);
    w.fd = fd;

    tls_server_ctx *s = NULL;
    tls_err e = tls_server_init(&s, &cfg, snd_cb, rcv_cb, &w);
    if (e != TLS_OK) { fprintf(stderr, "[probe] init: %s\n", tls_errstr(e)); return 92; }

    e = tls_server_accept(s);
    if (e != TLS_OK) { fprintf(stderr, "[probe] accept: %s\n", tls_errstr(e)); return 93; }

    char sni[256];
    memset(sni, 0, sizeof sni);
    tls_server_sni(s, sni, sizeof sni);

    uint8_t req[65536];
    size_t  n = 0;
    e = tls_server_read(s, req, sizeof req, &n);
    if (e != TLS_OK) {
        fprintf(stderr, "[probe] read: %s\n", tls_errstr(e));
        printf("SNI=%s\nHOST_REAL=0\nHOST_FRONT=0\nBODY=0\n", sni);
        fflush(stdout);
        return 94;
    }

    /* 解密后的请求：找 Host 头与请求体长度 */
    char   hostbuf[512];
    size_t cp = n < sizeof(hostbuf) - 1 ? n : sizeof(hostbuf) - 1;
    memcpy(hostbuf, req, cp);
    hostbuf[cp] = '\0';

    char needle_real[600], needle_front[600];
    snprintf(needle_real,  sizeof needle_real,  "Host: %s", real);
    snprintf(needle_front, sizeof needle_front, "Host: %s", front);

    int host_real  = (strstr(hostbuf, needle_real)  != NULL) ? 1 : 0;
    int host_front = (strstr(hostbuf, needle_front) != NULL) ? 1 : 0;

    size_t body = 0;
    {
        /* HTTP 头结束标志 \r\n\r\n 之后的字节数即为请求体 */
        for (size_t i = 0; i + 3 < n; i++) {
            if (req[i] == '\r' && req[i+1] == '\n' && req[i+2] == '\r' && req[i+3] == '\n') {
                body = n - (i + 4);
                break;
            }
        }
    }

    (void)tls_server_write(s, (const uint8_t *)RESP, strlen(RESP));
    (void)tls_server_close(s);
    /* 收完请求后再读一次，观测对端**如何结束**这场会话。
     *
     * 这是 C2 侧唯一的关闭语义来源：缺 close_notify 时，这里拿到的是
     * 传输层错误（连接被关但没有任何告警记录），而字节其实已经全收到了。
     * 那种情形下 C2 无法区分"采完一批正常收尾"与"链路中途被掐断"——
     * 正是本观测器要消灭的歧义。 */
    {
        uint8_t  tail[4];
        size_t   tn = 0;
        uint8_t  lv = 0, ds = 0;
        tls_err  e2 = tls_server_read(s, tail, sizeof tail, &tn);
        tls_server_last_alert(s, &lv, &ds);
        /* close_notify 是 (warning=1, desc=0)。只看返回码分不出它和致命
           告警——两者都返回 TLS_ERR_ALERT，故按字节判。 */
        int got_cn = (e2 == TLS_ERR_ALERT && lv == 1 && ds == 0);
        int got_fatal = (e2 == TLS_ERR_ALERT && lv == 2);
        printf("CLOSE_NOTIFY=%d\n", got_cn);
        printf("CLOSE_FATAL=%d\n", got_fatal);
        printf("CLOSE_RC=%d\n", (int)e2);
        printf("CLOSE_ALERT=%d,%d\n", (int)lv, (int)ds);
        fflush(stdout);
    }

    tls_server_free(s);
    rsa_privkey_clear(&key);
    x509_store_free(&st);
    close(fd);
    close(ls);

    printf("SNI=%s\n", sni);
    printf("HOST_REAL=%d\n", host_real);
    printf("HOST_FRONT=%d\n", host_front);
    printf("BODY=%zu\n", body);
    printf("WIRE_REAL=%d\n", in_wire(&w, real));
    printf("WIRE_FRONT=%d\n", in_wire(&w, front));
    printf("WIRE_N=%zu\n", w.n);
    fflush(stdout);
    return 0;
}
