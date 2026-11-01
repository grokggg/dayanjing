#define _DEFAULT_SOURCE
#include "transport.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

static int pass=0, fail=0;
#define CK(c,msg) do{ if(c){pass++;printf("[PASS] %s\n",msg);} \
    else {fail++;printf("[FAIL] %s\n",msg);} }while(0)

/* 一个最小 HTTP echo 服务端：把请求 body 里的 frame 原样回进响应 body */
static void echo_server(int listen_fd){
    for(;;){
        int c = accept(listen_fd, NULL, NULL);
        if(c < 0) break;
        char buf[8192]; ssize_t n = recv(c, buf, sizeof buf - 1, 0);
        if(n <= 0){ close(c); break; }
        buf[n] = 0;
        /* 找 body：\r\n\r\n 之后 */
        char *body = strstr(buf, "\r\n\r\n");
        size_t blen = body ? (size_t)(n - (body + 4 - buf)) : 0;
        unsigned char *b = body ? (unsigned char*)body + 4 : NULL;
        char resp[8192];
        int rl = snprintf(resp, sizeof resp,
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %zu\r\n\r\n", blen);
        memcpy(resp + rl, b, blen); rl += (int)blen;
        ssize_t w = send(c, resp, (size_t)rl, 0); (void)w;
        close(c);
        break;
    }
}

int main(void){
    printf("=== 03_transport 真实 socket 测试 ===\n");

    /* 1. listen port=0 内核分配 */
    int port = 0;
    int lfd = tx_tcp_listen(0, &port);
    CK(lfd >= 0 && port > 0, "listen 回环 port=0 内核分配成功");
    if(lfd < 0){ printf("total=%d pass=%d fail=%d\n",pass+fail,pass,fail); return 1; }

    /* 2. fork 出 echo 服务端 */
    pid_t pid = fork();
    if(pid == 0){ echo_server(lfd); _exit(0); }
    close(lfd);

    /* 3. 真实往返 */
    uint8_t frame[300]; for(size_t i=0;i<sizeof frame;i++) frame[i]=(uint8_t)(i*7+3);
    uint8_t out[600]; size_t olen = 0;
    int r = tx_roundtrip_http("127.0.0.1", port, frame, sizeof frame,
                              out, sizeof out, &olen, 3000);
    CK(r == 0, "HTTP 真实往返 connect→send→recv 成功");
    CK(olen == sizeof frame && memcmp(out, frame, sizeof frame) == 0,
       "往返帧字节级一致");

    /* 4. 连接不可达端口应失败 */
    int bad = tx_tcp_connect("127.0.0.1", 1, 500);
    CK(bad < 0, "连接不可达端口正确失败");

    /* 5. 非法 host 应失败（非 IP 不支持解析） */
    int bad2 = tx_tcp_connect("not-an-ip", 80, 500);
    CK(bad2 < 0, "非 IP host 被拒绝(不依赖 getaddrinfo)");

    /* 6. DNS UDP 查询构造可发送 */
    int usock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa; memset(&sa,0,sizeof sa);
    sa.sin_family=AF_INET; sa.sin_port=htons(53);
    sa.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    char label[512]; size_t ln = tx_dns_wrap(frame, 40, label, sizeof label);
    CK(ln > 0, "DNS base32 包装成功");
    ssize_t dw = tx_send_dns(usock, label, (struct sockaddr*)&sa, sizeof sa);
    CK(dw > 12, "DNS UDP 查询真实发出");
    close(usock);

    /* 7. ICMP raw socket：沙盒通常无权限，明确标记 */
    int unsupported = 0;
    int ifd = tx_icmp_socket(&unsupported);
    if(ifd >= 0){ close(ifd); CK(1, "ICMP raw socket 可用"); }
    else { CK(unsupported == 1, "ICMP raw socket 无权限(已明确标记 unsupported)"); }

    int st=0; waitpid(pid, &st, 0);
    printf("total=%d pass=%d fail=%d\n", pass+fail, pass, fail);
    return fail ? 1 : 0;
}
