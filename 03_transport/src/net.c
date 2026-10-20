#define _DEFAULT_SOURCE
#include "transport.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

void tx_close(int fd){ if(fd>=0) close(fd); }

static int set_nonblock(int fd){
    int fl = fcntl(fd, F_GETFL, 0);
    if(fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int wait_rw(int fd, int for_write, int timeout_ms){
    struct timeval tv; fd_set s;
    if(timeout_ms <= 0) timeout_ms = 5000;
    tv.tv_sec = timeout_ms/1000; tv.tv_usec = (timeout_ms%1000)*1000;
    FD_ZERO(&s); FD_SET(fd, &s);
    if(for_write) return select(fd+1, NULL, &s, NULL, &tv);
    return select(fd+1, &s, NULL, NULL, &tv);
}

int tx_tcp_connect(const char *host, int port, int timeout_ms){
    if(!host || port <= 0) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) return -1;
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port);
    if(inet_pton(AF_INET, host, &sa.sin_addr) != 1){
        /* 非 IP：不支持 DNS 解析（避免依赖 getaddrinfo 的阻塞与不确定性） */
        close(fd); errno = EINVAL; return -1;
    }
    if(set_nonblock(fd) < 0){ close(fd); return -1; }
    if(connect(fd, (struct sockaddr*)&sa, sizeof sa) < 0){
        if(errno != EINPROGRESS){ int e=errno; close(fd); errno=e; return -1; }
        int r = wait_rw(fd, 1, timeout_ms);
        if(r <= 0){ close(fd); errno = ETIMEDOUT; return -1; }
        int err = 0; socklen_t el = sizeof err;
        if(getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err){
            close(fd); errno = err ? err : ECONNREFUSED; return -1;
        }
    }
    return fd;
}

int tx_tcp_listen(int port, int *out_port){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) return -1;
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   /* 只绑回环，不暴露 */
    sa.sin_port = htons((uint16_t)port);
    if(bind(fd, (struct sockaddr*)&sa, sizeof sa) < 0){ close(fd); return -1; }
    if(listen(fd, 8) < 0){ close(fd); return -1; }
    if(out_port){
        struct sockaddr_in got; socklen_t gl = sizeof got;
        if(getsockname(fd, (struct sockaddr*)&got, &gl) == 0)
            *out_port = ntohs(got.sin_port);
    }
    return fd;
}

int tx_tcp_accept(int listen_fd, int timeout_ms){
    if(listen_fd < 0) return -1;
    int r = wait_rw(listen_fd, 0, timeout_ms);
    if(r <= 0){ errno = ETIMEDOUT; return -1; }
    return accept(listen_fd, NULL, NULL);
}

ssize_t tx_send_http(int fd, const uint8_t *frame, size_t len){
    uint8_t buf[4096];
    size_t n = tx_http_wrap(frame, len, buf, sizeof buf);
    if(n == 0) return -1;
    size_t sent = 0;
    while(sent < n){
        ssize_t w = send(fd, buf + sent, n - sent, MSG_NOSIGNAL);
        if(w < 0){ if(errno == EINTR) continue; return -1; }
        sent += (size_t)w;
    }
    return (ssize_t)sent;
}

int tx_recv_http(int fd, uint8_t *out, size_t cap, size_t *outlen, int timeout_ms){
    if(!out || !outlen || cap == 0) return -1;
    uint8_t buf[8192]; size_t got = 0;
    for(;;){
        /* 已收到完整响应（头部结束且 body 足够）则停 */
        if(got >= 4){
            size_t i; int found = 0;
            for(i = 0; i + 4 <= got; i++)
                if(buf[i]=='\r'&&buf[i+1]=='\n'&&buf[i+2]=='\r'&&buf[i+3]=='\n'){ found=1; break; }
            if(found) break;
        }
        if(got >= sizeof buf) break;
        int r = wait_rw(fd, 0, timeout_ms);
        if(r <= 0) break;
        ssize_t n = recv(fd, buf + got, sizeof buf - got, 0);
        if(n < 0){ if(errno == EINTR) continue; break; }
        if(n == 0) break;
        got += (size_t)n;
    }
    if(got == 0) return -1;
    size_t ol = cap;
    if(tx_http_unwrap(buf, got, out, &ol) != 0) return -1;
    *outlen = ol;
    return 0;
}

int tx_roundtrip_http(const char *host, int port,
                      const uint8_t *frame, size_t len,
                      uint8_t *out, size_t cap, size_t *outlen, int timeout_ms){
    int fd = tx_tcp_connect(host, port, timeout_ms);
    if(fd < 0) return -1;
    if(tx_send_http(fd, frame, len) < 0){ close(fd); return -1; }
    int r = tx_recv_http(fd, out, cap, outlen, timeout_ms);
    close(fd);
    return r;
}

ssize_t tx_send_dns(int sock, const char *label,
                    const struct sockaddr *srv, socklen_t slen){
    /* 构造最小 DNS 查询：hdr(12) + QNAME(label) + QTYPE(2) + QCLASS(2) */
    uint8_t q[512];
    if(!label) return -1;
    size_t ll = strlen(label);
    if(ll == 0 || ll > 200) return -1;
    memset(q, 0, sizeof q);
    uint16_t id = (uint16_t)(getpid() & 0xffff);
    q[0] = (uint8_t)(id >> 8); q[1] = (uint8_t)(id & 0xff);
    q[2] = 0x01;                    /* RD=1 */
    q[5] = 0x01;                    /* QDCOUNT=1 */
    size_t p = 12;
    /* label 拆成 DNS 标签（每节 <=63） */
    const char *s = label; size_t remain = ll;
    while(remain > 0){
        size_t seg = remain > 63 ? 63 : remain;
        if(p + 1 + seg > sizeof q - 4) return -1;
        q[p++] = (uint8_t)seg;
        memcpy(q + p, s, seg); p += seg; s += seg; remain -= seg;
    }
    q[p++] = 0;                      /* 根标签 */
    q[p++] = 0; q[p++] = 0x10;       /* QTYPE = TXT(16) */
    q[p++] = 0; q[p++] = 0x01;       /* QCLASS = IN */
    ssize_t w = sendto(sock, q, p, 0, srv, slen);
    return w < 0 ? -1 : (ssize_t)p;
}

int tx_icmp_socket(int *unsupported){
    if(unsupported) *unsupported = 0;
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(fd < 0){
        if(unsupported && (errno == EPERM || errno == EACCES)) *unsupported = 1;
        return -1;
    }
    return fd;
}
