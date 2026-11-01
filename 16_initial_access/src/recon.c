#include "initial_access.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int recon_banner(const char *host_ip, uint16_t port,
                 const char *request, char *out, size_t out_cap) {
    if (!host_ip || !request || !out || out_cap == 0) return -1;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    /* 只接受 IP 字面量：不调 getaddrinfo，规避静态链接告警与解析依赖 */
    if (inet_pton(AF_INET, host_ip, &sa.sin_addr) != 1) return -2;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -3;

    struct timeval tv;
    tv.tv_sec = 3; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(fd); return -4; }

    size_t rlen = strlen(request);
    size_t off = 0;
    while (off < rlen) {
        ssize_t n = send(fd, request + off, rlen - off, 0);
        if (n <= 0) { close(fd); return -5; }
        off += (size_t)n;
    }

    size_t got = 0;
    for (;;) {
        if (got >= out_cap - 1) break;
        ssize_t n = recv(fd, out + got, out_cap - 1 - got, 0);
        if (n > 0) { got += (size_t)n; continue; }
        break; /* 超时或对端关闭 */
    }
    out[got] = '\0';
    close(fd);
    return (got > 0) ? 0 : -6;
}
