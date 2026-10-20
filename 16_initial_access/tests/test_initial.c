#include "initial_access.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int tests_run = 0, tests_pass = 0;
#define CHECK(cond, name) do { \
    tests_run++; \
    if (cond) { tests_pass++; printf("[PASS] %s\n", name); } \
    else { printf("[FAIL] %s\n", name); } \
} while (0)

static void msleep(int ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

/* 起一个本地横幅/回显服务，返回监听 fd 与实际端口 */
static int start_banner_server(uint16_t *port_out) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int on = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET; sa.sin_port = 0;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(fd); return -1; }
    if (listen(fd, 4) < 0) { close(fd); return -1; }
    socklen_t len = sizeof(sa);
    getsockname(fd, (struct sockaddr *)&sa, &len);
    *port_out = ntohs(sa.sin_port);
    return fd;
}

static void banner_server_serve(int lfd, const char *payload) {
    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) return;
    char tmp[256];
    ssize_t n = recv(cfd, tmp, sizeof(tmp), 0); (void)n;
    send(cfd, payload, strlen(payload), 0);
    close(cfd);
}

/* 发一个 HTTP 请求并读回响应 */
static int http_req(int port, const char *req, char *out, size_t cap) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(fd); return -1; }
    send(fd, req, strlen(req), 0);
    size_t got = 0;
    for (;;) {
        if (got >= cap - 1) break;
        ssize_t n = recv(fd, out + got, cap - 1 - got, 0);
        if (n > 0) { got += (size_t)n; continue; }
        break;
    }
    out[got] = '\0';
    close(fd);
    return 0;
}

static int http_get(int port, const char *path, char *out, size_t cap) {
    char req[256];
    snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", path);
    return http_req(port, req, out, cap);
}

static int http_post(int port, const char *body, char *out, size_t cap) {
    char req[512];
    snprintf(req, sizeof(req),
        "POST /login HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(body), body);
    return http_req(port, req, out, cap);
}

int main(void) {
    const char *redir = "https://example.com/";
    char resp[1024];
    char creds[256];

    /* --- 1/2 监听与端口 --- */
    int lfd = phish_listen(0);
    CHECK(lfd >= 0, "phish_listen(0) 建立监听");
    int port = phish_listen_port(lfd);
    CHECK(port > 0, "phish_listen_port 取得实际端口");

    /* --- 3/4 GET 发表单 --- */
    if (port > 0 && http_get(port, "/login", resp, sizeof(resp)) == 0) {
        CHECK(strncmp(resp, "HTTP/1.1 200", 12) == 0, "GET /login 返回 200");
        CHECK(strstr(resp, "<form") != NULL, "GET 响应含登录表单");
    } else {
        CHECK(0, "GET /login 返回 200");
        CHECK(0, "GET 响应含登录表单");
    }

    /* --- 5 POST 返回 302 并跳转 --- */
    if (port > 0) {
        pid_t pid = fork();
        if (pid == 0) {
            phish_serve_once(lfd, redir, creds, sizeof(creds));
            _exit(0);
        } else {
            msleep(50);
            http_post(port, "user=admin&pass=s3cret", resp, sizeof(resp));
            CHECK(strncmp(resp, "HTTP/1.1 302", 12) == 0, "POST /login 返回 302");
            CHECK(strstr(resp, "Location: https://example.com/") != NULL,
                  "302 Location 指向真实站点");
            int st = 0; waitpid(pid, &st, 0);
        }
    }

    /* --- 6 凭证捕获正确性（走 pipe 带出子进程结果） --- */
    {
        int pfd[2];
        if (pipe(pfd) == 0) {
            pid_t pid = fork();
            if (pid == 0) {
                close(pfd[0]);
                char c[256] = {0};
                phish_serve_once(lfd, redir, c, sizeof(c));
                ssize_t w = write(pfd[1], c, strlen(c)); (void)w;
                close(pfd[1]);
                _exit(0);
            } else {
                close(pfd[1]);
                msleep(50);
                http_post(port, "user=admin&pass=s3cret", resp, sizeof(resp));
                char c[256] = {0};
                ssize_t r = read(pfd[0], c, sizeof(c) - 1);
                if (r > 0) c[r] = '\0';
                close(pfd[0]);
                int st = 0; waitpid(pid, &st, 0);
                CHECK(strcmp(c, "admin:s3cret") == 0, "捕获凭证 == admin:s3cret");
            }
        } else {
            CHECK(0, "捕获凭证 == admin:s3cret");
        }
    }

    /* --- 7/8 recon_banner 横幅 --- */
    uint16_t bport = 0;
    int blfd = start_banner_server(&bport);
    CHECK(blfd >= 0 && bport > 0, "横幅测试服务器启动");
    {
        pid_t pid = fork();
        if (pid == 0) {
            banner_server_serve(blfd, "SSH-2.0-TESTBANNER\r\n");
            _exit(0);
        } else {
            msleep(50);
            char out[256] = {0};
            int r = recon_banner("127.0.0.1", bport,
                                 "GET / HTTP/1.0\r\n\r\n", out, sizeof(out));
            CHECK(r == 0, "recon_banner 返回 0（收到数据）");
            CHECK(strstr(out, "SSH-2.0-TESTBANNER") != NULL, "recon_banner 取回横幅内容");
            int st = 0; waitpid(pid, &st, 0);
        }
    }
    close(blfd);

    /* --- 9 关闭端口应失败 --- */
    {
        char out[64] = {0};
        int r = recon_banner("127.0.0.1", 1, "x", out, sizeof(out));
        CHECK(r < 0, "recon_banner 对关闭端口返回负值");
    }

    /* --- 10/11 参数校验 --- */
    CHECK(recon_banner(NULL, 80, "x", NULL, 0) < 0, "recon_banner 空参数被拒");
    CHECK(phish_serve_once(-1, redir, creds, sizeof(creds)) < 0,
          "phish_serve_once 非法 fd 被拒");

    close(lfd);
    printf("\n%d/%d passed\n", tests_pass, tests_run);
    return (tests_pass == tests_run) ? 0 : 1;
}
