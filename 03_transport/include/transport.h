#ifndef TRANSPORT_H
#define TRANSPORT_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

typedef enum { TX_HTTP = 0, TX_DNS, TX_ICMP } tx_kind_t;

/* ---- 编解码（原有） ---- */
size_t tx_http_wrap(const uint8_t *frame, size_t len, uint8_t *out, size_t cap);
int tx_http_unwrap(const uint8_t *resp, size_t rlen, uint8_t *out, size_t *outlen);
size_t tx_dns_wrap(const uint8_t *frame, size_t len, char *out, size_t cap);
int tx_dns_unwrap(const char *label, uint8_t *out, size_t *outlen);
size_t tx_icmp_wrap(const uint8_t *frame, size_t len, uint8_t *out, size_t cap);
int tx_icmp_unwrap(const uint8_t *payload, size_t plen, uint8_t *out, size_t *outlen);

/* ---- 真实 socket 收发（新增完整能力） ---- */

/* 建立 TCP 连接；成功返回 fd，-1 失败。timeout_ms<=0 用默认 5s */
int  tx_tcp_connect(const char *host, int port, int timeout_ms);

/* 监听回环端口；port=0 由内核分配，*port 回填真实端口。成功返回 fd */
int  tx_tcp_listen(int port, int *out_port);

/* accept，成功返回新 fd */
int  tx_tcp_accept(int listen_fd, int timeout_ms);

/* 通过已连接 fd 发一帧：HTTP 包装后 POST。成功返回发送字节数 */
ssize_t tx_send_http(int fd, const uint8_t *frame, size_t len);
/* 从 fd 收一帧：读 HTTP 响应并解出 frame。成功 0，*outlen 为帧长 */
int     tx_recv_http(int fd, uint8_t *out, size_t cap, size_t *outlen, int timeout_ms);

/* 完整往返：connect→send→recv→close。成功 0 */
int     tx_roundtrip_http(const char *host, int port,
                          const uint8_t *frame, size_t len,
                          uint8_t *out, size_t cap, size_t *outlen, int timeout_ms);

/* DNS over UDP：向指定解析器发查询（已包装的 label）。成功返回响应字节数 */
ssize_t tx_send_dns(int sock, const char *label,
                    const struct sockaddr *srv, socklen_t slen);

/* ICMP：尝试开 raw socket；沙盒通常无 CAP_NET_RAW，失败返回 -1 并置 *unsupported */
int     tx_icmp_socket(int *unsupported);

void    tx_close(int fd);
#endif
