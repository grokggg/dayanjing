#ifndef P2P_RESOLV_H
#define P2P_RESOLV_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

/* 自研 A 记录解析器（RFC 1035 over UDP），取代 getaddrinfo。

   为什么要自己实现：
     静态链接时 glibc 会警告 getaddrinfo 在目标机可能需要运行时动态库
     （NSS/gconv 在精简容器或 musl 环境常缺失，表现为 "node 起不来但 ping 能通"）。
     本模块只依赖 socket + UDP，不依赖 libc 解析器、不读 NSS、不 dlopen。

   设计：
     - 主机名若已是点分十进制 IPv4，直接解析，不发任何报文（无外泄 DNS 查询）
     - 解析器来源优先级：显式传入 > 环境变量 P2P_RESOLVER > /etc/resolv.conf
     - 支持 CNAME 追赶，带深度上限防环
     - 支持 DNS 名字压缩指针（0xC0），带跳转次数上限防解压炸弹
     - 全程超时可控，失败返回负错误码，不做阻塞重试 */

#define P2P_RESOLV_MAXHOST 253

typedef enum {
    P2P_RESOLV_OK        =  0,
    P2P_RESOLV_ERR_ARGS  = -1,
    P2P_RESOLV_ERR_SOCK  = -2,
    P2P_RESOLV_ERR_SEND  = -3,
    P2P_RESOLV_ERR_RECV  = -4,
    P2P_RESOLV_ERR_PROTO = -5,
    P2P_RESOLV_ERR_NOADDR= -6,
    P2P_RESOLV_ERR_LOOP  = -7,
    P2P_RESOLV_ERR_NORES = -8,
} p2p_resolv_err_t;

const char *p2p_resolv_errstr(int e);

/* 判断是否为点分十进制 IPv4 字面量；是则直接填 *out（网络序） */
int p2p_host_is_ipv4(const char *host, uint32_t *out);

/* 取默认解析器：环境变量 P2P_RESOLVER 优先，其次 /etc/resolv.conf 第一个 nameserver */
int p2p_resolv_default(char *out, size_t cap);

/* 解析主机名 -> IPv4（网络序）。host 可以是字面量或域名。
   resolver 为 NULL 时用默认解析器。timeout_ms <= 0 用默认 3000 */
int p2p_resolve_a(const char *host, const char *resolver,
                  int timeout_ms, uint32_t *out);

/* 便捷：直接产出可直接 connect 的 sockaddr_in（内部调用 p2p_resolve_a） */
int p2p_resolve_sa(const char *host, uint16_t port,
                   const char *resolver, int timeout_ms,
                   struct sockaddr_in *out);

#endif
