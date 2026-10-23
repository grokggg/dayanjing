/* winsdk_shim/winsock2.h — Winsock 2 最小等价声明
 *
 * 只为让 Windows 专属源码（drop_stager_win.c）能被 g++ 真实编译并被测试
 * 真跑。shim 实现转发到宿主真实 socket，因此 stager 的网络代码验证到的
 * 是"真的连上服务端、真的收到字节"，而不是 mock 返回成功。
 *
 * 刻意不提供：WSAAsyncSelect / IOCP / 重叠 IO / getaddrinfo。
 * stager 走同步阻塞语义，且必须避免 NSS（静态 glibc 的 NSS 会带入
 * dlopen 系列符号与 /etc/passwd，破坏归因自查）。
 */
#ifndef WSDK_SHIM_WINSOCK2_H
#define WSDK_SHIM_WINSOCK2_H

/*
 * 刻意不 include windows.h：shim 的 windows.h 是 C++ 头（用 cstdint），
 * C 编译器无法包含。Winsock 只需要下面这两个基础类型，自包含后同一份
 * 头文件在 C 与 C++ 下都能编译 —— stager 与测试服务端都必须是 C。
 */
#include <stddef.h>
#include <stdint.h>

#ifndef LPVOID_DEFINED_SHIM
#define LPVOID_DEFINED_SHIM
typedef void *LPVOID;
#endif
#ifndef BOOL_DEFINED_SHIM
#define BOOL_DEFINED_SHIM
typedef int BOOL;
#endif

typedef uint64_t SOCKET;                    /* 真机：UINT_PTR */
#define INVALID_SOCKET ((SOCKET)(uint64_t)(int64_t)-1)
#define SOCKET_ERROR   (-1)

#define WSADESCRIPTION_LEN 256
#define WSASYS_STATUS_LEN  128

typedef struct {
    unsigned short wVersion;
    unsigned short wHighVersion;
    char           szDescription[WSADESCRIPTION_LEN + 1];
    char           szSystemStatus[WSASYS_STATUS_LEN + 1];
    unsigned short iMaxSockets;
    unsigned short iMaxUdpDg;
    char          *lpVendorInfo;
} WSADATA;

#define INADDR_ANY   0u
#ifndef SOL_SOCKET
#define SOL_SOCKET   0xffff
#endif
#define SO_REUSEADDR 0x0004

#define AF_INET      2
#define SOCK_STREAM  1
#define IPPROTO_TCP  6

#define SD_RECEIVE   0
#define SD_SEND      1
#define SD_BOTH      2

/*
 * SOCKADDR_IN 的布局必须与宿主的 struct sockaddr_in 逐字段一致 ——
 * shim 实现直接把它递给真实 socket 调用，不做任何转换。
 *   sa_family_t sin_family  (unsigned short)
 *   in_port_t   sin_port    (unsigned short, 网络序)
 *   struct in_addr sin_addr (4 字节, 网络序)
 *   char sin_zero[8]
 */
typedef struct {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned long  sin_addr;
    char           sin_zero[8];
} SOCKADDR_IN;

typedef struct {
    unsigned short sa_family;
    char           sa_data[14];
} SOCKADDR;

#define MAKEWORD(a, b) \
    ((unsigned short)(((unsigned char)(a)) | (((unsigned short)((unsigned char)(b))) << 8)))

#ifdef __cplusplus
extern "C" {
#endif

int     WSAStartup(unsigned short ver, WSADATA *d);
int     WSACleanup(void);
int     WSAGetLastError(void);

SOCKET  socket(int af, int type, int proto);
int     bind(SOCKET s, const SOCKADDR *name, int namelen);
int     listen(SOCKET s, int backlog);
SOCKET  accept(SOCKET s, SOCKADDR *addr, int *addrlen);
int     setsockopt(SOCKET s, int level, int optname, const char *val, int len);
int     getsockname(SOCKET s, SOCKADDR *name, int *namelen);
int     shutdown_fd(int fd);
int     connect(SOCKET s, const SOCKADDR *name, int namelen);
int     send(SOCKET s, const char *buf, int len, int flags);
int     recv(SOCKET s, char *buf, int len, int flags);
int     shutdown(SOCKET s, int how);
int     closesocket(SOCKET s);

unsigned short htons(unsigned short v);
unsigned short ntohs(unsigned short v);
unsigned long  inet_addr(const char *cp);

#ifdef __cplusplus
}
#endif

#endif /* WSDK_SHIM_WINSOCK2_H */
