/* winsdk_shim/shim_winsock.cpp — Winsock / 虚拟内存的 shim 实现
 *
 * 关键设计：转发到宿主**真实** socket，而不是返回伪造的成功。
 *
 * 为什么：stager 是投送到目标的第一段代码，它的网络路径若只在 mock 下
 * 跑通，"能拉到块"就没有任何证据价值 —— mock 恒返回成功时，请求格式错、
 * HTTP 解析错、块序错全都测不出来。转发真实 socket 后，stager 必须真的
 * 连上 25_deploy 的 drop_serve、真的解析真实 HTTP 响应才能拿到块。
 *
 * 为什么用 syscall(2) 而不是直接调 POSIX 函数：
 *   Winsock 的 socket/connect/send/recv 与宿主的 POSIX 同名函数签名不同，
 *   若同时 include <sys/socket.h> 并定义 extern "C" 同名函数，会因 C 语言
 *   不允许重载而编译失败。用 syscall 直接陷入内核可完全避开符号冲突，
 *   同时因为 sockaddr 布局是稳定 ABI，SOCKADDR_IN 可以原样递下去。
 *
 * 虚拟内存：VirtualAlloc/VirtualProtect/VirtualFree 映射到 mmap/mprotect/
 * munmap，使"权限切换"这一 Windows 语义能被真实断言（反射装载的节区设权
 * 是本链路的安全要点，不能是空转）。
 */
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstring>

#include <windows.h>
#include <winsock2.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/* ---------------- Winsock ---------------- */

extern "C" int WSAStartup(unsigned short ver, WSADATA *d)
{
    if (!d) return 1001;                      /* WSASYSNOTREADY 量级，仅表示失败 */
    std::memset(d, 0, sizeof(*d));
    d->wVersion = ver;
    d->wHighVersion = ver;
    d->iMaxSockets = 32767;
    return 0;
}

extern "C" int WSACleanup(void) { return 0; }

extern "C" int WSAGetLastError(void) { return 0; }

extern "C" SOCKET socket(int af, int type, int proto)
{
    long r = syscall(SYS_socket, af, type, proto);
    if (r < 0) return INVALID_SOCKET;
    return (SOCKET)r;
}

extern "C" int bind(SOCKET s, const SOCKADDR *name, int namelen)
{
    if ((int64_t)s < 0) return SOCKET_ERROR;
    long r = syscall(SYS_bind, (int)s, name, (unsigned)namelen);
    return r < 0 ? SOCKET_ERROR : 0;
}

extern "C" int listen(SOCKET s, int backlog)
{
    if ((int64_t)s < 0) return SOCKET_ERROR;
    long r = syscall(SYS_listen, (int)s, backlog);
    return r < 0 ? SOCKET_ERROR : 0;
}

extern "C" SOCKET accept(SOCKET s, SOCKADDR *addr, int *addrlen)
{
    if ((int64_t)s < 0) return INVALID_SOCKET;
    long r = syscall(SYS_accept4, (int)s, addr, addrlen, 0);
    if (r < 0) r = syscall(SYS_accept, (int)s, addr, addrlen);
    return r < 0 ? INVALID_SOCKET : (SOCKET)r;
}

extern "C" int setsockopt(SOCKET s, int level, int optname, const char *val,
                         int len)
{
    if ((int64_t)s < 0) return SOCKET_ERROR;
    long r = syscall(SYS_setsockopt, (int)s, level, optname, val, (unsigned)len);
    return r < 0 ? SOCKET_ERROR : 0;
}

extern "C" int getsockname(SOCKET s, SOCKADDR *name, int *namelen)
{
    if ((int64_t)s < 0 || !name || !namelen) return SOCKET_ERROR;
    /* 第三个参数是 socklen_t*（输入输出），必须传指针而不是值。
       传值会被当成地址解引用 -> EFAULT -> 服务端拿不到实际端口。 */
    long r = syscall(SYS_getsockname, (int)s, name, namelen);
    return r < 0 ? SOCKET_ERROR : 0;
}

extern "C" int connect(SOCKET s, const SOCKADDR *name, int namelen)
{
    if ((int64_t)s < 0) return SOCKET_ERROR;
    long r = syscall(SYS_connect, (int)s, name, (unsigned)namelen);
    return r < 0 ? SOCKET_ERROR : 0;
}

extern "C" int send(SOCKET s, const char *buf, int len, int flags)
{
    if ((int64_t)s < 0 || !buf || len < 0) return SOCKET_ERROR;
    long r = syscall(SYS_sendto, (int)s, buf, (size_t)len, (unsigned)flags,
                     nullptr, 0);
    return (int)r;
}

extern "C" int recv(SOCKET s, char *buf, int len, int flags)
{
    if ((int64_t)s < 0 || !buf || len < 0) return SOCKET_ERROR;
    long r = syscall(SYS_recvfrom, (int)s, buf, (size_t)len, (unsigned)flags,
                     nullptr, nullptr);
    return (int)r;
}

extern "C" int shutdown(SOCKET s, int how)
{
    if ((int64_t)s < 0) return SOCKET_ERROR;
    long r = syscall(SYS_shutdown, (int)s, how);
    return r < 0 ? SOCKET_ERROR : 0;
}

extern "C" int closesocket(SOCKET s)
{
    if ((int64_t)s < 0) return SOCKET_ERROR;
    long r = syscall(SYS_close, (int)s);
    return r < 0 ? SOCKET_ERROR : 0;
}

/*
 * 字节序：不依赖宿主的 htons，避免与 POSIX 同名冲突；
 * 实现本身是平台无关的大小端转换。
 */
extern "C" unsigned short htons(unsigned short v)
{
    union { uint16_t u; unsigned char b[2]; } t;
    t.b[0] = (unsigned char)(v >> 8);
    t.b[1] = (unsigned char)(v & 0xff);
    return t.u;
}

extern "C" unsigned short ntohs(unsigned short v) { return htons(v); }

/*
 * 点分十进制 -> 网络序 32 位。非法输入返回 INADDR_NONE。
 *
 * 必须逐八位组重置累加值：初版在 '.' 处没有把 v 清零，于是 "127.0.0.1"
 * 被累成 1270 / 12700 / 127001，产出的地址连不上任何东西 —— 而 stager
 * 只会表现为 WS_ERR_FETCH，看不出是地址解析错了。
 */
extern "C" unsigned long inet_addr(const char *cp)
{
    const unsigned long NONE = 0xffffffffUL;
    if (!cp) return NONE;

    unsigned char b[4];
    int i = 0, n = 0;
    unsigned v = 0;

    for (const char *p = cp;; p++) {
        if (*p >= '0' && *p <= '9') {
            v = v * 10u + (unsigned)(*p - '0');
            if (v > 255u) return NONE;
            if (++n > 3) return NONE;
        } else if (*p == '.' || *p == '\0') {
            if (n == 0) return NONE;
            if (i >= 4) return NONE;
            b[i++] = (unsigned char)v;
            v = 0; n = 0;
            if (*p == '\0') break;
        } else {
            return NONE;
        }
    }
    if (i != 4) return NONE;

    /* 网络序：首个八位组在最低字节（小端主机上即内存序 a.b.c.d） */
    return ((unsigned long)b[3] << 24) | ((unsigned long)b[2] << 16) |
           ((unsigned long)b[1] << 8)  | ((unsigned long)b[0]);
}

/* ---------------- 虚拟内存 ---------------- */

#define MEM_COMMIT     0x00001000u
#define MEM_RESERVE    0x00002000u
#define MEM_RELEASE    0x00008000u
#define PAGE_NOACCESS          0x01u
#define PAGE_READONLY          0x02u
#define PAGE_READWRITE         0x04u
#define PAGE_WRITECOPY         0x08u
#define PAGE_EXECUTE           0x10u
#define PAGE_EXECUTE_READ      0x20u
#define PAGE_EXECUTE_READWRITE 0x40u

static int prot_from_win(unsigned long p)
{
    switch (p) {
    case PAGE_NOACCESS:          return PROT_NONE;
    case PAGE_READONLY:          return PROT_READ;
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:         return PROT_READ | PROT_WRITE;
    case PAGE_EXECUTE:           return PROT_EXEC;
    case PAGE_EXECUTE_READ:      return PROT_READ | PROT_EXEC;
    case PAGE_EXECUTE_READWRITE: return PROT_READ | PROT_WRITE | PROT_EXEC;
    default:                     return -1;
    }
}

extern "C" LPVOID VirtualAlloc(LPVOID addr, size_t size, unsigned long type,
                               unsigned long protect)
{
    /*
     * 反射装载要先写入（映射、重定位、IAT 绑定），再由 protect 回调逐节收权。
     * 因此这里一律给 RW，最终权限由 rr_load_run 通过 VirtualProtect 设定。
     * 若按 Windows 语义严格按 protect 分配（例如 RX），装载阶段的写入会
     * 直接访问违例 —— 那是正确行为被错误分配策略破坏，不是缺陷。
     */
    (void)type; (void)protect;
    if (size == 0) return nullptr;
    void *p = mmap(addr, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? nullptr : p;
}

extern "C" BOOL VirtualProtect(LPVOID addr, size_t size, unsigned long new_prot,
                               unsigned long *old)
{
    if (!addr || size == 0) return FALSE;
    int pr = prot_from_win(new_prot);
    if (pr < 0) return FALSE;
    if (old) *old = PAGE_READWRITE;
    return mprotect(addr, size, pr) == 0 ? TRUE : FALSE;
}

extern "C" BOOL VirtualFree(LPVOID addr, size_t size, unsigned long type)
{
    (void)type;
    if (!addr) return FALSE;
    return munmap(addr, size) == 0 ? TRUE : FALSE;
}
