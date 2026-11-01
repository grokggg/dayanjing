/* tests/stager_srv.h — 测试用投递服务端（与 stager 同走 Winsock）
 *
 * 为什么服务端也用 Winsock 而不是 POSIX socket：
 *   测试进程同时链接 shim_winsock.o（提供 socket/connect/... 的 extern "C"
 *   定义）。若服务端改用 POSIX socket，两者会争抢同一个 C 符号 —— 静态链接
 *   下用户定义的符号胜出，服务端调用会落进 shim 的实现。参数布局在 x86-64
 *   上恰好兼容，于是"能跑"，但这是一次偶然；将来任何签名差异都会表现为
 *   难以定位的错乱。统一用 Winsock 后符号只有一份，且服务端代码在真机上
 *   就是可直接编译的 Windows 代码。
 *
 * 服务端提供的是**真实** TCP 上的真实 HTTP 响应：stager 必须真的连上、真的
 * 解析报文才能拿到块，而不是 mock 恒返回成功。
 */
#ifndef DAYANJING_TESTS_STAGER_SRV_H
#define DAYANJING_TESTS_STAGER_SRV_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const uint8_t *blob;
    size_t         blob_len;
    const void    *manifest;     /* dp_manifest_t*（避免本头文件依赖 drop.h） */
    int            serve_limit;  /* 最多服务多少块；<0 = 不限。用于断供用例 */
    int            tamper_idx;   /* 篡改哪一块的末字节；<0 = 不篡改 */
    uint16_t       port;         /* 出参：bind(0) 后的实际端口 */
    volatile int   served;       /* 已服务的块数（诊断） */
    volatile int   ready;        /* 监听已就绪 */
    volatile int   stop;
    void          *th;           /* pthread_t* */
    uint64_t       lsock;
} stager_srv_t;

int  stager_srv_start(stager_srv_t *s);
void stager_srv_stop(stager_srv_t *s);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_TESTS_STAGER_SRV_H */
