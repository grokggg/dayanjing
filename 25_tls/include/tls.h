/* tls.h — 自研 TLS 1.2 客户端（不含 OpenSSL，不调用任何第三方库）
 *
 * 支持的唯一套件：TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
 *   密钥交换 : X25519（RFC 8422, named curve 29）—— 复用 00_crypto
 *   认证     : RSA PKCS#1 v1.5 + SHA-256（自研 bn/rsa/x509）
 *   记录保护 : AES-128-GCM（复用 00_crypto），IV = salt(4) || explicit(8)
 *   伪随机   : TLS 1.2 PRF（HMAC-SHA256）
 *
 * 为什么只做一套件：多套件意味着多套未验证代码路径。真实部署只需一条，
 * 选最通用的一条并把它验证到真机握手通过。
 *
 * IO 通过回调注入：调用方可以是 socket、代理隧道、内存管道或域前置层。
 */
#ifndef TLS_H
#define TLS_H

#include <stdint.h>
#include <stddef.h>
#include "x509.h"

typedef enum {
    TLS_OK = 0,
    TLS_ERR_ARG,
    TLS_ERR_MEM,
    TLS_ERR_IO,          /* 回调读取失败 */
    TLS_ERR_RECORD,      /* 记录层结构非法 */
    TLS_ERR_ALERT,       /* 收到致命告警 */
    TLS_ERR_VERSION,
    TLS_ERR_CIPHER,      /* 服务端选了别的套件 */
    TLS_ERR_HANDSHAKE,   /* 握手消息非法 / 顺序错 */
    TLS_ERR_SKE,         /* ServerKeyExchange 签名校验失败 */
    TLS_ERR_CERT,        /* 证书链或主机名校验失败 */
    TLS_ERR_FINISHED,    /* 对端 Finished 校验失败 */
    TLS_ERR_RANGE,       /* 缓冲不够 */
    TLS_ERR_TRUNC,
    TLS_ERR_CLOSED       /* 本端已发过 close_notify，不能再写 */
} tls_err;

const char *tls_errstr(tls_err e);

/* 发送：返回**实际发出的字节数**。接收：返回读到的字节数。两者均以 <=0
 * 表示失败/关闭。
 *
 * 本注释此前写的是"发送：返回 0 成功"，与实现相反——tls.c 的 io_send_all
 * 是 `off += (size_t)r; if (r <= 0) return TLS_ERR_IO;`，把返回值当字节数
 * 累加而非当成功标志。照旧注释实现的回调会在第一次发送成功后被就地判为
 * IO 错误：握手报 transport error，对端只看到连接被关掉（OpenSSL 侧表现为
 * UNEXPECTED_EOF_WHILE_READING），而本地看不出是回调契约错了。
 * 既有实现见 25_tls/tests/test_tls.c:45。 */
typedef int (*tls_send_cb)(void *arg, const uint8_t *data, size_t len);
typedef int (*tls_recv_cb)(void *arg, uint8_t *buf, size_t cap);

typedef struct {
    const char *sni;         /* 写入 SNI 扩展的域名（观察者可见） */
    const char *verify_host; /* 证书主机名校验用；NULL 表示与 sni 相同 */
    const char *alpn;        /* ALPN 通告的协议名，如 "h2"；NULL = 不发 ALPN。
                                走 HTTP/2 必须给 "h2"，否则对端降级到 HTTP/1.1 */
    const char *ca_path;     /* 信任库 PEM；NULL 表示不校验证书 */
    int         verify;      /* 1 = 校验证书链与主机名 */
} tls_config;

typedef struct tls_ctx tls_ctx;

tls_err tls_client_init(tls_ctx **out, const tls_config *cfg,
                        tls_send_cb send, tls_recv_cb recv, void *arg);
void    tls_free(tls_ctx *c);
tls_err tls_handshake(tls_ctx *c);
tls_err tls_write(tls_ctx *c, const uint8_t *data, size_t len);
tls_err tls_read(tls_ctx *c, uint8_t *buf, size_t cap, size_t *out_len);

/* 发送 close_notify 并关闭本端写方向。
 *
 * 为什么必须显式发：不发的话对端只能看到 TCP 被关掉。真实 TLS 实现（实测
 * OpenSSL 3.0.2）会报 "unexpected eof while reading" 并把连接判为错误退出。
 * 更要紧的是语义：没有 close_notify，对端无法区分"正常结束"与"有人在
 * 中途掐断了连接"——截断攻击正是利用这个歧义。
 * 幂等：重复调用返回 TLS_OK。 */
tls_err tls_close(tls_ctx *c);

/* 诊断：实际发出的 ClientHello 中 SNI 扩展携带的主机名（取证用） */
int tls_sni_echo(const tls_ctx *c, char *out, size_t cap);

#endif /* TLS_H */
