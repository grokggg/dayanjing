#ifndef EVASION_INTERNAL_H
#define EVASION_INTERNAL_H

#include "evasion.h"

/* 私有扩展类型, 落在 [0x7F00, 0x7FFF] 实验性区间 */
#define EVASION_EXT_TYPE_C2_A  0x7FA1
#define EVASION_EXT_TYPE_C2_B  0x7FA2

/* base64url 编解码(无填充, RFC 4648) */
int evasion_b64url_encode(const uint8_t *in, size_t in_len, char *out, size_t out_len);
int evasion_b64url_decode(const char *in, uint8_t *out, size_t *out_len);

/* 简易 HTTP 响应解析: 返回 body 起始与长度 */
int evasion_parse_http_body(const uint8_t *resp, size_t resp_len,
                           uint8_t **body, size_t *body_len);

/* 提取 HTTP 响应状态码 */
int evasion_parse_http_status(const uint8_t *resp, size_t resp_len);

/* 生成合法长度的随机 qname 段, 用于伪造 DoH 查询名 */
int evasion_random_qname_label(char *out, size_t out_len);

#endif /* EVASION_INTERNAL_H */
