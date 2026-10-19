#include "evasion.h"
#include "evasion_internal.h"

#include <stdio.h>
#include <string.h>

int evasion_domain_front(const char *real_host, const char *fake_host,
                         const char *path,
                         const uint8_t *body, size_t body_len,
                         uint8_t *out, size_t *out_len)
{
    if (!real_host || !fake_host || !path || !out || !out_len)
        return EVASION_ERR;

    char *p = (char *)out;
    size_t cap = *out_len;
    size_t used = 0;

    /*
     * 关键: SNI 用 real_host(如 CDN IP), Host 头用 fake_host(伪装域名)。
     * 审查者从 TLS SNI 只看到 IP, 从 HTTP 层才看到 fake_host。
     */
    int n = snprintf(p, cap,
                     "POST %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                     "Accept: */*\r\n"
                     "Accept-Encoding: gzip, deflate, br\r\n"
                     "Connection: close\r\n"
                     "X-Forwarded-Host: %s\r\n"
                     "Content-Type: application/octet-stream\r\n"
                     "Content-Length: %zu\r\n"
                     "\r\n",
                     path, fake_host, real_host, body_len);
    if (n < 0) return EVASION_ERR;
    size_t hdr_len = (size_t)n;
    if (hdr_len + body_len + 1 > cap) return EVASION_ERR_NOMEM;
    used = hdr_len;
    memcpy(p + used, body, body_len);
    used += body_len;
    *out_len = used;
    return EVASION_OK;
}

int evasion_domain_front_parse_response(const uint8_t *resp, size_t resp_len,
                                        uint8_t *frame, size_t *frame_len)
{
    if (!resp || !frame || !frame_len) return EVASION_ERR;

    int status = evasion_parse_http_status(resp, resp_len);
    if (status < 0) return EVASION_ERR;
    /* 允许 2xx 与 3xx(CDN 可能返回 304 等) */
    if (status / 100 != 2 && status / 100 != 3) return EVASION_ERR_FMT;

    uint8_t *body = NULL;
    size_t body_len = 0;
    if (evasion_parse_http_body(resp, resp_len, &body, &body_len) != EVASION_OK)
        return EVASION_ERR_FMT;
    if (body_len > *frame_len) return EVASION_ERR_NOMEM;
    memcpy(frame, body, body_len);
    *frame_len = body_len;
    return EVASION_OK;
}
