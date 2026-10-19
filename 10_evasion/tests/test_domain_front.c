#include "evasion.h"
#include "evasion_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int test_basic(void)
{
    const char *real = "1.1.1.1";
    const char *fake = "update.microsoft.com";
    const char *path = "/api/v1/submit";
    uint8_t body[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03 };
    uint8_t out[4096];
    size_t out_len = sizeof(out);

    int rc = evasion_domain_front(real, fake, path, body, sizeof(body), out, &out_len);
    if (rc != EVASION_OK) { fprintf(stderr, "domain_front rc=%d\n", rc); return 1; }

    /* 验证 Host 头使用 fake_host, 而不是 real_host */
    char *host_hdr = strstr((char *)out, "Host: ");
    if (!host_hdr) { fprintf(stderr, "missing Host header\n"); return 1; }
    if (strncmp(host_hdr, "Host: update.microsoft.com", 26) != 0) {
        fprintf(stderr, "Host header mismatch: %s\n", host_hdr);
        return 1;
    }
    /*
     * 域前置核心语义:
     *   Host 头必须用 fake_host(update.microsoft.com) —— 审查设备只能看到这个
     *   X-Forwarded-Host 可携带真实目标 —— 这是 CDN 转发链的正常字段
     *   所以 real_host 允许出现在 X-Forwarded-Host, 但禁止出现在 Host 头
     */
    char *host_val = strstr((char *)out, "\r\nHost: ");
    if (host_val != NULL) {
        /* 取 Host 头的值部分(跳过 "\r\nHost: ") */
        char *hv = host_val + 8;
        /* 检查 Host 值是否等于 real_host(应不等) */
        if (strncmp(hv, "1.1.1.1", 7) == 0) {
            fprintf(stderr, "real_host leaked into Host header\n");
            return 1;
        }
    }
    /* X-Forwarded-Host 应携带真实目标 */
    char *xff = strstr((char *)out, "X-Forwarded-Host: ");
    if (!xff) { fprintf(stderr, "missing X-Forwarded-Host\n"); return 1; }
    if (strstr(xff + 18, "1.1.1.1") == NULL) {
        fprintf(stderr, "X-Forwarded-Host missing real_host\n");
        return 1;
    }
    /* Content-Length 正确 */
    char *cl = strstr((char *)out, "Content-Length: ");
    if (!cl) { fprintf(stderr, "missing Content-Length\n"); return 1; }
    int clv = atoi(cl + 16);
    if (clv != (int)sizeof(body)) {
        fprintf(stderr, "Content-Length=%d expect=%zu\n", clv, sizeof(body));
        return 1;
    }
    /* body 出现在头部之后 */
    char *dsep = strstr((char *)out, "\r\n\r\n");
    if (!dsep) { fprintf(stderr, "missing header/body sep\n"); return 1; }
    uint8_t *bstart = (uint8_t *)(dsep + 4);
    if (memcmp(bstart, body, sizeof(body)) != 0) {
        fprintf(stderr, "body mismatch\n");
        return 1;
    }
    printf("  [PASS] domain_front basic\n");
    return 0;
}

static int test_response_parse(void)
{
    /* 构造一个带 Content-Length 的 HTTP 响应, body 是 C2 帧 */
    const char *resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: 7\r\n"
        "Connection: close\r\n"
        "\r\n"
        "\x01\x02\x03\x04\x05\x06\x07";
    uint8_t frame[64];
    size_t frame_len = sizeof(frame);
    int rc = evasion_domain_front_parse_response((const uint8_t *)resp, strlen(resp),
                                                frame, &frame_len);
    if (rc != EVASION_OK) { fprintf(stderr, "parse_response rc=%d\n", rc); return 1; }
    if (frame_len != 7) { fprintf(stderr, "frame_len=%zu\n", frame_len); return 1; }
    for (int i = 0; i < 7; i++) {
        if (frame[i] != (uint8_t)(i + 1)) { fprintf(stderr, "frame[%d]=%u\n", i, frame[i]); return 1; }
    }
    printf("  [PASS] domain_front response_parse\n");
    return 0;
}

static int test_response_non_2xx(void)
{
    const char *resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    uint8_t frame[64];
    size_t frame_len = sizeof(frame);
    int rc = evasion_domain_front_parse_response((const uint8_t *)resp, strlen(resp),
                                                frame, &frame_len);
    if (rc == EVASION_OK) { fprintf(stderr, "expected error on 404\n"); return 1; }
    printf("  [PASS] domain_front non_2xx rejected\n");
    return 0;
}

int main(void)
{
    int f = 0;
    f |= test_basic();
    f |= test_response_parse();
    f |= test_response_non_2xx();
    return f;
}
