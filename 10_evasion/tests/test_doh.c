#include "evasion.h"
#include "evasion_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_basic(void)
{
    uint8_t frame[] = { 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x11, 0x22, 0x33 };
    const char *doh_server = "dns.google";

    uint8_t out[8192];
    size_t out_len = sizeof(out);
    int rc = evasion_frame_to_doh(frame, sizeof(frame), doh_server, out, &out_len);
    if (rc != EVASION_OK) { fprintf(stderr, "frame_to_doh rc=%d\n", rc); return 1; }

    /* 验证是合法 HTTP GET, 带 /dns-query?dns= */
    if (strncmp((char *)out, "GET /dns-query", 14) != 0) {
        fprintf(stderr, "not DoH GET: %s\n", out);
        return 1;
    }
    if (strstr((char *)out, "dns=") == NULL) {
        fprintf(stderr, "missing dns= param\n");
        return 1;
    }
    if (strstr((char *)out, "Host: dns.google") == NULL) {
        fprintf(stderr, "missing Host dns.google\n");
        return 1;
    }
    if (strstr((char *)out, "application/dns-message") == NULL) {
        fprintf(stderr, "missing DoH Accept type\n");
        return 1;
    }

    /* 构造响应: 200 + base64url(body) */
    char *dns_start = strstr((char *)out, "dns=") + 4;
    char *dns_end = strchr(dns_start, ' ');
    if (!dns_end) dns_end = strchr(dns_start, '\r');
    size_t b64len = dns_end ? (size_t)(dns_end - dns_start) : strlen(dns_start);

    char resp[9000];
    int n = snprintf(resp, sizeof(resp),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: application/dns-message\r\n"
                     "Content-Length: %zu\r\n"
                     "\r\n", b64len);
    memcpy(resp + n, dns_start, b64len);
    size_t resp_len = (size_t)n + b64len;

    uint8_t recovered[4096];
    size_t rec_len = sizeof(recovered);
    rc = evasion_doh_to_frame((const uint8_t *)resp, resp_len, recovered, &rec_len);
    if (rc != EVASION_OK) { fprintf(stderr, "doh_to_frame rc=%d\n", rc); return 1; }
    if (rec_len != sizeof(frame)) {
        fprintf(stderr, "rec_len=%zu expect=%zu\n", rec_len, sizeof(frame));
        return 1;
    }
    if (memcmp(recovered, frame, sizeof(frame)) != 0) {
        fprintf(stderr, "recovered mismatch\n");
        return 1;
    }
    printf("  [PASS] doh roundtrip (%zu bytes)\n", sizeof(frame));
    return 0;
}

static int test_b64url(void)
{
    uint8_t in[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0xFE };
    char b64[64];
    if (evasion_b64url_encode(in, sizeof(in), b64, sizeof(b64)) != EVASION_OK)
        return 1;
    /* 无 '=' 填充 */
    if (strchr(b64, '=') != NULL) { fprintf(stderr, "has padding: %s\n", b64); return 1; }
    /* 只含 base64url 字符 */
    for (char *c = b64; *c; c++) {
        if (!((*c >= 'A' && *c <= 'Z') || (*c >= 'a' && *c <= 'z') ||
              (*c >= '0' && *c <= '9') || *c == '-' || *c == '_')) {
            fprintf(stderr, "bad char '%c' in b64url\n", *c);
            return 1;
        }
    }
    uint8_t dec[64];
    size_t declen = sizeof(dec);
    if (evasion_b64url_decode(b64, dec, &declen) != EVASION_OK) return 1;
    if (declen != sizeof(in)) { fprintf(stderr, "declen=%zu\n", declen); return 1; }
    if (memcmp(dec, in, sizeof(in)) != 0) { fprintf(stderr, "decode mismatch\n"); return 1; }
    printf("  [PASS] b64url encode/decode\n");
    return 0;
}

int main(void)
{
    int f = 0;
    f |= test_b64url();
    f |= test_basic();
    return f;
}
