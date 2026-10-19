#include "transport.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <netinet/ip_icmp.h>

static int test_dns_encode(void) {
    const uint8_t frame[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    char out[512];
    if (transport_frame_to_dns(frame, sizeof(frame), out, sizeof(out)) != TRANSPORT_OK) {
        printf("dns encode fail\n"); return 1;
    }
    if (strlen(out) == 0) { printf("dns encode empty\n"); return 1; }
    printf("dns_encode ok: %s\n", out);
    return 0;
}

static int test_icmp_convert(void) {
    const uint8_t frame[] = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t icmp_buf[256];
    size_t icmp_len = sizeof(icmp_buf);
    if (transport_frame_to_icmp(frame, sizeof(frame), icmp_buf, &icmp_len) != TRANSPORT_OK) {
        printf("icmp encode fail\n"); return 1;
    }
    if (icmp_len < sizeof(struct icmphdr) + sizeof(frame)) { printf("icmp len wrong\n"); return 1; }

    uint8_t recovered[256];
    size_t rec_len = sizeof(recovered);
    if (transport_icmp_to_frame(icmp_buf, icmp_len, recovered, &rec_len) != TRANSPORT_OK) {
        printf("icmp decode fail\n"); return 1;
    }
    if (rec_len != sizeof(frame)) { printf("recovered len mismatch\n"); return 1; }
    if (memcmp(recovered, frame, sizeof(frame)) != 0) { printf("payload mismatch\n"); return 1; }

    printf("icmp_convert ok\n");
    return 0;
}

static int test_http_create(void) {
    transport_t *t = transport_http_new("127.0.0.1", 8080, "/api/v1/data");
    if (!t) { printf("http new fail\n"); return 1; }
    if (t->type != TRANSPORT_HTTP) { printf("type wrong\n"); return 1; }
    if (!t->send || !t->recv) { printf("callbacks missing\n"); return 1; }
    transport_free(t);
    printf("http_create ok\n");
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_http_create();
    rc |= test_dns_encode();
    rc |= test_icmp_convert();
    printf("ALL TESTS %s\n", rc == 0 ? "PASS" : "FAIL");
    return rc;
}
