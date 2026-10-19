#define _GNU_SOURCE
#include "evasion.h"
#include "evasion_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_basic(void)
{
    uint8_t frame[] = {
        0xD4, 0xA1,             /* magic */
        0x01,                   /* version */
        0x20,                   /* msg_type = HEARTBEAT */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, /* session_id */
        0x00,                   /* flags */
        0x00, 0x00, 0x00, 0x01, /* nonce_counter */
        0x00, 0x00, 0x00, 0x07, /* payload_len */
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, /* payload(7) */
        /* 后面接 16 字节 tag 占位 */
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
    };
    size_t frame_len = sizeof(frame);
    const char *sni = "www.baidu.com";

    uint8_t out[4096];
    size_t out_len = sizeof(out);
    int rc = evasion_frame_to_clienthello(frame, frame_len, sni, out, &out_len);
    if (rc != EVASION_OK) { fprintf(stderr, "frame_to_ch rc=%d\n", rc); return 1; }

    /* 验证外层是 TLS Handshake record */
    if (out[0] != 0x16) { fprintf(stderr, "not handshake record: %02x\n", out[0]); return 1; }
    if (out[1] != 0x03 || out[2] != 0x03) { fprintf(stderr, "not TLS1.2\n"); return 1; }
    /* ClientHello handshake type */
    if (out[5] != 0x01) { fprintf(stderr, "not ClientHello\n"); return 1; }
    /* SNI 出现在扩展段 */
    void *s = memmem(out, out_len, sni, strlen(sni));
    if (!s) { fprintf(stderr, "SNI not found\n"); return 1; }
    /* 私有扩展类型存在 */
    int found_c2 = 0;
    for (size_t i = 0; i + 1 < out_len; i++) {
        uint16_t t = ((uint16_t)out[i] << 8) | out[i + 1];
        if (t == EVASION_EXT_TYPE_C2_A || t == EVASION_EXT_TYPE_C2_B) {
            found_c2 = 1;
            break;
        }
    }
    if (!found_c2) { fprintf(stderr, "C2 extension type not found\n"); return 1; }

    /* 反向解析 */
    uint8_t recovered[4096];
    size_t rec_len = sizeof(recovered);
    rc = evasion_clienthello_to_frame(out, out_len, recovered, &rec_len);
    if (rc != EVASION_OK) { fprintf(stderr, "ch_to_frame rc=%d\n", rc); return 1; }
    if (rec_len != frame_len) {
        fprintf(stderr, "rec_len=%zu frame_len=%zu\n", rec_len, frame_len);
        return 1;
    }
    if (memcmp(recovered, frame, frame_len) != 0) {
        fprintf(stderr, "recovered frame mismatch\n");
        return 1;
    }
    printf("  [PASS] clienthello roundtrip (%zu bytes)\n", frame_len);
    return 0;
}

int main(void)
{
    return test_basic();
}
