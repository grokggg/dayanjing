#include "evasion.h"
#include <stdio.h>
#include <string.h>

static int fails = 0, total = 0;
static void ck(const char *name, int cond) {
    total++;
    if (!cond) { fails++; printf("  FAIL: %s\n", name); }
    else printf("  ok  : %s\n", name);
}

int main(void) {
    printf("=== 10_evasion 测试 ===\n");
    uint8_t frame[300];
    for (size_t i = 0; i < sizeof frame; i++) frame[i] = (uint8_t)(i * 7 + 3);

    /* --- 分片/重组（原最小单元） --- */
    uint8_t chunks[64 * 20];
    size_t nchunks = 0;
    size_t w = ev_frag_split(frame, sizeof frame, 64, chunks, sizeof chunks, &nchunks);
    ck("frag split", w == nchunks * 64 && nchunks == 5);
    uint8_t back[300]; size_t bl = sizeof back;
    ck("frag reassemble", ev_frag_reassemble(chunks, w, 64, back, &bl) == 0);
    ck("frag roundtrip equal", bl == sizeof frame && memcmp(back, frame, sizeof frame) == 0);

    /* --- jitter --- */
    int j = ev_jitter(100, 50);
    ck("jitter in range", j >= 100 && j <= 150);
    ck("jitter zero-jitter", ev_jitter(100, 0) == 100);

    /* --- 伪装：四种模式往返 --- */
    uint8_t camo[1024];
    uint8_t dec[1024];

    /* NONE */
    size_t cl = ev_camouflage(EV_MODE_NONE, frame, sizeof frame, NULL, camo, sizeof camo);
    size_t dl = sizeof dec;
    ck("camouflage NONE", cl == sizeof frame &&
                          ev_decamouflage(EV_MODE_NONE, camo, cl, dec, &dl) == 0 &&
                          dl == sizeof frame && memcmp(dec, frame, sizeof frame) == 0);

    /* DOMAIN_FRONT */
    cl = ev_camouflage(EV_MODE_DOMAIN_FRONT, frame, sizeof frame, "front.cdn.example", camo, sizeof camo);
    ck("camouflage DOMAIN_FRONT built", cl > sizeof frame);
    if (cl > 0) {
        ck("DOMAIN_FRONT has Host header", strstr((char*)camo, "Host: front.cdn.example") != NULL);
        dl = sizeof dec;
        ck("DOMAIN_FRONT decam", ev_decamouflage(EV_MODE_DOMAIN_FRONT, camo, cl, dec, &dl) == 0 &&
                                 dl == sizeof frame && memcmp(dec, frame, sizeof frame) == 0);
    }

    /* DOH */
    cl = ev_camouflage(EV_MODE_DOH, frame, sizeof frame, "dns.example", camo, sizeof camo);
    ck("camouflage DOH built", cl > sizeof frame);
    if (cl > 0) {
        ck("DOH path is /dns-query", strstr((char*)camo, "POST /dns-query") != NULL);
        dl = sizeof dec;
        ck("DOH decam", ev_decamouflage(EV_MODE_DOH, camo, cl, dec, &dl) == 0 &&
                        dl == sizeof frame && memcmp(dec, frame, sizeof frame) == 0);
    }

    /* TLS_HELLO */
    cl = ev_camouflage(EV_MODE_TLS_HELLO, frame, sizeof frame, NULL, camo, sizeof camo);
    ck("camouflage TLS_HELLO built", cl == 5 + sizeof frame && camo[0] == 0x16 && camo[1] == 0x03);
    if (cl > 0) {
        dl = sizeof dec;
        ck("TLS_HELLO decam", ev_decamouflage(EV_MODE_TLS_HELLO, camo, cl, dec, &dl) == 0 &&
                              dl == sizeof frame && memcmp(dec, frame, sizeof frame) == 0);
    }

    printf("--- total=%d pass=%d fail=%d ---\n", total, total - fails, fails);
    return fails ? 1 : 0;
}
