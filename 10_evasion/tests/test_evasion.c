#include "evasion.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int main(void) {
    uint8_t frame[100];
    for (int i = 0; i < 100; i++) frame[i] = (uint8_t)(i * 3 + 1);

    /* ---- 分片 + 重组 ---- */
    size_t mtu = 32;                 /* payload_max = 28 -> 100 字节需 4 片 */
    uint8_t buf[512];
    size_t chunks = 0;
    size_t wlen = ev_frag_split(frame, 100, mtu, buf, sizeof buf, &chunks);
    CHECK(wlen == 4 * mtu);
    CHECK(chunks == 4);

    uint8_t out[256];
    size_t olen = sizeof out;
    CHECK(ev_frag_reassemble(buf, wlen, mtu, out, &olen) == 0);
    CHECK(olen == 100);
    CHECK(memcmp(out, frame, 100) == 0);

    /* 边界：正好整数倍 */
    chunks = 0;
    wlen = ev_frag_split(frame, 84, mtu, buf, sizeof buf, &chunks);  /* 84/28=3 片 */
    CHECK(chunks == 3 && wlen == 3 * mtu);
    olen = sizeof out;
    CHECK(ev_frag_reassemble(buf, wlen, mtu, out, &olen) == 0);
    CHECK(olen == 84 && memcmp(out, frame, 84) == 0);

    /* 长度 1 */
    chunks = 0;
    wlen = ev_frag_split(frame, 1, mtu, buf, sizeof buf, &chunks);
    CHECK(chunks == 1);
    olen = sizeof out;
    CHECK(ev_frag_reassemble(buf, wlen, mtu, out, &olen) == 0);
    CHECK(olen == 1 && memcmp(out, frame, 1) == 0);

    /* 缓冲区不足 */
    chunks = 0;
    CHECK(ev_frag_split(frame, 100, mtu, buf, 10, &chunks) == 0);

    /* ---- jitter 区间 ---- */
    srand(1234);
    for (int i = 0; i < 200; i++) {
        int v = ev_jitter(100, 50);
        if (v < 100 || v > 150) { printf("FAIL jitter %d\n", v); fails++; break; }
    }
    CHECK(ev_jitter(100, 0) == 100);
    CHECK(ev_jitter(-5, 0) == 0);

    printf("10_evasion tests: fail=%d\n", fails);
    return fails ? 1 : 0;
}
