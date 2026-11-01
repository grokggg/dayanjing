#include "transport.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int main(void) {
    uint8_t frame[64];
    for (int i = 0; i < 64; i++) frame[i] = (uint8_t)(i * 7 + 3);

    /* ---- HTTP roundtrip ---- */
    uint8_t hbuf[512];
    size_t hl = tx_http_wrap(frame, 40, hbuf, sizeof hbuf);
    CHECK(hl > 0);
    const char hdr[] = "HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n";
    size_t hlen = strlen(hdr);
    uint8_t rbuf[512];
    memcpy(rbuf, hdr, hlen);
    memcpy(rbuf + hlen, frame, 40);
    uint8_t hout[64];
    size_t holen = sizeof hout;
    CHECK(tx_http_unwrap(rbuf, hlen + 40, hout, &holen) == 0);
    CHECK(holen == 40);
    CHECK(memcmp(hout, frame, 40) == 0);

    /* ---- DNS roundtrip (full) ---- */
    char dbuf[256];
    size_t dl = tx_dns_wrap(frame, 40, dbuf, sizeof dbuf);
    CHECK(dl > 0);
    uint8_t dout[64];
    size_t dolen = sizeof dout;
    CHECK(tx_dns_unwrap(dbuf, dout, &dolen) == 0);
    CHECK(dolen == 40);
    CHECK(memcmp(dout, frame, 40) == 0);

    /* ---- DNS every partial length 1..40 ---- */
    for (size_t n = 1; n <= 40; n++) {
        char tbuf[256];
        size_t tl = tx_dns_wrap(frame, n, tbuf, sizeof tbuf);
        if (tl == 0) { printf("FAIL dns wrap n=%zu\n", n); fails++; continue; }
        uint8_t tout[64];
        size_t tol = sizeof tout;
        if (tx_dns_unwrap(tbuf, tout, &tol) != 0 || tol != n || memcmp(tout, frame, n) != 0) {
            printf("FAIL dns roundtrip n=%zu\n", n);
            fails++;
        }
    }

    /* ---- ICMP roundtrip ---- */
    uint8_t ibuf[128];
    size_t il = tx_icmp_wrap(frame, 40, ibuf, sizeof ibuf);
    CHECK(il == 44);
    uint8_t iout[64];
    size_t iolen = sizeof iout;
    CHECK(tx_icmp_unwrap(ibuf, il, iout, &iolen) == 0);
    CHECK(iolen == 40);
    CHECK(memcmp(iout, frame, 40) == 0);

    /* ---- ICMP bad magic rejected ---- */
    ibuf[0] = 0x00;
    size_t badlen = sizeof iout;
    CHECK(tx_icmp_unwrap(ibuf, il, iout, &badlen) != 0);

    printf("03_transport tests: fail=%d\n", fails);
    return fails ? 1 : 0;
}
