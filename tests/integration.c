/*
 * 跨模块集成测试：
 *   原始帧 -> 03_transport(HTTP 包装)
 *          -> 10_evasion(分片)
 *          -> 06_db(落盘)
 *          -> 06_db(读出)
 *          -> 10_evasion(重组)
 *          -> 03_transport(HTTP 解包)
 *          -> 07_ui(响应构造)
 * 验证字节级一致。
 */
#include "transport.h"
#include "evasion.h"
#include "db.h"
#include "http.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main(void) {
    uint8_t frame[120];
    for (int i = 0; i < 120; i++) frame[i] = (uint8_t)(i * 5 + 2);

    /* 1. HTTP 包装（请求体即原始帧） */
    uint8_t httpbuf[512];
    size_t hl = tx_http_wrap(frame, sizeof frame, httpbuf, sizeof httpbuf);
    assert(hl > 0);

    /* 2. 分片 */
    size_t mtu = 32;
    uint8_t frag[1024];
    size_t chunks = 0;
    size_t flen = ev_frag_split(httpbuf, hl, mtu, frag, sizeof frag, &chunks);
    assert(flen > 0 && chunks > 0);

    /* 3. 落盘 */
    const char *dbpath = "/tmp/dayanjing_integration.bin";
    db_t w;
    assert(db_open_rw(&w, dbpath) == 0);
    assert(db_append(&w, 1, frag, (uint16_t)flen) == 0);
    assert(db_close(&w) == 0);

    /* 4. 读出 */
    db_t r;
    assert(db_open_ro(&r, dbpath) == 0);
    uint8_t rbuf[1024];
    uint8_t rtype = 0;
    uint16_t rlen = (uint16_t)sizeof rbuf;      /* 入参=容量 */
    assert(db_next(&r, &rtype, rbuf, &rlen) == 1);
    size_t stored = rlen;                        /* 出参=实际长度 */
    assert(db_close(&r) == 0);
    assert(stored == flen);

    /* 5. 重组 */
    uint8_t reass[1024];
    size_t rcap = sizeof reass;                  /* 入参=容量 */
    assert(ev_frag_reassemble(rbuf, stored, mtu, reass, &rcap) == 0);
    assert(rcap == hl);                          /* 还原为 HTTP 包装后长度 */

    /* 6. HTTP 解包出原始帧 */
    uint8_t final[512];
    size_t fcap = sizeof final;
    assert(tx_http_unwrap(reass, rcap, final, &fcap) == 0);
    assert(fcap == sizeof frame);
    assert(memcmp(final, frame, sizeof frame) == 0);

    /* 7. UI 响应 */
    char resp[512];
    size_t rn = http_build_response(200, "{\"ok\":true}", resp, sizeof resp);
    assert(rn > 0 && strstr(resp, "200 OK") != NULL);

    printf("integration OK: frame=%zu http=%zu chunks=%zu db=%zu ui=%zu\n",
           sizeof frame, hl, chunks, stored, rn);
    return 0;
}
