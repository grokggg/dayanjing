/*
 * tests/e2e_camo.c
 * 03_transport × 10_evasion 伪装联合 e2e（全本地内存，不发任何网络包）。
 *
 * 链路一：frame -> 伪装 -> 分片 -> 重组 -> 解伪装 -> 比对
 * 链路二：frame -> 伪装 -> HTTP 包装 -> HTTP 解包 -> 解伪装 -> 比对
 * 链路三：完整组合 伪装->分片->重组->HTTP包装->HTTP解包->解伪装
 * 负向：  容量不足 / 报文过短 / mtu 非法 / 丢片可检出 / 篡改可检出
 */
#include "transport.h"
#include "evasion.h"

#include <stdio.h>
#include <string.h>

static int total = 0, fails = 0;
static void ck(const char *name, int ok) {
    total++;
    if (!ok) { fails++; printf("[FAIL] %s\n", name); }
    else       printf("[PASS] %s\n", name);
}

static const char *mode_name(ev_mode_t m) {
    if (m == EV_MODE_NONE)         return "NONE";
    if (m == EV_MODE_DOMAIN_FRONT) return "DOMAIN_FRONT";
    if (m == EV_MODE_DOH)          return "DOH";
    if (m == EV_MODE_TLS_HELLO)    return "TLS_HELLO";
    return "?";
}

static const char *HOST = "cdn.example.com";

/* 链路一 + 链路二：对每种伪装模式各跑一遍 */
static void run_mode(ev_mode_t m) {
    char tag[128];
    uint8_t frame[137];
    for (size_t i = 0; i < sizeof frame; i++) frame[i] = (uint8_t)(i * 7 + 3);

    /* ---- 伪装 ---- */
    uint8_t camo[1024];
    size_t cl = ev_camouflage(m, frame, sizeof frame, HOST, camo, sizeof camo);
    snprintf(tag, sizeof tag, "%s: camouflage produced", mode_name(m));
    ck(tag, cl > 0);
    if (cl == 0) return;

    /* ---- 链路一：分片 -> 重组 ---- */
    const size_t mtu = 48;
    uint8_t chunks[4096];
    size_t nch = 0;
    size_t clen = ev_frag_split(camo, cl, mtu, chunks, sizeof chunks, &nch);
    snprintf(tag, sizeof tag, "%s: frag split", mode_name(m));
    ck(tag, clen > 0 && nch > 0 && clen == nch * mtu);

    uint8_t camo2[1024];
    size_t rlen = sizeof camo2;
    snprintf(tag, sizeof tag, "%s: frag reassemble", mode_name(m));
    ck(tag, ev_frag_reassemble(chunks, clen, mtu, camo2, &rlen) == 0);
    snprintf(tag, sizeof tag, "%s: reassembled length preserved", mode_name(m));
    ck(tag, rlen == cl && memcmp(camo2, camo, cl) == 0);

    uint8_t out1[1024];
    size_t o1 = sizeof out1;
    snprintf(tag, sizeof tag, "%s: decamouflage after frag", mode_name(m));
    ck(tag, ev_decamouflage(m, camo2, rlen, out1, &o1) == 0);
    snprintf(tag, sizeof tag, "%s: frame identical (frag path)", mode_name(m));
    ck(tag, o1 == sizeof frame && memcmp(out1, frame, sizeof frame) == 0);

    /* ---- 链路二：HTTP 包装 -> 解包 ---- */
    uint8_t http[2048];
    size_t hl = tx_http_wrap(camo, cl, http, sizeof http);
    snprintf(tag, sizeof tag, "%s: http wrap", mode_name(m));
    ck(tag, hl > 0);

    uint8_t camo3[1024];
    size_t blen = sizeof camo3;
    snprintf(tag, sizeof tag, "%s: http unwrap", mode_name(m));
    ck(tag, tx_http_unwrap(http, hl, camo3, &blen) == 0);
    snprintf(tag, sizeof tag, "%s: http body == camouflaged", mode_name(m));
    ck(tag, blen == cl && memcmp(camo3, camo, cl) == 0);

    uint8_t out2[1024];
    size_t o2 = sizeof out2;
    snprintf(tag, sizeof tag, "%s: decamouflage after transport", mode_name(m));
    ck(tag, ev_decamouflage(m, camo3, blen, out2, &o2) == 0);
    snprintf(tag, sizeof tag, "%s: frame identical (transport path)", mode_name(m));
    ck(tag, o2 == sizeof frame && memcmp(out2, frame, sizeof frame) == 0);
}

/* 链路三：完整组合，伪装 -> 分片 -> 重组 -> HTTP -> 解包 -> 解伪装 */
static void run_combined(void) {
    uint8_t frame[300];
    for (size_t i = 0; i < sizeof frame; i++) frame[i] = (uint8_t)(i ^ 0x5A);

    uint8_t camo[1024];
    size_t cl = ev_camouflage(EV_MODE_TLS_HELLO, frame, sizeof frame, HOST, camo, sizeof camo);
    ck("combined: camouflage", cl > 0);

    const size_t mtu = 64;
    uint8_t chunks[4096];
    size_t nch = 0;
    size_t clen = ev_frag_split(camo, cl, mtu, chunks, sizeof chunks, &nch);
    ck("combined: frag split", clen > 0 && clen == nch * mtu);

    uint8_t camo2[1024];
    size_t rlen = sizeof camo2;
    ck("combined: reassemble", ev_frag_reassemble(chunks, clen, mtu, camo2, &rlen) == 0);
    ck("combined: length preserved", rlen == cl);

    uint8_t http[2048];
    size_t hl = tx_http_wrap(camo2, rlen, http, sizeof http);
    ck("combined: http wrap", hl > 0);

    uint8_t body[1024];
    size_t blen = sizeof body;
    ck("combined: http unwrap", tx_http_unwrap(http, hl, body, &blen) == 0);

    uint8_t out[1024];
    size_t olen = sizeof out;
    ck("combined: decamouflage", ev_decamouflage(EV_MODE_TLS_HELLO, body, blen, out, &olen) == 0);
    ck("combined: frame identical end-to-end",
       olen == sizeof frame && memcmp(out, frame, sizeof frame) == 0);
}

/* 负向用例 */
static void run_negative(void) {
    uint8_t frame[64];
    memset(frame, 0xAB, sizeof frame);

    /* 容量不足 */
    uint8_t tiny[8];
    ck("neg: camouflage cap too small -> 0",
       ev_camouflage(EV_MODE_DOH, frame, sizeof frame, HOST, tiny, sizeof tiny) == 0);

    /* 伪装报文过短 */
    uint8_t shortbuf[3] = { 0x16, 0x03, 0x01 };
    uint8_t o[64]; size_t ol = sizeof o;
    ck("neg: decamouflage truncated TLS record -> -1",
       ev_decamouflage(EV_MODE_TLS_HELLO, shortbuf, sizeof shortbuf, o, &ol) == -1);

    /* 无头部结束符的 HTTP 形态 */
    const char nohdr[] = "POST /dns-query HTTP/1.1\r\nHost: x\r\n";
    size_t nol = sizeof o;
    ck("neg: decamouflage missing header terminator -> -1",
       ev_decamouflage(EV_MODE_DOH, (const uint8_t *)nohdr, strlen(nohdr), o, &nol) == -1);

    /* 分片 mtu 非法 */
    uint8_t chunks[64]; size_t nch = 0;
    ck("neg: frag split mtu<=4 -> 0",
       ev_frag_split(frame, sizeof frame, 4, chunks, sizeof chunks, &nch) == 0);

    /* 丢片可检出：伪装后分片，去掉最后一片 */
    uint8_t camo[512];
    size_t cl = ev_camouflage(EV_MODE_DOMAIN_FRONT, frame, sizeof frame, HOST, camo, sizeof camo);
    ck("neg: camouflage for loss test", cl > 0);
    const size_t mtu = 32;
    uint8_t fr[1024]; size_t n = 0;
    size_t flen = ev_frag_split(camo, cl, mtu, fr, sizeof fr, &n);
    ck("neg: frag split for loss test", flen > 0 && n >= 2);

    uint8_t rc[512]; size_t rl = sizeof rc;
    int rs = ev_frag_reassemble(fr, flen - mtu, mtu, rc, &rl);   /* 少一片 */
    ck("neg: lossy reassemble shorter than original", rs == 0 && rl < cl);

    /* 篡改可检出（此层无完整性保护，差异必须能被发现，保护由 02_c2 AEAD 负责） */
    uint8_t tampered[512];
    memcpy(tampered, camo, cl);
    tampered[cl - 1] ^= 0x01;                       /* 改 body 最后一字节 */
    uint8_t ot[128]; size_t otl = sizeof ot;
    int dr = ev_decamouflage(EV_MODE_DOMAIN_FRONT, tampered, cl, ot, &otl);
    ck("neg: tamper changes payload (detected by upper layer)",
       dr == 0 && memcmp(ot, frame, sizeof frame) != 0);
}

int main(void) {
    run_mode(EV_MODE_NONE);
    run_mode(EV_MODE_DOMAIN_FRONT);
    run_mode(EV_MODE_DOH);
    run_mode(EV_MODE_TLS_HELLO);
    run_combined();
    run_negative();

    printf("--- total=%d pass=%d fail=%d ---\n", total, total - fails, fails);
    return fails ? 1 : 0;
}
