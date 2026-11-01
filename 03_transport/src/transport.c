#include "transport.h"
#include <string.h>
#include <stdio.h>

/* ---------------- HTTP ---------------- */
size_t tx_http_wrap(const uint8_t *frame, size_t len, uint8_t *out, size_t cap) {
    static const char req[] =
        "POST /api/v1/telemetry HTTP/1.1\r\n"
        "Host: cdn.example.com\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: ";
    size_t rl = strlen(req);
    char num[32];
    int nl = snprintf(num, sizeof num, "%zu\r\n\r\n", len);
    if (nl < 0) return 0;
    size_t hl = rl + (size_t)nl;
    if (cap < hl + len) return 0;
    memcpy(out, req, rl);
    memcpy(out + rl, num, (size_t)nl);
    memcpy(out + hl, frame, len);
    return hl + len;
}

int tx_http_unwrap(const uint8_t *resp, size_t rlen, uint8_t *out, size_t *outlen) {
    size_t cap = *outlen;
    size_t i = 0;
    while (i + 3 < rlen) {
        if (resp[i] == '\r' && resp[i+1] == '\n' && resp[i+2] == '\r' && resp[i+3] == '\n') {
            i += 4;
            size_t body = rlen - i;
            if (body > cap) return -1;
            memcpy(out, resp + i, body);
            *outlen = body;
            return 0;
        }
        i++;
    }
    return -1;
}

/* ---------------- DNS (base32, no padding) ---------------- */
static const char b32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static int b32_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

size_t tx_dns_wrap(const uint8_t *frame, size_t len, char *out, size_t cap) {
    size_t o = 0;
    for (size_t i = 0; i < len; i += 5) {
        uint8_t b[5] = {0};
        size_t n = (len - i) < 5 ? (len - i) : 5;
        memcpy(b, frame + i, n);
        uint64_t acc = 0;
        for (size_t j = 0; j < n; j++) acc = (acc << 8) | (uint64_t)b[j];
        unsigned bits = (unsigned)(n * 8);
        unsigned chars = (bits + 4) / 5;
        if (o + chars >= cap) return 0;
        for (unsigned c = 0; c < chars; c++) {
            int shift = (int)bits - 5 * ((int)c + 1);
            if (shift >= 0)
                out[o++] = b32_alphabet[(acc >> shift) & 31u];
            else
                out[o++] = b32_alphabet[(acc << (-shift)) & 31u];
        }
    }
    if (o >= cap) return 0;
    out[o] = '\0';
    return o;
}

int tx_dns_unwrap(const char *label, uint8_t *out, size_t *outlen) {
    size_t cap = *outlen;
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (const char *p = label; *p; p++) {
        int v = b32_val(*p);
        if (v < 0) return -1;
        acc = (acc << 5) | (uint32_t)v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) return -1;
            out[o++] = (uint8_t)((acc >> bits) & 0xFFu);
        }
    }
    *outlen = o;
    return 0;
}

/* ---------------- ICMP ---------------- */
size_t tx_icmp_wrap(const uint8_t *frame, size_t len, uint8_t *out, size_t cap) {
    if (cap < len + 4) return 0;
    out[0] = 0xDA;
    out[1] = 0x7A;
    out[2] = (uint8_t)(len >> 8);
    out[3] = (uint8_t)(len & 0xFF);
    memcpy(out + 4, frame, len);
    return len + 4;
}

int tx_icmp_unwrap(const uint8_t *payload, size_t plen, uint8_t *out, size_t *outlen) {
    size_t cap = *outlen;
    if (plen < 4) return -1;
    if (payload[0] != 0xDA || payload[1] != 0x7A) return -1;
    size_t len = ((size_t)payload[2] << 8) | (size_t)payload[3];
    if (plen < len + 4) return -1;
    if (len > cap) return -1;
    memcpy(out, payload + 4, len);
    *outlen = len;
    return 0;
}
