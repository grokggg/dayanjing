#include "evasion.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

size_t ev_frag_split(const uint8_t *frame, size_t len, size_t mtu,
                     uint8_t *out, size_t cap, size_t *chunks) {
    if (!frame || !out || !chunks || mtu <= 4) return 0;
    size_t payload_max = mtu - 4;
    size_t n = (len + payload_max - 1) / payload_max;
    if (n == 0) return 0;
    if (cap < n * mtu) return 0;
    memset(out, 0, n * mtu);
    for (size_t i = 0; i < n; i++) {
        size_t off = i * payload_max;
        size_t plen = (len - off) < payload_max ? (len - off) : payload_max;
        uint8_t *c = out + i * mtu;
        c[0] = (uint8_t)(i & 0xFF);
        c[1] = (uint8_t)((i >> 8) & 0xFF);
        c[2] = (uint8_t)(plen & 0xFF);
        c[3] = (uint8_t)((plen >> 8) & 0xFF);
        memcpy(c + 4, frame + off, plen);
    }
    *chunks = n;
    return n * mtu;
}

int ev_frag_reassemble(const uint8_t *chunks, size_t chunks_len, size_t mtu,
                       uint8_t *out, size_t *outlen) {
    if (!chunks || !out || !outlen || mtu <= 4) return -1;
    size_t payload_max = mtu - 4;
    size_t n = chunks_len / mtu;
    if (n == 0) return -1;
    size_t total = 0;
    for (size_t i = 0; i < n; i++) {
        const uint8_t *c = chunks + i * mtu;
        size_t seq = (size_t)c[0] | ((size_t)c[1] << 8);
        size_t plen = (size_t)c[2] | ((size_t)c[3] << 8);
        if (plen > payload_max) return -1;
        size_t off = seq * payload_max;
        if (off + plen > *outlen) return -1;
        memcpy(out + off, c + 4, plen);
        if (off + plen > total) total = off + plen;
    }
    *outlen = total;
    return 0;
}

int ev_jitter(int base_ms, int jitter_ms) {
    if (base_ms < 0) base_ms = 0;
    if (jitter_ms <= 0) return base_ms;
    return base_ms + (int)(rand() % (jitter_ms + 1));
}

size_t ev_camouflage(ev_mode_t mode, const uint8_t *frame, size_t len,
                     const char *host, uint8_t *out, size_t cap) {
    if (!frame || !out) return 0;
    if (mode == EV_MODE_NONE) {
        if (cap < len) return 0;
        memcpy(out, frame, len);
        return len;
    }
    if (mode == EV_MODE_DOMAIN_FRONT || mode == EV_MODE_DOH) {
        const char *path = (mode == EV_MODE_DOH) ? "/dns-query" : "/cdn-cgi/trace";
        int hl = snprintf((char *)out, cap,
                          "POST %s HTTP/1.1\r\nHost: %s\r\n"
                          "Content-Length: %zu\r\n\r\n",
                          path, host ? host : "front.example.com", len);
        if (hl < 0 || (size_t)hl >= cap) return 0;
        if ((size_t)hl + len > cap) return 0;
        memcpy(out + hl, frame, len);
        return (size_t)hl + len;
    }
    if (mode == EV_MODE_TLS_HELLO) {
        if (cap < 5 + len) return 0;
        out[0] = 0x16; out[1] = 0x03; out[2] = 0x01;
        out[3] = (uint8_t)((len >> 8) & 0xFF);
        out[4] = (uint8_t)(len & 0xFF);
        memcpy(out + 5, frame, len);
        return 5 + len;
    }
    return 0;
}

int ev_decamouflage(ev_mode_t mode, const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len) {
    if (!in || !out || !out_len) return -1;
    if (mode == EV_MODE_NONE) {
        if (in_len > *out_len) return -1;
        memcpy(out, in, in_len);
        *out_len = in_len;
        return 0;
    }
    if (mode == EV_MODE_DOMAIN_FRONT || mode == EV_MODE_DOH) {
        long found = -1;
        for (size_t i = 0; i + 3 < in_len; i++) {
            if (in[i] == '\r' && in[i+1] == '\n' && in[i+2] == '\r' && in[i+3] == '\n') {
                found = (long)(i + 4);
                break;
            }
        }
        if (found < 0) return -1;
        size_t bl = in_len - (size_t)found;
        if (bl > *out_len) return -1;
        memcpy(out, in + found, bl);
        *out_len = bl;
        return 0;
    }
    if (mode == EV_MODE_TLS_HELLO) {
        if (in_len < 5 || in[0] != 0x16 || in[1] != 0x03 || in[2] != 0x01) return -1;
        size_t bl = in_len - 5;
        if (bl > *out_len) return -1;
        memcpy(out, in + 5, bl);
        *out_len = bl;
        return 0;
    }
    return -1;
}
