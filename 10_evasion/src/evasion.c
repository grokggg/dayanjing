#include "evasion.h"
#include <stdlib.h>
#include <string.h>

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
        if (off + plen > *outlen) return -1;   /* 调用方给的容量 */
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
