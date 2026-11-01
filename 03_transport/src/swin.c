#include "tx_swin.h"
#include <string.h>

void tx_swin_tx_init(tx_swin_tx_t *w, uint32_t size, uint32_t total) {
    if (!w) return;
    memset(w, 0, sizeof(*w));
    if (size == 0 || size > TX_SWIN_MAX) size = TX_SWIN_MAX;
    w->size = size;
    w->total = total;
}

int tx_swin_tx_next(tx_swin_tx_t *w, uint32_t *seq) {
    if (!w || !seq) return TX_SWIN_ERR_ARGS;
    if (w->next >= w->total) return TX_SWIN_DONE;
    if (w->next >= w->base + w->size) return TX_SWIN_DONE; /* 窗口满，等 ACK */
    *seq = w->next;
    w->next++;
    return 0;
}

int tx_swin_tx_ack(tx_swin_tx_t *w, uint32_t ack) {
    if (!w) return TX_SWIN_ERR_ARGS;
    if (ack > w->total) return TX_SWIN_ERR_RANGE;
    if (ack < w->base) return TX_SWIN_ERR_RANGE; /* 迟到/重复 ACK */
    if (ack > w->next) ack = w->next;            /* 不得超过已发范围 */
    w->base = ack;
    return 0;
}

int tx_swin_tx_done(const tx_swin_tx_t *w) {
    if (!w) return TX_SWIN_ERR_ARGS;
    return (w->base >= w->total) ? 1 : 0;
}

int tx_swin_tx_pending(const tx_swin_tx_t *w, uint32_t *from, uint32_t *count) {
    if (!w || !from || !count) return TX_SWIN_ERR_ARGS;
    *from = w->base;
    *count = (w->next > w->base) ? (w->next - w->base) : 0;
    return 0;
}

void tx_swin_rx_init(tx_swin_rx_t *w, uint32_t size) {
    if (!w) return;
    memset(w, 0, sizeof(*w));
    if (size == 0 || size > TX_SWIN_MAX) size = TX_SWIN_MAX;
    w->size = size;
}

int tx_swin_rx_put(tx_swin_rx_t *w, uint32_t seq, int fin,
                   const uint8_t *d, size_t n) {
    if (!w) return TX_SWIN_ERR_ARGS;
    if (n > 0 && !d) return TX_SWIN_ERR_ARGS;
    if (n > TX_SWIN_CHUNK) return TX_SWIN_ERR_TOOBIG;

    if (w->closed && w->total && seq >= w->total) return TX_SWIN_ERR_RANGE;
    if (seq < w->base) return 0;                       /* 已交付过，静默丢弃 */
    if (seq >= w->base + w->size) return TX_SWIN_ERR_RANGE; /* 超前，超出窗口 */

    uint32_t idx = seq % w->size;
    if (w->used[idx] && w->slen[idx] == (uint16_t)n) return 0; /* 重复片 */
    if (n > 0) memcpy(w->slot[idx], d, n);
    w->slen[idx] = (uint16_t)n;
    w->used[idx] = 1;
    if (fin) {
        w->closed = 1;
        w->total = seq + 1;
    }
    return 0;
}

int tx_swin_rx_drain(tx_swin_rx_t *w, uint8_t *out, size_t cap, size_t *olen) {
    if (!w || !olen) return TX_SWIN_ERR_ARGS;
    *olen = 0;
    if (out && cap == 0) return TX_SWIN_ERR_ARGS;

    size_t used_bytes = 0;
    while (1) {
        uint32_t idx = w->base % w->size;
        if (!w->used[idx]) break;
        if (used_bytes + w->slen[idx] > cap) return TX_SWIN_ERR_NOSPACE;
        if (out) memcpy(out + used_bytes, w->slot[idx], w->slen[idx]);
        used_bytes += w->slen[idx];
        w->used[idx] = 0;
        w->slen[idx] = 0;
        w->base++;
    }
    *olen = used_bytes;
    if (w->closed && w->total && w->base >= w->total) return TX_SWIN_DONE;
    return 0;
}

int tx_swin_rx_done(const tx_swin_rx_t *w) {
    if (!w) return TX_SWIN_ERR_ARGS;
    return (w->closed && w->total && w->base >= w->total) ? 1 : 0;
}
