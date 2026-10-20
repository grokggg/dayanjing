#include "evasion.h"
#include <string.h>

/* xorshift32：可复现、无全局状态 */
static uint32_t xs32(uint32_t *s){
    uint32_t x = *s ? *s : 0x9E3779B9u;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    *s = x;
    return x;
}

int ev_jitter_seeded(int base_ms, int jitter_ms, uint32_t *seed){
    if(base_ms < 0 || jitter_ms < 0) return -1;
    if(jitter_ms == 0) return base_ms;
    uint32_t r = xs32(seed);
    return base_ms + (int)(r % (uint32_t)(jitter_ms + 1));
}

size_t ev_plan(size_t frame_len, size_t mtu, int base_ms, int jitter_ms,
               uint32_t *seed, ev_slot_t *slots, size_t scap){
    if(mtu <= 4 || !slots || scap == 0) return 0;
    size_t per = mtu - 4;
    if(per == 0) return 0;
    size_t chunks = (frame_len + per - 1) / per;
    if(chunks == 0) return 0;
    size_t n = chunks < scap ? chunks : scap;
    for(size_t i = 0; i < n; i++){
        slots[i].index = i;
        slots[i].offset = i * mtu;
        slots[i].len = mtu;
        slots[i].delay_ms = ev_jitter_seeded(base_ms, jitter_ms, seed);
    }
    return chunks;
}
