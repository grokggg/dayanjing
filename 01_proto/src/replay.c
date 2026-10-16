/*
 * replay.c — 滑动重放窗口（复刻 13_c2_server/frame.py::ReplayWindow）
 *
 * 关键不变量：
 *  - 键 = (implant_id, key_generation)，跨重连不重置
 *  - seen 为稀疏集合，highest 为最高已接受序号
 *  - accept() 仅 'new' 允许上层处理
 *  - 窗口满且对端落后时明确拒绝（不静默接受）
 */
#include "proto.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* 每个窗口用位图表示 [highest-capacity+1, highest] 区间内的已接受序号 */
struct replay_window {
    struct replay_key key;
    uint64_t highest;
    uint32_t capacity;
    uint64_t *bits;      /* 变长位图，bits[0] 对应 highest-capacity+1 */
    size_t    bits_words;
};

struct replay_state {
    struct replay_window *w;
    size_t n, cap;
    uint32_t default_capacity;
};

struct replay_state *replay_new(uint32_t capacity) {
    if (capacity == 0) capacity = PROTO_REPLAY_WINDOW;
    struct replay_state *rs = calloc(1, sizeof(*rs));
    if (!rs) return NULL;
    rs->default_capacity = capacity;
    return rs;
}

void replay_free(struct replay_state *rs) {
    if (!rs) return;
    for (size_t i = 0; i < rs->n; i++) free(rs->w[i].bits);
    free(rs->w);
    free(rs);
}

static struct replay_window *find_win(struct replay_state *rs,
                                     const struct replay_key *key) {
    for (size_t i = 0; i < rs->n; i++)
        if (rs->w[i].key.generation == key->generation &&
            memcmp(rs->w[i].key.implant_id, key->implant_id,
                   sizeof(key->implant_id)) == 0)
            return &rs->w[i];
    return NULL;
}

static struct replay_window *ensure_win(struct replay_state *rs,
                                       const struct replay_key *key) {
    struct replay_window *w = find_win(rs, key);
    if (w) return w;
    if (rs->n == rs->cap) {
        size_t nc = rs->cap ? rs->cap * 2 : 4;
        struct replay_window *nw = realloc(rs->w, nc * sizeof(*nw));
        if (!nw) return NULL;
        rs->w = nw; rs->cap = nc;
    }
    w = &rs->w[rs->n++];
    memset(w, 0, sizeof(*w));
    memcpy(w->key.implant_id, key->implant_id, sizeof(key->implant_id));
    w->key.generation = key->generation;
    w->capacity = rs->default_capacity;
    return w;
}

static void bitmap_resize(struct replay_window *w, uint64_t new_highest) {
    /* 保证位图覆盖 [new_highest - capacity + 1, new_highest] */
    if (w->highest == 0 && w->capacity == 0) w->capacity = 1024;
    uint64_t lo = new_highest >= (uint64_t)w->capacity - 1
                    ? new_highest - (w->capacity - 1) : 0;
    size_t need = (size_t)(new_highest - lo + 1);   /* 区间元素数 */
    size_t words = (need + 63) / 64;
    if (words <= w->bits_words) return;
    uint64_t *nb = calloc(words, sizeof(uint64_t));
    if (!nb) return;
    /* 旧区间 [old_lo, old_hi] 搬到新位图 */
    uint64_t old_lo = w->highest >= (uint64_t)w->capacity - 1
                        ? w->highest - (w->capacity - 1) : 0;
    for (uint64_t s = old_lo; s <= w->highest && w->bits; s++) {
        uint64_t idx = s - old_lo;
        if (w->bits[idx / 64] & ((uint64_t)1 << (idx % 64))) {
            uint64_t ns = s;   /* 序号不变，在新位图中直接置位 */
            if (ns >= lo) {
                uint64_t off = ns - lo;
                nb[off / 64] |= ((uint64_t)1 << (off % 64));
            }
        }
    }
    free(w->bits);
    w->bits = nb;
    w->bits_words = words;
}

static void set_seen(struct replay_window *w, uint64_t seq) {
    if (w->highest == 0 && w->capacity == 0) w->capacity = 1024;
    uint64_t lo = w->highest >= (uint64_t)w->capacity - 1
                    ? w->highest - (w->capacity - 1) : 0;
    if (seq < lo) return;                      /* 超出窗口低位，丢弃 */
    if (!w->bits) bitmap_resize(w, seq);
    else if (seq - lo >= w->bits_words * 64) bitmap_resize(w, seq);
    if (!w->bits) return;
    uint64_t off = seq - lo;
    w->bits[off / 64] |= ((uint64_t)1 << (off % 64));
}

static bool is_seen(struct replay_window *w, uint64_t seq) {
    if (!w->bits) return false;
    uint64_t lo = w->highest >= (uint64_t)w->capacity - 1
                    ? w->highest - (w->capacity - 1) : 0;
    if (seq < lo) return false;                /* 低于窗口视为未记录 */
    uint64_t off = seq - lo;
    if (off >= w->bits_words * 64) return false;
    return (w->bits[off / 64] >> (off % 64)) & 1;
}

replay_decision_t replay_accept(struct replay_state *rs,
                               const struct replay_key *key, uint64_t seq) {
    if (!rs || !key) return REPLAY_REPLAY;
    struct replay_window *w = ensure_win(rs, key);
    if (!w) return REPLAY_REPLAY;

    if (is_seen(w, seq)) return REPLAY_REPLAY;

    uint64_t lo = w->highest >= (uint64_t)w->capacity - 1
                    ? w->highest - (w->capacity - 1) : 0;
    if (w->highest > 0 && seq < lo) return REPLAY_TOO_OLD;

    if (w->highest > 0 && seq - w->highest > (uint64_t)w->capacity)
        return REPLAY_FUTURE_GAP;

    set_seen(w, seq);
    if (seq > w->highest) w->highest = seq;
    return REPLAY_ACCEPTED;
}

void replay_rotate(struct replay_state *rs, const struct replay_key *key) {
    if (!rs || !key) return;
    /* 代际切换：新建空窗口；旧代际保留但不再前进 */
    struct replay_window *w = ensure_win(rs, key);
    (void)w;
}

uint64_t replay_highest(const struct replay_state *rs,
                       const struct replay_key *key) {
    if (!rs) return 0;
    struct replay_window *w = find_win((struct replay_state *)rs, key);
    return w ? w->highest : 0;
}

size_t replay_seen_count(const struct replay_state *rs,
                         const struct replay_key *key) {
    if (!rs) return 0;
    struct replay_window *w = find_win((struct replay_state *)rs, key);
    if (!w || !w->bits) return 0;
    size_t c = 0;
    for (size_t i = 0; i < w->bits_words; i++) {
        uint64_t v = w->bits[i];
        while (v) { c += v & 1; v >>= 1; }
    }
    return c;
}

uint8_t *replay_snapshot(const struct replay_state *rs,
                         const struct replay_key *key,
                         size_t *seen_bytes, uint64_t *highest) {
    if (seen_bytes) *seen_bytes = 0;
    if (highest) *highest = 0;
    if (!rs || !key || !seen_bytes || !highest) return NULL;
    struct replay_window *w = find_win((struct replay_state *)rs, key);
    if (!w) return NULL;
    *highest = w->highest;
    if (!w->bits || w->bits_words == 0) return NULL;
    size_t n = w->bits_words * sizeof(uint64_t);
    uint8_t *buf = malloc(n);
    if (!buf) return NULL;
    memcpy(buf, w->bits, n);
    *seen_bytes = n;
    return buf;
}

void replay_restore(struct replay_state *rs, const struct replay_key *key,
                    const uint8_t *seen_bits, size_t seen_bytes, uint64_t highest) {
    if (!rs || !key) return;
    struct replay_window *w = ensure_win(rs, key);
    if (!w) return;
    free(w->bits);
    w->bits = NULL;
    w->bits_words = 0;
    if (seen_bytes && seen_bits) {
        w->bits_words = seen_bytes / sizeof(uint64_t);
        if (w->bits_words) {
            w->bits = malloc(seen_bytes);
            if (w->bits) memcpy(w->bits, seen_bits, seen_bytes);
            else w->bits_words = 0;
        }
    }
    w->highest = highest;
}
