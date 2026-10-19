#include "evasion.h"
#include "evasion_internal.h"

#include <stdlib.h>
#include <string.h>

/*
 * 分片头(8 字节):
 *   magic(2)=0xE54A | total(2) | index(2) | reserved(2)
 * 之后是分片 payload。
 */

int evasion_fragment(const uint8_t *frame, size_t frame_len,
                     size_t max_payload,
                     uint8_t **out_frags, size_t *out_lens,
                     size_t max_frags, size_t *frag_count)
{
    if (!frame || !out_frags || !out_lens || !frag_count)
        return EVASION_ERR;
    if (max_payload == 0 || max_frags == 0)
        return EVASION_ERR;

    /* 计算分片数 */
    size_t total = (frame_len + max_payload - 1) / max_payload;
    if (total == 0) total = 1;
    if (total > EVASION_MAX_FRAGMENTS) return EVASION_ERR_NOMEM;
    if (total > max_frags) return EVASION_ERR_NOMEM;

    for (size_t i = 0; i < total; i++) {
        size_t off = i * max_payload;
        size_t plen = frame_len - off;
        if (plen > max_payload) plen = max_payload;

        size_t alloc = EVASION_FRAG_HEADER_LEN + plen;
        uint8_t *buf = (uint8_t *)malloc(alloc);
        if (!buf) {
            for (size_t j = 0; j < i; j++) free(out_frags[j]);
            return EVASION_ERR_NOMEM;
        }

        buf[0] = (uint8_t)(EVASION_FRAG_MAGIC >> 8);
        buf[1] = (uint8_t)(EVASION_FRAG_MAGIC & 0xff);
        buf[2] = (uint8_t)(total >> 8); buf[3] = (uint8_t)(total & 0xff);
        buf[4] = (uint8_t)(i >> 8);     buf[5] = (uint8_t)(i & 0xff);
        buf[6] = 0; buf[7] = 0;
        memcpy(buf + EVASION_FRAG_HEADER_LEN, frame + off, plen);

        out_frags[i] = buf;
        out_lens[i] = alloc;
    }
    *frag_count = total;
    return EVASION_OK;
}

void evasion_fragment_free(uint8_t **frags, size_t frag_count)
{
    if (!frags) return;
    for (size_t i = 0; i < frag_count; i++) free(frags[i]);
}

int evasion_defragment(const uint8_t **frags, const size_t *lens, size_t count,
                      uint8_t *out, size_t *out_len)
{
    if (!frags || !lens || !out || !out_len || count == 0)
        return EVASION_ERR;

    uint16_t total = 0;
    uint16_t max_idx = 0;
    /* 第一遍: 校验 magic, 确定 total */
    for (size_t i = 0; i < count; i++) {
        if (lens[i] < EVASION_FRAG_HEADER_LEN) return EVASION_ERR_FMT;
        uint16_t magic = ((uint16_t)frags[i][0] << 8) | frags[i][1];
        if (magic != EVASION_FRAG_MAGIC) return EVASION_ERR_FMT;
        uint16_t t = ((uint16_t)frags[i][2] << 8) | frags[i][3];
        if (i == 0) total = t;
        else if (t != total) return EVASION_ERR_FMT;
        uint16_t idx = ((uint16_t)frags[i][4] << 8) | frags[i][5];
        if (idx > max_idx) max_idx = idx;
    }

    if (total == 0 || max_idx >= total) return EVASION_ERR_FMT;

    /* 按 index 排序重组(用简单选择排序, 分片数少) */
    uint8_t *ordered[EVASION_MAX_FRAGMENTS];
    for (uint16_t i = 0; i < total; i++) ordered[i] = NULL;
    for (size_t i = 0; i < count; i++) {
        uint16_t idx = ((uint16_t)frags[i][4] << 8) | frags[i][5];
        ordered[idx] = (uint8_t *)frags[i];
    }
    /* 检查完整性 */
    for (uint16_t i = 0; i < total; i++) {
        if (!ordered[i]) return EVASION_ERR; /* 缺失分片 */
    }

    /* 计算总长并写出 */
    size_t need = 0;
    for (uint16_t i = 0; i < total; i++) {
        need += (lens[i] - EVASION_FRAG_HEADER_LEN);
    }
    if (need > *out_len) return EVASION_ERR_NOMEM;

    size_t pos = 0;
    for (uint16_t i = 0; i < total; i++) {
        size_t plen = lens[i] - EVASION_FRAG_HEADER_LEN;
        memcpy(out + pos, ordered[i] + EVASION_FRAG_HEADER_LEN, plen);
        pos += plen;
    }
    *out_len = pos;
    return EVASION_OK;
}
