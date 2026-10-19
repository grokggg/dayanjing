#include "evasion.h"
#include "evasion_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_basic(void)
{
    /* 构造一段 500 字节的伪帧 */
    uint8_t frame[500];
    for (int i = 0; i < 500; i++) frame[i] = (uint8_t)(i & 0xff);

    uint8_t *frags[16];
    size_t lens[16];
    size_t frag_count = 0;
    int rc = evasion_fragment(frame, sizeof(frame), 100, frags, lens, 16, &frag_count);
    if (rc != EVASION_OK) { fprintf(stderr, "fragment rc=%d\n", rc); return 1; }
    if (frag_count != 5) {
        fprintf(stderr, "frag_count=%zu expect=5\n", frag_count);
        evasion_fragment_free(frags, frag_count);
        return 1;
    }

    /* 验证每个分片头 */
    for (size_t i = 0; i < frag_count; i++) {
        uint16_t magic = ((uint16_t)frags[i][0] << 8) | frags[i][1];
        if (magic != EVASION_FRAG_MAGIC) { fprintf(stderr, "bad magic[%zu]\n", i); return 1; }
        uint16_t total = ((uint16_t)frags[i][2] << 8) | frags[i][3];
        if (total != 5) { fprintf(stderr, "bad total[%zu]=%u\n", i, total); return 1; }
        uint16_t idx = ((uint16_t)frags[i][4] << 8) | frags[i][5];
        if (idx != (uint16_t)i) { fprintf(stderr, "bad idx[%zu]=%u\n", i, idx); return 1; }
    }

    /* 重组 */
    uint8_t recovered[1024];
    size_t rec_len = sizeof(recovered);
    rc = evasion_defragment((const uint8_t **)frags, lens, frag_count, recovered, &rec_len);
    if (rc != EVASION_OK) { fprintf(stderr, "defrag rc=%d\n", rc); return 1; }
    if (rec_len != sizeof(frame)) {
        fprintf(stderr, "rec_len=%zu expect=%zu\n", rec_len, sizeof(frame));
        evasion_fragment_free(frags, frag_count);
        return 1;
    }
    if (memcmp(recovered, frame, sizeof(frame)) != 0) {
        fprintf(stderr, "recovered mismatch\n");
        evasion_fragment_free(frags, frag_count);
        return 1;
    }
    evasion_fragment_free(frags, frag_count);
    printf("  [PASS] fragment basic (500B -> 5 frags of 100B)\n");
    return 0;
}

static int test_out_of_order(void)
{
    uint8_t frame[250];
    for (int i = 0; i < 250; i++) frame[i] = (uint8_t)i;

    uint8_t *frags[8];
    size_t lens[8];
    size_t frag_count = 0;
    int rc = evasion_fragment(frame, sizeof(frame), 80, frags, lens, 8, &frag_count);
    if (rc != EVASION_OK) { fprintf(stderr, "fragment rc=%d\n", rc); return 1; }

    /* 乱序重排: 3,1,2,0 */
    uint8_t *ordered[8];
    size_t olens[8];
    for (size_t i = 0; i < frag_count; i++) ordered[i] = NULL;
    for (size_t i = 0; i < frag_count; i++) {
        uint16_t idx = ((uint16_t)frags[i][4] << 8) | frags[i][5];
        ordered[idx] = frags[i];
        olens[idx] = lens[i];
    }

    uint8_t recovered[512];
    size_t rec_len = sizeof(recovered);
    rc = evasion_defragment((const uint8_t **)ordered, olens, frag_count, recovered, &rec_len);
    if (rc != EVASION_OK) { fprintf(stderr, "defrag oo rc=%d\n", rc); return 1; }
    if (rec_len != sizeof(frame)) { fprintf(stderr, "oo rec_len=%zu\n", rec_len); return 1; }
    if (memcmp(recovered, frame, sizeof(frame)) != 0) {
        fprintf(stderr, "oo recovered mismatch\n");
        evasion_fragment_free(frags, frag_count);
        return 1;
    }
    evasion_fragment_free(frags, frag_count);
    printf("  [PASS] fragment out-of-order defrag\n");
    return 0;
}

static int test_single(void)
{
    uint8_t frame[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
    uint8_t *frags[1];
    size_t lens[1];
    size_t frag_count = 0;
    int rc = evasion_fragment(frame, sizeof(frame), 1024, frags, lens, 1, &frag_count);
    if (rc != EVASION_OK) return 1;
    if (frag_count != 1) { fprintf(stderr, "single: frag_count=%zu\n", frag_count); return 1; }
    uint8_t rec[32];
    size_t rec_len = sizeof(rec);
    rc = evasion_defragment((const uint8_t **)frags, lens, 1, rec, &rec_len);
    if (rc != EVASION_OK) return 1;
    if (rec_len != 16 || memcmp(rec, frame, 16) != 0) return 1;
    evasion_fragment_free(frags, frag_count);
    printf("  [PASS] fragment single\n");
    return 0;
}

int main(void)
{
    int f = 0;
    f |= test_basic();
    f |= test_out_of_order();
    f |= test_single();
    return f;
}
