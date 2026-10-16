/*
 * test_proto.c — 协议层测试
 *
 * 密钥语义：ChaCha20-Poly1305 是对称 AEAD，收发双方使用同一会话密钥。
 * k_send / k_recv 是方向语义标记，实际值相同（由同一 master 派生）。
 * 不同 master 派生出的密钥互不可解，这才是真正的密钥分离。
 */
#include "proto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int total = 0, failed = 0;
#define CHECK(name, cond) do { total++; if (!(cond)) { failed++; fprintf(stderr,"  FAIL %s\n",name); } } while(0)

static void fixed_key(uint8_t out[PROTO_KEY_LEN], uint8_t v) {
    memset(out, v, PROTO_KEY_LEN);
}

/* 派生会话密钥：收发共享同一密钥（对称 AEAD 要求） */
static void derive_session_key(const uint8_t master[PROTO_KEY_LEN],
                               uint8_t key[PROTO_KEY_LEN]) {
    crypto_kdf_derive(key, PROTO_KEY_LEN, master, PROTO_KEY_LEN,
                      (const uint8_t *)"proto:session:v1", 15);
}

static void reset_prefix(uint8_t prefix[8]) {
    for (int i = 0; i < 8; i++) prefix[i] = (uint8_t)i;
}

int main(void) {
    uint8_t prefix[8];
    reset_prefix(prefix);

    /* ===== 1. seal/open 往返 ===== */
    {
        uint8_t master[PROTO_KEY_LEN];
        fixed_key(master, 0xAA);
        uint8_t key[PROTO_KEY_LEN];
        derive_session_key(master, key);

        uint32_t counter = 0;
        uint8_t nonce[12];
        uint8_t wire[64*1024];
        size_t wire_len = 0;
        uint8_t payload[] = "hello payload";
        CHECK("seal ok", proto_seal(key, prefix, &counter, nonce, 1, 3,
                    payload, sizeof(payload)-1, wire, sizeof(wire), &wire_len) == PROTO_OK);
        CHECK("counter increments", counter == 1);
        CHECK("wire has type+nonce+tag", wire_len >= 4+4+12+16);

        uint64_t seq = 0; uint32_t type = 0;
        uint8_t plout[64*1024]; size_t pllen = 0;
        CHECK("open ok", proto_open(key, 0, wire, wire_len,
                    &seq, &type, plout, sizeof(plout), &pllen) == PROTO_OK);
        CHECK("seq match", seq == 1);
        CHECK("type match", type == 3);
        CHECK("payload match", pllen == sizeof(payload)-1
                && memcmp(plout, payload, pllen) == 0);
    }

    /* ===== 2. 错误密钥被拒绝 ===== */
    {
        uint8_t m1[PROTO_KEY_LEN], m2[PROTO_KEY_LEN];
        fixed_key(m1, 0xAA); fixed_key(m2, 0xBB);
        uint8_t key1[PROTO_KEY_LEN], key2[PROTO_KEY_LEN];
        derive_session_key(m1, key1);
        derive_session_key(m2, key2);

        uint32_t counter = 0;
        uint8_t nonce[12];
        uint8_t wire[64*1024]; size_t wire_len = 0;
        proto_seal(key1, prefix, &counter, nonce, 5, 1,
                   (const uint8_t *)"x", 1, wire, sizeof(wire), &wire_len);

        uint64_t seq; uint32_t type; uint8_t plout[16]; size_t pllen = 0;
        CHECK("different master rejected",
            proto_open(key2, 0, wire, wire_len,
                &seq, &type, plout, sizeof(plout), &pllen) == PROTO_TAG_FAIL);
        /* 完全无关密钥 */
        uint8_t garbage[PROTO_KEY_LEN];
        fixed_key(garbage, 0xFF);
        CHECK("garbage key rejected",
            proto_open(garbage, 0, wire, wire_len,
                &seq, &type, plout, sizeof(plout), &pllen) == PROTO_TAG_FAIL);
    }

    /* ===== 3. 篡改检测 ===== */
    {
        uint8_t master[PROTO_KEY_LEN]; fixed_key(master, 0xBB);
        uint8_t key[PROTO_KEY_LEN]; derive_session_key(master, key);
        uint32_t counter = 0;
        uint8_t nonce[12];
        uint8_t wire[64*1024]; size_t wire_len = 0;
        proto_seal(key, prefix, &counter, nonce, 7, 2,
                   (const uint8_t *)"tamper", 6, wire, sizeof(wire), &wire_len);

        uint64_t seq; uint32_t type; uint8_t plout[16]; size_t pllen = 0;
        uint8_t t1[sizeof(wire)]; memcpy(t1, wire, wire_len); t1[24] ^= 0x01;
        CHECK("tamper ct detected",
            proto_open(key, 0, t1, wire_len,
                &seq, &type, plout, sizeof(plout), &pllen) == PROTO_TAG_FAIL);

        uint8_t t2[sizeof(wire)]; memcpy(t2, wire, wire_len); t2[wire_len-1] ^= 0x01;
        CHECK("tamper tag detected",
            proto_open(key, 0, t2, wire_len,
                &seq, &type, plout, sizeof(plout), &pllen) == PROTO_TAG_FAIL);

        uint8_t t3[sizeof(wire)]; memcpy(t3, wire, wire_len); t3[10] ^= 0x01;
        CHECK("tamper nonce detected",
            proto_open(key, 0, t3, wire_len,
                &seq, &type, plout, sizeof(plout), &pllen) == PROTO_TAG_FAIL);

        /* 改帧头明文 msg_type → AAD 不一致 → 验签失败 */
        uint8_t t4[sizeof(wire)]; memcpy(t4, wire, wire_len);
        t4[4] ^= 0x01;
        CHECK("tamper hdr_type detected",
            proto_open(key, 0, t4, wire_len,
                &seq, &type, plout, sizeof(plout), &pllen) == PROTO_TAG_FAIL);
    }

    /* ===== 4. 重放窗口 ===== */
    {
        struct replay_state *rs = replay_new(1024);
        struct replay_key key = { .implant_id = "impl-001", .generation = 1 };
        CHECK("first seq accepted", replay_accept(rs, &key, 1) == REPLAY_ACCEPTED);
        CHECK("replay rejected", replay_accept(rs, &key, 1) == REPLAY_REPLAY);
        CHECK("seq 2 accepted", replay_accept(rs, &key, 2) == REPLAY_ACCEPTED);
        CHECK("seq 3 accepted", replay_accept(rs, &key, 3) == REPLAY_ACCEPTED);
        CHECK("out-of-order 5", replay_accept(rs, &key, 5) == REPLAY_ACCEPTED);
        CHECK("out-of-order 4", replay_accept(rs, &key, 4) == REPLAY_ACCEPTED);
        CHECK("out-of-order 6", replay_accept(rs, &key, 6) == REPLAY_ACCEPTED);
        replay_free(rs);
    }

    /* ===== 5. too_old / future_gap ===== */
    {
        struct replay_state *rs = replay_new(8);
        struct replay_key key = { .implant_id = "impl-old", .generation = 1 };
        for (int s = 10; s < 20; s++) replay_accept(rs, &key, s);
        CHECK("too old rejected", replay_accept(rs, &key, 5) == REPLAY_TOO_OLD);
        CHECK("future accepted", replay_accept(rs, &key, 25) == REPLAY_ACCEPTED);
        CHECK("gap rejected", replay_accept(rs, &key, 60) == REPLAY_FUTURE_GAP);
        replay_free(rs);
    }

    /* ===== 6. 跨代际 / 跨 implant 隔离 ===== */
    {
        struct replay_state *rs = replay_new(1024);
        struct replay_key g1 = { .implant_id = "impl-x", .generation = 1 };
        struct replay_key g2 = { .implant_id = "impl-x", .generation = 2 };
        replay_accept(rs, &g1, 1);
        CHECK("gen1 replay", replay_accept(rs, &g1, 1) == REPLAY_REPLAY);
        CHECK("gen2 fresh", replay_accept(rs, &g2, 1) == REPLAY_ACCEPTED);

        struct replay_key ka = { .implant_id = "impl-a", .generation = 1 };
        struct replay_key kb = { .implant_id = "impl-b", .generation = 1 };
        replay_accept(rs, &ka, 42);
        CHECK("other implant fresh", replay_accept(rs, &kb, 42) == REPLAY_ACCEPTED);
        replay_free(rs);
    }

    /* ===== 7. 快照/恢复持久化契约 ===== */
    {
        struct replay_state *rs = replay_new(1024);
        struct replay_key key = { .implant_id = "impl-p", .generation = 1 };
        replay_accept(rs, &key, 100);
        replay_accept(rs, &key, 101);
        replay_accept(rs, &key, 105);

        size_t sb = 0; uint64_t hi = 0;
        uint8_t *snap = replay_snapshot(rs, &key, &sb, &hi);
        CHECK("snapshot highest", hi == 105);
        CHECK("snapshot has data", snap != NULL && sb > 0);

        struct replay_state *rs2 = replay_new(1024);
        replay_restore(rs2, &key, snap, sb, hi);
        CHECK("restore: 100 replay", replay_accept(rs2, &key, 100) == REPLAY_REPLAY);
        CHECK("restore: 999 fresh", replay_accept(rs2, &key, 999) == REPLAY_ACCEPTED);
        free(snap);
        replay_free(rs); replay_free(rs2);
    }

    /* ===== 8. nonce counter 递增与溢出 ===== */
    {
        uint8_t master[PROTO_KEY_LEN]; fixed_key(master, 0xCC);
        uint8_t key[PROTO_KEY_LEN]; derive_session_key(master, key);
        uint8_t pfx[8]; reset_prefix(pfx);
        uint32_t c = UINT32_MAX - 2;
        uint8_t nonce[12];
        uint8_t wire[64*1024]; size_t wl = 0;
        CHECK("counter near full seal ok", proto_seal(key, pfx, &c, nonce, 1, 1,
                    (const uint8_t *)"a", 1, wire, sizeof(wire), &wl) == PROTO_OK);
        CHECK("counter advances", c == UINT32_MAX - 1);
        CHECK("counter full returns COUNTER_FULL", proto_seal(key, pfx, &c, nonce, 2, 1,
                    (const uint8_t *)"b", 1, wire, sizeof(wire), &wl) == PROTO_COUNTER_FULL);
    }

    /* ===== 9. 空 payload ===== */
    {
        uint8_t master[PROTO_KEY_LEN]; fixed_key(master, 0xDD);
        uint8_t key[PROTO_KEY_LEN]; derive_session_key(master, key);
        uint8_t pfx[8]; reset_prefix(pfx);
        uint32_t c = 0; uint8_t nonce[12];
        uint8_t wire[64*1024]; size_t wl = 0;
        CHECK("empty payload seal", proto_seal(key, pfx, &c, nonce, 0, 0,
                    NULL, 0, wire, sizeof(wire), &wl) == PROTO_OK);
        uint64_t seq; uint32_t type; uint8_t plout[8]; size_t pllen = 0;
        CHECK("empty payload open", proto_open(key, 0, wire, wl,
                    &seq, &type, plout, sizeof(plout), &pllen) == PROTO_OK
                && pllen == 0 && seq == 0);
    }

    /* ===== 10. 输出缓冲区太小 ===== */
    {
        uint8_t master[PROTO_KEY_LEN]; fixed_key(master, 0xEE);
        uint8_t key[PROTO_KEY_LEN]; derive_session_key(master, key);
        uint8_t pfx[8]; reset_prefix(pfx);
        uint32_t c = 0; uint8_t nonce[12];
        uint8_t wire[64]; size_t wl = 0;
        CHECK("too small out buffer rejected", proto_seal(key, pfx, &c, nonce, 0, 0,
                    NULL, 0, wire, sizeof(wire), &wl) == PROTO_RANGE);
    }

    /* ===== 11. 帧过短被拒 ===== */
    {
        uint8_t k[PROTO_KEY_LEN]; fixed_key(k, 0x11);
        uint64_t seq; uint32_t type; uint8_t pl[8]; size_t plen = 0;
        uint8_t tiny[16] = {0};
        CHECK("too short frame", proto_open(k, 0, tiny, sizeof(tiny),
                    &seq, &type, pl, sizeof(pl), &plen) == PROTO_TOO_SHORT);
    }

    /* ===== 12. 派生密钥确定性 & 分离 ===== */
    {
        uint8_t m[PROTO_KEY_LEN]; fixed_key(m, 0x77);
        uint8_t a[PROTO_KEY_LEN], b[PROTO_KEY_LEN];
        derive_session_key(m, a);
        derive_session_key(m, b);
        CHECK("key deterministic", memcmp(a, b, PROTO_KEY_LEN) == 0);

        uint8_t other[PROTO_KEY_LEN];
        crypto_kdf_derive(other, PROTO_KEY_LEN, m, PROTO_KEY_LEN,
                          (const uint8_t *)"proto:session:v2", 15);
        CHECK("info separates keys", memcmp(a, other, PROTO_KEY_LEN) != 0);

        uint8_t m2[PROTO_KEY_LEN]; fixed_key(m2, 0x88);
        uint8_t c[PROTO_KEY_LEN]; derive_session_key(m2, c);
        CHECK("master separates keys", memcmp(a, c, PROTO_KEY_LEN) != 0);
    }

    printf("[proto] %d/%d tests passed\n", total - failed, total);
    return failed ? 1 : 0;
}
