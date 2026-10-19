#include "proto.h"
#include "crypto.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int test_encode_decode(void) {
    uint8_t key[32];
    crypto_rng(key, 32);

    proto_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.msg_type = PROTO_MSG_TASK;
    frame.flags = 0x01;
    frame.nonce_counter = 42;
    crypto_rng(frame.session_id, 6);
    crypto_rng(frame.nonce, PROTO_NONCE_LEN);
    const char *payload = "echo hello world";
    frame.payload_len = strlen(payload);
    frame.payload = (uint8_t*)malloc(frame.payload_len);
    memcpy(frame.payload, payload, frame.payload_len);

    uint8_t encoded[PROTO_HEADER_LEN + 256];
    size_t encoded_len = sizeof(encoded);
    if (proto_frame_encode(&frame, encoded, &encoded_len) != PROTO_OK) {
        printf("encode fail\n"); return 1;
    }

    proto_frame_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    if (proto_frame_decode(encoded, encoded_len, &decoded) != PROTO_OK) {
        printf("decode fail\n"); return 1;
    }

    if (decoded.msg_type != frame.msg_type) { printf("msg_type mismatch\n"); return 1; }
    if (decoded.flags != frame.flags) { printf("flags mismatch\n"); return 1; }
    if (decoded.nonce_counter != frame.nonce_counter) { printf("counter mismatch\n"); return 1; }
    if (decoded.payload_len != frame.payload_len) { printf("len mismatch\n"); return 1; }
    if (memcmp(decoded.payload, frame.payload, frame.payload_len) != 0) {
        printf("payload mismatch\n"); return 1;
    }

    proto_frame_free(&frame);
    proto_frame_free(&decoded);
    printf("encode_decode ok\n");
    return 0;
}

static int test_seal_open(void) {
    uint8_t key[32];
    crypto_rng(key, 32);

    proto_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.msg_type = PROTO_MSG_RESULT;
    frame.flags = 0x02;
    frame.nonce_counter = 100;
    crypto_rng(frame.session_id, 6);
    crypto_rng(frame.nonce, PROTO_NONCE_LEN);
    const char *payload = "command output: success";
    frame.payload_len = strlen(payload);
    frame.payload = (uint8_t*)malloc(frame.payload_len);
    memcpy(frame.payload, payload, frame.payload_len);

    uint8_t sealed[PROTO_HEADER_LEN + 256 + PROTO_TAG_LEN];
    size_t sealed_len = sizeof(sealed);
    if (proto_seal(key, &frame, sealed, &sealed_len) != PROTO_OK) {
        printf("seal fail\n"); return 1;
    }

    /* tamper with ciphertext */
    sealed[PROTO_HEADER_LEN + 5] ^= 1;

    proto_frame_t opened;
    memset(&opened, 0, sizeof(opened));
    int rc = proto_open(key, sealed, sealed_len, &opened);
    if (rc != PROTO_ERR_AUTH) {
        printf("tamper not detected (got %d)\n", rc);
        proto_frame_free(&frame);
        return 1;
    }

    proto_frame_free(&frame);
    printf("seal_open ok\n");
    return 0;
}

static int test_magic_check(void) {
    uint8_t key[32];
    crypto_rng(key, 32);

    proto_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.msg_type = PROTO_MSG_HEARTBEAT;
    crypto_rng(frame.session_id, 6);
    crypto_rng(frame.nonce, PROTO_NONCE_LEN);

    uint8_t buf[128];
    size_t buf_len = sizeof(buf);
    proto_seal(key, &frame, buf, &buf_len);

    /* corrupt magic */
    buf[0] ^= 0xFF;

    proto_frame_t opened;
    memset(&opened, 0, sizeof(opened));
    int rc = proto_open(key, buf, buf_len, &opened);
    if (rc == PROTO_OK) { printf("magic check failed\n"); return 1; }

    printf("magic_check ok\n");
    return 0;
}

static int test_replay(void) {
    uint32_t window[2] = {0, 0}; /* [low, high] */
    uint32_t window_size = 10;

    if (proto_replay_check(window, window_size, 5) != PROTO_OK) { printf("replay 5 fail\n"); return 1; }
    if (proto_replay_check(window, window_size, 6) != PROTO_OK) { printf("replay 6 fail\n"); return 1; }
    if (proto_replay_check(window, window_size, 3) != PROTO_ERR_REPLAY) { printf("replay 3 should fail\n"); return 1; }
    if (proto_replay_check(window, window_size, 15) != PROTO_OK) { printf("replay 15 fail\n"); return 1; }

    printf("replay ok\n");
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_encode_decode();
    rc |= test_seal_open();
    rc |= test_magic_check();
    rc |= test_replay();
    printf("ALL TESTS %s\n", rc == 0 ? "PASS" : "FAIL");
    return rc;
}
