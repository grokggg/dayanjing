#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>
#include <stddef.h>

#define PROTO_OK          0
#define PROTO_ERR         (-1)
#define PROTO_ERR_FORMAT  (-2)
#define PROTO_ERR_AUTH    (-3)
#define PROTO_ERR_REPLAY  (-4)
#define PROTO_ERR_NOMEM   (-5)

#define PROTO_MAGIC       0xD4A1
#define PROTO_VERSION     1

/* message types */
#define PROTO_MSG_HANDSHAKE  0x01
#define PROTO_MSG_CHALLENGE  0x02
#define PROTO_MSG_AUTH       0x03
#define PROTO_MSG_SESSION    0x04
#define PROTO_MSG_CONFIRM    0x05
#define PROTO_MSG_TASK       0x10
#define PROTO_MSG_RESULT     0x11
#define PROTO_MSG_HEARTBEAT  0x20
#define PROTO_MSG_DATA       0x30

#define PROTO_MAX_PAYLOAD    (64 * 1024)

/* frame header: 32 bytes
 *  magic(2) | version(1) | msg_type(1) | session_id(6) | flags(1) | nonce_counter(4) | payload_len(4) | nonce(8) | payload | tag(16)
 *  total header = 2+1+1+6+1+4+4+8 = 27, payload, then 16-byte tag
 */
#define PROTO_HEADER_LEN     27
#define PROTO_TAG_LEN        16
#define PROTO_NONCE_LEN      8

typedef struct {
    uint8_t  session_id[6];
    uint32_t nonce_counter;
    uint8_t  nonce[PROTO_NONCE_LEN];
    uint8_t  msg_type;
    uint8_t  flags;
    uint32_t payload_len;
    uint8_t *payload;
} proto_frame_t;

/* encode: build wire-format frame from frame struct + plaintext payload
 * output buffer must be at least PROTO_HEADER_LEN + payload_len + PROTO_TAG_LEN */
int proto_frame_encode(const proto_frame_t *frame, uint8_t *out, size_t *out_len);

/* decode: parse wire-format frame into frame struct
 * caller must free frame->payload */
int proto_frame_decode(const uint8_t *in, size_t in_len, proto_frame_t *frame);

/* seal: encrypt + encode (uses crypto_aead_seal from 00_crypto)
 * key must be 32 bytes */
int proto_seal(const uint8_t *key, proto_frame_t *frame, uint8_t *out, size_t *out_len);

/* open: decode + decrypt
 * returns PROTO_OK on success, PROTO_ERR_AUTH on tag mismatch */
int proto_open(const uint8_t *key, const uint8_t *in, size_t in_len, proto_frame_t *frame);

/* replay window: check if nonce_counter is fresh */
int proto_replay_check(uint32_t *window, uint32_t window_size, uint32_t counter);

/* helper: build AAD for AEAD from frame metadata */
void proto_build_aad(const proto_frame_t *frame, uint8_t *aad, size_t *aad_len);

/* cleanup */
void proto_frame_free(proto_frame_t *frame);

const char *proto_strerror(int err);

#endif
