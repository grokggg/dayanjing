#define _POSIX_C_SOURCE 200809L
#include "proto.h"
#include "crypto.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

const char *proto_strerror(int err) {
    switch (err) {
        case PROTO_OK: return "ok";
        case PROTO_ERR: return "error";
        case PROTO_ERR_FORMAT: return "format error";
        case PROTO_ERR_AUTH: return "auth failed";
        case PROTO_ERR_REPLAY: return "replay detected";
        case PROTO_ERR_NOMEM: return "no memory";
        default: return "unknown";
    }
}

void proto_frame_free(proto_frame_t *frame) {
    if (frame && frame->payload) {
        crypto_secure_zero(frame->payload, frame->payload_len);
        free(frame->payload);
        frame->payload = NULL;
    }
}

/* AAD construction: session_id || msg_type || direction || nonce_counter */
void proto_build_aad(const proto_frame_t *frame, uint8_t *aad, size_t *aad_len) {
    memcpy(aad, frame->session_id, 6);
    aad[6] = frame->msg_type;
    aad[7] = frame->flags;
    aad[8] = (frame->nonce_counter >> 24) & 0xFF;
    aad[9] = (frame->nonce_counter >> 16) & 0xFF;
    aad[10] = (frame->nonce_counter >> 8) & 0xFF;
    aad[11] = frame->nonce_counter & 0xFF;
    *aad_len = 12;
}

/* Wire format for sealed frame:
 *  [nonce(12)] [encrypted(header||payload)] [tag(16)]
 *  where header = magic|version|msg_type|session_id|flags|nonce_counter|payload_len
 */
int proto_seal(const uint8_t *key, proto_frame_t *frame, uint8_t *out, size_t *out_len) {
    if (!key || !frame || !out || !out_len) return PROTO_ERR;

    /* Step 1: encode plaintext frame (header + payload) */
    size_t plain_len = PROTO_HEADER_LEN + frame->payload_len;
    uint8_t *plain = (uint8_t*)malloc(plain_len);
    if (!plain) return PROTO_ERR_NOMEM;

    size_t pl = plain_len;
    int rc = proto_frame_encode(frame, plain, &pl);
    if (rc != PROTO_OK) {
        free(plain);
        return rc;
    }

    /* Step 2: build AAD.  Must be derivable by the receiver WITHOUT decrypting,
     * so we use the 12-byte AEAD nonce (frame->nonce(8) || counter(4)).  This is
     * identical to what proto_open() reconstructs from the ciphertext prefix. */
    uint8_t aad[12];
    memcpy(aad, frame->nonce, 8);
    aad[8]  = (frame->nonce_counter >> 24) & 0xFF;
    aad[9]  = (frame->nonce_counter >> 16) & 0xFF;
    aad[10] = (frame->nonce_counter >> 8) & 0xFF;
    aad[11] = frame->nonce_counter & 0xFF;
    size_t aad_len = 12;

    /* Step 3: AEAD encrypt
     * output layout: [12-byte AEAD nonce] [ciphertext] [16-byte tag]
     */
    size_t total = 12 + plain_len + PROTO_TAG_LEN;
    if (*out_len < total) {
        free(plain);
        return PROTO_ERR_NOMEM;
    }

    /* Use frame->nonce (8 bytes) + counter as 12-byte AEAD nonce */
    uint8_t aead_nonce[12];
    memcpy(aead_nonce, frame->nonce, 8);
    aead_nonce[8]  = (frame->nonce_counter >> 24) & 0xFF;
    aead_nonce[9]  = (frame->nonce_counter >> 16) & 0xFF;
    aead_nonce[10] = (frame->nonce_counter >> 8) & 0xFF;
    aead_nonce[11] = frame->nonce_counter & 0xFF;

    /* Write AEAD nonce first */
    memcpy(out, aead_nonce, 12);

    /* Encrypt: ciphertext goes after nonce, tag after ciphertext */
    uint8_t tag[PROTO_TAG_LEN];
    int ret = crypto_aead_seal(key, aead_nonce, 12,
                               aad, aad_len,
                               plain, plain_len,
                               out + 12, tag);
    if (ret == CRYPTO_OK) {
        memcpy(out + 12 + plain_len, tag, PROTO_TAG_LEN);
        *out_len = total;
        ret = PROTO_OK;
    } else {
        ret = PROTO_ERR;
    }

    crypto_secure_zero(plain, plain_len);
    free(plain);
    crypto_secure_zero(tag, PROTO_TAG_LEN);
    crypto_secure_zero(aead_nonce, 12);
    return ret;
}

int proto_open(const uint8_t *key, const uint8_t *in, size_t in_len, proto_frame_t *frame) {
    if (!key || !in || !frame) return PROTO_ERR;
    if (in_len < 12 + PROTO_HEADER_LEN + PROTO_TAG_LEN) return PROTO_ERR_FORMAT;

    /* Extract AEAD nonce (first 12 bytes) */
    uint8_t aead_nonce[12];
    memcpy(aead_nonce, in, 12);

    size_t ciphertext_len = in_len - 12 - PROTO_TAG_LEN;
    const uint8_t *ciphertext = in + 12;
    const uint8_t *tag = in + 12 + ciphertext_len;

    /*
     * AAD = frame->nonce(8) || counter(4) = the first 12 bytes of the AEAD nonce.
     * This is identical to what proto_seal() used, and is derivable by the receiver
     * directly from the ciphertext prefix without decrypting anything.
     */
    uint8_t aad[12];
    memcpy(aad, aead_nonce, 12);
    size_t aad_len = 12;

    uint8_t *decrypted = (uint8_t*)malloc(ciphertext_len);
    if (!decrypted) return PROTO_ERR_NOMEM;

    int ret = crypto_aead_open(key, aead_nonce, 12,
                               aad, aad_len,
                               ciphertext, ciphertext_len,
                               tag, decrypted);

    if (ret == CRYPTO_OK) {
        ret = proto_frame_decode(decrypted, ciphertext_len, frame);
    } else {
        ret = PROTO_ERR_AUTH;
    }

    crypto_secure_zero(decrypted, ciphertext_len);
    free(decrypted);
    crypto_secure_zero(aead_nonce, 12);
    return ret;
}

int proto_frame_encode(const proto_frame_t *frame, uint8_t *out, size_t *out_len) {
    if (!frame || !out || !out_len) return PROTO_ERR;
    if (frame->payload_len > PROTO_MAX_PAYLOAD) return PROTO_ERR_FORMAT;

    size_t total = PROTO_HEADER_LEN + frame->payload_len;
    if (*out_len < total) return PROTO_ERR_NOMEM;
    *out_len = total;

    size_t pos = 0;
    out[pos++] = (PROTO_MAGIC >> 8) & 0xFF;
    out[pos++] = PROTO_MAGIC & 0xFF;
    out[pos++] = PROTO_VERSION;
    out[pos++] = frame->msg_type;
    memcpy(out + pos, frame->session_id, 6); pos += 6;
    out[pos++] = frame->flags;
    out[pos++] = (frame->nonce_counter >> 24) & 0xFF;
    out[pos++] = (frame->nonce_counter >> 16) & 0xFF;
    out[pos++] = (frame->nonce_counter >> 8) & 0xFF;
    out[pos++] = frame->nonce_counter & 0xFF;
    out[pos++] = (frame->payload_len >> 24) & 0xFF;
    out[pos++] = (frame->payload_len >> 16) & 0xFF;
    out[pos++] = (frame->payload_len >> 8) & 0xFF;
    out[pos++] = frame->payload_len & 0xFF;
    memcpy(out + pos, frame->nonce, PROTO_NONCE_LEN); pos += PROTO_NONCE_LEN;
    if (frame->payload_len > 0 && frame->payload) {
        memcpy(out + pos, frame->payload, frame->payload_len);
    }
    return PROTO_OK;
}

int proto_frame_decode(const uint8_t *in, size_t in_len, proto_frame_t *frame) {
    if (!in || !frame) return PROTO_ERR;
    if (in_len < PROTO_HEADER_LEN) return PROTO_ERR_FORMAT;

    uint16_t magic = ((uint16_t)in[0] << 8) | in[1];
    if (magic != PROTO_MAGIC) return PROTO_ERR_FORMAT;

    frame->payload = NULL;
    size_t pos = 2;
    uint8_t version = in[pos++];
    if (version != PROTO_VERSION) return PROTO_ERR_FORMAT;

    frame->msg_type = in[pos++];
    memcpy(frame->session_id, in + pos, 6); pos += 6;
    frame->flags = in[pos++];
    frame->nonce_counter = ((uint32_t)in[pos] << 24) | ((uint32_t)in[pos+1] << 16)
                        | ((uint32_t)in[pos+2] << 8) | in[pos+3];
    pos += 4;
    frame->payload_len = ((uint32_t)in[pos] << 24) | ((uint32_t)in[pos+1] << 16)
                       | ((uint32_t)in[pos+2] << 8) | in[pos+3];
    pos += 4;

    if (frame->payload_len > PROTO_MAX_PAYLOAD) return PROTO_ERR_FORMAT;

    memcpy(frame->nonce, in + pos, PROTO_NONCE_LEN);
    pos += PROTO_NONCE_LEN;

    if (frame->payload_len > 0) {
        if (in_len < PROTO_HEADER_LEN + frame->payload_len) return PROTO_ERR_FORMAT;
        frame->payload = (uint8_t*)malloc(frame->payload_len);
        if (!frame->payload) return PROTO_ERR_NOMEM;
        memcpy(frame->payload, in + pos, frame->payload_len);
    }
    return PROTO_OK;
}

int proto_replay_check(uint32_t *window, uint32_t window_size, uint32_t counter) {
    if (!window || window_size == 0) return PROTO_ERR;
    if (counter < window[0]) return PROTO_ERR_REPLAY;
    if (counter > window[1]) {
        window[0] = counter > window_size - 1 ? counter - window_size + 1 : 0;
        window[1] = counter;
        return PROTO_OK;
    }
    /* within window - check if already seen (simplified: reject all within window) */
    return PROTO_ERR_REPLAY;
}
