/*
 * proto.c — DAYANJING v3 C2 协议帧层（C 端口，复刻 13_c2_server/frame.py）
 *
 * 帧格式：
 *   u32(total_len) || u32(msg_type 明文) || nonce(12) || ct || tag(16)
 *
 * Envelope（AEAD 明文，确定性编码）：
 *   u64(seq) || u32(version) || u32(type) || u32(payload_len) || payload
 *
 * AAD = "c2:v1" || u32(version) || u8(role) || u32(msg_type)  定长 14 字节
 *
 * 关键不变量：
 *  - 先验签后 accept：proto_open 先 AEAD 验签，失败立即返回，不污染重放窗口
 *  - msg_type 双重校验：帧头明文与密文内 type 必须一致
 *  - 调用方负责维护 nonce counter，溢出即报错（禁止回绕）
 */
#include "proto.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

const char *proto_strerror(proto_err_t e) {
    switch (e) {
        case PROTO_OK:            return "ok";
        case PROTO_INVALID_ROLE:  return "invalid role";
        case PROTO_KEYLEN:        return "key must be 32 bytes";
        case PROTO_KEYS_EQUAL:    return "k_send must differ from k_recv";
        case PROTO_COUNTER_FULL:  return "nonce counter exhausted";
        case PROTO_TOO_SHORT:     return "frame too short";
        case PROTO_TOO_LONG:      return "frame exceeds max length";
        case PROTO_LEN_MISMATCH:  return "frame length mismatch";
        case PROTO_VER_MISMATCH:  return "protocol version mismatch";
        case PROTO_TYPE_MISMATCH: return "msg_type mismatch";
        case PROTO_TAG_FAIL:      return "aead verify failed";
        case PROTO_SEQ_REPLAY:    return "seq replay";
        case PROTO_SEQ_TOO_OLD:   return "seq too old";
        case PROTO_SEQ_GAP:       return "seq future gap";
        case PROTO_NOMEM:         return "no memory";
        case PROTO_RANGE:         return "out of range";
        case PROTO_NOT_FOUND:     return "not found";
        default:                  return "unknown";
    }
}

/* 小端读写 */
static void w32(uint8_t **p, uint32_t v) { *(*p)++ = v;       *(*p)++ = v>>8;
                                          *(*p)++ = v>>16;   *(*p)++ = v>>24; }
static void w64(uint8_t **p, uint64_t v) { for (int i=0;i<8;i++) { *(*p)++ = v; v>>=8; } }
static uint32_t r32(const uint8_t **p) { uint32_t v=(*p)[0]|((uint32_t)(*p)[1]<<8)
        |((uint32_t)(*p)[2]<<16)|((uint32_t)(*p)[3]<<24); *p+=4; return v; }
static uint64_t r64(const uint8_t **p) { uint64_t v=0; for(int i=0;i<8;i++){v|=((uint64_t)*(*p)++)<<(i*8);} return v; }

proto_err_t proto_build_aad(uint8_t role, uint32_t msg_type, uint8_t aad[PROTO_AAD_LEN]) {
    if (!aad) return PROTO_ERR;
    /* 定长域分离编码：prefix(6) || version(4) || role(1) || type(4) = 15 字节 */
    aad[0]=0; aad[1]='c'; aad[2]=':'; aad[3]='v'; aad[4]='1'; aad[5]=0;
    aad[6]  = (uint8_t)(PROTO_VERSION);
    aad[7]  = (uint8_t)(PROTO_VERSION >> 8);
    aad[8]  = (uint8_t)(PROTO_VERSION >> 16);
    aad[9]  = (uint8_t)(PROTO_VERSION >> 24);
    aad[10] = 0;   /* role 不公开（参考 python 版占位 0） */
    aad[11] = (uint8_t)(msg_type);
    aad[12] = (uint8_t)(msg_type >> 8);
    aad[13] = (uint8_t)(msg_type >> 16);
    aad[14] = (uint8_t)(msg_type >> 24);
    return PROTO_OK;
}

/*
 * 编码：构造 Envelope 明文，构 AAD，调 crypto_aead_seal。
 * 编码：构造 Envelope 明文 -> 构 AAD -> 调 crypto_aead_seal。
 * 帧头附明文 msg_type，供对端重建一致 AAD。
 */
proto_err_t proto_seal(const uint8_t k_send[PROTO_KEY_LEN],
                       uint8_t nonce_prefix[8], uint32_t *counter,
                       uint8_t *nonce_buf,
                       uint64_t seq, uint32_t msg_type,
                       const uint8_t *payload, uint32_t payload_len,
                       uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!k_send || !counter || !nonce_buf || !out || !out_len)
        return PROTO_ERR;
    if (payload_len > 0 && !payload) return PROTO_ERR;

    /* 计算各段长度 */
    size_t env_len = PROTO_ENVELOPE_MIN + payload_len;
    size_t body_len = 4 /*type*/ + 12 /*nonce*/ + env_len + CRYPTO_TAG_LEN;
    size_t wire_len = 4 /*total_len*/ + body_len;

    if (wire_len > PROTO_MAX_FRAME) return PROTO_TOO_LONG;
    if (wire_len > out_cap) return PROTO_RANGE;

    if (*counter == UINT32_MAX) return PROTO_COUNTER_FULL;

    /* 构造 12B nonce = 8B 随机前缀 || 4B 计数器（大端，与 python 版一致） */
    uint8_t nonce[CRYPTO_NONCE_LEN];
    memcpy(nonce, nonce_prefix, 8);
    nonce[8]  = (uint8_t)((*counter >> 24) & 0xff);
    nonce[9]  = (uint8_t)((*counter >> 16) & 0xff);
    nonce[10] = (uint8_t)((*counter >> 8)  & 0xff);
    nonce[11] = (uint8_t)(*counter & 0xff);

    /* Envelope 明文 */
    uint8_t *env = malloc(env_len);
    if (!env) return PROTO_NOMEM;
    uint8_t *p = env;
    w64(&p, seq);
    w32(&p, PROTO_VERSION);
    w32(&p, msg_type);
    w32(&p, payload_len);
    if (payload_len) memcpy(p, payload, payload_len);

    /* AAD（定长域分离） */
    uint8_t aad[PROTO_AAD_LEN];
    proto_err_t rc = proto_build_aad(0, msg_type, aad);
    if (rc != PROTO_OK) { free(env); return rc; }

    /* AEAD seal：ciphertext 缓冲 = ct(env_len) + tag(16) */
    uint8_t *ct_tag = malloc(env_len + CRYPTO_TAG_LEN);
    if (!ct_tag) { free(env); return PROTO_NOMEM; }
    size_t sealed = 0;
    rc = (proto_err_t)crypto_aead_seal(ct_tag, &sealed, env, env_len,
                                       aad, sizeof(aad), k_send, nonce);
    free(env);
    if (rc != PROTO_OK) { free(ct_tag); return rc; }
    if (sealed != env_len + CRYPTO_TAG_LEN) { free(ct_tag); return PROTO_ERR; }

    /* 组装 wire */
    uint8_t *q = out;
    w32(&q, (uint32_t)body_len);     /* total_len（body 部分长度）*/
    w32(&q, msg_type);               /* 明文 msg_type */
    memcpy(q, nonce, 12); q += 12;   /* nonce */
    memcpy(q, ct_tag, sealed); q += sealed;  /* ct || tag */

    memcpy(nonce_buf, nonce, CRYPTO_NONCE_LEN);
    (*counter)++;
    *out_len = wire_len;
    free(ct_tag);
    return PROTO_OK;
}

/*
 * 解码：先读帧头与 nonce，重建 AAD，调 crypto_aead_open 验签；
 * 验签通过后解析 Envelope 并双重校验 msg_type。
 * 任何失败返回 PROTO_TAG_FAIL —— 调用方应静默关连接，不回显细节。
 */
proto_err_t proto_open(const uint8_t k_recv[PROTO_KEY_LEN], uint8_t role,
                       const uint8_t *wire, size_t wire_len,
                       uint64_t *seq, uint32_t *msg_type,
                       uint8_t *payload_out, size_t payload_cap,
                       size_t *payload_len) {
    if (!k_recv || !wire || !seq || !msg_type || !payload_out || !payload_len)
        return PROTO_ERR;

    if (wire_len < 4 + 4 + 12 + CRYPTO_TAG_LEN + PROTO_ENVELOPE_MIN)
        return PROTO_TOO_SHORT;
    if (wire_len > PROTO_MAX_FRAME) return PROTO_TOO_LONG;

    const uint8_t *p = wire;
    uint32_t total_len = r32(&p);
    if (total_len > PROTO_MAX_FRAME) return PROTO_TOO_LONG;
    if (total_len + 4 != wire_len) return PROTO_LEN_MISMATCH;

    uint32_t hdr_type = r32(&p);            /* 帧头明文 msg_type */
    uint8_t nonce[CRYPTO_NONCE_LEN];
    memcpy(nonce, p, 12); p += 12;

    size_t ct_tag_len = total_len - 4 - 12;  /* 去掉 type 和 nonce */
    if (ct_tag_len < CRYPTO_TAG_LEN + PROTO_ENVELOPE_MIN) return PROTO_TOO_SHORT;

    /* 重建 AAD（与加密端一致） */
    uint8_t aad[PROTO_AAD_LEN];
    proto_err_t rc = proto_build_aad(0, hdr_type, aad);
    if (rc != PROTO_OK) return rc;

    /* 先验签 */
    size_t pt_len = 0;
    uint8_t *pt = malloc(ct_tag_len - CRYPTO_TAG_LEN);
    if (!pt) return PROTO_NOMEM;
    rc = (proto_err_t)crypto_aead_open(pt, &pt_len, p, ct_tag_len,
                                       aad, sizeof(aad), k_recv, nonce);
    if (rc != PROTO_OK) { free(pt); return PROTO_TAG_FAIL; }
    if (pt_len != ct_tag_len - CRYPTO_TAG_LEN) { free(pt); return PROTO_TAG_FAIL; }

    /* 解析 Envelope */
    const uint8_t *q = pt;
    uint64_t e_seq = r64(&q);
    uint32_t e_ver = r32(&q);
    uint32_t e_type = r32(&q);
    uint32_t e_plen = r32(&q);
    if (e_ver != PROTO_VERSION) { free(pt); return PROTO_VER_MISMATCH; }
    if (e_type != hdr_type)      { free(pt); return PROTO_TYPE_MISMATCH; }
    if (pt_len != PROTO_ENVELOPE_MIN + e_plen) { free(pt); return PROTO_LEN_MISMATCH; }
    if (e_plen > pt_len - PROTO_ENVELOPE_MIN)  { free(pt); return PROTO_LEN_MISMATCH; }
    if (e_plen > payload_cap)    { free(pt); return PROTO_RANGE; }

    memcpy(payload_out, q, e_plen);
    *seq = e_seq;
    *msg_type = e_type;
    *payload_len = e_plen;
    free(pt);
    return PROTO_OK;
}
