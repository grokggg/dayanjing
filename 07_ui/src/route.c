#define _GNU_SOURCE
#include "ui_internal.h"
#include "ui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================
 * base64url 编码 / 解码
 * ============================================================ */

size_t b64url_encoded_len(size_t in_len) {
    size_t n = (in_len + 2) / 3 * 4;
    return n;
}

int b64url_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t need = b64url_encoded_len(in_len);
    if (out_cap <= need) return -1;
    size_t oi = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < in_len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < in_len) v |= (uint32_t)in[i + 2];
        out[oi++] = tbl[(v >> 18) & 0x3F];
        out[oi++] = tbl[(v >> 12) & 0x3F];
        out[oi++] = (i + 1 < in_len) ? tbl[(v >> 6) & 0x3F] : '\0';
        out[oi++] = (i + 2 < in_len) ? tbl[v & 0x3F] : '\0';
    }
    out[oi] = '\0';
    return 0;
}

int b64url_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap) {
    if (out_cap < in_len * 3 / 4 + 4) return -1;
    static int8_t itbl[256];
    static int itbl_ready = 0;
    if (!itbl_ready) {
        for (int i = 0; i < 256; i++) itbl[i] = -1;
        for (int i = 0; i < 26; i++) { itbl['A' + i] = (int8_t)i; itbl['a' + i] = (int8_t)(i + 26); }
        for (int i = 0; i < 10; i++) itbl['0' + i] = (int8_t)(i + 52);
        itbl[(int)'-'] = 62;
        itbl[(int)'_'] = 63;
        itbl_ready = 1;
    }
    size_t oi = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < in_len; i++) {
        int v = itbl[(unsigned char)in[i]];
        if (v == 0 && in[i] != 'A' && in[i] != '0') {
            if (in[i] == '\0' || in[i] == '=') break;
            return -1;
        }
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[oi++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    return (int)oi;
}

/* ============================================================
 * Token 认证 (HMAC + 常量时间比对)
 * ============================================================ */

int64_t ui_now_sec(void) {
    return (int64_t)time(NULL);
}

void token_signer_init(token_signer_t *ts,
                       const uint8_t *secret, size_t secret_len,
                       const uint8_t *issuer, size_t issuer_len,
                       int64_t ttl_sec) {
    memset(ts, 0, sizeof(*ts));
    if (secret && secret_len > 0) {
        size_t c = secret_len > TOKEN_SECRET_LEN ? TOKEN_SECRET_LEN : secret_len;
        memcpy(ts->secret, secret, c);
    }
    if (issuer && issuer_len > 0) {
        size_t c = issuer_len > TOKEN_ISSUER_LEN ? TOKEN_ISSUER_LEN : issuer_len;
        memcpy(ts->issuer, issuer, c);
    }
    ts->ttl_sec = ttl_sec > 0 ? ttl_sec : 3600;
}

/* HMAC 签名：key=secret, msg = issuer || subject || exp */
int ui_hmac_sign(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t *out, size_t out_cap) {
    (void)out_cap;
    /* 调用 00_crypto 的 crypto_hmac(key, key_len, msg, msg_len, out) */
    extern int crypto_hmac(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t *out);
    return crypto_hmac(key, key_len, msg, msg_len, out);
}

int ui_hmac_verify_ct(const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *expect, size_t expect_len) {
    (void)key_len; (void)msg_len; (void)expect_len;
    /* 调用 00_crypto 的 crypto_hmac_verify(a, b, len) — 常量时间比对 */
    extern int crypto_hmac_verify(const uint8_t *a, const uint8_t *b, size_t len);
    return crypto_hmac_verify(key, expect, msg_len);
}

int token_issue(const token_signer_t *ts, const char *subject,
                char *out_b64, size_t out_cap) {
    if (!ts || !subject || !out_b64) return -1;
    int64_t exp = ui_now_sec() + ts->ttl_sec;

    /* 构造 payload: subject(以\0结尾) || issuer(\0) || exp(8字节小端) */
    size_t slen = strlen(subject);
    size_t ilen = strlen((const char *)ts->issuer);
    size_t msg_len = slen + 1 + ilen + 1 + 8;
    uint8_t *msg = (uint8_t *)malloc(msg_len);
    if (!msg) return -1;
    uint8_t *mp = msg;
    memcpy(mp, subject, slen + 1); mp += slen + 1;
    memcpy(mp, ts->issuer, ilen + 1); mp += ilen + 1;
    uint64_t exp_be = (uint64_t)exp;
    for (int i = 0; i < 8; i++) *mp++ = (uint8_t)(exp_be >> (i * 8));

    uint8_t sig[32];
    int hrc = ui_hmac_sign(ts->secret, TOKEN_SECRET_LEN, msg, msg_len, sig, sizeof(sig));
    fprintf(stderr, "[TOKEN] hmac rc=%d msg_len=%zu\n", hrc, msg_len);
    if (hrc != 0) {
        free(msg); return -1;
    }
    free(msg);

    /* 组装 token = base64url( subject\0issuer\0exp(8) || sig ) */
    size_t payload_len = msg_len;   /* 重新算一次 */
    payload_len = slen + 1 + ilen + 1 + 8 + sizeof(sig);
    uint8_t *payload = (uint8_t *)malloc(payload_len);
    if (!payload) return -1;
    memcpy(payload, subject, slen + 1);
    memcpy(payload + slen + 1, ts->issuer, ilen + 1);
    mp = payload + slen + 1 + ilen + 1;
    for (int i = 0; i < 8; i++) *mp++ = (uint8_t)(exp_be >> (i * 8));
    memcpy(mp, sig, sizeof(sig));

    int rc = b64url_encode(payload, payload_len, out_b64, out_cap);
    free(payload);
    return rc;
}

int token_verify(const token_signer_t *ts, const char *b64,
                 size_t b64_len, char *out_subject, size_t subject_cap) {
    if (!ts || !b64 || !out_subject) return 0;
    if (b64_len == 0) b64_len = strlen(b64);
    size_t max_payload = b64_len * 3 / 4 + 4 + 32;
    uint8_t *payload = (uint8_t *)malloc(max_payload);
    if (!payload) return 0;
    int plen = b64url_decode(b64, b64_len, payload, max_payload);
    if (plen < (int)(1 + 1 + 8 + 32)) { free(payload); return 0; }

    uint8_t *sig = payload + plen - 32;
    size_t msg_len = (size_t)(plen - 32);

    uint8_t expect[32];
    if (ui_hmac_sign(ts->secret, TOKEN_SECRET_LEN, payload, msg_len, expect, 32) != 0) {
        free(payload); return 0;
    }
    /* 常量时间比对 */
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= (uint8_t)(sig[i] ^ expect[i]);
    if (diff != 0) { free(payload); return 0; }

    /* 解析 exp */
    int64_t exp = 0;
    uint8_t *exp_p = NULL;
    /* 找 issuer\0 之后的 8 字节 */
    /* payload = subject\0issuer\0exp(8)sig(32) */
    size_t slen = strlen((const char *)payload) + 1;
    size_t ilen = strlen((const char *)payload + slen) + 1;
    exp_p = payload + slen + ilen;
    for (int i = 0; i < 8; i++) exp |= ((int64_t)exp_p[i]) << (i * 8);

    if (exp < ui_now_sec()) { free(payload); return 0; }

    if (subject_cap > 0) {
        size_t c = slen - 1;
        if (c > subject_cap - 1) c = subject_cap - 1;
        memcpy(out_subject, (const char *)payload, c);
        out_subject[c] = '\0';
    }
    free(payload);
    return 1;
}

int token_authenticate(const token_signer_t *ts, const http_req_t *req,
                       char *out_subject, size_t subject_cap) {
    const char *auth = http_get_header(req, "authorization");
    if (!auth) return 0;
    const char *prefix = "Bearer ";
    size_t plen = strlen(prefix);
    if (strncasecmp(auth, prefix, plen) != 0) return 0;
    const char *tok = auth + plen;
    return token_verify(ts, tok, strlen(tok), out_subject, subject_cap);
}

/* ============================================================
 * 路由匹配
 * ============================================================ */

int route_match(const char *tmpl, const char *uri,
                const char **params, int params_cap) {
    int n = 0;
    const char *tp = tmpl;
    const char *up = uri;
    while (n < params_cap) {
        if (*tp == '\0' && *up == '\0') return n;
        if (*tp == '\0' || *up == '\0') break;
        if (*tp == ':') {
            /* 参数段：消费模板中 ':' 之后的参数名（直到 / 或 \0） */
            while (*tp && *tp != '/') tp++;
            const char *start = up;
            while (*up && *up != '/') up++;
            size_t len = (size_t)(up - start);
            if (len == 0) return -1;
            char *seg = (char *)malloc(len + 1);
            if (!seg) return -1;
            memcpy(seg, start, len);
            seg[len] = '\0';
            params[n++] = seg;
        } else if (*tp == *up) {
            tp++; up++;
        } else {
            return -1;
        }
    }
    /* 收尾：一方到结尾，跳过尾部斜杠 */
    while (*tp == '/') tp++;
    while (*up == '/') up++;
    if (*tp == '\0' && *up == '\0') return n;
    return -1;
}

/* ============================================================
 * UI 上下文与请求分发
 * ============================================================ */

void ui_ctx_init(ui_ctx_t *ctx, const uint8_t *secret, size_t secret_len,
                 const uint8_t *issuer, size_t issuer_len, int64_t ttl_sec) {
    memset(ctx, 0, sizeof(*ctx));
    token_signer_init(&ctx->token, secret, secret_len, issuer, issuer_len, ttl_sec);
}

handle_result_t ui_handle(ui_ctx_t *ctx, http_req_t *req,
                          char *out, size_t out_cap,
                          int *out_http_status) {
    ctx->req_total++;
    if (!ctx->routes || ctx->route_count == 0) {
        ui_write_error(HANDLE_INTERNAL_ERROR, out, out_cap, out_http_status);
        ctx->req_5xx++;
        return HANDLE_INTERNAL_ERROR;
    }
    for (int ri = 0; ri < ctx->route_count; ri++) {
        const route_t *rt = &ctx->routes[ri];
        if (rt->method != req->method) continue;
        const char *params[8];
        for (int i = 0; i < 8; i++) params[i] = NULL;
        int nparam = route_match(rt->path, req->uri, params, 8);
        if (nparam < 0) {
            for (int i = 0; i < 8; i++) free((void *)params[i]);
            continue;
        }
        handle_result_t r = rt->handler(ctx, req, params, nparam, out, out_cap);
        for (int i = 0; i < 8; i++) free((void *)params[i]);
        if (out_http_status) {
            switch (r) {
            case HANDLE_OK:               *out_http_status = 200; ctx->req_2xx++; break;
            case HANDLE_NOT_FOUND:        *out_http_status = 404; ctx->req_4xx++; break;
            case HANDLE_METHOD_NOT_ALLOWED:*out_http_status = 405; ctx->req_4xx++; break;
            case HANDLE_UNAUTHORIZED:     *out_http_status = 401; ctx->req_4xx++; break;
            case HANDLE_BAD_REQUEST:      *out_http_status = 400; ctx->req_4xx++; break;
            default:                      *out_http_status = 500; ctx->req_5xx++; break;
            }
        }
        return r;
    }
    ui_write_error(HANDLE_NOT_FOUND, out, out_cap, out_http_status);
    ctx->req_4xx++;
    return HANDLE_NOT_FOUND;
}

void ui_write_error(handle_result_t r, char *out, size_t out_cap,
                    int *out_http_status) {
    const char *msg = "internal error";
    int code = 500;
    switch (r) {
    case HANDLE_NOT_FOUND:         msg = "not found"; code = 404; break;
    case HANDLE_METHOD_NOT_ALLOWED:msg = "method not allowed"; code = 405; break;
    case HANDLE_UNAUTHORIZED:      msg = "unauthorized"; code = 401; break;
    case HANDLE_BAD_REQUEST:       msg = "bad request"; code = 400; break;
    default:                       msg = "internal error"; code = 500; break;
    }
    if (out_http_status) *out_http_status = code;
    json_value_t *j = json_obj();
    json_obj_set(j, "error", json_str(msg));
    json_obj_set(j, "code", json_num((double)code));
    json_serialize(j, out, out_cap);
    json_free(j);
}
