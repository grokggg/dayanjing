#ifndef UI_INTERNAL_H
#define UI_INTERNAL_H

#include "ui.h"

/* 内部共享辅助：base64url 编码/解码（无第三方依赖） */
int  b64url_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);
size_t b64url_encoded_len(size_t in_len);
int  b64url_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap);

/* 时间来源（可注入，便于测试固定时间） */
int64_t ui_now_sec(void);

/* HMAC 签名：调用 00_crypto */
int ui_hmac_sign(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t *out, size_t out_cap);
int ui_hmac_verify_ct(const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *expect, size_t expect_len);

#endif /* UI_INTERNAL_H */
