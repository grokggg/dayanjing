/* rsa.h — RSA PKCS#1 v1.5 验签（仅验签，不签名、不加密） */
#ifndef RSA_H
#define RSA_H

#include <stdint.h>
#include <stddef.h>
#include "bn.h"

typedef enum {
    RSA_OK = 0,
    RSA_ERR_ARG,
    RSA_ERR_KEY,     /* 公钥不合法（模数为 0 / 指数过小） */
    RSA_ERR_RANGE,   /* 签名长度与模数不符或超过实现上限 */
    RSA_ERR_PAD,     /* PKCS#1 v1.5 填充结构不合法 */
    RSA_ERR_SIG      /* 摘要不匹配 */
} rsa_err;

const char *rsa_errstr(rsa_err e);

/* 用 RSA 公钥 (n, e) 验证 tbs 数据的 SHA-256 签名。
   sig 为 signatureValue 的原始字节，长度应等于模数字节数。 */
rsa_err rsa_verify_sha256(const bn_t *n, uint32_t e,
                          const uint8_t *tbs, size_t tbs_len,
                          const uint8_t *sig, size_t sig_len);

#endif /* RSA_H */
