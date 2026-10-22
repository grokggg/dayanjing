/* x509.h — 证书解析、链校验、主机名匹配（自研，不依赖 OpenSSL）
 *
 * 只支持真实部署会遇到的子集：
 *   签名算法 : sha256WithRSAEncryption（1.2.840.113549.1.1.11）
 *   公钥算法 : rsaEncryption（1.2.840.113549.1.1.1）
 *   扩展     : subjectAltName 的 dNSName；无 SAN 时回落 CN
 *   时间     : UTCTime / GeneralizedTime，均要求 'Z' 结尾
 * 其余一律显式报错，不做静默降级 —— 静默降级会让"没验成"看起来像"验过了"。
 */
#ifndef X509_H
#define X509_H

#include <stdint.h>
#include <stddef.h>
#include "asn1.h"
#include "bn.h"

#define X509_SAN_MAX   8
#define X509_NAME_MAX  256
#define X509_STORE_MAX 160   /* 系统 bundle 约 122 张 */
#define X509_CHAIN_MAX 8
#define X509_DER_MAX   8192

typedef struct {
    const uint8_t *der;      /* 整张证书（调用方持有） */
    size_t         der_len;
    der_buf tbs;             /* tbsCertificate 完整 DER（含 tag+len），签名覆盖它 */
    der_buf sigval;          /* signatureValue 位串内容 */
    der_buf issuer;          /* issuer Name 的 DER（含头），用于链匹配 */
    der_buf subject;         /* subject Name 的 DER（含头） */
    int  sig_sha256_rsa;     /* 签名算法是 sha256WithRSAEncryption */
    int  has_rsa;            /* 公钥是 RSA */
    bn_t n;
    uint32_t e;
    int64_t not_before;
    int64_t not_after;
    char cn[X509_NAME_MAX];
    char san[X509_SAN_MAX][X509_NAME_MAX];
    int  san_n;
} x509_cert;

typedef struct {
    uint8_t   der[X509_DER_MAX];
    size_t    der_len;
    x509_cert c;
} x509_entry;

typedef struct {
    x509_entry e[X509_STORE_MAX];
    int        n;
} x509_store;

typedef enum {
    X509_OK = 0,
    X509_ERR_PARSE,      /* DER 解析失败 */
    X509_ERR_ALGO,       /* 算法不支持 */
    X509_ERR_SIG,        /* 签名验证失败 */
    X509_ERR_CHAIN,      /* 找不到签发者 */
    X509_ERR_EXPIRED,    /* 有效期外 */
    X509_ERR_HOST,       /* 主机名不匹配 */
    X509_ERR_RANGE,      /* 超出容量 */
    X509_ERR_IO          /* 读取信任库失败 */
} x509_err;

const char *x509_errstr(x509_err e);

x509_err x509_parse(const uint8_t *der, size_t len, x509_cert *c);
int  x509_name_eq(const der_buf *a, const der_buf *b);
int  x509_host_match(const x509_cert *c, const char *host);
x509_err x509_verify_signed_by(const x509_cert *c, const x509_cert *issuer);

/* 从 PEM 文件加载信任锚（可含多张证书） */
x509_err x509_store_load_pem(x509_store *st, const char *path);
x509_err x509_store_add_der(x509_store *st, const uint8_t *der, size_t len);

/* 完整链校验：叶子 -> ... -> 信任锚，并校验有效期与主机名 */
x509_err x509_verify_chain(const x509_cert *chain, int n,
                           const x509_store *anchors,
                           const char *host, int64_t now);

#endif /* X509_H */
