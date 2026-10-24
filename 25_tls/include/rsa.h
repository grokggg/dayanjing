/* rsa.h — RSA PKCS#1 v1.5 验签 + 签名
 *
 * 验签：客户端校验证书链与 ServerKeyExchange，只需要公钥 (n, e)。
 * 签名：服务端签发 ServerKeyExchange 必须有私钥。少了它，服务端就无法向
 *       客户端证明自己持有证书对应的私钥 —— 握手退化成"谁都能顶替"，
 *       且客户端若不检查就会全盘接受。故服务端是本模块的必需能力，不是可选。
 */
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

/* ---- 私钥：签名用 ---- */
typedef struct {
    bn_t    n;      /* 模数（签名长度由它决定） */
    uint32_t e;     /* 公钥指数（仅自检用） */
    bn_t    d;      /* 私钥指数 */

    /* ---- CRT 分量（PKCS#1 的 p/q/dP/dQ/qInv）----
     * 为什么必须有：2048 位模数的裸模幂实测 1.71 秒/次。握手时每一次
     * ServerKeyExchange 都要签一次，等于每次握手卡住近两秒 —— 这既是
     * 可用性问题，也是指纹（真实 TLS 服务端不会在这个位置停两秒）。
     * CRT 把它拆成两个 1024 位模幂，理论上约 1/4。
     *
     * has_crt == 0 时走原来的裸模幂路径。两条路径必须产出逐字节相同的
     * 签名（由测试钉死），否则就是"加速加错了"。 */
    bn_t    p, q, dp, dq, qinv;
    int     has_crt;   /* 1 = 上述五个分量齐全且 p*q == n */
} rsa_privkey;

/* 从 PEM 加载私钥。同时支持
 *   "-----BEGIN PRIVATE KEY-----"      (PKCS#8, OpenSSL genrsa 默认输出)
 *   "-----BEGIN RSA PRIVATE KEY-----"  (PKCS#1)
 * 两者混用是现实中的常见坑：只认一种会在对方换工具时静默失败，
 * 而失败点会落在"签名长度不对"这种完全看不出是解析问题的地方。 */
rsa_err rsa_privkey_load_pem(const char *path, rsa_privkey *k);
rsa_err rsa_privkey_load_mem(const uint8_t *pem, size_t len, rsa_privkey *k);

/* 私钥用完即清：私钥留在不再使用的结构体里，等同于多留一份明文副本。 */
void    rsa_privkey_clear(rsa_privkey *k);

/* PKCS#1 v1.5 SHA-256 签名。sig 恰为 k 字节（k = 模数字节数）。 */
rsa_err rsa_sign_sha256(const rsa_privkey *k,
                        const uint8_t *tbs, size_t tbs_len,
                        uint8_t *sig, size_t cap, size_t *sig_len);

#endif /* RSA_H */
