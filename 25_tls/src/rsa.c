/* rsa.c — RSA PKCS#1 v1.5 验签实现
 *
 * 验证的是公开信息（证书签名），没有秘密输入，因此不做常数时间处理。
 * 常数时间只在 X25519 / GCM 层需要，那部分在 00_crypto。
 */
#include "rsa.h"
#include "crypto_hash.h"
#include <string.h>

/* DigestInfo ::= SEQUENCE { AlgorithmIdentifier(sha256), OCTET STRING }
   用于 RSASSA-PKCS1-v1_5 的 SHA-256 前缀（19 字节） */
static const uint8_t DI_SHA256[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};
#define DI_SHA256_LEN (sizeof(DI_SHA256))

const char *rsa_errstr(rsa_err e) {
    switch (e) {
    case RSA_OK:        return "ok";
    case RSA_ERR_ARG:   return "invalid argument";
    case RSA_ERR_KEY:   return "invalid public key";
    case RSA_ERR_RANGE: return "signature length mismatch";
    case RSA_ERR_PAD:   return "bad PKCS#1 v1.5 padding";
    case RSA_ERR_SIG:   return "digest mismatch";
    }
    return "unknown";
}

rsa_err rsa_verify_sha256(const bn_t *n, uint32_t e,
                          const uint8_t *tbs, size_t tbs_len,
                          const uint8_t *sig, size_t sig_len) {
    if (!n || !tbs || !sig) return RSA_ERR_ARG;
    if (bn_is_zero(n)) return RSA_ERR_KEY;
    if (e < 3 || (e % 2) == 0) return RSA_ERR_KEY;

    int nbits = bn_bitlen(n);
    size_t k = (size_t)((nbits + 7) / 8);
    if (k == 0 || k > BN_MAX_BYTES) return RSA_ERR_RANGE;
    if (sig_len != k) return RSA_ERR_RANGE;

    bn_t s, m, cmp;
    bn_from_be(&s, sig, sig_len);
    if (bn_cmp(&s, n) >= 0) return RSA_ERR_SIG;   /* s 必须小于 n */

    if (bn_modpow_u32(&m, &s, e, n) != BN_OK) return RSA_ERR_RANGE;

    /* EM = 0x00 || 0x01 || PS(0xFF...) || 0x00 || T，左填充到 k 字节 */
    uint8_t em[BN_MAX_BYTES];
    memset(em, 0, sizeof(em));
    int used = bn_to_be(&m, em + (sizeof(em) - k), k);
    if (used < 0) return RSA_ERR_RANGE;
    const uint8_t *p = em + (sizeof(em) - k);

    if (p[0] != 0x00 || p[1] != 0x01) return RSA_ERR_PAD;
    size_t i = 2;
    while (i < k && p[i] == 0xff) i++;
    /* PS 至少 8 字节，且必须以 0x00 结束 */
    if (i < 2 + 8) return RSA_ERR_PAD;
    if (i >= k || p[i] != 0x00) return RSA_ERR_PAD;
    i++;
    size_t tlen = k - i;
    if (tlen != DI_SHA256_LEN + SHA256_DIGEST_LEN) return RSA_ERR_PAD;
    /* SEC-CMP:PUBLIC: 双方均为公开数据（传输中可见或可自行计算），无秘密可泄露 */
    if (memcmp(p + i, DI_SHA256, DI_SHA256_LEN) != 0) return RSA_ERR_PAD;

    uint8_t h[SHA256_DIGEST_LEN];
    sha256(tbs, tbs_len, h);
    /* SEC-CMP:PUBLIC: h 为 SHA256(tbs)，tbs 在握手中公开传输，攻击者可自行算出，比较它无从泄露 */
    if (memcmp(p + i + DI_SHA256_LEN, h, SHA256_DIGEST_LEN) != 0) return RSA_ERR_SIG;

    /* cmp 未使用，消除告警 */
    (void)cmp;
    return RSA_OK;
}
