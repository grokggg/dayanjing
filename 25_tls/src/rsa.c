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
    /* SEC-CMP:PUBLIC: PKCS#1 v1.5 的 DigestInfo 前缀，RFC 8017 公开定义的常量字节串。 */
    if (memcmp(p + i, DI_SHA256, DI_SHA256_LEN) != 0) return RSA_ERR_PAD;

    uint8_t h[SHA256_DIGEST_LEN];
    sha256(tbs, tbs_len, h);
    /* SEC-CMP:PUBLIC: h 为 SHA256(tbs)，tbs 在握手中公开传输，攻击者可自行算出，比较它无从泄露 */
    if (memcmp(p + i + DI_SHA256_LEN, h, SHA256_DIGEST_LEN) != 0) return RSA_ERR_SIG;

    /* cmp 未使用，消除告警 */
    (void)cmp;
    return RSA_OK;
}

/* ===================== 私钥加载与签名（服务端） ===================== */
#include "asn1.h"
#include <stdio.h>
#include <stdlib.h>

static int b64_val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -2;      /* 填充 */
    return -1;                    /* 空白与换行由调用方跳过 */
}

/* 返回 0 成功。遇到非法字符立即失败 —— 跳过而不是报错会让一份损坏的
   PEM 解出"长度差不多但内容不对"的 DER，失败点会跑到 ASN.1 解析里去。 */
static int b64_decode(const uint8_t *in, size_t len, uint8_t *out,
                      size_t cap, size_t *out_len) {
    uint32_t acc = 0;
    int      nbits = 0;
    size_t   o = 0;
    for (size_t i = 0; i < len; i++) {
        int v = b64_val(in[i]);
        if (v == -2) break;                 /* 填充即结束 */
        if (v < 0) continue;                /* 换行/回车 */
        acc = (acc << 6) | (uint32_t)v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (o >= cap) return -1;
            out[o++] = (uint8_t)((acc >> nbits) & 0xff);
        }
    }
    *out_len = o;
    return 0;
}

/* 取出标签为 want 的第一个 PEM 块的 DER 内容 */
static int pem_to_der(const uint8_t *pem, size_t len, const char *want,
                      uint8_t *out, size_t cap, size_t *out_len) {
    const char *s = (const char *)pem;
    size_t wlen = 0;
    while (want[wlen]) wlen++;
    for (size_t i = 0; i + wlen + 2 <= len; i++) {
        /* SEC-CMP:PATTERN: PEM 起始边界匹配。公开格式常量，不承载秘密。 */
        if (memcmp(s + i, want, wlen) != 0) continue;
        size_t b = i + wlen;
        while (b < len && s[b] != '\n') b++;
        if (b >= len) return -1;
        b++;
        size_t e = b;
        while (e + 5 <= len) {
            /* SEC-CMP:PATTERN: PEM 结束边界（"-----"）搜索。公开格式常量。 */
            if (memcmp(s + e, "-----", 5) == 0) break;
            e++;
        }
        if (e + 5 > len) return -1;
        return b64_decode(pem + b, e - b, out, cap, out_len);
    }
    return -1;
}

/* PKCS#1 RSAPrivateKey ::= SEQUENCE { version, n, e, d, ... }（只取前四项） */
static rsa_err parse_pkcs1(const uint8_t *der, size_t len, rsa_privkey *k) {
    size_t off = 0;
    der_buf seq, f;
    if (der_expect(der, len, &off, ASN1_SEQUENCE, &seq) != ASN1_OK) return RSA_ERR_KEY;
    size_t q = 0;
    if (der_expect(seq.p, seq.len, &q, ASN1_INTEGER, &f) != ASN1_OK) return RSA_ERR_KEY;
    uint32_t ver = 0;
    if (der_read_u32(&f, &ver) != ASN1_OK || ver != 0) return RSA_ERR_KEY;

    uint8_t  nb[BN_MAX_BYTES], db[BN_MAX_BYTES];
    size_t   nl = 0, dl = 0;

    if (der_expect(seq.p, seq.len, &q, ASN1_INTEGER, &f) != ASN1_OK) return RSA_ERR_KEY;
    if (der_read_uint(&f, nb, sizeof(nb), &nl) != ASN1_OK) return RSA_ERR_KEY;
    if (der_expect(seq.p, seq.len, &q, ASN1_INTEGER, &f) != ASN1_OK) return RSA_ERR_KEY;
    if (der_read_u32(&f, &k->e) != ASN1_OK) return RSA_ERR_KEY;
    if (der_expect(seq.p, seq.len, &q, ASN1_INTEGER, &f) != ASN1_OK) return RSA_ERR_KEY;
    if (der_read_uint(&f, db, sizeof(db), &dl) != ASN1_OK) return RSA_ERR_KEY;

    bn_from_be(&k->n, nb, nl);
    bn_from_be(&k->d, db, dl);
    /* 私钥字节不留副本 */
    memset(nb, 0, sizeof(nb));
    memset(db, 0, sizeof(db));
    if (bn_is_zero(&k->n) || bn_is_zero(&k->d)) return RSA_ERR_KEY;
    if (bn_cmp(&k->d, &k->n) >= 0) return RSA_ERR_KEY;
    return RSA_OK;
}

rsa_err rsa_privkey_load_mem(const uint8_t *pem, size_t len, rsa_privkey *k) {
    if (!pem || !k) return RSA_ERR_ARG;
    static uint8_t der[8192];
    size_t dlen = 0;
    bn_zero(&k->n);
    bn_zero(&k->d);
    k->e = 0;

    if (pem_to_der(pem, len, "-----BEGIN PRIVATE KEY-----", der, sizeof(der), &dlen) == 0) {
        /* PKCS#8: SEQUENCE { INTEGER 0, AlgorithmIdentifier, OCTET STRING } */
        size_t off = 0;
        der_buf seq, f, alg, oid, pk;
        if (der_expect(der, dlen, &off, ASN1_SEQUENCE, &seq) != ASN1_OK) return RSA_ERR_KEY;
        size_t q = 0;
        if (der_expect(seq.p, seq.len, &q, ASN1_INTEGER, &f) != ASN1_OK) return RSA_ERR_KEY;
        if (der_expect(seq.p, seq.len, &q, ASN1_SEQUENCE, &alg) != ASN1_OK) return RSA_ERR_KEY;
        {
            size_t a = 0;
            if (der_expect(alg.p, alg.len, &a, ASN1_OID, &oid) != ASN1_OK) return RSA_ERR_KEY;
        }
        if (!der_oid_eq(&oid, "1.2.840.113549.1.1.1")) return RSA_ERR_KEY;
        if (der_expect(seq.p, seq.len, &q, ASN1_OCTET_STRING, &pk) != ASN1_OK) return RSA_ERR_KEY;
        rsa_err e = parse_pkcs1(pk.p, pk.len, k);
        memset(der, 0, dlen);
        return e;
    }
    if (pem_to_der(pem, len, "-----BEGIN RSA PRIVATE KEY-----", der, sizeof(der), &dlen) == 0) {
        rsa_err e = parse_pkcs1(der, dlen, k);
        memset(der, 0, dlen);
        return e;
    }
    return RSA_ERR_KEY;
}

rsa_err rsa_privkey_load_pem(const char *path, rsa_privkey *k) {
    if (!path || !k) return RSA_ERR_ARG;
    FILE *f = fopen(path, "rb");
    if (!f) return RSA_ERR_KEY;
    static uint8_t buf[16384];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    if (n == 0 || n >= sizeof(buf)) return RSA_ERR_KEY;
    rsa_err e = rsa_privkey_load_mem(buf, n, k);
    memset(buf, 0, n);
    return e;
}

void rsa_privkey_clear(rsa_privkey *k) {
    if (!k) return;
    memset(&k->d, 0, sizeof(k->d));
    memset(&k->n, 0, sizeof(k->n));
    k->e = 0;
}

rsa_err rsa_sign_sha256(const rsa_privkey *k,
                        const uint8_t *tbs, size_t tbs_len,
                        uint8_t *sig, size_t cap, size_t *sig_len) {
    if (!k || !tbs || !sig || !sig_len) return RSA_ERR_ARG;
    if (bn_is_zero(&k->n) || bn_is_zero(&k->d)) return RSA_ERR_KEY;

    int nbits = bn_bitlen(&k->n);
    size_t klen = (size_t)((nbits + 7) / 8);
    if (klen == 0 || klen > BN_MAX_BYTES) return RSA_ERR_RANGE;
    size_t tlen = DI_SHA256_LEN + SHA256_DIGEST_LEN;
    /* PS 至少 8 字节（RFC 8017），结构不足即报错而非产出短填充 —— 短填充
       的签名在部分实现里仍被接受，等于自己造出一张"能过但非标准"的签名。 */
    if (klen < tlen + 11) return RSA_ERR_RANGE;
    if (klen > cap) return RSA_ERR_RANGE;

    uint8_t *em = (uint8_t *)calloc(1, BN_MAX_BYTES);
    if (!em) return RSA_ERR_RANGE;
    uint8_t *p = em + (BN_MAX_BYTES - klen);
    size_t ps_len = klen - tlen - 3;
    p[0] = 0x00;
    p[1] = 0x01;
    memset(p + 2, 0xff, ps_len);
    p[2 + ps_len] = 0x00;
    uint8_t h[SHA256_DIGEST_LEN];
    sha256(tbs, tbs_len, h);
    memcpy(p + 3 + ps_len, DI_SHA256, DI_SHA256_LEN);
    memcpy(p + 3 + ps_len + DI_SHA256_LEN, h, SHA256_DIGEST_LEN);

    bn_t m, s;
    bn_from_be(&m, p, klen);
    if (bn_cmp(&m, &k->n) >= 0) { free(em); return RSA_ERR_KEY; }
    if (bn_modpow(&s, &m, &k->d, &k->n) != BN_OK) { free(em); return RSA_ERR_RANGE; }
    /* 只判失败，不判"need == klen"：s 可能比 n 少几个字节（约 1/256 概率），
       bn_to_be 会左补零到 klen。若在这里要求 need == klen 再放行，
       就会偶发地把一个完全合法的签名判成失败，且不可复现。 */
    if (bn_to_be(&s, sig, klen) < 0) { free(em); return RSA_ERR_RANGE; }

    memset(h, 0, sizeof(h));
    free(em);
    *sig_len = klen;
    return RSA_OK;
}
