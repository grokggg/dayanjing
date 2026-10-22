/* x509.c — 证书解析 / 链校验 / 主机名匹配 */
#include "x509.h"
#include "rsa.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* 解析失败定位：编译时加 -DX509_PARSE_DEBUG 才生效，默认零开销。
   没有它，失败只能看到 "certificate parse error"，定位要靠猜。 */
#ifdef X509_PARSE_DEBUG
#include <stdio.h>
#define XF(e) do { fprintf(stderr, "[x509] fail: %s @ line %d\n", x509_errstr(e), __LINE__); return (e); } while (0)
#else
#define XF(e) return (e)
#endif

const char *x509_errstr(x509_err e) {
    switch (e) {
    case X509_OK:        return "ok";
    case X509_ERR_PARSE: return "certificate parse error";
    case X509_ERR_ALGO:  return "unsupported algorithm";
    case X509_ERR_SIG:   return "signature verification failed";
    case X509_ERR_CHAIN: return "issuer not found";
    case X509_ERR_EXPIRED: return "certificate expired or not yet valid";
    case X509_ERR_HOST:  return "hostname mismatch";
    case X509_ERR_RANGE: return "capacity exceeded";
    case X509_ERR_MEM:   return "out of memory";
    case X509_ERR_IO:    return "trust store unreadable";
    }
    return "unknown";
}

/* 名称规范化：把 Name 降为 (OID || 值内容) 的拼接字节串。
 *
 * 为什么不能直接比 DER：同一个名称在不同证书里可能用不同字符串类型编码
 * （PrintableString / UTF8String / BMPString），字节不同但语义相同。
 * 逐字节比会在真实环境里随机失败 —— 表现为"信任库明明有这个 CA，却报
 * issuer not found"，而且只在部分签发者身上出现，极难复现和定位。
 */
static int name_canon(const der_buf *name, uint8_t *out, size_t cap, size_t *out_len) {
    size_t used = 0, off = 0;
    while (off < name->len) {
        uint8_t tag = 0;
        der_buf rdn;
        if (der_read_tlv(name->p, name->len, &off, &tag, &rdn) != ASN1_OK) return -1;
        if (tag != ASN1_SET) continue;
        size_t o2 = 0;
        while (o2 < rdn.len) {
            uint8_t t2 = 0;
            der_buf atv;
            if (der_read_tlv(rdn.p, rdn.len, &o2, &t2, &atv) != ASN1_OK) break;
            if (t2 != ASN1_SEQUENCE) continue;
            size_t o3 = 0;
            der_buf oid, val;
            if (der_read_tlv(atv.p, atv.len, &o3, NULL, &oid) != ASN1_OK) continue;
            if (der_read_tlv(atv.p, atv.len, &o3, NULL, &val) != ASN1_OK) continue;
            if (used + oid.len + val.len > cap) return -1;
            memcpy(out + used, oid.p, oid.len); used += oid.len;
            memcpy(out + used, val.p, val.len); used += val.len;
        }
    }
    *out_len = used;
    return 0;
}

int x509_name_eq(const der_buf *a, const der_buf *b) {
    uint8_t ca[512], cb[512];
    size_t la = 0, lb = 0;
    if (name_canon(a, ca, sizeof(ca), &la) != 0) return 0;
    if (name_canon(b, cb, sizeof(cb), &lb) != 0) return 0;
    return la == lb && (la == 0 || memcmp(ca, cb, la) == 0);
}

/* --- 从 Name 中取 CN（2.5.4.3） --- */
static void parse_name_cn(const der_buf *name, char *cn, size_t cap) {
    cn[0] = '\0';
    size_t off = 0;
    while (off < name->len) {
        der_buf rdn;
        uint8_t tag = 0;
        if (der_read_tlv(name->p, name->len, &off, &tag, &rdn) != ASN1_OK) return;
        if (tag != ASN1_SET) continue;          /* 比 tag，不是内容首字节 */
        size_t o2 = 0;
        while (o2 < rdn.len) {
            der_buf atv;
            uint8_t t2 = 0;
            if (der_read_tlv(rdn.p, rdn.len, &o2, &t2, &atv) != ASN1_OK) break;
            if (t2 != ASN1_SEQUENCE) continue;
            size_t o3 = 0;
            der_buf oid, val;
            if (der_expect(atv.p, atv.len, &o3, ASN1_OID, &oid) != ASN1_OK) continue;
            (void)der_read_tlv(atv.p, atv.len, &o3, NULL, &val);
            if (der_oid_eq(&oid, "2.5.4.3") && val.len > 0 && val.len < cap) {
                memcpy(cn, val.p, val.len);
                cn[val.len] = '\0';
                return;
            }
        }
    }
}

/* --- SAN 扩展：取 dNSName ([2] primitive = 0x82) --- */
static void parse_san(const der_buf *extnval, x509_cert *c) {
    /* extnValue 是 OCTET STRING，其内容才是 DER 编码的 SubjectAltName，
       所以要先解开一层 SEQUENCE，再遍历 GeneralName。
       少了这一层就永远找不到 dNSName，表现为"主机名校验恒失败"，
       而且没有任何报错 —— 这是最难发现的一类静默失效。 */
    size_t off = 0;
    der_buf seq;
    uint8_t stag = 0;
    if (der_read_tlv(extnval->p, extnval->len, &off, &stag, &seq) != ASN1_OK) return;
    if (stag != ASN1_SEQUENCE) return;
    size_t o2 = 0;
    while (o2 < seq.len) {
        der_buf gn;
        uint8_t tag = 0;
        if (der_read_tlv(seq.p, seq.len, &o2, &tag, &gn) != ASN1_OK) return;
        if (tag != 0x82) continue;                     /* 只认 dNSName */
        if (c->san_n >= X509_SAN_MAX) return;
        size_t n = gn.len < X509_NAME_MAX - 1 ? gn.len : X509_NAME_MAX - 1;
        memcpy(c->san[c->san_n], gn.p, n);
        c->san[c->san_n][n] = '\0';
        c->san_n++;
    }
}

/* basicConstraints (2.5.29.19)：只取 cA 布尔。
 * 取不到就按 DEFAULT FALSE 记 0 —— 扩展存在却不带 cA，语义上就是非 CA。
 * 扩展整体缺失时保持 -1（由调用方决定，见 x509_cert.is_ca 的注释）。
 * 这里手工解 TLV 而不复用 der_read_tlv：extnValue 这一层的偏移语义在调用链
 * 上容易搞错，写错了不会报错，只会静默解析出错误的 cA 值。 */
static void parse_basic_constraints(const der_buf *v, x509_cert *c) {
    const uint8_t *p = v->p;
    size_t n = v->len;
    if (n < 2) return;
    /* 兼容两种传入形态：已剥壳的 DER，或还带着 OCTET STRING 头 */
    if (p[0] == ASN1_OCTET_STRING) {
        size_t i = 1, l = 0;
        if (p[i] < 0x80) { l = p[i]; i += 1; }
        else if (p[i] == 0x81) { l = p[i + 1]; i += 2; }
        else if (p[i] == 0x82) { l = ((size_t)p[i + 1] << 8) | p[i + 2]; i += 3; }
        else return;
        if (i + l > n) return;
        p += i; n = l;
    }
    if (n < 2 || p[0] != ASN1_SEQUENCE) return;
    size_t i = 1, l = 0;
    if (p[i] < 0x80) { l = p[i]; i += 1; }
    else if (p[i] == 0x81) { l = p[i + 1]; i += 2; }
    else if (p[i] == 0x82) { l = ((size_t)p[i + 1] << 8) | p[i + 2]; i += 3; }
    else return;
    if (i + l > n) l = n - i;
    /* SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER OPTIONAL } */
    if (l >= 3 && p[i] == 0x01 && p[i + 1] == 0x01) {
        c->is_ca = p[i + 2] ? 1 : 0;
        return;
    }
    c->is_ca = 0;
}

static x509_err parse_extensions(const der_buf *exts, x509_cert *c) {
    /* extensions 是 [3] EXPLICIT SEQUENCE OF Extension */
    if (exts->len < 2 || exts->p[0] != ASN1_SEQUENCE) return X509_ERR_PARSE;
    size_t off = 0;
    der_buf seq;
    if (der_read_tlv(exts->p, exts->len, &off, NULL, &seq) != ASN1_OK) return X509_ERR_PARSE;
    if (seq.p[0] != ASN1_SEQUENCE) return X509_ERR_PARSE;
    size_t o2 = 0;
    while (o2 < seq.len) {
        der_buf ext;
        uint8_t etag = 0;
        if (der_read_tlv(seq.p, seq.len, &o2, &etag, &ext) != ASN1_OK) break;
        if (etag != ASN1_SEQUENCE) continue;
        size_t o3 = 0;
        der_buf oid, val;
        if (der_expect(ext.p, ext.len, &o3, ASN1_OID, &oid) != ASN1_OK) continue;
        /* 可选 critical BOOLEAN */
        size_t save = o3;
        der_buf crit;
        if (der_expect(ext.p, ext.len, &o3, 0x01, &crit) != ASN1_OK) o3 = save;
        if (der_expect(ext.p, ext.len, &o3, ASN1_OCTET_STRING, &val) != ASN1_OK) continue;
        if (der_oid_eq(&oid, "2.5.29.17")) parse_san(&val, c);
        else if (der_oid_eq(&oid, "2.5.29.19")) parse_basic_constraints(&val, c);
    }
    return X509_OK;
}

x509_err x509_parse(const uint8_t *der, size_t len, x509_cert *c) {
    if (!der || !c || len < 32) XF(X509_ERR_PARSE);
    memset(c, 0, sizeof(*c));
    c->der = der;
    c->is_ca = -1;          /* 扩展缺失；明确写出来的才置 1/0 */
    c->der_len = len;
    c->san_n = 0;

    size_t off = 0;
    der_buf cert;
    if (der_expect(der, len, &off, ASN1_SEQUENCE, &cert) != ASN1_OK) XF(X509_ERR_PARSE);

    /* 后续解析一律以 cert 的内容为缓冲、以 co 为游标。
       踩过的坑：第一次写的版本继续用 (der, off)，而 der_read_tlv 读完后
       off 已经指向整个证书末尾（off = 4 + 802），下一层解析必然越界，
       表现为"第一层成功、第二层失败"，非常容易误判成数据问题。 */
    size_t co = 0;
    size_t tbs_start = co;
    der_buf tbs;
    if (der_expect(cert.p, cert.len, &co, ASN1_SEQUENCE, &tbs) != ASN1_OK) XF(X509_ERR_PARSE);
    c->tbs.p = cert.p + tbs_start;
    c->tbs.len = co - tbs_start;

    /* --- TBSCertificate 内部 --- */
    size_t to = 0;
    der_buf v;
    /* version [0] 可选 */
    size_t save = to;
    if (der_expect(tbs.p, tbs.len, &to, 0xa0, &v) != ASN1_OK) to = save;
    /* serialNumber */
    if (der_expect(tbs.p, tbs.len, &to, ASN1_INTEGER, &v) != ASN1_OK) XF(X509_ERR_PARSE);
    /* signature AlgorithmIdentifier */
    if (der_expect(tbs.p, tbs.len, &to, ASN1_SEQUENCE, &v) != ASN1_OK) XF(X509_ERR_PARSE);
    /* issuer */
    if (der_expect(tbs.p, tbs.len, &to, ASN1_SEQUENCE, &c->issuer) != ASN1_OK) XF(X509_ERR_PARSE);
    /* validity */
    der_buf validity;
    if (der_expect(tbs.p, tbs.len, &to, ASN1_SEQUENCE, &validity) != ASN1_OK) XF(X509_ERR_PARSE);
    {
        size_t vo = 0;
        der_buf nb, na;
        if (der_read_tlv(validity.p, validity.len, &vo, NULL, &nb) != ASN1_OK) XF(X509_ERR_PARSE);
        if (der_read_time(&nb, &c->not_before) != ASN1_OK) XF(X509_ERR_PARSE);
        if (der_read_tlv(validity.p, validity.len, &vo, NULL, &na) != ASN1_OK) XF(X509_ERR_PARSE);
        if (der_read_time(&na, &c->not_after) != ASN1_OK) XF(X509_ERR_PARSE);
    }
    /* subject */
    if (der_expect(tbs.p, tbs.len, &to, ASN1_SEQUENCE, &c->subject) != ASN1_OK) XF(X509_ERR_PARSE);
    parse_name_cn(&c->subject, c->cn, sizeof(c->cn));
    /* subjectPublicKeyInfo */
    der_buf spki;
    if (der_expect(tbs.p, tbs.len, &to, ASN1_SEQUENCE, &spki) != ASN1_OK) XF(X509_ERR_PARSE);
    {
        size_t so = 0;
        der_buf alg, pk;
        if (der_expect(spki.p, spki.len, &so, ASN1_SEQUENCE, &alg) != ASN1_OK) XF(X509_ERR_PARSE);
        {
            size_t ao = 0;
            der_buf oid;
            if (der_expect(alg.p, alg.len, &ao, ASN1_OID, &oid) != ASN1_OK) XF(X509_ERR_PARSE);
            if (!der_oid_eq(&oid, "1.2.840.113549.1.1.1")) XF(X509_ERR_ALGO);
        }
        if (der_expect(spki.p, spki.len, &so, ASN1_BIT_STRING, &pk) != ASN1_OK) XF(X509_ERR_PARSE);
        der_buf rsa_pub;
        if (der_read_bitstring(&pk, &rsa_pub) != ASN1_OK) XF(X509_ERR_PARSE);
        /* RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } */
        size_t ro = 0;
        der_buf rseq;
        if (der_expect(rsa_pub.p, rsa_pub.len, &ro, ASN1_SEQUENCE, &rseq) != ASN1_OK) XF(X509_ERR_PARSE);
        size_t ro2 = 0;
        der_buf n_v, e_v;
        if (der_expect(rseq.p, rseq.len, &ro2, ASN1_INTEGER, &n_v) != ASN1_OK) XF(X509_ERR_PARSE);
        if (der_expect(rseq.p, rseq.len, &ro2, ASN1_INTEGER, &e_v) != ASN1_OK) XF(X509_ERR_PARSE);
        uint8_t nbytes[BN_MAX_BYTES];
        size_t nlen = 0;
        if (der_read_uint(&n_v, nbytes, sizeof(nbytes), &nlen) != ASN1_OK) XF(X509_ERR_PARSE);
        if (der_read_u32(&e_v, &c->e) != ASN1_OK) XF(X509_ERR_ALGO);
        bn_from_be(&c->n, nbytes, nlen);
        c->has_rsa = 1;
    }
    /* 可选 [1] [2] [3] */
    while (to < tbs.len) {
        size_t s2 = to;
        der_buf opt;
        uint8_t tag = 0;
        if (der_read_tlv(tbs.p, tbs.len, &to, &tag, &opt) != ASN1_OK) break;
        if (tag == 0xa3) { if (parse_extensions(&opt, c) != X509_OK) XF(X509_ERR_PARSE); }
        (void)s2;
    }

    /* signatureAlgorithm */
    der_buf sigalg;
    if (der_expect(cert.p, cert.len, &co, ASN1_SEQUENCE, &sigalg) != ASN1_OK) XF(X509_ERR_PARSE);
    {
        size_t ao = 0;
        der_buf oid;
        if (der_expect(sigalg.p, sigalg.len, &ao, ASN1_OID, &oid) != ASN1_OK) XF(X509_ERR_PARSE);
        if (der_oid_eq(&oid, "1.2.840.113549.1.1.11")) c->sig_sha256_rsa = 1;
        else XF(X509_ERR_ALGO);
    }
    /* signatureValue */
    der_buf sigbit;
    if (der_expect(cert.p, cert.len, &co, ASN1_BIT_STRING, &sigbit) != ASN1_OK) XF(X509_ERR_PARSE);
    if (der_read_bitstring(&sigbit, &c->sigval) != ASN1_OK) XF(X509_ERR_PARSE);

    return X509_OK;
}

x509_err x509_verify_signed_by(const x509_cert *c, const x509_cert *issuer) {
    if (!c || !issuer || !c->sig_sha256_rsa) return X509_ERR_ALGO;
    if (!issuer->has_rsa) return X509_ERR_ALGO;
    if (!x509_name_eq(&c->issuer, &issuer->subject)) return X509_ERR_CHAIN;
    rsa_err r = rsa_verify_sha256(&issuer->n, issuer->e,
                                  c->tbs.p, c->tbs.len,
                                  c->sigval.p, c->sigval.len);
    if (r != RSA_OK) return X509_ERR_SIG;
    return X509_OK;
}

/* 自己实现不区分大小写比较：不用 strcasecmp —— 它在某些最小运行环境
   里没有声明（编译期才发现），而且 locale 行为不可控。 */
static int ci_eq(const char *a, const char *b) {
    while (*a && *b) {
        int ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : (int)*a;
        int cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : (int)*b;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == *b;
}

/* 主机名匹配：SAN 优先；"*.example.com" 只匹配一级左侧标签 */
static int host_eq(const char *pat, const char *host) {
    if (!pat || !host) return 0;
    size_t pl = strlen(pat), hl = strlen(host);
    if (pl == 0 || hl == 0) return 0;
    if (pat[0] == '*') {
        if (pl < 3 || pat[1] != '.') return 0;
        const char *suffix = pat + 1;            /* ".example.com" */
        size_t sl = pl - 1;
        if (hl <= sl) return 0;
        if (!ci_eq(host + (hl - sl), suffix)) return 0;
        /* 左侧剩余部分不得再含点 */
        for (size_t i = 0; i + sl < hl; i++) if (host[i] == '.') return 0;
        return 1;
    }
    return ci_eq(pat, host);
}

int x509_host_match(const x509_cert *c, const char *host) {
    if (!c || !host) return 0;
    if (c->san_n > 0) {
        for (int i = 0; i < c->san_n; i++) if (host_eq(c->san[i], host)) return 1;
        return 0;   /* 有 SAN 就不再看 CN（RFC 6125） */
    }
    return host_eq(c->cn, host);
}

/* --- PEM 解码 --- */
static int b64_val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char *in, size_t len, uint8_t *out, size_t cap, size_t *out_len) {
    uint32_t acc = 0; int bits = 0; size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        int v = b64_val((unsigned char)in[i]);
        if (v < 0) continue;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) return -1;
            out[o++] = (uint8_t)((acc >> bits) & 0xff);
        }
    }
    *out_len = o;
    return 0;
}

void x509_store_free(x509_store *st) {
    if (!st || !st->e) return;
    for (int i = 0; i < st->n; i++) free(st->e[i].der);
    free(st->e);
    st->e = NULL;
    st->n = 0;
}

x509_err x509_store_add_der(x509_store *st, const uint8_t *der, size_t len) {
    if (!st || !der) return X509_ERR_PARSE;
    if (len > X509_DER_MAX) return X509_ERR_RANGE;
    /* 懒分配：调用方可以直接 memset 为 0 后使用，不必先调 init。
     * store 本体若内联 160 个 entry（每个含 8KB der）会是约 1.7MB，
     * 在栈上声明两三个就爆栈，且崩溃点与调用点无关。 */
    if (!st->e) {
        st->e = calloc(X509_STORE_MAX, sizeof(*st->e));
        if (!st->e) return X509_ERR_MEM;
        st->n = 0;
    }
    if (st->n >= X509_STORE_MAX) return X509_ERR_RANGE;
    uint8_t *copy = malloc(len ? len : 1);
    if (!copy) return X509_ERR_MEM;
    memcpy(copy, der, len);
    x509_entry *e = &st->e[st->n];
    e->der = copy;
    e->der_len = len;
    if (x509_parse(e->der, len, &e->c) != X509_OK) {
        free(copy);
        e->der = NULL;
        e->der_len = 0;
        return X509_ERR_PARSE;
    }
    st->n++;
    return X509_OK;
}

x509_err x509_store_load_pem(x509_store *st, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return X509_ERR_IO;
    static uint8_t buf[1 << 20];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    if (n == 0) return X509_ERR_IO;
    const char *s = (const char *)buf;
    const char *begin = "-----BEGIN CERTIFICATE-----";
    const char *end   = "-----END CERTIFICATE-----";
    size_t bl = strlen(begin), el = strlen(end);
    int loaded = 0;
    for (size_t i = 0; i + bl < n; i++) {
        if (memcmp(s + i, begin, bl) != 0) continue;
        const char *body = s + i + bl;
        size_t rest = n - (body - s);
        const char *e = NULL;
        for (size_t j = 0; j + el < rest; j++) {
            if (memcmp(body + j, end, el) == 0) { e = body + j; break; }
        }
        if (!e) break;
        static uint8_t der[X509_DER_MAX];
        size_t dlen = 0;
        if (b64_decode(body, (size_t)(e - body), der, sizeof(der), &dlen) != 0) continue;
        /* 信任库里必然有我们不支持的算法（ECDSA / Ed25519 / DSA）。
           遇到就跳过，不能让一张不认识的证书把整个信任库判死 ——
           那样表现为"所有站点都验不过"，且看不出是信任库加载的问题。 */
        if (x509_store_add_der(st, der, dlen) != X509_OK) continue;
        loaded++;
        i = (size_t)(e - s) + el;
    }
    return loaded > 0 ? X509_OK : X509_ERR_IO;
}

x509_err x509_verify_chain(const x509_cert *chain, int n,
                           const x509_store *anchors,
                           const char *host, int64_t now) {
    if (!chain || n <= 0) return X509_ERR_PARSE;
    /* 有效期：链内每张都要检查 */
    for (int i = 0; i < n; i++) {
        if (now < chain[i].not_before || now > chain[i].not_after) return X509_ERR_EXPIRED;
    }
    /* 主机名只对叶子 */
    if (host && !x509_host_match(&chain[0], host)) return X509_ERR_HOST;

    /* 逐级找签发者：优先链内下一张，其次信任锚 */
    for (int i = 0; i < n; i++) {
        const x509_cert *issuer = NULL;
        int from_anchor = 0;
        if (i + 1 < n && x509_name_eq(&chain[i].issuer, &chain[i + 1].subject)) {
            issuer = &chain[i + 1];
        } else if (anchors) {
            for (int a = 0; a < anchors->n; a++) {
                if (x509_name_eq(&chain[i].issuer, &anchors->e[a].c.subject)) {
                    issuer = &anchors->e[a].c;
                    from_anchor = 1;
                    break;
                }
            }
        }
        if (!issuer) return X509_ERR_CHAIN;
        /* 明确写着 CA:FALSE 的证书不能充当签发者。
         * 少了这道检查，一张普通服务器证书就能签出任意域名。
         * is_ca == -1（扩展缺失，老式证书）按允许处理，是刻意的兼容取舍。 */
        if (issuer->is_ca == 0) return X509_ERR_CHAIN;
        x509_err e = x509_verify_signed_by(&chain[i], issuer);
        if (e != X509_OK) return e;
        /* 链必须由信任锚收尾：中间证书自己签自己不算可信 */
        if (from_anchor) return X509_OK;
    }
    return X509_OK;
}
