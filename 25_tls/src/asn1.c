/* asn1.c — DER 最小解析实现 */
#include "asn1.h"
#include <string.h>
#include <stdio.h>

const char *asn1_errstr(asn1_err e) {
    switch (e) {
    case ASN1_OK:        return "ok";
    case ASN1_ERR_TRUNC: return "truncated DER";
    case ASN1_ERR_TAG:   return "unexpected tag";
    case ASN1_ERR_LEN:   return "unsupported length encoding";
    case ASN1_ERR_RANGE: return "output buffer too small";
    }
    return "unknown";
}

asn1_err der_read_tlv(const uint8_t *p, size_t len, size_t *off,
                      uint8_t *tag, der_buf *val) {
    size_t o = *off;
    if (o + 2 > len) return ASN1_ERR_TRUNC;
    uint8_t t = p[o++];
    uint8_t l0 = p[o++];
    size_t l;
    if (l0 < 0x80) {
        l = l0;
    } else if (l0 == 0x81) {
        if (o + 1 > len) return ASN1_ERR_TRUNC;
        l = p[o++];
    } else if (l0 == 0x82) {
        if (o + 2 > len) return ASN1_ERR_TRUNC;
        l = ((size_t)p[o] << 8) | p[o + 1];
        o += 2;
    } else {
        return ASN1_ERR_LEN;   /* 不定长或 >64KB：X.509 不会出现 */
    }
    if (o + l > len) return ASN1_ERR_TRUNC;
    if (tag) *tag = t;
    if (val) { val->p = p + o; val->len = l; }
    *off = o + l;
    return ASN1_OK;
}

asn1_err der_expect(const uint8_t *p, size_t len, size_t *off,
                    uint8_t want_tag, der_buf *val) {
    size_t save = *off;
    uint8_t tag = 0;
    asn1_err e = der_read_tlv(p, len, off, &tag, val);
    if (e != ASN1_OK) return e;
    if (tag != want_tag) { *off = save; return ASN1_ERR_TAG; }
    return ASN1_OK;
}

asn1_err der_seq_begin(const der_buf *seq, size_t *off) {
    (void)seq;
    *off = 0;
    return ASN1_OK;
}

asn1_err der_read_uint(const der_buf *v, uint8_t *out, size_t cap, size_t *out_len) {
    if (v->len == 0) return ASN1_ERR_TRUNC;
    /* DER INTEGER：无符号数在最高位为 1 时前置 0x00 */
    const uint8_t *p = v->p;
    size_t n = v->len;
    if (p[0] & 0x80) return ASN1_ERR_TAG;  /* 负数：证书里不该出现 */
    if (n > 1 && p[0] == 0x00) { p++; n--; }
    if (n > cap) return ASN1_ERR_RANGE;
    memcpy(out, p, n);
    *out_len = n;
    return ASN1_OK;
}

asn1_err der_read_u32(const der_buf *v, uint32_t *out) {
    if (v->len == 0 || v->len > 5) return ASN1_ERR_RANGE;
    if (v->p[0] & 0x80) return ASN1_ERR_TAG;
    uint64_t val = 0;
    const uint8_t *p = v->p;
    size_t n = v->len;
    if (n > 1 && p[0] == 0x00) { p++; n--; }
    if (n > 4) return ASN1_ERR_RANGE;
    for (size_t i = 0; i < n; i++) val = (val << 8) | p[i];
    *out = (uint32_t)val;
    return ASN1_OK;
}

asn1_err der_read_bitstring(const der_buf *v, der_buf *out) {
    if (v->len < 1) return ASN1_ERR_TRUNC;
    if (v->p[0] != 0x00) return ASN1_ERR_LEN;  /* 非整字节：不支持 */
    out->p = v->p + 1;
    out->len = v->len - 1;
    return ASN1_OK;
}

static int is_digit(char c) { return c >= '0' && c <= '9'; }

/* 仅支持 "Z"（UTC）结尾，X.509 强制要求 */
asn1_err der_read_time(const der_buf *v, int64_t *out) {
    if (v->len < 11) return ASN1_ERR_TRUNC;
    const uint8_t *p = v->p;
    int year, mon, day, hour, min, sec;
    size_t i = 0;
    if (p[v->len - 1] != 'Z') return ASN1_ERR_LEN;
    if (v->len == 13) {          /* UTCTime YYMMDDHHMMSSZ */
        year = (p[0] - '0') * 10 + (p[1] - '0');
        year += (year < 50) ? 2000 : 1900;
        i = 2;
    } else if (v->len == 15) {   /* GeneralizedTime YYYYMMDDHHMMSSZ */
        year = (p[0]-'0')*1000 + (p[1]-'0')*100 + (p[2]-'0')*10 + (p[3]-'0');
        i = 4;
    } else {
        return ASN1_ERR_LEN;
    }
    mon  = (p[i]-'0')*10 + (p[i+1]-'0'); i += 2;
    day  = (p[i]-'0')*10 + (p[i+1]-'0'); i += 2;
    hour = (p[i]-'0')*10 + (p[i+1]-'0'); i += 2;
    min  = (p[i]-'0')*10 + (p[i+1]-'0'); i += 2;
    sec  = (p[i]-'0')*10 + (p[i+1]-'0'); i += 2;
    (void)is_digit;
    if (mon < 1 || mon > 12 || day < 1 || day > 31) return ASN1_ERR_LEN;

    /* 换算为 Unix 秒（自己算，不依赖 timegm 的时区行为） */
    static const int mdays[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
    long days = 0;
    for (int y = 1970; y < year; y++)
        days += ((y%4==0 && y%100!=0) || y%400==0) ? 366 : 365;
    for (int m = 1; m < mon; m++) {
        days += mdays[m-1];
        if (m == 2 && ((year%4==0 && year%100!=0) || year%400==0)) days += 1;
    }
    days += day - 1;
    *out = (int64_t)(days * 86400 + hour * 3600 + min * 60 + sec);
    return ASN1_OK;
}

asn1_err der_find_tag(const uint8_t *p, size_t len, uint8_t tag, der_buf *out) {
    size_t off = 0;
    while (off < len) {
        uint8_t t = 0;
        der_buf v;
        asn1_err e = der_read_tlv(p, len, &off, &t, &v);
        if (e != ASN1_OK) return e;
        if (t == tag) { *out = v; return ASN1_OK; }
    }
    return ASN1_ERR_TAG;
}

int der_eq(const der_buf *a, const der_buf *b) {
    if (a->len != b->len) return 0;
    /* SEC-CMP:PUBLIC: ASN.1/DER 内容比较。比较对象是证书/签名的公开结构字段（如 OID、算法标识），非秘密。注：全仓无调用者（死代码），若将来用于比较秘密值须重新判定。 */
    return a->len == 0 || memcmp(a->p, b->p, a->len) == 0;
}

/* OID -> 点分字符串，再整体比较。
   先解码成字符串再比，比边解码边比清晰得多 —— 之前那版边解码边比
   在第一段（40*x+y）的处理上写错了，导致所有 OID 比较失败，
   表现为"证书解析不过"，而真正原因藏在 OID 里，极难定位。 */
int der_oid_eq(const der_buf *v, const char *dotted) {
    if (v->len == 0 || !dotted) return 0;
    char buf[256];
    size_t used = 0;
    uint64_t val = 0;
    int first = 1, pending = 0;
    for (size_t i = 0; i < v->len; i++) {
        uint8_t b = v->p[i];
        if (val > (UINT64_MAX >> 7)) return 0;
        val = (val << 7) | (b & 0x7f);
        pending = 1;
        if (b & 0x80) continue;
        int n;
        if (first) {
            uint64_t x = (val < 40) ? 0 : (val < 80 ? 1 : 2);
            uint64_t y = val - x * 40;
            n = snprintf(buf + used, sizeof(buf) - used, "%llu.%llu",
                         (unsigned long long)x, (unsigned long long)y);
            first = 0;
        } else {
            n = snprintf(buf + used, sizeof(buf) - used, ".%llu",
                         (unsigned long long)val);
        }
        if (n < 0 || (size_t)n >= sizeof(buf) - used) return 0;
        used += (size_t)n;
        val = 0;
        pending = 0;
    }
    if (pending) return 0;          /* 以续位字节结尾：非法编码 */
    return strcmp(buf, dotted) == 0;
}
