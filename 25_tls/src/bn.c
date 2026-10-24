/* bn.c — 定长大数运算实现 */
#include "bn.h"
#include <string.h>
#include <stdio.h>

const char *bn_errstr(bn_err e) {
    switch (e) {
    case BN_OK:          return "ok";
    case BN_ERR_RANGE:   return "value exceeds BN_MAX_BYTES";
    case BN_ERR_EXP:     return "exponent not supported";
    case BN_ERR_NEG:     return "subtraction would go negative";
    case BN_ERR_ZERO_MOD:return "modulus is zero";
    }
    return "unknown";
}

void bn_zero(bn_t *r) {
    memset(r->d, 0, sizeof(r->d));
    r->n = 0;
}

static void trim(bn_t *r) {
    while (r->n > 0 && r->d[r->n - 1] == 0) r->n--;
}

void bn_from_be(bn_t *r, const uint8_t *be, size_t len) {
    bn_zero(r);
    if (len > BN_MAX_BYTES) len = BN_MAX_BYTES;
    for (size_t i = 0; i < len; i++) {
        size_t byte_idx = len - 1 - i;
        uint32_t limb = i / 4;
        uint32_t shift = (i % 4) * 8;
        r->d[limb] |= ((uint32_t)be[byte_idx]) << shift;
    }
    r->n = (int)((len + 3) / 4);
    trim(r);
}

/* 输出固定 out_len 字节、数值右对齐（低字节在末尾）。
   RSA 的 EM 必须是 k 字节定长，左对齐会让 PKCS#1 填充结构整体错位，
   表现为"验签永远失败"却查不出原因 —— 这个坑踩过一次。 */
int bn_to_be(const bn_t *a, uint8_t *out, size_t out_len) {
    size_t need = (size_t)((bn_bitlen(a) + 7) / 8);
    if (need > out_len) return -1;
    memset(out, 0, out_len);
    for (size_t i = 0; i < need; i++) {
        uint32_t limb = a->d[i / 4];
        out[out_len - 1 - i] = (uint8_t)(limb >> ((i % 4) * 8));
    }
    return (int)need;
}

int bn_bitlen(const bn_t *a) {
    if (a->n == 0) return 0;
    uint32_t hi = a->d[a->n - 1];
    int bits = 0;
    while (hi) { bits++; hi >>= 1; }
    return (a->n - 1) * 32 + bits;
}

int bn_cmp(const bn_t *a, const bn_t *b) {
    if (a->n != b->n) return a->n < b->n ? -1 : 1;
    for (int i = a->n - 1; i >= 0; i--) {
        if (a->d[i] != b->d[i]) return a->d[i] < b->d[i] ? -1 : 1;
    }
    return 0;
}

int bn_is_zero(const bn_t *a) { return a->n == 0; }

bn_err bn_add(bn_t *r, const bn_t *a, const bn_t *b) {
    uint64_t carry = 0;
    int n = a->n > b->n ? a->n : b->n;
    if (n + 1 > BN_LIMBS) return BN_ERR_RANGE;
    bn_zero(r);
    for (int i = 0; i < n; i++) {
        uint64_t av = i < a->n ? a->d[i] : 0;
        uint64_t bv = i < b->n ? b->d[i] : 0;
        uint64_t s = av + bv + carry;
        r->d[i] = (uint32_t)s;
        carry = s >> 32;
    }
    if (carry) r->d[n++] = (uint32_t)carry;
    r->n = n;
    trim(r);
    return BN_OK;
}

bn_err bn_sub(bn_t *r, const bn_t *a, const bn_t *b) {
    if (bn_cmp(a, b) < 0) return BN_ERR_NEG;
    uint64_t borrow = 0;
    bn_zero(r);
    for (int i = 0; i < a->n; i++) {
        uint64_t av = a->d[i];
        uint64_t bv = i < b->n ? b->d[i] : 0;
        uint64_t d = av - bv - borrow;
        r->d[i] = (uint32_t)d;
        borrow = (d >> 32) & 1;
    }
    r->n = a->n;
    trim(r);
    return BN_OK;
}

bn_err bn_mul(bn_t *r, const bn_t *a, const bn_t *b) {
    if (a->n + b->n > BN_LIMBS) return BN_ERR_RANGE;
    bn_zero(r);
    for (int i = 0; i < a->n; i++) {
        uint64_t carry = 0;
        uint64_t av = a->d[i];
        if (!av) continue;
        for (int j = 0; j < b->n; j++) {
            uint64_t cur = (uint64_t)r->d[i + j] + av * b->d[j] + carry;
            r->d[i + j] = (uint32_t)cur;
            carry = cur >> 32;
        }
        int k = i + b->n;
        while (carry) {
            uint64_t cur = (uint64_t)r->d[k] + carry;
            r->d[k] = (uint32_t)cur;
            carry = cur >> 32;
            k++;
        }
    }
    r->n = a->n + b->n;
    trim(r);
    return BN_OK;
}

/* 移位-减法取模：r = a mod m */
bn_err bn_mod(bn_t *r, const bn_t *a, const bn_t *m) {
    if (bn_is_zero(m)) return BN_ERR_ZERO_MOD;
    bn_t acc, tmp;
    bn_zero(&acc);
    int bits = bn_bitlen(a);
    for (int i = bits - 1; i >= 0; i--) {
        /* acc = acc * 2 */
        uint64_t carry = 0;
        for (int k = 0; k < acc.n; k++) {
            uint64_t v = ((uint64_t)acc.d[k] << 1) | carry;
            acc.d[k] = (uint32_t)v;
            carry = v >> 32;
        }
        if (carry && acc.n < BN_LIMBS) acc.d[acc.n++] = (uint32_t)carry;
        /* 置入当前位 */
        if ((a->d[i / 32] >> (i % 32)) & 1) {
            uint64_t c = 1;
            for (int k = 0; k < acc.n && c; k++) {
                uint64_t v = (uint64_t)acc.d[k] + c;
                acc.d[k] = (uint32_t)v;
                c = v >> 32;
            }
            if (c && acc.n < BN_LIMBS) acc.d[acc.n++] = (uint32_t)c;
        }
        /* if acc >= m: acc -= m */
        if (bn_cmp(&acc, m) >= 0) {
            if (bn_sub(&tmp, &acc, m) != BN_OK) return BN_ERR_RANGE;
            acc = tmp;
        }
    }
    *r = acc;
    return BN_OK;
}

/* 模加：r = (a + b) mod m，要求 a,b < m（则一次减法足够） */
static void modadd(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m) {
    bn_t s, t;
    bn_add(&s, a, b);
    if (bn_cmp(&s, m) >= 0) {
        bn_sub(&t, &s, m);
        s = t;
    }
    *r = s;
}

/* 移位-加法乘法取模：r = a*b mod m */
bn_err bn_mulmod(bn_t *r, const bn_t *a0, const bn_t *b0, const bn_t *m) {
    if (bn_is_zero(m)) return BN_ERR_ZERO_MOD;
    bn_t a = *a0, b = *b0, res, tmp, twice;
    /* 归约到 < m */
    if (bn_cmp(&a, m) >= 0) { if (bn_mod(&tmp, &a, m) != BN_OK) return BN_ERR_RANGE; a = tmp; }
    if (bn_cmp(&b, m) >= 0) { if (bn_mod(&tmp, &b, m) != BN_OK) return BN_ERR_RANGE; b = tmp; }
    bn_zero(&res);
    int bits = bn_bitlen(&a);
    for (int i = 0; i < bits; i++) {
        if ((a.d[i / 32] >> (i % 32)) & 1) modadd(&res, &res, &b, m);
        /* b = 2b mod m */
        modadd(&twice, &b, &b, m);
        b = twice;
    }
    *r = res;
    return BN_OK;
}

/* 模幂（指数为 uint32）：平方-乘 */
bn_err bn_modpow_u32(bn_t *r, const bn_t *a, uint32_t e, const bn_t *m) {
    if (bn_is_zero(m)) return BN_ERR_ZERO_MOD;
    bn_t base, res, tmp;
    base = *a;
    if (bn_cmp(&base, m) >= 0) { if (bn_mod(&tmp, &base, m) != BN_OK) return BN_ERR_RANGE; base = tmp; }
    /* res = 1 */
    bn_zero(&res);
    res.d[0] = 1;
    res.n = 1;
    if (e == 0) { *r = res; return BN_OK; }
    while (e) {
        if (e & 1) {
            if (bn_mulmod(&tmp, &res, &base, m) != BN_OK) return BN_ERR_RANGE;
            res = tmp;
        }
        e >>= 1;
        if (e) {
            if (bn_mulmod(&tmp, &base, &base, m) != BN_OK) return BN_ERR_RANGE;
            base = tmp;
        }
    }
    *r = res;
    return BN_OK;
}

/* 模幂（指数为大数）：平方-乘，从指数最高位向下扫描。
   签名用（d 与模数等长，2048 位即 2048 轮）。
   注意不能用 bn_modpow_u32 顶替：d 被截成 u32 不会报错，
   只会产出一份结构完全合法、验签必然失败的签名。 */
bn_err bn_modpow(bn_t *r, const bn_t *a, const bn_t *e, const bn_t *m) {
    if (bn_is_zero(m)) return BN_ERR_ZERO_MOD;
    bn_t base, res, tmp;
    base = *a;
    if (bn_cmp(&base, m) >= 0) { if (bn_mod(&tmp, &base, m) != BN_OK) return BN_ERR_RANGE; base = tmp; }
    bn_zero(&res);
    res.d[0] = 1;
    res.n = 1;
    int bits = bn_bitlen(e);
    for (int i = bits - 1; i >= 0; i--) {
        if (bn_mulmod(&tmp, &res, &res, m) != BN_OK) return BN_ERR_RANGE;
        res = tmp;
        if ((e->d[i / 32] >> (i % 32)) & 1u) {
            if (bn_mulmod(&tmp, &res, &base, m) != BN_OK) return BN_ERR_RANGE;
            res = tmp;
        }
    }
    *r = res;
    return BN_OK;
}

void bn_dump(const char *tag, const bn_t *a) {
    printf("%s (%d bits): ", tag, bn_bitlen(a));
    if (a->n == 0) { printf("0\n"); return; }
    for (int i = a->n - 1; i >= 0; i--) printf("%08x", a->d[i]);
    printf("\n");
}
