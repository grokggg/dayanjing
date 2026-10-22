/* test_asn1.c — DER 解析：结构与边界 */
#include "asn1.h"
#include <stdio.h>
#include <string.h>

static int fails = 0, total = 0;
#define CHECK(cond, name) do { \
    total++; \
    if (cond) printf("[PASS] %s\n", name); \
    else { printf("[FAIL] %s\n", name); fails++; } \
} while (0)

int main(void) {
    /* SEQUENCE { INTEGER 0x0100 } */
    const uint8_t der[] = { 0x30, 0x04, 0x02, 0x02, 0x01, 0x00 };
    size_t off = 0;
    uint8_t tag = 0;
    der_buf top;
    CHECK(der_read_tlv(der, sizeof(der), &off, &tag, &top) == ASN1_OK && tag == 0x30,
          "读外层 SEQUENCE");
    CHECK(top.len == 4 && off == 6, "长度与游标推进正确");

    size_t o2 = 0;
    der_buf in;
    CHECK(der_expect(top.p, top.len, &o2, ASN1_INTEGER, &in) == ASN1_OK, "读内层 INTEGER");
    uint8_t val[8]; size_t vl = 0;
    CHECK(der_read_uint(&in, val, sizeof(val), &vl) == ASN1_OK && vl == 2 && val[0] == 0x01,
          "INTEGER -> 无符号字节（去前导零）");

    /* 标签不符必须报错，且游标不能推进。
       注意要在"还有数据"的位置测：游标已到末尾时返回的是 TRUNC 而不是 TAG，
       那是正确语义，不能把两者混为一谈。 */
    size_t o_save = 0;
    der_buf dummy;
    CHECK(der_expect(top.p, top.len, &o_save, ASN1_OCTET_STRING, &dummy) == ASN1_ERR_TAG
          && o_save == 0, "标签不符报错且游标不动");
    /* 缓冲耗尽应报 TRUNC，而不是 TAG */
    CHECK(der_expect(top.p, top.len, &o2, ASN1_INTEGER, &dummy) == ASN1_ERR_TRUNC,
          "数据耗尽报 TRUNC（与标签不符区分开）");

    /* 截断数据必须报错，不能越界读 */
    const uint8_t trunc[] = { 0x30, 0x08, 0x02 };
    size_t off3 = 0;
    der_buf t3;
    CHECK(der_read_tlv(trunc, sizeof(trunc), &off3, NULL, &t3) == ASN1_ERR_TRUNC, "截断数据被拒");

    /* 不定长长度必须拒绝，不猜测 */
    const uint8_t indef[] = { 0x30, 0x80, 0x02, 0x01, 0x00, 0x00, 0x00 };
    size_t off4 = 0;
    der_buf t4;
    CHECK(der_read_tlv(indef, sizeof(indef), &off4, NULL, &t4) == ASN1_ERR_LEN, "不定长编码被拒");

    /* OID：sha256WithRSAEncryption = 1.2.840.113549.1.1.11 */
    const uint8_t oid[] = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b };
    size_t off5 = 0;
    der_buf o5;
    CHECK(der_read_tlv(oid, sizeof(oid), &off5, NULL, &o5) == ASN1_OK, "读 OID");
    CHECK(der_oid_eq(&o5, "1.2.840.113549.1.1.11") == 1, "OID 匹配 sha256WithRSAEncryption");
    CHECK(der_oid_eq(&o5, "1.2.840.113549.1.1.1") == 0, "OID 不匹配 rsaEncryption");
    CHECK(der_oid_eq(&o5, "1.2.840.113549") == 0, "OID 前缀不误判为相等");

    /* rsaEncryption = 1.2.840.113549.1.1.1 */
    const uint8_t oid2[] = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
    size_t off6 = 0;
    der_buf o6;
    der_read_tlv(oid2, sizeof(oid2), &off6, NULL, &o6);
    CHECK(der_oid_eq(&o6, "1.2.840.113549.1.1.1") == 1, "OID 匹配 rsaEncryption");

    /* commonName = 2.5.4.3 */
    const uint8_t oid3[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };
    size_t off7 = 0;
    der_buf o7;
    der_read_tlv(oid3, sizeof(oid3), &off7, NULL, &o7);
    CHECK(der_oid_eq(&o7, "2.5.4.3") == 1, "OID 匹配 commonName");

    /* subjectAltName = 2.5.29.17 */
    const uint8_t oid4[] = { 0x06, 0x03, 0x55, 0x1d, 0x11 };
    size_t off8 = 0;
    der_buf o8;
    der_read_tlv(oid4, sizeof(oid4), &off8, NULL, &o8);
    CHECK(der_oid_eq(&o8, "2.5.29.17") == 1, "OID 匹配 subjectAltName");

    /* 时间：UTCTime 与 GeneralizedTime */
    {
        const uint8_t t[] = { 0x17, 0x0d, '2','6','1','0','2','2','0','7','3','3','5','7','Z' };
        size_t o = 0; der_buf tv;
        der_read_tlv(t, sizeof(t), &o, NULL, &tv);
        int64_t ts = 0;
        CHECK(der_read_time(&tv, &ts) == ASN1_OK, "UTCTime 解析");
        int64_t expect = 0;
        {
            int days = 0;
            for (int y = 1970; y < 2026; y++)
                days += ((y%4==0 && y%100!=0) || y%400==0) ? 366 : 365;
            static const int mdays[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
            for (int m = 1; m < 10; m++) days += mdays[m-1];
            days += 22 - 1;
            expect = (int64_t)(days * 86400 + 7*3600 + 33*60 + 57);
        }
        CHECK(ts == expect, "UTCTime -> Unix 秒正确");
    }
    {
        const uint8_t t[] = { 0x18, 0x0f, '2','0','2','6','1','0','2','2','0','7','3','3','5','7','Z' };
        size_t o = 0; der_buf tv;
        der_read_tlv(t, sizeof(t), &o, NULL, &tv);
        int64_t ts = 0;
        CHECK(der_read_time(&tv, &ts) == ASN1_OK, "GeneralizedTime 解析");
        CHECK(ts > 0, "GeneralizedTime 得到正时间戳");
    }
    {
        const uint8_t t[] = { 0x17, 0x0d, '2','6','1','0','2','2','0','7','3','3','5','7','X' };
        size_t o = 0; der_buf tv;
        der_read_tlv(t, sizeof(t), &o, NULL, &tv);
        int64_t ts = 0;
        CHECK(der_read_time(&tv, &ts) == ASN1_ERR_LEN, "非 Z 结尾时间被拒");
    }

    printf("\n=== %d/%d passed ===\n", total - fails, total);
    return fails == 0 ? 0 : 1;
}
