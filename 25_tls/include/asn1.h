/* asn1.h — DER 最小解析（够 X.509 用，不多写一个字节）
 *
 * 只支持我们真正会遇到的：SEQUENCE、INTEGER、BIT STRING、OCTET STRING、
 * OBJECT IDENTIFIER、PrintableString/UTF8String、UTCTime/GeneralizedTime、
 * 以及 context-specific 构造（X.509 扩展用 [3]）。
 * 不支持：不定长编码、超过 2 字节的长度、BER。遇到即报错，绝不猜测。
 */
#ifndef ASN1_H
#define ASN1_H

#include <stdint.h>
#include <stddef.h>

#define ASN1_INTEGER        0x02
#define ASN1_BIT_STRING     0x03
#define ASN1_OCTET_STRING   0x04
#define ASN1_NULL           0x05
#define ASN1_OID            0x06
#define ASN1_UTF8STRING     0x0c
#define ASN1_SEQUENCE       0x30
#define ASN1_SET            0x31
#define ASN1_PRINTABLE      0x13
#define ASN1_UTCTIME        0x17
#define ASN1_GENERALIZED    0x18
#define ASN1_CTX_CONSTRUCT  0xa0   /* [0]..[3] 等构造标签基址 */

typedef struct {
    const uint8_t *p;
    size_t         len;
} der_buf;

typedef enum {
    ASN1_OK = 0,
    ASN1_ERR_TRUNC,      /* 数据不够 */
    ASN1_ERR_TAG,        /* 标签不符预期 */
    ASN1_ERR_LEN,        /* 长度编码不支持（不定长/超长） */
    ASN1_ERR_RANGE       /* 输出缓冲不够 */
} asn1_err;

const char *asn1_errstr(asn1_err e);

/* 从 p[0..len) 的 offset 处读一个 TLV；成功则推进 *off 到下一个 TLV。
   val 指向 TLV 的“内容”部分。 */
asn1_err der_read_tlv(const uint8_t *p, size_t len, size_t *off,
                      uint8_t *tag, der_buf *val);

/* 读一个 TLV 并校验标签 */
asn1_err der_expect(const uint8_t *p, size_t len, size_t *off,
                    uint8_t want_tag, der_buf *val);

/* 取 SEQUENCE 之后的内容游标（用于逐项遍历） */
asn1_err der_seq_begin(const der_buf *seq, size_t *off);

/* INTEGER -> 大端无符号字节（自动去掉前导 0x00，拒绝负数） */
asn1_err der_read_uint(const der_buf *v, uint8_t *out, size_t cap, size_t *out_len);

/* INTEGER -> uint32（用于 RSA 公钥指数 e） */
asn1_err der_read_u32(const der_buf *v, uint32_t *out);

/* BIT STRING -> 返回去掉“未用位数”字节后的内容 */
asn1_err der_read_bitstring(const der_buf *v, der_buf *out);

/* 时间字符串 -> time_t（UTC）。支持 UTCTime(YYMMDDHHMMSSZ) 与 GeneralizedTime(YYYY...) */
asn1_err der_read_time(const der_buf *v, int64_t *out);

/* 在 SET/SEQUENCE 内容里查找指定标签的首个 TLV（不递归） */
asn1_err der_find_tag(const uint8_t *p, size_t len, uint8_t tag, der_buf *out);

/* 比较两个 DER 编码是否逐字节相等（用于 issuer/subject 匹配） */
int der_eq(const der_buf *a, const der_buf *b);

/* OID 比较：v 是否等于点分 OID 串（如 "1.2.840.113549.1.1.11"） */
int der_oid_eq(const der_buf *v, const char *dotted);

#endif /* ASN1_H */
