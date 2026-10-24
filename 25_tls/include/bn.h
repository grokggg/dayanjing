/* bn.h — 定长大数运算（仅 RSA 验签所需的最小集合）
 *
 * 设计取舍：
 *   - 定长 4096 位上限，栈上结构体，无 malloc —— implant 侧不做动态分配。
 *   - 只实现需要的操作：比较、加法、减法、乘法、模加、模倍、模幂。
 *     不做除法/模逆 —— 用不到的代码不写，写了就是未验证代码。
 *   - 两种模幂并存，用途不同，不可互相替代：
 *       bn_modpow_u32：指数为 u32，用于【验签】（公钥 e = 65537/3）。
 *       bn_modpow    ：指数为大数，用于【签名】（私钥 d 与模数等长）。
 *     在只有客户端时确实只需要前者；25_tls 新增服务端（SKE 签名）后
 *     后者成为必需。把 d 截断进 u32 会静默产出错误签名，而不是报错。
 *   - 常数时间不是本层目标：RSA 验签只处理公开信息（证书签名、公钥），
 *     没有秘密输入，侧信道无意义。真正需要常数时间的是 X25519/GCM，在 00_crypto。
 */
#ifndef BN_H
#define BN_H

#include <stdint.h>
#include <stddef.h>

#define BN_MAX_BITS  4096
#define BN_MAX_BYTES (BN_MAX_BITS / 8)      /* 512 */
#define BN_LIMBS     32                     /* 1024 位，够 RSA-1024 */

/* 提高到 4096 位需要更多 limb，这里按 2048/4096 兼顾：*/
#undef  BN_LIMBS
#define BN_LIMBS     (BN_MAX_BYTES / 4)     /* 128 limb × 32 bit = 4096 bit */

typedef struct {
    uint32_t d[BN_LIMBS];   /* 小端 limb */
    int      n;             /* 已用 limb 数，0 表示值为 0 */
} bn_t;

typedef enum {
    BN_OK = 0,
    BN_ERR_RANGE,      /* 输入超过 BN_MAX_BYTES */
    BN_ERR_EXP,        /* 指数不支持（非 uint32 或未实现） */
    BN_ERR_NEG,        /* 减法出现负数（调用方需保证 a>=b） */
    BN_ERR_ZERO_MOD    /* 模数为 0 */
} bn_err;

const char *bn_errstr(bn_err e);

void bn_zero(bn_t *r);
void bn_from_be(bn_t *r, const uint8_t *be, size_t len);
int  bn_to_be(const bn_t *a, uint8_t *out, size_t out_len); /* 返回所需字节数，<=0 失败 */
int  bn_bitlen(const bn_t *a);
int  bn_cmp(const bn_t *a, const bn_t *b);
int  bn_is_zero(const bn_t *a);

bn_err bn_add(bn_t *r, const bn_t *a, const bn_t *b);
bn_err bn_sub(bn_t *r, const bn_t *a, const bn_t *b);              /* 要求 a >= b */
bn_err bn_mul(bn_t *r, const bn_t *a, const bn_t *b);              /* 要求结果不超 4096 位 */
bn_err bn_mod(bn_t *r, const bn_t *a, const bn_t *m);              /* 移位-减法取模 */
bn_err bn_mulmod(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m);
bn_err bn_modpow_u32(bn_t *r, const bn_t *a, uint32_t e, const bn_t *m);

/* 模幂（指数为大数）：平方-乘，从最高位向下扫描。
   签名用（私钥 d）。指数为 0 时返回 1，与数学定义一致。 */
bn_err bn_modpow(bn_t *r, const bn_t *a, const bn_t *e, const bn_t *m);

/* 调试：十六进制打印（测试用） */
void bn_dump(const char *tag, const bn_t *a);

#endif /* BN_H */
