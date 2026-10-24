/*
 * DAYANJING v3 — crypto_gcm.h
 *
 * AES-128-GCM 自研实现（C11）。
 *
 * 与 Python 层 crypto_layer.py 的契约保持一致：
 *   - 密钥长度：16 字节（AES-128）
 *   - IV 长度：12 字节（96 位）
 *   - Tag 长度：16 字节
 *   - HKDF info 标签：与 key_derivation.py 完全一致
 *
 * 设计：
 *   - AES-128 ECB 自研：SubBytes / ShiftRows / MixColumns / AddRoundKey，10 轮
 *   - GCM 自研：GCTR_K 流密码 + GHASH (GF(2^128) 乘法)
 *   - GHASH 采用 MSB-first 标准表示，避免 reflected 域字节序陷阱
 *   - 归约多项式：x^128 + x^7 + x^2 + x + 1，R = 0xE1 << 120
 *
 * 用途：C 端 agent / c2_server / delivery 的 AEAD 底座。
 * 不依赖 OpenSSL。
 */

#ifndef DAYANJING_CRYPTO_GCM_H
#define DAYANJING_CRYPTO_GCM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 常量 ---- */
#define GCM_KEY_LEN   16   /* AES-128 密钥 */
#define GCM_IV_LEN    12   /* GCM 推荐 IV 长度（96 位） */
#define GCM_TAG_LEN   16   /* 默认 tag 长度（128 位） */
#define GCM_BLOCK     16   /* AES 分组长度 */

/* ---- 返回值 ---- */
#define GCM_OK        0
#define GCM_ERR_KEY  -1    /* 密钥长度错误 */
#define GCM_ERR_IV   -2    /* IV 长度错误 */
#define GCM_ERR_TAG  -3    /* tag 长度错误 */
#define GCM_ERR_AUTH -4    /* 认证失败（密文/tag 被篡改） */

/* ---- AES-128（ECB，自研） ---- */
void aes128_encrypt_block(const uint8_t key[GCM_KEY_LEN],
                          const uint8_t in[GCM_BLOCK],
                          uint8_t out[GCM_BLOCK]);

void aes128_decrypt_block(const uint8_t key[GCM_KEY_LEN],
                          const uint8_t in[GCM_BLOCK],
                          uint8_t out[GCM_BLOCK]);

/* ---- AES-128-GCM ---- */

/*
 * Seal（加密 + 认证）。
 *
 * 入参：
 *   key      : 16 字节密钥
 *   iv       : 12 字节 IV
 *   aad      : 附加认证数据，可为 NULL（len_aad=0）
 *   len_aad  : aad 长度（字节）
 *   plaintext: 明文，可为 NULL（len_pt=0）
 *   len_pt   : 明文长度（字节）
 * 出参：
 *   ciphertext: 密文，调用方分配，至少 len_pt 字节
 *   tag        : 16 字节 tag，调用方分配
 *
 * 返回 GCM_OK 表示成功。
 */
int gcm_seal(const uint8_t key[GCM_KEY_LEN],
             const uint8_t iv[GCM_IV_LEN],
             const uint8_t *aad, size_t len_aad,
             const uint8_t *plaintext, size_t len_pt,
             uint8_t *ciphertext,
             uint8_t tag[GCM_TAG_LEN]);

/*
 * Open（验签 + 解密）。
 *
 * 入参：
 *   key      : 16 字节密钥
 *   iv       : 12 字节 IV
 *   aad      : 附加认证数据，可为 NULL（len_aad=0）
 *   len_aad  : aad 长度（字节）
 *   ciphertext: 密文
 *   len_ct   : 密文长度（字节）
 *   tag      : 16 字节待验证 tag
 * 出参：
 *   plaintext: 解密结果，调用方分配，至少 len_ct 字节
 *
 * 返回 GCM_OK 表示验签通过且解密成功；
 * 返回 GCM_ERR_AUTH 表示 tag 不匹配（密文或 tag 被篡改）。
 */
int gcm_open(const uint8_t key[GCM_KEY_LEN],
             const uint8_t iv[GCM_IV_LEN],
             const uint8_t *aad, size_t len_aad,
             const uint8_t *ciphertext, size_t len_ct,
             const uint8_t tag[GCM_TAG_LEN],
             uint8_t *plaintext);

/*
 * GHASH(H, X)：GF(2^128) 上的消息认证码。
 * 供测试程序直接调用，对照 NIST 中间值。
 *
 * H : 16 字节（= E_K(0^128)）
 * X : 已按 16 字节对齐、零填充的输入块序列
 * len_x : X 的长度（字节，必须是 16 的倍数）
 * out   : 16 字节输出
 */
void ghash(const uint8_t h[GCM_BLOCK],
           const uint8_t *x, size_t len_x,
           uint8_t out[GCM_BLOCK]);

/* 工具：固定时间比较，防止 tag 比对侧信道 */
int crypto_constant_time_eq(const uint8_t *a, const uint8_t *b, size_t len);

/*
 * 常量时间三路比较：返回 -1 / 0 / +1（a<b / a==b / a>b）。
 *
 * 为什么需要它 —— 密钥排序不能用 memcmp：
 *   双向派生为保证两端得到同一 ikm，必须把两个方向的密钥按固定次序拼
 *   接（klo||khi）。用 memcmp(ks,kr,n) 定序，其耗时在【第一个不同字节】
 *   处终止，泄露"两密钥首个失配位置"。虽然本进程内的纳秒级差异难以被
 *   网络观测，但这是"测不出来"而非"不存在"，换平台即可测出。
 *
 * 实现要点（两层）：
 *   1) 源码层：循环步数恒为 len，无 break / return / 条件 continue；
 *   2) 机器码层：大小关系用【无符号下溢的最高位】求得，不写任何比较
 *      运算符，因此不依赖编译器把 'x > y' 降级成 seta/setb。
 *
 * 【实测更正 —— 别再重复这个错误声称】
 * 曾在此处写过"改回比较运算符会让条件跳转从 2 变 3、守卫变红"。
 * 实测是错的：两种写法的条件跳转数都是 4（3 条 NULL 检查 + 1 条数据
 * 无关的循环条件），编译器把 x<y 优化成了 sub+shr，与手写算术版生成
 * 的机器码等价。反汇编确认循环体内零分支。
 *
 * 所以"不写比较运算符"的价值是【消除对编译器行为的依赖】，而不是
 * 【已有机器码守卫能抓到它】。该替换已记为变异 M17 的已知盲区：
 * 本工具链下无害，但换个编译器或降优化级别就可能生成分支。
 *
 * 真正有守卫的是另一类破坏：不改步数、只在循环体内加分支（如
 * if (gt|lt) continue; if (x>y) gt=1; ...）。它源码层全绿、机器码
 * 条件跳转 4 -> 7，由变异 M16 钉住。
 */
int crypto_ct_cmp(const uint8_t *a, const uint8_t *b, size_t len);

/*
 * 常量时间比较的观测计数器 —— 仅当以 -DCRYPTO_CT_INSTRUMENT 编译时存在。
 *
 * 用途：把"验签是否走了常量时间原语"变成可断言的事实。
 *   - 正常：gcm open 一次 -> 计数器 == GCM_TAG_LEN
 *   - 若有人把 tag 比对换成 memcmp，或改成发现不同即 break 的早退写法，
 *     计数器就不会等于 GCM_TAG_LEN，测试立即失败。
 *
 * 注意它测的是【源码级执行步数】，不是机器码级常量时间。后者仍需
 * 人工审查生成的汇编（编译器理论上可把无副作用循环优化成早退）。
 * 但源码级早退是最常见的破坏方式，且这一层能捕获 memcmp 替换。
 */
#ifdef CRYPTO_CT_INSTRUMENT
extern size_t crypto_ct_steps;
#endif

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_CRYPTO_GCM_H */
