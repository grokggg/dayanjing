/*
 * DAYANJING v4 — 20_packer / poly.h
 *
 * 多态引擎（x86-64）：为每次构建生成一份"语义等价、字节不同"的解码存根，
 * 外层用每构建随机的 RC4 密钥包裹载荷，使制品不存在跨构建可提取的静态特征。
 *
 * 制品布局：
 *     [ 多态存根 (变长) ][ 随机间隔 gap (0..48) ][ RC4 密文 ]
 *
 * 存根职责（全部位置无关，不依赖任何导入/重定位）：
 *     1. call/pop 取自身 RIP
 *     2. 计算密文起始地址（间隔长度在构建时确定，已打进立即数）
 *     3. 在栈上初始化 RC4 S 盒（256 字节），用内联 16 字节密钥做 KSA
 *     4. PRGA 原地解密载荷
 *     5. 恢复栈帧后 jmp 到明文载荷
 *
 * 变异维度（每一次构建独立随机）：
 *     - 寄存器重命名：13 个活跃角色从 14 个可用寄存器中随机分配
 *     - 等价指令替换：置零 / 自增 / 取模 / 加载 / 指针计算 / 循环判据
 *     - 垃圾指令注入：仅使用不影响标志位的等价空操作
 *     - 栈帧布局：S 盒偏移与密钥偏移随机化，帧大小随之变化
 *     - 间隔长度：0..48 随机
 *
 * 安全边界声明（不要误解本层的作用）：
 *     本层是"反静态签名"，不是"机密性"。RC4 仅用于让每次构建的字节不同，
 *     真正的机密性由内层 pack.c 的 AES-128-GCM 提供。密钥以立即数形式内联
 *     在存根里，逆向者总能取出——这是所有多态壳的固有性质。
 *
 * 不依赖 OpenSSL / zlib，仅 libc。仅支持 x86-64 System V。
 */

#ifndef DAYANJING_POLY_H
#define DAYANJING_POLY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define POLY_KEY_LEN 16   /* RC4 密钥长度，与存根内联立即数数量对应 */

/* 返回码 */
#define POLY_OK          0
#define POLY_ERR_PARAM  -1
#define POLY_ERR_MEM    -2
#define POLY_ERR_TOOBIG -3
#define POLY_ERR_NOBUILD -4

typedef struct poly_ctx poly_ctx;

/* 以给定种子创建引擎。同一种子的构建结果逐字节可复现。 */
poly_ctx *poly_new(uint64_t seed);
void      poly_free(poly_ctx *p);

/*
 * 生成一个多态制品。
 *   payload / pay_len : 待包裹的明文载荷（位置无关机器码）
 *   out / out_len     : 出参，malloc 分配，调用方 free
 * 成功返回 POLY_OK。
 */
int poly_build(poly_ctx *p, const uint8_t *payload, size_t pay_len,
               uint8_t **out, size_t *out_len);

/* 取回上一次构建使用的 RC4 密钥（供测试独立解密校验；运行时无需） */
int poly_last_key(poly_ctx *p, uint8_t key[POLY_KEY_LEN]);

/* 取回上一次构建的区间划分（供测试定位密文段） */
int poly_last_span(poly_ctx *p, size_t *stub_len, size_t *gap_len,
                   size_t *ct_off);

/*
 * 参考 RC4：与存根内实现的算法逐位等价（KSA 用 i%16 作密钥下标，
 * PRGA 的 i 从 1 开始）。对称，加密与解密同一函数。
 */
void poly_rc4(const uint8_t key[POLY_KEY_LEN], uint8_t *buf, size_t len);

const char *poly_strerror(int rc);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_POLY_H */
