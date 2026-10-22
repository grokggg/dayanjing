/*
 * DAYANJING v4 — 20_packer / pack_int.h
 *
 * 模块内部接口：不对外暴露，仅供 src/ 下各编译单元共享。
 * 对外公共接口一律在 include/packer.h。
 */

#ifndef DAYANJING_PACK_INT_H
#define DAYANJING_PACK_INT_H

#include "packer.h"

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
