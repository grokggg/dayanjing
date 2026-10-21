/*
 * DAYANJING v4 — 20_packer / pack_int.h
 *
 * 模块内部接口：不对外暴露，仅供 src/ 下各编译单元共享。
 * 对外公共接口一律在 include/packer.h。
 */

#ifndef DAYANJING_PACK_INT_H
#define DAYANJING_PACK_INT_H

#include "packer.h"

/* AAD 长度随版本变化：v1 = 80，v2 = 112（多 bind_id 32 字节） */
#define PK_AAD_V1_LEN 80u
#define PK_AAD_V2_LEN 112u

/*
 * 打包核心。version 为 PK_VERSION 或 PK_VERSION2。
 * version==2 时 bind_id 必须非 NULL，写入头并纳入 AAD；
 * version==1 时 bind_id 忽略（头中该区全零）。
 */
int pk_pack_core(const uint8_t *raw, size_t raw_len,
                 const uint8_t *seed, size_t seed_len,
                 uint32_t version,
                 const uint8_t bind_id[PK_BIND_ID_LEN],
                 uint8_t *out, size_t *out_len);

/*
 * 解包核心。按头部声明的版本构造对应 AAD 并验签。
 * 不检查 bind_id 是否匹配——那是 pk_unpack_session 的职责。
 */
int pk_unpack_core(const uint8_t *blob, size_t blob_len,
                   const uint8_t *seed, size_t seed_len,
                   uint8_t *out, size_t *out_len);

#endif /* DAYANJING_PACK_INT_H */
