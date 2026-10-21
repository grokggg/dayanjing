/*
 * DAYANJING v4 — 20_packer / binding.c
 *
 * 规范化绑定上下文（canonical binding context）。
 *
 * ====================================================================
 * 解决的问题
 * ====================================================================
 * v2 把 bind_ctx 当作不透明字节串接受，由调用方自行序列化。这带来一个
 * 真实的绑定退化风险：两个不同的（server_static_id, implant_id, generation）
 * 三元组，若调用方用不同的拼接方式（有无分隔符、长度是否固定、字段顺序
 * 不同）却碰巧产生相同字节，bind_id 就相同 —— 绑定失效。
 *
 * 典型例子：id="AB", implant="C" 与 id="A", implant="BC"，
 * 在无长度前缀的直接拼接下都得到 "ABC"。
 *
 * ====================================================================
 * 规范编码
 * ====================================================================
 *   域标签(27) || u32(version) || 16B(server_static_id)
 *              || u16(nid) || implant_id(nid 字节) || u64(generation) || u32(epoch)
 *
 * 单射性来自三点：
 *   1. 固定字段顺序与固定宽度（id 恒 16B、generation 恒 u64、epoch 恒 u32）
 *   2. implant_id 以 u16 长度前缀引导，不用 NUL 分隔 —— 内容无法伪造边界
 *   3. 域标签做协议隔离：绑定上下文不会被误用于其他派生
 *
 * 解码端再做 canonical 校验：长度必须恰好等于 need，且 [need, in_len)
 * 区间必须全零。因此"同一结构体两种编码"被判 PK_ERR_CANON，而不是静默
 * 接受 —— 这正是 v2 缺少的那道检查。
 *
 * ====================================================================
 * implant_id 字符集
 * ====================================================================
 * 限定为可打印 ASCII 且排除 '/'、'\\'、':'，并拒绝 "." 与 ".."。
 * 目的不是美观，而是防止 implant_id 被下游拼进路径或 URL 时造成穿越
 * （"../../etc/cron.d/x"）。绑定上下文里出现这类字符直接拒绝。
 */

#include "packer.h"

#include <string.h>

/* 域标签：与 seed/bind_id 的标签互不相同，避免跨协议复用 */
static const uint8_t PK_BINDING_LABEL[] = "dayanjing:packer:binding:v1";
#define PK_BINDING_LABEL_LEN 27u

/* 固定部分：label(27) + version(4) + id(16) + nid(2) + gen(8) + epoch(4) */
#define PK_BINDING_FIXED_LEN 61u

/* ---------- 小端读写（与 pack.c 同约定：显式，不依赖结构体布局） ---------- */

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xffu);
}

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t get64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | (uint64_t)p[i];
    return v;
}

/* ---------- implant_id 校验 ---------- */

/*
 * 合法：长度 1..PK_IMPLANT_ID_MAX；全部可打印 ASCII(0x20..0x7e)；
 * 不含 '/'、'\\'、':'；整体不是 "." 或 ".."。
 */
static int implid_ok(const char *s, size_t *n_out)
{
    size_t n;

    if (!s) return 0;
    n = strlen(s);
    if (n == 0 || n > PK_IMPLANT_ID_MAX) return 0;

    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20u || c > 0x7eu) return 0;      /* 控制字符 / 非 ASCII */
        if (c == '/' || c == '\\' || c == ':') return 0;  /* 路径 / URL 分隔 */
    }
    if (n == 1 && s[0] == '.') return 0;
    if (n == 2 && s[0] == '.' && s[1] == '.') return 0;

    *n_out = n;
    return 1;
}

/* ---------- 公开接口 ---------- */

int pk_binding_make(const uint8_t server_static_id[PK_SERVER_ID_LEN],
                    const char *implant_id,
                    uint64_t generation,
                    uint32_t epoch,
                    pk_binding_t *out)
{
    size_t n = 0;

    if (!out || !server_static_id) return PK_ERR_ARG;
    if (!implid_ok(implant_id, &n)) return PK_ERR_IMPLID;

    memset(out, 0, sizeof(*out));
    out->version = PK_BINDING_VERSION;
    memcpy(out->server_static_id, server_static_id, PK_SERVER_ID_LEN);
    memcpy(out->implant_id, implant_id, n);
    out->implant_id[n] = '\0';
    out->generation = generation;
    out->epoch = epoch;
    return PK_OK;
}

int pk_binding_encode(const pk_binding_t *b, uint8_t *out, size_t cap,
                      size_t *out_len)
{
    size_t n = 0;
    size_t need;
    size_t off = 0;

    if (!b || !out_len) return PK_ERR_ARG;
    if (b->version != PK_BINDING_VERSION) return PK_ERR_VERSION;
    if (!implid_ok(b->implant_id, &n)) return PK_ERR_IMPLID;

    need = PK_BINDING_FIXED_LEN + n;
    *out_len = need;

    if (!out) return PK_OK;            /* 仅探测长度 */
    if (cap < need) return PK_ERR_NOMEM;

    /* 清零整个缓冲区，保证 [need, cap) 全零 —— 解码端 canonical 校验依赖此点 */
    memset(out, 0, cap);

    memcpy(out + off, PK_BINDING_LABEL, PK_BINDING_LABEL_LEN);
    off += PK_BINDING_LABEL_LEN;
    put32(out + off, b->version);            off += 4;
    memcpy(out + off, b->server_static_id, PK_SERVER_ID_LEN);
    off += PK_SERVER_ID_LEN;
    put16(out + off, (uint16_t)n);           off += 2;
    memcpy(out + off, b->implant_id, n);     off += n;
    put64(out + off, b->generation);         off += 8;
    put32(out + off, b->epoch);              off += 4;

    return PK_OK;
}

int pk_binding_decode(const uint8_t *in, size_t in_len, pk_binding_t *out)
{
    size_t off = 0;
    size_t n;
    uint32_t ver;

    if (!in || !out) return PK_ERR_ARG;
    if (in_len < PK_BINDING_FIXED_LEN) return PK_ERR_SMALL;

    if (memcmp(in, PK_BINDING_LABEL, PK_BINDING_LABEL_LEN) != 0)
        return PK_ERR_MAGIC;
    off += PK_BINDING_LABEL_LEN;

    ver = get32(in + off); off += 4;
    if (ver != PK_BINDING_VERSION) return PK_ERR_VERSION;

    memset(out, 0, sizeof(*out));
    out->version = ver;

    /* 字段顺序必须与编码端严格一致：version -> id -> nid -> implant_id
     * -> generation -> epoch。任何一步漏算宽度都会让后续字段整体错位。 */
    memcpy(out->server_static_id, in + off, PK_SERVER_ID_LEN);
    off += PK_SERVER_ID_LEN;

    n = (size_t)get16(in + off); off += 2;

    /* nid 必须落在合法区间，且总长自洽 */
    if (n == 0 || n > PK_IMPLANT_ID_MAX) return PK_ERR_IMPLID;
    if (in_len < PK_BINDING_FIXED_LEN + n) return PK_ERR_SMALL;

    /*
     * canonical 校验：多余字节必须全零。
     * 若调用方给了更大缓冲却残留垃圾，说明编码路径不统一 —— 拒绝而不是接受。
     */
    for (size_t i = PK_BINDING_FIXED_LEN + n; i < in_len; i++)
        if (in[i] != 0) return PK_ERR_CANON;

    memcpy(out->implant_id, in + off, n);
    out->implant_id[n] = '\0';
    off += n;

    /* 回读校验：implant_id 必须同时满足字符集约束（防绕过 make 直接构造） */
    {
        size_t chk = 0;
        if (!implid_ok(out->implant_id, &chk) || chk != n)
            return PK_ERR_IMPLID;
    }

    out->generation = get64(in + off); off += 8;
    out->epoch = get32(in + off);      off += 4;

    return PK_OK;
}
