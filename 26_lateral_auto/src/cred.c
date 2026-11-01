/* 26_lateral_auto/src/cred.c —— 凭据生成、发现、指纹 */
#include "lateral_auto.h"
#include "crypto_hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>

/* ---- 内部 base64（自包含，不污染公共层） ---- */

static const char B64T[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_val(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* 解码。返回写入 out 的字节数，失败返回 -1。 */
static long b64_dec(const char *in, size_t len, uint8_t *out, size_t cap)
{
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;

    for (size_t i = 0; i < len; i++) {
        int v = b64_val((unsigned char)in[i]);
        if (v < 0) {
            if (in[i] == '=') break;
            return -1;               /* 非法字符：宁可失败，不可静默跳过 */
        }
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) return -1;
            out[o++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    return (long)o;
}

/* 编码，无填充（ssh-keygen 的 SHA256: 指纹无 '='）。 */
static long b64_enc_nopad(const uint8_t *in, size_t len, char *out, size_t cap)
{
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        size_t rem = len - i;
        uint32_t acc = (uint32_t)in[i] << 16;
        int nbyte;

        if (rem >= 2) acc |= (uint32_t)in[i + 1] << 8;
        if (rem >= 3) acc |= (uint32_t)in[i + 2];
        nbyte = (rem >= 3) ? 4 : (rem == 2 ? 3 : 2);

        for (int k = 0; k < 4; k++) {
            if (k >= nbyte) break;
            if (o + 1 >= cap) return -1;
            out[o++] = B64T[(acc >> (18 - k * 6)) & 0x3F];
        }
    }
    if (o < cap) out[o] = '\0';
    return (long)o;
}

/* ---- 指纹 ---- */

int lat_cred_fingerprint(const char *pub_b64, size_t b64len,
                         char *out, size_t cap)
{
    uint8_t blob[4096];
    uint8_t dgst[SHA256_DIGEST_LEN];
    long    n;
    char    b64[64];
    long    m;

    if (!pub_b64 || !out || cap < 8) return -1;
    if (b64len == 0) return -1;

    n = b64_dec(pub_b64, b64len, blob, sizeof(blob));
    if (n <= 0) return -1;

    sha256(blob, (size_t)n, dgst);

    m = b64_enc_nopad(dgst, SHA256_DIGEST_LEN, b64, sizeof(b64));
    if (m <= 0) return -1;

    if ((size_t)m + 8 > cap) return -1;         /* "SHA256:" 7 字节 + NUL */
    memcpy(out, "SHA256:", 7);
    memcpy(out + 7, b64, (size_t)m + 1);
    return 0;
}

/* ---- 从 .pub 文件取第二字段 ---- */

static int pub_second_field(const char *publine, const char **b, size_t *blen)
{
    const char *p = publine;
    const char *s;
    const char *e;

    while (*p && *p != ' ' && *p != '\t') p++;   /* 跳过算法名 */
    if (!*p) return -1;
    while (*p == ' ' || *p == '\t') p++;
    s = p;
    while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
    e = p;
    if (e == s) return -1;
    *b = s;
    *blen = (size_t)(e - s);
    return 0;
}

/* ---- 密钥类型识别 ---- */

static const char *type_from_pub(const char *publine)
{
    if (strncmp(publine, "ssh-ed25519", 11) == 0) return "ed25519";
    if (strncmp(publine, "ssh-rsa", 7) == 0)      return "rsa";
    if (strncmp(publine, "ecdsa-sha2-", 11) == 0) return "ecdsa";
    return "unknown";
}

/* ---- 生成 ---- */

int lat_cred_gen(const char *dir, const char *name, const char *comment,
                 lat_cred_t *out)
{
    char kpath[LAT_PATH_MAX];
    pid_t pid;
    int   st = -1;

    if (!dir || !name || !out) return -1;
    if (strlen(dir) + strlen(name) + 2 > sizeof(kpath)) return -1;

    snprintf(kpath, sizeof(kpath), "%s/%s", dir, name);

    unlink(kpath);
    {
        char pub[LAT_PATH_MAX + 4];
        snprintf(pub, sizeof(pub), "%s.pub", kpath);
        unlink(pub);
    }

    /*
     * -q 静默；-N "" 空口令（非交互必需）；-t ed25519 短密钥、高安全。
     * 用 fork+exec 而非 system()，避免 shell 注入与环境变量污染。
     */
    pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, 1);
            dup2(devnull, 2);
            close(devnull);
        }
        execl("/usr/bin/ssh-keygen", "ssh-keygen", "-q", "-t", "ed25519",
              "-N", "", "-C", comment ? comment : "agent", "-f", kpath,
              (char *)NULL);
        _exit(127);
    }
    if (waitpid(pid, &st, 0) != pid) return -1;
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return -1;

    memset(out, 0, sizeof(*out));
    snprintf(out->path, sizeof(out->path), "%s", kpath);
    snprintf(out->type, sizeof(out->type), "ed25519");
    out->owned = 1;

    {
        char publine[1024];
        if (lat_cred_pubkey(out, publine, sizeof(publine)) == 0) {
            const char *b;
            size_t bl;
            if (pub_second_field(publine, &b, &bl) == 0) {
                char fp[LAT_FP_MAX];
                if (lat_cred_fingerprint(b, bl, fp, sizeof(fp)) == 0)
                    snprintf(out->fp, sizeof(out->fp), "%s", fp);
            }
        }
    }
    return 0;
}

/* ---- 读取公钥 ---- */

int lat_cred_pubkey(const lat_cred_t *c, char *out, size_t cap)
{
    char pub[LAT_PATH_MAX + 8];
    FILE *f;

    if (!c || !out || cap == 0) return -1;
    snprintf(pub, sizeof(pub), "%s.pub", c->path);

    f = fopen(pub, "r");
    if (!f) return -1;
    out[0] = '\0';
    if (!fgets(out, (int)cap, f)) { fclose(f); return -1; }
    fclose(f);

    {
        size_t l = strlen(out);
        while (l && (out[l - 1] == '\n' || out[l - 1] == '\r')) out[--l] = '\0';
    }
    return 0;
}

/* ---- 扫描 ---- */

static int is_private_name(const char *n)
{
    static const char *known[] = {
        "id_ed25519", "id_rsa", "id_ecdsa", "id_dsa",
        "id_ed25519_sk", "id_ecdsa_sk"
    };
    for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++)
        if (strcmp(n, known[i]) == 0) return 1;
    return 0;
}

int lat_cred_scan(const char *home, lat_cred_t *out, size_t cap, size_t *n)
{
    char sshdir[LAT_PATH_MAX];
    DIR *d;
    struct dirent *e;
    size_t cnt = 0;

    if (!home || !out || !n) return -1;
    *n = 0;
    if (snprintf(sshdir, sizeof(sshdir), "%s/.ssh", home) >= (int)sizeof(sshdir))
        return -1;

    d = opendir(sshdir);
    if (!d) return -1;

    while ((e = readdir(d)) != NULL) {
        char full[LAT_PATH_MAX];
        char pub[LAT_PATH_MAX + 8];
        struct stat st;
        lat_cred_t c;
        char publine[1024];

        if (!is_private_name(e->d_name)) continue;
        if (snprintf(full, sizeof(full), "%s/%s", sshdir, e->d_name)
            >= (int)sizeof(full)) continue;
        if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) continue;

        snprintf(pub, sizeof(pub), "%s.pub", full);
        {
            struct stat pst;
            if (stat(pub, &pst) != 0) continue;   /* 无 .pub 则无指纹可用 */
        }

        if (cnt >= cap) break;

        memset(&c, 0, sizeof(c));
        snprintf(c.path, sizeof(c.path), "%s", full);
        c.owned = 0;

        if (lat_cred_pubkey(&c, publine, sizeof(publine)) != 0) continue;
        snprintf(c.type, sizeof(c.type), "%s", type_from_pub(publine));
        {
            const char *b;
            size_t bl;
            if (pub_second_field(publine, &b, &bl) == 0)
                lat_cred_fingerprint(b, bl, c.fp, sizeof(c.fp));
        }
        out[cnt++] = c;
    }
    closedir(d);
    *n = cnt;
    return 0;
}

void lat_cred_redact(lat_cred_t *c)
{
    if (!c) return;
    c->owned = c->owned ? 1 : 0;
    c->path[LAT_PATH_MAX - 1] = '\0';
    c->type[sizeof(c->type) - 1] = '\0';
    c->fp[LAT_FP_MAX - 1] = '\0';
    /* 结构中不含任何密钥字节，此函数仅确保串终止，供调用方强制调用 */
}
