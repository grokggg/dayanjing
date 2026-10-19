#include "evasion.h"
#include "evasion_internal.h"

#include <string.h>
#include <stdlib.h>

int evasion_b64url_encode(const uint8_t *in, size_t in_len, char *out, size_t out_len)
{
    static const char tab[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    /* 最坏长度: ceil(in_len/3)*4 + 1(NUL) */
    size_t need = (in_len / 3 + (in_len % 3 ? 1 : 0)) * 4 + 1;
    if (out_len < need) return EVASION_ERR_NOMEM;

    size_t oi = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < in_len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < in_len) v |= (uint32_t)in[i + 2];
        int n = (in_len - i >= 3) ? 4 : (in_len - i == 2 ? 3 : 2);
        out[oi++] = tab[(v >> 18) & 0x3F];
        out[oi++] = tab[(v >> 12) & 0x3F];
        if (n > 2) out[oi++] = tab[(v >> 6) & 0x3F];
        if (n > 3) out[oi++] = tab[v & 0x3F];
        /* 无填充(RFC 4648 无填充变体) */
    }
    out[oi] = '\0';
    return EVASION_OK;
}

int evasion_b64url_decode(const char *in, uint8_t *out, size_t *out_len)
{
    if (!in || !out || !out_len) return EVASION_ERR;

    /* 建解码表 */
    static const uint8_t dtable[256] = {
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
        ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
        ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
        ['Y']=24,['Z']=25,
        ['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,['g']=32,['h']=33,
        ['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,['o']=40,['p']=41,
        ['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,['w']=48,['x']=49,
        ['y']=50,['z']=51,
        ['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,['6']=58,['7']=59,
        ['8']=60,['9']=61,['-']=62,['_']=63
    };

    size_t ilen = strlen(in);
    size_t oi = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < ilen; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '=') break; /* 容忍有填充的输入 */
        uint8_t v = dtable[c];
        if (v == 0 && c != 'A' && c != '0') return EVASION_ERR_FMT; /* 非法字符 */
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (oi < *out_len) out[oi++] = (uint8_t)((acc >> bits) & 0xff);
        }
    }
    *out_len = oi;
    return EVASION_OK;
}

int evasion_parse_http_status(const uint8_t *resp, size_t resp_len)
{
    if (!resp || resp_len < 12) return EVASION_ERR;
    /* 状态行: "HTTP/1.x XXX ..." */
    if (resp[0] != 'H' || resp[1] != 'T' || resp[2] != 'T' || resp[3] != 'P')
        return EVASION_ERR_FMT;
    /* 找第一个空格后跟 3 位数字 */
    for (size_t i = 5; i + 5 < resp_len; i++) {
        if (resp[i] == ' ') {
            if (resp[i + 1] >= '0' && resp[i + 1] <= '9' &&
                resp[i + 2] >= '0' && resp[i + 2] <= '9' &&
                resp[i + 3] >= '0' && resp[i + 3] <= '9') {
                return (resp[i + 1] - '0') * 100
                     + (resp[i + 2] - '0') * 10
                     + (resp[i + 3] - '0');
            }
        }
    }
    return EVASION_ERR_FMT;
}

int evasion_parse_http_body(const uint8_t *resp, size_t resp_len,
                           uint8_t **body, size_t *body_len)
{
    if (!resp || !body || !body_len) return EVASION_ERR;
    /* 逐行区间解析, 找 "\r\n\r\n" 头体分隔 */
    size_t header_end = 0;
    for (size_t i = 0; i + 3 < resp_len; i++) {
        if (resp[i] == '\r' && resp[i + 1] == '\n' &&
            resp[i + 2] == '\r' && resp[i + 3] == '\n') {
            header_end = i + 4;
            break;
        }
    }
    if (header_end == 0) return EVASION_ERR_FMT;

    /* 解析 Content-Length */
    size_t content_len = 0;
    int has_cl = 0;
    size_t p = 0;
    while (p < header_end) {
        /* 找行尾 */
        size_t line_end = p;
        while (line_end < header_end && resp[line_end] != '\n') line_end++;
        if (line_end > header_end) line_end = header_end;
        /* 检查是否以 Content-Length: 开头(不区分大小写) */
        if (line_end - p > 15) {
            int match = 1;
            const char *cl = "Content-Length:";
            for (int k = 0; k < 15 && p + k < line_end; k++) {
                char c = (char)resp[p + k];
                if (c >= 'A' && c <= 'Z') c += 32;
                if (c != cl[k]) { match = 0; break; }
            }
            if (match) {
                /* 解析数值 */
                size_t vi = p + 15;
                while (vi < line_end && (resp[vi] == ' ' || resp[vi] == '\t')) vi++;
                content_len = 0;
                while (vi < line_end && resp[vi] >= '0' && resp[vi] <= '9') {
                    content_len = content_len * 10 + (resp[vi] - '0');
                    vi++;
                }
                has_cl = 1;
            }
        }
        p = line_end + 1;
    }

    if (!has_cl) {
        /* 无 Content-Length 时返回剩余全部 */
        content_len = resp_len - header_end;
    }
    if (header_end + content_len > resp_len) return EVASION_ERR_FMT;

    *body = (uint8_t *)(resp + header_end);
    *body_len = content_len;
    return EVASION_OK;
}

int evasion_random_qname_label(char *out, size_t out_len)
{
    if (!out || out_len < 16) return EVASION_ERR_NOMEM;
    static const char alpha[] = "abcdefghijklmnopqrstuvwxyz0123456789-";
    /* 生成 8~15 字符的随机合法标签 */
    size_t len = 8 + (rand() % 8);
    if (len + 1 > out_len) len = out_len - 1;
    for (size_t i = 0; i < len; i++) {
        out[i] = alpha[rand() % (sizeof(alpha) - 1)];
    }
    out[len] = '\0';
    return EVASION_OK;
}

const char *evasion_strerror(int err)
{
    switch (err) {
    case EVASION_OK:       return "ok";
    case EVASION_ERR:      return "general error";
    case EVASION_ERR_FMT:  return "format error";
    case EVASION_ERR_NOMEM:return "buffer too small";
    default:               return "unknown";
    }
}
