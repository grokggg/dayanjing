#define _GNU_SOURCE
#include "ui_internal.h"
#include "ui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ============================================================
 * 构造 / 销毁
 * ============================================================ */

static json_value_t *json_alloc(json_type_t t) {
    json_value_t *v = (json_value_t *)calloc(1, sizeof(*v));
    if (v) v->type = t;
    return v;
}

json_value_t *json_null(void)  { return json_alloc(JSON_NULL); }
json_value_t *json_bool(int v) {
    json_value_t *j = json_alloc(JSON_BOOL);
    if (j) j->u.b = !!v;
    return j;
}
json_value_t *json_num(double v){
    json_value_t *j = json_alloc(JSON_NUM);
    if (j) j->u.n = v;
    return j;
}

json_value_t *json_str(const char *s) {
    return json_strn(s, s ? strlen(s) : 0);
}

json_value_t *json_strn(const char *s, size_t n) {
    json_value_t *j = json_alloc(JSON_STR);
    if (!j) return NULL;
    j->u.s = (char *)malloc(n + 1);
    if (!j->u.s) { free(j); return NULL; }
    memcpy(j->u.s, s, n);
    j->u.s[n] = '\0';
    return j;
}

json_value_t *json_obj(void) { return json_alloc(JSON_OBJ); }
json_value_t *json_arr(void) { return json_alloc(JSON_ARR); }

void json_free(json_value_t *v) {
    if (!v) return;
    switch (v->type) {
    case JSON_STR:
        free(v->u.s);
        break;
    case JSON_OBJ: {
        json_kv_t *kv = v->u.obj.head;
        while (kv) {
            json_kv_t *n = kv->next;
            free(kv->key);
            json_free(kv->val);
            free(kv);
            kv = n;
        }
        break;
    }
    case JSON_ARR: {
        for (size_t i = 0; i < v->u.arr.len; i++) json_free(v->u.arr.items[i]);
        free(v->u.arr.items);
        break;
    }
    default: break;
    }
    free(v);
}

/* ============================================================
 * 对象增删查
 * ============================================================ */

static json_kv_t *obj_find_kv(const json_value_t *obj, const char *key) {
    if (!obj || obj->type != JSON_OBJ) return NULL;
    for (json_kv_t *kv = obj->u.obj.head; kv; kv = kv->next)
        if (strcmp(kv->key, key) == 0) return kv;
    return NULL;
}

json_value_t *json_obj_get(const json_value_t *obj, const char *key) {
    json_kv_t *kv = obj_find_kv(obj, key);
    return kv ? kv->val : NULL;
}

int json_obj_set(json_value_t *obj, const char *key, json_value_t *val) {
    if (!obj || obj->type != JSON_OBJ || !key) return -1;
    json_kv_t *kv = obj_find_kv(obj, key);
    if (kv) {
        json_free(kv->val);
        kv->val = val;
        return 0;
    }
    kv = (json_kv_t *)malloc(sizeof(*kv));
    if (!kv) { return -1; }
    kv->key = strdup(key);
    if (!kv->key) { free(kv); return -1; }
    kv->val = val;
    kv->next = obj->u.obj.head;
    obj->u.obj.head = kv;
    obj->u.obj.len++;
    return 0;
}

int json_obj_del(json_value_t *obj, const char *key) {
    if (!obj || obj->type != JSON_OBJ || !key) return -1;
    json_kv_t **pp = &obj->u.obj.head;
    while (*pp) {
        if (strcmp((*pp)->key, key) == 0) {
            json_kv_t *d = *pp;
            *pp = d->next;
            free(d->key);
            json_free(d->val);
            free(d);
            obj->u.obj.len--;
            return 0;
        }
        pp = &(*pp)->next;
    }
    return -1;
}

int json_arr_append(json_value_t *arr, json_value_t *val) {
    if (!arr || arr->type != JSON_ARR) return -1;
    if (arr->u.arr.len == arr->u.arr.cap) {
        size_t nc = arr->u.arr.cap ? arr->u.arr.cap * 2 : 4;
        json_value_t **ni = (json_value_t **)realloc(arr->u.arr.items,
                                                    nc * sizeof(*ni));
        if (!ni) return -1;
        arr->u.arr.items = ni;
        arr->u.arr.cap = nc;
    }
    arr->u.arr.items[arr->u.arr.len++] = val;
    return 0;
}

/* ============================================================
 * 递归下降解析器
 * ============================================================ */

typedef struct {
    const char *p;
    const char *end;
    const char *mark;   /* 错误位置 */
} parser_t;

static void skip_ws(parser_t *ps) {
    while (ps->p < ps->end) {
        char c = *ps->p;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ps->p++;
        else break;
    }
}

static json_value_t *parse_value(parser_t *ps, int depth);

static int parse_utf16_escape(parser_t *ps, uint32_t *out_cp) {
    if (ps->p + 4 > ps->end) return -1;
    uint16_t h = 0;
    for (int i = 0; i < 4; i++) {
        char c = ps->p[i];
        h <<= 4;
        if (c >= '0' && c <= '9')      h |= (uint16_t)(c - '0');
        else if (c >= 'a' && c <= 'f') h |= (uint16_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') h |= (uint16_t)(c - 'A' + 10);
        else return -1;
    }
    ps->p += 4;
    if (h >= 0xD800 && h <= 0xDBFF) {
        /* 代理对 */
        if (ps->p + 2 > ps->end || ps->p[0] != '\\' || ps->p[1] != 'u') return -1;
        ps->p += 2;
        uint16_t l = 0;
        for (int i = 0; i < 4; i++) {
            char c = ps->p[i];
            l <<= 4;
            if (c >= '0' && c <= '9')      l |= (uint16_t)(c - '0');
            else if (c >= 'a' && c <= 'f') l |= (uint16_t)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') l |= (uint16_t)(c - 'A' + 10);
            else return -1;
        }
        ps->p += 4;
        if (l < 0xDC00 || l > 0xDFFF) return -1;
        *out_cp = 0x10000 + (((uint32_t)(h - 0xD800) << 10) | (uint32_t)(l - 0xDC00));
    } else if (h >= 0xDC00 && h <= 0xDFFF) {
        return -1;
    } else {
        *out_cp = h;
    }
    return 0;
}

/* 将 code point 编码为 UTF-8，返回写入字节数 */
static int utf8_encode(uint32_t cp, char *out) {
    if (cp <= 0x7F) {
        out[0] = (char)cp; return 1;
    } else if (cp <= 0x7FF) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    } else if (cp <= 0xFFFF) {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    } else if (cp <= 0x10FFFF) {
        out[0] = (char)(0xF0 | (cp >> 18));
        out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[3] = (char)(0x80 | (cp & 0x3F));
        return 4;
    }
    return 0;
}

static char *parse_string_raw(parser_t *ps, size_t *out_len) {
    if (ps->p >= ps->end || *ps->p != '"') { ps->mark = ps->p; return NULL; }
    ps->p++;

    /* 单遍：边解析边展开到动态 buffer */
    size_t cap = 32;
    size_t pos = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) { ps->mark = ps->p; return NULL; }

    for (;;) {
        if (ps->p >= ps->end) { free(buf); ps->mark = ps->p; return NULL; }
        unsigned char c = (unsigned char)*ps->p++;
        if (c == '"') break;   /* 字符串结束 */
        if (c == '\\') {
            if (ps->p >= ps->end) { free(buf); ps->mark = ps->p; return NULL; }
            unsigned char e = (unsigned char)*ps->p++;
            char ch = 0;
            int is_utf = 0;
            switch (e) {
            case '"':  ch = '"'; break;
            case '\\': ch = '\\'; break;
            case '/':  ch = '/'; break;
            case 'b':  ch = '\b'; break;
            case 'f':  ch = '\f'; break;
            case 'n':  ch = '\n'; break;
            case 'r':  ch = '\r'; break;
            case 't':  ch = '\t'; break;
            case 'u':  is_utf = 1; break;
            default: free(buf); ps->mark = ps->p; return NULL;
            }
            if (is_utf) {
                /* ps->p 此时已指向 \u 后第一个 hex 字符 */
                uint32_t cp = 0;
                if (parse_utf16_escape(ps, &cp) != 0) { free(buf); ps->mark = ps->p; return NULL; }
                while (pos + 4 > cap) { cap *= 2; char *nb = realloc(buf, cap); if (!nb) { free(buf); return NULL; } buf = nb; }
                pos += utf8_encode(cp, buf + pos);
            } else {
                while (pos + 1 > cap) { cap *= 2; char *nb = realloc(buf, cap); if (!nb) { free(buf); return NULL; } buf = nb; }
                buf[pos++] = ch;
            }
        } else if (c < 0x20) {
            free(buf); ps->mark = ps->p - 1; return NULL;
        } else {
            while (pos + 1 > cap) { cap *= 2; char *nb = realloc(buf, cap); if (!nb) { free(buf); return NULL; } buf = nb; }
            buf[pos++] = (char)c;
        }
    }
    buf[pos] = '\0';
    *out_len = pos;
    return buf;
}

static json_value_t *parse_string(parser_t *ps, int depth) {
    (void)depth;
    size_t len = 0;
    char *s = parse_string_raw(ps, &len);
    if (!s) return NULL;
    json_value_t *j = json_alloc(JSON_STR);
    if (!j) { free(s); return NULL; }
    j->u.s = s;
    return j;
}

static json_value_t *parse_number(parser_t *ps, int depth) {
    (void)depth;
    const char *start = ps->p;
    if (ps->p < ps->end && (*ps->p == '-')) ps->p++;
    if (ps->p >= ps->end || !(*ps->p >= '0' && *ps->p <= '9')) { ps->mark = ps->p; return NULL; }
    if (ps->p[0] == '0') {
        ps->p++;
    } else {
        while (ps->p < ps->end && (*ps->p >= '0' && *ps->p <= '9')) ps->p++;
    }
    int is_float = 0;
    if (ps->p < ps->end && *ps->p == '.') {
        is_float = 1;
        ps->p++;
        if (ps->p >= ps->end || !(*ps->p >= '0' && *ps->p <= '9')) { ps->mark = ps->p; return NULL; }
        while (ps->p < ps->end && (*ps->p >= '0' && *ps->p <= '9')) ps->p++;
    }
    if (ps->p < ps->end && (*ps->p == 'e' || *ps->p == 'E')) {
        is_float = 1;
        ps->p++;
        if (ps->p < ps->end && (*ps->p == '+' || *ps->p == '-')) ps->p++;
        if (ps->p >= ps->end || !(*ps->p >= '0' && *ps->p <= '9')) { ps->mark = ps->p; return NULL; }
        while (ps->p < ps->end && (*ps->p >= '0' && *ps->p <= '9')) ps->p++;
    }
    size_t n = (size_t)(ps->p - start);
    if (n > 32) { ps->mark = start; return NULL; }
    char tmp[48];
    memcpy(tmp, start, n);
    tmp[n] = '\0';
    double d = strtod(tmp, NULL);
    (void)is_float;
    json_value_t *j = json_alloc(JSON_NUM);
    if (!j) return NULL;
    j->u.n = d;
    return j;
}

static json_value_t *parse_array(parser_t *ps, int depth) {
    if (depth > JSON_MAX_DEPTH) { ps->mark = ps->p; return NULL; }
    json_value_t *arr = json_alloc(JSON_ARR);
    if (!arr) return NULL;
    ps->p++; /* skip '[' */
    skip_ws(ps);
    if (ps->p < ps->end && *ps->p == ']') { ps->p++; return arr; }
    for (;;) {
        skip_ws(ps);
        json_value_t *el = parse_value(ps, depth + 1);
        if (!el) { json_free(arr); return NULL; }
        if (json_arr_append(arr, el) != 0) { json_free(el); json_free(arr); return NULL; }
        skip_ws(ps);
        if (ps->p >= ps->end) { json_free(arr); ps->mark = ps->p; return NULL; }
        if (*ps->p == ',') { ps->p++; continue; }
        if (*ps->p == ']') { ps->p++; return arr; }
        json_free(arr); ps->mark = ps->p; return NULL;
    }
}

static json_value_t *parse_object(parser_t *ps, int depth) {
    if (depth > JSON_MAX_DEPTH) { ps->mark = ps->p; return NULL; }
    json_value_t *obj = json_alloc(JSON_OBJ);
    if (!obj) return NULL;
    ps->p++; /* skip '{' */
    skip_ws(ps);
    if (ps->p < ps->end && *ps->p == '}') { ps->p++; return obj; }
    for (;;) {
        skip_ws(ps);
        size_t klen = 0;
        char *key = parse_string_raw(ps, &klen);
        if (!key) { json_free(obj); return NULL; }
        skip_ws(ps);
        if (ps->p >= ps->end || *ps->p != ':') { free(key); json_free(obj); ps->mark = ps->p; return NULL; }
        ps->p++; /* skip ':' */
        skip_ws(ps);
        json_value_t *val = parse_value(ps, depth + 1);
        if (!val) { free(key); json_free(obj); return NULL; }
        if (json_obj_set(obj, key, val) != 0) { free(key); json_free(val); json_free(obj); return NULL; }
        free(key);
        skip_ws(ps);
        if (ps->p >= ps->end) { json_free(obj); ps->mark = ps->p; return NULL; }
        if (*ps->p == ',') { ps->p++; continue; }
        if (*ps->p == '}') { ps->p++; return obj; }
        json_free(obj); ps->mark = ps->p; return NULL;
    }
}

static json_value_t *parse_value(parser_t *ps, int depth) {
    skip_ws(ps);
    if (ps->p >= ps->end) { ps->mark = ps->p; return NULL; }
    char c = *ps->p;
    if (c == '{') return parse_object(ps, depth);
    if (c == '[') return parse_array(ps, depth);
    if (c == '"') return parse_string(ps, depth);
    if (c == 't') {
        if (ps->p + 4 <= ps->end && memcmp(ps->p, "true", 4) == 0) {
            ps->p += 4; return json_bool(1);
        }
        ps->mark = ps->p; return NULL;
    }
    if (c == 'f') {
        if (ps->p + 5 <= ps->end && memcmp(ps->p, "false", 5) == 0) {
            ps->p += 5; return json_bool(0);
        }
        ps->mark = ps->p; return NULL;
    }
    if (c == 'n') {
        if (ps->p + 4 <= ps->end && memcmp(ps->p, "null", 4) == 0) {
            ps->p += 4; return json_null();
        }
        ps->mark = ps->p; return NULL;
    }
    if (c == '-' || (c >= '0' && c <= '9')) return parse_number(ps, depth);
    ps->mark = ps->p;
    return NULL;
}

json_value_t *json_parse(const char *buf, size_t len, const char **out_err) {
    parser_t ps;
    ps.p = buf;
    ps.end = buf + len;
    ps.mark = buf;
    json_value_t *v = parse_value(&ps, 0);
    if (!v) {
        if (out_err) *out_err = ps.mark;
        return NULL;
    }
    skip_ws(&ps);
    if (ps.p != ps.end) {
        /* 严格模式：解析完后不应有剩余字符 */
        json_free(v);
        if (out_err) *out_err = ps.p;
        return NULL;
    }
    return v;
}

/* ============================================================
 * 序列化
 * ============================================================ */

static size_t serialize_rec(const json_value_t *v, char *out, size_t cap, size_t pos);

static size_t append_str(char *out, size_t cap, size_t pos, const char *s, size_t len) {
    if (pos + len <= cap) memcpy(out + pos, s, len);
    return pos + len;
}

static size_t serialize_string(const char *s, size_t slen, char *out, size_t cap, size_t pos) {
    pos = append_str(out, cap, pos, "\"", 1);
    for (size_t i = 0; i < slen; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':  pos = append_str(out, cap, pos, "\\\"", 2); break;
        case '\\': pos = append_str(out, cap, pos, "\\\\", 2); break;
        case '\b': pos = append_str(out, cap, pos, "\\b", 2); break;
        case '\f': pos = append_str(out, cap, pos, "\\f", 2); break;
        case '\n': pos = append_str(out, cap, pos, "\\n", 2); break;
        case '\r': pos = append_str(out, cap, pos, "\\r", 2); break;
        case '\t': pos = append_str(out, cap, pos, "\\t", 2); break;
        default:
            if (c < 0x20) {
                char buf[8];
                int n = snprintf(buf, sizeof(buf), "\\u%04x", c);
                pos = append_str(out, cap, pos, buf, (size_t)n);
            } else {
                pos = append_str(out, cap, pos, (const char *)&s[i], 1);
            }
        }
    }
    pos = append_str(out, cap, pos, "\"", 1);
    return pos;
}

static size_t serialize_rec(const json_value_t *v, char *out, size_t cap, size_t pos) {
    switch (v->type) {
    case JSON_NULL: pos = append_str(out, cap, pos, "null", 4); break;
    case JSON_BOOL: pos = append_str(out, cap, pos, v->u.b ? "true" : "false",
                                     v->u.b ? 4 : 5); break;
    case JSON_NUM: {
        char buf[64];
        double d = v->u.n;
        int n;
        if (d == (double)(long long)d && fabs(d) < 1e16) {
            n = snprintf(buf, sizeof(buf), "%.0f", d);
        } else {
            n = snprintf(buf, sizeof(buf), "%.17g", d);
        }
        pos = append_str(out, cap, pos, buf, (size_t)n);
        break;
    }
    case JSON_STR: {
        size_t slen = v->u.s ? strlen(v->u.s) : 0;
        pos = serialize_string(v->u.s ? v->u.s : "", slen, out, cap, pos);
        break;
    }
    case JSON_OBJ: {
        pos = append_str(out, cap, pos, "{", 1);
        json_kv_t *kv = v->u.obj.head;
        int first = 1;
        while (kv) {
            if (!first) pos = append_str(out, cap, pos, ",", 1);
            first = 0;
            pos = serialize_string(kv->key, strlen(kv->key), out, cap, pos);
            pos = append_str(out, cap, pos, ":", 1);
            pos = serialize_rec(kv->val, out, cap, pos);
            kv = kv->next;
        }
        pos = append_str(out, cap, pos, "}", 1);
        break;
    }
    case JSON_ARR: {
        pos = append_str(out, cap, pos, "[", 1);
        for (size_t i = 0; i < v->u.arr.len; i++) {
            if (i) pos = append_str(out, cap, pos, ",", 1);
            pos = serialize_rec(v->u.arr.items[i], out, cap, pos);
        }
        pos = append_str(out, cap, pos, "]", 1);
        break;
    }
    }
    return pos;
}

size_t json_serialized_size(const json_value_t *v) {
    return serialize_rec(v, NULL, 0, 0);
}

int json_serialize(const json_value_t *v, char *out, size_t out_cap) {
    if (!v || !out || out_cap == 0) return -1;
    size_t need = serialize_rec(v, out, out_cap, 0);
    if (need >= out_cap) return -1;   /* 空间不足 */
    out[need] = '\0';
    return 0;
}
