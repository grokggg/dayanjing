#ifndef UI_H
#define UI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * JSON 值类型 (零第三方依赖，自研递归下降解析器)
 * ============================================================ */

#define JSON_MAX_DEPTH  32   /* 递归深度上限，防爆栈 */
#define JSON_MAX_KEY    256
#define JSON_MAX_STR    4096

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUM,
    JSON_STR,
    JSON_OBJ,
    JSON_ARR
} json_type_t;

typedef struct json_value json_value_t;

/* 有序键值对（保持插入顺序，便于序列化） */
typedef struct json_kv {
    char           *key;
    json_value_t   *val;
    struct json_kv *next;
} json_kv_t;

struct json_value {
    json_type_t type;
    union {
        int         b;        /* JSON_BOOL */
        double      n;        /* JSON_NUM */
        char       *s;        /* JSON_STR */
        struct {                    /* JSON_OBJ */
            json_kv_t *head;
            size_t     len;
        } obj;
        struct {                    /* JSON_ARR */
            json_value_t **items;
            size_t       len;
            size_t       cap;
        } arr;
    } u;
};

/* ---------- 构造 / 销毁 ---------- */
json_value_t *json_null(void);
json_value_t *json_bool(int v);
json_value_t *json_num(double v);
json_value_t *json_str(const char *s);
json_value_t *json_strn(const char *s, size_t n);
json_value_t *json_obj(void);
json_value_t *json_arr(void);
void          json_free(json_value_t *v);

/* 对象增删查 */
int  json_obj_set(json_value_t *obj, const char *key, json_value_t *val);
json_value_t *json_obj_get(const json_value_t *obj, const char *key);
int  json_obj_del(json_value_t *obj, const char *key);

/* 数组追加 */
int  json_arr_append(json_value_t *arr, json_value_t *val);

/* ---------- 解析 / 序列化 ---------- */
/* parse 返回 NULL 表示解析失败；out_err 可选，写入错误位置 */
json_value_t *json_parse(const char *buf, size_t len, const char **out_err);
int           json_serialize(const json_value_t *v, char *out, size_t out_cap);
size_t        json_serialized_size(const json_value_t *v);

/* ============================================================
 * HTTP/1.1 轻量解析
 * ============================================================ */

#define HTTP_MAX_HEADERS  32
#define HTTP_MAX_URI      1024
#define HTTP_MAX_REASON   256

typedef enum {
    HTTP_GET,
    HTTP_POST,
    HTTP_DELETE
} http_method_t;

typedef struct {
    http_method_t method;
    char          uri[HTTP_MAX_URI];
    int           status;                 /* 响应时填写 */
    int           content_length;
    int           keep_alive;             /* 1 = Connection: keep-alive */
    int           header_count;
    char         *header_names[HTTP_MAX_HEADERS];
    char         *header_vals[HTTP_MAX_HEADERS];
    char         *body;
    size_t        body_len;
    size_t        body_cap;
} http_req_t;

/* 解析状态机：
 *  返回  1 完整报文已解析
 *  返回  0 需要更多数据
 *  返回 -1 解析错误 / 报文非法 */
int  http_parse_req(http_req_t *req, const char *buf, size_t len);
void http_req_reset(http_req_t *req);
const char *http_get_header(const http_req_t *req, const char *name);

/* ============================================================
 * 路由表
 * ============================================================ */

struct ui_ctx;   /* 前向声明 */

typedef enum {
    HANDLE_OK = 0,
    HANDLE_NOT_FOUND,
    HANDLE_METHOD_NOT_ALLOWED,
    HANDLE_UNAUTHORIZED,
    HANDLE_BAD_REQUEST,
    HANDLE_INTERNAL_ERROR
} handle_result_t;

typedef struct {
    http_method_t method;
    const char   *path;          /* 形如 "/api/v1/agents/:id" */
    handle_result_t (*handler)(struct ui_ctx *ctx,
                              http_req_t *req,
                              const char **path_params,
                              int param_count,
                              char *out, size_t out_cap);
} route_t;

/* 路径参数提取：将 "/api/v1/agents/abc" 按模板匹配，
 * 返回参数个数，params 数组由调用者提供容量 */
int route_match(const char *tmpl, const char *uri,
                const char **params, int params_cap);

/* ============================================================
 * Token 认证 (基于 00_crypto HMAC，常量时间比对)
 * ============================================================ */

#define TOKEN_ISSUER_LEN  32
#define TOKEN_SECRET_LEN  32
/* base64url 编码后的 token：subject + issuer + 8字节exp + 32字节sig，最坏情况
 * (32+32+1+1+8+32)/3*4 ≈ 192，留足余量 */
#define TOKEN_B64_LEN     256

typedef struct {
    uint8_t secret[TOKEN_SECRET_LEN];
    uint8_t issuer[TOKEN_ISSUER_LEN];
    int64_t ttl_sec;
} token_signer_t;

void token_signer_init(token_signer_t *ts,
                       const uint8_t *secret, size_t secret_len,
                       const uint8_t *issuer, size_t issuer_len,
                       int64_t ttl_sec);

/* 签发：subject 任意字符串；out_b64 容量至少 TOKEN_B64_LEN */
int token_issue(const token_signer_t *ts, const char *subject,
                char *out_b64, size_t out_cap);

/* 校验：返回 1 有效，0 无效/过期/签名不符 */
int token_verify(const token_signer_t *ts, const char *b64,
                 size_t b64_len, char *out_subject, size_t subject_cap);

/* 从 Authorization: Bearer <token> 头中提取并校验 */
int token_authenticate(const token_signer_t *ts, const http_req_t *req,
                       char *out_subject, size_t subject_cap);

/* ============================================================
 * UI 上下文 (挂在 05_server epoll 控制面)
 * ============================================================ */

typedef struct ui_ctx {
    token_signer_t token;
    const route_t  *routes;
    int             route_count;
    /* 统计 */
    uint64_t        req_total;
    uint64_t        req_2xx;
    uint64_t        req_4xx;
    uint64_t        req_5xx;
} ui_ctx_t;

void ui_ctx_init(ui_ctx_t *ctx, const uint8_t *secret, size_t secret_len,
                 const uint8_t *issuer, size_t issuer_len, int64_t ttl_sec);

/* 处理一个完整 HTTP 请求，写入响应到 out，返回 handle_result_t */
handle_result_t ui_handle(ui_ctx_t *ctx, http_req_t *req,
                          char *out, size_t out_cap,
                          int *out_http_status);

/* 便捷：把 handle_result_t 转成 HTTP 状态码 + JSON 错误体 */
void ui_write_error(handle_result_t r, char *out, size_t out_cap,
                    int *out_http_status);

#define UI_OK 0
#define UI_ERR (-1)

#ifdef __cplusplus
}
#endif

#endif /* UI_H */
