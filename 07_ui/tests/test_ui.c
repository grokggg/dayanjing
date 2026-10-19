#define _GNU_SOURCE
#include "ui.h"
#include "ui_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

static int g_fail = 0;
#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        g_fail++; \
    } \
} while (0)

/* ============ JSON 测试 ============ */
static void test_json_basic(void) {
    printf("[test_json_basic]\n");
    json_value_t *j = json_parse("{\"name\":\"alice\",\"age\":30,\"admin\":true,\"score\":null}", strlen("{\"name\":\"alice\",\"age\":30,\"admin\":true,\"score\":null}"), NULL);
    CHECK(j != NULL);
    CHECK(j->type == JSON_OBJ);
    json_value_t *name = json_obj_get(j, "name");
    CHECK(name != NULL && name->type == JSON_STR);
    CHECK(strcmp(name->u.s, "alice") == 0);
    json_value_t *age = json_obj_get(j, "age");
    CHECK(age != NULL && age->type == JSON_NUM);
    CHECK(age->u.n == 30.0);
    json_value_t *admin = json_obj_get(j, "admin");
    CHECK(admin != NULL && admin->type == JSON_BOOL && admin->u.b == 1);
    json_value_t *score = json_obj_get(j, "score");
    CHECK(score != NULL && score->type == JSON_NULL);
    json_free(j);
}

static void test_json_array(void) {
    printf("[test_json_array]\n");
    json_value_t *j = json_parse("[1,2,3,\"four\",true,null]", strlen("[1,2,3,\"four\",true,null]"), NULL);
    CHECK(j != NULL && j->type == JSON_ARR);
    CHECK(j->u.arr.len == 6);
    CHECK(j->u.arr.items[0]->type == JSON_NUM);
    CHECK(j->u.arr.items[0]->u.n == 1.0);
    CHECK(j->u.arr.items[3]->type == JSON_STR);
    CHECK(strcmp(j->u.arr.items[3]->u.s, "four") == 0);
    CHECK(j->u.arr.items[4]->type == JSON_BOOL && j->u.arr.items[4]->u.b == 1);
    CHECK(j->u.arr.items[5]->type == JSON_NULL);
    json_free(j);
}

static void test_json_escape(void) {
    printf("[test_json_escape]\n");
    json_value_t *j = json_parse("\"hello\\nworld\\ttab\\r\\\"quote\\u4f60\\u597d\"", strlen("\"hello\\nworld\\ttab\\r\\\"quote\\u4f60\\u597d\""), NULL);
    CHECK(j != NULL && j->type == JSON_STR);
    /* hello\nworld\ttab\r"quote你好 */
    CHECK(strcmp(j->u.s, "hello\nworld\ttab\r\"quote你好") == 0);
    json_free(j);
}

static void test_json_serialize_roundtrip(void) {
    printf("[test_json_serialize_roundtrip]\n");
    json_value_t *obj = json_obj();
    json_obj_set(obj, "s", json_str("str"));
    json_obj_set(obj, "n", json_num(42.5));
    json_obj_set(obj, "b", json_bool(1));
    json_obj_set(obj, "nil", json_null());
    json_value_t *arr = json_arr();
    json_arr_append(arr, json_num(1));
    json_arr_append(arr, json_num(2));
    json_obj_set(obj, "a", arr);

    size_t cap = json_serialized_size(obj) + 1;
    char *buf = (char *)malloc(cap);
    CHECK(json_serialize(obj, buf, cap) == 0);

    json_value_t *j2 = json_parse(buf, strlen(buf), NULL);
    CHECK(j2 != NULL);
    CHECK(strcmp(json_obj_get(j2, "s")->u.s, "str") == 0);
    CHECK(json_obj_get(j2, "n")->u.n == 42.5);
    CHECK(json_obj_get(j2, "b")->u.b == 1);
    CHECK(json_obj_get(j2, "nil")->type == JSON_NULL);
    CHECK(json_obj_get(j2, "a")->u.arr.len == 2);
    json_free(j2);
    free(buf);
    json_free(obj);
}

static void test_json_invalid(void) {
    printf("[test_json_invalid]\n");
    CHECK(json_parse("", 0, NULL) == NULL);
    CHECK(json_parse("{", 1, NULL) == NULL);
    CHECK(json_parse("{,}", 3, NULL) == NULL);
    CHECK(json_parse("[1,]", 3, NULL) == NULL);
    CHECK(json_parse("{\"a\":}", 6, NULL) == NULL);
    CHECK(json_parse("\x01", 1, NULL) == NULL);
}

/* ============ HTTP 测试 ============ */
static void test_http_parse(void) {
    printf("[test_http_parse]\n");
    const char *raw =
        "GET /api/v1/agents HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Length: 5\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "hello";
    http_req_t req;
    memset(&req, 0, sizeof(req));
    int rc = http_parse_req(&req, raw, strlen(raw));
    CHECK(rc == 1);
    CHECK(req.method == HTTP_GET);
    CHECK(strcmp(req.uri, "/api/v1/agents") == 0);
    CHECK(req.content_length == 5);
    CHECK(req.keep_alive == 1);
    CHECK(strcmp(http_get_header(&req, "Host"), "example.com") == 0);
    CHECK(strcmp(req.body, "hello") == 0);
    CHECK(req.body_len == 5);
    http_req_reset(&req);
}

static void test_http_post(void) {
    printf("[test_http_post]\n");
    const char *raw =
        "POST /api/v1/cmd HTTP/1.1\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        "{\"x\":1,\"y\":2}";
    http_req_t req;
    memset(&req, 0, sizeof(req));
    int rc = http_parse_req(&req, raw, strlen(raw));
    CHECK(rc == 1);
    CHECK(req.method == HTTP_POST);
    CHECK(strcmp(req.uri, "/api/v1/cmd") == 0);
    /* POST body 应能直接 json_parse */
    json_value_t *j = json_parse(req.body, req.body_len, NULL);
    CHECK(j != NULL && j->type == JSON_OBJ);
    CHECK(json_obj_get(j, "x")->u.n == 1.0);
    CHECK(json_obj_get(j, "y")->u.n == 2.0);
    json_free(j);
    http_req_reset(&req);
}

static void test_http_partial(void) {
    printf("[test_http_partial]\n");
    const char *raw = "GET /api HTTP/1.1\r\nHost: x\r\n";
    http_req_t req;
    memset(&req, 0, sizeof(req));
    int rc = http_parse_req(&req, raw, strlen(raw));
    CHECK(rc == 0);   /* 需要更多数据 */
    http_req_reset(&req);
}

/* ============ 路由测试 ============ */
static handle_result_t h_agents(ui_ctx_t *ctx, http_req_t *req,
                               const char **params, int param_count,
                               char *out, size_t out_cap) {
    (void)ctx; (void)req; (void)params; (void)param_count; (void)out_cap;
    json_value_t *j = json_obj();
    json_obj_set(j, "agents", json_str("list"));
    json_serialize(j, out, out_cap);
    json_free(j);
    return HANDLE_OK;
}

static handle_result_t h_agent_id(ui_ctx_t *ctx, http_req_t *req,
                                  const char **params, int param_count,
                                  char *out, size_t out_cap) {
    (void)ctx; (void)req; (void)out_cap;
    if (param_count < 1) return HANDLE_BAD_REQUEST;
    json_value_t *j = json_obj();
    json_obj_set(j, "id", json_str(params[0]));
    json_serialize(j, out, out_cap);
    return HANDLE_OK;
}

static const route_t routes[] = {
    { HTTP_GET,    "/api/v1/agents",     h_agents },
    { HTTP_GET,    "/api/v1/agents/:id", h_agent_id },
};
static const int route_count = sizeof(routes) / sizeof(routes[0]);

static void test_route_match(void) {
    printf("[test_route_match]\n");
    const char *p[4];
    int n = route_match("/api/v1/agents/:id", "/api/v1/agents/abc123", p, 4);
    CHECK(n == 1);
    if (n >= 1) { CHECK(strcmp(p[0], "abc123") == 0); free((void *)p[0]); }
}

static void test_ui_dispatch(void) {
    printf("[test_ui_dispatch]\n");
    ui_ctx_t ctx;
    uint8_t secret[32] = {0};
    for (int i = 0; i < 32; i++) secret[i] = (uint8_t)i;
    ui_ctx_init(&ctx, secret, 32, (const uint8_t *)"dayanjing", 10, 3600);
    ctx.routes = routes;
    ctx.route_count = route_count;

    const char *raw = "GET /api/v1/agents/xyz HTTP/1.1\r\n\r\n";
    http_req_t req;
    memset(&req, 0, sizeof(req));
    http_parse_req(&req, raw, strlen(raw));

    char out[4096];
    int status = 0;
    handle_result_t r = ui_handle(&ctx, &req, out, sizeof(out), &status);
    CHECK(r == HANDLE_OK);
    CHECK(status == 200);
    json_value_t *j = json_parse(out, strlen(out), NULL);
    CHECK(j != NULL);
    CHECK(strcmp(json_obj_get(j, "id")->u.s, "xyz") == 0);
    json_free(j);
    http_req_reset(&req);
}

static void test_ui_404(void) {
    printf("[test_ui_404]\n");
    ui_ctx_t ctx;
    uint8_t secret[32] = {1,2,3};
    ui_ctx_init(&ctx, secret, 3, (const uint8_t *)"d", 1, 3600);
    ctx.routes = routes;
    ctx.route_count = route_count;

    const char *raw = "GET /api/v1/nope HTTP/1.1\r\n\r\n";
    http_req_t req;
    memset(&req, 0, sizeof(req));
    http_parse_req(&req, raw, strlen(raw));
    char out[4096];
    int status = 0;
    handle_result_t r = ui_handle(&ctx, &req, out, sizeof(out), &status);
    CHECK(r == HANDLE_NOT_FOUND);
    CHECK(status == 404);
    http_req_reset(&req);
}

/* ============ Token 测试 ============ */
static void test_token(void) {
    printf("[test_token]\n");
    token_signer_t ts;
    uint8_t secret[32];
    for (int i = 0; i < 32; i++) secret[i] = (uint8_t)(i + 7);
    token_signer_init(&ts, secret, 32, (const uint8_t *)"issuer-1", 8, 60);

    char tok[TOKEN_B64_LEN];
    CHECK(token_issue(&ts, "agent-001", tok, sizeof(tok)) == 0);
    CHECK(strlen(tok) > 0);

    char subj[128] = {0};
    CHECK(token_verify(&ts, tok, strlen(tok), subj, sizeof(subj)) == 1);
    CHECK(strcmp(subj, "agent-001") == 0);

    /* 篡改 token 应校验失败 */
    tok[5] ^= 0x01;
    char subj2[128] = {0};
    CHECK(token_verify(&ts, tok, strlen(tok), subj2, sizeof(subj2)) == 0);

    /* 错误 secret */
    token_signer_t ts2;
    uint8_t secret2[32];
    memset(secret2, 0xFF, 32);
    token_signer_init(&ts2, secret2, 32, (const uint8_t *)"issuer-1", 8, 60);
    char tok2[TOKEN_B64_LEN];
    CHECK(token_issue(&ts2, "agent-002", tok2, sizeof(tok2)) == 0);
    char subj3[128] = {0};
    CHECK(token_verify(&ts, tok2, strlen(tok2), subj3, sizeof(subj3)) == 0);
}

static void test_token_auth_header(void) {
    printf("[test_token_auth_header]\n");
    token_signer_t ts;
    uint8_t secret[32] = {9,9,9};
    token_signer_init(&ts, secret, 3, (const uint8_t *)"i", 1, 60);
    char tok[TOKEN_B64_LEN];
    token_issue(&ts, "root", tok, sizeof(tok));

    char raw[256];
    snprintf(raw, sizeof(raw),
             "GET /api/v1/agents HTTP/1.1\r\n"
             "Authorization: Bearer %s\r\n"
             "\r\n", tok);
    http_req_t req;
    memset(&req, 0, sizeof(req));
    http_parse_req(&req, raw, strlen(raw));

    char subj[128] = {0};
    CHECK(token_authenticate(&ts, &req, subj, sizeof(subj)) == 1);
    CHECK(strcmp(subj, "root") == 0);

    /* 无 Authorization 头 */
    const char *raw2 = "GET /api/v1/agents HTTP/1.1\r\n\r\n";
    http_req_t req2;
    memset(&req2, 0, sizeof(req2));
    http_parse_req(&req2, raw2, strlen(raw2));
    char subj2[128] = {0};
    CHECK(token_authenticate(&ts, &req2, subj2, sizeof(subj2)) == 0);

    http_req_reset(&req);
    http_req_reset(&req2);
}

int main(void) {
    test_json_basic();
    test_json_array();
    test_json_escape();
    test_json_serialize_roundtrip();
    test_json_invalid();
    test_http_parse();
    test_http_post();
    test_http_partial();
    test_route_match();
    test_ui_dispatch();
    test_ui_404();
    test_token();
    test_token_auth_header();

    if (g_fail == 0) {
        printf("\n*** ALL TESTS PASSED ***\n");
        return 0;
    } else {
        printf("\n*** %d TEST(S) FAILED ***\n", g_fail);
        return 1;
    }
}
