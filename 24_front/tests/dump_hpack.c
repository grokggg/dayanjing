/* dump_hpack.c — 把 C 侧 HPACK 编码结果以 hex 输出，供 Python 侧独立实现解码
 *
 * 为什么需要它：自编自解会掩盖双方同步出错。用第三方独立实现（python-hpack）
 * 解码我们产出的字节，才能证明编码是符合 RFC 7541 的，而不只是"我们自己对得上"。
 */
#include "h2.h"
#include <stdio.h>
#include <string.h>

static void emit(const char *method, const char *scheme,
                 const char *path, const char *authority) {
    uint8_t buf[512];
    size_t n = 0;
    if (h2_hpack_request(method, scheme, path, authority, buf, sizeof(buf), &n) != H2_OK) {
        fprintf(stderr, "encode failed\n");
        return;
    }
    for (size_t i = 0; i < n; i++) printf("%02x", buf[i]);
    printf("\t%s\t%s\t%s\t%s\n", method, scheme, path, authority);
}

int main(void) {
    /* 格式：hex<TAB>method<TAB>scheme<TAB>path<TAB>authority */
    emit("GET",  "https", "/api/v1/x9f2", "real.c2.example");
    emit("POST", "https", "/api/v1/submit", "c2.internal.example");
    emit("GET",  "http",  "/", "localhost");
    emit("GET",  "https", "/a/very/long/path/with/many/segments/0123456789abcdef",
         "another.real.host.example");
    emit("PUT",  "https", "/api/v1/put", "real.c2.example");
    return 0;
}
