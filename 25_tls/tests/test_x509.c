/* test_x509.c — 证书解析 / 链校验 / 主机名匹配
 *
 * 重点不是"能解析"，而是"该拒绝的必须拒绝"：
 *   主机名不符、有效期外、签名被篡改、找不到签发者 —— 四者都必须报错。
 * 只测"能通过"的测试等于没测：一个恒返回 OK 的实现也能全绿。
 */
#include "x509.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static int fails = 0, total = 0;
#define CHECK(cond, name) do { \
    total++; \
    if (cond) printf("[PASS] %s\n", name); \
    else { printf("[FAIL] %s\n", name); fails++; } \
} while (0)

static int64_t now_sec(void) { return (int64_t)time(NULL); }

int main(void) {
    x509_store st;
    memset(&st, 0, sizeof(st));

    /* --- 自签证书（OpenSSL 生成） --- */
    x509_err e = x509_store_load_pem(&st, "tests/data/selfsigned.pem");
    if (e != X509_OK) printf("[INFO] load_pem 失败: %s\n", x509_errstr(e));
    CHECK(e == X509_OK, "加载 OpenSSL 自签证书");
    if (e != X509_OK) { printf("=== %d/%d passed ===\n", total - fails, total); return 1; }

    x509_cert leaf = st.e[0].c;
    CHECK(leaf.has_rsa == 1, "解析出 RSA 公钥");
    CHECK(bn_bitlen(&leaf.n) == 2048, "模数长度 2048 位");
    CHECK(leaf.e == 65537, "公钥指数 65537");
    CHECK(leaf.sig_sha256_rsa == 1, "签名算法 sha256WithRSAEncryption");
    CHECK(strcmp(leaf.cn, "test.local") == 0, "CN 解析正确");
    CHECK(leaf.san_n == 1 && strcmp(leaf.san[0], "test.local") == 0, "SAN dNSName 解析正确");

    /* 用自己验自己（自签） */
    CHECK(x509_verify_signed_by(&leaf, &leaf) == X509_OK,
          "自签证书签名校验通过（与 OpenSSL 互操作）");

    /* 链校验：合格 */
    x509_cert chain[1] = { leaf };
    CHECK(x509_verify_chain(chain, 1, &st, "test.local", now_sec()) == X509_OK,
          "链校验通过（自签 + 主机名匹配）");

    /* 主机名不符 —— 必须拒 */
    CHECK(x509_verify_chain(chain, 1, &st, "evil.example", now_sec()) == X509_ERR_HOST,
          "主机名不符被拒");

    /* 有效期外 —— 必须拒 */
    CHECK(x509_verify_chain(chain, 1, &st, "test.local", 0) == X509_ERR_EXPIRED,
          "有效期外被拒（now=0）");

    /* 通配匹配 */
    CHECK(x509_host_match(&leaf, "TEST.local") == 1, "主机名匹配大小写不敏感");

    /* --- 篡改：改证书一个字节，签名必须失效 --- */
    {
        x509_store st2;
        memset(&st2, 0, sizeof(st2));
        uint8_t der[X509_DER_MAX];
        memcpy(der, st.e[0].der, st.e[0].der_len);
        size_t dl = st.e[0].der_len;
        /* 改 tbs 内部（偏移靠后，避免破坏结构导致 PARSE 而非 SIG） */
        der[dl / 2] ^= 0x40;
        x509_cert bad;
        x509_err pe = x509_parse(der, dl, &bad);
        if (pe == X509_OK) {
            x509_store_add_der(&st2, st.e[0].der, st.e[0].der_len);  /* 锚点是好的 */
            x509_cert c2[1] = { bad };
            x509_err ve = x509_verify_chain(c2, 1, &st2, "test.local", now_sec());
            CHECK(ve != X509_OK, "篡改后的证书被拒");
        } else {
            CHECK(1, "篡改后解析即失败（同样可接受）");
        }
    }

    /* --- 真实服务端证书链 --- */
    {
        x509_store real, anchors;
        memset(&real, 0, sizeof(real));
        memset(&anchors, 0, sizeof(anchors));
        if (x509_store_load_pem(&real, "tests/data/real_chain.pem") != X509_OK) {
            printf("[SKIP] 真实链素材缺失\n");
        } else {
            printf("[INFO] 真实链含 %d 张证书\n", real.n);
            CHECK(x509_store_load_pem(&anchors, "/etc/zeroproxy-tls/ca-bundle.pem") == X509_OK,
                  "加载系统信任库");
            x509_cert ch[X509_CHAIN_MAX];
            int n = real.n < X509_CHAIN_MAX ? real.n : X509_CHAIN_MAX;
            for (int i = 0; i < n; i++) ch[i] = real.e[i].c;
            x509_err ve = x509_verify_chain(ch, n, &anchors, "api.github.com", now_sec());
            CHECK(ve == X509_OK, "真实服务端链校验通过（SAN: api.github.com）");
            CHECK(x509_verify_chain(ch, n, &anchors, "not-the-host.example", now_sec())
                  == X509_ERR_HOST, "真实链下错误主机名被拒");
        }
    }

    printf("\n=== %d/%d passed ===\n", total - fails, total);
    return fails == 0 ? 0 : 1;
}
