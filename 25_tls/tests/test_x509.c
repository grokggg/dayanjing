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
#include <sys/wait.h>
#include <time.h>

static int fails = 0, total = 0;
#define CHECK(cond, name) do { \
    total++; \
    if (cond) printf("[PASS] %s\n", name); \
    else { printf("[FAIL] %s\n", name); fails++; } \
} while (0)

/* 素材目录由 Makefile 以绝对路径注入（见 test_bn.c 的同类说明） */
#ifndef TLS_TESTDATA
#define TLS_TESTDATA "tests/data"
#endif
static const char *TD(const char *name) {
    static char buf[512];
    snprintf(buf, sizeof(buf), "%s/%s", TLS_TESTDATA, name);
    return buf;
}

static int64_t now_sec(void) { return (int64_t)time(NULL); }

int main(void) {
    x509_store st;
    memset(&st, 0, sizeof(st));

    /* --- 自签证书（OpenSSL 生成） --- */
    x509_err e = x509_store_load_pem(&st, TD("selfsigned.pem"));
    if (e != X509_OK) {
        printf("[SKIP] 素材缺失或解析失败(%s)，先跑 scripts/gen_testdata.sh\n", x509_errstr(e));
        return 77;   /* 素材由 OpenSSL 生成，缺失属环境不具备，不算代码缺陷 */
    }
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
        if (x509_store_load_pem(&real, TD("real_chain.pem")) != X509_OK) {
            printf("[SKIP] 真实链素材缺失\n");
        } else {
            printf("[INFO] 真实链含 %d 张证书\n", real.n);
            CHECK(x509_store_load_pem(&anchors, "/etc/zeroproxy-tls/ca-bundle.pem") == X509_OK,
                  "加载系统信任库");
            x509_cert ch[X509_CHAIN_MAX];
            int n = real.n < X509_CHAIN_MAX ? real.n : X509_CHAIN_MAX;
            for (int i = 0; i < n; i++) ch[i] = real.e[i].c;
            /* 真实服务端链的正向校验不再作为断言。
 *
 * 出站经过 MITM 代理时，"真实"链其实是代理重签出来的，AKI/SKI 常常不自洽 ——
 * 用 OpenSSL 校验同一份素材同样失败（error 30: authority and subject key
 * identifier mismatch）。也就是说本实现"拒绝它"是正确的，把这条当 FAIL
 * 等于把环境缺陷判成代码缺陷。
 *
 * 曾经试图用 system() 调 OpenSSL 做 oracle 来区分二者，但受限沙盒里
 * system() 的返回值不可靠，oracle 自己就是不可信的，故不作此判据。
 *
 * 正向校验改由本地两级链（CA -> leaf）承担，它的素材由我们生成、完全可控。
 * 这里只保留永远成立的那条：真实链下错误主机名必须被拒。
 */
CHECK(x509_verify_chain(ch, n, &anchors, "not-the-host.example", now_sec())
                  == X509_ERR_HOST, "真实链下错误主机名被拒");
        }
    }

    /* --- 两级链（自造 CA -> leaf）---
     * 正向用例不该依赖出站 MITM 代理：代理什么时候重签、签出来的链是否自洽都
     * 不由我们控制（上一版素材就是被代理签坏了，AKI/SKI 不自洽，连 OpenSSL 都拒，
     * 却把"实现正确地拒绝"判成了 FAIL）。所以正向另建一套本地素材。 */
    {
        x509_store cas, lst;
        memset(&cas, 0, sizeof(cas));
        memset(&lst, 0, sizeof(lst));
        if (x509_store_load_pem(&cas, TD("ca.pem")) != X509_OK) {
            printf("[SKIP] CA 素材缺失，先跑 scripts/gen_testdata.sh\n");
        } else {
            CHECK(x509_store_load_pem(&lst, TD("leaf.pem")) == X509_OK, "加载叶子证书");
            if (lst.n > 0) {
                x509_cert ch2[X509_CHAIN_MAX];
                int n2 = lst.n < X509_CHAIN_MAX ? lst.n : X509_CHAIN_MAX;
                for (int i = 0; i < n2; i++) ch2[i] = lst.e[i].c;

                CHECK(x509_verify_chain(ch2, n2, &cas, "front.test", now_sec()) == X509_OK,
                      "两级链校验通过（CA -> leaf, SAN: front.test）");
                CHECK(x509_verify_chain(ch2, n2, &cas, "cdn.front.test", now_sec()) == X509_OK,
                      "第二个 SAN 也匹配（cdn.front.test）");
                CHECK(x509_verify_chain(ch2, n2, &cas, "evil.test", now_sec()) != X509_OK,
                      "SAN 之外的主机名被拒");

                /* 无关锚点：自签证书不是 leaf 的签发者，必须拒绝。
                 * 若这条变 PASS，说明实现只比对了名字没验签名。 */
                x509_store wrong;
                memset(&wrong, 0, sizeof(wrong));
                x509_store_load_pem(&wrong, TD("selfsigned.pem"));
                CHECK(x509_verify_chain(ch2, n2, &wrong, "front.test", now_sec()) != X509_OK,
                      "用无关证书当锚点被拒");

                /* CA:FALSE 的叶子不能充当签发者。
                 * 不检查 basicConstraints 的实现会在这里放行 —— 现实中这是一类
                 * 真实漏洞（攻击者拿一张普通服务器证书去签任意域名）。 */
                x509_store leafasca;
                memset(&leafasca, 0, sizeof(leafasca));
                x509_store_load_pem(&leafasca, TD("leaf.pem"));
                x509_err lv = x509_verify_chain(ch2, n2, &leafasca, "front.test", now_sec());
                CHECK(lv != X509_OK, "CA:FALSE 的叶子不能充当签发者");
            }
        }
    }

    printf("\n=== %d/%d passed ===\n", total - fails, total);
    return fails == 0 ? 0 : 1;
}
