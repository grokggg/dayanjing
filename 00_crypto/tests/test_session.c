#include "crypto.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

int main(void) {
    printf("[*] 会话封装（自动 nonce 管理）测试\n");

    /* ---- 未初始化就使用应报错 ---- */
    {
        struct crypto_session s;
        memset(&s, 0, sizeof(s));
        uint8_t ct[64];
        size_t o = 0;
        crypto_err_t rc = crypto_session_seal(&s, ct, &o,
                                            (const uint8_t *)"x", 1, NULL, 0);
        assert(rc == CRYPTO_ERR);
        printf("  [+] 未初始化会话 seal 返回 ERR\n");
    }

    /* ---- 空密钥应报错 ---- */
    {
        struct crypto_session s;
        crypto_err_t rc = crypto_session_init(&s, NULL);
        assert(rc == CRYPTO_ERR);
        printf("  [+] NULL 密钥 init 返回 ERR\n");
    }

    /* ---- 多次 seal 的 nonce 必须单调递增 ---- */
    {
        uint8_t key[32];
        crypto_rng(key, 32);
        struct crypto_session s;
        crypto_err_t rc = crypto_session_init(&s, key);
        assert(rc == CRYPTO_OK);

        uint8_t ct[16];
        size_t o = 0;
        rc = crypto_session_seal(&s, ct, &o,
                                (const uint8_t *)"msg1", 4, NULL, 0);
        assert(rc == CRYPTO_OK);
        assert(s.counter == 1);
        rc = crypto_session_seal(&s, ct, &o,
                                (const uint8_t *)"msg2", 4, NULL, 0);
        assert(rc == CRYPTO_OK);
        assert(s.counter == 2);
        printf("  [+] 每次 seal 后 counter 递增 (1->2)\n");
    }

    /* ---- seal / open 配对，按顺序往返 ---- */
    {
        uint8_t key[32];
        crypto_rng(key, 32);
        struct crypto_session alice, bob;
        crypto_session_init(&alice, key);
        crypto_session_init(&bob, key);

        const char *messages[] = {"hello", "world", "this is a test", ""};
        for (int i = 0; i < 4; i++) {
            size_t mlen = strlen(messages[i]);
            uint8_t ct[256];
            size_t o = 0;
            crypto_err_t rc = crypto_session_seal(&alice, ct, &o,
                                                (const uint8_t *)messages[i],
                                                mlen, NULL, 0);
            assert(rc == CRYPTO_OK);
            uint8_t pt[256];
            size_t p = 0;
            rc = crypto_session_open(&bob, pt, &p, ct, o, NULL, 0);
            assert(rc == CRYPTO_OK);
            assert(p == mlen);
            assert(memcmp(pt, messages[i], mlen) == 0);
            assert(alice.counter == bob.counter);
        }
        printf("  [+] 4 轮 seal/open 配对成功，双方 counter 同步\n");
    }

    /* ---- 乱序：bob 跳过一条消息再收下一条 -> 失败 ---- */
    {
        uint8_t key[32];
        crypto_rng(key, 32);
        struct crypto_session alice, bob;
        crypto_session_init(&alice, key);
        crypto_session_init(&bob, key);

        uint8_t ct1[64], ct2[64];
        size_t o1 = 0, o2 = 0;
        crypto_session_seal(&alice, ct1, &o1, (const uint8_t *)"m1", 2, NULL, 0);
        crypto_session_seal(&alice, ct2, &o2, (const uint8_t *)"m2", 2, NULL, 0);

        uint8_t pt[64];
        size_t p = 0;
        /* bob 先收 ct2（counter 已为 2），期望的是 counter=1 */
        crypto_err_t rc = crypto_session_open(&bob, pt, &p, ct2, o2, NULL, 0);
        assert(rc == CRYPTO_TAG_MISMATCH);
        printf("  [+] 乱序消息 -> TAG_MISMATCH（反重放）\n");
    }

    /* ---- 重复使用同一 counter 会被检测（手动构造 nonce 重用）---- */
    {
        uint8_t key[32], n[12];
        crypto_rng(key, 32); crypto_rng(n, 12);
        uint8_t ct1[64], ct2[64];
        size_t o1 = 0, o2 = 0;
        crypto_aead_seal(ct1, &o1, (const uint8_t *)"aaaa", 4, NULL, 0, key, n);
        crypto_aead_seal(ct2, &o2, (const uint8_t *)"bbbb", 4, NULL, 0, key, n);
        /* 用同一个 nonce 解密两条不同的密文 —— 密钥流重用，XOR 可恢复明文。
         * 这里仅验证接口不崩溃。 */
        uint8_t p1[64], p2[64];
        size_t lp1 = 0, lp2 = 0;
        crypto_aead_open(p1, &lp1, ct1, o1, NULL, 0, key, n);
        crypto_aead_open(p2, &lp2, ct2, o2, NULL, 0, key, n);
        /* 两条密文各自认证通过（因为 tag 各自正确），但同一 nonce
         * 不应被协议层允许。这里仅确认实现不崩溃。 */
        printf("  [+] nonce 重用：两条密文各自可解（协议层需避免）\n");
    }

    printf("\n[+] 会话封装测试全部通过\n");
    return 0;
}
