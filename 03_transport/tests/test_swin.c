#include "tx_swin.h"
#include <stdio.h>
#include <string.h>

static int pass = 0, fail = 0;
#define CK(c, name) do { if (c) { printf("[PASS] %s\n", name); pass++; } \
    else { printf("[FAIL] %s\n", name); fail++; } } while (0)

int main(void) {
    tx_swin_tx_t w;
    uint32_t seq;

    /* 1 发送窗口基本推进 */
    tx_swin_tx_init(&w, 4, 5);
    CK(tx_swin_tx_next(&w, &seq) == 0 && seq == 0, "tx: 首片序号0");
    CK(tx_swin_tx_next(&w, &seq) == 0 && seq == 1, "tx: 次片序号1");
    CK(tx_swin_tx_next(&w, &seq) == 0 && seq == 2, "tx: 三片序号2");
    CK(tx_swin_tx_next(&w, &seq) == 0 && seq == 3, "tx: 四片序号3(窗口满)");
    CK(tx_swin_tx_next(&w, &seq) == TX_SWIN_DONE, "tx: 窗口满后不可再发");

    /* 2 ACK 推进窗口后可续发 */
    CK(tx_swin_tx_ack(&w, 2) == 0, "tx: ack=2 推进");
    CK(tx_swin_tx_next(&w, &seq) == 0 && seq == 4, "tx: 推进后可发序号4");
    CK(tx_swin_tx_next(&w, &seq) == TX_SWIN_DONE, "tx: 全发完后 DONE");
    CK(tx_swin_tx_done(&w) == 0, "tx: 未全确认不算完成");
    CK(tx_swin_tx_ack(&w, 5) == 0, "tx: ack=5 全部确认");
    CK(tx_swin_tx_done(&w) == 1, "tx: 全部确认后 done");

    /* 3 非法 ACK 被拒 */
    tx_swin_tx_init(&w, 4, 5);
    tx_swin_tx_next(&w, &seq); tx_swin_tx_next(&w, &seq);
    CK(tx_swin_tx_ack(&w, 9) == TX_SWIN_ERR_RANGE, "tx: ack 超 total 被拒");
    CK(tx_swin_tx_ack(&w, 3) == 0, "tx: ack 超 next 被夹到 next");
    CK(w.base == 2, "tx: 夹取后 base==next==2");
    CK(tx_swin_tx_ack(&w, 1) == TX_SWIN_ERR_RANGE, "tx: 回退 ack 被拒");

    /* 4 重扫区间 */
    tx_swin_tx_init(&w, 8, 10);
    for (int i = 0; i < 5; i++) tx_swin_tx_next(&w, &seq);
    uint32_t from, cnt;
    CK(tx_swin_tx_pending(&w, &from, &cnt) == 0 && from == 0 && cnt == 5,
       "tx: 未确认区间 [0,5)");
    CK(tx_swin_tx_ack(&w, 3) == 0, "tx: ack=3");
    CK(tx_swin_tx_pending(&w, &from, &cnt) == 0 && from == 3 && cnt == 2,
       "tx: 推进后区间 [3,5)");

    /* 5 窗口容量为 1 时退化为停等 */
    tx_swin_tx_init(&w, 1, 3);
    CK(tx_swin_tx_next(&w, &seq) == 0 && seq == 0, "tx: size=1 首片");
    CK(tx_swin_tx_next(&w, &seq) == TX_SWIN_DONE, "tx: size=1 必须等 ACK");
    CK(tx_swin_tx_ack(&w, 1) == 0, "tx: size=1 ack");
    CK(tx_swin_tx_next(&w, &seq) == 0 && seq == 1, "tx: size=1 续发");

    /* 6 接收窗口按序交付 */
    tx_swin_rx_t r;
    tx_swin_rx_init(&r, 8);
    uint8_t out[4096]; size_t olen = 0;
    CK(tx_swin_rx_put(&r, 1, 0, (const uint8_t *)"BB", 2) == 0, "rx: 乱序片1入槽");
    CK(tx_swin_rx_drain(&r, out, sizeof out, &olen) == 0 && olen == 0,
       "rx: 缺片0时不交付");
    CK(tx_swin_rx_put(&r, 0, 0, (const uint8_t *)"AA", 2) == 0, "rx: 补片0");
    CK(tx_swin_rx_drain(&r, out, sizeof out, &olen) == 0 && olen == 4
       && memcmp(out, "AABB", 4) == 0, "rx: 补齐后按序交付AABB");

    /* 7 FIN 终结 */
    CK(tx_swin_rx_put(&r, 2, 1, NULL, 0) == 0, "rx: FIN 片");
    CK(tx_swin_rx_drain(&r, out, sizeof out, &olen) == TX_SWIN_DONE,
       "rx: FIN 后 drain 返回 DONE");
    CK(tx_swin_rx_done(&r) == 1, "rx: done");

    /* 8 窗口外与重复片 */
    tx_swin_rx_init(&r, 4);
    CK(tx_swin_rx_put(&r, 9, 0, (const uint8_t *)"x", 1) == TX_SWIN_ERR_RANGE,
       "rx: 超前片超出窗口被拒");
    CK(tx_swin_rx_put(&r, 0, 0, (const uint8_t *)"AA", 2) == 0, "rx: 片0");
    CK(tx_swin_rx_put(&r, 0, 0, (const uint8_t *)"ZZ", 2) == 0, "rx: 重复片不报错");
    tx_swin_rx_drain(&r, out, sizeof out, &olen);
    CK(memcmp(out, "AA", 2) == 0, "rx: 重复片不覆盖已收内容");
    CK(tx_swin_rx_put(&r, 0, 0, (const uint8_t *)"y", 1) == 0, "rx: 已交付序号静默丢弃");

    /* 9 输出缓冲不足 */
    tx_swin_rx_init(&r, 4);
    tx_swin_rx_put(&r, 0, 0, (const uint8_t *)"AAAA", 4);
    tx_swin_rx_put(&r, 1, 0, (const uint8_t *)"BBBB", 4);
    uint8_t small[4];
    CK(tx_swin_rx_drain(&r, small, sizeof small, &olen) == TX_SWIN_ERR_NOSPACE,
       "rx: 输出缓冲不足返回 NOSPACE");

    /* 10 超大片 */
    tx_swin_rx_init(&r, 4);
    uint8_t big[TX_SWIN_CHUNK + 1];
    memset(big, 0x41, sizeof big);
    CK(tx_swin_rx_put(&r, 0, 0, big, sizeof big) == TX_SWIN_ERR_TOOBIG,
       "rx: 超 CHUNK 被拒");

    /* 11 多片重组大块数据 */
    tx_swin_rx_init(&r, 8);
    uint8_t src[600], got[600];
    for (int i = 0; i < 600; i++) src[i] = (uint8_t)(i * 7 + 3);
    for (int i = 0; i < 3; i++)
        tx_swin_rx_put(&r, (uint32_t)i, 0, src + i * 200, 200);
    tx_swin_rx_put(&r, 3, 1, NULL, 0);
    size_t total = 0;
    int rc;
    while ((rc = tx_swin_rx_drain(&r, got + total, sizeof got - total, &olen)) == 0
           || rc == TX_SWIN_DONE) {
        total += olen;
        if (rc == TX_SWIN_DONE) break;
    }
    CK(total == 600 && memcmp(got, src, 600) == 0, "rx: 3片+FIN 重组600字节一致");

    printf("\n---- swin: pass=%d fail=%d ----\n", pass, fail);
    return fail ? 1 : 0;
}
