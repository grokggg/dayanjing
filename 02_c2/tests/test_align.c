/* 02_c2 与 13_c2_server（Python）的双向协议对齐测试。
 *
 * 1) 用与 Python 完全相同的固定输入派生会话密钥，逐字节比对落盘密钥文件
 *    —— 验证密钥派生链对齐
 * 2) 解开 Python 密封的帧（/tmp/py_seal.bin），校验 payload == b"ALIGN"
 *    —— 验证 Python -> C 方向
 * 3) 用 k_s2c 密封响应帧写入 /tmp/c_seal.bin，供 Python 侧 verify
 *    —— 验证 C -> Python 方向
 */
#include "c2.h"
#include "c2_frame.h"
#include "crypto_hash.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int fails = 0, total = 0;
static void ck(const char *name, int cond) {
    total++;
    if (!cond) { fails++; printf("  FAIL: %s\n", name); } else printf("  ok  : %s\n", name);
}

static uint8_t PSK[32];
static uint8_t SALT_REG[32];
static uint8_t SERVER_ID[16];
static const char   *IMPLANT_ID   = "implant-align-001";

static uint8_t *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) { fclose(f); return NULL; }
    uint8_t *b = malloc((size_t)n);
    if (!b) { fclose(f); return NULL; }
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); fclose(f); return NULL; }
    fclose(f);
    *len = (size_t)n;
    return b;
}

int main(void) {
    printf("=== 02_c2 <-> 13_c2_server 协议对齐测试 ===\n");

    /* 夹具由 13_c2_server/tools/align_proto.py seal 生成。缺夹具时不能静默通过：
     * 那会让"从未真正比对过两端"看起来像"比对一致"。返回 77 = 环境不具备，
     * 回归记为 SKIP（既不冒认通过，也不算代码缺陷）。真正的执行入口是
     * scripts/run_c2_align.sh，它保证夹具先被生成。 */
    {
        FILE *probe = fopen("/tmp/py_seal.bin", "rb");
        if (!probe) {
            printf("[SKIP] 缺少夹具 /tmp/py_seal.bin；"
                   "请先运行 13_c2_server/tools/align_proto.py seal"
                   "（或 scripts/run_c2_align.sh）\n");
            return 77;
        }
        fclose(probe);
    }

    memset(PSK, 0x0b, sizeof PSK);
    memset(SALT_REG, 0x01, sizeof SALT_REG);
    memset(SERVER_ID, 0x02, sizeof SERVER_ID);

    /* 1) 密钥派生对齐 */
    c2_keymat_t km;
    if (c2_derive_pair(PSK, sizeof PSK, SALT_REG, &km) != C2_OK) {
        printf("  FAIL: c2_derive_pair\n"); return 1;
    }
    uint8_t transcript[32];
    /* 与 Python 侧 SHA256(b"align-transcript") 一致：此处用相同常量避免依赖 sha256 导出 */
    sha256((const uint8_t *)"align-transcript", strlen("align-transcript"), transcript);

    c2_session_keys_t sk;
    if (c2_derive_session(km.k_server_hold, transcript, SERVER_ID, IMPLANT_ID, 1, &sk) != C2_OK) {
        printf("  FAIL: c2_derive_session\n"); return 1;
    }
    size_t kl = 0;
    uint8_t *py_c2s = slurp("/tmp/align_key_c2s.bin", &kl);
    uint8_t *py_s2c = slurp("/tmp/align_key_s2c.bin", &kl);
    ck("python key files loaded", py_c2s != NULL && py_s2c != NULL);
    if (py_c2s && py_s2c) {
        ck("k_c2s matches python", memcmp(py_c2s, sk.k_c2s, 16) == 0);
        ck("k_s2c matches python", memcmp(py_s2c, sk.k_s2c, 16) == 0);
        ck("k_c2s != k_s2c", memcmp(sk.k_c2s, sk.k_s2c, 16) != 0);
    }

    /* 2) Python -> C */
    size_t wl = 0;
    uint8_t *wire = slurp("/tmp/py_seal.bin", &wl);
    ck("py_seal.bin loaded", wire != NULL);
    if (wire) {
        uint64_t seq = 0; uint32_t mt = 0;
        uint8_t pl[256]; size_t plen = sizeof pl;
        int rc = c2_frame_open(sk.k_c2s, wire, wl, &seq, &mt, pl, sizeof pl, &plen);
        ck("c2_frame_open(py) rc==OK", rc == C2_FRAME_OK);
        if (rc == C2_FRAME_OK) {
            ck("py->C seq == 1", seq == 1);
            ck("py->C msg_type == 0x21", mt == 0x21);
            ck("py->C payload == ALIGN", plen == 5 && memcmp(pl, "ALIGN", 5) == 0);
        }
        free(wire);
    }

    /* 3) C -> Python */
    const uint8_t rsp[9] = "ALIGN_RSP";
    size_t need = 0;
    if (c2_frame_seal(sk.k_s2c, (const uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00", 1,
                      2, 0x12, rsp, sizeof rsp, NULL, 0, &need) != C2_FRAME_OK) {
        printf("  FAIL: c2_frame_seal probe\n"); return 1;
    }
    uint8_t *out = malloc(need);
    size_t olen = 0;
    int rc = c2_frame_seal(sk.k_s2c, (const uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00", 1,
                           2, 0x12, rsp, sizeof rsp, out, need, &olen);
    ck("c2_frame_seal(rsp) rc==OK", rc == C2_FRAME_OK && olen == need);
    if (rc == C2_FRAME_OK) {
        FILE *f = fopen("/tmp/c_seal.bin", "wb");
        if (f) { fwrite(out, 1, olen, f); fclose(f); }
        ck("c_seal.bin written", f != NULL);
    }
    free(out);
    free(py_c2s); free(py_s2c);

    printf("--- total=%d pass=%d fail=%d ---\n", total, total - fails, fails);
    return fails ? 1 : 0;
}
