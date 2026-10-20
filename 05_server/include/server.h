#ifndef SERVER_H
#define SERVER_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "session.h"

typedef enum {
    SRV_EV_NONE = 0,
    SRV_EV_ACCEPT,   /* 新连接，已登记会话 */
    SRV_EV_DATA,     /* 有数据可读，调用方应 recv */
    SRV_EV_CLOSE     /* 对端关闭，会话已移除 */
} srv_ev_t;

typedef struct {
    srv_ev_t type;
    int      fd;
    uint8_t  id[SESSION_ID_LEN];
} srv_event_t;

typedef struct srv srv_t;

/* 创建监听 + epoll 实例。port=0 由内核分配并回填。成功返回句柄 */
srv_t *srv_create(int port, int *out_port);
void   srv_destroy(srv_t *s);

int    srv_listen_fd(const srv_t *s);
size_t srv_session_count(const srv_t *s);
session_table_t *srv_sessions(srv_t *s);

/* 处理一批事件，最多填充 evcap 个。返回事件数，0=超时，-1=错误 */
int    srv_run_once(srv_t *s, int timeout_ms, srv_event_t *ev, size_t evcap);

/* 主动关闭并移除某会话 */
int    srv_close_session(srv_t *s, const uint8_t *id);
#endif
