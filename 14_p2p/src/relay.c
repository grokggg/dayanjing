#include "p2p.h"
#include "lateral.h"

/*
 * 数据面：字节级双工转发完全委托 08_lateral 的 lat_proxy_relay（poll 实现）。
 * 本模块不重复实现事件循环——两套事件循环抢同一个 fd 是真实 bug 来源。
 */
int p2p_relay(int cfd, int tfd, int idle_ms) {
    if (cfd < 0 || tfd < 0) return P2P_ERR_ARGS;
    return lat_proxy_relay(cfd, tfd, idle_ms) == 0 ? P2P_OK : P2P_ERR_NOLINK;
}
