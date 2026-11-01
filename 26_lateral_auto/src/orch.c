/* 26_lateral_auto/src/orch.c —— 批量编排 */
#include "lateral_auto.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

/*
 * 串行分批：每批不超过 max_parallel，批间 sleep(delay_ms)。
 *
 * 硬规则 6：并发与速率必须有上界。无上界的扫描会形成 SYN 风暴，
 * 触发 IDS/IPS —— 这是自暴露，不是效率问题。因此这里刻意不用线程/进程池
 * 全速并发，宁慢勿爆。
 *
 * 退避：第 k 次失败后 sleep(backoff_ms * 2^(k-1))，上限 8 倍基数，
 * 避免长尾目标把整批拖死。
 */
int lat_orch_run(const lat_orch_t *o, lat_result_t *results, size_t cap)
{
    int parallel, attempts, backoff, delay, timeout;
    int ok_count = 0;

    if (!o || !results || !o->hosts) return -1;
    if (o->nhosts == 0) return 0;
    if (cap < o->nhosts) return -1;

    parallel = o->max_parallel  > 0 ? o->max_parallel  : 4;
    attempts = o->max_attempts  > 0 ? o->max_attempts  : 2;
    backoff  = o->backoff_ms    > 0 ? o->backoff_ms    : 500;
    delay    = o->delay_ms      > 0 ? o->delay_ms      : 0;
    timeout  = o->timeout_ms    > 0 ? o->timeout_ms    : 30000;

    if (parallel > 64) parallel = 64;         /* 绝对上界 */

    memset(results, 0, sizeof(*results) * cap);

    for (size_t i = 0; i < o->nhosts; i++) {
        lat_ssh_opt_t opt;
        lat_result_t *r = &results[i];
        char out[LAT_OUT_MAX];
        int  done = 0;

        snprintf(r->host, sizeof(r->host), "%s", o->hosts[i]);
        snprintf(r->user, sizeof(r->user), "%s", o->user ? o->user : "root");
        r->rc = -1;

        memset(&opt, 0, sizeof(opt));
        opt.host = o->hosts[i];
        opt.port = 22;
        opt.user = o->user ? o->user : "root";
        opt.key_path = o->cred.path[0] ? o->cred.path : NULL;
        opt.connect_timeout_ms = timeout > 5000 ? 5000 : (timeout > 0 ? timeout : 5);
        opt.remote_cmd = o->cmd ? o->cmd : "true";

        for (int k = 0; k < attempts && !done; k++) {
            int rc = lat_ssh_exec(&opt,
                                  o->ssh_bin ? o->ssh_bin : "/usr/bin/ssh",
                                  out, sizeof(out), timeout);
            r->attempts++;
            r->rc = rc;
            if (rc == 0) { r->ok = 1; done = 1; break; }

            if (k + 1 < attempts) {
                int mult = 1 << k;
                struct timespec ts;
                if (mult > 8) mult = 8;
                ts.tv_sec  = (long)(backoff * mult) / 1000;
                ts.tv_nsec = (long)((backoff * mult) % 1000) * 1000000L;
                nanosleep(&ts, NULL);
            }
        }

        if (r->ok) ok_count++;

        /* 速率限制：每批结束休眠 */
        if (delay > 0 && ((i + 1) % (size_t)parallel) == 0) {
            struct timespec ts;
            ts.tv_sec  = (long)delay / 1000;
            ts.tv_nsec = (long)(delay % 1000) * 1000000L;
            nanosleep(&ts, NULL);
        }
    }

    return ok_count;
}
