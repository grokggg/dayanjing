#ifndef AGENT_H
#define AGENT_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    char hostname[64];
    char os[160];
    char user[64];
    int  pid;
} agent_info_t;

/* 采集本机信息；成功返回 0 */
int agent_collect(agent_info_t *info);

/*
 * 执行命令并捕获 stdout。
 * 返回: >=0 子进程退出码；-1 超时；-2 参数错误/内部错误；-3 被信号杀死
 * out/outlen: 输出缓冲与长度（不含结尾 NUL，函数会补 NUL）
 *
 * timeout_ms 必须为正数。0 或负数直接返回 -2 —— 宁可拒绝执行，也不
 * 接受"永不超时"这种会永久挂死 agent 的语义。
 *
 * 超时是**总时限**（poll 毫秒精度），不因命令持续吐输出而续期。
 * 输出超过 cap 时截断，但管道继续排空，不会因写满 64KiB 而死锁。
 *
 * 子进程 stdin 指向 /dev/null，且关闭所有继承 fd —— 命令既不会读
 * agent 的 stdin 卡住，也不会持有 agent 的 socket / 管道。
 */
int agent_exec(const char *cmd, char *out, size_t cap, size_t *outlen, int timeout_ms);


/* ---- 任务循环（完整能力） ---- */
#define AGENT_CMD_MAX   256
#define AGENT_OUT_MAX   1024
#define AGENT_QUEUE_MAX 16

typedef struct { int seq; char cmd[AGENT_CMD_MAX]; } agent_task_t;
typedef struct { int seq; int exitcode; char out[AGENT_OUT_MAX]; } agent_result_t;

/* 任务队列：入队 / 出队 / 待处理数 / 清空 */
int    agent_task_push(const char *cmd);
int    agent_task_pop(agent_task_t *t);
size_t agent_task_pending(void);
void   agent_task_reset(void);

/* 取一个待处理任务执行并产出结果。无任务返回 1，成功 0 */
int    agent_run_once(agent_result_t *r, int timeout_ms);

/* 结果序列化/反序列化（seq u32 LE + exit i32 LE + outlen u16 LE + out） */
size_t agent_result_serialize(const agent_result_t *r, uint8_t *out, size_t cap);
int    agent_result_deserialize(const uint8_t *in, size_t len, agent_result_t *r);

/* 守护化：fork + setsid + 重定向 stdio 到 /dev/null。
 * 父进程成功返回子进程 pid(>0)，子进程内返回 0；失败 -1 */
int    agent_daemonize(void);

#endif
