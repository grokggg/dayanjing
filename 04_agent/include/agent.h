#ifndef AGENT_H
#define AGENT_H
#include <stddef.h>

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
 * 返回: >=0 子进程退出码；-1 超时；-2 内部错误；-3 被信号杀死
 * out/outlen: 输出缓冲与长度（不含结尾 NUL，函数会补 NUL）
 */
int agent_exec(const char *cmd, char *out, size_t cap, size_t *outlen, int timeout_ms);

#endif
