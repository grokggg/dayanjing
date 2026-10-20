#define _DEFAULT_SOURCE
#include "agent.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

static agent_task_t g_q[AGENT_QUEUE_MAX];
static int g_head, g_tail, g_count, g_seq;

void agent_task_reset(void){ g_head = g_tail = g_count = 0; g_seq = 0; memset(g_q, 0, sizeof g_q); }

size_t agent_task_pending(void){ return (size_t)(g_count < 0 ? 0 : g_count); }

int agent_task_push(const char *cmd){
    if(!cmd || cmd[0] == 0) return -1;
    if(g_count >= AGENT_QUEUE_MAX) return -1;
    if(strlen(cmd) >= AGENT_CMD_MAX) return -1;
    snprintf(g_q[g_tail].cmd, AGENT_CMD_MAX, "%s", cmd);
    g_q[g_tail].seq = ++g_seq;
    g_tail = (g_tail + 1) % AGENT_QUEUE_MAX;
    g_count++;
    return g_q[(g_tail - 1 + AGENT_QUEUE_MAX) % AGENT_QUEUE_MAX].seq;
}

int agent_task_pop(agent_task_t *t){
    if(!t || g_count <= 0) return -1;
    *t = g_q[g_head];
    g_q[g_head].cmd[0] = 0;
    g_head = (g_head + 1) % AGENT_QUEUE_MAX;
    g_count--;
    return 0;
}

int agent_run_once(agent_result_t *r, int timeout_ms){
    agent_task_t t;
    if(agent_task_pop(&t) != 0) return 1;          /* 队列空 */
    if(!r) return -1;
    size_t olen = 0;
    r->seq = t.seq;
    r->exitcode = agent_exec(t.cmd, r->out, AGENT_OUT_MAX, &olen, timeout_ms);
    if(olen < AGENT_OUT_MAX) r->out[olen] = 0;
    return 0;
}

size_t agent_result_serialize(const agent_result_t *r, uint8_t *out, size_t cap){
    if(!r || !out || cap < 11) return 0;
    size_t ol = strnlen(r->out, AGENT_OUT_MAX);
    if(cap < 10 + ol) return 0;
    uint32_t seq = (uint32_t)r->seq;
    uint32_t ex  = (uint32_t)r->exitcode;
    out[0]=(uint8_t)(seq); out[1]=(uint8_t)(seq>>8); out[2]=(uint8_t)(seq>>16); out[3]=(uint8_t)(seq>>24);
    out[4]=(uint8_t)(ex);  out[5]=(uint8_t)(ex>>8);  out[6]=(uint8_t)(ex>>16);  out[7]=(uint8_t)(ex>>24);
    out[8]=(uint8_t)(ol & 0xFF); out[9]=(uint8_t)((ol >> 8) & 0xFF);
    if(ol) memcpy(out + 10, r->out, ol);
    return 10 + ol;
}

int agent_result_deserialize(const uint8_t *in, size_t len, agent_result_t *r){
    if(!in || !r || len < 10) return -1;
    uint32_t seq = (uint32_t)in[0] | ((uint32_t)in[1]<<8) | ((uint32_t)in[2]<<16) | ((uint32_t)in[3]<<24);
    uint32_t ex  = (uint32_t)in[4] | ((uint32_t)in[5]<<8) | ((uint32_t)in[6]<<16) | ((uint32_t)in[7]<<24);
    size_t ol = (size_t)in[8] | ((size_t)in[9] << 8);
    if(len < 10 + ol) return -1;
    if(ol >= AGENT_OUT_MAX) return -1;
    r->seq = (int)seq; r->exitcode = (int)ex;
    if(ol) memcpy(r->out, in + 10, ol);
    r->out[ol] = 0;
    return 0;
}

int agent_daemonize(void){
    pid_t pid = fork();
    if(pid < 0) return -1;
    if(pid > 0) return (int)pid;          /* 父进程：返回子进程 pid */
    if(setsid() < 0) _exit(1);
    int fd = open("/dev/null", O_RDWR);
    if(fd >= 0){
        dup2(fd, STDIN_FILENO); dup2(fd, STDOUT_FILENO); dup2(fd, STDERR_FILENO);
        if(fd > 2) close(fd);
    }
    return 0;                              /* 子进程内返回 0 */
}
