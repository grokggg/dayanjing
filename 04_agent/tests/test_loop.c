#include "agent.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static int pass=0,fail=0;
#define CK(c,m) do{ if(c){pass++;printf("[PASS] %s\n",m);} else{fail++;printf("[FAIL] %s\n",m);} }while(0)
int main(void){
    printf("=== 04_agent 任务循环测试 ===\n");
    agent_task_reset();
    CK(agent_task_pending()==0, "初始队列为空");
    agent_task_t t;
    CK(agent_task_pop(&t)==-1, "空队列 pop 返回 -1");

    int s1=agent_task_push("echo hello-agent");
    int s2=agent_task_push("printf ABC");
    CK(s1>0 && s2>0 && s1!=s2, "两个任务入队且 seq 递增不同");
    CK(agent_task_pending()==2, "待处理数为 2");

    agent_result_t r;
    CK(agent_run_once(&r,3000)==0, "run_once 执行第一个任务");
    CK(r.seq==s1, "结果 seq 与任务一致");
    CK(r.exitcode==0, "echo 退出码为 0");
    CK(strstr(r.out,"hello-agent")!=NULL, "捕获到 stdout 含 hello-agent");

    CK(agent_run_once(&r,3000)==0, "run_once 执行第二个任务");
    CK(r.seq==s2 && strcmp(r.out,"ABC")==0, "第二个任务输出为 ABC");

    CK(agent_task_pending()==0, "队列已排空");
    CK(agent_run_once(&r,3000)==1, "空队列 run_once 返回 1");

    /* 序列化往返 */
    agent_result_t src; src.seq=42; src.exitcode=-3;
    snprintf(src.out,sizeof src.out,"signal-killed");
    uint8_t buf[2048]; size_t n=agent_result_serialize(&src,buf,sizeof buf);
    CK(n==10+strlen("signal-killed"), "序列化长度为 10+out");
    agent_result_t dst;
    CK(agent_result_deserialize(buf,n,&dst)==0, "反序列化成功");
    CK(dst.seq==42 && dst.exitcode==-3 && strcmp(dst.out,"signal-killed")==0,
       "往返后字段完全一致(含负数退出码)");

    /* 负向 */
    uint8_t tiny[5]={0};
    CK(agent_result_deserialize(tiny,5,&dst)!=0, "过短输入被拒绝");
    buf[8]=0xFF; buf[9]=0xFF;
    CK(agent_result_deserialize(buf,n,&dst)!=0, "声明长度超出实际被拒绝");

    /* 边界：超长命令拒绝 */
    char big[AGENT_CMD_MAX+8]; memset(big,'a',sizeof big-1); big[sizeof big-1]=0;
    CK(agent_task_push(big)==-1, "超长命令入队被拒绝");
    CK(agent_task_push("")==-1, "空命令入队被拒绝");
    agent_task_reset();
    printf("total=%d pass=%d fail=%d\n",pass+fail,pass,fail);
    return fail?1:0;
}
