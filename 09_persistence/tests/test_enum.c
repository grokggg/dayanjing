#include "persist.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
static int pass=0,fail=0;
#define CK(c,m) do{ if(c){pass++;printf("[PASS] %s\n",m);} else{fail++;printf("[FAIL] %s\n",m);} }while(0)
static int g_hits; static persist_method_t g_last;
static void cb(persist_method_t m,const char*fn,const char*p,void*ud){
    (void)fn;(void)p;(void)ud; g_hits++; g_last=m; }
int main(void){
    printf("=== 09_persistence 枚举测试 ===\n");
    const char *root="/tmp/t_persist_enum";
    rmdir("/tmp/t_persist_enum");
    CK(persist_enumerate(root,cb,NULL)==0, "空假根枚举到 0 项(不崩溃)");
    CK(persist_enumerate(NULL,cb,NULL)==-1, "NULL 假根返回 -1");
    CK(persist_enumerate(root,NULL,NULL)==-1, "NULL 回调返回 -1");

    CK(persist_install(PERSIST_CRON,root,"/opt/a")==0, "安装 cron 成功");
    CK(persist_install(PERSIST_SSHKEY,root,"ssh-rsa AAA")==0, "安装 sshkey 成功");
    CK(persist_installed(root,PERSIST_CRON)==1, "cron 已安装");
    CK(persist_installed(root,PERSIST_SSHKEY)==1, "sshkey 已安装");
    CK(persist_installed(root,PERSIST_SYSTEMD)==0, "systemd 未安装");
    CK(persist_installed(root,PERSIST_LKM)==-1, "LKM 非文件型返回 -1");
    CK(persist_installed(NULL,PERSIST_CRON)==-1, "NULL 假根返回 -1");

    g_hits=0;
    int n=persist_enumerate(root,cb,NULL);
    CK(n==2, "枚举到 2 项");
    CK(g_hits==2, "回调被调用 2 次");
    CK(g_last==PERSIST_SSHKEY, "回调按方法序号升序(最后为 sshkey)");

    CK(persist_uninstall(PERSIST_CRON,root,"/opt/a")==0, "卸载 cron 成功");
    CK(persist_installed(root,PERSIST_CRON)==0, "卸载后 cron 不在位");
    g_hits=0;
    CK(persist_enumerate(root,cb,NULL)==1, "卸载后枚举只剩 1 项");
    rmdir("/tmp/t_persist_enum");
    printf("total=%d pass=%d fail=%d\n",pass+fail,pass,fail);
    return fail?1:0;
}
