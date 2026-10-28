#define _DEFAULT_SOURCE   /* -std=c11 严格模式下 mkdtemp 不声明，需显式开启 */
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
    char root_tpl[] = "/tmp/t_persist_enum_XXXXXX";
    const char *root = mkdtemp(root_tpl);
    if(!root){ printf("[FAIL] mkdtemp 失败\n"); return 1; }
    CK(persist_enumerate(root,cb,NULL)==0, "空假根枚举到 0 项(不崩溃)");
    { int rn=persist_enumerate(NULL,cb,NULL); CK(rn>=0, "NULL 根(真实系统)可枚举不崩溃"); }
    CK(persist_enumerate(root,NULL,NULL)==-1, "NULL 回调返回 -1");

    CK(persist_install(PERSIST_CRON,root,"/opt/a")==0, "安装 cron 成功");
    CK(persist_install(PERSIST_SSHKEY,root,"ssh-rsa AAA")!=0, "未注入公钥时 sshkey 安装被拒");
    CK(persist_sshkey_pubkey("ssh-rsa AAAAB3NzaC1yc2EExampleBlobForEnumTest")==0, "注入测试公钥行");
    CK(persist_install(PERSIST_SSHKEY,root,"ssh-rsa AAA")==0, "安装 sshkey 成功");
    CK(persist_installed(root,PERSIST_CRON)==1, "cron 已安装");
    CK(persist_installed(root,PERSIST_SSHKEY)==1, "sshkey 已安装");
    CK(persist_installed(root,PERSIST_SYSTEMD)==0, "systemd 未安装");
    CK(persist_installed(root,PERSIST_LKM)==-1, "LKM 非文件型返回 -1");
    /* NULL 根 = 真实系统。这里只能断言"查询返回合法值"，不能断言具体是 0 还是 1：
     * 真实机器上 cron 是否已装是**环境状态**，不是代码行为。原判据写 ==0，
     * 于是任何一次写真实根的部署（如 onekey.sh install）都会让它永久变红，
     * 而失败信息只说"返回 X"，排查者会去查 persist.c 而不是去查是谁污染了 /etc。
     * 实测：本仓多次部署测试在真实 /etc/cron.d 留下 dayanjing / sysupdate 两条，
     * 09_persistence 因此在全仓回归里长期 FAIL。
     * 顺带：若返回 1 说明真实系统上有该驻留（可能是本仓测试残留），打印出来，
     * 让"环境脏"与"代码错"在输出里可区分。 */
    {
        int r = persist_installed(NULL,PERSIST_CRON);
        CK(r==0 || r==1, "真实系统 cron 查询返回合法值(0/1，非错误)");
        if (r==1) printf("  [INFO] 真实系统已存在 cron 驻留（可能为本仓测试残留），已按合法值处理\n");
    }

    g_hits=0;
    int n=persist_enumerate(root,cb,NULL);
    CK(n==2, "枚举到 2 项");
    CK(g_hits==2, "回调被调用 2 次");
    CK(g_last==PERSIST_SSHKEY, "回调按方法序号升序(最后为 sshkey)");

    CK(persist_uninstall(PERSIST_CRON,root,"/opt/a")==0, "卸载 cron 成功");
    CK(persist_installed(root,PERSIST_CRON)==0, "卸载后 cron 不在位");
    g_hits=0;
    CK(persist_enumerate(root,cb,NULL)==1, "卸载后枚举只剩 1 项");
    /* 清理：先卸载残留项，再删目录；mkdtemp 每次独立，避免跨轮污染 */
    persist_uninstall(PERSIST_SSHKEY, root, "ssh-rsa AAA");
    rmdir(root);
    printf("total=%d pass=%d fail=%d\n",pass+fail,pass,fail);
    return fail?1:0;
}
