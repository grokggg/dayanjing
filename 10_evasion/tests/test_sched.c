#include "evasion.h"
#include <stdio.h>
#include <string.h>
static int pass=0,fail=0;
#define CK(c,m) do{ if(c){pass++;printf("[PASS] %s\n",m);} else{fail++;printf("[FAIL] %s\n",m);} }while(0)
int main(void){
    printf("=== 10_evasion 调度测试 ===\n");
    uint32_t s1=12345, s2=12345;
    int a1=ev_jitter_seeded(100,50,&s1), a2=ev_jitter_seeded(100,50,&s2);
    CK(a1==a2, "同 seed 抖动可复现(相同结果)");
    CK(a1>=100 && a1<=150, "抖动落在 [base, base+jitter] 区间");
    uint32_t s3=999; int b1=ev_jitter_seeded(100,50,&s3);
    CK(b1>=100 && b1<=150, "不同 seed 抖动仍在区间内");
    CK(ev_jitter_seeded(100,0,&s3)==100, "jitter=0 时等于 base");
    CK(ev_jitter_seeded(-1,10,&s3)==-1, "负 base 被拒绝");
    CK(ev_jitter_seeded(10,-5,&s3)==-1, "负 jitter 被拒绝");

    ev_slot_t sl[16];
    size_t n=ev_plan(1000,64,50,20,&s3,sl,16);
    CK(n==(1000+59)/60, "分片数正确(1000/(64-4)=17)");
    CK(sl[0].offset==0 && sl[1].offset==64, "offset 按 mtu 递增");
    CK(sl[0].len==64, "每片占用固定 mtu");
    int inrange=1; for(size_t i=0;i<n&&i<16;i++) if(sl[i].delay_ms<50||sl[i].delay_ms>70) inrange=0;
    CK(inrange, "所有片延迟均在抖动区间内");
    CK(ev_plan(1000,4,50,20,&s3,sl,16)==0, "mtu<=4 被拒绝返回 0");
    CK(ev_plan(1000,64,50,20,&s3,NULL,16)==0, "slots 为空返回 0");
    size_t big=ev_plan(10000,64,50,20,&s3,sl,4);
    CK(big>4, "返回真实需要片数(即使 slots 容量不足)");
    CK(ev_plan(0,64,50,20,&s3,sl,16)==0, "空帧返回 0 片");
    printf("total=%d pass=%d fail=%d\n",pass+fail,pass,fail);
    return fail?1:0;
}
