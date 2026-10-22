/* 25_deploy 制品取证：多 seed 打包同一载荷，逐偏移统计取值种类。
   恒定偏移 = 可直接提取的静态签名。 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "packer.h"

#define NSEED 20
#define WIN   512   /* 只统计前 512 字节：签名提取只看前缀 */

static uint8_t *raw; static size_t raw_len;

static int rd(const char *p, uint8_t **o, size_t *n){
    FILE *f=fopen(p,"rb"); if(!f) return -1;
    fseek(f,0,SEEK_END); long s=ftell(f); if(s<0){fclose(f);return -1;} rewind(f);
    uint8_t *b=malloc((size_t)s); if(!b){fclose(f);return -1;}
    if(fread(b,1,(size_t)s,f)!=(size_t)s){free(b);fclose(f);return -1;}
    fclose(f); *o=b; *n=(size_t)s; return 0;
}

int main(int argc,char**argv){
    if(argc<2){fprintf(stderr,"usage: %s <elf>\n",argv[0]);return 2;}
    if(rd(argv[1],&raw,&raw_len)!=0){fprintf(stderr,"read fail\n");return 1;}

    size_t cap=pk_size_bound_v4(raw_len);
    uint8_t *out=malloc(cap); if(!out){return 1;}
    uint8_t id[PK_BIND_ID_LEN], ep[PK_EPH_PUB_LEN];
    memset(id,0,sizeof(id)); memset(ep,0,sizeof(ep));

    /* samples[seed][offset] 的第一份先存下来，之后逐字节比对 */
    uint8_t **smp=calloc(NSEED,sizeof(uint8_t*));
    size_t  *slen=calloc(NSEED,sizeof(size_t));
    if(!smp||!slen){fprintf(stderr,"oom\n");return 1;}

    size_t minlen=(size_t)-1;
    for(int s=0;s<NSEED;s++){
        uint8_t seed[32];
        for(int i=0;i<32;i++) seed[i]=(uint8_t)((s*2654435761u>>(i%8))^(i*97+s));
        size_t olen=cap;
        int rc=pk_pack_shaped(raw,raw_len,seed,sizeof(seed),id,1u,ep,out,&olen);
        if(rc!=0){fprintf(stderr,"pack rc=%d seed=%d\n",rc,s);return 1;}
        smp[s]=malloc(olen); memcpy(smp[s],out,olen); slen[s]=olen;
        if(olen<minlen) minlen=olen;
    }

    size_t win = minlen<WIN?minlen:WIN;
    int *kind=calloc(win,sizeof(int));
    int *seen=calloc(win*256,sizeof(int));
    int nconst=0;
    for(size_t o=0;o<win;o++){
        int k=0;
        for(int s=0;s<NSEED;s++){
            int v=smp[s][o];
            if(!seen[o*256+v]){seen[o*256+v]=1;k++;}
        }
        kind[o]=k;
        if(k==1) nconst++;
    }
    /* 最长恒定游程 */
    int run=0,best=0;
    for(size_t o=0;o<win;o++){ if(kind[o]==1){run++; if(run>best)best=run;} else run=0; }

    printf("载荷=%zu  样本=%d  窗口=%zu\n", raw_len, NSEED, win);
    printf("恒定偏移(取值种类==1) = %d\n", nconst);
    printf("最长恒定游程 = %d\n", best);
    if(nconst>0){
        printf("恒定偏移列表: ");
        int c=0;
        for(size_t o=0;o<win && c<32;o++) if(kind[o]==1){printf("%zu(0x%02x) ",o,smp[0][o]);c++;}
        printf("\n");
    }
    for(int s=0;s<NSEED;s++) free(smp[s]);
    free(smp); free(slen); free(kind); free(seen); free(out); free(raw);
    return 0;
}
