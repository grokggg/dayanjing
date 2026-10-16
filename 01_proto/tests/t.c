#include "proto.h"
#include <stdio.h>
#include <string.h>
int main(void){
    uint8_t k[32],prefix[8]; memset(k,1,32); for(int i=0;i<8;i++)prefix[i]=i;
    uint32_t c=0; uint8_t nonce[12];
    uint8_t wire[65536]; size_t wl=0;
    proto_err_t r=proto_seal(k,prefix,&c,nonce,1,3,(const uint8_t*)"hello payload",13,wire,sizeof(wire),&wl);
    printf("seal rc=%d wl=%zu\n",r,wl);
    /* 手动解码 */
    uint32_t total_len=0; memcpy(&total_len,wire,4);
    uint32_t hdr_type=0; memcpy(&hdr_type,wire+4,4);
    printf("total_len=%u hdr_type=%u\n",total_len,hdr_type);
    size_t env_len=20+13;
    size_t expected_body=4+12+env_len+16;
    printf("expected body_len=%zu\n",expected_body);
    return 0;
}
