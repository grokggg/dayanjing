/*
 * 01_proto / 02_c2 职责分层集成测试
 *
 * 裁定（本文件即为该裁定的可执行证据）：
 *   01_proto = 内层应用帧（frame_hdr + payload + CRC32），负责应用级分帧与完整性自检
 *   02_c2    = 外层 wire 信封（AEAD），负责机密性、完整性、防重放
 * 两者不再重叠：01_proto 不做加密，02_c2 不做应用分帧。
 */
#include "frame.h"
#include "c2_frame.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int pass=0, fail=0;
#define CK(c,m) do{ if(c){pass++;printf("[PASS] %s\n",m);} else{fail++;printf("[FAIL] %s\n",m);} }while(0)

int main(void){
    printf("=== 01_proto x 02_c2 分层集成测试 ===\n");

    uint8_t key[16]; for(int i=0;i<16;i++) key[i]=(uint8_t)(i*11+1);
    uint8_t nprefix[8] = {1,2,3,4,5,6,7,8};

    /* 1. 构造内层应用帧 */
    struct frame f; frame_init(&f);
    const char *app = "HELLO-APP-DATA";
    CK(frame_set_payload(&f,(const uint8_t*)app,strlen(app))==0, "01_proto 设置 payload");
    uint8_t inner[512];
    int pk = frame_pack(&f, inner, sizeof inner);
    CK(pk > 0, "01_proto frame_pack 成功(返回写入字节数)");
    frame_calc_crc(&f);   /* pack 接受 const，不回写 f->crc，需显式计算 */
    CK(frame_verify_crc(&f)==0, "01_proto CRC 自检通过(显式 calc 后 verify)");
    /* 内层帧长度 = 头部(12) + payload_len + CRC(4) */
    size_t ib_len = (size_t)(pk > 0 ? pk : 0);
    uint8_t inner_bytes[512];
    memcpy(inner_bytes, inner, ib_len);
    printf("  [INFO] 内层帧长度 = %zu\n", ib_len);

    size_t need = 0;
    CK(c2_frame_seal(key,nprefix,0,1,0x21,inner_bytes,ib_len,NULL,0,&need)==0,
       "02_c2 探测所需 wire 长度");
    uint8_t *wire = malloc(need);
    size_t wlen = 0;
    CK(c2_frame_seal(key,nprefix,0,1,0x21,inner_bytes,ib_len,wire,need,&wlen)==0,
       "02_c2 c2_frame_seal 封装内层帧");
    printf("  [INFO] wire 长度 = %zu (内层 %zu + 信封开销 %zu)\n", wlen, ib_len, wlen-ib_len);
    CK(wlen > ib_len, "wire 比内层帧长（存在信封开销）");

    /* 3. 解封 */
    uint64_t seq=0; uint32_t mt=0; size_t plen=0;
    CK(c2_frame_open(key,wire,wlen,&seq,&mt,NULL,0,&plen)==0, "02_c2 探测解封 payload 长度");
    CK(plen==ib_len, "解封出的 payload 长度等于原内层帧");
    uint8_t *back = malloc(plen);
    CK(c2_frame_open(key,wire,wlen,&seq,&mt,back,plen,&plen)==0, "02_c2 c2_frame_open 成功");
    CK(seq==1 && mt==0x21, "seq 与 msg_type 正确还原");
    CK(memcmp(back,inner_bytes,ib_len)==0, "解封后与内层帧字节一致");

    /* 4. 回到 01_proto 解析内层 */
    struct frame out; frame_init(&out);
    CK(frame_unpack(&out, back, ib_len) > 0, "01_proto 重新解析内层帧成功(返回消耗字节数)");
    CK(frame_verify_crc(&out)==0, "内层帧 CRC 校验通过");
    CK(out.hdr.payload_len==strlen(app) && memcmp(out.payload,app,strlen(app))==0,
       "应用数据端到端还原一致");
    frame_fini(&out);

    /* 5. 负向：篡改 wire 应被 AEAD 拒绝（证明机密性由 02_c2 负责） */
    wire[wlen-1] ^= 0x01;
    CK(c2_frame_open(key,wire,wlen,&seq,&mt,back,plen,&plen)!=0, "篡改 wire 被 AEAD 拒绝");
    frame_fini(&f);
    free(wire); free(back);
    printf("total=%d pass=%d fail=%d\n",pass+fail,pass,fail);
    return fail?1:0;
}
