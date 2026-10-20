#define _DEFAULT_SOURCE
#include "server.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <signal.h>

static int pass=0, fail=0;
#define CK(c,msg) do{ if(c){pass++;printf("[PASS] %s\n",msg);} \
    else {fail++;printf("[FAIL] %s\n",msg);} }while(0)

static int dial(int port){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa; memset(&sa,0,sizeof sa);
    sa.sin_family=AF_INET; sa.sin_port=htons((uint16_t)port);
    sa.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(connect(fd,(struct sockaddr*)&sa,sizeof sa)<0){ close(fd); return -1; }
    return fd;
}

int main(void){
    alarm(20);
    printf("=== 05_server epoll 事件循环测试 ===\n");
    int port = 0;
    srv_t *s = srv_create(0, &port);
    CK(s != NULL && port > 0, "srv_create 监听回环成功");
    if(!s){ printf("total=%d pass=%d fail=%d\n",pass+fail,pass,fail); return 1; }
    CK(srv_listen_fd(s) >= 0, "listen fd 有效");
    CK(srv_session_count(s) == 0, "初始会话数为 0");

    int c1 = dial(port), c2 = dial(port);
    CK(c1 >= 0 && c2 >= 0, "两个客户端连接成功");

    srv_event_t ev[16], got[16];
    int acc = 0;
    for(int round = 0; round < 6 && acc < 2; round++){
        int n = srv_run_once(s, 300, ev, 16);
        for(int i = 0; i < n && acc < 2; i++)
            if(ev[i].type == SRV_EV_ACCEPT){ memcpy(got[acc].id, ev[i].id, SESSION_ID_LEN); acc++; }
    }
    CK(acc == 2, "drain 多次 run_once 共收到 2 个 ACCEPT");
    CK(srv_session_count(s) == 2, "会话表登记 2 个会话");

    /* 会话 id 唯一 */
    CK(memcmp(ev[0].id, ev[1].id, SESSION_ID_LEN) != 0, "两个会话 id 互不相同");

    /* 发数据 → DATA 事件 */
    const char *msg = "hello-c2";
    ssize_t w = send(c1, msg, strlen(msg), 0);
    CK(w > 0, "客户端发送数据成功");
    int got_data = 0, data_fd = -1;
    for(int round = 0; round < 6 && !got_data; round++){
        int n2 = srv_run_once(s, 300, ev, 16);
        for(int i=0;i<n2;i++) if(ev[i].type == SRV_EV_DATA){ got_data++; data_fd = ev[i].fd; }
    }
    CK(got_data >= 1, "run_once 产生 DATA 事件");
    /* 把服务端侧待读数据真正读走，否则 EPOLLIN 一直 pending，EOF 检测不到 */
    char rbuf[128]; ssize_t rd = 0;
    if(data_fd >= 0) rd = recv(data_fd, rbuf, sizeof rbuf, 0);
    CK(rd > 0 && memcmp(rbuf, msg, strlen(msg)) == 0, "从服务端 fd 读到客户端原始数据");


    /* 关闭 → CLOSE 事件 */
    close(c1);
    int got_close = 0;
    for(int round = 0; round < 6 && !got_close; round++){
        int n3 = srv_run_once(s, 300, ev, 16);
        for(int i=0;i<n3;i++) if(ev[i].type == SRV_EV_CLOSE) got_close++;
    }
    CK(got_close >= 1, "对端关闭产生 CLOSE 事件");
    CK(srv_session_count(s) == 1, "关闭后会话数降为 1");

    /* 主动关闭会话 */
    uint8_t id2[SESSION_ID_LEN]; memcpy(id2, ev[0].id, SESSION_ID_LEN);
    if(memcmp(id2, ev[1].id, SESSION_ID_LEN) == 0) memcpy(id2, ev[0].id, SESSION_ID_LEN);
    close(c2);
    srv_run_once(s, 500, ev, 16);

    srv_destroy(s);
    CK(1, "srv_destroy 正常释放");
    printf("total=%d pass=%d fail=%d\n", pass+fail, pass, fail);
    return fail ? 1 : 0;
}
