#define _DEFAULT_SOURCE
#include "http.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
static int pass=0,fail=0;
#define CK(c,m) do{ if(c){pass++;printf("[PASS] %s\n",m);} else{fail++;printf("[FAIL] %s\n",m);} }while(0)

static int h_list(const http_req_t*r,const char*b,char*o,size_t c){
    (void)r;(void)b; return snprintf(o,c,"{\"sessions\":2}")>0?0:-1; }
static int h_bad(const http_req_t*r,const char*b,char*o,size_t c){
    (void)r;(void)b;(void)o;(void)c; return -1; }

int main(void){
    printf("=== 07_ui 控制台测试 ===\n");
    ui_route_reset();
    CK(ui_route_count()==0, "初始路由数为 0");
    CK(ui_route_add("GET","/api/sessions",h_list)==0, "注册 GET /api/sessions");
    CK(ui_route_add("POST","/api/task",h_list)==0, "注册 POST /api/task");
    CK(ui_route_add("GET","/api/bad",h_bad)==0, "注册会失败的 handler");
    CK(ui_route_count()==3, "路由数为 3");

    CK(ui_route_add("GET","/api/sessions",h_list)==0, "重复注册覆盖不新增");
    CK(ui_route_count()==3, "重复注册后仍为 3");

    CK(ui_route_find("GET","/api/sessions")==h_list, "查找到 handler");
    CK(ui_route_find("get","/api/sessions")==h_list, "method 大小写不敏感");
    CK(ui_route_find("GET","/nope")==NULL, "未注册路径返回 NULL");

    http_req_t req; memset(&req,0,sizeof req);
    snprintf(req.method,sizeof req.method,"GET");
    snprintf(req.path,sizeof req.path,"/api/sessions");
    char out[4096];
    CK(ui_dispatch(&req,"",out,sizeof out)==0, "dispatch 成功");
    CK(strstr(out,"200")!=NULL && strstr(out,"{\"sessions\":2}")!=NULL,
       "响应含 200 与 handler 输出");

    snprintf(req.path,sizeof req.path,"/nope");
    CK(ui_dispatch(&req,"",out,sizeof out)==0, "未匹配 dispatch 返回成功(404 响应)");
    CK(strstr(out,"404")!=NULL, "未匹配路径返回 404");

    snprintf(req.path,sizeof req.path,"/api/bad");
    CK(ui_dispatch(&req,"",out,sizeof out)==0, "handler 失败 dispatch 仍返回");
    CK(strstr(out,"500")!=NULL, "handler 失败返回 500");

    /* JSON 转义 */
    char je[256]; size_t jl = ui_json_escape("a\"b\\c\nd", je, sizeof je);
    CK(strcmp(je,"a\\\"b\\\\c\\nd")==0, "JSON 转义正确(引号/反斜杠/换行)");
    CK(jl==strlen(je), "转义返回长度与字符串一致");

    /* HTML 页面 */
    char pg[2048]; size_t pl = ui_page("T<>&","line1\nline2", pg, sizeof pg);
    CK(pl>0 && strstr(pg,"<title>T")!=NULL, "HTML 页面生成且标题已转义");
    CK(strstr(pg,"<pre>")!=NULL, "HTML 含正文区");

    /* 真实 socket 服务 */
    int lfd=socket(AF_INET,SOCK_STREAM,0);
    int one=1; setsockopt(lfd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in sa; memset(&sa,0,sizeof sa);
    sa.sin_family=AF_INET; sa.sin_addr.s_addr=htonl(INADDR_LOOPBACK); sa.sin_port=0;
    CK(bind(lfd,(struct sockaddr*)&sa,sizeof sa)==0, "绑定回环成功");
    socklen_t sl=sizeof sa; getsockname(lfd,(struct sockaddr*)&sa,&sl);
    int port=ntohs(sa.sin_port);
    listen(lfd,4);
    int cfd=socket(AF_INET,SOCK_STREAM,0);
    sa.sin_port=htons((uint16_t)port); sa.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    CK(connect(cfd,(struct sockaddr*)&sa,sizeof sa)==0, "客户端连接控制台成功");
    const char*rq="GET /api/sessions HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";
    ssize_t w=send(cfd,rq,strlen(rq),0); CK(w>0,"发送 HTTP 请求");
    int sfd=accept(lfd,NULL,NULL); CK(sfd>=0,"accept 成功");
    char resp[4096];
    CK(ui_serve_once(sfd,resp,sizeof resp,3000)==0, "ui_serve_once 处理成功");
    CK(strstr(resp,"200")!=NULL && strstr(resp,"sessions")!=NULL, "真实服务响应正确");
    char rb[4096]; ssize_t rr=recv(cfd,rb,sizeof rb-1,0);
    if(rr>0){ rb[rr]=0; CK(strstr(rb,"200")!=NULL,"客户端收到 200 响应"); }
    else CK(0,"客户端收到 200 响应");
    close(cfd); close(sfd); close(lfd);
    printf("total=%d pass=%d fail=%d\n",pass+fail,pass,fail);
    return fail?1:0;
}
