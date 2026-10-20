#define _DEFAULT_SOURCE
#include "server.h"
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define SRV_MAX_EVENTS 64

struct srv {
    int              lfd;
    int              epfd;
    session_table_t  tbl;
    uint32_t         idctr;
};

static int set_nb(int fd){
    int fl = fcntl(fd, F_GETFL, 0);
    if(fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void assign_id(srv_t *s, uint8_t out[SESSION_ID_LEN]){
    uint32_t v = ++s->idctr;
    memset(out, 0, SESSION_ID_LEN);
    out[0] = (uint8_t)(v >> 24); out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);  out[3] = (uint8_t)(v);
    out[4] = (uint8_t)(v >> 12); out[5] = (uint8_t)(v >> 4);
}

srv_t *srv_create(int port, int *out_port){
    srv_t *s = calloc(1, sizeof *s);
    if(!s) return NULL;
    s->lfd = socket(AF_INET, SOCK_STREAM, 0);
    if(s->lfd < 0){ free(s); return NULL; }
    int one = 1; setsockopt(s->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((uint16_t)port);
    if(bind(s->lfd, (struct sockaddr*)&sa, sizeof sa) < 0){ close(s->lfd); free(s); return NULL; }
    if(listen(s->lfd, 16) < 0){ close(s->lfd); free(s); return NULL; }
    if(out_port){
        struct sockaddr_in got; socklen_t gl = sizeof got;
        if(getsockname(s->lfd, (struct sockaddr*)&got, &gl) == 0) *out_port = ntohs(got.sin_port);
    }
    s->epfd = epoll_create1(0);
    if(s->epfd < 0){ close(s->lfd); free(s); return NULL; }
    struct epoll_event ee; memset(&ee, 0, sizeof ee);
    ee.events = EPOLLIN; ee.data.fd = s->lfd;
    if(epoll_ctl(s->epfd, EPOLL_CTL_ADD, s->lfd, &ee) < 0){
        close(s->epfd); close(s->lfd); free(s); return NULL;
    }
    st_init(&s->tbl);
    return s;
}

void srv_destroy(srv_t *s){
    if(!s) return;
    if(s->epfd >= 0) close(s->epfd);
    if(s->lfd  >= 0) close(s->lfd);
    free(s);
}

int srv_listen_fd(const srv_t *s){ return s ? s->lfd : -1; }
size_t srv_session_count(const srv_t *s){ return s ? s->tbl.count : 0; }
session_table_t *srv_sessions(srv_t *s){ return s ? &s->tbl : NULL; }

int srv_close_session(srv_t *s, const uint8_t *id){
    if(!s || !id) return -1;
    session_t *se = st_lookup(&s->tbl, id);
    if(!se) return -1;
    epoll_ctl(s->epfd, EPOLL_CTL_DEL, se->fd, NULL);
    close(se->fd);
    return st_remove(&s->tbl, id);
}

int srv_run_once(srv_t *s, int timeout_ms, srv_event_t *ev, size_t evcap){
    if(!s || !ev || evcap == 0) return -1;
    struct epoll_event ee[SRV_MAX_EVENTS];
    int n = epoll_wait(s->epfd, ee, SRV_MAX_EVENTS, timeout_ms < 0 ? -1 : timeout_ms);
    if(n < 0){ if(errno == EINTR) return 0; return -1; }
    if(n == 0) return 0;

    size_t out = 0;
    for(int i = 0; i < n && out < evcap; i++){
        int fd = ee[i].data.fd;
        if(fd == s->lfd){
            int c = accept(s->lfd, NULL, NULL);
            if(c < 0) continue;
            if(set_nb(c) < 0){ close(c); continue; }
            uint8_t id[SESSION_ID_LEN]; assign_id(s, id);
            if(st_insert(&s->tbl, id, c) != 0){ close(c); continue; }
            struct epoll_event ne; memset(&ne, 0, sizeof ne);
            ne.events = EPOLLIN; ne.data.fd = c;
            if(epoll_ctl(s->epfd, EPOLL_CTL_ADD, c, &ne) < 0){
                st_remove(&s->tbl, id); close(c); continue;
            }
            ev[out].type = SRV_EV_ACCEPT; ev[out].fd = c;
            memcpy(ev[out].id, id, SESSION_ID_LEN); out++;
        } else {
            if(ee[i].events & (EPOLLHUP | EPOLLERR)){
                /* 找到该 fd 所属会话并移除 */
                session_t *se = NULL;
                for(size_t b = 0; b < 256 && !se; b++)
                    for(session_t *p = s->tbl.buckets[b]; p; p = p->hnext)
                        if(p->fd == fd){ se = p; break; }
                if(se){
                    ev[out].type = SRV_EV_CLOSE; ev[out].fd = fd;
                    memcpy(ev[out].id, se->id, SESSION_ID_LEN); out++;
                    epoll_ctl(s->epfd, EPOLL_CTL_DEL, fd, NULL);
                    close(fd); st_remove(&s->tbl, se->id);
                }
                continue;
            }
            if(ee[i].events & EPOLLIN){
                /* 探测是否真的可读（0 字节=对端关闭） */
                char probe[1];
                ssize_t r = recv(fd, probe, 1, MSG_PEEK);
                if(r == 0){
                    session_t *se = NULL;
                    for(size_t b = 0; b < 256 && !se; b++)
                        for(session_t *p = s->tbl.buckets[b]; p; p = p->hnext)
                            if(p->fd == fd){ se = p; break; }
                    if(se){
                        ev[out].type = SRV_EV_CLOSE; ev[out].fd = fd;
                        memcpy(ev[out].id, se->id, SESSION_ID_LEN); out++;
                        epoll_ctl(s->epfd, EPOLL_CTL_DEL, fd, NULL);
                        close(fd); st_remove(&s->tbl, se->id);
                    }
                    continue;
                }
                if(r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) continue;
                session_t *se = NULL;
                for(size_t b = 0; b < 256 && !se; b++)
                    for(session_t *p = s->tbl.buckets[b]; p; p = p->hnext)
                        if(p->fd == fd){ se = p; break; }
                ev[out].type = SRV_EV_DATA; ev[out].fd = fd;
                memset(ev[out].id, 0, SESSION_ID_LEN);
                if(se) memcpy(ev[out].id, se->id, SESSION_ID_LEN);
                out++;
            }
        }
    }
    return (int)out;
}
