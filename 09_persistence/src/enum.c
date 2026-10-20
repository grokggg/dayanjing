#include "persist.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* 与 persist.c 中 fname_of 保持一致 */
static const char *enum_fname(persist_method_t m){
    switch(m){
        case PERSIST_CRON:        return "cron";
        case PERSIST_SYSTEMD:     return "systemd";
        case PERSIST_LAUNCHAGENT: return "launchagent";
        case PERSIST_LDPRELOAD:   return "ld.so.preload";
        case PERSIST_SSHKEY:      return "authorized_keys";
        default:                  return NULL;
    }
}

static int exists(const char *p){
    struct stat st;
    return stat(p, &st) == 0;
}

int persist_enumerate(const char *root_prefix, persist_cb_t cb, void *ud){
    if(!root_prefix || !cb) return -1;
    int hits = 0;
    for(int m = 0; m <= (int)PERSIST_LKM; m++){
        const char *fn = enum_fname((persist_method_t)m);
        if(!fn) continue;
        char path[512];
        int n = snprintf(path, sizeof path, "%s/%s", root_prefix, fn);
        if(n < 0 || (size_t)n >= sizeof path) continue;
        if(exists(path)){ cb((persist_method_t)m, fn, path, ud); hits++; }
    }
    return hits;
}

int persist_installed(const char *root_prefix, persist_method_t m){
    if(!root_prefix) return -1;
    const char *fn = enum_fname(m);
    if(!fn) return -1;                 /* 非文件型 */
    char path[512];
    int n = snprintf(path, sizeof path, "%s/%s", root_prefix, fn);
    if(n < 0 || (size_t)n >= sizeof path) return -1;
    return exists(path) ? 1 : 0;
}
