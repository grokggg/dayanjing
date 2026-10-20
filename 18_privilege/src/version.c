#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "privilege.h"

#include <ctype.h>
#include <string.h>

const char *pr_errstr(int e)
{
    switch (e) {
    case PR_OK:           return "ok";
    case PR_ERR_ARGS:     return "invalid argument";
    case PR_ERR_IO:       return "io error";
    case PR_ERR_NOTFOUND: return "not found";
    case PR_ERR_BUFSMALL: return "buffer too small";
    default:              return "unknown";
    }
}

/* 逐段比较：数字段按数值，数字段后的非数字后缀按字典序。
 * "1.9.5p1" < "1.9.5p2"；"1.8.31" < "1.8.31p2"。 */
int pr_version_cmp(const char *a, const char *b)
{
    const char *pa, *pb;

    if (!a) a = "";
    if (!b) b = "";
    pa = a;
    pb = b;

    while (*pa || *pb) {
        long   na = 0, nb = 0;
        int    da = 0, db = 0;
        size_t sa, sb;
        const char *ta, *tb;
        size_t la, lb, lm;
        int    c;

        while (*pa && !isdigit((unsigned char)*pa)) pa++;
        while (*pb && !isdigit((unsigned char)*pb)) pb++;

        sa = strspn(pa, "0123456789");
        sb = strspn(pb, "0123456789");

        if (sa > 0) { na = strtol(pa, NULL, 10); da = 1; }
        if (sb > 0) { nb = strtol(pb, NULL, 10); db = 1; }

        if (da && db) {
            if (na != nb) return (na < nb) ? -1 : 1;
        } else if (da && !db) {
            return 1;
        } else if (!da && db) {
            return -1;
        }

        /* 数字段相同 → 比较紧随其后的非数字后缀 */
        ta = pa + sa;
        tb = pb + sb;
        la = strcspn(ta, "0123456789.");
        lb = strcspn(tb, "0123456789.");
        lm = (la < lb) ? la : lb;

        if (lm > 0) {
            c = strncmp(ta, tb, lm);
            if (c != 0) return (c < 0) ? -1 : 1;
        }
        if (la != lb) return (la < lb) ? -1 : 1;

        pa += sa;
        pb += sb;
        if (*pa == '.') pa++;
        if (*pb == '.') pb++;
    }
    return 0;
}
