#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "privilege.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int pr_sudo_audit(const char *ver, const pr_cve_t **out, size_t cap, size_t *out_n)
{
    const pr_cve_t *tbl;
    size_t n = 0, i, cnt = 0;

    if (!ver) return PR_ERR_ARGS;

    tbl = pr_sudo_table(&n);

    for (i = 0; i < n; i++) {
        if (!pr_cve_match(&tbl[i], ver)) continue;
        if (out && cnt < cap) out[cnt] = &tbl[i];
        cnt++;
    }
    if (out_n) *out_n = cnt;
    return PR_OK;
}
