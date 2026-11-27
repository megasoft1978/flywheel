#include "flywheel.h"

/* Ratcliff-Obershelp gestalt: 2*M/(la+lb), M = recursive longest
   matching blocks — same metric as Python difflib.ratio. */
static int lcs_block(const char *a, int la, const char *b, int lb,
                     int *ai, int *bi) {
    /* longest common substring via DP row — O(la*lb) */
    int best = 0;
    *ai = *bi = 0;
    if (!la || !lb) return 0;
    int *prev = calloc(lb + 1, sizeof(int));
    int *cur = calloc(lb + 1, sizeof(int));
    for (int i = 1; i <= la; i++) {
        for (int j = 1; j <= lb; j++) {
            if (a[i-1] == b[j-1]) {
                cur[j] = prev[j-1] + 1;
                if (cur[j] > best) { best = cur[j]; *ai = i - best; *bi = j - best; }
            } else cur[j] = 0;
        }
        int *t = prev; prev = cur; cur = t;
    }
    free(prev); free(cur);
    return best;
}

static int match_blocks(const char *a, int la, const char *b, int lb) {
    int ai, bi;
    int len = lcs_block(a, la, b, lb, &ai, &bi);
    if (!len) return 0;
    return len
        + match_blocks(a, ai, b, bi)
        + match_blocks(a + ai + len, la - ai - len,
                       b + bi + len, lb - bi - len);
}

double sim_ratio(const char *a, const char *b) {
    char ab[701], bb[701];
    snprintf(ab, sizeof ab, "%.700s", a ? a : "");
    snprintf(bb, sizeof bb, "%.700s", b ? b : "");
    int la = (int)strlen(ab), lb = (int)strlen(bb);
    if (!la && !lb) return 1.0;
    if (!la || !lb) return 0.0;
    int m = match_blocks(ab, la, bb, lb);
    return 2.0 * m / (la + lb);
}

void rec_clear(Recent *r) {
    for (int i = 0; i < r->n; i++) { free(r->cmds[i]); free(r->outs[i]); }
    r->n = 0;
}

void rec_push(Recent *r, const char *cmd, const char *out) {
    if (r->n == MAXRECENT) {
        free(r->cmds[0]);
        free(r->outs[0]);
        memmove(r->cmds, r->cmds + 1, (MAXRECENT - 1) * sizeof(char *));
        memmove(r->outs, r->outs + 1, (MAXRECENT - 1) * sizeof(char *));
        r->n--;
    }
    r->cmds[r->n] = str_dup(cmd);
    r->outs[r->n++] = str_dup(out);
}

/* A repeat needs a similar command AND a similar result: different scripts
   often share their first lines, and a new result is progress. File edits
   (keys starting with \001) repeat only when identical. */
static bool same(const Recent *r, int i, int j, double t) {
    const char *a = r->cmds[i], *b = r->cmds[j];
    bool cmd = *a == '\001' || *b == '\001' ? !strcmp(a, b) : sim_ratio(a, b) > t;
    return cmd && sim_ratio(r->outs[i], r->outs[j]) > t;
}

const char *detect_loop(const Recent *r, int *clen) {
    int n = r->n;
    if (n >= 3 && same(r, n-1, n-2, 0.82) && same(r, n-2, n-3, 0.82)) { *clen = 3; return "p1"; }
    if (n >= 4 && same(r, n-1, n-3, 0.82) && same(r, n-2, n-4, 0.82)) { *clen = 4; return "p2"; }
    if (n >= 6 && same(r, n-1, n-4, 0.82) && same(r, n-2, n-5, 0.82)
              && same(r, n-3, n-6, 0.82)) { *clen = 6; return "p3"; }
    if (n >= 5) {
        int cnt = 0, lo = n - 8 < 0 ? 0 : n - 8;
        for (int i = lo; i < n - 1; i++)
            if (same(r, i, n-1, 0.88)) cnt++;
        if (cnt >= 3) { *clen = 3; return "rep"; }
    }
    return NULL;
}
