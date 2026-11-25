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
