/* spiral.c — failure classification + graveyard of dead-end approaches.
 *
 * Idea (borrowed from Cortheon's "graveyard backtracking"): when the loop
 * breaker prunes turns or resets the context, the model loses the record of
 * what it already tried, and happily walks the same dead end again. The
 * graveyard keeps a compact, bounded list of failed attempts (command +
 * output tail) that is re-injected after prunes/resets and fed to the
 * fresh-context diagnosis call.
 *
 * Pure functions only (no network, no globals) so tests/test_unit.c can
 * link this file directly.
 */
#include "flywheel.h"
#include <ctype.h>

#define GY_CMD 160   /* chars of the command kept per entry */
#define GY_OUT 260   /* chars of the output tail kept per entry */

/* copy at most n bytes of src, never splitting a UTF-8 sequence at the end */
static size_t utf8_prefix_len(const char *s, size_t n) {
    size_t L = strlen(s);
    if (L <= n) return L;
    while (n > 0 && ((unsigned char)s[n] & 0xC0) == 0x80) n--;
    return n;
}

/* start offset of the last <= n bytes of s, never starting mid-sequence */
static size_t utf8_suffix_start(const char *s, size_t n) {
    size_t L = strlen(s);
    if (L <= n) return 0;
    size_t i = L - n;
    while (s[i] && ((unsigned char)s[i] & 0xC0) == 0x80) i++;
    return i;
}

/* append src to dst collapsing runs of whitespace (incl. newlines) to one space */
static void append_flat(char *dst, size_t cap, const char *src, size_t n) {
    size_t d = strlen(dst);
    bool sp = d > 0 && dst[d - 1] == ' ';
    for (size_t i = 0; i < n && src[i] && d + 1 < cap; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '\n' || c == '\r' || c == '\t' || c == ' ') {
            if (!sp && d > 0) { dst[d++] = ' '; sp = true; }
        } else { dst[d++] = (char)c; sp = false; }
    }
    while (d > 0 && dst[d - 1] == ' ') d--;
    dst[d] = 0;
}

bool spiral_is_failure(bool is_bash, int exit_code, const char *out) {
    if (!out) return false;
    /* user said no: that is a decision, not a failed approach */
    if (strstr(out, "user denied")) return false;
    /* tool-level errors (bad args, deny rules, failed edits) */
    if (!strncmp(out, "error", 5)) return true;
    if (!is_bash) return false;
    if (!strncmp(out, "[timeout after", 14)) return true;
    if (exit_code == 0) return false;
    /* non-zero exit with no real output is usually a probe (grep no match,
       test -f ...), not a failed approach */
    for (const char *p = out; *p; p++)
        if (!isspace((unsigned char)*p)) return strcmp(out, "(no output)") != 0;
    return false;
}

void gy_add(Graveyard *g, const char *what, const char *out) {
    char e[GY_CMD + GY_OUT + 32];
    strcpy(e, "$ ");
    size_t cl = utf8_prefix_len(what ? what : "", GY_CMD);
    char cmd[GY_CMD + 8];
    cmd[0] = 0;
    append_flat(cmd, sizeof cmd, what ? what : "", cl);
    strncat(e, cmd, sizeof e - strlen(e) - 1);
    if (strlen(what ? what : "") > cl) strncat(e, "…", sizeof e - strlen(e) - 1);
    strncat(e, " -> ", sizeof e - strlen(e) - 1);
    const char *o = out ? out : "";
    size_t st = utf8_suffix_start(o, GY_OUT);
    char tail[GY_OUT + 8];
    tail[0] = 0;
    append_flat(tail, sizeof tail, o + st, strlen(o + st));
    strncat(e, tail, sizeof e - strlen(e) - 1);

    /* near-duplicate of the newest entry: the model retried the same thing */
    if (g->n > 0 && sim_ratio(g->v[g->n - 1], e) > 0.9) return;
    if (g->n == GY_MAX) {
        free(g->v[0]);
        memmove(g->v, g->v + 1, (GY_MAX - 1) * sizeof(char *));
        g->n--;
    }
    g->v[g->n++] = str_dup(e);
}

char *gy_format(const Graveyard *g) {
    if (g->n == 0) return str_dup("");
    size_t cap = 96;
    for (int i = 0; i < g->n; i++) cap += strlen(g->v[i]) + 8;
    char *s = malloc(cap);
    size_t o = (size_t)snprintf(s, cap, "Approaches that already failed (do NOT repeat them):\n");
    for (int i = 0; i < g->n && o < cap; i++)
        o += (size_t)snprintf(s + o, cap - o, "%d. %s\n", i + 1, g->v[i]);
    return s;
}

void gy_clear(Graveyard *g) {
    for (int i = 0; i < g->n; i++) free(g->v[i]);
    g->n = 0;
}
