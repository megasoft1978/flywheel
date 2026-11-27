#define _DARWIN_C_SOURCE 1   /* O_NOFOLLOW */
#include "flywheel.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <ctype.h>
#include <limits.h>
#include <sys/stat.h>
#include <time.h>

static bool lex_normalize(const char *in, char *out, size_t cap);
static bool is_within(const char *base, const char *path);
static bool mkdir_parents(const char *path);

static const char *DENY_SUBSTR[] = {
    "sudo ", "mkfs", "dd of=/",
    "shutdown", "reboot", "> /dev/sd", ":(){", "chmod -R 777 /",
    NULL
};

/* Heredoc payload ranges: text between the opener line and the closing
   delimiter line is data, not shell syntax — redirects/paths inside it
   must not be scanned. Supports up to 8 heredocs per command. */
typedef struct { const char *lo, *hi; } Range;

static int heredoc_ranges(const char *cmd, Range *out, int maxr) {
    int n = 0;
    const char *p = cmd;
    while (n < maxr && (p = strstr(p, "<<"))) {
        const char *q = p + 2;
        if (*q == '-') q++;
        while (*q == ' ' || *q == '\t') q++;
        if (*q == '\'' || *q == '"') q++;
        char delim[64] = {0};
        int dl = 0;
        while (q[dl] && (isalnum((unsigned char)q[dl]) || q[dl] == '_') && dl < 63)
            delim[dl] = q[dl], dl++;
        if (!dl) { p += 2; continue; }
        /* payload starts after the opener line's newline */
        const char *body = strchr(q, '\n');
        if (!body) { p += 2; continue; }
        body++;
        /* closing delimiter: a line whose first token is delim */
        const char *cur = body;
        const char *end = NULL;
        while (*cur) {
            if (!strncmp(cur, delim, dl) && (cur[dl] == '\n' || cur[dl] == 0
                || cur[dl] == ' ' || cur[dl] == '\t' || cur[dl] == '\r')) {
                end = cur;
                break;
            }
            const char *nl = strchr(cur, '\n');
            if (!nl) break;
            cur = nl + 1;
        }
        if (!end) { p += 2; continue; }  /* unterminated: treat rest as payload-free */
        out[n].lo = body;
        out[n].hi = end;
        n++;
        p = end + dl;
    }
    return n;
}

static bool in_ranges(const Range *r, int n, const char *p) {
    for (int i = 0; i < n; i++)
        if (p >= r[i].lo && p < r[i].hi) return true;
    return false;
}

/* ---------- best-effort shell scan (NOT a sandbox) ---------- */

#define MAXWORDS 4096
#define MAXHEREDOC 8

#define OPAQUE '\001'   /* word we cannot decode */

/* Read one shell word at *s, removing quotes and backslashes. Stops at an
   unquoted blank or operator. out needs strlen(*s)+1 bytes. *sub is set to
   the first command substitution found inside double quotes (or NULL). */
static void read_word(const char **s, char *out, const char **sub) {
    const char *p = *s;
    char *w = out;
    if (sub) *sub = NULL;
    while (*p && !strchr(" \t\r\n;&|<>()`", *p)) {
        if (*p == '\\') {
            p++;
            if (*p == '\n') p++;
            else if (*p) *w++ = *p++;
        } else if (*p == '$' && p[1] == '"') {
            p++;                                  /* locale quoting == "..." */
        } else if (*p == '$' && p[1] == '\'') {
            /* ANSI-C quoting: we do not decode escapes, so mark the word */
            bool esc = false;
            for (p += 2; *p && *p != '\''; p++) {
                if (*p == '\\' && p[1]) { esc = true; *w++ = *p++; }
                *w++ = *p;
            }
            if (*p) p++;
            if (esc) *w++ = OPAQUE;
        } else if (*p == '\'') {
            for (p++; *p && *p != '\''; ) *w++ = *p++;
            if (*p) p++;
        } else if (*p == '"') {
            for (p++; *p && *p != '"'; ) {
                if (*p == '\\' && p[1] && strchr("\"\\$`\n", p[1])) {
                    p++;
                    if (*p == '\n') { p++; continue; }
                } else if (sub && !*sub && (*p == '`' || (*p == '$' && p[1] == '('))) {
                    *sub = p + (*p == '`' ? 1 : 2);
                }
                *w++ = *p++;
            }
            if (*p) p++;
        } else *w++ = *p++;
    }
    *w = 0;
    *s = p;
}

/* brace expansion or a dot-glob (".*" matches "..") can leave the project */
static bool expands_unsafely(const char *w) {
    if (strchr(w, OPAQUE)) return true;
    for (const char *b = strchr(w, '{'); b; b = strchr(b + 1, '{'))
        if ((b == w || b[-1] != '$') && strchr(b, '}') && (strchr(b, ',') || strstr(b, "..")))
            return true;
    for (const char *c = w; c; c = strchr(c, '/')) {
        if (*c == '/') c++;
        if (*c == '.' && c[1] && strchr(".*?[", c[1]) && strcspn(c, "*?[") < strcspn(c, "/"))
            return true;
    }
    return false;
}

/* may `w` be written/removed? inside cwd, /tmp or harmless /dev nodes */
static bool path_ok(const char *w, const char *cwd) {
    if (!*w) return true;
    if (expands_unsafely(w)) return false;
    const char *home = getenv("HOME") ? getenv("HOME") : "/nonexistent-home";
    char ex[PATH_MAX], abs[PATH_MAX], norm[PATH_MAX], real[PATH_MAX];
    const char *rest = NULL;
    if (w[0] == '~') {
        if (w[1] && w[1] != '/') return false;
        rest = w + 1;
    } else if (!strncmp(w, "$HOME", 5) && (!w[5] || w[5] == '/')) rest = w + 5;
    else if (!strncmp(w, "${HOME}", 7)) rest = w + 7;
    if (rest) { snprintf(ex, sizeof ex, "%s%s", home, rest); w = ex; }
    if (w[0] != '/') {
        for (const char *p = w; (p = strstr(p, "..")); p += 2)
            if ((p == w || p[-1] == '/') && (!p[2] || p[2] == '/')) return false;
        if (w[0] == '$') return true;   /* unknown variable: best effort */
        snprintf(abs, sizeof abs, "%s/%s", cwd, w);
        w = abs;
    }
    if (!lex_normalize(w, norm, sizeof norm)) return false;
    if (!strncmp(norm, "/dev/sd", 7) || !strncmp(norm, "/dev/disk", 9) ||
        !strncmp(norm, "/dev/rdisk", 10) || !strncmp(norm, "/dev/nvme", 9)) return false;
    if (!realpath(cwd, real)) snprintf(real, sizeof real, "%s", cwd);
    return is_within(cwd, norm) || is_within(real, norm) || is_within("/tmp", norm) ||
           is_within("/private/tmp", norm) || is_within("/dev", norm);
}

static const char *E_RULE = "error: command blocked by deny rule";
static const char *E_OUTSIDE = "error: write outside working dir is forbidden";

static const char *scan_script(const char *s, const char *cwd, int depth);

static bool one_of(const char *s, const char *const *list) {
    for (; *list; list++)
        if (!strcmp(s, *list)) return true;
    return false;
}

/* path_ok for a command operand: harmless brace lists are expanded first */
static bool operand_ok(const char *w, const char *cwd, int *budget) {
    for (const char *b = strchr(w, '{'); b; b = strchr(b + 1, '{')) {
        if (b > w && b[-1] == '$') continue;
        const char *e = b + 1;
        int level = 0;
        bool list = false;
        for (; *e && (level || *e != '}'); e++) {
            if (*e == '{') level++;
            else if (*e == '}') level--;
            else if (*e == ',' && !level) list = true;
        }
        if (!*e) continue;
        const char *dots = strstr(b + 1, "..");
        bool range = !list && dots && dots > b + 1 && dots + 2 < e;
        for (const char *c = b + 1; range && c < e; c++)
            if (!isalnum((unsigned char)*c) && *c != '.' && *c != '-') range = false;
        if (!list && !range) continue;
        for (const char *alt = b + 1; alt <= e; ) {
            const char *end = alt;
            for (level = 0; end < e && (level || *end != ','); end++) {
                if (*end == '{') level++;
                else if (*end == '}') level--;
            }
            if (--*budget < 0) return false;
            size_t cap = strlen(w) + 2;
            char *x = malloc(cap);
            if (range) snprintf(x, cap, "%.*s0%s", (int)(b - w), w, e + 1);
            else snprintf(x, cap, "%.*s%.*s%s", (int)(b - w), w, (int)(end - alt), alt, e + 1);
            bool ok = operand_ok(x, cwd, budget);
            free(x);
            if (!ok) return false;
            if (range) break;
            alt = end + 1;
        }
        return true;
    }
    return path_ok(w, cwd);
}

static bool target_ok(const char *w, const char *cwd) {
    int budget = 256;
    return operand_ok(w, cwd, &budget);
}

static const char *check_simple(char **v, int n, const char *cwd, int depth);

/* find: -delete, -fprint and a mutating -exec act below the starting points */
static const char *check_find(char **a, int na, const char *cwd, int depth) {
    static const char *const readers[] = {"grep", "egrep", "fgrep", "rg", "cat", "head", "tail", "wc",
        "ls", "stat", "file", "echo", "printf", "basename", "dirname", "du", "md5", "md5sum",
        "shasum", "sha256sum", "test", NULL};
    int k = 0;
    while (k < na && a[k][0] == '-' && a[k][1] && strspn(a[k] + 1, "HLPEXdsx") == strlen(a[k] + 1)) k++;
    int first = k;
    while (k < na && a[k][0] != '-' && strcmp(a[k], "!") && strcmp(a[k], "(")) k++;
    int end = k;
    bool mutates = false;
    for (; k < na; k++) {
        if (!strcmp(a[k], "-delete")) mutates = true;
        else if ((!strncmp(a[k], "-fprint", 7) || !strcmp(a[k], "-fls")) && k + 1 < na) {
            if (!target_ok(a[++k], cwd)) return E_OUTSIDE;
        } else if (!strncmp(a[k], "-exec", 5) || !strncmp(a[k], "-ok", 3)) {
            int s = ++k;
            while (k < na && strcmp(a[k], ";") && strcmp(a[k], "+")) k++;
            if (s == k) continue;
            const char *c = strrchr(a[s], '/') ? strrchr(a[s], '/') + 1 : a[s];
            if (!one_of(c, readers)) mutates = true;
            if (depth > 4) return E_RULE;
            const char *e = check_simple(a + s, k - s, cwd, depth + 1);
            if (e) return e;
        }
    }
    for (int i = first; mutates && i < end; i++)
        if (!target_ok(a[i], cwd)) return E_OUTSIDE;
    return NULL;
}

/* sed -i / perl -i: the files edited in place (not the script) */
static const char *check_inplace(bool perl, char **a, int na, const char *cwd) {
    bool inplace = false, script = false;
    int k = 0;
    for (; k < na && a[k][0] == '-' && a[k][1]; k++) {
        const char *o = a[k];
        if (!strcmp(o, "--")) { k++; break; }
        if (o[1] == '-') {
            if (!strncmp(o, "--in-place", 10)) inplace = true;
            if (!strncmp(o, "--expression", 12) || !strncmp(o, "--file", 6)) {
                script = true;
                if (!strchr(o, '=')) k++;
            }
            continue;
        }
        for (const char *c = o + 1; *c; c++) {
            if (*c == 'i') {
                inplace = true;
                if (!perl && !c[1] && k + 1 < na && !*a[k + 1]) k++;   /* BSD: -i '' */
                /* perl -pie 'code': the e still introduces the program */
                if (perl && (c[1] == 'e' || c[1] == 'E') && !c[2]) { script = true; k++; }
                break;
            }
            if (*c == 'e' || (perl ? *c == 'E' : *c == 'f')) {
                script = true;
                if (!c[1]) k++;
                break;
            }
            if (perl && strchr("IMm", *c)) { if (!c[1]) k++; break; }
        }
    }
    /* -i may also follow the script (GNU sed permutes) */
    for (int j = k; !perl && j < na; j++)
        if (!strncmp(a[j], "-i", 2) || !strncmp(a[j], "--in-place", 10)) inplace = true;
    if (!inplace) return NULL;
    for (; k < na; k++) {
        if (!perl && !strncmp(a[k], "-e", 2)) { if (!a[k][2]) k++; continue; }
        if (a[k][0] == '-') continue;
        if (!script) { script = true; continue; }
        if (!target_ok(a[k], cwd)) return E_OUTSIDE;
    }
    return NULL;
}

/* git -C / --git-dir / --work-tree outside the project: read-only only */
static const char *check_git(char **a, int na, const char *cwd) {
    static const char *const reads[] = {"status", "log", "diff", "show", "rev-parse", "ls-files",
        "blame", "grep", "describe", "cat-file", NULL};
    bool outside = false;
    int k = 0;
    for (; k < na && a[k][0] == '-'; k++) {
        const char *o = a[k], *dir = NULL;
        if ((!strcmp(o, "-C") || !strcmp(o, "--git-dir") || !strcmp(o, "--work-tree")) && k + 1 < na)
            dir = a[++k];
        else if (!strncmp(o, "--git-dir=", 10)) dir = o + 10;
        else if (!strncmp(o, "--work-tree=", 12)) dir = o + 12;
        else if (!strcmp(o, "-c")) k++;
        if (dir && !target_ok(dir, cwd)) outside = true;
    }
    if (!outside) return NULL;
    if (k >= na || !one_of(a[k], reads)) return E_OUTSIDE;
    for (; k < na; k++)
        if (!strncmp(a[k], "--output", 8)) return E_OUTSIDE;
    return NULL;
}

/* commands that change the files named by their operands */
static const char *check_operands(const char *base, char **a, int na, const char *cwd) {
    bool chmod_ = !strcmp(base, "chmod");
    bool owner = !strcmp(base, "chown") || !strcmp(base, "chgrp");
    bool ln = !strcmp(base, "ln"), rsync = !strcmp(base, "rsync"), inst = !strcmp(base, "install");
    bool all = !strcmp(base, "touch") || !strcmp(base, "mkdir") || !strcmp(base, "rmdir") ||
               !strcmp(base, "truncate");
    if (!all && !chmod_ && !owner && !ln && !rsync && !inst) return NULL;
    /* options whose separate value is not a file being written */
    const char *valued = !strcmp(base, "touch") ? "rtdA" : !strcmp(base, "truncate") ? "sr"
        : !strcmp(base, "mkdir") ? "m" : inst ? "mogSBf" : rsync ? "ef" : "";
    bool symbolic = false, dirs = false, moves = false, opts = true, mode_seen = false;
    const char *target = NULL;
    char **p = malloc((size_t)(na + 1) * sizeof *p);
    int np = 0;
    for (int k = 0; k < na; k++) {
        char *w = a[k];
        if (opts && !strcmp(w, "--")) { opts = false; continue; }
        if (opts && w[0] == '-' && w[1]) {
            if (chmod_ && strspn(w + 1, "rwxXst,+=ugoa") == strlen(w + 1)) { mode_seen = true; continue; }
            if (!strncmp(w, "--reference=", 12)) mode_seen = true;
            if (!strncmp(w, "--target-directory=", 19)) target = w + 19;
            if (!strcmp(w, "--symbolic")) symbolic = true;
            if (!strcmp(w, "--directory")) dirs = true;
            if (!strcmp(w, "--remove-source-files")) moves = true;
            if (w[1] == '-') continue;
            if (ln && strchr(w, 's')) symbolic = true;
            if (inst && strchr(w, 'd')) dirs = true;
            if ((ln || inst) && !strcmp(w, "-t") && k + 1 < na) target = a[++k];
            else if (strchr(valued, w[strlen(w) - 1])) k++;
            continue;
        }
        if ((chmod_ || owner) && !mode_seen) { mode_seen = true; continue; }
        p[np++] = w;
    }
    const char *err = NULL;
    if (target && !target_ok(target, cwd)) err = E_OUTSIDE;
    for (int k = 0; !err && k < np; k++) {
        bool check;
        if (ln)           /* a hard link makes the source itself writable here */
            check = !symbolic || (!target && np > 1 && k == np - 1);
        else if (rsync)
            check = np > 1 && (moves || k == np - 1);
        else if (inst)
            check = dirs || (!target && np > 1 && k == np - 1);
        else check = true;
        if (check && !target_ok(p[k], cwd)) err = E_OUTSIDE;
    }
    free(p);
    return err;
}

/* inspect one simple command (words after quote removal) */
static const char *check_simple(char **v, int n, const char *cwd, int depth) {
    static const char *const kw[] = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "time", NULL};
    static const char *const wrap[] = {"env", "nohup", "command", "exec", "nice", "xargs", "timeout", "setsid", NULL};
    static const char *const shells[] = {"sh", "bash", "zsh", "dash", NULL};
    int i = 0;
    bool wrapped = false;
    const char *base = NULL;
    for (; i < n; i++) {
        const char *w = v[i];
        const char *eq = strchr(w, '=');
        if (eq && eq > w && !memchr(w, '/', (size_t)(eq - w)) && w[0] != '-') continue;
        if (one_of(w, kw)) continue;
        if (wrapped && (w[0] == '-' || isdigit((unsigned char)w[0]))) continue;
        base = strrchr(w, '/') ? strrchr(w, '/') + 1 : w;
        if (!one_of(base, wrap)) break;
        wrapped = true;
    }
    if (i >= n) return NULL;
    if (strchr(v[i], OPAQUE)) return E_RULE;
    char **a = v + i + 1;
    int na = n - i - 1;

    if (!strcmp(base, "sudo") || !strcmp(base, "doas") || !strcmp(base, "shutdown") ||
        !strcmp(base, "reboot") || !strncmp(base, "mkfs", 4))
        return E_RULE;
    if (!strcmp(base, "eval")) {                  /* eval joins its arguments */
        size_t len = 1;
        for (int k = 0; k < na; k++) len += strlen(a[k]) + 1;
        char *j = malloc(len), *q = j;
        for (int k = 0; k < na; k++) q += sprintf(q, "%s ", a[k]);
        *q = 0;
        const char *e = strchr(j, OPAQUE) ? E_RULE : scan_script(j, cwd, depth + 1);
        free(j);
        return e;
    }
    if (one_of(base, shells)) {
        bool c = false;
        for (int k = 0; k < na; k++) {
            const char *o = a[k];
            if ((o[0] == '-' || o[0] == '+') && o[1]) {
                if (!strcmp(o, "--rcfile") || !strcmp(o, "--init-file")) k++;
                else if (o[1] != '-') {
                    if (o[0] == '-' && strchr(o, 'c')) c = true;
                    if (strchr("oO", o[strlen(o) - 1])) k++;   /* takes a value */
                }
                continue;
            }
            if (!c) break;
            if (strchr(o, OPAQUE)) return E_RULE;   /* would be re-parsed */
            return scan_script(o, cwd, depth + 1);
        }
        return NULL;
    }
    if (!strcmp(base, "find")) return check_find(a, na, cwd, depth);
    if (!strcmp(base, "sed") || !strcmp(base, "gsed")) return check_inplace(false, a, na, cwd);
    if (!strcmp(base, "perl")) return check_inplace(true, a, na, cwd);
    if (!strcmp(base, "git")) return check_git(a, na, cwd);
    bool rm = !strcmp(base, "rm"), tee = !strcmp(base, "tee");
    bool cp = !strcmp(base, "cp"), mv = !strcmp(base, "mv");
    if (!rm && !tee && !cp && !mv) return check_operands(base, a, na, cwd);
    bool recursive = false, opts = true;
    const char *target = NULL, *last = NULL;
    int nargs = 0;
    for (int k = 0; k < na; k++) {
        const char *w = a[k];
        if (opts && !strcmp(w, "--")) { opts = false; continue; }
        if (opts && w[0] == '-' && w[1]) {
            if (!strcmp(w, "--recursive") || (w[1] != '-' && (strchr(w, 'r') || strchr(w, 'R'))))
                recursive = true;
            if ((cp || mv) && !strcmp(w, "-t") && k + 1 < na) target = a[++k];
            if ((cp || mv) && !strncmp(w, "--target-directory=", 19)) target = w + 19;
            continue;
        }
        nargs++;
        last = w;
        if (tee && !path_ok(w, cwd)) return E_OUTSIDE;
        if (mv && !path_ok(w, cwd)) return E_OUTSIDE;
    }
    if (rm && recursive) {
        opts = true;
        for (int k = 0; k < na; k++) {
            if (opts && !strcmp(a[k], "--")) { opts = false; continue; }
            if (opts && a[k][0] == '-') continue;
            if (!target_ok(a[k], cwd)) return E_RULE;
        }
    } else if (rm) {
        opts = true;
        for (int k = 0; k < na; k++) {
            if (opts && !strcmp(a[k], "--")) { opts = false; continue; }
            if (opts && a[k][0] == '-' && a[k][1]) continue;
            if (!target_ok(a[k], cwd)) return E_OUTSIDE;
        }
    }
    if ((cp || mv) && target && !path_ok(target, cwd)) return E_OUTSIDE;
    if (cp && !target && nargs >= 2 && !path_ok(last, cwd)) return E_OUTSIDE;
    return NULL;
}

/* Walk a script: split into simple commands, check redirect targets, skip
   heredoc payloads and comments (they're data, not shell syntax). */
static const char *scan_script(const char *s, const char *cwd, int depth) {
    if (depth > 4) return E_RULE;   /* too deep to check: fail closed */
    char *arena = malloc(2 * strlen(s) + 2), *top = arena;
    char *v[MAXWORDS];
    char delim[MAXHEREDOC][64];
    bool dash[MAXHEREDOC];
    int n = 0, nd = 0;
    bool redir_out = false, redir_in = false;
    const char *err = NULL, *p = s;
    while (!err) {
        char c = *p;
        if (c == ' ' || c == '\t' || c == '\r') { p++; continue; }
        if (c == '\\' && p[1] == '\n') { p += 2; continue; }
        if (c == '#') { while (*p && *p != '\n') p++; continue; }
        if (c == '$' && p[1] == '(' && p[2] == '(') {   /* arithmetic */
            const char *e = strstr(p + 3, "))");
            /* skip only plain arithmetic; anything else is scanned */
            if (e && strspn(p + 3, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "0123456789_ $+-*/%<>=!?:^~.") >= (size_t)(e - p - 3)) {
                p = e + 2;
                continue;
            }
        }
        if (c == '>' || (c == '&' && p[1] == '>')) {
            p += c == '&' ? 2 : 1;
            if (*p == '>' || *p == '|') p++;
            if (*p == '&') {
                p++;
                if (isdigit((unsigned char)*p) || *p == '-') { p++; continue; }
            }
            if (*p != '(') redir_out = true;
            continue;
        }
        if (c == '<') {
            if (p[1] == '<' && p[2] == '<') { p += 3; continue; }
            if (p[1] == '<') {
                p += 2;
                bool d = *p == '-';
                if (d) p++;
                while (*p == ' ' || *p == '\t') p++;
                char *w = top;
                read_word(&p, w, NULL);
                if (*w && nd < MAXHEREDOC && strlen(w) < sizeof delim[0]) {
                    strcpy(delim[nd], w);
                    dash[nd++] = d;
                }
                continue;
            }
            p++;
            if (*p != '(') redir_in = true;
            continue;
        }
        if (!c || strchr("\n;&|()`", c)) {
            if (n) err = check_simple(v, n, cwd, depth);
            n = 0;
            redir_out = redir_in = false;
            if (!c) break;
            p++;
            if (c == '\n') {
                for (int h = 0; h < nd; h++) {
                    size_t dl = strlen(delim[h]);
                    for (const char *l = p; *l; ) {
                        const char *t = l;
                        if (dash[h]) while (*t == '\t') t++;
                        const char *nl = strchr(l, '\n');
                        if (!strncmp(t, delim[h], dl) && (!t[dl] || t[dl] == '\n')) {
                            p = nl ? nl + 1 : t + dl;
                            break;
                        }
                        if (!nl) break;   /* unterminated: keep scanning it */
                        l = nl + 1;
                    }
                }
                nd = 0;
            }
            continue;
        }
        const char *sub;
        char *w = top;
        read_word(&p, w, &sub);
        top += strlen(w) + 1;
        if (sub) err = scan_script(sub, cwd, depth + 1);
        if (!err && redir_out) {
            if (!path_ok(w, cwd)) err = E_OUTSIDE;
        } else if (!redir_in) {
            bool fd = *p == '>' && *w && strspn(w, "0123456789") == strlen(w);
            if (!fd) {
                if (n < MAXWORDS) v[n++] = w;
                else err = E_RULE;
            }
        }
        redir_out = redir_in = false;
    }
    free(arena);
    return err;
}

char *deny_check(const char *cmd, const char *cwd) {
    for (int i = 0; DENY_SUBSTR[i]; i++)
        if (strstr(cmd, DENY_SUBSTR[i]))
            return (char *)E_RULE;
    /* "rm -rf /" and "rm -rf ~" exactly, wherever they appear (incl. heredocs
       fed to a shell); /tmp/x and friends are judged by the scan below */
    static const char *const ROOTS[] = {"rm -rf /", "rm -rf ~", NULL};
    for (int i = 0; ROOTS[i]; i++)
        for (const char *p = cmd; (p = strstr(p, ROOTS[i])); p++) {
            char nx = p[strlen(ROOTS[i])];
            if (!nx || strchr(" \t\n*;\"')&|", nx)) return (char *)E_RULE;
        }
    return (char *)scan_script(cmd, cwd, 0);
}

/* does this payload line open another heredoc using `delim`? */
static bool line_opens(const char *l, size_t len, const char *delim) {
    const char *end = l + len;
    size_t dl = strlen(delim);
    for (const char *p = l; p + 2 < end; p++) {
        if (p[0] != '<' || p[1] != '<') continue;
        const char *q = p + 2;
        if (q < end && *q == '-') q++;
        while (q < end && (*q == ' ' || *q == '\t')) q++;
        if (q < end && (*q == '\'' || *q == '"' || *q == '\\')) q++;
        if (q + dl <= end && !strncmp(q, delim, dl) &&
            (q + dl == end || !(isalnum((unsigned char)q[dl]) || q[dl] == '_')))
            return true;
    }
    return false;
}

/* Rewrite a standard heredoc delimiter (EOF/EOT/END) to a unique token
   when the delimiter string appears more than twice (opener + closer) —
   the payload is colliding and bash would truncate the write early.
   Only the opener and the closing delimiter line are renamed; payload
   bytes are never touched. */
char *heredoc_fix(const char *cmd) {
    static int n;
    const char *p = strstr(cmd, "<<");
    if (!p) return str_dup(cmd);
    const char *q = p + 2;
    bool dash = *q == '-';
    if (dash) q++;
    while (*q == ' ' || *q == '\t') q++;
    if (*q == '\'' || *q == '"') q++;
    char delim[64] = {0};
    int dl = 0;
    while (q[dl] && (isalnum((unsigned char)q[dl]) || q[dl] == '_') && dl < 63)
        delim[dl] = q[dl], dl++;
    delim[dl] = 0;
    if (!dl || (strcmp(delim, "EOF") && strcmp(delim, "EOT") && strcmp(delim, "END")))
        return str_dup(cmd);

    /* closer = last bare delimiter line before another such heredoc opens;
       heredocs nested in the payload consume their own closer */
    const char *closer = NULL, *l = strchr(q, '\n');
    int depth = 0;
    while (l) {
        l++;
        const char *nl = strchr(l, '\n');
        size_t len = nl ? (size_t)(nl - l) : strlen(l);
        const char *t = l;
        if (dash) while (*t == '\t') t++;
        if ((size_t)(l + len - t) == (size_t)dl && !strncmp(t, delim, dl)) {
            if (depth > 0) depth--;
            else closer = t;
        } else if (line_opens(l, len, delim)) {
            if (closer && !depth) break;
            depth++;
        }
        l = nl;
    }
    if (!closer) return str_dup(cmd);

    /* count token-bounded occurrences within this heredoc */
    int occ = 0;
    for (const char *r = strstr(cmd, delim); r && r <= closer; r = strstr(r + dl, delim)) {
        bool pre = (r == cmd) || strchr(" \t\n;<-('\"", r[-1]) != NULL;
        bool post = !r[dl] || strchr(" \t\n;')\"", r[dl]) != NULL;
        if (pre && post) occ++;
    }
    if (occ <= 2) return str_dup(cmd);

    char nd[80];
    snprintf(nd, sizeof nd, "FW_EOF_%d", ++n);
    size_t cap = strlen(cmd) + 2 * strlen(nd) + 1;
    char *out = malloc(cap);
    snprintf(out, cap, "%.*s%s%.*s%s%s", (int)(q - cmd), cmd, nd,
             (int)(closer - (q + dl)), q + dl, nd, closer + dl);
    return out;
}

bool cmd_is_write(const char *cmd) {
    /* crude port of agentrun7 is_write: '>' to non-tmp, tee, sed -i */
    char c[8192];
    snprintf(c, sizeof c, "%s", cmd);
    /* strip innocuous redirects */
    char *x;
    while ((x = strstr(c, "2>&1"))) memmove(x, x + 4, strlen(x + 4) + 1);
    while ((x = strstr(c, "2>/dev/null"))) memmove(x, x + 11, strlen(x + 11) + 1);
    while ((x = strstr(c, ">/dev/null"))) memmove(x, x + 10, strlen(x + 10) + 1);
    Range hr[8];
    int nhr = heredoc_ranges(c, hr, 8);
    for (const char *p = c; (p = strchr(p, '>')); p++) {
        if (in_ranges(hr, nhr, p)) continue;
        if (p > c && (p[-1] == '>' || p[-1] == '<' || p[-1] == '=' || p[-1] == '-')) continue;
        const char *q = p + 1;
        if (*q == '>') q++;
        while (*q == ' ' || *q == '\t') q++;
        if (!strncmp(q, "/tmp/", 5) || !strncmp(q, "/dev/", 5)) continue;
        if (*q) return true;
    }
    if (strstr(c, "tee ") && !strstr(c, "tee /tmp/")) return true;
    if (strstr(c, "sed -i")) return true;
    return false;
}

/* replace invalid UTF-8 bytes with '?' and drop stray control chars
   (except \n \t \r) — raw shell bytes would poison the JSON request body
   and the server 400s (seen on ndjson: finish=error invalid_request). */
void utf8_sanitize(char *s) {
    unsigned char *r = (unsigned char *)s, *w = (unsigned char *)s;
    while (*r) {
        unsigned char c = *r;
        int len = 0;
        if (c < 0x20) {
            if (c == '\n' || c == '\t' || c == '\r') *w++ = c;
            r++;
            continue;
        }
        if (c < 0x80) len = 1;
        else if (c >= 0xC2 && c < 0xE0) len = 2;
        else if (c >= 0xE0 && c < 0xF0) len = 3;
        else if (c >= 0xF0 && c < 0xF5) len = 4;
        if (!len) { *w++ = '?'; r++; continue; }
        int ok = 1;
        for (int i = 1; i < len; i++)
            if ((r[i] & 0xC0) != 0x80) { ok = 0; break; }
        if (len == 3 && r[1] && ((c == 0xE0 && r[1] < 0xA0) || (c == 0xED && r[1] > 0x9F))) ok = 0;
        if (len == 4 && r[1] && ((c == 0xF0 && r[1] < 0x90) || (c == 0xF4 && r[1] > 0x8F))) ok = 0;
        if (!ok) { *w++ = '?'; r++; continue; }
        for (int i = 0; i < len; i++) *w++ = r[i];
        r += len;
    }
    *w = 0;
}

#define OUT_CAP (32 * 1024)

/* Read until EAGAIN/EOF or max_reads. buf stays bounded: once full, keep the
   head and the newest tail. Returns true if data may still be waiting. */
static bool drain_pipe(int fd, char *buf, size_t *len, int max_reads) {
    for (int i = 0; i < max_reads; i++) {
        char tmp[8192];
        ssize_t r = read(fd, tmp, sizeof tmp);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        if (*len + (size_t)r > OUT_CAP) {
            memmove(buf + 4096, buf + *len - 8192, 8192);
            *len = 4096 + 8192;
        }
        memcpy(buf + *len, tmp, (size_t)r);
        *len += (size_t)r;
    }
    return true;
}

char *run_bash(const char *cmd, const char *cwd, int timeout_s) {
    return run_bash_status(cmd, cwd, timeout_s, NULL);
}

char *run_bash_status(const char *cmd, const char *cwd, int timeout_s, int *code) {
    if (code) *code = -1;
    int fds[2];
    if (pipe(fds)) return str_dup("error: pipe failed");
    fcntl(fds[0], F_SETFL, O_NONBLOCK);

    pid_t pid = fork();
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], 1); dup2(fds[1], 2);
        close(fds[1]);
        /* children must not steal keystrokes from the TUI */
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) { dup2(devnull, 0); close(devnull); }
        chdir(cwd);
        setpgid(0, 0);
        execl("/bin/bash", "bash", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    char *buf = malloc(OUT_CAP + 1);
    size_t len = 0;
    int status = 0;
    bool timed = false;
    struct timespec t0, now;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        bool more = drain_pipe(fds[0], buf, &len, 64);
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) break;
        if (fw_tick_hook) fw_tick_hook();
        if (!more) usleep(20000);
        clock_gettime(CLOCK_MONOTONIC, &now);
        double waited = (now.tv_sec - t0.tv_sec) + (now.tv_nsec - t0.tv_nsec) / 1e9;
        if ((timeout_s > 0 && waited >= timeout_s) || g_abort) { /* hung, or user Esc */
            timed = true;
            killpg(pid, SIGKILL);
            waitpid(pid, &status, 0);
            break;
        }
    }
    /* drain what is left; bounded so a surviving background writer can't pin us */
    drain_pipe(fds[0], buf, &len, 1024);
    close(fds[0]);
    buf[len] = 0;
    utf8_sanitize(buf);
    if (code && !timed && WIFEXITED(status)) *code = WEXITSTATUS(status);
    char *out;
    if (timed) {
        out = malloc(len + 160);
        snprintf(out, len + 160,
                 "[timeout after %ds — command hung; check infinite loop, open handle, unresolved stream/promise]\n%s",
                 timeout_s, buf);
        free(buf);
    } else out = buf;
    if (!*out) { free(out); out = str_dup("(no output)"); }
    /* middle-truncate at 4000 chars */
    size_t L = strlen(out);
    if (L > 4000) {
        char *t = malloc(4100);
        memcpy(t, out, 2000);
        int off = snprintf(t + 2000, 100, "\n...[truncated]...\n");
        memcpy(t + 2000 + off, out + L - 2000, 2000);
        t[2000 + off + 2000] = 0;
        free(out); out = t;
    }
    return out;
}

/* ---------- permission rules (claude-code style) ----------
   builtin safe read-only prefixes + persisted rules from
   ~/.config/flywheel/allow and the per-project file
   ~/.config/flywheel/projects/<hash of project realpath>.allow.
   Nothing inside the project is trusted: a cloned repo must not be able
   to grant itself permissions.
   A rule matches when the command equals it or starts with it
   followed by a space or tab. */

static const char *BUILTIN_ALLOW[] = {
    "ls", "cat", "grep", "rg", "find", "fd", "head", "tail", "wc", "echo",
    "pwd", "file", "stat", "which", "cd", "true",
    "printf", "test", "sort", "uniq", "tr", "cut",
    NULL
};

#define MAX_RULES 256
static char *rules[MAX_RULES];
static int nrules;
static bool rules_loaded;

static bool rule_match(const char *rule, const char *cmd) {
    size_t n = strlen(rule);
    if (!n) return false;
    if (strncmp(cmd, rule, n)) return false;
    return cmd[n] == 0 || cmd[n] == ' ' || cmd[n] == '\t';
}

static void perm_load_file(const char *path) {
    char *c = read_file(path);
    if (!c) return;
    for (char *ln = strtok(c, "\n"); ln; ln = strtok(NULL, "\n")) {
        while (*ln == ' ') ln++;
        if (!*ln || *ln == '#') continue;
        char *e = ln + strlen(ln) - 1;
        while (e > ln && (*e == ' ' || *e == '\r')) *e-- = 0;
        if (nrules < MAX_RULES) rules[nrules++] = str_dup(ln);
    }
    free(c);
}

bool perm_project_file(char *out, size_t cap) {
    const char *home = getenv("HOME");
    if (!home || !*home || !g_cfg.cwd) return false;
    char real[PATH_MAX];
    if (!realpath(g_cfg.cwd, real)) return false;
    unsigned long long h = 14695981039346656037ULL;   /* FNV-1a */
    for (const unsigned char *p = (const unsigned char *)real; *p; p++)
        h = (h ^ *p) * 1099511628211ULL;
    int n = snprintf(out, cap, "%s/.config/flywheel/projects/%016llx.allow", home, h);
    return n > 0 && (size_t)n < cap;
}

void perm_load(void) {
    if (rules_loaded) return;
    rules_loaded = true;
    char p[PATH_MAX];
    const char *home = getenv("HOME");
    if (home) {
        snprintf(p, sizeof p, "%s/.config/flywheel/allow", home);
        perm_load_file(p);
    }
    if (perm_project_file(p, sizeof p)) perm_load_file(p);
}

/* chaining, redirection, substitution: a prefix match proves nothing */
static bool has_shell_meta(const char *cmd) {
    return strpbrk(cmd, ";&|<>`\n\r") || strstr(cmd, "$(");
}

/* Positive rule: expansion syntax is only tolerated inside single quotes.
   Expansions can run code (${x:=..} fed to a later arithmetic context) or turn
   into flags the checks below never see (braces, globs). */
static bool has_expansion(const char *cmd) {
    char q = 0;
    for (const char *p = cmd; *p; p++) {
        if (q == '\'') { if (*p == q) q = 0; continue; }
        if (strchr("$`\\{}()", *p)) return true;
        if (q) { if (*p == q) q = 0; continue; }
        if (*p == '*' || *p == '?' || (*p == '[' && strchr(p + 1, ']'))) return true;  /* globs */
        if (*p == '~' && (p == cmd || strchr(" \t=:", p[-1]))) return true;
        if (*p == '\'' || *p == '"') q = *p;
    }
    return q != 0;
}

/* is a (up to '=') an abbreviation, at least min long, of the long option? */
static bool abbrev(const char *a, const char *full, size_t min) {
    size_t n = strcspn(a, "=");
    return n >= min && n <= strlen(full) && !strncmp(a, full, n);
}

/* printf's %n assigns to a variable named by an argument */
static bool has_percent_n(const char *s) {
    for (; (s = strchr(s, '%')); s++)
        if (s[1 + strspn(s + 1, "-+ #'0123456789.*hlLjzt")] == 'n') return true;
    return false;
}

/* %G, %+GG, % G? ...: verifying a signature runs the repo's gpg.program */
static bool has_sig_format(const char *s) {
    for (; (s = strchr(s, '%')); s++)
        if (s[1 + strspn(s + 1, "+- ")] == 'G') return true;
    return false;
}

/* read-only-looking commands whose flags can write or execute */
static bool has_mutating_args(const char *cmd) {
    char *arena = malloc(2 * strlen(cmd) + 2), *top = arena;
    char *v[MAXWORDS];
    int n = 0;
    bool bad = false;
    for (const char *p = cmd; *p; ) {
        if (strchr(" \t()", *p)) { p++; continue; }
        if (n == MAXWORDS) { bad = true; break; }
        read_word(&p, top, NULL);
        v[n++] = top;
        top += strlen(top) + 1;
    }
    const char *c = n ? v[0] : "";
    if (strrchr(c, '/')) c = strrchr(c, '/') + 1;
    bool find = !strcmp(c, "find"), fd = !strcmp(c, "fd"), sort = !strcmp(c, "sort");
    bool rg = !strcmp(c, "rg"), uniq = !strcmp(c, "uniq"), git = !strcmp(c, "git") && n > 1;
    bool branch = git && !strcmp(v[1], "branch");
    bool file = !strcmp(c, "file"), pf = !strcmp(c, "printf");
    bool tst = !strcmp(c, "test") || !strcmp(c, "[");
    bool tsc = !strcmp(c, "npx") && n > 1 && !strcmp(v[1], "tsc"), noemit = false;
    bool opts = true;
    int plain = 0;
    for (int i = 1; i < n && !bad; i++) {
        const char *a = v[i];
        bool shortopt = a[0] == '-' && a[1] != '-';
        if ((find || fd || sort || rg || git) && (strchr(a, '$') || strchr(a, '{'))) bad = true;
        if (find && (!strcmp(a, "-delete") || !strncmp(a, "-exec", 5) || !strncmp(a, "-ok", 3) ||
                     !strncmp(a, "-fprint", 7) || !strcmp(a, "-fls"))) bad = true;
        if (fd && (!strncmp(a, "--exec", 6) || (shortopt && (strchr(a, 'x') || strchr(a, 'X'))))) bad = true;
        if (sort && (!strncmp(a, "--o", 3) || !strncmp(a, "--co", 4) || (shortopt && strchr(a, 'o')))) bad = true;
        if (rg && (!strncmp(a, "--pre", 5) || !strncmp(a, "--hostname-bin", 14) ||
                   !strncmp(a, "--search-zip", 12) || (shortopt && strchr(a, 'z')))) bad = true;
        if (git && (!strncmp(a, "--output", 8) || abbrev(a, "--output", 3) || abbrev(a, "--ext-diff", 4) ||
                    (abbrev(a, "--textconv", 5) && strcmp(a, "--text")) ||
                    abbrev(a, "--show-signature", 8) || strstr(a, "signature") || has_sig_format(a))) bad = true;
        if (uniq) {   /* a second operand is the output file; "-" is an operand */
            if (opts && !strcmp(a, "--")) opts = false;
            else if (!opts || a[0] != '-' || !a[1]) {
                opts = false;   /* BSD uniq does not permute: the rest are operands */
                if (++plain > 1) bad = true;
            }
        }
        if (file) {   /* only flags known not to compile, decompress or unsandbox */
            static const char *const longs[] = {"--brief", "--mime", "--mime-type",
                "--mime-encoding", "--dereference", "--no-dereference", NULL};
            if (a[0] == '-' && a[1] == '-' && !one_of(a, longs)) bad = true;
            if (shortopt && a[1 + strspn(a + 1, "bhiIkLNnrs0")]) bad = true;
        }
        if ((pf || tst) && (strchr(a, '$') || !strncmp(a, "-v", 2))) bad = true;
        if (pf && has_percent_n(a)) bad = true;
        if (tsc && i > 1) {   /* anything not listed may emit files */
            static const char *const check[] = {"--pretty", "--strict", "--skipLibCheck", NULL};
            if (!strcmp(a, "--noEmit")) noemit = true;
            else if (!strcmp(a, "-p") && i + 1 < n && v[i + 1][0] != '-') i++;
            else if (!one_of(a, check)) bad = true;
        }
        if (branch && i > 1) {
            static const char *const listing[] = {"-a", "-r", "-v", "-vv", "-av", "--list", "--all",
                "--remotes", "--verbose", "--show-current", "--merged", "--no-merged", "--no-color", NULL};
            if (!one_of(a, listing) && strncmp(a, "--sort=", 7) && strncmp(a, "--format=", 9) &&
                strncmp(a, "--color", 7)) bad = true;
        }
    }
    if (tsc && !noemit) bad = true;
    free(arena);
    return bad;
}

/* does a read of `p` stay inside the project? */
static bool read_inside(const char *p) {
    if (!*p || !strcmp(p, "-") || !strcmp(p, "/dev/null")) return true;
    bool away = p[0] == '/' || p[0] == '~';
    for (const char *d = p; !away && (d = strstr(d, "..")); d += 2)
        away = (d == p || d[-1] == '/') && (!d[2] || d[2] == '/');
    const char *cwd = g_cfg.cwd;
    char root[PATH_MAX], abs[PATH_MAX], real[PATH_MAX], norm[PATH_MAX];
    if (!cwd || !realpath(cwd, root)) return !away;
    if (p[0] == '~') return false;
    int n = p[0] == '/' ? snprintf(abs, sizeof abs, "%s", p) : snprintf(abs, sizeof abs, "%s/%s", cwd, p);
    if (n < 0 || (size_t)n >= sizeof abs) return false;
    /* existing paths are judged by where their symlinks really lead */
    if (realpath(abs, real)) return is_within(root, real);
    if (!away) return true;
    return lex_normalize(abs, norm, sizeof norm) && (is_within(cwd, norm) || is_within(root, norm));
}

/* a builtin reader given a path outside the project must prompt */
static bool reads_outside(const char *cmd) {
    static const char *const readers[] = {"ls", "cat", "grep", "rg", "find", "fd", "head", "tail",
        "wc", "file", "stat", "cd", "test", "sort", "uniq", "cut", NULL};
    char *buf = malloc(strlen(cmd) + 1);
    const char *p = cmd;
    read_word(&p, buf, NULL);
    bool out = false, cut = !strcmp(buf, "cut"), sort = !strcmp(buf, "sort");
    if (one_of(buf, readers))
        while (!out && *p) {
            if (strchr(" \t()", *p)) { p++; continue; }
            read_word(&p, buf, NULL);
            const char *path = buf;
            if (buf[0] == '-' && buf[1]) {
                const char *eq = strchr(buf, '=');
                if (buf[1] == '-') path = eq ? eq + 1 : "";
                else if ((cut && buf[1] == 'd') || (sort && buf[1] == 't')) path = "";   /* delimiter */
                else {   /* attached value: -f/etc/x, -nf../x */
                    path = buf + 1 + strcspn(buf + 1, "/~.");
                }
            }
            out = !read_inside(path);
        }
    free(buf);
    return out;
}

bool perm_allowed(const char *cmd) {
    perm_load();
    while (*cmd == ' ') cmd++;
    /* a leading VAR=value makes the real command whatever follows it */
    if (cmd[strcspn(cmd, "= \t")] == '=') return false;
    if (has_shell_meta(cmd) || has_expansion(cmd) || has_mutating_args(cmd)) return false;
    if (reads_outside(cmd)) return false;
    for (int i = 0; BUILTIN_ALLOW[i]; i++)
        if (rule_match(BUILTIN_ALLOW[i], cmd)) return true;
    for (int i = 0; i < nrules; i++)
        if (rule_match(rules[i], cmd)) return true;
    return false;
}

void perm_add_rule(const char *rule) {
    perm_load();
    for (int i = 0; i < nrules; i++)
        if (!strcmp(rules[i], rule)) return;
    if (nrules < MAX_RULES) rules[nrules++] = str_dup(rule);
    char p[PATH_MAX];
    if (!perm_project_file(p, sizeof p) || !mkdir_parents(p)) return;
    FILE *f = fopen(p, "a");
    if (f) { fprintf(f, "%s\n", rule); fclose(f); }
}

/* would remembering this command's prefix whitelist arbitrary code? */
static bool runs_inline_code(const char *cmd) {
    static const char *const interp[] = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ruby", "perl",
        "php", "lua", "awk", "gawk", "osascript", "deno", "bun", "swift", "tclsh", "Rscript", "env",
        "xargs", "eval", "exec", "command", "nohup", "nice", "timeout", "setsid", "time", "source",
        ".", "ssh", "su", "parallel", NULL};
    char *a = malloc(strlen(cmd) + 1), *b = malloc(strlen(cmd) + 1);
    const char *p = cmd;
    while (*p == ' ' || *p == '\t') p++;
    read_word(&p, a, NULL);
    while (*p == ' ' || *p == '\t') p++;
    read_word(&p, b, NULL);
    const char *base = strrchr(a, '/') ? strrchr(a, '/') + 1 : a;
    bool script = !strcmp(a, "python") || !strcmp(a, "python3") || !strcmp(a, "node");
    bool multi = script || !strcmp(a, "git") || !strcmp(a, "npx") || !strcmp(a, "npm") ||
                 !strcmp(a, "brew") || !strcmp(a, "go") || !strcmp(a, "cargo");
    bool bad = one_of(base, interp) || strstr(cmd, "--eval") != NULL;
    /* the rule is "tool second-word": a flag or nothing there covers any code */
    if (multi && (*b == '-' || !*b)) bad = true;
    /* python3.12, /usr/bin/node, nodejs: same interpreters under other names */
    size_t stem = !strncmp(base, "python", 6) ? 6 : !strncmp(base, "nodejs", 6) ? 6
                : !strncmp(base, "node", 4) ? 4 : 0;
    if (!script && stem && !base[stem + strspn(base + stem, "0123456789.")]) bad = true;
    if (!strcmp(a, "npm") && (!strcmp(b, "exec") || !strcmp(b, "x"))) bad = true;
    free(a);
    free(b);
    return bad;
}

/* "always" rule derived from a command: first token, or first two
   tokens for multiword tools. "" = nothing safe to remember. */
char *perm_prefix(const char *cmd) {
    while (*cmd == ' ') cmd++;
    if (runs_inline_code(cmd)) return str_dup("");
    static const char *two[] = {"git", "npx", "npm", "brew", "go", "cargo", "python3", "python", "node", NULL};
    char first[128] = {0};
    int i = 0;
    while (cmd[i] && cmd[i] != ' ' && cmd[i] != '\t' && i < 127) { first[i] = cmd[i]; i++; }
    bool two_tok = false;
    for (int j = 0; two[j]; j++) if (!strcmp(first, two[j])) two_tok = true;
    if (!two_tok) return str_dup(first);
    char out[260];
    snprintf(out, sizeof out, "%s", first);
    const char *p = cmd + i;
    while (*p == ' ' || *p == '\t') p++;
    int k = strlen(out);
    out[k++] = ' ';
    while (*p && *p != ' ' && *p != '\t' && k < 250) out[k++] = *p++;
    out[k] = 0;
    return str_dup(out);
}

void perm_free(void) {
    for (int i = 0; i < nrules; i++) { free(rules[i]); rules[i] = NULL; }
    nrules = 0;
    rules_loaded = false;
}

/* ---------- structured file tools (write_file / edit_file) ---------- */

/* Lexically normalize a path: resolve "." and ".." without touching the fs.
   Returns false if ".." escapes the root. out must hold cap bytes. */
static bool lex_normalize(const char *in, char *out, size_t cap) {
    if (!in || !*in || in[0] != '/') return false;
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof tmp, "%s", in);
    char *segs[256];
    int n = 0;
    char *save = NULL;
    for (char *tok = strtok_r(tmp, "/", &save); tok; tok = strtok_r(NULL, "/", &save)) {
        if (!strcmp(tok, ".")) continue;
        if (!strcmp(tok, "..")) {
            if (n == 0) return false;   /* escapes root */
            n--;
            continue;
        }
        if (n < 256) segs[n++] = tok;
    }
    size_t w = 0;
    out[w++] = '/';
    for (int i = 0; i < n; i++) {
        size_t l = strlen(segs[i]);
        if (w + l + 2 >= cap) return false;
        memcpy(out + w, segs[i], l);
        w += l;
        if (i < n - 1) out[w++] = '/';
    }
    out[w] = 0;
    return true;
}

static bool is_within(const char *base, const char *path) {
    size_t bl = strlen(base);
    if (!strncmp(base, path, bl))
        return path[bl] == 0 || path[bl] == '/' || (bl > 0 && base[bl - 1] == '/');
    return false;
}

/* mkdir -p for the parent directory of path (path must be absolute). */
static bool mkdir_parents(const char *path) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof tmp, "%s", path);
    char *slash = strrchr(tmp, '/');
    if (!slash || slash == tmp) return true;
    *slash = 0;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, 0755) && errno != EEXIST) return false;
            *p = '/';
        }
    }
    return !(mkdir(tmp, 0755) && errno != EEXIST);
}

/* Resolve `path` (absolute or cwd-relative) to a confined absolute path.
   Fills `out` with the symlink-free path on success and returns NULL;
   otherwise returns a static error string. When `for_write`, parent dirs
   are created. Every component is checked before it is used, so nothing is
   ever created through a link that leaves cwd; dangling links are refused. */
const char *resolve_confined(const char *cwd, const char *path, char *out, size_t cap, bool for_write) {
    if (!path || !*path) return "error: empty path";
    for (const unsigned char *p = (const unsigned char *)path; *p; p++)
        if (*p < 0x20) return "error: control characters in path";

    char absbuf[PATH_MAX];
    if (path[0] == '/') snprintf(absbuf, sizeof absbuf, "%s", path);
    else snprintf(absbuf, sizeof absbuf, "%s/%s", cwd, path);

    char norm[PATH_MAX];
    if (!lex_normalize(absbuf, norm, sizeof norm))
        return "error: path escapes working dir";

    char realcwd[PATH_MAX];
    if (!realpath(cwd, realcwd)) snprintf(realcwd, sizeof realcwd, "%s", cwd);

    /* lexical confinement first */
    const char *rel;
    if (is_within(realcwd, norm)) rel = norm + strlen(realcwd);
    else if (is_within(cwd, norm)) rel = norm + strlen(cwd);
    else return "error: path escapes working dir";

    char relbuf[PATH_MAX], cur[PATH_MAX];
    snprintf(relbuf, sizeof relbuf, "%s", rel);
    snprintf(cur, sizeof cur, "%s", realcwd);
    char *save = NULL;
    for (char *tok = strtok_r(relbuf, "/", &save); tok; ) {
        char *next_tok = strtok_r(NULL, "/", &save);
        char next[PATH_MAX];
        int nw = snprintf(next, sizeof next, "%s%s%s", cur,
                          cur[strlen(cur) - 1] == '/' ? "" : "/", tok);
        if (nw < 0 || (size_t)nw >= sizeof next) return "error: path too long";
        struct stat st;
        if (!lstat(next, &st) && S_ISLNK(st.st_mode)) {
            char real[PATH_MAX];
            if (!realpath(next, real)) return "error: path goes through a dangling symlink";
            if (!is_within(realcwd, real)) return "error: path escapes working dir through a symlink";
            snprintf(cur, sizeof cur, "%s", real);
        } else {
            if (next_tok && for_write && mkdir(next, 0755) && errno != EEXIST)
                return "error: cannot create parent directories";
            snprintf(cur, sizeof cur, "%s", next);
        }
        tok = next_tok;
    }

    snprintf(out, cap, "%s", cur);
    return NULL;
}

/* never follow a link swapped in after the check above */
static FILE *open_nofollow(const char *path, int flags, const char *mode) {
    int fd = open(path, flags | O_NOFOLLOW, 0666);
    if (fd < 0) return NULL;
    FILE *f = fdopen(fd, mode);
    if (!f) close(fd);
    return f;
}

#define FILETOOL_MAX_CONTENT (4 * 1024 * 1024)

char *tool_write_file(const char *cwd, const char *path, const char *content) {
    char abs[PATH_MAX];
    const char *err = resolve_confined(cwd, path, abs, sizeof abs, true);
    if (err) return str_dup(err);
    if (!content) content = "";
    size_t len = strlen(content);
    if (len > FILETOOL_MAX_CONTENT) return str_dup("error: content too large (4 MiB cap)");

    FILE *f = open_nofollow(abs, O_WRONLY | O_CREAT | O_TRUNC, "w");
    if (!f) {
        char buf[300];
        snprintf(buf, sizeof buf, "error: cannot open %s: %s", path, strerror(errno));
        return str_dup(buf);
    }
    size_t wr = fwrite(content, 1, len, f);
    int bad = ferror(f);
    fclose(f);
    if (bad || wr != len) return str_dup("error: write failed (disk full?)");

    int lines = len ? 1 : 0;
    for (size_t i = 0; i < len; i++) if (content[i] == '\n') lines++;
    char buf[300];
    snprintf(buf, sizeof buf, "ok: wrote %s (%zu bytes, %d lines)", path, len, lines);
    return str_dup(buf);
}

char *tool_edit_file(const char *cwd, const char *path, const char *old_str, const char *new_str) {
    if (!old_str || !*old_str) return str_dup("error: old_string must be non-empty");
    if (!new_str) new_str = "";
    char abs[PATH_MAX];
    const char *err = resolve_confined(cwd, path, abs, sizeof abs, false);
    if (err) return str_dup(err);

    FILE *f = open_nofollow(abs, O_RDONLY, "rb");
    if (!f) {
        char buf[300];
        snprintf(buf, sizeof buf, "error: cannot read %s: %s — use write_file to create it", path, strerror(errno));
        return str_dup(buf);
    }
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsz < 0 || fsz > FILETOOL_MAX_CONTENT) { fclose(f); return str_dup("error: file too large to edit (4 MiB cap)"); }
    char *data = malloc((size_t)fsz + 1);
    size_t rd = fread(data, 1, (size_t)fsz, f);
    fclose(f);
    data[rd] = 0;

    /* count occurrences of old_str */
    size_t ol = strlen(old_str);
    int occ = 0;
    const char *hit = NULL;
    for (const char *p = data; (p = strstr(p, old_str)); p += ol) {
        if (!hit) hit = p;
        occ++;
    }
    if (occ == 0) {
        free(data);
        return str_dup("error: old_string not found in file — re-read the file and match the exact text including whitespace");
    }
    if (occ > 1) {
        char buf[200];
        snprintf(buf, sizeof buf, "error: old_string matches %d places — make it unique by including more surrounding context", occ);
        free(data);
        return str_dup(buf);
    }

    size_t nl = strlen(new_str);
    size_t pre = (size_t)(hit - data);
    size_t post = rd - pre - ol;
    if (nl > FILETOOL_MAX_CONTENT || pre + nl + post > FILETOOL_MAX_CONTENT) {
        free(data);
        return str_dup("error: result too large (4 MiB cap)");
    }
    char *out = malloc(pre + nl + post + 1);
    memcpy(out, data, pre);
    memcpy(out + pre, new_str, nl);
    memcpy(out + pre + nl, data + pre + ol, post);
    out[pre + nl + post] = 0;

    int line = 1;
    for (size_t i = 0; i < pre; i++) if (data[i] == '\n') line++;
    free(data);

    f = open_nofollow(abs, O_WRONLY | O_CREAT | O_TRUNC, "w");
    if (!f) {
        free(out);
        return str_dup("error: cannot open file for writing");
    }
    size_t total = pre + nl + post;
    size_t wr = fwrite(out, 1, total, f);
    int bad = ferror(f);
    fclose(f);
    free(out);
    if (bad || wr != total) return str_dup("error: write failed (disk full?)");

    char buf[300];
    snprintf(buf, sizeof buf, "ok: edited %s at line %d (%zu bytes)", path, line, total);
    return str_dup(buf);
}
