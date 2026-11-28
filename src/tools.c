#define _DARWIN_C_SOURCE 1   /* O_NOFOLLOW */
#include "flywheel.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <ctype.h>
#include <strings.h>
#include <limits.h>
#include <pwd.h>
#include <sys/stat.h>
#include <time.h>
#ifdef __APPLE__
#include <libproc.h>
extern int sandbox_check(pid_t pid, const char *operation, int type, ...);
#endif

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
#define MAXNEST 64

#define OPAQUE '\001'   /* word we cannot decode */

/* Read one shell word at *s, removing quotes and backslashes. Stops at an
   unquoted blank or operator. out needs strlen(*s)+1 bytes. *sub is set to
   the first command substitution found inside double quotes (or NULL),
   *expands whether the shell would substitute something into the word. */
static bool starts_expansion(const char *p) {
    return *p == '`' || (*p == '$' && p[1] && (isalnum((unsigned char)p[1]) || strchr("_{([@*#?!$-", p[1]) ||
                                               (p[1] == '\\' && p[2] == '\n')));
}

static void read_word(const char **s, char *out, const char **sub, bool *expands) {
    const char *p = *s;
    char *w = out;
    int brace = 0;   /* unquoted "{", then "," or "..", then "}" */
    if (sub) *sub = NULL;
    if (expands) *expands = false;
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
                if (expands && *p != '\\' && starts_expansion(p)) *expands = true;
                if (*p == '\\' && p[1] && strchr("\"\\$`\n", p[1])) {
                    p++;
                    if (*p == '\n') { p++; continue; }
                } else if (sub && !*sub && (*p == '`' || (*p == '$' && p[1] == '('))) {
                    *sub = p + (*p == '`' ? 1 : 2);
                }
                *w++ = *p++;
            }
            if (*p) p++;
        } else {
            /* `$` before `(` ends the word here, so look at the input */
            if (expands && starts_expansion(p)) *expands = true;
            /* globs, tilde and brace lists are expansions too */
            if (expands && (*p == '*' || *p == '?' || (*p == '[' && strchr(p + 1, ']')) ||
                            (*p == '~' && w == out) || (*p == '}' && brace == 2)))
                *expands = true;
            if (*p == '{') brace = brace ? brace : 1;
            else if (brace == 1 && (*p == ',' || (*p == '.' && p[1] == '.'))) brace = 2;
            *w++ = *p++;
        }
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
static bool block_device(const char *p) {
    return !strncmp(p, "/dev/sd", 7) || !strncmp(p, "/dev/disk", 9) ||
           !strncmp(p, "/dev/rdisk", 10) || !strncmp(p, "/dev/nvme", 9);
}

/* with g_cfg.outside_writes (a container run) only devices stay off limits */
static bool path_ok(const char *w, const char *cwd) {
    if (!*w) return true;
    if (g_cfg.outside_writes) {
        char norm[PATH_MAX];
        return !(w[0] == '/' && lex_normalize(w, norm, sizeof norm) && block_device(norm));
    }
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
    if (block_device(norm)) return false;
    if (!realpath(cwd, real)) snprintf(real, sizeof real, "%s", cwd);
    return is_within(cwd, norm) || is_within(real, norm) || is_within("/tmp", norm) ||
           is_within("/private/tmp", norm) || is_within("/dev", norm);
}

static const char *E_RULE = "error: command blocked by deny rule";
static const char *E_OUTSIDE = "error: write outside working dir is forbidden";
static const char *E_SED = "error: sed script uses shell expansion or -f; write it literally "
                           "(and put -- before expanded file operands)";

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

/* w with every {} replaced by `by` */
static char *fill_braces(const char *w, const char *by) {
    size_t n = 0, bl = strlen(by);
    for (const char *p = w; (p = strstr(p, "{}")); p += 2) n++;
    bool expands = w[strlen(w) + 1];
    char *out = malloc(strlen(w) + n * bl + 2), *q = out;
    while (*w) {
        if (w[0] == '{' && w[1] == '}') { memcpy(q, by, bl); q += bl; w += 2; }
        else *q++ = *w++;
    }
    *q = 0;
    q[1] = expands;
    return out;
}

/* find: -delete, -fprint and a mutating -exec act below the starting points */
static const char *check_find(char **a, int na, const char *cwd, int depth) {
    static const char *const readers[] = {"grep", "egrep", "fgrep", "rg", "cat", "head", "tail", "wc",
        "ls", "stat", "file", "echo", "printf", "basename", "dirname", "du", "md5", "md5sum",
        "shasum", "sha256sum", "test", NULL};
    /* check_operands knows which operands these write */
    static const char *const known[] = {"rm", "tee", "cp", "mv", "touch", "mkdir", "rmdir", "truncate",
        "chmod", "chown", "chgrp", "ln", "rsync", "install", NULL};
    char **pts = malloc((size_t)(na + 2) * sizeof *pts);
    int np = 0, k = 0;
    while (k < na) {
        if (!strcmp(a[k], "--")) k++;
        else if (!strcmp(a[k], "-D")) k += 2;
        else if (!strcmp(a[k], "-f") && k + 1 < na) { pts[np++] = a[k + 1]; k += 2; }
        else if (a[k][0] == '-' && a[k][1] == 'O') k++;
        else if (a[k][0] == '-' && a[k][1] && strspn(a[k] + 1, "HLPEXdsx") == strlen(a[k] + 1)) k++;
        else break;
    }
    for (; k < na && a[k][0] != '-' && strcmp(a[k], "!") && strcmp(a[k], "("); k++) pts[np++] = a[k];
    if (!np) pts[np++] = (char *)".";
    bool mutates = false, listed = false, acts = false;
    const char *err = NULL;
    for (; !err && k < na; k++) {
        if (!strncmp(a[k], "-files0-from", 12)) listed = true;
        else if (!strcmp(a[k], "-delete")) mutates = acts = true;
        else if ((!strncmp(a[k], "-fprint", 7) || !strcmp(a[k], "-fls")) && k + 1 < na) {
            if (!target_ok(a[++k], cwd)) err = E_OUTSIDE;
        } else if (!strncmp(a[k], "-exec", 5) || !strncmp(a[k], "-ok", 3)) {
            bool indir = strstr(a[k], "dir") != NULL;
            int s = ++k;
            while (k < na && strcmp(a[k], ";") && strcmp(a[k], "+")) k++;
            if (s == k) continue;
            if (depth > 4) { err = E_RULE; break; }
            const char *c = strrchr(a[s], '/') ? strrchr(a[s], '/') + 1 : a[s];
            err = check_simple(a + s, k - s, cwd, depth + 1);
            if (one_of(c, readers)) continue;
            acts = true;
            if (indir || !one_of(c, known)) { mutates = true; continue; }
            /* judge the command as if {} were a file below each start point */
            char **x = malloc((size_t)(k - s) * sizeof *x);
            for (int i = 0; !err && i < np; i++) {
                size_t cap = strlen(pts[i]) + 3;
                char *under = malloc(cap);
                snprintf(under, cap, "%s/x", pts[i]);
                for (int j = s; j < k; j++) x[j - s] = fill_braces(a[j], under);
                err = check_simple(x, k - s, cwd, depth + 1);
                for (int j = 0; j < k - s; j++) free(x[j]);
                free(under);
            }
            free(x);
        }
    }
    /* start points read from a file cannot be judged */
    if (!err && acts && listed && !g_cfg.outside_writes) err = E_OUTSIDE;
    for (int i = 0; !err && mutates && i < np; i++)
        if (!target_ok(pts[i], cwd)) err = E_OUTSIDE;
    free(pts);
    return err;
}

/* past a delimited sed part; `re` parts may hold the delimiter inside [...] */
static const char *sed_part(const char *p, char d, bool re) {
    for (; *p && *p != d; p++) {
        if (*p == '\\' && p[1]) p++;
        else if (re && *p == '[') {
            const char *q = p + 1;
            if (*q == '^') q++;
            if (*q == ']') q++;
            while (*q && *q != ']') q++;
            if (*q) p = q;
        }
    }
    return *p ? p + 1 : p;
}

/* is the file named by the rest of the line writable? advances *p */
static const char *sed_file(const char **p, const char *cwd) {
    const char *s = *p;
    while (*s == ' ' || *s == '\t') s++;
    size_t n = strcspn(s, "\n");
    char *f = malloc(n + 1);
    memcpy(f, s, n);
    f[n] = 0;
    *p = s + n;
    bool ok = path_ok(f, cwd);
    free(f);
    return ok ? NULL : E_OUTSIDE;
}

/* w/W and s///w write files without -i, e runs a shell command */
static const char *check_sed_script(const char *p, const char *cwd) {
    if (g_cfg.outside_writes || !*p) return NULL;
    /* p ends where its word does; scan_script stores the flag after the NUL.
       Anything the shell substitutes anywhere in it can add commands. */
    if (strchr(p, OPAQUE) || p[strlen(p) + 1]) return E_SED;
    const char *err = NULL;
    while (!err && *p) {
        if (strchr(" \t\r\n;{}!,+~$", *p) || isdigit((unsigned char)*p)) { p++; continue; }
        if (*p == '/') { p = sed_part(p + 1, '/', true); p += strspn(p, "IM"); continue; }
        if (*p == '\\' && p[1]) { p = sed_part(p + 2, p[1], true); p += strspn(p, "IM"); continue; }
        char c = *p++;
        if (c == 'w' || c == 'W') err = sed_file(&p, cwd);
        else if (c == 'e') err = E_OUTSIDE;
        else if (strchr("rR#:btTv", c)) p += strcspn(p, c == 'r' || c == 'R' || c == '#' ? "\n" : ";\n");
        else if (strchr("aic", c)) {
            while (*p && *p != '\n') p += *p == '\\' && p[1] ? 2 : 1;
        } else if (c == 's' || c == 'y') {
            char d = *p;
            if (!d) break;
            p = sed_part(p + 1, d, c == 's');
            p = sed_part(p, d, false);
            while (c == 's' && !err && *p && !strchr(";\n}", *p)) {
                char f = *p++;
                if (f == 'w') err = sed_file(&p, cwd);
                else if (f == 'e') err = E_OUTSIDE;
            }
        } else if (!strchr("pPdDgGhHnNxlqQzF=", c)) err = E_OUTSIDE;
    }
    return err;
}

/* sed: files edited by -i and files written by the script itself */
static const char *check_sed(char **a, int na, const char *cwd) {
    static const char *const flags[] = {"quiet", "silent", "regexp-extended", "separate", "unbuffered",
        "null-data", "zero-terminated", "posix", "debug", "follow-symlinks", "sandbox", "help",
        "version", NULL};
    bool inplace = false, script = false, opts = true, expanded = false, may_opt = false;
    char **files = malloc((size_t)(na + 1) * sizeof *files);
    int nf = 0;
    const char *err = NULL;
    for (int k = 0; !err && k < na; k++) {
        const char *o = a[k], *code = NULL;
        bool expands = o[strlen(o) + 1] && !g_cfg.outside_writes;
        /* {-e,...} turns into options of its own */
        if (expands && *o == '{') { err = E_SED; break; }
        if (opts && !strcmp(o, "--")) { opts = false; continue; }
        if (!opts || o[0] != '-' || !o[1]) {
            /* an expansion that may turn into -e makes any later word a script */
            if (may_opt) { err = E_SED; break; }
            if (expands && opts && (strchr(o, '$') || strchr(o, '`') || (*o && strchr("{*?[", *o))))
                may_opt = true;
            expanded |= expands;
            files[nf++] = a[k];
            continue;
        }
        /* an expanded option word may carry a script of its own */
        if (expands) { err = E_SED; break; }
        /* ...and an earlier expansion may change what a later -e/-f means */
        if (expanded) {
            bool later = !strncmp(o, "--e", 3) || !strncmp(o, "--fi", 4);
            for (const char *c = o + 1; o[1] != '-' && *c && !strchr("iIl", *c); c++)
                if (*c == 'e' || *c == 'f') later = true;
            if (later) { err = E_SED; break; }
        }
        if (o[1] == '-') {
            const char *eq = strchr(o, '=');
            size_t len = eq ? (size_t)(eq - o - 2) : strlen(o + 2);
            if (len == 10 && !strncmp(o + 2, "expression", len)) {
                script = true;
                code = eq ? eq + 1 : k + 1 < na ? a[++k] : "";
            } else if (len == 4 && !strncmp(o + 2, "file", len)) {
                script = true;
                if (!eq) k++;
                if (!g_cfg.outside_writes) err = E_SED;   /* script not visible */
            } else if (len == 11 && !strncmp(o + 2, "line-length", len)) {
                if (!eq) k++;
            } else if (len == 8 && !strncmp(o + 2, "in-place", len)) inplace = true;
            else if (!one_of(o + 2, flags) && !g_cfg.outside_writes) err = E_OUTSIDE;
        } else {
            for (const char *c = o + 1; *c; c++) {
                if (*c == 'i' || *c == 'I') {
                    inplace = true;
                    if (!c[1] && k + 1 < na && !*a[k + 1]) k++;   /* BSD: -i '' */
                    break;
                }
                if (*c == 'e') {
                    script = true;
                    code = c[1] ? c + 1 : k + 1 < na ? a[++k] : "";
                    break;
                }
                if (*c == 'f') {
                    script = true;
                    if (!c[1]) k++;
                    if (!g_cfg.outside_writes) err = E_SED;   /* script not visible */
                    break;
                }
                if (*c == 'l' && !c[1] && k + 1 < na && *a[k + 1] &&
                    strspn(a[k + 1], "0123456789") == strlen(a[k + 1])) k++;
            }
        }
        if (code && !err) err = check_sed_script(code, cwd);
    }
    int first = 0;
    if (!script && nf) { if (!err) err = check_sed_script(files[0], cwd); first = 1; }
    for (int k = first; !err && inplace && k < nf; k++)
        if (!target_ok(files[k], cwd)) err = E_OUTSIDE;
    free(files);
    return err;
}

/* perl -i: the files edited in place (not the program) */
static const char *check_perl(char **a, int na, const char *cwd) {
    bool inplace = false, script = false;
    int k = 0;
    for (; k < na && a[k][0] == '-' && a[k][1]; k++) {
        const char *o = a[k];
        if (!strcmp(o, "--")) { k++; break; }
        for (const char *c = o + 1; o[1] != '-' && *c; c++) {
            if (*c == 'i') {
                inplace = true;
                /* perl -pie 'code': the e still introduces the program */
                if ((c[1] == 'e' || c[1] == 'E') && !c[2]) { script = true; k++; }
                break;
            }
            if (*c == 'e' || *c == 'E') {
                script = true;
                if (!c[1]) k++;
                break;
            }
            if (strchr("IMm", *c)) { if (!c[1]) k++; break; }
        }
    }
    if (!inplace) return NULL;
    for (; k < na; k++) {
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

/* Options of the commands that change the files named by their operands.
   Long options: `flags` take no separate word, `values` take one, `files`
   name something written. Anything unlisted is refused. */
typedef struct {
    const char *cmd, *valued;   /* short options that take a value */
    char target;                /* short option naming a target directory */
    const char *flags, *values, *files;
} OpSpec;

static const OpSpec OPSPECS[] = {
    {"rm", "", 0, "force interactive one-file-system no-preserve-root preserve-root recursive dir", "", ""},
    {"tee", "", 0, "append ignore-interrupts output-error", "", ""},
    {"cp", "S", 't', "archive attributes-only backup copy-contents dereference force interactive link "
        "no-clobber no-dereference preserve no-preserve parents recursive reflink remove-destination "
        "sparse strip-trailing-slashes symbolic-link no-target-directory update one-file-system context",
        "suffix", ""},
    {"mv", "S", 't', "backup force interactive no-clobber strip-trailing-slashes no-target-directory "
        "update context", "suffix", ""},
    {"ln", "S", 't', "backup directory force no-dereference interactive logical physical relative "
        "symbolic no-target-directory", "suffix", ""},
    {"install", "mogSBf", 't', "backup compare directory preserve-timestamps strip no-target-directory "
        "preserve-context context", "group mode owner suffix", "strip-program"},
    {"touch", "rtdA", 0, "no-create no-dereference", "date reference time", ""},
    {"mkdir", "m", 0, "parents context", "mode", ""},
    {"rmdir", "", 0, "ignore-fail-on-non-empty parents", "", ""},
    {"truncate", "sr", 0, "no-create io-blocks", "reference size", ""},
    {"chmod", "", 0, "changes quiet silent no-preserve-root preserve-root recursive", "reference", ""},
    {"chown", "", 0, "changes quiet silent no-preserve-root preserve-root recursive dereference "
        "no-dereference", "reference from", ""},
    {"chgrp", "", 0, "changes quiet silent no-preserve-root preserve-root recursive dereference "
        "no-dereference", "reference from", ""},
    {"rsync", "efBTM@", 0, "archive quiet checksum ignore-times size-only recursive relative backup "
        "update inplace append append-verify dirs links copy-links copy-unsafe-links safe-links "
        "munge-links copy-dirlinks keep-dirlinks hard-links perms executability acls xattrs owner group "
        "devices specials times omit-dir-times omit-link-times super fake-super sparse preallocate "
        "dry-run whole-file one-file-system existing ignore-existing remove-source-files delete "
        "delete-before delete-during delete-delay delete-after delete-excluded ignore-errors force "
        "partial delay-updates prune-empty-dirs numeric-ids compress stats human-readable progress "
        "itemize-changes list-only cvs-exclude from0 protect-args secluded-args blocking-io fuzzy "
        "mkpath ipv4 ipv6 del motd implied-dirs",
        "exclude include exclude-from include-from files-from filter rsh rsync-path chmod chown usermap "
        "groupmap max-size min-size max-delete bwlimit port timeout contimeout compare-dest copy-dest "
        "link-dest password-file out-format log-file-format compress-level compress-choice "
        "checksum-choice checksum-seed skip-compress block-size modify-window iconv suffix read-batch "
        "info debug protocol sockopts address remote-option max-alloc outbuf stop-after stop-at",
        "log-file backup-dir temp-dir partial-dir write-batch only-write-batch"},
};

static bool word_in(const char *list, const char *w, size_t n) {
    for (const char *p = list; *p; ) {
        size_t len = strcspn(p, " ");
        if (len == n && !strncmp(p, w, n)) return true;
        p += len;
        p += strspn(p, " ");
    }
    return false;
}

/* is `w` / or the home directory, or everything in one of them? */
static bool root_like(const char *w, const char *cwd) {
    const char *home = getenv("HOME") ? getenv("HOME") : "/nonexistent-home";
    char abs[PATH_MAX], norm[PATH_MAX], h[PATH_MAX];
    if (strchr(w, OPAQUE)) return true;
    if (!*w) return false;
    if (w[0] == '~' && (!w[1] || w[1] == '/')) snprintf(abs, sizeof abs, "%s%s", home, w + 1);
    else if (!strncmp(w, "$HOME", 5)) snprintf(abs, sizeof abs, "%s%s", home, w + 5);
    else if (!strncmp(w, "${HOME}", 7)) snprintf(abs, sizeof abs, "%s%s", home, w + 7);
    else if (w[0] == '/') snprintf(abs, sizeof abs, "%s", w);
    else snprintf(abs, sizeof abs, "%s/%s", cwd, w);
    if (!lex_normalize(abs, norm, sizeof norm)) return true;
    for (char *s; (s = strrchr(norm, '/')) && (!strcmp(s, "/*") || !strcmp(s, "/.*")); ) *s = 0;
    if (!lex_normalize(home, h, sizeof h)) h[0] = 0;
    return !*norm || !strcmp(norm, "/") || !strcmp(norm, h);
}

/* commands that change the files named by their operands */
static const char *check_operands(const char *base, char **a, int na, const char *cwd) {
    const OpSpec *sp = NULL;
    for (size_t i = 0; i < sizeof OPSPECS / sizeof *OPSPECS; i++)
        if (!strcmp(base, OPSPECS[i].cmd)) sp = &OPSPECS[i];
    if (!sp) return NULL;
    bool rm = !strcmp(base, "rm"), cp = !strcmp(base, "cp"), chmod_ = !strcmp(base, "chmod");
    bool owner = !strcmp(base, "chown") || !strcmp(base, "chgrp");
    bool ln = !strcmp(base, "ln"), rsync = !strcmp(base, "rsync"), inst = !strcmp(base, "install");
    bool symbolic = false, dirs = false, moves = false, recursive = false, opts = true, mode_seen = false;
    const char *target = NULL, *err = NULL;
    char **p = malloc((size_t)(na + 1) * sizeof *p);
    int np = 0;
    for (int k = 0; k < na; k++) {
        char *w = a[k];
        if (opts && !strcmp(w, "--")) { opts = false; continue; }
        if (opts && w[0] == '-' && w[1] == '-') {
            const char *name = w + 2, *eq = strchr(name, '='), *val = eq ? eq + 1 : NULL;
            size_t n = eq ? (size_t)(eq - name) : strlen(name);
            if (sp->target && word_in("target-directory", name, n)) {
                target = val ? val : k + 1 < na ? a[++k] : "";
            } else if (word_in(sp->files, name, n)) {
                if (!val && k + 1 < na) val = a[++k];
                if (val && !target_ok(val, cwd)) err = E_OUTSIDE;
            } else if (word_in(sp->values, name, n)) {
                if (!val) k++;
                if (word_in("reference", name, n)) mode_seen = true;
            } else if (word_in(sp->flags, name, n) || word_in("help version verbose", name, n) ||
                       (rsync && !strncmp(name, "no-", 3) && word_in(sp->flags, name + 3, n - 3))) {
                if (word_in("symbolic", name, n)) symbolic = true;
                if (word_in("directory", name, n)) dirs = true;
                if (word_in("recursive", name, n)) recursive = true;
                if (word_in("remove-source-files", name, n)) moves = true;
            } else if (!g_cfg.outside_writes) err = E_OUTSIDE;
            continue;
        }
        if (opts && w[0] == '-' && w[1]) {
            if (chmod_ && strspn(w + 1, "rwxXst,+=ugoa") == strlen(w + 1)) { mode_seen = true; continue; }
            for (const char *c = w + 1; *c; c++) {
                if (ln && *c == 's') symbolic = true;
                if (inst && *c == 'd') dirs = true;
                if (rm && (*c == 'r' || *c == 'R')) recursive = true;
                bool named = *c == sp->target;
                if (!named && !strchr(sp->valued, *c)) continue;
                const char *val = c[1] ? c + 1 : k + 1 < na ? a[++k] : "";
                if (named) target = val;
                else if (rsync && *c == 'T' && !target_ok(val, cwd)) err = E_OUTSIDE;
                break;
            }
            continue;
        }
        if ((chmod_ || owner) && !mode_seen) { mode_seen = true; continue; }
        p[np++] = w;
    }
    if (!err && target && !target_ok(target, cwd)) err = E_OUTSIDE;
    for (int k = 0; !err && k < np; k++) {
        bool check;
        if (ln)           /* a hard link makes the source itself writable here */
            check = !symbolic || (!target && np > 1 && k == np - 1);
        else if (rsync)
            check = np > 1 && (moves || k == np - 1);
        else if (inst)
            check = dirs || (!target && np > 1 && k == np - 1);
        else if (cp)
            check = !target && np > 1 && k == np - 1;
        else check = true;
        if (!check) continue;
        if (rm && recursive) {
            /* never / or ~, whatever else is allowed */
            if (g_cfg.outside_writes ? root_like(p[k], cwd) : !target_ok(p[k], cwd)) err = E_RULE;
        } else if (!target_ok(p[k], cwd)) err = E_OUTSIDE;
    }
    free(p);
    return err;
}

/* Commands that run another command. Options: `flags` take no value, `valued`
   take one (attached or next word), `attached` only an attached one. Anything
   unlisted could shift or hide the command, so it is refused. */
typedef struct {
    const char *cmd, *flags, *valued, *attached, *lflags, *lvalues;
} Wrapper;

static const Wrapper WRAPPERS[] = {
    {"env", "i0v", "uPCa", "", "ignore-environment null debug block-signal default-signal "
        "ignore-signal list-signal-handling", "unset chdir argv0"},
    {"nohup", "", "", "", "", ""},
    {"command", "pvV", "", "", "", ""},
    {"exec", "cl", "a", "", "", ""},
    {"nice", "", "n", "", "", "adjustment"},
    {"xargs", "0tprxo", "adEIJLnPRSs", "eil", "null verbose interactive no-run-if-empty exit open-tty "
        "show-limits eof replace max-lines",
        "arg-file delimiter max-args max-procs max-chars process-slot-var"},
    {"timeout", "fpv", "sk", "", "foreground preserve-status verbose", "signal kill-after"},
    {"setsid", "cfw", "", "", "ctty fork wait", ""},
    {"time", "pvlha", "", "", "portability verbose", ""},
};

/* skip the options of wrapper `w` from v[*i]; *i ends on the command */
static const char *skip_wrapper(const Wrapper *w, char **v, int n, int *i, const char *cwd) {
    bool env = !strcmp(w->cmd, "env"), nice = !strcmp(w->cmd, "nice");
    for (; *i < n; ++*i) {
        const char *o = v[*i], *val = NULL;
        bool chdir_ = false;
        if (env && !strcmp(o, "-")) continue;
        if (o[0] != '-' || !o[1]) break;
        if (!strcmp(o, "--")) { ++*i; break; }
        if (o[1] == '-') {
            const char *name = o + 2, *eq = strchr(name, '=');
            size_t len = eq ? (size_t)(eq - name) : strlen(name);
            if (word_in(w->lvalues, name, len)) {
                val = eq ? eq + 1 : *i + 1 < n ? v[++*i] : NULL;
                chdir_ = env && len == 5 && !strncmp(name, "chdir", len);
            } else if (!word_in(w->lflags, name, len) && !word_in("help version", name, len))
                return E_RULE;
        } else if (!(nice && o[1 + strspn(o + 1, "-0123456789")] == 0)) {
            for (const char *c = o + 1; *c; c++) {
                if (strchr(w->flags, *c)) continue;
                if (strchr(w->attached, *c)) break;
                if (!strchr(w->valued, *c)) return E_RULE;
                val = c[1] ? c + 1 : *i + 1 < n ? v[++*i] : NULL;
                chdir_ = env && *c == 'C';
                break;
            }
        }
        /* the command's relative paths are judged from cwd: stay inside it */
        if (chdir_ && val && ((val[strlen(val) + 1] && !g_cfg.outside_writes) || !target_ok(val, cwd)))
            return E_OUTSIDE;
    }
    return NULL;
}

/* inspect one simple command (words after quote removal) */
static const char *check_simple(char **v, int n, const char *cwd, int depth) {
    static const char *const kw[] = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", NULL};
    static const char *const shells[] = {"sh", "bash", "zsh", "dash", NULL};
    int i = 0;
    const char *base = NULL;
    while (i < n) {
        const char *w = v[i];
        const char *eq = strchr(w, '=');
        if (eq && eq > w && !memchr(w, '/', (size_t)(eq - w)) && w[0] != '-') { i++; continue; }
        if (one_of(w, kw)) { i++; continue; }
        base = strrchr(w, '/') ? strrchr(w, '/') + 1 : w;
        const Wrapper *wr = NULL;
        for (size_t k = 0; k < sizeof WRAPPERS / sizeof *WRAPPERS; k++)
            if (!strcmp(base, WRAPPERS[k].cmd)) wr = &WRAPPERS[k];
        if (!wr) break;
        i++;
        const char *err = skip_wrapper(wr, v, n, &i, cwd);
        if (err) return err;
        if (!strcmp(wr->cmd, "timeout")) i++;   /* the duration */
    }
    if (i >= n) return NULL;
    if (strchr(v[i], OPAQUE)) return E_RULE;
    char **a = v + i + 1;
    int na = n - i - 1;

    if (!strcmp(base, "sudo") || !strcmp(base, "doas") || !strcmp(base, "shutdown") ||
        !strcmp(base, "reboot") || !strncmp(base, "mkfs", 4))
        return E_RULE;
    if (!strncmp(base, "flywheel", 8))            /* a model must not opt itself out */
        for (int k = 0; k < na; k++)
            if (!strcmp(a[k], "--allow-outside-writes")) return E_RULE;
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
    if (!strcmp(base, "sed") || !strcmp(base, "gsed")) return check_sed(a, na, cwd);
    if (!strcmp(base, "perl")) return check_perl(a, na, cwd);
    if (!strcmp(base, "git")) return check_git(a, na, cwd);
    return check_operands(base, a, na, cwd);
}

/* Walk a script: split into simple commands, check redirect targets, skip
   heredoc payloads and comments (they're data, not shell syntax). */
static const char *scan_pass(const char *s, const char *cwd, int depth, bool nest) {
    if (depth > 4) return E_RULE;   /* too deep to check: fail closed */
    char *arena = malloc(3 * strlen(s) + 3), *top = arena;
    char *v[MAXWORDS];
    char delim[MAXHEREDOC][64];
    bool dash[MAXHEREDOC];
    int n = 0, nd = 0;
    int base = 0, level = 0;   /* current command is v[base..n) */
    /* what a substitution interrupted: the command, and the word it is part
       of (v[ph], or a redirect target) so that a glued suffix stays in it */
    struct { int base, ph; bool redir; } outer[MAXNEST];
    char *joined[MAXWORDS];
    int nj = 0, last = -1;     /* the word ending at word_end */
    bool last_redir = false;
    bool redir_out = false, redir_in = false, tick = false;
    const char *err = NULL, *p = s, *word_end = NULL;
    static char subst[] = {'$', 0, 1};   /* stands for a `...` word */
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
                read_word(&p, w, NULL, NULL);
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
        if (c == '`') {   /* opening one: part of the current command's words */
            if (!tick && !redir_out && !redir_in) {
                if (n && word_end == p) v[n - 1][strlen(v[n - 1]) + 1] = 1;
                else if (n > base && n < MAXWORDS) {
                    v[n++] = subst;
                    word_end = p;
                    last = n - 1;
                    last_redir = false;
                }
            }
            tick = !tick;
        }
        if (!c || strchr("\n;&|()`", c)) {
            bool glued = word_end == p, redir = glued ? last_redir : redir_out;
            int ph = glued && !last_redir ? last : -1, closed = -1;
            redir_out = redir_in = false;
            if (nest && (c == '(' || (c == '`' && tick))) {
                /* the outer command resumes after the substitution */
                if (level == MAXNEST) err = E_RULE;
                else {
                    outer[level].base = base;
                    outer[level].ph = ph;
                    outer[level++].redir = redir;
                    base = n;
                }
            } else {
                if (n > base) err = check_simple(v + base, n - base, cwd, depth);
                n = base;
                if (nest && (c == ')' || c == '`') && level) {
                    base = outer[--level].base;
                    closed = level;
                }
            }
            if (!c) {
                while (!err && level) {   /* unterminated: judge what is open */
                    n = base;
                    base = outer[--level].base;
                    if (n > base) err = check_simple(v + base, n - base, cwd, depth);
                }
                break;
            }
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
            /* $(pwd)/build is one word: glue the suffix to its `$` */
            if (!err && closed >= 0 && *p && !strchr(" \t\r\n;&|<>()`", *p)) {
                int at = outer[closed].ph;
                bool target = outer[closed].redir;
                if (at >= 0 || target) {
                    const char *sub;
                    char *tail = malloc(strlen(p) + 1);
                    read_word(&p, tail, &sub, NULL);
                    const char *head = at >= 0 ? v[at] : "$";
                    size_t hl = strlen(head), tl = strlen(tail);
                    char *j = malloc(hl + tl + 2);
                    memcpy(j, head, hl);
                    memcpy(j + hl, tail, tl + 1);
                    j[hl + tl + 1] = 1;   /* expands */
                    free(tail);
                    if (sub) err = scan_script(sub, cwd, depth + 1);
                    if (nj == MAXWORDS) { free(j); err = E_RULE; break; }
                    joined[nj++] = j;
                    if (at >= 0) v[at] = j;
                    else if (!err && !path_ok(j, cwd)) err = E_OUTSIDE;
                    word_end = p;
                    last = at;
                    last_redir = at < 0;
                }
            }
            continue;
        }
        const char *sub;
        bool expands;
        char *w = top;
        read_word(&p, w, &sub, &expands);
        word_end = p;
        last = -1;
        last_redir = redir_out;
        top += strlen(w) + 2;
        top[-1] = expands;
        if (sub) err = scan_script(sub, cwd, depth + 1);
        if (!err && redir_out) {
            if (!path_ok(w, cwd)) err = E_OUTSIDE;
        } else if (!redir_in) {
            bool fd = *p == '>' && *w && strspn(w, "0123456789") == strlen(w);
            if (!fd) {
                if (n < MAXWORDS) { last = n; v[n++] = w; }
                else err = E_RULE;
            }
        }
        redir_out = redir_in = false;
    }
    while (nj) free(joined[--nj]);
    free(arena);
    return err;
}

/* Judged twice: split at every substitution (finds the inner commands), then
   with each outer command rejoined around them (finds its later operands). */
static const char *scan_script(const char *s, const char *cwd, int depth) {
    const char *err = scan_pass(s, cwd, depth, false);
    return err ? err : scan_pass(s, cwd, depth, true);
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
#define SCRIPT_CAP (1024 * 1024)

/* Read until EAGAIN/EOF or max_reads. buf stays within cap: once full, keep the
   head and the newest tail. Returns true if data may still be waiting. */
static bool drain_pipe(int fd, char *buf, size_t *len, size_t cap, int max_reads) {
    for (int i = 0; i < max_reads; i++) {
        char tmp[8192];
        ssize_t r = read(fd, tmp, sizeof tmp);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        if (*len + (size_t)r > cap) {
            size_t head = cap / 8, tail = cap / 4;
            memmove(buf + head, buf + *len - tail, tail);
            *len = head + tail;
        }
        memcpy(buf + *len, tmp, (size_t)r);
        *len += (size_t)r;
    }
    return true;
}

/* ---------- sandbox for model-run commands ----------
   macOS Seatbelt through sandbox-exec, deny by default: writes only inside the
   working directory and a private TMPDIR, no reads under the home directory
   but the project, git's files and the toolchain folders, no reads of
   credential stores anywhere, no writes to project files that later run outside
   the sandbox, no network unless the user approved it for that one command.
   Elsewhere there is no sandbox yet, which callers must treat as unavailable. */

#define SBX_EXEC "/usr/bin/sandbox-exec"
#define SBX_CAP (256 * 1024)

static int sbx_state = -1;   /* -1 = not probed, 0 = unavailable, 1 = works */

/* readable by nobody in the sandbox, relative to the home directory */
static const char *const SBX_SECRETS[] = {
    ".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".netrc", ".git-credentials",
    ".config/gh", ".config/flywheel", ".config/gcloud", ".config/git/credentials",
    "Library/Keychains", "Library/Cookies", "Library/Safari", "Library/Containers/com.apple.Safari",
    "Library/Application Support/Google", "Library/Application Support/Chromium",
    "Library/Application Support/BraveSoftware", "Library/Application Support/Firefox",
    "Library/Application Support/Microsoft Edge", "Library/Application Support/Arc",
    "Library/Application Support/Vivaldi", "Library/Application Support/com.operasoftware.Opera",
    /* package registry, database and vault credentials */
    ".npmrc", ".pypirc", ".cargo/credentials", ".cargo/credentials.toml", ".gem/credentials",
    ".pgpass", ".vault-token", ".m2/settings.xml", ".gradle/gradle.properties",
    /* shell and REPL history: pasted tokens end up there */
    ".bash_history", ".bash_sessions", ".zsh_history", ".zhistory", ".zsh_sessions",
    ".sh_history", ".history", ".local/share/fish/fish_history", ".python_history",
    ".node_repl_history", ".irb_history", ".psql_history", ".mysql_history",
    ".sqlite_history", ".rediscli_history",
    NULL
};

/* in the project, but run or obeyed later by tools outside the sandbox. The
   rebase state carries commands a later `git rebase --continue` runs. */
static const char *const SBX_PROJ[] = {
    ".envrc", ".git/hooks", ".git/config", ".git/config.worktree", ".git/commondir",
    ".git/rebase-merge", ".git/rebase-apply", ".git/sequencer", NULL
};

/* what stays readable under home besides the project: where toolchains and
   their downloaded dependencies live by default. The sandbox environment passes
   none of the variables that move them. The secrets above stay closed inside
   them. */
static const char *const SBX_TOOLS[] = {
    ".cargo/bin", ".cargo/registry", ".cargo/git", ".rustup",
    "go/bin", "go/pkg/mod",
    ".nvm/versions", ".bun/bin",
    ".pyenv", "Library/Python", ".local/bin", ".local/lib",
    ".local/share/uv/python", ".local/share/uv/tools", ".local/share/pipx/venvs",
    ".rbenv",
    ".sdkman/candidates", ".m2/repository", ".gradle/caches", ".gradle/wrapper/dists",
    ".gradle/jdks",
    ".config/git/ignore", ".config/git/attributes",   /* the configs: see cfg_global */
    NULL
};

/* credentials those trees hold at names that vary: below a home, `dir`, then
   `middle` (regex), `file`, `rest` (regex) */
static const char *const SBX_TOOL_SECRETS[][4] = {
    {".nvm/versions", "[^/]+(/[^/]+)?/", "etc/npmrc", ""},
    {".nvm/versions", "[^/]+(/[^/]+)?/", "lib/node_modules/npm/npmrc", ""},
    {".sdkman/candidates/maven", "[^/]+/", "conf/settings.xml", ""},
    {".local/share/uv/tools", "[^/]+/", "uv-receipt.toml", ""},
    {".local/share/pipx/venvs", "[^/]+/", "pipx_metadata.json", ""},
    {".cargo/registry", "", "credentials", "[^/]*"},
};

/* pins are written once per section: `from` is where the current one starts */
typedef struct { char *s; size_t n; bool full; size_t from; } Sb;

static void sb_add(Sb *b, const char *s) {
    size_t n = strlen(s);
    if (b->full || b->n + n + 1 > SBX_CAP) { b->full = true; return; }
    memcpy(b->s + b->n, s, n + 1);
    b->n += n;
}

/* ` (kind "path")` */
static void sb_filter(Sb *b, const char *kind, const char *path) {
    sb_add(b, " (");
    sb_add(b, kind);
    sb_add(b, " \"");
    for (const char *p = path; *p; p++) {
        char c[3] = {'\\', *p, 0};
        sb_add(b, *p == '"' || *p == '\\' ? c : c + 1);
    }
    sb_add(b, "\")");
}

static void sb_path(Sb *b, const char *path) {
    /* a history file linked to /dev/null must not close /dev/null */
    if (strncmp(path, "/dev/", 5)) sb_filter(b, "subpath", path);
}

/* the entry itself, once: it cannot be renamed, removed or replaced */
static void sb_pin(Sb *b, const char *path) {
    size_t at = b->n;
    sb_filter(b, "literal", path);
    if (!b->full && strstr(b->s + b->from, b->s + at) < b->s + at) b->s[b->n = at] = 0;
}

/* a rule on a path means nothing once a directory above it can be moved */
static void sb_pin_above(Sb *b, const char *path) {
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s", path);
    for (char *s; (s = strrchr(p, '/')) && s != p; ) {
        *s = 0;
        sb_pin(b, p);
    }
}

/* where `path` leads, also when its tail does not exist yet: the deepest
   existing ancestor is resolved and dangling links are followed. Lenient about
   what cannot be searched: for the secret rules only. out holds PATH_MAX
   bytes. */
static bool sbx_resolve(const char *path, char *out, int depth) {
    if (realpath(path, out)) return true;
    char parent[PATH_MAX], real[PATH_MAX], link[PATH_MAX], next[PATH_MAX];
    snprintf(parent, sizeof parent, "%s", path);
    char *slash = strrchr(parent, '/');
    if (!slash || depth > 32) return false;
    *slash = 0;
    if (!sbx_resolve(*parent ? parent : "/", real, depth + 1)) return false;
    const char *dir = strcmp(real, "/") ? real : "";
    if (snprintf(out, PATH_MAX, "%s/%s", dir, slash + 1) >= PATH_MAX) return false;
    ssize_t n = readlink(out, link, sizeof link - 1);
    /* not a link, not there, or out of reach of the sandbox too */
    if (n < 0) return errno == EINVAL || errno == ENOENT || errno == ENOTDIR
                      || errno == EACCES || errno == EPERM;
    link[n] = 0;
    if (snprintf(next, sizeof next, "%s%s%s", *link == '/' ? "" : dir,
                 *link == '/' ? "" : "/", link) >= (int)sizeof next) return false;
    return sbx_resolve(next, out, depth + 1);
}

typedef bool (*SecretFn)(const char *path, void *arg);   /* true stops the walk */

static bool home_secrets(const char *home, SecretFn fn, void *arg) {
    if (!home || !*home) return false;
    /* as spelled and as resolved: a linked HOME must not be repointed either */
    char base[2][PATH_MAX], p[PATH_MAX], target[PATH_MAX];
    if (!lex_normalize(home, base[0], PATH_MAX)) base[0][0] = 0;
    if (!sbx_resolve(home, base[1], 0) || !strcmp(base[0], base[1])) base[1][0] = 0;
    for (int h = 0; h < 2; h++)
        for (int i = 0; *base[h] && SBX_SECRETS[i]; i++) {
            if (snprintf(p, sizeof p, "%s/%s", base[h], SBX_SECRETS[i]) >= (int)sizeof p) continue;
            if (fn(p, arg)) return true;
            /* a symlinked store (dotfiles checkout) is judged by where it leads */
            if (sbx_resolve(p, target, 0) && strcmp(p, target) && fn(target, arg)) return true;
        }
    return false;
}

/* every credential store path of $HOME and of the account's home */
static bool each_secret(SecretFn fn, void *arg) {
    const char *home = getenv("HOME");
    const struct passwd *pw = getpwuid(getuid());
    return fn("/Library/Keychains", arg) || home_secrets(home, fn, arg)
        || (pw && (!home || strcmp(home, pw->pw_dir)) && home_secrets(pw->pw_dir, fn, arg));
}

static bool sb_deny_secret(const char *path, void *b) { sb_path(b, path); return false; }
static bool sb_pin_secret(const char *path, void *b) { sb_pin_above(b, path); return false; }
/* a store that cannot be followed cannot be ruled out: nothing runs */
static bool secret_unresolved(const char *path, void *unused) {
    (void)unused;
    char target[PATH_MAX];
    return !sbx_resolve(path, target, 0);
}

/* path is root or below it, however its case or Unicode form is spelled */
static bool path_under(const char *root, const char *path) {
    size_t n = strlen(root);
    if (!strncasecmp(root, path, n) && (!path[n] || path[n] == '/')) return true;
    struct stat r, st;
    if (stat(root, &r)) return false;
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s", path);
    for (;;) {
        if (!stat(p, &st) && st.st_dev == r.st_dev && st.st_ino == r.st_ino) return true;
        char *s = strrchr(p, '/');
        if (!s || s == p) return false;
        *s = 0;
    }
}

static bool secret_holds(const char *store, void *path) { return path_under(store, path); }

static bool in_secret_store(const char *path) {
    return each_secret(secret_holds, (void *)path);
}

static bool store_below(const char *store, void *dir) {
    char parent[PATH_MAX];
    snprintf(parent, sizeof parent, "%s", store);
    char *slash = strrchr(parent, '/');
    if (!slash || slash == parent) return false;
    *slash = 0;
    return path_under(dir, parent);
}

static bool non_ascii(const char *s) {
    while (*s && (unsigned char)*s < 0x80) s++;
    return *s != 0;
}

#ifndef O_SEARCH
#define O_SEARCH O_RDONLY
#endif

/* A descriptor for the directory holding abs (absolute, symlink-free), reached
   one component at a time without following links: nothing swapped in after a
   path check can redirect the I/O done relative to it. *leaf is the last
   component. Returns -1 with errno set. */
static int open_parent(const char *abs, bool make, const char **leaf) {
    char p[PATH_MAX];
    if (snprintf(p, sizeof p, "%s", abs) >= (int)sizeof p) { errno = ENAMETOOLONG; return -1; }
    int fd = open("/", O_SEARCH | O_DIRECTORY);
    char *s = p + 1;
    for (char *slash; fd >= 0 && (slash = strchr(s, '/')); s = slash + 1) {
        *slash = 0;
        int next = openat(fd, s, O_SEARCH | O_DIRECTORY | O_NOFOLLOW);
        if (next < 0 && errno == ENOENT && make && (!mkdirat(fd, s, 0755) || errno == EEXIST))
            next = openat(fd, s, O_SEARCH | O_DIRECTORY | O_NOFOLLOW);
        int err = errno;
        close(fd);
        errno = err;
        fd = next;
    }
    *leaf = abs + (s - p);
    return fd;
}

/* ---------- git files below the project ----------
   git, run later outside the sandbox, obeys any repository it finds. Nothing
   the sandbox runs may create or change a nested .git, .envrc, or the config,
   hooks and commondir of any git directory under a .git: preventive rules
   only, nothing is ever scanned, moved or repaired. */

static bool has_entry(const char *dir, const char *name) {
    char p[PATH_MAX];
    struct stat st;
    return snprintf(p, sizeof p, "%s/%s", dir, name) < (int)sizeof p && !lstat(p, &st);
}

/* what git would accept as a git directory, or one file short of it */
static bool bare_like(const char *dir) {
    return (has_entry(dir, "objects") && has_entry(dir, "refs"))
        || (has_entry(dir, "HEAD") && has_entry(dir, "commondir"));
}

static bool gitdir_name(const char *n) {
    return !strcasecmp(n, "config") || !strcasecmp(n, "config.worktree")
        || !strcasecmp(n, "commondir") || !strcasecmp(n, "hooks")
        || !strcasecmp(n, "rebase-merge") || !strcasecmp(n, "rebase-apply")
        || !strcasecmp(n, "sequencer");
}

/* bare_like, or a HEAD file already there: the root counts as a repository */
static bool root_bare(const char *proj) {
    char p[PATH_MAX];
    struct stat st;
    return bare_like(proj)
        || (snprintf(p, sizeof p, "%s/HEAD", proj) < (int)sizeof p && !lstat(p, &st)
            && !S_ISDIR(st.st_mode));
}

/* the whole of a small regular file, NUL terminated; -1 for anything else */
static ssize_t read_small(const char *path, char *buf, size_t cap) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return -1;
    struct stat st;
    ssize_t n = -1;
    if (!fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_size < (off_t)cap)
        n = read(fd, buf, cap - 1);
    close(fd);
    if (n >= 0) buf[n] = 0;
    return n;
}

/* `rel` as seen from dir, resolved */
static bool resolve_from(const char *dir, const char *rel, char *out) {
    char p[PATH_MAX];
    return snprintf(p, sizeof p, "%s%s%s", *rel == '/' ? "" : dir, *rel == '/' ? "" : "/", rel)
           < (int)sizeof p && realpath(p, out);
}

static void parent_of(const char *path, char *out) {
    snprintf(out, PATH_MAX, "%s", path);
    char *s = strrchr(out, '/');
    if (s) *s = 0;
}

static bool first_line(const char *path, char *out, size_t cap) {
    if (read_small(path, out, cap) < 0) return false;
    out[strcspn(out, "\r\n")] = 0;
    return *out != 0;
}

/* ----- the way to a protected file -----
   A rule on the target means nothing if a link or a gitfile on the way can be
   repointed, so every step is looked at, never through realpath. */

typedef enum {
    N_PIN,      /* a directory on the way: must stay where it is */
    N_LINK,     /* a link on the way: closed */
    N_ENTRY,    /* a gitfile, or what is not a directory yet: closed */
    N_CLOSED    /* a protected file, or one not there yet: closed with all below */
} Node;
typedef void (*NodeFn)(Node kind, const char *path, void *arg);

static char sbx_blocked[PATH_MAX];   /* what stopped the rules */
static const char *sbx_reason;        /* and why */

static bool refuse(const char *reason, const char *path) {
    sbx_reason = reason;
    snprintf(sbx_blocked, sizeof sbx_blocked, "%s", path);
    return false;
}

static bool cannot(const char *path) { return refuse("cannot follow or read", path); }

static bool absent(void) { return errno == ENOENT || errno == ENOTDIR; }

/* /System/Volumes/Data spells every path a second time, which the rules would
   not match: nothing may lead through it */
static bool data_volume(const char *path, const struct stat *st) {
    static const char data[] = "/System/Volumes/Data";
    struct stat d;
    return !strcasecmp(path, data)
        || (st && !stat(data, &d) && d.st_dev == st->st_dev && d.st_ino == st->st_ino);
}

/* nor through a dot name at the root (/.vol, /.nofollow, /.resolve, /.file and
   whatever comes next), nor through /dev, where fd/N is the opener's */
static bool alias_path(const char *path) {
    return path[1] == '.' || (!strncasecmp(path, "/dev/", 5) && strcasecmp(path, "/dev/null"));
}

/* Follow the absolute path one component at a time, reporting every step. A
   final directory is only pinned unless `closed`. False, naming the place, for
   a loop, a second spelling and anything that cannot be looked at. out: where it
   leads, PATH_MAX bytes. */
static bool walk(const char *path, bool closed, char *out, NodeFn fn, void *arg) {
    char rest[PATH_MAX], next[PATH_MAX], link[PATH_MAX];
    if (snprintf(rest, sizeof rest, "%s", path) >= (int)sizeof rest) return cannot(path);
    struct stat st;
    bool there = true;
    int hops = 0;
    out[0] = 0;
    for (char *s = rest;;) {
        s += strspn(s, "/");
        if (!*s) break;
        size_t len = strcspn(s, "/"), at = strlen(out);
        bool more = s[len + strspn(s + len, "/")] != 0;
        if (len <= 2 && !strncmp(s, "..", len)) {
            char *up = strrchr(out, '/');
            if (len == 2 && up) *up = 0;
            s += len;
            continue;
        }
        if (at + len + 2 > PATH_MAX) return cannot(path);
        snprintf(out + at, PATH_MAX - at, "/%.*s", (int)len, s);
        s += len;
        if (there && lstat(out, &st)) {
            if (!absent()) return cannot(out);
            there = false;
        }
        if (alias_path(out) || data_volume(out, there ? &st : NULL)) return cannot(path);
        if (there && S_ISLNK(st.st_mode)) {
            ssize_t n = readlink(out, link, sizeof link - 1);
            if (n < 0 || ++hops > 32) return cannot(out);
            link[n] = 0;
            fn(N_LINK, out, arg);
            if (snprintf(next, sizeof next, "%s%s", link, s) >= (int)sizeof next) return cannot(out);
            memcpy(rest, next, sizeof rest);
            s = rest;
            out[*link == '/' ? 0 : at] = 0;
            continue;
        }
        if (!more) continue;
        if (there && S_ISDIR(st.st_mode)) fn(N_PIN, out, arg);
        else {
            there = false;
            fn(N_ENTRY, out, arg);
        }
    }
    if (!*out) snprintf(out, PATH_MAX, "/");
    if (there && lstat(out, &st)) {
        if (!absent()) return cannot(out);
        there = false;
    }
    fn(closed || !there ? N_CLOSED : S_ISDIR(st.st_mode) ? N_PIN : N_ENTRY, out, arg);
    return true;
}

static void no_node(Node kind, const char *path, void *arg) {
    (void)kind;
    (void)path;
    (void)arg;
}

/* The root's git directory when .git only leads to it: a link, or a "gitdir:"
   file. The rules by name do not see it. 1 with out (PATH_MAX bytes), 0 if
   there is none, -1 if it cannot be followed or read. */
static int gitdir_elsewhere(const char *proj, char *out, NodeFn fn, void *arg) {
    char git[PATH_MAX], at[PATH_MAX], line[PATH_MAX], next[PATH_MAX];
    struct stat st;
    if (snprintf(git, sizeof git, "%s/.git", proj) >= (int)sizeof git) { cannot(proj); return -1; }
    if (lstat(git, &st)) return absent() ? 0 : (cannot(git), -1);
    if (S_ISDIR(st.st_mode)) return 0;
    if (!walk(git, false, at, fn, arg)) return -1;
    bool missing = stat(at, &st) != 0;
    if (missing && !absent()) { cannot(at); return -1; }
    if (missing || S_ISDIR(st.st_mode)) {
        snprintf(out, PATH_MAX, "%s", at);
        return 1;
    }
    if (!S_ISREG(st.st_mode)) return 0;
    if (read_small(at, line, sizeof line) < 0) { cannot(at); return -1; }
    line[strcspn(line, "\r\n")] = 0;
    if (strncmp(line, "gitdir: ", 8)) return 0;
    const char *rel = line + 8;
    if (snprintf(next, sizeof next, "%s%s%s", *rel == '/' ? "" : proj, *rel == '/' ? "" : "/", rel)
        >= (int)sizeof next) { cannot(at); return -1; }
    return walk(next, false, out, fn, arg) ? 1 : -1;
}

/* what makes git run something, in a git directory */
static const char *const GIT_CLOSED[] = {
    "config", "config.worktree", "commondir", "hooks", "rebase-merge", "rebase-apply",
    "sequencer", NULL
};

/* git runs what a linked hook leads to: close that as well */
static bool walk_hooks(const char *dir, NodeFn fn, void *arg) {
    DIR *d = opendir(dir);
    if (!d) return absent() || cannot(dir);
    char p[PATH_MAX], out[PATH_MAX];
    bool ok = true;
    struct dirent *e;
    while (ok && (errno = 0, e = readdir(d))) {
        struct stat st;
        if (snprintf(p, sizeof p, "%s/%s", dir, e->d_name) >= (int)sizeof p || lstat(p, &st))
            ok = cannot(dir);
        else if (S_ISLNK(st.st_mode))
            ok = walk(p, true, out, fn, arg);
    }
    if (ok && errno) ok = cannot(dir);
    closedir(d);
    return ok;
}

/* one protected file, and for a hooks directory the links in it */
static bool walk_closed(const char *dir, const char *name, NodeFn fn, void *arg) {
    char p[PATH_MAX], out[PATH_MAX];
    if (snprintf(p, sizeof p, "%s/%s", dir, name) >= (int)sizeof p) return cannot(dir);
    if (!walk(p, true, out, fn, arg)) return false;
    const char *base = strrchr(name, '/');
    return strcmp(base ? base + 1 : name, "hooks") || walk_hooks(out, fn, arg);
}

static bool walk_files(const char *dir, const char *const *names, NodeFn fn, void *arg) {
    for (int i = 0; names[i]; i++)
        if (!walk_closed(dir, names[i], fn, arg)) return false;
    return true;
}

/* the directory a git directory's commondir file names, and its files */
static bool walk_common(const char *gitdir, NodeFn fn, void *arg) {
    char file[PATH_MAX], line[PATH_MAX], next[PATH_MAX], out[PATH_MAX];
    struct stat st;
    if (snprintf(file, sizeof file, "%s/commondir", gitdir) >= (int)sizeof file) return cannot(gitdir);
    if (stat(file, &st)) return absent() || cannot(file);
    if (!S_ISREG(st.st_mode)) return true;
    if (!realpath(file, out) || read_small(out, line, sizeof line) < 0) return cannot(file);
    line[strcspn(line, "\r\n")] = 0;
    if (!*line) return true;
    if (snprintf(next, sizeof next, "%s%s%s", *line == '/' ? "" : gitdir, *line == '/' ? "" : "/", line)
        >= (int)sizeof next) return cannot(file);
    return walk(next, false, out, fn, arg) && walk_files(out, GIT_CLOSED, fn, arg);
}

/* SBX_PROJ, and the same files wherever .git, gitdir: and commondir lead */
static bool each_gitfile(const char *proj, NodeFn fn, void *arg) {
    char p[PATH_MAX], other[PATH_MAX];
    struct stat st;
    if (!walk_files(proj, SBX_PROJ, fn, arg)) return false;
    if (root_bare(proj) && !walk_files(proj, GIT_CLOSED, fn, arg)) return false;
    int moved = gitdir_elsewhere(proj, other, fn, arg);
    if (moved < 0) return false;
    if (moved && !walk_files(other, GIT_CLOSED, fn, arg)) return false;
    if (!moved) {
        if (snprintf(p, sizeof p, "%s/.git", proj) >= (int)sizeof p) return cannot(proj);
        if (stat(p, &st)) return absent() || cannot(p);
        if (!S_ISDIR(st.st_mode)) return true;
    }
    return walk_common(moved ? other : p, fn, arg);
}

/* ----- core.hooksPath -----
   What it names is run by git outside, like .git/hooks. The configs are read
   here (asking git would run what PATH or the repository chose), every value of
   every one counts, and every include is followed whatever its condition. */

#define CFG_MAX (256 * 1024)
#define CFG_VALUES 16
#define CFG_FILES 64

typedef struct { char *v[CFG_VALUES]; int n; } Values;
/* what a command may write: the project, TMPDIR and a linked worktree's files */
typedef struct { char dir[6][PATH_MAX]; int n; } Areas;

/* the places left readable under a closed home, written in two passes: their
   contents, then with `meta` the way to them, which may only be looked up.
   With `guard` they are not granted: what of the way to them a command could
   write is closed, in the two sections of the write rules (`pins`). */
typedef struct { Sb *b; bool meta; const Areas *areas; bool guard, pins; } Reads;
static void sb_read(const Reads *r, const char *path, bool keep);

typedef struct {
    const char *proj;
    NodeFn fn;
    void *arg;
    Values hooks, tree;     /* core.hooksPath, core.worktree */
    int files;              /* read for the current repository */
    const Reads *reads;     /* the files a global config sends git to, or NULL */
} Hooks;

static void values_cut(Values *v, int n) {
    while (v->n > n) free(v->v[--v->n]);
}

static bool values_add(Values *v, const char *s) {
    for (int i = 0; i < v->n; i++)
        if (!strcmp(v->v[i], s)) return true;
    if (v->n == CFG_VALUES) return false;
    v->v[v->n++] = str_dup(s);
    return true;
}

static bool join(char *out, const char *dir, const char *rel) {
    return snprintf(out, PATH_MAX, "%s%s%s", *rel == '/' ? "" : dir, *rel == '/' ? "" : "/", rel)
           < PATH_MAX;
}

/* a path value as git reads it: ~ and ~user. False for what cannot be known. */
static bool cfg_expand(const char *v, char *out) {
    if (!strncmp(v, "%(", 2) || !strncmp(v, ":(", 2)) return false;
    if (*v != '~') return snprintf(out, PATH_MAX, "%s", v) < PATH_MAX;
    size_t n = strcspn(v + 1, "/");
    char user[256];
    if (n >= sizeof user) return false;
    snprintf(user, sizeof user, "%.*s", (int)n, v + 1);
    const struct passwd *pw = n ? getpwnam(user) : NULL;
    const char *home = n ? (pw ? pw->pw_dir : NULL) : getenv("HOME");
    return home && *home && snprintf(out, PATH_MAX, "%s%s", home, v + 1 + n) < PATH_MAX;
}

static bool cfg_file(Hooks *h, const char *path, int depth);

/* one key; val is NULL when there is none or it does not fit */
static bool cfg_key(Hooks *h, const char *path, const char *sec, bool sub, const char *key,
                    const char *val, int depth) {
    bool core = !sub && !strcmp(sec, "core");
    bool hooks = core && !strcmp(key, "hookspath"), tree = core && !strcmp(key, "worktree");
    bool inc = !strcmp(key, "path")
        && (sub ? !strcmp(sec, "includeif") : !strcmp(sec, "include"));
    if (h->reads && core && val
        && (!strcmp(key, "excludesfile") || !strcmp(key, "attributesfile"))) {
        char file[PATH_MAX];
        struct stat st;
        /* A file only: a directory named here stays closed. A relative value
           is whatever the project puts there, a link included. */
        if (cfg_expand(val, file) && *file == '/'
            && (h->reads->guard || (!stat(file, &st) && S_ISREG(st.st_mode))))
            sb_read(h->reads, file, false);
    }
    if (!hooks && !tree && !inc) return true;
    if (!val) return cannot(path);
    if (!inc) return values_add(hooks ? &h->hooks : &h->tree, val) || cannot(path);
    char file[PATH_MAX], dir[PATH_MAX], full[PATH_MAX];
    if (!*val) return true;
    parent_of(path, dir);
    if (!cfg_expand(val, file) || !join(full, dir, file)) return cannot(path);
    return cfg_file(h, full, depth + 1);
}

/* the value after '=', up to the end of its line; NULL for bad syntax.
   Blank is space, tab and CR, as git has it: form feed and the like are kept. */
static const char *cfg_value(const char *s, char *out, bool *fits) {
    size_t n = 0, keep = 0, odd = 0;
    bool quote = false;
    *fits = true;
    for (;; s++) {
        char c = *s;
        if (c == '\r' && s[1] == '\n') c = *++s;
        if (!c || c == '\n') break;
        if (!quote && (c == '#' || c == ';')) { s += strcspn(s, "\n"); break; }
        bool blank = !quote && (c == ' ' || c == '\t' || c == '\r');
        if (blank && !n) continue;
        if (c == '"') { quote = !quote; keep = n; continue; }
        if (c == '\\') {
            keep = n;           /* blanks before an escape stay */
            c = *++s;
            if (c == '\r' && s[1] == '\n') c = *++s;
            if (c == '\n') continue;
            if (c == 'n') c = '\n';
            else if (c == 't') c = '\t';
            else if (c == 'b') c = '\b';
            else if (c != '"' && c != '\\') return NULL;
        }
        if (n + 1 >= PATH_MAX) { *fits = false; continue; }
        if (blank && c != ' ' && !odd) odd = n + 1;
        out[n++] = c;
        if (!blank) keep = n;
    }
    out[keep] = 0;
    /* some gits keep an unquoted tab or CR inside a value, some make it a space */
    if (odd && odd <= keep) *fits = false;
    return quote ? NULL : s;
}

/* git's config syntax; anything else fails */
static bool cfg_parse(Hooks *h, const char *path, const char *s, int depth) {
    char sec[32] = "", key[32], val[PATH_MAX];
    bool sub = false;
    if (!strncmp(s, "\xef\xbb\xbf", 3)) s += 3;
    for (;;) {
        s += strspn(s, " \t\r\n");
        if (!*s) return true;
        if (*s == '#' || *s == ';') { s += strcspn(s, "\n"); continue; }
        size_t n = 0;
        if (*s == '[') {
            sub = false;
            for (s++; isalnum((unsigned char)*s) || *s == '-' || *s == '.'; s++) {
                if (*s == '.') sub = true;
                else if (!sub && n + 1 < sizeof sec) sec[n++] = (char)tolower((unsigned char)*s);
            }
            sec[n] = 0;
            if (*s == ' ' || *s == '\t' || *s == '\r') {
                s += strspn(s, " \t\r");
                if (*s++ != '"') return cannot(path);
                for (sub = true; *s && *s != '"' && *s != '\n'; s++)
                    if (*s == '\\' && s[1]) s++;
                if (*s++ != '"') return cannot(path);
            }
            if (*s++ != ']') return cannot(path);
            continue;
        }
        if (!isalpha((unsigned char)*s)) return cannot(path);
        for (; isalnum((unsigned char)*s) || *s == '-'; s++)
            if (n + 1 < sizeof key) key[n++] = (char)tolower((unsigned char)*s);
        key[n] = 0;
        s += strspn(s, " \t");
        bool fits = false;
        if (*s == '=') {
            if (!(s = cfg_value(s + 1, val, &fits))) return cannot(path);
        } else if (*s && !strchr("\r\n#;", *s)) return cannot(path);
        if (!cfg_key(h, path, sec, sub, key, fits ? val : NULL, depth)) return false;
    }
}

/* one config file: closed, there or not, since it can name a hooks directory */
static bool cfg_file(Hooks *h, const char *path, int depth) {
    char at[PATH_MAX];
    if (!walk(path, true, at, h->fn, h->arg)) return false;
    struct stat st;
    if (stat(at, &st)) return absent() || cannot(at);
    if (S_ISCHR(st.st_mode)) return true;   /* /dev/null */
    if (!S_ISREG(st.st_mode) || depth > 10 || ++h->files > CFG_FILES) return cannot(at);
    if (h->reads) sb_read(h->reads, path, false);
    char *buf = malloc(CFG_MAX);
    ssize_t n = read_small(at, buf, CFG_MAX);
    bool ok = n >= 0 && n == (ssize_t)strlen(buf) ? cfg_parse(h, path, buf, depth) : cannot(at);
    free(buf);
    return ok;
}

static bool cfg_in(Hooks *h, const char *dir, const char *name) {
    char p[PATH_MAX];
    return join(p, dir, name) ? cfg_file(h, p, 0) : cannot(dir);
}

/* system and global: every place a git on this machine may look */
static bool cfg_global(Hooks *h) {
    static const char *const fixed[] = {
        "/etc/gitconfig", "/opt/homebrew/etc/gitconfig", "/usr/local/etc/gitconfig",
        "/opt/local/etc/gitconfig",
        "/Applications/Xcode.app/Contents/Developer/usr/share/git-core/gitconfig",
        "/Library/Developer/CommandLineTools/usr/share/git-core/gitconfig", NULL
    };
    static const char *const env[] = {"GIT_CONFIG_SYSTEM", "GIT_CONFIG_GLOBAL", NULL};
    for (int i = 0; fixed[i]; i++)
        if (!cfg_file(h, fixed[i], 0)) return false;
    for (int i = 0; env[i]; i++) {
        const char *v = getenv(env[i]);
        char p[PATH_MAX];
        if (v && *v && !(join(p, h->proj, v) ? cfg_file(h, p, 0) : cannot(v))) return false;
    }
    const char *xdg = getenv("XDG_CONFIG_HOME"), *home = getenv("HOME");
    if (xdg && *xdg == '/' && !cfg_in(h, xdg, "git/config")) return false;
    return !home || *home != '/'
        || (cfg_in(h, home, ".config/git/config") && cfg_in(h, home, ".gitconfig"));
}

/* the directory is or contains `inner` */
static bool covers(const char *dir, const char *inner) {
    return !strcmp(dir, "/") || path_under(dir, inner);
}

static bool hooks_dir(Hooks *h, const char *path, const char *tree) {
    char at[PATH_MAX];
    if (!walk(path, true, at, h->fn, h->arg)) return false;
    if (covers(at, h->proj) || (tree && covers(at, tree)))
        return refuse("core.hooksPath covers the whole project:", path);
    return walk_hooks(at, h->fn, h->arg);
}

/* husky points git at .husky/_, whose stubs run the scripts in .husky */
static bool husky_stubs(const char *path) {
    size_t n = strlen(path);
    return n >= 9 && !strcasecmp(path + n - 9, "/.husky/_");
}

/* every core.hooksPath value, as seen from one work tree (or git directory);
   NULL: no repository, only an absolute value means anything */
static bool hooks_apply(Hooks *h, const char *tree) {
    for (int i = 0; i < h->hooks.n; i++) {
        const char *v = h->hooks.v[i];
        if (!*v || !strcmp(v, "/dev/null")) continue;
        char dir[PATH_MAX], full[PATH_MAX], at[PATH_MAX], up[PATH_MAX];
        if (!cfg_expand(v, dir)) return refuse("cannot resolve core.hooksPath", v);
        if (*dir != '/' && !tree) continue;
        /* a work tree that is gone: leading ".." steps are taken by name */
        const char *base = tree ? tree : "", *rel = dir;
        struct stat st;
        if (*dir != '/' && stat(tree, &st))
            for (snprintf(up, sizeof up, "%s", tree); !strncmp(rel, "../", 3); rel += 3, base = up) {
                char *s = strrchr(up, '/');
                if (s) s[s == up] = 0;
            }
        if (!join(full, base, rel)) return refuse("cannot resolve core.hooksPath", v);
        for (size_t n = strlen(full); n > 1 && full[n - 1] == '/'; ) full[--n] = 0;
        if (!hooks_dir(h, full, tree)) return false;
        if (husky_stubs(full)) {
            parent_of(full, up);
            if (!hooks_dir(h, up, tree)) return false;
        }
        if (realpath(full, at) && husky_stubs(at)) {
            parent_of(at, up);
            if (!hooks_dir(h, up, tree)) return false;
        }
    }
    return true;
}

/* the work trees core.worktree names, relative to the git directory */
static bool hooks_trees(Hooks *h, const char *gitdir) {
    for (int i = 0; i < h->tree.n; i++) {
        char dir[PATH_MAX], full[PATH_MAX];
        if (!cfg_expand(h->tree.v[i], dir) || !join(full, gitdir, dir)) return cannot(gitdir);
        if (!hooks_apply(h, full)) return false;
    }
    return true;
}

static bool hooks_worktrees(Hooks *h, const char *common);

/* what git keeps in a git directory and never holds another one */
static bool git_data(const char *name) {
    return !strcmp(name, "objects") || !strcmp(name, "refs") || !strcmp(name, "logs")
        || !strcmp(name, "lfs") || !strcmp(name, "svn");
}

/* every submodule git directory below `dir`, with its own config. Only a
   `config` file marks one: a submodule's path may itself have "config" or
   "HEAD" in it, so what is below is searched either way. */
static bool hooks_modules(Hooks *h, const char *dir, int depth) {
    DIR *d = opendir(dir);
    if (!d) return absent() || cannot(dir);
    bool ok = depth <= 16 || cannot(dir);
    struct stat st;
    char mark[PATH_MAX];
    bool gitdir = join(mark, dir, "config") && !lstat(mark, &st) && !S_ISDIR(st.st_mode);
    if (ok && gitdir && depth) {
        int hooks = h->hooks.n, tree = h->tree.n;
        h->files = 0;
        ok = cfg_in(h, dir, "config") && cfg_in(h, dir, "config.worktree")
             && hooks_apply(h, dir)   /* hooks run there on receive */
             && hooks_trees(h, dir) && hooks_worktrees(h, dir);
        values_cut(&h->hooks, hooks);
        values_cut(&h->tree, tree);
    }
    struct dirent *e;
    while (ok && (errno = 0, e = readdir(d))) {
        char p[PATH_MAX];
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (gitdir && depth && git_data(e->d_name)) continue;
        if (!join(p, dir, e->d_name)) { ok = cannot(dir); break; }
        if (stat(p, &st)) { ok = absent() || cannot(p); continue; }
        if (S_ISDIR(st.st_mode)) ok = hooks_modules(h, p, depth + 1);
    }
    if (ok && errno) ok = cannot(dir);
    closedir(d);
    return ok;
}

/* every linked worktree, wherever it lies: git runs hooks from there, and what
   its values name may be in the project */
static bool hooks_worktrees(Hooks *h, const char *common) {
    char dir[PATH_MAX];
    if (!join(dir, common, "worktrees")) return cannot(common);
    DIR *d = opendir(dir);
    if (!d) return absent() || cannot(dir);
    bool ok = true;
    struct dirent *e;
    while (ok && (errno = 0, e = readdir(d))) {
        char wt[PATH_MAX], file[PATH_MAX], line[PATH_MAX], git[PATH_MAX], tree[PATH_MAX];
        char at[PATH_MAX], kept[PATH_MAX];
        struct stat st;
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (!join(wt, dir, e->d_name) || !join(file, wt, "gitdir")) { ok = cannot(dir); break; }
        if (stat(wt, &st)) { ok = absent() || cannot(wt); continue; }
        if (!S_ISDIR(st.st_mode)) continue;
        /* without this file the next command would not find the work tree */
        if (!walk(file, true, kept, h->fn, h->arg)) { ok = false; break; }
        if (!first_line(file, line, sizeof line) || !*line || !join(git, wt, line)) {
            ok = cannot(file);
            break;
        }
        parent_of(git, tree);   /* a removed work tree is still named */
        int hooks = h->hooks.n;
        h->files = 0;
        ok = cfg_in(h, wt, "config.worktree") && hooks_apply(h, realpath(tree, at) ? at : tree);
        values_cut(&h->hooks, hooks);
    }
    if (ok && errno) ok = cannot(dir);
    closedir(d);
    return ok;
}

/* one repository: its configs, its work trees and what it holds */
static bool hooks_one(Hooks *h, const char *top, const char *gitdir) {
    char common[PATH_MAX], p[PATH_MAX], line[PATH_MAX];
    snprintf(common, sizeof common, "%s", gitdir);
    struct stat st;
    if (!join(p, gitdir, "commondir")) return cannot(gitdir);
    if (!stat(p, &st) && S_ISREG(st.st_mode)) {
        if (read_small(p, line, sizeof line) < 0) return cannot(p);
        line[strcspn(line, "\r\n")] = 0;
        if (*line && !join(common, gitdir, line)) return cannot(p);
    } else if (stat(p, &st) && !absent()) return cannot(p);

    int hooks = h->hooks.n, tree = h->tree.n;
    h->files = 0;
    /* a relative value also counts from the git directories: hooks run there
       on receive */
    if (!cfg_in(h, common, "config") || !cfg_in(h, common, "config.worktree")
        || !cfg_in(h, gitdir, "config") || !cfg_in(h, gitdir, "config.worktree")
        || !hooks_apply(h, top) || !hooks_apply(h, gitdir) || !hooks_apply(h, common)
        || !hooks_trees(h, gitdir) || !hooks_worktrees(h, common))
        return false;
    values_cut(&h->hooks, hooks);
    values_cut(&h->tree, tree);
    if (!join(p, gitdir, "modules") || !hooks_modules(h, p, 0)) return false;
    return !strcmp(common, gitdir) || (join(p, common, "modules") && hooks_modules(h, p, 0));
}

/* the configs of the repository the project is in, then of what is inside it.
   Only .git ends the search upward: a directory that merely looks bare (a
   command can make one) is read as one on the way. */
static bool hooks_repo(Hooks *h) {
    char top[PATH_MAX], gitdir[PATH_MAX];
    snprintf(top, sizeof top, "%s", h->proj);
    bool bare = false;
    for (bool first = true; !has_entry(top, ".git"); first = false) {
        if (first ? root_bare(top) : bare_like(top)) {
            bare = true;
            if (!hooks_one(h, top, top)) return false;
        }
        char *s = strrchr(top, '/');
        if (!s || !s[1]) return bare || hooks_apply(h, NULL);
        s[s == top] = 0;
    }
    int moved = gitdir_elsewhere(top, gitdir, no_node, NULL);
    if (moved < 0) return false;
    if (!moved && !join(gitdir, top, ".git")) return cannot(top);
    return hooks_one(h, top, gitdir);
}

static bool hooks_paths(const char *proj, NodeFn fn, void *arg) {
    Hooks h = {.proj = proj, .fn = fn, .arg = arg};
    bool ok = cfg_global(&h) && hooks_repo(&h);
    values_cut(&h.hooks, 0);
    values_cut(&h.tree, 0);
    return ok;
}

static bool sbx_probing;    /* the availability probe is not about any project */

/* every step to every protected file of the project, and to what its
   core.hooksPath names */
static bool each_protected(const char *proj, NodeFn fn, void *arg) {
    return each_gitfile(proj, fn, arg) && (sbx_probing || hooks_paths(proj, fn, arg));
}

/* ---------- linked worktree: git keeps its files outside the project ---------- */

typedef struct { char dir[PATH_MAX], common[PATH_MAX]; } Linked;

/* trusted only if the repository points back: the git directory must be
   <common>/worktrees/<name> and name this project's .git file */
static bool linked_worktree(const char *proj, Linked *w) {
    char git[PATH_MAX], file[PATH_MAX], line[PATH_MAX], back[PATH_MAX], up[PATH_MAX], want[PATH_MAX];
    struct stat st;
    if (snprintf(git, sizeof git, "%s/.git", proj) >= (int)sizeof git
        || lstat(git, &st) || !S_ISREG(st.st_mode)
        || !first_line(git, line, sizeof line) || strncmp(line, "gitdir: ", 8)
        || !resolve_from(proj, line + 8, w->dir)) return false;
    if (snprintf(file, sizeof file, "%s/gitdir", w->dir) >= (int)sizeof file
        || !first_line(file, line, sizeof line) || !resolve_from(w->dir, line, back)
        || strcmp(back, git)) return false;
    if (snprintf(file, sizeof file, "%s/commondir", w->dir) >= (int)sizeof file
        || !first_line(file, line, sizeof line) || !resolve_from(w->dir, line, w->common)) return false;
    parent_of(w->dir, up);
    return snprintf(want, sizeof want, "%s/worktrees", w->common) < (int)sizeof want
        && !strcmp(up, want) && !is_within(proj, w->common)
        && has_entry(w->common, "objects") && has_entry(w->common, "HEAD")
        && !in_secret_store(w->dir) && !in_secret_store(w->common);
}

/* the project, TMPDIR, and of a linked worktree its git directory and objects,
   refs and logs of the repository */
static void writable(Areas *a, const char *proj, const char *tmp, const Linked *w) {
    static const char *const shared[] = {"objects", "refs", "logs", NULL};
    a->n = 0;
    snprintf(a->dir[a->n++], PATH_MAX, "%s", proj);
    if (tmp) snprintf(a->dir[a->n++], PATH_MAX, "%s", tmp);
    if (!w) return;
    snprintf(a->dir[a->n++], PATH_MAX, "%s", w->dir);
    for (int i = 0; shared[i]; i++)
        if (join(a->dir[a->n], w->common, shared[i])) a->n++;
}

static const char *const LINKED_CLOSED[] = {
    "config", "config.worktree", "commondir", "gitdir", "hooks", "modules",
    "rebase-merge", "rebase-apply", "sequencer", NULL
};

static bool walk_linked(const Linked *w, NodeFn fn, void *arg) {
    for (int h = 0; h < 2; h++)
        for (int i = 0; LINKED_CLOSED[i]; i++) {
            const char *dir = h ? w->common : w->dir;
            if (h && !strcmp(LINKED_CLOSED[i], "modules")) continue;
            if (!walk_closed(dir, LINKED_CLOSED[i], fn, arg)) return false;
        }
    return true;
}

#define SBX_RX 1000

/* name as a regex matching every spelling the filesystem folds to it. Beyond
   case, APFS folds a few characters to ASCII: these are all that occur in the
   names closed here (none contains "ff", "fl" or "ss"). */
static const char *fold(const char *name, char *out) {   /* out holds 256 */
    static const char *const also[][2] = {
        {"fi", "[fF][iI]|\xef\xac\x81"}, {"st", "[sS][tT]|\xef\xac\x85|\xef\xac\x86"},
        {"s", "[sS]|\xc5\xbf"}, {"k", "[kK]|\xe2\x84\xaa"},
    };
    size_t n = 0;
    for (const char *p = name; *p && n < 200; ) {
        size_t i = 0;
        while (i < sizeof also / sizeof *also && strncmp(p, also[i][0], strlen(also[i][0]))) i++;
        if (i < sizeof also / sizeof *also) {
            n += (size_t)snprintf(out + n, 256 - n, "(%s)", also[i][1]);
            p += strlen(also[i][0]);
            continue;
        }
        if (isalpha((unsigned char)*p))
            n += (size_t)snprintf(out + n, 256 - n, "[%c%c]", tolower((unsigned char)*p),
                                  toupper((unsigned char)*p));
        else n += (size_t)snprintf(out + n, 256 - n, *p == '.' ? "[.]" : "%c", *p);
        p++;
    }
    out[n] = 0;
    return out;
}

/* path as regex text; what cannot be quoted matches any character */
static void re_path(const char *path, char *out, size_t cap) {
    size_t n = 0;
    for (const char *p = path; *p && n + 4 < cap; p++) {
        if (strchr("\"[]\\^", *p)) out[n++] = '.';
        else if (strchr(".*+?()|{}$", *p)) { out[n++] = '['; out[n++] = *p; out[n++] = ']'; }
        else out[n++] = *p;
    }
    out[n] = 0;
}

static void sb_regex(Sb *b, const char *head, const char *tail) {
    if (strlen(head) + strlen(tail) > SBX_RX) b->full = true;
    sb_add(b, " (regex #\"");
    sb_add(b, head);
    sb_add(b, tail);
    sb_add(b, "\")");
}

/* ---------- reads under a home: closed unless listed ---------- */

/* $HOME and the account's home, each as spelled and as resolved */
static int homes(char out[4][PATH_MAX]) {
    const struct passwd *pw = getpwuid(getuid());
    const char *from[2] = {getenv("HOME"), pw ? pw->pw_dir : NULL};
    int n = 0;
    for (int i = 0; i < 2; i++) {
        if (!from[i] || *from[i] != '/') continue;
        /* a home reached by a second spelling would not match its rule */
        char at[PATH_MAX];
        if (!walk(from[i], true, at, no_node, NULL)) return -1;
        if (!lex_normalize(from[i], out[n], PATH_MAX)) return -1;
        n++;
        if (strcmp(at, out[n - 1])) snprintf(out[n++], PATH_MAX, "%s", at);
    }
    return n;
}

static void sb_way(Node kind, const char *path, void *b) {
    (void)kind;
    if (strncmp(path, "/dev/", 5)) sb_pin(b, path);
}

typedef struct { Sb *b; bool pins; } Rules;

static void sb_node(Node kind, const char *path, void *arg) {
    const Rules *r = arg;
    if (r->pins) {
        if (kind == N_PIN) sb_pin(r->b, path);
        return;
    }
    if (!strcasecmp(path, "/dev/null")) return;     /* links to it stay writable */
    if (kind == N_CLOSED) sb_path(r->b, path);
    else if (kind != N_PIN) sb_pin(r->b, path);
}

static bool in_areas(const Areas *a, const char *path) {
    for (int i = 0; i < a->n; i++)
        if (path_under(a->dir[i], path)) return true;
    return false;
}

/* a step a command could change stays as it is, there or not */
static void guard_open(Node kind, const char *path, void *arg) {
    const Reads *r = arg;
    if (!in_areas(r->areas, path)) return;
    /* but what leads to a whole writable place does not close it */
    for (int i = 0; kind == N_CLOSED && i < r->areas->n; i++)
        if (covers(path, r->areas->dir[i])) return;
    Rules rules = {r->b, r->pins};
    sb_node(kind, path, &rules);
}

typedef struct { const Areas *areas; bool found; } Planted;

/* a link a command can repoint */
static void see_link(Node kind, const char *path, void *arg) {
    Planted *p = arg;
    if (kind == N_LINK && in_areas(p->areas, path)) p->found = true;
}

/* One place that stays readable. keep: the project and TMPDIR are what was
   asked for; anything else that turns out to hold a home stays closed, and so
   does what cannot be followed or is reached by a link a command can write. */
static void sb_read(const Reads *r, const char *path, bool keep) {
    char at[PATH_MAX], home[4][PATH_MAX];
    if (r->guard) {
        if (walk(path, true, at, guard_open, (void *)r)) return;
        if (in_areas(r->areas, path) || in_areas(r->areas, sbx_blocked)) r->b->full = true;
        else *sbx_blocked = 0;
        return;
    }
    Planted planted = {r->areas, false};
    if (!walk(path, true, at, see_link, &planted)) { *sbx_blocked = 0; return; }
    if (!keep && planted.found) return;
    if (r->meta) {
        if (!walk(path, true, at, sb_way, r->b)) *sbx_blocked = 0;
        return;
    }
    int n = keep ? 0 : homes(home);
    for (int i = 0; i < n; i++)
        if (covers(at, home[i])) return;
    if (n >= 0) sb_path(r->b, at);
}

/* the toolchain folders of each home and the files git's global configs name */
static bool each_home_read(const Reads *r, const char *proj, char home[4][PATH_MAX], int n) {
    char p[PATH_MAX];
    for (int i = 0; i < n; i++)
        for (int t = 0; SBX_TOOLS[t]; t++)
            if (snprintf(p, sizeof p, "%s/%s", home[i], SBX_TOOLS[t]) < (int)sizeof p)
                sb_read(r, p, false);
    Hooks h = {.proj = proj, .fn = no_node, .reads = r};
    bool ok = cfg_global(&h);
    values_cut(&h.hooks, 0);
    values_cut(&h.tree, 0);
    return ok;
}

/* ----- a project that is a submodule ----- */

/* every core.worktree of the git directory names the project, and one does */
static bool points_back(const char *gitdir, const char *proj) {
    Hooks h = {.proj = proj, .fn = no_node};
    bool ok = cfg_in(&h, gitdir, "config") && h.tree.n;
    for (int i = 0; ok && i < h.tree.n; i++) {
        char dir[PATH_MAX], full[PATH_MAX], at[PATH_MAX];
        ok = cfg_expand(h.tree.v[i], dir) && join(full, gitdir, dir) && realpath(full, at)
             && !strcmp(at, proj);
    }
    values_cut(&h.hooks, 0);
    values_cut(&h.tree, 0);
    *sbx_blocked = 0;
    return ok;
}

/* The git directory a submodule's .git file names, if it lies under modules/ of
   the nearest .git directory above and points back. Never one at a home or above
   it. A subdirectory of a repository gets nothing: git there reads the work tree
   root, which would list it. */
static bool module_dir(const char *proj, char home[4][PATH_MAX], int n, char *mod) {
    char git[PATH_MAX], line[PATH_MAX], up[PATH_MAX], mods[PATH_MAX];
    struct stat st;
    if (!join(git, proj, ".git") || lstat(git, &st) || !S_ISREG(st.st_mode)
        || !first_line(git, line, sizeof line) || strncmp(line, "gitdir: ", 8)
        || !resolve_from(proj, line + 8, mod)) return false;

    snprintf(up, sizeof up, "%s", proj);
    for (;;) {
        char *s = strrchr(up, '/');
        if (!s || s == up) return false;
        *s = 0;
        for (int i = 0; i < n; i++)
            if (covers(up, home[i])) return false;
        if (!join(git, up, ".git")) return false;
        if (lstat(git, &st)) {
            if (errno != ENOENT) return false;
        } else if (S_ISDIR(st.st_mode)) break;     /* a submodule may be inside another */
    }
    if (st.st_uid != getuid() || !join(mods, git, "modules")) return false;
    size_t len = strlen(mods);
    return !strncmp(mod, mods, len) && mod[len] == '/' && !lstat(mod, &st) && S_ISDIR(st.st_mode)
           && st.st_uid == getuid() && !in_secret_store(mod) && !covers(mod, proj)
           && points_back(mod, proj);
}

/* pipx asks whether its other default home is there and stops if it may not:
   that one entry can be looked up, never listed, and nothing in it read */
#define SBX_PIPX "Library/Application Support/pipx"

static bool sb_home_reads(Sb *b, const Areas *areas, const char *proj, const char *tmp,
                          const Linked *linked, const char *ro) {
    char home[4][PATH_MAX];
    int n = homes(home);
    if (n < 0) return false;
    if (n) {
        sb_add(b, "(deny file-read*");
        for (int i = 0; i < n; i++) sb_path(b, home[i]);
        sb_add(b, ")");
    }
    char mod[PATH_MAX];
    bool module = module_dir(proj, home, n, mod);
    for (int meta = 0; meta < 2; meta++) {
        Reads r = {.b = b, .meta = meta, .areas = areas};
        sb_add(b, meta ? "(allow file-read-metadata" : "(allow file-read*");
        b->from = b->n;
        sb_read(&r, proj, true);
        if (tmp) sb_read(&r, tmp, true);
        if (linked) {
            sb_read(&r, linked->dir, false);
            sb_read(&r, linked->common, false);
        }
        if (module) sb_read(&r, mod, false);
        if (ro) sb_read(&r, ro, false);
        for (int i = 0; i < n; i++)
            sb_read(&r, home[i], false);        /* itself only ever looked up */
        if (!each_home_read(&r, proj, home, n)) return false;
        char pipx[PATH_MAX];
        for (int i = 0; meta && i < n; i++)
            if (join(pipx, home[i], SBX_PIPX)) sb_read(&r, pipx, false);
        sb_add(b, ")");
    }
    b->from = b->n;
    return true;
}

/* Nothing a command writes may become the way to something readable, for it or
   a later one: where those ways run through a writable place they are closed. */
static bool sb_guard_reads(Sb *b, const Areas *areas, bool pins) {
    char home[4][PATH_MAX];
    int n = homes(home);
    Reads r = {.b = b, .areas = areas, .guard = true, .pins = pins};
    return n >= 0 && each_home_read(&r, areas->dir[0], home, n);
}

/* SBX_TOOL_SECRETS under each home, and under where its folder leads */
static void sb_tool_secrets(Sb *b) {
    char home[4][PATH_MAX], dir[PATH_MAX], to[PATH_MAX];
    int n = homes(home);
    if (n < 0) b->full = true;
    for (int i = 0; i < n; i++)
        for (size_t k = 0; k < sizeof SBX_TOOL_SECRETS / sizeof *SBX_TOOL_SECRETS; k++) {
            const char *const *c = SBX_TOOL_SECRETS[k];
            if (!join(dir, home[i], c[0])) { b->full = true; continue; }
            bool linked = sbx_resolve(dir, to, 0) && strcmp(dir, to);
            for (int j = 0; j <= linked; j++) {
                char at[SBX_RX], head[SBX_RX + 2], tail[SBX_RX], file[256];
                re_path(j ? to : dir, at, sizeof at);
                snprintf(head, sizeof head, "^%s", at);
                snprintf(tail, sizeof tail, "/%s%s%s(/|$)", c[1], fold(c[2], file), c[3]);
                sb_regex(b, head, tail);
            }
        }
}

/* the protected files of the project: closed, along with every link and gitfile
   on the way there, and every directory on the way pinned. Without a real .git
   directory nothing may create or change .git, or a prepared one could be moved
   into place. */
static void sb_project(Sb *b, const Areas *areas, bool repo, const Linked *linked) {
    const char *proj = areas->dir[0];
    char p[PATH_MAX];
    Rules r = {b, false};
    /* a root that is already a bare repository */
    bool is_bare = root_bare(proj);
    sb_add(b, "(deny file-write*");
    if (snprintf(p, sizeof p, "%s/.git", proj) >= (int)sizeof p) b->full = true;
    if (!repo) sb_path(b, p);
    for (int i = 0; is_bare && GIT_CLOSED[i]; i++) {
        if (snprintf(p, sizeof p, "%s/%s", proj, GIT_CLOSED[i]) >= (int)sizeof p) b->full = true;
        sb_path(b, p);
    }
    for (int i = 0; SBX_PROJ[i]; i++) {
        if (snprintf(p, sizeof p, "%s/%s", proj, SBX_PROJ[i]) >= (int)sizeof p) b->full = true;
        sb_path(b, p);
    }
    if (!each_protected(proj, sb_node, &r) || (linked && !walk_linked(linked, sb_node, &r)))
        b->full = true;
    /* once .git is not valid, a HEAD (in any case) makes the root itself a
       repository, and a command can make it so: never one in the root */
    for (int m = 0; m < 16; m++) {
        char head[5] = "head";
        for (int i = 0; i < 4; i++) if (m >> i & 1) head[i] = (char)toupper((unsigned char)head[i]);
        if (snprintf(p, sizeof p, "%s/%s", proj, head) >= (int)sizeof p) b->full = true;
        sb_filter(b, "literal", p);
    }
    if (!b->full && !sbx_probing && !sb_guard_reads(b, areas, false)) b->full = true;
    sb_add(b, ")(deny file-write-unlink");
    sb_pin(b, proj);
    r.pins = true;
    if (!each_protected(proj, sb_node, &r) || (linked && !walk_linked(linked, sb_node, &r)))
        b->full = true;
    if (!b->full && !sbx_probing && !sb_guard_reads(b, areas, true)) b->full = true;
    each_secret(sb_pin_secret, b);
    sb_add(b, ")");
}

/* ----- rules by name -----
   Not anchored, so they bind in every writable directory: nothing can be
   prepared in TMPDIR and moved into place. Constant in size, always on, and
   inherited by detached processes. The sandbox limits one regex string to 1023
   characters. */

/* every nested .git and .envrc (directory, file or link) and the files in a git
   directory that make git run something. repo: proj/.git is a real directory,
   the one .git that may be written into. other: the root's git directory under
   another name, closed in the same way, or NULL. */
static void sb_names(Sb *b, const char *proj, bool repo, const char *other) {
    char git[256], mods[256], trees[256], a[256], n[3][256], cfg[256];
    char closed[2][1100], t[2000], r[SBX_RX], o[SBX_RX], p[PATH_MAX], dir[2][SBX_RX + 2];
    fold(".git", git);
    fold("modules", mods);
    fold("worktrees", trees);
    /* two groups: one regex would pass the length limit */
    snprintf(closed[0], sizeof closed[0], "(%s|%s|%s|%s)(/|$)", fold("config", cfg),
             fold("config.worktree", n[0]), fold("commondir", n[1]), fold("hooks", n[2]));
    snprintf(closed[1], sizeof closed[1], "(%s|%s|%s)(/|$)", fold("rebase-merge", n[0]),
             fold("rebase-apply", n[1]), fold("sequencer", n[2]));
    if (snprintf(p, sizeof p, "%s/.git", proj) >= (int)sizeof p) b->full = true;
    /* where git directories are: any .git, and the other one by its path */
    const char *head[2] = {"", "^"};
    int dirs = other ? 2 : 1;
    snprintf(dir[0], sizeof dir[0], "/%s", git);
    if (other) {
        re_path(other, o, sizeof o);
        snprintf(dir[1], sizeof dir[1], "%s", o);
    }

    sb_add(b, "(deny file-write*");
    for (int i = 0; i < dirs; i++)
        for (int c = 0; c < 2; c++) {
            snprintf(t, sizeof t, "%s/%s", dir[i], closed[c]);
            sb_regex(b, head[i], t);
            snprintf(t, sizeof t, "%s/(%s/.+|%s/[^/]+)/%s", dir[i], mods, trees, closed[c]);
            sb_regex(b, head[i], t);
        }
    snprintf(t, sizeof t, "/%s(/|$)", fold(".envrc", a));
    sb_regex(b, "", t);
    if (repo) {
        sb_add(b, " (require-all");
        snprintf(t, sizeof t, "/%s$", git);
        sb_regex(b, "", t);
        sb_add(b, " (require-not");
        sb_filter(b, "literal", p);
        sb_add(b, "))");
    } else {
        snprintf(t, sizeof t, "/%s$", git);
        sb_regex(b, "", t);
        /* the root's, in any case of the name */
        re_path(proj, r, sizeof r);
        snprintf(t, sizeof t, "/%s(/|$)", git);
        char start[SBX_RX + 2];
        snprintf(start, sizeof start, "^%s", r);
        sb_regex(b, start, t);
    }
    /* no submodule or worktree entry appears, by creation or by renaming */
    sb_add(b, ")(deny file-write-create");
    for (int i = 0; i < dirs; i++) {
        snprintf(t, sizeof t, "%s/%s(/(.+/%s/)?[^/]+)?$", dir[i], mods, mods);
        sb_regex(b, head[i], t);
        snprintf(t, sizeof t, "%s/%s(/[^/]+)?$", dir[i], trees);
        sb_regex(b, head[i], t);
    }
    /* nor is one moved away and another put in its place */
    sb_add(b, ")(deny file-write-unlink");
    for (int i = 0; i < dirs; i++) {
        sb_add(b, " (require-all");
        snprintf(t, sizeof t, "%s/%s(/.+)?$", dir[i], mods);
        sb_regex(b, head[i], t);
        sb_add(b, " (vnode-type DIRECTORY))");
        snprintf(t, sizeof t, "%s/%s(/[^/]+)?$", dir[i], trees);
        sb_regex(b, head[i], t);
    }
    sb_add(b, ")");
}

/* uv opens a .git in its cache for writing and fails when it cannot. No command
   may create one, so TMPDIR starts with it, as a link to /dev/null: opening it
   needs no rule of its own, and it can never name a repository. The name rules
   keep the link itself; this keeps it where uv looks. */
#define SBX_UV_GIT "cache/uv/sdists-v9/.git"

static void sb_uv_git(Sb *b, const char *tmp) {
    char p[PATH_MAX];
    if (snprintf(p, sizeof p, "%s/%s", tmp, SBX_UV_GIT) >= (int)sizeof p) b->full = true;
    b->from = b->n;
    sb_add(b, "(deny file-write-unlink");
    sb_pin(b, p);
    sb_pin_above(b, p);
    sb_add(b, ")");
}

/* malloc'd profile, NULL if it cannot be built whole: the command is then not
   run. tmp, mark and ro (one more place to read, never to write) may be NULL. */
static char *sbx_profile(const char *cwd, const char *tmp, bool net, const char *mark,
                         const char *ro) {
    char proj[PATH_MAX], rtmp[PATH_MAX], git[PATH_MAX];
    *sbx_blocked = 0;
    if (!cwd || !realpath(cwd, proj)) return NULL;
    if (tmp && !realpath(tmp, rtmp)) return NULL;
    struct stat st;
    if (snprintf(git, sizeof git, "%s/.git", proj) >= (int)sizeof git) return NULL;
    bool repo = !lstat(git, &st) && S_ISDIR(st.st_mode);
    char elsewhere[PATH_MAX];
    int moved = gitdir_elsewhere(proj, elsewhere, no_node, NULL);
    if (moved < 0) return NULL;
    const char *other = moved ? elsewhere : NULL;
    Sb b = {.s = malloc(SBX_CAP)};
    b.s[0] = 0;
    sb_add(&b,
        "(version 1)(deny default)"
        "(allow process-exec process-fork)"
        "(allow signal (target same-sandbox))"
        "(allow process-info* (target same-sandbox))"
        "(allow sysctl-read)"
        "(allow file-read*)"
        "(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\"))"
        "(allow ipc-posix-shm ipc-posix-sem)"
        "(allow file-write-data file-ioctl (literal \"/dev/null\") (literal \"/dev/zero\")"
        " (literal \"/dev/dtracehelper\") (literal \"/dev/stdout\") (literal \"/dev/stderr\")"
        " (subpath \"/dev/fd\"))");
    Linked w;
    bool linked = linked_worktree(proj, &w);
    Areas areas;
    writable(&areas, proj, tmp ? rtmp : NULL, linked ? &w : NULL);
    sb_add(&b, "(allow file-write*");
    for (int i = 0; i < areas.n; i++) sb_path(&b, areas.dir[i]);
    sb_add(&b, ")");
    /* the probe runs a system binary: a home that cannot be ruled on must stop
       commands, not make the sandbox count as unavailable */
    if (!sbx_probing && !sb_home_reads(&b, &areas, proj, tmp ? rtmp : NULL, linked ? &w : NULL, ro)) {
        free(b.s);
        return NULL;
    }
    /* the last matching rule wins: secrets stay closed even inside the project */
    sb_add(&b, "(deny file-read* file-write*");
    each_secret(sb_deny_secret, &b);
    if (!sbx_probing) sb_tool_secrets(&b);
    sb_add(&b, ")");
    sb_project(&b, &areas, repo, linked ? &w : NULL);
    sb_names(&b, proj, repo, other);
    if (tmp) sb_uv_git(&b, rtmp);
    /* names this command's processes, so that all of them can be found later */
    if (mark) {
        char rule[160];
        snprintf(rule, sizeof rule, "(allow mach-lookup (global-name \"%s-a\"))", mark);
        sb_add(&b, rule);
    }
    /* IP and name lookup only: other unix sockets (Docker, ssh-agent) stay shut */
    if (net)
        sb_add(&b,
            "(allow system-socket)"
            "(allow network-outbound (remote ip)"
            " (remote unix-socket (path-literal \"/private/var/run/mDNSResponder\")))"
            "(allow network-bind network-inbound (local ip))"
            "(allow mach-lookup (global-name \"com.apple.trustd.agent\")"
            " (global-name \"com.apple.TrustEvaluationAgent\")"
            " (global-name \"com.apple.SystemConfiguration.configd\"))");
    if (b.full) { free(b.s); return NULL; }
    return b.s;
}

bool sandbox_available(void) {
    if (sbx_state >= 0) return sbx_state;
    sbx_state = 0;
#ifdef __APPLE__
    /* run something under a real profile: a nested sandbox or a policy that
       blocks sandbox-exec must count as unavailable */
    sbx_probing = true;
    char *prof = sbx_profile("/usr/share", NULL, false, NULL, NULL);
    sbx_probing = false;
    if (!prof) return false;
    pid_t pid = fork();
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) { dup2(devnull, 0); dup2(devnull, 1); dup2(devnull, 2); }
        execl(SBX_EXEC, "sandbox-exec", "-p", prof, "/usr/bin/true", (char *)NULL);
        _exit(127);
    }
    free(prof);
    int status = 0;
    pid_t w;
    do w = pid > 0 ? waitpid(pid, &status, 0) : -1; while (w < 0 && errno == EINTR);
    sbx_state = w == pid && WIFEXITED(status) && !WEXITSTATUS(status);
#endif
    return sbx_state;
}

void sandbox_disable_for_test(bool off) { sbx_state = off ? 0 : -1; }

bool sandbox_on(void) { return !g_cfg.unsafe && sandbox_available(); }

static char sbx_tmp[PATH_MAX];
static pid_t sbx_owner;

/* in a new TMPDIR, before any command has seen it. A failure only costs uv. */
static void sbx_tmp_fill(const char *tmp) {
    char p[PATH_MAX];
    if (snprintf(p, sizeof p, "%s/%s", tmp, SBX_UV_GIT) >= (int)sizeof p) return;
    for (char *s = p + strlen(tmp) + 1; (s = strchr(s, '/')); *s++ = '/') {
        *s = 0;
        mkdir(p, 0700);
    }
    if (symlink("/dev/null", p)) return;
}

static void sbx_tmp_remove(void) {
    if (getpid() != sbx_owner) return;
    char p[PATH_MAX];
    if (snprintf(p, sizeof p, "%s/%s", sbx_tmp, SBX_UV_GIT) < (int)sizeof p) {
        unlink(p);
        for (char *s; (s = strrchr(p, '/')) && s > p + strlen(sbx_tmp); ) {
            *s = 0;
            rmdir(p);
        }
    }
    rmdir(sbx_tmp);   /* only if nothing else was left in it */
}

/* this process's private TMPDIR, NULL if it cannot be made */
static const char *sbx_tmpdir(void) {
    struct stat st;
    if (*sbx_tmp && !lstat(sbx_tmp, &st) && S_ISDIR(st.st_mode) && st.st_uid == getuid())
        return sbx_tmp;
    const char *base = getenv("TMPDIR");
    if (!base || !*base) base = "/tmp";
    snprintf(sbx_tmp, sizeof sbx_tmp, "%s%sfwsbx-XXXXXX", base,
             base[strlen(base) - 1] == '/' ? "" : "/");
    if (!mkdtemp(sbx_tmp)) { *sbx_tmp = 0; return NULL; }
    sbx_tmp_fill(sbx_tmp);
    if (!sbx_owner) { sbx_owner = getpid(); atexit(sbx_tmp_remove); }
    return sbx_tmp;
}

#define SBX_NENV 11

static bool through_link(const char *path) {
    char p[PATH_MAX];
    if (snprintf(p, sizeof p, "%s", path) >= (int)sizeof p) return false;
    for (char *s = p + 1;; s++) {
        if (*s && *s != '/') continue;
        char c = *s;
        *s = 0;
        struct stat st;
        if (!lstat(p, &st) && S_ISLNK(st.st_mode)) return true;
        if (!(*s = c)) return false;
    }
}

/* any step of the way, or its end, in a place a command may write */
static void see_open(Node kind, const char *path, void *arg) {
    (void)kind;
    Planted *p = arg;
    if (in_areas(p->areas, path)) p->found = true;
}

/* False also for what cannot be followed. */
static bool fixed_way(const char *path, const Areas *areas) {
    char at[PATH_MAX];
    Planted p = {.areas = areas};
    if (!walk(path, true, at, see_open, &p)) {
        *sbx_blocked = 0;
        return false;
    }
    return !p.found;
}

/* "PATH=..." with each entry that passes through a link, and is or leads under a
   home, replaced by where it leads: a link there cannot be read, and a PATH
   search that fails on it gives up (libuv). An entry whose way touches a place
   commands may write stays as it is: a command could repoint a link there to
   learn where a link it cannot read leads. Closed entries stay: programs in
   them run. */
static char *sbx_path(const char *v, const char *cwd, const char *tmp) {
    char home[4][PATH_MAX], one[PATH_MAX], to[PATH_MAX];
    int n = homes(home);
    char proj[PATH_MAX], rtmp[PATH_MAX];
    Linked w;
    Areas areas = {.n = 0};
    bool known = realpath(cwd, proj) && realpath(tmp, rtmp);
    if (known) writable(&areas, proj, rtmp, linked_worktree(proj, &w) ? &w : NULL);
    *sbx_blocked = 0;
    size_t entries = 1;
    for (const char *p = v; *p; p++) entries += *p == ':';
    size_t cap = strlen(v) + entries * PATH_MAX + 6, len = 5;
    char *out = malloc(cap);
    memcpy(out, "PATH=", 6);
    for (;;) {
        size_t k = strcspn(v, ":");
        const char *use = v;
        size_t used = k;
        if (*v == '/' && k < sizeof one) {
            memcpy(one, v, k);
            one[k] = 0;
            if (known && through_link(one) && fixed_way(one, &areas)
                && realpath(one, to) && !strchr(to, ':')) {
                bool under = false;
                for (int i = 0; i < n; i++)
                    under = under || path_under(home[i], one) || path_under(home[i], to);
                if (under) { use = to; used = strlen(to); }
            }
        }
        memcpy(out + len, use, used);
        len += used;
        if (!v[k]) break;
        out[len++] = ':';
        v += k + 1;
    }
    out[len] = 0;
    return out;
}

/* the whole environment of a command: nothing else is inherited (tokens, agent
   sockets). The cache variables keep build tools out of the home directory. */
/* Where that folder exists pipx also makes it its home, which commands cannot
   read, so they are given one in TMPDIR, and a man page folder there too, the one
   it makes in the real home being closed as well. */
static void sbx_env(char **env, const char *cwd, const char *tmp) {
    static const char *const keep[] = {"PATH", "HOME", "LANG", "TERM", NULL};
    static const char *const redirect[][2] = {{"TMPDIR", ""}, {"XDG_CACHE_HOME", "/cache"},
        {"GOCACHE", "/go-build"}, {"npm_config_cache", "/npm"}, {NULL, NULL}};
    int n = 0;
    for (int i = 0; keep[i]; i++) {
        const char *v = getenv(keep[i]);
        if (!v) continue;
        if (!strcmp(keep[i], "PATH")) { env[n++] = sbx_path(v, cwd, tmp); continue; }
        size_t len = strlen(keep[i]) + strlen(v) + 2;
        env[n] = malloc(len);
        snprintf(env[n++], len, "%s=%s", keep[i], v);
    }
    for (int i = 0; redirect[i][0]; i++) {
        size_t len = strlen(redirect[i][0]) + strlen(tmp) + strlen(redirect[i][1]) + 2;
        env[n] = malloc(len);
        snprintf(env[n++], len, "%s=%s%s", redirect[i][0], tmp, redirect[i][1]);
    }
    const char *home = getenv("HOME");
    char pipx[PATH_MAX];
    struct stat st;
    if (home && *home == '/' && join(pipx, home, SBX_PIPX) && !stat(pipx, &st)) {
        static const char *const own[][2] = {{"PIPX_HOME", "/pipx"},
            {"PIPX_MAN_DIR", "/pipx/man"}};
        for (int i = 0; i < 2; i++) {
            size_t len = strlen(own[i][0]) + strlen(tmp) + strlen(own[i][1]) + 2;
            env[n] = malloc(len);
            snprintf(env[n++], len, "%s=%s%s", own[i][0], tmp, own[i][1]);
        }
    }
    env[n] = NULL;
}

#ifdef __APPLE__
/* the profile of one command allows looking up "<mark>-a" and nothing else of
   that name, which no other process matches */
static bool sbx_ours(pid_t pid, const char *a, const char *b) {
    const int global_name = 2, no_report = 0x40000000;
    return sandbox_check(pid, "mach-lookup", global_name | no_report, a) == 0
        && sandbox_check(pid, "mach-lookup", global_name | no_report, b) == 1;
}
#endif

/* Kill every process of the command named by mark, detached ones included.
   Returns how many were found; *left says some are still there. */
static int sbx_sweep(const char *mark, bool grace, bool *left) {
    int total = 0;
    *left = false;
#ifdef __APPLE__
    char a[96], b[96];
    snprintf(a, sizeof a, "%s-a", mark);
    snprintf(b, sizeof b, "%s-b", mark);
    for (int round = 0; round < 50; round++) {
        int cap = proc_listallpids(NULL, 0) + 256;
        pid_t *pids = malloc((size_t)cap * sizeof *pids);
        int n = proc_listallpids(pids, cap * (int)sizeof *pids), found = 0;
        for (int i = 0; i < n; i++)
            if (pids[i] > 1 && pids[i] != getpid() && sbx_ours(pids[i], a, b)) pids[found++] = pids[i];
        if (found && grace) {   /* let what is already finishing finish */
            grace = false;
            free(pids);
            usleep(100000);
            continue;
        }
        /* all stopped before any dies, so that none can start another */
        for (int i = 0; i < found; i++) kill(pids[i], SIGSTOP);
        for (int i = 0; i < found; i++) kill(pids[i], SIGKILL);
        free(pids);
        *left = found > 0;
        if (!found) break;
        total += found;
        usleep(2000);
    }
#else
    (void)mark;
    (void)grace;
#endif
    return total;
}

static void sbx_mark(char *mark, size_t cap) {
    static unsigned runs;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    snprintf(mark, cap, "fw.mark.%ld.%ld.%09ld.%u", (long)getpid(), (long)ts.tv_sec,
             ts.tv_nsec, ++runs);
}

/* the profile, or NULL with the reason in why */
static char *sbx_setup(const char *cwd, const char *tmp, bool net, const char *mark,
                       const char *ro, char *why, size_t cap) {
    char *prof = NULL;
    *sbx_blocked = 0;
    if (each_secret(secret_unresolved, NULL) || !(prof = sbx_profile(cwd, tmp, net, mark, ro)))
        snprintf(why, cap, "error: cannot set up the sandbox for this directory%s%s%s%s"
                 " — not executed", *sbx_blocked ? ": " : "", *sbx_blocked ? sbx_reason : "",
                 *sbx_blocked ? " " : "", sbx_blocked);
    return prof;
}

/* in the child: no inherited sockets or files, and no controlling terminal */
static void sbx_detach(void) {
    long max = sysconf(_SC_OPEN_MAX);
    for (int fd = 3; fd < (max > 0 && max < 65536 ? max : 65536); fd++) close(fd);
    setsid();
}

/* cwd is below the root of a repository under a home, which commands cannot
   read: git there reports that there is none */
static bool below_repo(const char *cwd) {
    char p[PATH_MAX], git[PATH_MAX], home[4][PATH_MAX];
    struct stat st;
    int n = homes(home);
    if (!realpath(cwd, p) || !join(git, p, ".git") || !lstat(git, &st)) return false;
    for (char *s; (s = strrchr(p, '/')) && s != p; ) {
        *s = 0;
        if (!join(git, p, ".git") || lstat(git, &st)) continue;
        for (int i = 0; i < n; i++)
            if (path_under(home[i], p)) return true;
        return false;
    }
    return false;
}

static char *run_command(const char *cmd, const char *cwd, int timeout_s, int *code, bool net) {
    if (code) *code = -1;
    /* --unsafe: as is. Otherwise a clean environment always, and the sandbox when
       there is one (without it only an interactive session gets this far) */
    bool clean = !g_cfg.unsafe, boxed = sandbox_on();
    char *env[SBX_NENV] = {NULL}, *prof = NULL;
    char mark[64] = "";
    if (clean) {
        const char *tmp = sbx_tmpdir();
        if (!tmp) return str_dup("error: cannot create a private TMPDIR — not executed");
        if (boxed) {
            char why[PATH_MAX + 128];
            if (net) sbx_mark(mark, sizeof mark);
            prof = sbx_setup(cwd, tmp, net, *mark ? mark : NULL, NULL, why, sizeof why);
            if (!prof) return str_dup(why);
        }
        sbx_env(env, cwd, tmp);
    }
    int fds[2];
    pid_t pid = -1;
    if (!pipe(fds)) {
        fcntl(fds[0], F_SETFL, O_NONBLOCK);
        pid = fork();
        if (pid < 0) { close(fds[0]); close(fds[1]); }
    }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], 1); dup2(fds[1], 2);
        close(fds[1]);
        /* children must not steal keystrokes from the TUI */
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) { dup2(devnull, 0); close(devnull); }
        if (chdir(cwd)) {
            perror("error: cannot enter the working directory");
            _exit(126);
        }
        if (clean) {
            sbx_detach();
            if (boxed)
                execle(SBX_EXEC, "sandbox-exec", "-p", prof, "/bin/bash", "-c", cmd,
                       (char *)NULL, env);
            else execle("/bin/bash", "bash", "-c", cmd, (char *)NULL, env);
        } else {
            setpgid(0, 0);
            execl("/bin/bash", "bash", "-c", cmd, (char *)NULL);
        }
        _exit(127);
    }
    free(prof);
    for (int i = 0; env[i]; i++) free(env[i]);
    if (pid < 0) return str_dup("error: pipe failed");
    close(fds[1]);
    char *buf = malloc(OUT_CAP + 1);
    size_t len = 0;
    int status = 0;
    bool timed = false;
    struct timespec t0, now;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        bool more = drain_pipe(fds[0], buf, &len, OUT_CAP, 64);
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
    /* nothing started with network access outlives its approval, not even what
       left the process group; the rest stays bound by the sandbox and lives on */
    if (net && !timed) killpg(pid, SIGKILL);
    int swept = 0;
    bool left = false;
    if (boxed && net) swept = sbx_sweep(mark, !timed && !g_abort, &left);
    /* drain what is left; bounded so a surviving background writer can't pin us */
    drain_pipe(fds[0], buf, &len, OUT_CAP, 1024);
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
    if (boxed) {
        /* after the truncation, so that it always reaches the reader */
        const char *denied = strstr(out, "could not lock config file")
                             || strstr(out, "could not write config")
            ? "[sandbox: git config and hooks are read-only here — that setting was NOT saved,"
              " whatever git reported]\n" : "";
        const char *stopped = left
            ? "[sandbox: some processes of this command could NOT be stopped, tell the user]\n"
            : swept && !timed
            ? "[sandbox: background processes of a network command end with it; they were"
              " stopped]\n" : "";
        const char *above = strstr(out, "ot a git repository") && below_repo(cwd)
            ? "[sandbox: the project is inside a git repository whose root is above it; commands"
              " cannot read that, so git does not work here — start at the repository root]\n" : "";
        if (*denied || *stopped || *above) {
            size_t cap = strlen(out) + strlen(denied) + strlen(stopped) + strlen(above) + 2;
            char *t = malloc(cap);
            snprintf(t, cap, "%s%s%s%s%s", out, out[strlen(out) - 1] == '\n' ? "" : "\n", denied,
                     stopped, above);
            free(out);
            out = t;
        }
    }
    return out;
}

char *run_bash(const char *cmd, const char *cwd, int timeout_s) {
    return run_command(cmd, cwd, timeout_s, NULL, false);
}

char *run_bash_status(const char *cmd, const char *cwd, int timeout_s, int *code) {
    return run_command(cmd, cwd, timeout_s, code, false);
}

char *run_bash_net(const char *cmd, const char *cwd, int timeout_s, int *code) {
    return run_command(cmd, cwd, timeout_s, code, true);
}

/* see flywheel.h. Nothing is shared with the agent's commands, which may have
   left processes behind: the caller's work and a TMPDIR inside it are new. */
bool run_script(const char *script, const char *a1, const char *a2, const char *work,
                const char *ro, int timeout_s, char **out, char **err) {
    *out = NULL;
    *err = NULL;
    bool boxed = !g_cfg.unsafe;
    char *env[SBX_NENV] = {NULL}, *prof = NULL;
    char mark[64] = "", tmp[PATH_MAX], rro[PATH_MAX], why[PATH_MAX + 128];
    if (boxed) {
        const char *no = NULL;
        if (!sandbox_available()) no = "error: no sandbox here and no --unsafe — not executed";
        else if (snprintf(tmp, sizeof tmp, "%s/tmp", work) >= (int)sizeof tmp
                 || mkdir(tmp, 0700) || !realpath(ro, rro))
            no = "error: cannot create the script's directories — not executed";
        if (no) { *err = str_dup(no); return false; }
        sbx_tmp_fill(tmp);
        sbx_mark(mark, sizeof mark);
        if (!(prof = sbx_setup(work, tmp, false, mark, rro, why, sizeof why))) {
            *err = str_dup(why);
            return false;
        }
        sbx_env(env, work, tmp);
    }
    int o[2] = {-1, -1}, e[2] = {-1, -1};
    pid_t pid = -1;
    if (!pipe(o) && !pipe(e)) {
        fcntl(o[0], F_SETFL, O_NONBLOCK);
        fcntl(e[0], F_SETFL, O_NONBLOCK);
        pid = fork();
    }
    if (pid == 0) {
        dup2(o[1], 1);
        dup2(e[1], 2);
        close(o[0]); close(o[1]); close(e[0]); close(e[1]);
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) { dup2(devnull, 0); close(devnull); }
        if (boxed) {
            if (chdir(work)) _exit(126);
            sbx_detach();
            /* env: the bash found in PATH, as without the sandbox */
            execle(SBX_EXEC, "sandbox-exec", "-p", prof, "/usr/bin/env", "bash", script, a1, a2,
                   (char *)NULL, env);
        } else {
            setpgid(0, 0);
            execlp("bash", "bash", script, a1, a2, (char *)NULL);
        }
        _exit(127);
    }
    free(prof);
    for (int i = 0; env[i]; i++) free(env[i]);
    if (o[1] >= 0) close(o[1]);
    if (e[1] >= 0) close(e[1]);
    if (pid < 0) {
        if (o[0] >= 0) close(o[0]);
        if (e[0] >= 0) close(e[0]);
        *err = str_dup("error: cannot start the script");
        return false;
    }
    char *ob = malloc(SCRIPT_CAP + 1), *eb = malloc(OUT_CAP + 1);
    size_t ol = 0, el = 0;
    int status;
    bool timed = false;
    struct timespec t0, now;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        bool more = drain_pipe(o[0], ob, &ol, SCRIPT_CAP, 64);
        more = drain_pipe(e[0], eb, &el, OUT_CAP, 64) || more;
        if (waitpid(pid, &status, WNOHANG) == pid) break;
        if (!more) usleep(20000);
        clock_gettime(CLOCK_MONOTONIC, &now);
        double waited = (now.tv_sec - t0.tv_sec) + (now.tv_nsec - t0.tv_nsec) / 1e9;
        if ((timeout_s > 0 && waited >= timeout_s) || g_abort) {
            timed = true;
            killpg(pid, SIGKILL);
            kill(pid, SIGKILL);   /* in case it has no group of its own yet */
            waitpid(pid, &status, 0);
            break;
        }
    }
    /* nothing the script started outlives it */
    if (!timed) killpg(pid, SIGKILL);
    bool left = false;
    if (boxed) sbx_sweep(mark, false, &left);
    if (left) fprintf(stderr, "flywheel: some processes of %s could NOT be stopped\n", script);
    drain_pipe(o[0], ob, &ol, SCRIPT_CAP, 1024);
    drain_pipe(e[0], eb, &el, OUT_CAP, 1024);
    close(o[0]);
    close(e[0]);
    ob[ol] = 0;
    eb[el] = 0;
    utf8_sanitize(ob);
    utf8_sanitize(eb);
    *out = ob;
    *err = eb;
    return true;
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

/* one of `want` in a short option cluster, before any attached value */
static bool has_letter(const char *a, const char *want, const char *valued) {
    for (a++; *a; a++) {
        if (strchr(want, *a)) return true;
        if (strchr(valued, *a)) break;
    }
    return false;
}

/* git ls-remote/clone take flags that run programs (-c, --config, --template,
   -u ...): only the exact ones listed here go unasked */
static bool git_remote_unsafe(char **v, int n) {
    int k = 1;
    bool global = false, unknown = false;
    for (; k < n && v[k][0] == '-'; k++) {
        global = true;
        if (!strcmp(v[k], "-c") || !strcmp(v[k], "-C")) k++;
        else unknown = true;   /* may take the next word as its value */
    }
    for (int i = 1; unknown && i < n; i++)
        if (!strcmp(v[i], "clone") || !strcmp(v[i], "ls-remote")) return true;
    if (k >= n) return false;
    bool clone = !strcmp(v[k], "clone");
    if (!clone && strcmp(v[k], "ls-remote")) return false;
    if (global) return true;
    const char *flags = clone ? "-q --quiet -v --verbose --progress -n --no-checkout --bare "
                                "--single-branch --no-single-branch --no-tags"
                              : "-h --heads -t --tags --branches --refs -q --quiet --exit-code "
                                "--get-url --symref";
    const char *valued = clone ? "--depth -b --branch -o --origin" : "--sort";
    for (k++; k < n; k++) {
        const char *a = v[k], *eq = strchr(a, '=');
        if (!strcmp(a, "--")) break;
        if (a[0] != '-') continue;
        if (word_in(flags, a, strlen(a))) continue;
        if (!word_in(valued, a, strcspn(a, "="))) return true;
        if (!eq) k++;
    }
    return false;
}

/* go flags write files and run programs under many names: only these pass */
static bool go_flag_ok(const char *a) {
    const char *name = a + (a[1] == '-' ? 2 : 1);
    if (!strncmp(name, "test.", 5)) name += 5;
    return word_in("v race run count short timeout tags bench benchmem failfast json cover covermode "
                   "parallel atomic", name, strcspn(name, "="));
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
        read_word(&p, top, NULL, NULL);
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
    bool go = !strcmp(c, "go");
    if (git && git_remote_unsafe(v, n)) bad = true;
    bool grep = !strcmp(c, "grep"), ls = !strcmp(c, "ls"), perl = !strncmp(c, "perl", 4);
    bool opts = true;
    int plain = 0;
    for (int i = 1; i < n && !bad; i++) {
        const char *a = v[i];
        bool shortopt = a[0] == '-' && a[1] != '-';
        /* recursive reads that follow symlinks can leave the project */
        if (grep && (abbrev(a, "--dereference-recursive", 5) || (shortopt && has_letter(a, "RS", "efmABCDd"))))
            bad = true;
        if (rg && (!strcmp(a, "--follow") || (shortopt && has_letter(a, "L", "efgtTABCmMjdEr")))) bad = true;
        if (fd && (!strcmp(a, "--follow") || (shortopt && has_letter(a, "L", "deEtScoj")))) bad = true;
        if (find && (!strcmp(a, "-follow") || (shortopt && strspn(a + 1, "HLPEXdsx") == strlen(a + 1) &&
                                               strchr(a, 'L')))) bad = true;
        if (ls && (abbrev(a, "--dereference", 5) || (shortopt && has_letter(a, "L", "wTI")))) bad = true;
        if (perl && shortopt && (strchr(a, 'e') || strchr(a, 'E'))) bad = true;   /* opaque code */
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
        if (git && (abbrev(a, "--upload-pack", 3) || abbrev(a, "--receive-pack", 5) ||
                    abbrev(a, "--exec", 3))) bad = true;   /* runs a program */
        if (go && a[0] == '-' && a[1] && !go_flag_ok(a)) bad = true;
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

/* grep/rg: the first operand is the pattern unless -e/-f gave one. Options
   not listed here may shift that position, so then nothing is skipped. */
static bool grep_reads_outside(const char *p, bool rg, char *buf) {
    static const char *const flags[] = {"--recursive", "--line-number", "--ignore-case", "--count",
        "--files-with-matches", "--word-regexp", "--fixed-strings", "--extended-regexp", "--hidden",
        "--no-ignore", "--smart-case", "--color", NULL};
    const char *valued = rg ? "efgtTABCmMjdEr" : "efmABCDd";
    bool given = false, unknown = false, opts = true, out = false;
    char next = 0;   /* option letter waiting for its value */
    char *first = NULL;
    while (!out && *p) {
        if (strchr(" \t()", *p)) { p++; continue; }
        read_word(&p, buf, NULL, NULL);
        if (next) {
            if (next == 'f') out = !read_inside(buf);
            next = 0;
        } else if (opts && !strcmp(buf, "--")) opts = false;
        else if (opts && buf[0] == '-' && buf[1] == '-') {
            const char *eq = strchr(buf, '=');
            if (!strncmp(buf, "--regexp", 8) || !strncmp(buf, "--file=", 7) || !strcmp(buf, "--file"))
                given = true;
            else if (!eq && !one_of(buf, flags)) unknown = true;
            if (!strcmp(buf, "--regexp")) next = 'e';
            else if (eq && strncmp(buf, "--regexp=", 9)) out = !read_inside(eq + 1);
        } else if (opts && buf[0] == '-' && buf[1]) {
            for (const char *c = buf + 1; *c; c++) {
                if (!strchr(valued, *c)) continue;
                if (*c == 'e' || *c == 'f') given = true;
                if (!c[1]) next = *c;
                else if (*c == 'f') out = !read_inside(c + 1);
                break;
            }
        } else if (!first) first = str_dup(buf);   /* judged once -e/-f are known */
        else out = !read_inside(buf);
    }
    if (!out && first && (given || unknown)) out = !read_inside(first);
    free(first);
    return out;
}

/* a builtin reader given a path outside the project must prompt */
static bool reads_outside(const char *cmd) {
    static const char *const readers[] = {"ls", "cat", "grep", "rg", "find", "fd", "head", "tail",
        "wc", "file", "stat", "cd", "test", "sort", "uniq", "cut", NULL};
    char *buf = malloc(strlen(cmd) + 1);
    const char *p = cmd;
    read_word(&p, buf, NULL, NULL);
    bool out = false, cut = !strcmp(buf, "cut"), sort = !strcmp(buf, "sort"), skip = false;
    if (!strcmp(buf, "grep") || !strcmp(buf, "rg"))
        out = grep_reads_outside(p, buf[0] == 'r', buf);
    else if (one_of(buf, readers))
        while (!out && *p) {
            if (strchr(" \t()", *p)) { p++; continue; }
            read_word(&p, buf, NULL, NULL);
            if (skip) { skip = false; continue; }
            const char *path = buf;
            if (buf[0] == '-' && buf[1]) {
                const char *eq = strchr(buf, '=');
                if (buf[1] == '-') path = eq ? eq + 1 : "";
                else if ((cut && buf[1] == 'd') || (sort && buf[1] == 't')) {
                    skip = !buf[2];                      /* separate delimiter */
                    path = "";
                } else {   /* attached value: -f/etc/x, -nf../x */
                    path = buf + 1 + strcspn(buf + 1, "/~.");
                }
            }
            out = !read_inside(path);
        }
    free(buf);
    return out;
}

static bool is_gate(const char *s) {
    return !strncmp(s, GATE_PERM, sizeof GATE_PERM - 1);
}

/* A verification gate is remembered as its whole command, matched exactly and
   never applied to the model's own commands. */
bool perm_gate_allowed(const char *cmd) {
    perm_load();
    for (int i = 0; i < nrules; i++)
        if (is_gate(rules[i]) && !strcmp(rules[i] + sizeof GATE_PERM - 1, cmd)) return true;
    return perm_allowed(cmd);
}

bool perm_allowed(const char *cmd) {
    perm_load();
    while (*cmd == ' ') cmd++;
    if (is_gate(cmd)) return false;
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
    if (strpbrk(rule, "\n\r")) return;   /* the file holds one rule per line */
    perm_load();
    for (int i = 0; i < nrules; i++)
        if (!strcmp(rules[i], rule)) return;
    if (nrules < MAX_RULES) rules[nrules++] = str_dup(rule);
    char p[PATH_MAX];
    if (!perm_project_file(p, sizeof p) || !mkdir_parents(p)) return;
    FILE *f = fopen(p, "a");
    if (f) { fprintf(f, "%s\n", rule); fclose(f); }
}

/* "always" rules are only offered for these: tools whose second word is a
   fixed subcommand, and a few that cannot run other code. */
static const struct { const char *tool, *subs; } SUBCMDS[] = {
    {"git", "status log diff show add commit fetch branch blame rev-parse ls-files describe"},
    {"npm", "test ls run"},
    {"npx", "vitest jest tsc eslint prettier"},
    {"go", "build test vet fmt"},
    {"cargo", "build test check clippy fmt"},
    {"brew", "list info search"},
    {"pip", "list show"},
    {"pip3", "list show"},
    {"docker", "ps images"},
    {"kubectl", "get describe"},
};
static const char *PLAIN_TOOLS = "rm rmdir mkdir touch cp mv ln chmod uname whoami id du df diff cmp "
    "basename dirname realpath readlink md5 md5sum shasum sha256sum";

/* "always" rule derived from a command: the tool, or tool and subcommand
   ("npm run" also needs the script name). "" = nothing safe to remember. */
char *perm_prefix(const char *cmd) {
    if (strpbrk(cmd, "\n\r")) return str_dup("");
    char w[3][96] = {{0}};
    for (int i = 0; i < 3; i++) {
        while (*cmd == ' ' || *cmd == '\t') cmd++;
        size_t n = strcspn(cmd, " \t");
        if (n < sizeof w[i]) memcpy(w[i], cmd, n);
        cmd += n;
    }
    char out[300] = {0};
    if (word_in(PLAIN_TOOLS, w[0], strlen(w[0])) && w[0][0]) snprintf(out, sizeof out, "%s", w[0]);
    for (size_t i = 0; i < sizeof SUBCMDS / sizeof *SUBCMDS; i++) {
        if (strcmp(w[0], SUBCMDS[i].tool) || !w[1][0] || !word_in(SUBCMDS[i].subs, w[1], strlen(w[1])))
            continue;
        if (strcmp(w[0], "npm") || strcmp(w[1], "run"))
            snprintf(out, sizeof out, "%s %s", w[0], w[1]);
        else if (w[2][0] && w[2][0] != '-')
            snprintf(out, sizeof out, "%s %s %s", w[0], w[1], w[2]);
    }
    return str_dup(out);
}

void perm_free(void) {
    for (int i = 0; i < nrules; i++) { free(rules[i]); rules[i] = NULL; }
    nrules = 0;
    rules_loaded = false;
}

/* ---------- structured file tools (write_file / edit_file) ---------- */

void (*fw_file_hook)(void);

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
   are created, after every component has been checked and never through a
   link; dangling links are refused. */
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
            if (in_secret_store(real)) return "error: path is in a credential store";
            snprintf(cur, sizeof cur, "%s", real);
        } else {
            if (in_secret_store(next)) return "error: path is in a credential store";
            /* the filesystem folds some of these into the ASCII of a store not
               made yet; an existing one is compared by inode above */
            if (non_ascii(tok) && lstat(next, &st) && each_secret(store_below, cur))
                return "error: new non-ASCII name next to a credential store — use an ASCII name";
            snprintf(cur, sizeof cur, "%s", next);
        }
        tok = next_tok;
    }

    if (in_secret_store(cur)) return "error: path is in a credential store";
    if (for_write) {
        const char *leaf;
        int dfd = open_parent(cur, true, &leaf);
        if (dfd < 0) return "error: cannot create parent directories";
        close(dfd);
    }
    snprintf(out, cap, "%s", cur);
    return NULL;
}

typedef struct { const char *abs; bool hit; } Guard;

/* abs is link-free, so a link on the way never is it */
static void guard_node(Node kind, const char *path, void *arg) {
    Guard *g = arg;
    if ((kind == N_ENTRY || kind == N_CLOSED) && path_under(path, g->abs)) g->hit = true;
}

/* the file tools run outside the sandbox: they keep its SBX_PROJ rule, and for
   what is below the root, the same names the sandbox closes */
static const char *protected_write(const char *cwd, const char *abs) {
    static const char *const why =
        "error: this file can run code outside the sandbox (.envrc, git hooks and config)";
    static char unsure[PATH_MAX + 64];
    char root[PATH_MAX], p[PATH_MAX], other[PATH_MAX];
    if (!realpath(cwd, root)) return NULL;
    for (int i = 0; SBX_PROJ[i]; i++) {
        if (snprintf(p, sizeof p, "%s/%s", root, SBX_PROJ[i]) >= (int)sizeof p) return why;
        if (path_under(p, abs)) return why;
    }
    Guard g = {abs, false};
    *sbx_blocked = 0;
    int moved = each_protected(root, guard_node, &g)
                ? gitdir_elsewhere(root, other, no_node, NULL) : -1;
    if (moved < 0) {
        snprintf(unsure, sizeof unsure, "error: %s %s — not written",
                 *sbx_blocked ? sbx_reason : "cannot follow or read", sbx_blocked);
        return unsure;
    }
    if (g.hit) return why;
    struct stat st;
    snprintf(p, sizeof p, "%s/.git", root);
    bool any = !lstat(p, &st);
    if (path_under(p, abs) && (!any || !S_ISDIR(st.st_mode))) return why;
    if (!is_within(root, abs)) return NULL;

    char rel[PATH_MAX], dir[PATH_MAX];
    snprintf(rel, sizeof rel, "%s", abs + strlen(root));
    snprintf(dir, sizeof dir, "%s", root);
    enum { OUTSIDE, GITDIR, SUBREPOS, DATA } at = OUTSIDE;
    char *save = NULL;
    for (char *tok = strtok_r(rel, "/", &save), *next; tok; tok = next) {
        next = strtok_r(NULL, "/", &save);
        if (!strcasecmp(tok, ".envrc")) return why;
        bool top = !strcmp(dir, root);
        /* in the root only what is below an existing directory of that name */
        if (top && !strcasecmp(tok, "HEAD")) {
            struct stat h;
            snprintf(p, sizeof p, "%s/%s", root, tok);
            if (!next || lstat(p, &h) || !S_ISDIR(h.st_mode)) return why;
        }
        if ((top ? root_bare(dir) : bare_like(dir)) && (gitdir_name(tok) || non_ascii(tok)))
            return why;
        size_t n = strlen(dir);
        snprintf(dir + n, sizeof dir - n, "/%s", tok);
        if (!strcasecmp(tok, ".git")) {
            if (!next) return why;
            at = GITDIR;
        } else if (moved && at == OUTSIDE && path_under(other, dir)) {
            if (!next) return why;
            at = GITDIR;
        } else if (at != OUTSIDE) {
            /* git's names are ASCII; another spelling may fold into one */
            if (non_ascii(tok) || (at != DATA && gitdir_name(tok))) return why;
            if (at == GITDIR)
                at = !strcasecmp(tok, "modules") || !strcasecmp(tok, "worktrees") ? SUBREPOS : DATA;
        }
    }
    return NULL;
}

#define FILETOOL_MAX_CONTENT (4 * 1024 * 1024)

static int write_all(int fd, const char *data, size_t len) {
    for (size_t off = 0; off < len; ) {
        ssize_t w = write(fd, data + off, len - off);
        if (w > 0) off += (size_t)w;
        else if (w == 0 || errno != EINTR) return w ? errno : EIO;
    }
    return 0;
}

/* not atomic: *inplace says the file may be partly written on error. Nothing
   is touched unless the opened file is still `was` and has no other name. */
static int write_in_place(int dfd, const char *name, const struct stat *was,
                          const char *data, size_t len, bool *inplace) {
    int fd = openat(dfd, name, O_WRONLY | O_NOFOLLOW);
    if (fd < 0) return errno;
    struct stat now;
    int err = 0;
    if (fstat(fd, &now)) err = errno;
    else if (now.st_nlink > 1) err = EMLINK;
    else if (!S_ISREG(now.st_mode) || now.st_nlink != 1
             || now.st_dev != was->st_dev || now.st_ino != was->st_ino) err = EINVAL;
    else {
        *inplace = true;
        err = ftruncate(fd, 0) ? errno : write_all(fd, data, len);
    }
    if (close(fd) && !err) err = errno;
    return err;
}

/* Replace `name` in the directory dfd through a temp file and rename, so a
   failed write leaves the old file. Falls back to writing in place where a
   rename cannot keep ownership, or the directory refuses a new file. A file
   with several hard links is refused (EMLINK): another name may be outside the
   project. Returns 0, or the errno of the failure. */
static int write_atomic(int dfd, const char *name, const char *data, size_t len, bool *inplace) {
    *inplace = false;
    struct stat st;
    bool had = !fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW);
    if (had) {
        /* rename would replace what open() refuses: a link, a directory,
           a read-only file */
        if (S_ISLNK(st.st_mode)) return ELOOP;
        if (S_ISDIR(st.st_mode)) return EISDIR;
        if (!S_ISREG(st.st_mode)) return EINVAL;
        if (faccessat(dfd, name, W_OK, 0)) return errno;
        if (st.st_nlink > 1) return EMLINK;
    }
    char tmp[64];
    int fd = -1;
    for (int i = 0; fd < 0 && i < 100; i++) {
        snprintf(tmp, sizeof tmp, ".fw-tmp-%ld-%d", (long)getpid(), i);
        fd = openat(dfd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, had ? 0600 : 0666);
        if (fd < 0 && errno != EEXIST) {
            if (had && (errno == EACCES || errno == EPERM))
                return write_in_place(dfd, name, &st, data, len, inplace);
            return errno;
        }
    }
    if (fd < 0) return EEXIST;
    struct stat ts;
    if (had && (fstat(fd, &ts) || ((ts.st_uid != st.st_uid || ts.st_gid != st.st_gid)
                                   && fchown(fd, st.st_uid, st.st_gid)))) {
        close(fd);
        unlinkat(dfd, tmp, 0);
        return write_in_place(dfd, name, &st, data, len, inplace);
    }
    int err = write_all(fd, data, len);
    if (!err && had && fchmod(fd, st.st_mode & 07777)) err = errno;
    if (close(fd) && !err) err = errno;
    if (!err && renameat(dfd, tmp, dfd, name)) err = errno;
    if (err) unlinkat(dfd, tmp, 0);
    return err;
}

static const char *write_why(int err) {
    return err == EMLINK ? "file has several hard links" : strerror(err);
}

char *tool_write_file(const char *cwd, const char *path, const char *content) {
    char abs[PATH_MAX];
    /* judged before any parent directory is created */
    const char *err = resolve_confined(cwd, path, abs, sizeof abs, false);
    if (!err) err = protected_write(cwd, abs);
    if (err) return str_dup(err);
    if (!content) content = "";
    size_t len = strlen(content);
    if (len > FILETOOL_MAX_CONTENT) return str_dup("error: content too large (4 MiB cap)");

    bool inplace = false;
    if (fw_file_hook) fw_file_hook();
    const char *leaf;
    int dfd = open_parent(abs, true, &leaf);
    int werr = dfd < 0 ? errno : write_atomic(dfd, leaf, content, len, &inplace);
    if (dfd >= 0) close(dfd);
    if (werr) {
        char buf[300];
        snprintf(buf, sizeof buf, "error: cannot write %s: %s — %s", path, write_why(werr),
                 inplace ? "written in place, the file may be incomplete" : "nothing was changed");
        return str_dup(buf);
    }

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
    if (!err) err = protected_write(cwd, abs);
    if (err) return str_dup(err);
    if (fw_file_hook) fw_file_hook();

    /* read and write relative to the same directory, reached without links */
    const char *leaf;
    int dfd = open_parent(abs, false, &leaf);
    int in = dfd < 0 ? -1 : openat(dfd, leaf, O_RDONLY | O_NOFOLLOW);
    FILE *f = in < 0 ? NULL : fdopen(in, "rb");
    if (!f) {
        char buf[300];
        snprintf(buf, sizeof buf, "error: cannot read %s: %s — use write_file to create it", path, strerror(errno));
        if (in >= 0) close(in);
        if (dfd >= 0) close(dfd);
        return str_dup(buf);
    }
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsz < 0 || fsz > FILETOOL_MAX_CONTENT) {
        fclose(f);
        close(dfd);
        return str_dup("error: file too large to edit (4 MiB cap)");
    }
    char *data = malloc((size_t)fsz + 1);
    size_t rd = fread(data, 1, (size_t)fsz, f);
    fclose(f);
    data[rd] = 0;

    /* count occurrences of old_str */
    size_t ol = strlen(old_str);
    int occ = 0;
    const char *hit = NULL;
    for (const char *p = data; (p = strstr(p, old_str)); p++) {   /* overlaps count */
        if (!hit) hit = p;
        occ++;
    }
    if (occ == 0) {
        close(dfd);
        free(data);
        return str_dup("error: old_string not found in file — re-read the file and match the exact text including whitespace");
    }
    if (occ > 1) {
        char buf[200];
        snprintf(buf, sizeof buf, "error: old_string matches %d places — make it unique by including more surrounding context", occ);
        free(data);
        close(dfd);
        return str_dup(buf);
    }

    size_t nl = strlen(new_str);
    size_t pre = (size_t)(hit - data);
    size_t post = rd - pre - ol;
    if (nl > FILETOOL_MAX_CONTENT || pre + nl + post > FILETOOL_MAX_CONTENT) {
        free(data);
        close(dfd);
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

    size_t total = pre + nl + post;
    bool inplace;
    int werr = write_atomic(dfd, leaf, out, total, &inplace);
    close(dfd);
    free(out);
    if (werr) {
        char buf[300];
        snprintf(buf, sizeof buf, "error: cannot write %s: %s — %s", path, write_why(werr),
                 inplace ? "written in place, the file may be incomplete" : "nothing was changed");
        return str_dup(buf);
    }

    char buf[300];
    snprintf(buf, sizeof buf, "ok: edited %s at line %d (%zu bytes)", path, line, total);
    return str_dup(buf);
}
