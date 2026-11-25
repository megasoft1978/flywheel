#include "flywheel.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <ctype.h>

static const char *DENY_SUBSTR[] = {
    "sudo ", "rm -rf /", "rm -rf ~", "mkfs", "dd of=/",
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

char *deny_check(const char *cmd, const char *cwd) {
    for (int i = 0; DENY_SUBSTR[i]; i++)
        if (strstr(cmd, DENY_SUBSTR[i]))
            return "error: command blocked by deny rule";
    /* block writes/redirects resolving outside cwd or /tmp —
       skipping heredoc payloads (they're data, not shell syntax) */
    Range hr[8];
    int nhr = heredoc_ranges(cmd, hr, 8);
    const char *p = cmd;
    while ((p = strchr(p, '>'))) {
        if (in_ranges(hr, nhr, p)) { p += 1; continue; }
        if (p[1] == '>') p += 2; else p += 1;
        while (*p == ' ' || *p == '\t') p++;
        char path[1024];
        int i = 0;
        while (p[i] && p[i] != ' ' && p[i] != '\t' && p[i] != ';' && i < 1023)
            path[i] = p[i], i++;
        path[i] = 0;
        if (!i) continue;
        if (path[0] == '/' && strncmp(path, "/tmp", 4) && strncmp(path, "/dev", 4)
            && strncmp(path, cwd, strlen(cwd)))
            return "error: write outside working dir is forbidden";
        if (strstr(path, "..") || strstr(path, "~/"))
            return "error: path escapes working dir";
    }
    return NULL;
}

/* Rewrite a standard heredoc delimiter (EOF/EOT/END) to a unique token
   when the delimiter string appears more than twice (opener + closer) —
   the payload is colliding and bash would truncate the write early. */
char *heredoc_fix(const char *cmd) {
    static int n;
    const char *p = strstr(cmd, "<<");
    if (!p) return str_dup(cmd);
    const char *q = p + 2;
    if (*q == '-') q++;
    while (*q == ' ' || *q == '\t') q++;
    bool quoted = (*q == '\'' || *q == '"');
    if (quoted) q++;
    char delim[64] = {0};
    int dl = 0;
    while (q[dl] && (isalnum((unsigned char)q[dl]) || q[dl] == '_') && dl < 63)
        delim[dl] = q[dl], dl++;
    delim[dl] = 0;
    if (!dl || (strcmp(delim, "EOF") && strcmp(delim, "EOT") && strcmp(delim, "END")))
        return str_dup(cmd);

    /* count token-bounded occurrences */
    int occ = 0;
    for (const char *r = strstr(cmd, delim); r; r = strstr(r + dl, delim)) {
        bool pre = (r == cmd) || strchr(" \t\n;('\"", r[-1]) != NULL;
        bool post = !r[dl] || strchr(" \t\n;')\"", r[dl]) != NULL;
        if (pre && post) occ++;
    }
    if (occ <= 2) return str_dup(cmd);

    char nd[80];
    snprintf(nd, sizeof nd, "FW_EOF_%d", ++n);
    char *out = malloc(strlen(cmd) + 64);
    const char *r = cmd;
    out[0] = 0;
    for (;;) {
        const char *hit = NULL;
        for (const char *s = strstr(r, delim); s; s = strstr(s + dl, delim)) {
            bool pre = (s == cmd) || strchr(" \t\n;('\"", s[-1]) != NULL;
            bool post = !s[dl] || strchr(" \t\n;')\"", s[dl]);
            if (pre && post) { hit = s; break; }
        }
        if (!hit) break;
        strncat(out, r, hit - r);
        strcat(out, nd);
        r = hit + dl;
    }
    strcat(out, r);
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

char *run_bash(const char *cmd, const char *cwd, int timeout_s) {
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
    size_t cap = 1 << 16, len = 0;
    char *buf = malloc(cap);
    int status = 0;
    bool timed = false;
    int waited = 0;
    for (;;) {
        char tmp[8192];
        ssize_t r = read(fds[0], tmp, sizeof tmp);
        if (r > 0) {
            if (len + r + 1 > cap) { cap *= 2; buf = realloc(buf, cap); }
            memcpy(buf + len, tmp, r); len += r;
        }
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) break;
        if (fw_tick_hook) fw_tick_hook();
        usleep(20000);
        waited += 20;
        if (timeout_s > 0 && waited >= timeout_s * 1000) {
            timed = true;
            killpg(pid, SIGKILL);
            waitpid(pid, &status, 0);
            break;
        }
        if (g_abort) { /* user Esc — kill the command too */
            timed = true;
            killpg(pid, SIGKILL);
            waitpid(pid, &status, 0);
            break;
        }
    }
    /* drain remainder */
    for (;;) {
        ssize_t r = read(fds[0], buf + len, cap - len - 1);
        if (r <= 0) break;
        len += r;
        if (cap - len - 1 < 8192) { cap *= 2; buf = realloc(buf, cap); }
    }
    close(fds[0]);
    buf[len] = 0;
    utf8_sanitize(buf);
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
   ~/.config/flywheel/allow and <cwd>/.flywheel.allow.
   A rule matches when the command equals it or starts with it
   followed by a space or tab. */

static const char *BUILTIN_ALLOW[] = {
    "ls", "cat", "grep", "rg", "find", "fd", "head", "tail", "wc", "echo",
    "pwd", "file", "stat", "which", "git status", "git diff", "git log",
    "git show", "git rev-parse", "git branch", "npx tsc", "cd", "true",
    "printf", "test", "xargs", "sort", "uniq", "tr", "cut", "env",
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

void perm_load(void) {
    if (rules_loaded) return;
    rules_loaded = true;
    const char *home = getenv("HOME");
    if (home) {
        char p[1024];
        snprintf(p, sizeof p, "%s/.config/flywheel/allow", home);
        perm_load_file(p);
    }
    char pp[1024];
    snprintf(pp, sizeof pp, "%s/.flywheel.allow", g_cfg.cwd);
    perm_load_file(pp);
}

bool perm_allowed(const char *cmd) {
    perm_load();
    while (*cmd == ' ') cmd++;
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
    char p[1024];
    snprintf(p, sizeof p, "%s/.flywheel.allow", g_cfg.cwd);
    FILE *f = fopen(p, "a");
    if (f) { fprintf(f, "%s\n", rule); fclose(f); }
}

/* "always" rule derived from a command: first token, or first two
   tokens for multiword tools. */
char *perm_prefix(const char *cmd) {
    while (*cmd == ' ') cmd++;
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

#include <sys/stat.h>
#include <limits.h>

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
   Fills `out` with the lexical absolute path on success and returns NULL;
   otherwise returns a static error string. When `for_write`, parent dirs
   are created. Symlink escapes are rejected via realpath checks. */
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
    if (!is_within(realcwd, norm) && !is_within(cwd, norm))
        return "error: path escapes working dir";

    if (for_write && !mkdir_parents(norm))
        return "error: cannot create parent directories";

    /* symlink confinement: parent dir must really live inside cwd */
    char parent[PATH_MAX];
    snprintf(parent, sizeof parent, "%s", norm);
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) *slash = 0;
    char realparent[PATH_MAX];
    if (realpath(parent, realparent)) {
        if (!is_within(realcwd, realparent))
            return "error: path escapes working dir through a symlink";
    }
    /* existing file must not be a symlink escaping either */
    struct stat st;
    if (!lstat(norm, &st) && S_ISLNK(st.st_mode)) {
        char realf[PATH_MAX];
        if (realpath(norm, realf) && !is_within(realcwd, realf))
            return "error: path is a symlink escaping working dir";
    }

    snprintf(out, cap, "%s", norm);
    return NULL;
}

#define FILETOOL_MAX_CONTENT (4 * 1024 * 1024)

char *tool_write_file(const char *cwd, const char *path, const char *content) {
    char abs[PATH_MAX];
    const char *err = resolve_confined(cwd, path, abs, sizeof abs, true);
    if (err) return str_dup(err);
    if (!content) content = "";
    size_t len = strlen(content);
    if (len > FILETOOL_MAX_CONTENT) return str_dup("error: content too large (4 MiB cap)");

    FILE *f = fopen(abs, "w");
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

    FILE *f = fopen(abs, "rb");
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

    f = fopen(abs, "w");
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
