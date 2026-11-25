#define _XOPEN_SOURCE 700
#define _DARWIN_C_SOURCE 1
#include "flywheel.h"
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <signal.h>
#include <wchar.h>
#include <errno.h>
#include <time.h>

/* claude-code-style TUI v4 (Mica / libvterm & xterm compatible):
   - structured transcript buffer with atomic full-viewport rendering
     inside Mica synchronized output frames (CSI ?2026h / ?2026l)
   - collapsed Bash(...) command blocks by default; click (SGR mouse ?1000h/?1006h)
     or press ^O to expand/collapse in place
   - mouse wheel + PageUp/PageDown smooth transcript scrolling
   - interactive Claude-Code-style modal menu for bash approvals & multi-choice
     prompts (↑↓ + Enter, 1-9, y/a/n shortcuts, or mouse click)
   - rounded input box + slash menu below it + status bar pinned at bottom
   - UTF-8 / emoji width via wcwidth(), soft-wrapped input (up to 4 visible rows)
   - Shift+Enter / Alt+Enter multiline, bracketed paste (?2004h) with [paste#N] collapse
   - Cmd+V / Ctrl+V clipboard image paste (Mica sends 0x16 for images)
   - SIGWINCH live resize with full transcript re-wrap; Esc aborts streams */

static struct termios saved_t;
static int rows = 24, cols = 80;
static char status[256] = "ready";
static bool raw_on, working;
static char inbuf[8192];
static int ilen, icur;
static volatile sig_atomic_t g_resized = 0;

#define MAXHIST 128

static void handle_key(unsigned char ch, bool busy);
static void drain_queue(void);
static void tui_pump(void);
static char *HIST[MAXHIST];
static int hist_n, hpos = -1;

#define MAXPASTE 8
static char *pastes[MAXPASTE];
static int npastes;
static int paste_start = -1, paste_bytes;

/* message queue for input typed while the agent is busy */
static char qmsg[8][16384];
static int qn;
static bool want_exit;
static bool pasting;

static const struct { const char *cmd, *desc; } SLASH[] = {
    {"/init",   "write .flywheel.md project notes + check engine"},
    {"/clear",  "clear conversation and screen"},
    {"/model",  "show or switch model (/model NAME)"},
    {"/allow",  "list permission rules (.flywheel.allow)"},
    {"/status", "engine, model, profile, conversation size"},
    {"/help",   "keys, mouse, and commands"},
    {"/exit",   "quit flywheel"},
    {"/quit",   "quit flywheel"},
    {NULL, NULL}
};

/* ---------- structured transcript ---------- */

typedef enum {
    T_RAW,     /* banner, events, slash output (may contain ANSI SGR) */
    T_USER,    /* user prompt */
    T_THINK,   /* dimmed model reasoning */
    T_TEXT,    /* assistant answer text */
    T_TOOL     /* collapsible Bash(cmd) + output */
} ItemKind;

typedef struct {
    ItemKind kind;
    char *text;         /* T_RAW / T_USER / T_THINK / T_TEXT, or detail for T_TOOL */
    size_t len, cap;
    char *out;          /* T_TOOL output (NULL while running) */
    char tname[16];     /* T_TOOL: "Bash" | "Write" | "Edit" */
    bool expanded;      /* T_TOOL collapse state (default false) */
    bool done;          /* T_TOOL finished / T_THINK closed */
    double t0, t1;      /* T_THINK timing */
} TItem;

static TItem *items = NULL;
static int nitems = 0, cap_items = 0;
static int scroll_off = 0;       /* 0 = pinned at bottom; >0 = scrolled up N rows */
static int max_scroll = 0;
static int row_tool_idx[512];    /* screen row (0-based) -> tool item index, or -1 */
static int slash_menu_top = -1;  /* screen row (0-based) where slash menu starts */
static int slash_menu_cnt = 0;

/* active modal menu (approval / multi-choice), NULL when normal input box is shown */
typedef struct {
    const char *title;
    const char *body;         /* e.g. command text, optional */
    const char *prompt;       /* e.g. "Do you want to proceed?" */
    const char **opts;
    int nopts;
    int sel;
    int opt_row_start;        /* 0-based screen row of option 0 (for mouse click) */
} Modal;

static Modal *active_modal = NULL;

static int menu_sel = 0;
static bool menu_dismissed = false;
static int sync_depth = 0;

/* Live session & task telemetry */
static struct {
    int sess_turns, sess_calls, sess_toks;
    int last_ptoks;
    int ctx_limit;          /* from /models context_length, default 262144 */
    double sess_secs;
    double last_tps;
    int task_turns, task_calls, task_toks;
    int stream_chunks;      /* live token estimate while streaming current turn */
    struct timespec task_t0;
    const char *phase;      /* "thinking" | "writing" | "bash" */
    int spin;
    AgentStats last_final;
    bool has_final;
    char proj_name[128];
    char git_branch[128];
} g_stat = { .ctx_limit = 262144, .phase = "working" };

static const char *SPIN_FRAMES[] = {
    "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"
};

static double mono_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void fmt_toks(int n, char *out, size_t cap) {
    if (n >= 1000000) snprintf(out, cap, "%.1fM", n / 1e6);
    else if (n >= 1000) snprintf(out, cap, "%.1fk", n / 1e3);
    else snprintf(out, cap, "%d", n);
}

static void detect_project_meta(void) {
    const char *base = strrchr(g_cfg.cwd, '/');
    snprintf(g_stat.proj_name, sizeof g_stat.proj_name, "%s",
             (base && base[1]) ? base + 1 : g_cfg.cwd);
    g_stat.git_branch[0] = 0;
    char *br = run_bash("git rev-parse --abbrev-ref HEAD 2>/dev/null", g_cfg.cwd, 2);
    if (br) {
        char *nl = strchr(br, '\n');
        if (nl) *nl = 0;
        if (*br && strcmp(br, "HEAD") && strncmp(br, "(no output)", 11) && strncmp(br, "fatal:", 6) &&
            strncmp(br, "error:", 6) && !strstr(br, "exit ")) {
            snprintf(g_stat.git_branch, sizeof g_stat.git_branch, "%.60s", br);
        }
        free(br);
    }
}

static void on_winch(int sig) { (void)sig; g_resized = 1; }

static void begin_sync(void) {
    if (sync_depth++ == 0) fputs("\033[?2026h", stdout);
}
static void end_sync(void) {
    if (sync_depth > 0 && --sync_depth == 0) {
        fputs("\033[?2026l", stdout);
        fflush(stdout);
    }
}

static TItem *item_new(ItemKind kind) {
    if (nitems == cap_items) {
        cap_items = cap_items ? cap_items * 2 : 32;
        items = realloc(items, (size_t)cap_items * sizeof(TItem));
    }
    TItem *it = &items[nitems++];
    memset(it, 0, sizeof *it);
    it->kind = kind;
    return it;
}

static void item_append(TItem *it, const char *s) {
    if (!s || !*s) return;
    size_t sl = strlen(s);
    if (it->len + sl + 1 > it->cap) {
        size_t nc = it->cap ? it->cap * 2 : 256;
        while (nc < it->len + sl + 1) nc *= 2;
        it->text = realloc(it->text, nc);
        it->cap = nc;
    }
    memcpy(it->text + it->len, s, sl);
    it->len += sl;
    it->text[it->len] = 0;
}

static void transcript_clear(void) {
    for (int i = 0; i < nitems; i++) {
        free(items[i].text);
        free(items[i].out);
    }
    nitems = 0;
    scroll_off = 0;
}

/* ---------- UTF-8 helpers ---------- */

static int utf8_cell_width(const char *s, int max, int *blen) {
    if (max <= 0 || !*s) { *blen = 0; return 0; }
    unsigned char c = (unsigned char)s[0];
    if (c < 0x80) { *blen = 1; return c < 0x20 ? 0 : 1; }
    mbstate_t st;
    memset(&st, 0, sizeof st);
    wchar_t wc = 0;
    size_t r = mbrtowc(&wc, s, (size_t)max, &st);
    if (r == (size_t)-1 || r == (size_t)-2 || r == 0) { *blen = 1; return 1; }
    *blen = (int)r;
    if (wc == 0xFE0F || wc == 0xFE0E || wc == 0x200D) return 0;
    int w = wcwidth(wc);
    if (w < 0) w = 1;
    return w;
}

static int utf8_prev(const char *s, int pos) {
    if (pos <= 0) return 0;
    pos--;
    while (pos > 0 && (((unsigned char)s[pos]) & 0xC0) == 0x80) pos--;
    return pos;
}

static int utf8_next(const char *s, int len, int pos) {
    if (pos >= len) return len;
    pos++;
    while (pos < len && (((unsigned char)s[pos]) & 0xC0) == 0x80) pos++;
    return pos;
}

/* ---------- terminal mode ---------- */

static void term_raw(bool on) {
    if (on && !raw_on) {
        tcgetattr(0, &saved_t);
        struct termios t = saved_t;
        t.c_lflag &= ~(ICANON | ECHO | ISIG | IEXTEN);
        t.c_iflag &= ~(IXON | ICRNL);
        t.c_cc[VMIN] = 0; t.c_cc[VTIME] = 1;
        tcsetattr(0, TCSANOW, &t);
        /* bracketed paste + SGR click/wheel mouse reporting */
        fputs("\033[?2004h\033[?1000h\033[?1006h", stdout);
        fflush(stdout);
        raw_on = true;
    } else if (!on && raw_on) {
        fputs("\033[?1006l\033[?1000l\033[?2004l", stdout);
        fflush(stdout);
        tcsetattr(0, TCSANOW, &saved_t);
        raw_on = false;
    }
}

static void get_size(void) {
    struct winsize ws;
    if (ioctl(1, TIOCGWINSZ, &ws) == 0) {
        if (ws.ws_row >= 8) rows = ws.ws_row;
        if (ws.ws_col >= 24) cols = ws.ws_col;
    }
}

/* ---------- input wrapping & slash menu ---------- */

typedef struct { int start, len; } VLine;
#define MAX_VLINES 64

static int layout_input(VLine *vlines, int maxv, int inner_w, int *cur_vl, int *cur_col) {
    if (inner_w < 8) inner_w = 8;
    int nv = 0, ls = 0, w = 0;
    *cur_vl = 0; *cur_col = 0;
    bool cur_set = false;

    for (int i = 0; i < ilen;) {
        if (i == icur) { *cur_vl = nv; *cur_col = w; cur_set = true; }
        if (inbuf[i] == '\n') {
            if (nv < maxv) { vlines[nv].start = ls; vlines[nv].len = i - ls; nv++; }
            i++; ls = i; w = 0;
            continue;
        }
        int bl = 0;
        int cw = utf8_cell_width(inbuf + i, ilen - i, &bl);
        if (bl <= 0) bl = 1;
        if (w + cw > inner_w && i > ls) {
            if (nv < maxv) { vlines[nv].start = ls; vlines[nv].len = i - ls; nv++; }
            ls = i; w = 0;
            if (i == icur) { *cur_vl = nv; *cur_col = 0; cur_set = true; }
        }
        w += cw;
        i += bl;
    }
    if (!cur_set) { *cur_vl = nv; *cur_col = w; }
    if (nv < maxv) { vlines[nv].start = ls; vlines[nv].len = ilen - ls; nv++; }
    if (nv == 0) { vlines[0].start = 0; vlines[0].len = 0; nv = 1; }
    if (*cur_vl >= nv) { *cur_vl = nv - 1; *cur_col = 0; }
    return nv;
}

static int menu_matches(const char **out, int max) {
    if (active_modal || menu_dismissed || ilen <= 0 || inbuf[0] != '/') return 0;
    if (strchr(inbuf, ' ') || strchr(inbuf, '\n')) return 0;
    char prefix[64] = {0};
    for (int i = 0; i < ilen && i < 60; i++) { prefix[i] = inbuf[i]; prefix[i + 1] = 0; }
    int n = 0;
    for (int i = 0; SLASH[i].cmd && n < max; i++)
        if (!strncmp(SLASH[i].cmd, prefix, strlen(prefix))) out[n++] = SLASH[i].cmd;
    return n;
}

static int menu_count(void) {
    const char *m[8];
    int n = menu_matches(m, 8);
    return n > 6 ? 6 : n;
}

/* ---------- transcript visual line builder ---------- */

typedef struct {
    char *s;          /* rendered row with ANSI SGR, fits within cols */
    int tool_idx;     /* >=0 if clicking this row toggles items[tool_idx] */
} VRow;

typedef struct {
    VRow *v;
    int n, cap;
} VBuf;

static void vb_push(VBuf *vb, const char *s, int tool_idx) {
    if (vb->n == vb->cap) {
        vb->cap = vb->cap ? vb->cap * 2 : 128;
        vb->v = realloc(vb->v, (size_t)vb->cap * sizeof(VRow));
    }
    vb->v[vb->n].s = str_dup(s);
    vb->v[vb->n].tool_idx = tool_idx;
    vb->n++;
}

static void vb_free(VBuf *vb) {
    for (int i = 0; i < vb->n; i++) free(vb->v[i].s);
    free(vb->v);
    vb->v = NULL; vb->n = vb->cap = 0;
}

/* Wrap a string (which may contain ANSI CSI/OSC escapes and \n) into visual rows of width <= cols.
   prefix0 is prepended on the first line, prefix_cont on continuation/wrapped lines.
   style_open / style_close wrap each emitted visual row so colors survive line wraps. */
static void vb_wrap(VBuf *vb, const char *text, const char *prefix0, int p0_w,
                    const char *prefix_cont, int pc_w,
                    const char *style_open, const char *style_close, int tool_idx) {
    if (!text) return;
    int maxw = cols > 10 ? cols : 80;
    size_t lcap = (size_t)maxw * 16 + 1024;
    char *line = malloc(lcap);
    if (!line) return;

    const char *p = text;
    bool first = true;
    for (;;) {
        size_t lw = 0;
        const char *pfx = first ? prefix0 : prefix_cont;
        int col = first ? p0_w : pc_w;
        first = false;
        bool had_esc = false;

        if (pfx && *pfx) {
            size_t pl = strlen(pfx);
            if (lw + pl < lcap - 64) { memcpy(line + lw, pfx, pl); lw += pl; }
        }
        if (style_open && *style_open) {
            size_t sl = strlen(style_open);
            if (lw + sl < lcap - 64) { memcpy(line + lw, style_open, sl); lw += sl; }
        }

        while (*p) {
            if (*p == '\r') { p++; continue; }
            if (*p == '\n') { p++; break; }
            if (*p == '\033') {
                had_esc = true;
                const char *s0 = p++;
                if (*p == '[') {
                    p++;
                    while (*p && !((unsigned char)*p >= 0x40 && (unsigned char)*p <= 0x7E)) p++;
                    if (*p) p++;
                } else if (*p == ']') {
                    p++;
                    while (*p && *p != '\007') {
                        if (*p == '\033' && p[1] == '\\') { p += 2; break; }
                        p++;
                    }
                    if (*p == '\007') p++;
                } else if (*p) p++;
                size_t el = (size_t)(p - s0);
                if (lw + el < lcap - 64) { memcpy(line + lw, s0, el); lw += el; }
                continue;
            }
            if (*p == '\t') {
                int sp = 4 - (col % 4);
                if (col + sp > maxw) break;
                for (int k = 0; k < sp && lw < lcap - 64; k++) { line[lw++] = ' '; col++; }
                p++;
                continue;
            }
            if ((unsigned char)*p < 0x20) { p++; continue; }
            int bl = 0;
            int cw = utf8_cell_width(p, (int)strlen(p), &bl);
            if (bl <= 0) { p++; continue; }
            if (col + cw > maxw && col > (pfx ? pc_w : 0)) break;
            if (lw + (size_t)bl < lcap - 64) { memcpy(line + lw, p, (size_t)bl); lw += (size_t)bl; }
            col += cw;
            p += bl;
        }
        if (style_close && *style_close) {
            size_t sl = strlen(style_close);
            if (lw + sl < lcap - 16) { memcpy(line + lw, style_close, sl); lw += sl; }
        } else if (had_esc && lw + 8 < lcap) {
            memcpy(line + lw, RESET, strlen(RESET));
            lw += strlen(RESET);
        }
        line[lw] = 0;
        vb_push(vb, line, tool_idx);
        if (!*p) break;
    }
    free(line);
}

/* ---------- terminal Markdown renderer (streaming-safe) ---------- */

typedef struct { char *b; size_t n, cap; } MdBuf;

static void md_catn(MdBuf *m, const char *s, size_t n) {
    if (m->n + n + 1 > m->cap) {
        size_t nc = m->cap ? m->cap * 2 : 128;
        while (nc < m->n + n + 1) nc *= 2;
        m->b = realloc(m->b, nc);
        m->cap = nc;
    }
    memcpy(m->b + m->n, s, n);
    m->n += n;
    m->b[m->n] = 0;
}
static void md_cat(MdBuf *m, const char *s) { md_catn(m, s, strlen(s)); }

static bool md_word_ch(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

/* Measure display width of a string, skipping ANSI CSI/OSC sequences. */
static int ansi_display_width(const char *s) {
    int w = 0;
    const char *p = s;
    while (*p) {
        if (*p == '\033') {
            p++;
            if (*p == '[') {
                p++;
                while (*p && !((unsigned char)*p >= 0x40 && (unsigned char)*p <= 0x7E)) p++;
                if (*p) p++;
            } else if (*p == ']') {
                p++;
                while (*p && *p != '\007') {
                    if (*p == '\033' && p[1] == '\\') { p += 2; break; }
                    p++;
                }
                if (*p == '\007') p++;
            } else if (*p) p++;
            continue;
        }
        int bl = 0;
        w += utf8_cell_width(p, (int)strlen(p), &bl);
        p += bl > 0 ? bl : 1;
    }
    return w;
}

/* Render inline markdown (`code`, **bold**, *italic*, ~~strike~~, [label](url)) into ANSI. */
static char *md_inline(const char *s, size_t len) {
    MdBuf out = {0};
    md_catn(&out, "", 0);
    size_t i = 0;
    while (i < len) {
        /* Escaped markdown punctuation */
        if (s[i] == '\\' && i + 1 < len && strchr("\\`*_{}[]()#+-.!~|", s[i + 1])) {
            md_catn(&out, s + i + 1, 1);
            i += 2;
            continue;
        }
        /* Inline code `...` */
        if (s[i] == '`') {
            const char *end = memchr(s + i + 1, '`', len - i - 1);
            if (end && end > s + i + 1) {
                md_cat(&out, CYAN);
                md_catn(&out, s + i + 1, (size_t)(end - (s + i + 1)));
                md_cat(&out, "\033[39m");
                i = (size_t)(end - s) + 1;
                continue;
            }
        }
        /* Bold **...** or __...__ */
        if (i + 3 < len && ((s[i] == '*' && s[i + 1] == '*') || (s[i] == '_' && s[i + 1] == '_'))) {
            char mark = s[i];
            if (mark == '_' && i > 0 && md_word_ch((unsigned char)s[i - 1])) goto plain;
            const char *close = NULL;
            for (size_t j = i + 2; j + 1 < len; j++) {
                if (s[j] == mark && s[j + 1] == mark) {
                    if (mark == '_' && j + 2 < len && md_word_ch((unsigned char)s[j + 2])) continue;
                    close = s + j;
                    break;
                }
            }
            if (close && close > s + i + 2) {
                char *inner = md_inline(s + i + 2, (size_t)(close - (s + i + 2)));
                md_cat(&out, "\033[1m");
                if (inner) { md_cat(&out, inner); free(inner); }
                md_cat(&out, "\033[22m");
                i = (size_t)(close - s) + 2;
                continue;
            }
        }
        /* Strikethrough ~~...~~ */
        if (i + 3 < len && s[i] == '~' && s[i + 1] == '~') {
            const char *close = NULL;
            for (size_t j = i + 2; j + 1 < len; j++) {
                if (s[j] == '~' && s[j + 1] == '~') { close = s + j; break; }
            }
            if (close && close > s + i + 2) {
                md_cat(&out, "\033[9m");
                md_catn(&out, s + i + 2, (size_t)(close - (s + i + 2)));
                md_cat(&out, "\033[29m");
                i = (size_t)(close - s) + 2;
                continue;
            }
        }
        /* Italic *...* or _..._ (word-bounded so snake_case stays literal) */
        if (i + 2 < len && (s[i] == '*' || s[i] == '_') && s[i + 1] != s[i] && s[i + 1] != ' ') {
            char mark = s[i];
            if (mark == '_' && i > 0 && md_word_ch((unsigned char)s[i - 1])) goto plain;
            const char *close = NULL;
            for (size_t j = i + 1; j < len; j++) {
                if (s[j] == mark && s[j - 1] != ' ') {
                    if (mark == '_' && j + 1 < len && md_word_ch((unsigned char)s[j + 1])) continue;
                    close = s + j;
                    break;
                }
            }
            if (close && close > s + i + 1) {
                md_cat(&out, "\033[3m");
                md_catn(&out, s + i + 1, (size_t)(close - (s + i + 1)));
                md_cat(&out, "\033[23m");
                i = (size_t)(close - s) + 1;
                continue;
            }
        }
        /* Link [label](url) -> OSC 8 clickable hyperlink in Mica for safe schemes */
        if (s[i] == '[') {
            const char *rb = memchr(s + i + 1, ']', len - i - 1);
            if (rb && (size_t)(rb - s) + 2 < len && rb[1] == '(') {
                const char *rp = memchr(rb + 2, ')', len - (size_t)(rb + 2 - s));
                if (rp && rp > rb + 2) {
                    size_t l_len = (size_t)(rb - (s + i + 1));
                    const char *u = rb + 2;
                    size_t u_len = (size_t)(rp - u);
                    bool safe_osc8 = (u_len >= 7 && (!strncmp(u, "http://", 7) || !strncmp(u, "https://", 8)));
                    for (size_t k = 0; k < u_len && safe_osc8; k++)
                        if ((unsigned char)u[k] < 0x20 || u[k] == 0x7f) safe_osc8 = false;
                    if (safe_osc8) {
                        md_cat(&out, "\033]8;;");
                        md_catn(&out, u, u_len);
                        md_cat(&out, "\033\\\033[4m" CYAN);
                        md_catn(&out, s + i + 1, l_len);
                        md_cat(&out, "\033[24m\033[39m\033]8;;\033\\");
                    } else {
                        md_cat(&out, "\033[4m" CYAN);
                        md_catn(&out, s + i + 1, l_len);
                        md_cat(&out, "\033[24m\033[39m" DIM " (");
                        md_catn(&out, u, u_len);
                        md_cat(&out, ")" RESET);
                    }
                    i = (size_t)(rp - s) + 1;
                    continue;
                }
            }
        }
plain:
        md_catn(&out, s + i, 1);
        i++;
    }
    return out.b;
}

static bool md_is_hr(const char *s, size_t len) {
    char ch = 0;
    int cnt = 0;
    for (size_t i = 0; i < len; i++) {
        if (s[i] == ' ' || s[i] == '\t') continue;
        if (s[i] != '-' && s[i] != '*' && s[i] != '_') return false;
        if (!ch) ch = s[i];
        if (s[i] != ch) return false;
        cnt++;
    }
    return cnt >= 3;
}

static bool md_is_table_line(const char *s, size_t len) {
    while (len > 0 && (*s == ' ' || *s == '\t')) { s++; len--; }
    return len >= 2 && s[0] == '|' && memchr(s + 1, '|', len - 1) != NULL;
}

static bool md_is_table_sep(const char *s, size_t len) {
    if (!md_is_table_line(s, len)) return false;
    int dashes = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '-') dashes++;
        else if (c != '|' && c != ':' && c != ' ' && c != '\t') return false;
    }
    return dashes >= 2;
}

static int md_split_cells(const char *s, size_t len, char *cells[], int maxc) {
    while (len > 0 && (*s == ' ' || *s == '\t')) { s++; len--; }
    if (len > 0 && s[0] == '|') { s++; len--; }
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t')) len--;
    if (len > 0 && s[len - 1] == '|') len--;
    int nc = 0;
    size_t start = 0;
    for (size_t i = 0; i <= len && nc < maxc; i++) {
        if (i == len || s[i] == '|') {
            size_t a = start, b = i;
            while (a < b && (s[a] == ' ' || s[a] == '\t')) a++;
            while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t')) b--;
            cells[nc++] = md_inline(s + a, b - a);
            start = i + 1;
        }
    }
    return nc;
}

static void md_render_table(VBuf *vb, const char **lines, const size_t *lens, int nlines) {
    #define MAX_TCOLS 12
    #define MAX_TROWS 64
    if (nlines > MAX_TROWS) nlines = MAX_TROWS;
    char *grid[MAX_TROWS][MAX_TCOLS];
    int ncols_row[MAX_TROWS];
    int max_cols = 0;
    int colw[MAX_TCOLS] = {0};
    memset(grid, 0, sizeof grid);

    for (int r = 0; r < nlines; r++) {
        if (r == 1) { ncols_row[r] = 0; continue; } /* separator row */
        ncols_row[r] = md_split_cells(lines[r], lens[r], grid[r], MAX_TCOLS);
        if (ncols_row[r] > max_cols) max_cols = ncols_row[r];
        for (int c = 0; c < ncols_row[r]; c++) {
            int w = ansi_display_width(grid[r][c]);
            if (w > colw[c]) colw[c] = w;
        }
    }
    if (max_cols <= 0) return;

    /* Shrink widest columns if table exceeds terminal width */
    int avail = (cols > 20 ? cols : 80) - 2 - (max_cols * 3 + 1);
    if (avail < max_cols * 3) avail = max_cols * 3;
    for (;;) {
        int tot = 0, widest = 0;
        for (int c = 0; c < max_cols; c++) {
            tot += colw[c];
            if (colw[c] > colw[widest]) widest = c;
        }
        if (tot <= avail || colw[widest] <= 4) break;
        colw[widest]--;
    }

    /* Emit border helper */
    MdBuf row = {0};
    const char *borders[3][4] = {
        {"╭", "─", "┬", "╮"},
        {"├", "─", "┼", "┤"},
        {"╰", "─", "┴", "╯"}
    };
    #define EMIT_TBORDER(idx) do { \
        row.n = 0; md_cat(&row, " " DIM); md_cat(&row, borders[idx][0]); \
        for (int c = 0; c < max_cols; c++) { \
            for (int k = 0; k < colw[c] + 2; k++) md_cat(&row, borders[idx][1]); \
            md_cat(&row, c + 1 < max_cols ? borders[idx][2] : borders[idx][3]); \
        } \
        md_cat(&row, RESET); vb_push(vb, row.b, -1); \
    } while (0)

    EMIT_TBORDER(0);
    for (int r = 0; r < nlines; r++) {
        if (r == 1) { EMIT_TBORDER(1); continue; }
        row.n = 0;
        md_cat(&row, " " DIM "│" RESET);
        for (int c = 0; c < max_cols; c++) {
            const char *cell = (c < ncols_row[r] && grid[r][c]) ? grid[r][c] : "";
            md_cat(&row, " ");
            if (r == 0) md_cat(&row, BOLD);
            /* Truncate cell if wider than colw[c] */
            int w = 0;
            const char *p = cell;
            while (*p) {
                if (*p == '\033') {
                    const char *s0 = p++;
                    if (*p == '[') { p++; while (*p && !((unsigned char)*p >= 0x40 && (unsigned char)*p <= 0x7E)) p++; if (*p) p++; }
                    else if (*p == ']') { p++; while (*p && *p != '\007') { if (*p == '\033' && p[1] == '\\') { p += 2; break; } p++; } if (*p == '\007') p++; }
                    else if (*p) p++;
                    md_catn(&row, s0, (size_t)(p - s0));
                    continue;
                }
                int bl = 0;
                int cw = utf8_cell_width(p, (int)strlen(p), &bl);
                if (bl <= 0) { p++; continue; }
                if (w + cw > colw[c]) break;
                md_catn(&row, p, (size_t)bl);
                w += cw;
                p += bl;
            }
            if (r == 0) md_cat(&row, RESET);
            while (w < colw[c]) { md_cat(&row, " "); w++; }
            md_cat(&row, " " DIM "│" RESET);
        }
        vb_push(vb, row.b, -1);
    }
    EMIT_TBORDER(2);
    #undef EMIT_TBORDER

    free(row.b);
    for (int r = 0; r < nlines; r++)
        for (int c = 0; c < ncols_row[r]; c++)
            free(grid[r][c]);
    #undef MAX_TCOLS
    #undef MAX_TROWS
}

static void vb_markdown(VBuf *vb, const char *text) {
    if (!text) return;
    /* Split into line pointers */
    int nlines = 0, cap = 64;
    const char **ls = malloc((size_t)cap * sizeof(char *));
    size_t *ll = malloc((size_t)cap * sizeof(size_t));
    if (!ls || !ll) { free(ls); free(ll); return; }

    const char *p = text;
    for (;;) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len > 0 && p[len - 1] == '\r') len--;
        if (nlines == cap) {
            cap *= 2;
            ls = realloc(ls, (size_t)cap * sizeof(char *));
            ll = realloc(ll, (size_t)cap * sizeof(size_t));
        }
        ls[nlines] = p;
        ll[nlines] = len;
        nlines++;
        if (!nl) break;
        p = nl + 1;
    }

    bool in_code = false;
    int rule_w = (cols > 12 ? cols - 4 : 40);

    for (int i = 0; i < nlines; i++) {
        const char *s = ls[i];
        size_t len = ll[i];

        /* Fenced code block ```[lang] */
        size_t lead = 0;
        while (lead < len && s[lead] == ' ') lead++;
        if (len - lead >= 3 && s[lead] == '`' && s[lead + 1] == '`' && s[lead + 2] == '`') {
            if (!in_code) {
                in_code = true;
                const char *lang = s + lead + 3;
                size_t llen = len - lead - 3;
                while (llen > 0 && (*lang == ' ' || *lang == '\t')) { lang++; llen--; }
                while (llen > 0 && (lang[llen - 1] == ' ' || lang[llen - 1] == '\t')) llen--;
                MdBuf h = {0};
                md_cat(&h, "  " DIM "╭");
                int used = 3;
                if (llen > 0) {
                    md_cat(&h, "─ ");
                    md_catn(&h, lang, llen);
                    md_cat(&h, " ");
                    used += (int)llen + 3;
                }
                for (int k = used; k < rule_w; k++) md_cat(&h, "─");
                md_cat(&h, RESET);
                vb_push(vb, h.b, -1);
                free(h.b);
            } else {
                in_code = false;
                MdBuf h = {0};
                md_cat(&h, "  " DIM "╰");
                for (int k = 3; k < rule_w; k++) md_cat(&h, "─");
                md_cat(&h, RESET);
                vb_push(vb, h.b, -1);
                free(h.b);
            }
            continue;
        }

        if (in_code) {
            char *raw = str_ndup(s, len);
            vb_wrap(vb, raw, "  " DIM "│ " RESET, 4, "  " DIM "│ " RESET, 4, CYAN, RESET, -1);
            free(raw);
            continue;
        }

        /* Empty line */
        if (lead == len) {
            vb_push(vb, "", -1);
            continue;
        }

        /* Markdown table */
        if (i + 1 < nlines && md_is_table_line(s, len) && md_is_table_sep(ls[i + 1], ll[i + 1])) {
            int j = i + 2;
            while (j < nlines && md_is_table_line(ls[j], ll[j])) j++;
            md_render_table(vb, ls + i, ll + i, j - i);
            i = j - 1;
            continue;
        }

        /* Horizontal rule */
        if (md_is_hr(s, len)) {
            MdBuf h = {0};
            md_cat(&h, DIM);
            for (int k = 0; k < rule_w; k++) md_cat(&h, "─");
            md_cat(&h, RESET);
            vb_push(vb, h.b, -1);
            free(h.b);
            continue;
        }

        /* Headings (# .. ####) */
        if (s[lead] == '#') {
            size_t h = lead;
            while (h < len && s[h] == '#' && h - lead < 4) h++;
            if (h < len && s[h] == ' ') {
                size_t lvl = h - lead;
                char *inl = md_inline(s + h + 1, len - h - 1);
                const char *st = (lvl == 1) ? (CYAN BOLD) : (lvl == 2 ? (BLUE BOLD) : BOLD);
                vb_wrap(vb, inl ? inl : "", "", 0, "", 0, st, RESET, -1);
                free(inl);
                continue;
            }
        }

        /* Blockquote (> ...) */
        if (s[lead] == '>' && (lead + 1 == len || s[lead + 1] == ' ')) {
            size_t off = lead + 1 + (lead + 1 < len && s[lead + 1] == ' ' ? 1 : 0);
            char *inl = md_inline(s + off, len - off);
            vb_wrap(vb, inl ? inl : "", DIM "▎ " RESET, 2, DIM "▎ " RESET, 2, DIM, RESET, -1);
            free(inl);
            continue;
        }

        /* Unordered list (- / * / +) */
        if ((s[lead] == '-' || s[lead] == '*' || s[lead] == '+') && lead + 1 < len && s[lead + 1] == ' ') {
            int ind = (int)(lead > 8 ? 8 : lead);
            char p0[64], pc[64];
            memset(p0, ' ', (size_t)ind);
            snprintf(p0 + ind, sizeof p0 - (size_t)ind, CYAN "• " RESET);
            memset(pc, ' ', (size_t)(ind + 2));
            pc[ind + 2] = 0;
            char *inl = md_inline(s + lead + 2, len - lead - 2);
            vb_wrap(vb, inl ? inl : "", p0, ind + 2, pc, ind + 2, "", "", -1);
            free(inl);
            continue;
        }

        /* Ordered list (1. ...) */
        if (s[lead] >= '0' && s[lead] <= '9') {
            size_t d = lead;
            while (d < len && s[d] >= '0' && s[d] <= '9' && d - lead < 4) d++;
            if (d + 1 < len && (s[d] == '.' || s[d] == ')') && s[d + 1] == ' ') {
                int ind = (int)(lead > 8 ? 8 : lead);
                int numw = (int)(d - lead) + 2;
                char p0[64], pc[64];
                memset(p0, ' ', (size_t)ind);
                snprintf(p0 + ind, sizeof p0 - (size_t)ind, CYAN "%.*s " RESET, (int)(d - lead + 1), s + lead);
                memset(pc, ' ', (size_t)(ind + numw));
                pc[ind + numw] = 0;
                char *inl = md_inline(s + d + 2, len - d - 2);
                vb_wrap(vb, inl ? inl : "", p0, ind + numw, pc, ind + numw, "", "", -1);
                free(inl);
                continue;
            }
        }

        /* Normal paragraph line */
        char *inl = md_inline(s, len);
        vb_wrap(vb, inl ? inl : "", "", 0, "", 0, "", "", -1);
        free(inl);
    }

    free(ls);
    free(ll);
}

static int count_lines(const char *s) {
    if (!s || !*s) return 0;
    int n = 1;
    for (const char *p = s; *p; p++) if (*p == '\n' && p[1]) n++;
    return n;
}

static void build_transcript(VBuf *vb) {
    for (int i = 0; i < nitems; i++) {
        TItem *it = &items[i];
        if (it->kind == T_RAW) {
            vb_wrap(vb, it->text ? it->text : "", "", 0, "", 0, "", "", -1);
        } else if (it->kind == T_USER) {
            vb_push(vb, "", -1);
            vb_wrap(vb, it->text ? it->text : "", CYAN BOLD "› " RESET, 2, "  ", 2, BOLD, RESET, -1);
        } else if (it->kind == T_THINK) {
            const char *txt = it->text ? it->text : "";
            if (!it->done) {
                /* live: header + last 3 rows only */
                double dt = mono_now() - it->t0;
                char hdr[96];
                snprintf(hdr, sizeof hdr, DIM "∴ Thinking… %.0fs" RESET, dt < 1 ? 1 : dt);
                vb_push(vb, hdr, -1);
                int nl = 0;
                const char *s = txt + strlen(txt);
                while (s > txt && nl < 3) {
                    s--;
                    if (*s == '\n' && s + 1 < txt + strlen(txt)) nl++;
                }
                if (nl >= 3) s += 1;
                vb_wrap(vb, s, DIM "┆ " RESET, 2, DIM "┆ " RESET, 2, DIM, RESET, -1);
            } else if (!it->expanded) {
                double dt = it->t1 - it->t0;
                if (dt < 0) dt = 0;
                int toks = (int)(strlen(txt) / 4);
                char hdr[160];
                snprintf(hdr, sizeof hdr, DIM "∴ Thought for %.1fs · ~%d tok ▸" RESET, dt, toks);
                vb_push(vb, hdr, i);
            } else {
                double dt = it->t1 - it->t0;
                if (dt < 0) dt = 0;
                char hdr[160];
                snprintf(hdr, sizeof hdr, DIM "∴ Thought for %.1fs ▾" RESET, dt);
                vb_push(vb, hdr, i);
                vb_wrap(vb, txt, DIM "┆ " RESET, 2, DIM "┆ " RESET, 2, DIM, RESET, i);
            }
        } else if (it->kind == T_TEXT) {
            vb_markdown(vb, it->text ? it->text : "");
        } else if (it->kind == T_TOOL) {
            /* Command header line (clickable to toggle expand/collapse) */
            char one[200];
            int k = 0;
            const char *c = it->text ? it->text : "";
            for (const char *p = c; *p && *p != '\n' && k < 140; p++) one[k++] = *p;
            one[k] = 0;
            char hdr[480];
            bool iswrite = !strcmp(it->tname, "Write") || !strcmp(it->tname, "Edit");
            const char *badge = iswrite ? MAGENTA "✎" RESET : YELLOW "⚙" RESET;
            const char *tail = " " DIM "running…" RESET;
            if (it->done && it->out) {
                bool is_err = !strncmp(it->out, "error:", 6) || strstr(it->out, "\n[exit ") != NULL;
                badge = is_err ? (RED "✗" RESET) : (GREEN "✓" RESET);
                tail = it->expanded ? (" " DIM "▾" RESET) : (" " DIM "▸" RESET);
            }
            snprintf(hdr, sizeof hdr, "%s " BOLD "%s" RESET "(%s%s)%s",
                     badge, it->tname[0] ? it->tname : "Bash", one,
                     (strchr(c, '\n') || strlen(c) > 140) ? "…" : "", tail);
            vb_wrap(vb, hdr, "", 0, "  ", 2, "", "", i);

            if (!it->out) continue;
            int nl = count_lines(it->out);
            if (!it->expanded) {
                /* Collapsed view (Claude Code style): up to 2 preview lines + "+N lines" hint */
                if (nl <= 2 && strlen(it->out) <= 240) {
                    vb_wrap(vb, it->out, "  " GRAY "⎿  ", 5, "     ", 5, GRAY, RESET, i);
                } else {
                    /* First 2 lines only */
                    char preview[512];
                    int pw = 0, seen = 0;
                    for (const char *p = it->out; *p && pw < 480; p++) {
                        if (*p == '\n') {
                            seen++;
                            if (seen >= 2) break;
                        }
                        preview[pw++] = *p;
                    }
                    preview[pw] = 0;
                    vb_wrap(vb, preview, "  " GRAY "⎿  ", 5, "     ", 5, GRAY, RESET, i);
                    char hint[160];
                    int hidden = nl - 2;
                    if (hidden < 1) hidden = 1;
                    snprintf(hint, sizeof hint, "     " DIM "… +%d line%s (click or ^O to expand)" RESET,
                             hidden, hidden == 1 ? "" : "s");
                    vb_push(vb, hint, i);
                }
            } else {
                /* Expanded view: full output (capped at 200 lines so UI stays snappy) */
                const char *p = it->out;
                int shown = 0;
                char chunk[8192];
                size_t cw = 0;
                while (*p && shown < 200 && cw < sizeof chunk - 2) {
                    if (*p == '\n') shown++;
                    chunk[cw++] = *p++;
                }
                chunk[cw] = 0;
                vb_wrap(vb, chunk, "  " GRAY "⎿  ", 5, "     ", 5, GRAY, RESET, i);
                char hint[160];
                if (*p)
                    snprintf(hint, sizeof hint, "     " DIM "… truncated (click or ^O to collapse)" RESET);
                else
                    snprintf(hint, sizeof hint, "     " DIM "▴ click or ^O to collapse" RESET);
                vb_push(vb, hint, i);
            }
        }
    }
}

/* ---------- full-screen atomic renderer ---------- */

static void draw_hline(const char *left, const char *right, int inner) {
    fputs(DIM, stdout);
    fputs(left, stdout);
    for (int i = 0; i < inner; i++) fputs("─", stdout);
    fputs(right, stdout);
    fputs(RESET, stdout);
}

static void draw_input_top(int box_w) {
    char label[280];
    if (g_stat.git_branch[0])
        snprintf(label, sizeof label, "%s " DIM "(⎇ %s)" RESET, g_stat.proj_name, g_stat.git_branch);
    else if (g_stat.proj_name[0])
        snprintf(label, sizeof label, "%s", g_stat.proj_name);
    else
        snprintf(label, sizeof label, "flywheel");

    /* Measure the exact left segment so dashes fill correctly regardless of glyph widths.
       box_w is the INNER width (dash count between corners), same as draw_hline. */
    char seg[400];
    snprintf(seg, sizeof seg, DIM "╭─ " RESET CYAN BOLD "⚡ " RESET DIM "%s ", label);
    int sw = ansi_display_width(seg);
    int rem = box_w - sw + 1; /* total width = box_w + 2; seg already includes ╭ */
    if (rem < 2) { draw_hline("╭", "╮", box_w); return; }
    fputs(seg, stdout);
    for (int i = 0; i < rem; i++) fputs("─", stdout);
    fputs("╮" RESET, stdout);
}

static void draw_status_bar(void) {
    char scroll_tag[64] = "";
    if (scroll_off > 0) snprintf(scroll_tag, sizeof scroll_tag, " · ↑%d lines · End to jump", scroll_off);
    char qtag[32] = "";
    if (qn > 0) snprintf(qtag, sizeof qtag, " · ⎿%d queued", qn);

    printf("\033[%d;1H" CLR_LINE, rows);
    if (working) {
        const char *sp = SPIN_FRAMES[(g_stat.spin++) % 10];
        const char *ico = "⚙";
        if (!strcmp(g_stat.phase, "thinking")) ico = "💭";
        else if (!strcmp(g_stat.phase, "writing")) ico = "✍";
        double dt = mono_now() - (g_stat.task_t0.tv_sec + g_stat.task_t0.tv_nsec / 1e9);
        if (dt < 0) dt = 0;
        char tbuf[24];
        int est_tok = g_stat.task_toks + g_stat.stream_chunks;
        fmt_toks(est_tok, tbuf, sizeof tbuf);
        char tps_str[32] = "";
        double tps = g_stat.last_tps > 0.1 ? g_stat.last_tps : (dt > 0.3 && est_tok > 0 ? est_tok / dt : 0);
        if (tps >= 1.0) snprintf(tps_str, sizeof tps_str, " · " YELLOW "⚡ %.0f tok/s" RESET, tps);
        printf(CYAN BOLD "%s" RESET " %s " CYAN "%s" RESET DIM " · %.1fs · %s tok" RESET "%s" DIM "%s%s · esc interrupts" RESET,
               sp, ico, g_stat.phase, dt, tbuf, tps_str, scroll_tag, qtag);
        return;
    }

    /* Idle status bar: ready dot + context gauge bar + session stats */
    int pct = (g_stat.ctx_limit > 0 && g_stat.last_ptoks > 0)
              ? (int)((long long)g_stat.last_ptoks * 100 / g_stat.ctx_limit) : 0;
    if (pct > 100) pct = 100;
    int filled = (pct + 5) / 10;
    if (g_stat.last_ptoks > 0 && filled == 0) filled = 1;
    const char *bar_col = pct >= 85 ? RED : (pct >= 60 ? YELLOW : GREEN);

    char bar[128] = "";
    if (cols >= 64 && g_stat.last_ptoks > 0) {
        char pb[10];
        if (pct == 0) snprintf(pb, sizeof pb, "<1%%");
        else snprintf(pb, sizeof pb, "%d%%", pct);
        size_t bw = 0;
        bw += (size_t)snprintf(bar + bw, sizeof bar - bw, DIM " · ctx " RESET "%s", bar_col);
        for (int i = 0; i < 8; i++)
            bw += (size_t)snprintf(bar + bw, sizeof bar - bw, "%s", i < (filled * 8 + 5) / 10 ? "▓" : "░");
        snprintf(bar + bw, sizeof bar - bw, RESET DIM " %s" RESET, pb);
    }

    char stats[160] = "";
    if (g_stat.sess_turns > 0 && cols >= 72) {
        char tb[24];
        fmt_toks(g_stat.sess_toks, tb, sizeof tb);
        if (g_stat.last_tps >= 1.0)
            snprintf(stats, sizeof stats, DIM " · %dt · %s tok · " RESET YELLOW "⚡ %.0f tok/s" RESET,
                     g_stat.sess_turns, tb, g_stat.last_tps);
        else
            snprintf(stats, sizeof stats, DIM " · %dt · %s tok" RESET, g_stat.sess_turns, tb);
    }

    const char *hint = (cols >= 92 && !scroll_tag[0]) ? (DIM " · ^O cmds · /help" RESET) : "";
    printf(GREEN "●" RESET " " DIM "%s" RESET "%s%s" DIM "%s%s" RESET "%s",
           status, bar, stats, scroll_tag, qtag, hint);
}
static void draw_titled_top(const char *title, int box_w) {
    fputs(YELLOW "╭─ " BOLD, stdout);
    fputs(title, stdout);
    fputs(RESET YELLOW " ", stdout);
    int tw = 0;
    for (const char *p = title; *p;) {
        int bl = 0;
        tw += utf8_cell_width(p, (int)strlen(p), &bl);
        p += bl > 0 ? bl : 1;
    }
    int rem = box_w - tw - 3;
    if (rem < 0) rem = 0;
    for (int i = 0; i < rem; i++) fputs("─", stdout);
    fputs("╮" RESET, stdout);
}

static void render_screen(void) {
    get_size();
    int box_w = cols - 2;
    if (box_w < 10) box_w = 10;
    int inner_w = cols - 4;
    if (inner_w < 8) inner_w = 8;

    /* Determine chrome height */
    VLine vl[MAX_VLINES];
    int cur_vl = 0, cur_col = 0, nv = 1, vis = 1, vstart = 0;
    int mc = 0, ch = 0;
    int modal_body_lines = 0;

    if (active_modal) {
        modal_body_lines = (active_modal->body && *active_modal->body) ? 2 : 0; /* body + blank */
        ch = 2 /*borders*/ + modal_body_lines + 1 /*prompt*/ + active_modal->nopts + 1 /*status*/;
        if (ch > rows - 2) { modal_body_lines = 0; ch = 2 + 1 + active_modal->nopts + 1; }
    } else {
        nv = layout_input(vl, MAX_VLINES, inner_w, &cur_vl, &cur_col);
        vis = nv > 4 ? 4 : nv;
        if (cur_vl >= vis) vstart = cur_vl - vis + 1;
        if (vstart + vis > nv) vstart = nv - vis;
        if (vstart < 0) vstart = 0;
        mc = menu_count();
        ch = vis + 2 + mc + 1;
        if (ch > rows - 2) { mc = 0; ch = vis + 3; }
        if (menu_sel >= mc) menu_sel = mc > 0 ? mc - 1 : 0;
    }

    int view_h = rows - ch;
    if (view_h < 1) view_h = 1;

    /* Build transcript visual rows & clamp scroll_off */
    VBuf vb = {0};
    build_transcript(&vb);
    /* scroll anchoring: when scrolled up, new lines push the bottom down,
       so compensate scroll_off to keep the same content in view */
    {
        static int last_vb_n;
        if (scroll_off > 0 && last_vb_n > 0 && vb.n > last_vb_n)
            scroll_off += vb.n - last_vb_n;
        last_vb_n = vb.n;
    }
    max_scroll = vb.n > view_h ? vb.n - view_h : 0;
    if (scroll_off > max_scroll) scroll_off = max_scroll;
    if (scroll_off < 0) scroll_off = 0;

    int start_idx = vb.n - view_h - scroll_off;
    if (start_idx < 0) start_idx = 0;

    for (int r = 0; r < 512; r++) row_tool_idx[r] = -1;
    slash_menu_top = -1;
    slash_menu_cnt = 0;

    begin_sync();
    printf("\033[1;%dr", rows);   /* full screen region (no DECSTBM drift) */

    /* 1. Transcript viewport rows [0 .. view_h - 1] */
    for (int r = 0; r < view_h; r++) {
        printf("\033[%d;1H" CLR_LINE, r + 1);
        int idx = start_idx + r;
        if (idx >= 0 && idx < vb.n) {
            fputs(vb.v[idx].s, stdout);
            if (r < 512) row_tool_idx[r] = vb.v[idx].tool_idx;
        }
    }

    /* 2. Chrome at rows [view_h + 1 .. rows] (1-based) */
    int r = view_h + 1;
    if (active_modal) {
        Modal *m = active_modal;
        printf("\033[%d;1H" CLR_LINE, r++);
        draw_titled_top(m->title, box_w);

        if (modal_body_lines > 0) {
            char flat[512];
            int fk = 0;
            for (const char *p = m->body; *p && fk < inner_w - 2 && fk < 500; p++) {
                if (*p == '\n') { flat[fk++] = ' '; }
                else flat[fk++] = *p;
            }
            flat[fk] = 0;
            printf("\033[%d;1H" CLR_LINE YELLOW "│" RESET " " BOLD "%s%s" RESET "\033[%d;%dH" YELLOW "│" RESET,
                   r, flat, (int)strlen(m->body) > fk ? "…" : "", r, cols);
            r++;
            printf("\033[%d;1H" CLR_LINE YELLOW "│" RESET "\033[%d;%dH" YELLOW "│" RESET, r, r, cols);
            r++;
        }

        printf("\033[%d;1H" CLR_LINE YELLOW "│" RESET " %.*s\033[%d;%dH" YELLOW "│" RESET,
               r, inner_w, m->prompt ? m->prompt : "", r, cols);
        r++;

        m->opt_row_start = r - 1;   /* 0-based screen row of option 0 */
        for (int i = 0; i < m->nopts; i++, r++) {
            int omax = inner_w - 6;
            if (omax < 10) omax = 10;
            if (i == m->sel)
                printf("\033[%d;1H" CLR_LINE YELLOW "│" RESET " " CYAN BOLD "▸ %d. %.*s" RESET "\033[%d;%dH" YELLOW "│" RESET,
                       r, i + 1, omax, m->opts[i], r, cols);
            else
                printf("\033[%d;1H" CLR_LINE YELLOW "│" RESET "   " DIM "%d. " RESET "%.*s\033[%d;%dH" YELLOW "│" RESET,
                       r, i + 1, omax, m->opts[i], r, cols);
        }

        printf("\033[%d;1H" CLR_LINE YELLOW "╰", r++);
        for (int i = 0; i < box_w; i++) fputs("─", stdout);
        fputs("╯" RESET, stdout);

        printf("\033[%d;1H" CLR_LINE DIM " ↑↓ choose · Enter/1-%d or click · Esc cancel" RESET,
               rows, m->nopts);
        /* Hide cursor on modal menu (or park at selected row) */
        printf("\033[%d;3H", m->opt_row_start + m->sel + 1);
    } else {
        /* Input box top border with project/branch badge */
        printf("\033[%d;1H" CLR_LINE, r++);
        draw_input_top(box_w);

        /* Input text lines */
        int input_top_row = r;
        for (int li = 0; li < vis; li++, r++) {
            VLine *l = &vl[vstart + li];
            printf("\033[%d;1H" CLR_LINE DIM "│" RESET, r);
            if (vstart + li == 0) {
                fputs(CYAN BOLD "›" RESET " ", stdout);
                if (ilen == 0) fputs(DIM "Type a message, / for commands" RESET, stdout);
            } else fputs("  ", stdout);
            if (l->len > 0) fwrite(inbuf + l->start, 1, (size_t)l->len, stdout);
            printf("\033[%d;%dH" DIM "│" RESET, r, cols);
        }

        /* Input box bottom border */
        printf("\033[%d;1H" CLR_LINE, r++);
        draw_hline("╰", "╯", box_w);

        /* Slash menu below input box */
        if (mc > 0) {
            const char *m[8];
            int nm = menu_matches(m, 8);
            slash_menu_top = r - 1;   /* 0-based */
            slash_menu_cnt = mc < nm ? mc : nm;
            for (int i = 0; i < slash_menu_cnt; i++, r++) {
                const char *desc = "";
                for (int j = 0; SLASH[j].cmd; j++)
                    if (!strcmp(SLASH[j].cmd, m[i])) { desc = SLASH[j].desc; break; }
                int max_desc = cols - 16;
                if (max_desc < 10) max_desc = 10;
                if (i == menu_sel)
                    printf("\033[%d;1H" CLR_LINE CYAN BOLD " ▸ %-8s" RESET " %.*s",
                           r, m[i], max_desc, desc);
                else
                    printf("\033[%d;1H" CLR_LINE DIM "   %-8s %.*s" RESET,
                           r, m[i], max_desc, desc);
            }
        }

        /* Status line at bottom row */
        draw_status_bar();

        /* Cursor at exact cell inside input box: │(1) ›(2) ' '(3) text(4..) */
        int crow = input_top_row + (cur_vl - vstart);
        int ccol = cur_col + 4;
        if (ccol > cols - 1) ccol = cols - 1;
        printf("\033[%d;%dH", crow, ccol);
    }

    end_sync();
    vb_free(&vb);
}

static void set_status(const char *s) { snprintf(status, sizeof status, "%s", s); }

/* Toggle latest tool output (Ctrl+O) or specific tool index (mouse click). */
static bool item_toggleable(const TItem *it) {
    if (it->kind == T_TOOL && it->out) return true;
    if (it->kind == T_THINK && it->done) return true;
    return false;
}

static void toggle_tool(int idx) {
    if (idx < 0) {
        for (int i = nitems - 1; i >= 0; i--) {
            if (item_toggleable(&items[i])) { idx = i; break; }
        }
    }
    if (idx >= 0 && idx < nitems && item_toggleable(&items[idx])) {
        items[idx].expanded = !items[idx].expanded;
        render_screen();
    }
}

/* Parse an SGR mouse sequence "\033[<btn;col;rowM" (press) or "...m" (release).
   Returns true if it was a mouse sequence (consumed). Sets *clicked_row (0-based) on left press. */
static bool handle_mouse_seq(const unsigned char *buf, int len, int *clicked_row) {
    *clicked_row = -1;
    if (len < 6 || buf[0] != 27 || buf[1] != '[' || buf[2] != '<') return false;
    char term = (char)buf[len - 1];
    if (term != 'M' && term != 'm') return false;
    int btn = 0, mx = 0, my = 0;
    if (sscanf((const char *)buf + 3, "%d;%d;%d", &btn, &mx, &my) != 3) return true;
    if (term != 'M') return true; /* ignore button release */
    if (btn == 64) { /* wheel up */
        scroll_off += 3;
        if (scroll_off > max_scroll) scroll_off = max_scroll;
        render_screen();
        return true;
    }
    if (btn == 65) { /* wheel down */
        scroll_off -= 3;
        if (scroll_off < 0) scroll_off = 0;
        render_screen();
        return true;
    }
    if ((btn & 3) == 0 && !(btn & 32)) { /* left click press */
        int r0 = my - 1;
        *clicked_row = r0;
        if (r0 >= 0 && r0 < 512 && row_tool_idx[r0] >= 0) {
            toggle_tool(row_tool_idx[r0]);
            *clicked_row = -1; /* already handled */
        }
    }
    return true;
}

/* Collect one escape sequence after reading initial ESC (27). */
static int read_esc_seq(unsigned char *buf, int cap) {
    int n = 0;
    buf[n++] = 27;
    unsigned char c2;
    while (n < cap - 1) {
        fd_set ef;
        FD_ZERO(&ef);
        FD_SET(0, &ef);
        struct timeval etv = {.tv_sec = 0, .tv_usec = 25000};
        if (select(1, &ef, NULL, NULL, &etv) <= 0) break;
        if (read(0, &c2, 1) != 1) break;
        buf[n++] = c2;
        if (n == 2 && c2 != '[' && c2 != 'O') break; /* e.g. Alt+Enter (\033\r) */
        if (n >= 3 && buf[1] == '[' && buf[2] == '<') {
            if (c2 == 'M' || c2 == 'm') break;       /* SGR mouse */
            continue;
        }
        if ((c2 >= 'A' && c2 <= 'Z') || (c2 >= 'a' && c2 <= 'z') || c2 == '~') break;
    }
    buf[n] = 0;
    return n;
}

/* Reusable Claude-Code-style modal menu: returns chosen index 0..nopts-1, or -1 on Esc/cancel. */
static int tui_choose_menu(const char *title, const char *body, const char *prompt,
                           const char **opts, int nopts, const char *shortcuts) {
    Modal m = {
        .title = title, .body = body, .prompt = prompt,
        .opts = opts, .nopts = nopts, .sel = 0, .opt_row_start = -1
    };
    active_modal = &m;
    render_screen();

    int result = -1;
    for (;;) {
        if (g_resized) { g_resized = 0; render_screen(); }
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(0, &rf);
        struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};
        if (select(1, &rf, NULL, NULL, &tv) <= 0) continue;

        unsigned char ch = 0;
        if (read(0, &ch, 1) != 1) continue;

        if (ch == 27) {
            unsigned char eb[32];
            int en = read_esc_seq(eb, sizeof eb);
            if (en == 1) { result = -1; break; }
            int clicked = -1;
            if (handle_mouse_seq(eb, en, &clicked)) {
                if (clicked >= m.opt_row_start && clicked < m.opt_row_start + m.nopts) {
                    result = clicked - m.opt_row_start;
                    break;
                }
                continue;
            }
            if (eb[1] == '[' || eb[1] == 'O') {
                char k = (char)eb[en - 1];
                if (k == 'A') { m.sel = (m.sel > 0) ? m.sel - 1 : m.nopts - 1; render_screen(); }
                else if (k == 'B') { m.sel = (m.sel + 1) % m.nopts; render_screen(); }
                else if (k == '~' && en >= 3 && eb[2] == '5') { scroll_off += 8; render_screen(); }
                else if (k == '~' && en >= 3 && eb[2] == '6') { scroll_off -= 8; render_screen(); }
            }
            continue;
        }
        if (ch == 3) { result = -1; break; }               /* ^C cancels */
        if (ch == 15) { toggle_tool(-1); continue; }       /* ^O toggles last command */
        if (ch == '\r' || ch == '\n') { result = m.sel; break; }
        if (ch >= '1' && ch < '1' + nopts) { result = ch - '1'; break; }
        if (shortcuts) {
            for (int i = 0; i < nopts && shortcuts[i]; i++) {
                if (ch == (unsigned char)shortcuts[i] ||
                    (shortcuts[i] >= 'a' && shortcuts[i] <= 'z' && ch == (unsigned char)(shortcuts[i] - 32))) {
                    result = i;
                    goto done;
                }
            }
        }
    }
done:
    active_modal = NULL;
    render_screen();
    return result;
}

/* ---------- Ui callbacks ---------- */

/* Close a trailing open think item (reasoning finished). */
static void think_close(void) {
    if (nitems > 0 && items[nitems - 1].kind == T_THINK && !items[nitems - 1].done) {
        items[nitems - 1].done = true;
        items[nitems - 1].t1 = mono_now();
    }
}

static void ui_text(const char *p, void *ud) {
    (void)ud;
    if (!p || !*p) return;
    think_close();
    g_stat.phase = "writing";
    g_stat.stream_chunks++;
    TItem *it = (nitems > 0 && items[nitems - 1].kind == T_TEXT) ? &items[nitems - 1] : item_new(T_TEXT);
    item_append(it, p);
    render_screen();
}

static void ui_think(const char *p, void *ud) {
    (void)ud;
    if (!p || !*p) return;
    g_stat.phase = "thinking";
    g_stat.stream_chunks++;
    TItem *it;
    if (nitems > 0 && items[nitems - 1].kind == T_THINK && !items[nitems - 1].done) {
        it = &items[nitems - 1];
    } else {
        it = item_new(T_THINK);
        it->t0 = mono_now();
    }
    item_append(it, p);
    render_screen();
}

static void ui_tool(const char *name, const char *detail, void *ud) {
    (void)ud;
    think_close();
    g_stat.phase = "bash";
    TItem *it = item_new(T_TOOL);
    snprintf(it->tname, sizeof it->tname, "%s", name ? name : "Bash");
    item_append(it, detail ? detail : "");
    it->expanded = false;
    it->done = false;
    render_screen();
}

static void ui_stats(const AgentStats *st, void *ud) {
    (void)ud;
    if (!st) return;
    if (st->prompt_tokens > 0) g_stat.last_ptoks = st->prompt_tokens;
    g_stat.task_turns = st->turns;
    g_stat.task_calls = st->calls;
    g_stat.task_toks = st->completion_tokens;
    g_stat.stream_chunks = 0;
    if (st->tok_per_sec > 0.1) g_stat.last_tps = st->tok_per_sec;
    if (st->finish) {
        g_stat.last_final = *st;
        g_stat.has_final = true;
        g_stat.sess_turns += st->turns;
        g_stat.sess_calls += st->calls;
        g_stat.sess_toks += st->completion_tokens;
        g_stat.sess_secs += st->secs;
    }
}

static void ui_out(const char *out, void *ud) {
    (void)ud;
    TItem *it = NULL;
    for (int i = nitems - 1; i >= 0; i--) {
        if (items[i].kind == T_TOOL && !items[i].done) { it = &items[i]; break; }
    }
    if (it) {
        free(it->out);
        it->out = str_dup(out ? out : "(no output)");
        it->done = true;
    } else {
        TItem *r = item_new(T_RAW);
        item_append(r, out ? out : "");
    }
    render_screen();
}

static void ui_status(const char *s, void *ud) { (void)ud; set_status(s); render_screen(); }

static void ui_event(const char *kind, const char *detail, void *ud) {
    (void)ud;
    char b[512];
    if (!strcmp(kind, "prune")) snprintf(b, sizeof b, YELLOW "  ✂ loop pruned (%s)" RESET, detail);
    else if (!strcmp(kind, "reset")) snprintf(b, sizeof b, YELLOW "  ↺ context reset (%s)" RESET, detail);
    else if (!strcmp(kind, "gate")) snprintf(b, sizeof b, BLUE "  ○ %s" RESET, detail);
    else snprintf(b, sizeof b, "  %s %s", kind, detail);
    TItem *r = item_new(T_RAW);
    item_append(r, b);
    render_screen();
}

/* Claude-Code-style approval modal menu. */
static bool ui_approve(const char *cmd, void *ud) {
    (void)ud;
    /* OSC 9 notification for Mica attention indicator */
    fputs("\033]9;flywheel: command approval needed\007", stdout);
    fflush(stdout);

    char *rule = perm_prefix(cmd);
    char opt2[256];
    snprintf(opt2, sizeof opt2, "Yes, and don't ask again for `%s` commands", rule ? rule : cmd);
    const char *opts[3] = {
        "Yes",
        opt2,
        "No"
    };
    int pick = tui_choose_menu("⚠ Bash command", cmd, "Do you want to proceed?", opts, 3, "yan");
    if (pick == 0) {
        set_status("approved once");
        free(rule);
        return true;
    }
    if (pick == 1) {
        if (rule) perm_add_rule(rule);
        snprintf(status, sizeof status, "always allowed: %s", rule ? rule : "");
        free(rule);
        return true;
    }
    set_status("denied");
    free(rule);
    return false;
}

static Msgs *g_msgs;
void g_msgs_link(Msgs *m) { g_msgs = m; }

static bool project_init_done(void) {
    const char *files[] = {".flywheel.md", "AGENTS.md", "CLAUDE.md", NULL};
    for (int i = 0; files[i]; i++) {
        char p[1024];
        snprintf(p, sizeof p, "%s/%s", g_cfg.cwd, files[i]);
        if (access(p, F_OK) == 0) return true;
    }
    return false;
}

static void refresh_system(void) {
    char *ns = fw_build_system(true);
    free(g_msgs->v[0].content);
    g_msgs->v[0].content = ns;
}

void tui_run_task(const char *prompt) {
    scroll_off = 0;
    msgs_push(g_msgs, "user", prompt);
    TItem *u = item_new(T_USER);
    item_append(u, prompt);
    render_screen();

    Ui ui = {.emit_text = ui_text, .emit_think = ui_think, .emit_tool = ui_tool,
             .emit_out = ui_out, .emit_status = ui_status, .emit_event = ui_event,
             .emit_stats = ui_stats, .approve_cmd = ui_approve, .interactive = true};
    char sum[256];
    g_abort = 0;
    working = true;
    g_stat.phase = "thinking";
    g_stat.task_turns = g_stat.task_calls = g_stat.task_toks = g_stat.stream_chunks = 0;
    g_stat.has_final = false;
    clock_gettime(CLOCK_MONOTONIC, &g_stat.task_t0);
    set_status("working…");
    render_screen();
    fw_tick_hook = tui_pump;
    const char *fin = agent_run(g_msgs, &ui, sum, sizeof sum);
    fw_tick_hook = NULL;
    working = false;
    think_close();

    double wall_dt = mono_now() - (g_stat.task_t0.tv_sec + g_stat.task_t0.tv_nsec / 1e9);
    if (wall_dt < 0) wall_dt = 0;

    char done[640];
    if (g_stat.has_final && !strcmp(fin, "done")) {
        char tb[24], extras[160] = "", tps_s[48] = "";
        fmt_toks(g_stat.last_final.completion_tokens, tb, sizeof tb);
        if (g_stat.last_final.tok_per_sec >= 1.0)
            snprintf(tps_s, sizeof tps_s, " · " YELLOW "⚡ %.0f tok/s" RESET, g_stat.last_final.tok_per_sec);
        if (g_stat.last_final.prunes)
            snprintf(extras + strlen(extras), sizeof extras - strlen(extras),
                     " · " YELLOW "⚡ %d prune%s" RESET, g_stat.last_final.prunes, g_stat.last_final.prunes == 1 ? "" : "s");
        if (g_stat.last_final.gates)
            snprintf(extras + strlen(extras), sizeof extras - strlen(extras),
                     " · " BLUE "○ %d gate%s" RESET, g_stat.last_final.gates, g_stat.last_final.gates == 1 ? "" : "s");
        snprintf(done, sizeof done,
                 GREEN "✓ done" RESET DIM " · %d turn%s · %d bash · %s tok" RESET "%s%s" DIM " · %.1fs" RESET,
                 g_stat.last_final.turns, g_stat.last_final.turns == 1 ? "" : "s",
                 g_stat.last_final.calls, tb, tps_s, extras, wall_dt);
    } else {
        snprintf(done, sizeof done, YELLOW "✗ %s" RESET DIM " · %.1fs" RESET, fin, wall_dt);
    }
    TItem *d = item_new(T_RAW);
    item_append(d, done);
    set_status("ready");
    render_screen();
    if (wall_dt > 15.0) {
        fputs("\033]9;flywheel: task finished\007", stdout);
        fflush(stdout);
    }
    drain_queue();
}

static void ins(const char *s, int n) {
    if (ilen + n >= (int)sizeof inbuf - 1) return;
    memmove(inbuf + icur + n, inbuf + icur, (size_t)(ilen - icur));
    memcpy(inbuf + icur, s, (size_t)n);
    icur += n; ilen += n;
    inbuf[ilen] = 0;
    menu_dismissed = false;
}

static void push_raw(const char *s) {
    TItem *r = item_new(T_RAW);
    item_append(r, s);
    render_screen();
}

static void run_slash(const char *cmd) {
    if (!strcmp(cmd, "/init")) {
        term_raw(false);
        printf("\033[r\033[%d;1H\n", rows);
        fflush(stdout);
        fw_do_init();
        refresh_system();
        term_raw(true);
        push_raw(GREEN "  ✓ init done" RESET);
    } else if (!strcmp(cmd, "/clear")) {
        while (g_msgs->n > 1) msgs_trunc(g_msgs, 1);
        transcript_clear();
        render_screen();
    } else if (!strcmp(cmd, "/help")) {
        push_raw("commands: /init /clear /model /allow /status /help /exit\n"
                 "keys: ↑↓ history · Shift/Alt+Enter newline · ^O expand/collapse cmd · Cmd/Ctrl+V image · PgUp/PgDn or wheel scroll · Esc aborts · ^C clear · ^D quit");
    } else if (!strncmp(cmd, "/model", 6)) {
        if (cmd[6] == ' ' && cmd[7]) {
            free(g_cfg.model);
            g_cfg.model = str_dup(cmd + 7);
            char b[300];
            snprintf(b, sizeof b, "  model: " CYAN "%s" RESET, g_cfg.model);
            push_raw(b);
        } else {
            /* Fetch served models and show interactive picker if >1, else show current */
            char *mj = http_get("/models");
            const char *mnames[16];
            int nm = 0;
            cJSON *root = mj ? cJSON_Parse(mj) : NULL;
            free(mj);
            cJSON *data = root ? cJSON_GetObjectItemCaseSensitive(root, "data") : NULL;
            cJSON *el;
            if (data && cJSON_IsArray(data)) {
                cJSON_ArrayForEach(el, data) {
                    cJSON *id = cJSON_GetObjectItemCaseSensitive(el, "id");
                    if (cJSON_IsString(id) && nm < 16) mnames[nm++] = id->valuestring;
                }
            }
            if (nm > 1) {
                int pick = tui_choose_menu("Model", NULL, "Choose a model:", mnames, nm, NULL);
                if (pick >= 0 && pick < nm) {
                    free(g_cfg.model);
                    g_cfg.model = str_dup(mnames[pick]);
                }
            }
            char b[300];
            snprintf(b, sizeof b, "  model: " CYAN "%s" RESET, g_cfg.model);
            push_raw(b);
            if (root) cJSON_Delete(root);
        }
    } else if (!strcmp(cmd, "/allow")) {
        perm_load();
        char p[1024];
        snprintf(p, sizeof p, "%s/.flywheel.allow", g_cfg.cwd);
        char *c = read_file(p);
        if (c) {
            char b[4200];
            snprintf(b, sizeof b, "  permission rules (.flywheel.allow + builtin read-only):\n%.3900s", c);
            push_raw(b);
            free(c);
        } else {
            push_raw("  permission rules (.flywheel.allow): (none yet — approve with option 2 to add)");
        }
    } else if (!strcmp(cmd, "/status")) {
        char b[600];
        const Profile *prof = profile_detect(g_cfg.cwd, g_cfg.profile);
        char *models = http_get("/models");
        snprintf(b, sizeof b, "  engine: %s %s · model: " CYAN "%s" RESET " · profile: %s · msgs: %d",
                 g_cfg.endpoint, models ? GREEN "up" RESET : RED "down" RESET,
                 g_cfg.model, prof->name, g_msgs->n);
        free(models);
        push_raw(b);
    } else {
        char b[300];
        snprintf(b, sizeof b, "  unknown command: %.200s (try /help)", cmd);
        push_raw(b);
    }
}

/* Cmd+V (Mica sends 0x16 for clipboard images) / Ctrl+V:
   save clipboard image (PNG, or TIFF fallback converted to PNG) without shell-injecting cwd. */
static void paste_clipboard_image(void) {
    char dir[1024];
    snprintf(dir, sizeof dir, "%s/.flywheel", g_cfg.cwd);
    mkdir(dir, 0755);
    static int imgn;
    char path[1200], tiff[1200];
    snprintf(path, sizeof path, "%s/paste-%d.png", dir, ++imgn);
    snprintf(tiff, sizeof tiff, "%s/paste-%d.tiff", dir, imgn);
    setenv("FW_IMG_PATH", path, 1);
    setenv("FW_TIFF_PATH", tiff, 1);
    const char *png_cmd =
        "osascript -e 'set p to system attribute \"FW_IMG_PATH\"' "
        "-e 'set d to (the clipboard as «class PNGf»)' "
        "-e 'set fp to open for access POSIX file p with write permission' "
        "-e 'write d to fp' -e 'close access fp' >/dev/null 2>&1";
    const char *tiff_cmd =
        "osascript -e 'set p to system attribute \"FW_TIFF_PATH\"' "
        "-e 'set d to (the clipboard as TIFF picture)' "
        "-e 'set fp to open for access POSIX file p with write permission' "
        "-e 'write d to fp' -e 'close access fp' >/dev/null 2>&1 "
        "&& sips -s format png \"$FW_TIFF_PATH\" --out \"$FW_IMG_PATH\" >/dev/null 2>&1 "
        "&& rm -f \"$FW_TIFF_PATH\"";
    bool ok = (system(png_cmd) == 0 && access(path, F_OK) == 0);
    if (!ok) {
        unlink(path);
        ok = (system(tiff_cmd) == 0 && access(path, F_OK) == 0);
        unlink(tiff);
    }
    if (ok) {
        char ref[1300];
        snprintf(ref, sizeof ref, "[image: %s]", path);
        ins(ref, (int)strlen(ref));
        set_status("image pasted (vision needs engine without --language-only)");
    } else {
        unlink(path);
        set_status("no image in clipboard");
    }
}

static void collapse_paste_if_big(void) {
    if (paste_start < 0) return;
    if (paste_start + paste_bytes > ilen) { paste_start = -1; return; }
    bool multiline = false;
    for (int i = paste_start; i < paste_start + paste_bytes; i++)
        if (inbuf[i] == '\n') multiline = true;
    if (!multiline && paste_bytes < 200) { paste_start = -1; return; }
    if (npastes >= MAXPASTE) { paste_start = -1; return; }
    pastes[npastes] = str_ndup(inbuf + paste_start, (size_t)paste_bytes);
    char tok[48];
    int lines = 1;
    for (const char *p = pastes[npastes]; *p; p++) if (*p == '\n') lines++;
    snprintf(tok, sizeof tok, "[paste#%d +%d lines]", npastes + 1, lines);
    npastes++;
    memmove(inbuf + paste_start, inbuf + paste_start + paste_bytes,
            (size_t)(ilen - paste_start - paste_bytes));
    ilen -= paste_bytes;
    inbuf[ilen] = 0;
    icur = paste_start;
    ins(tok, (int)strlen(tok));
    paste_start = -1;
}

static void expand_pastes(char *cmd, size_t cap) {
    char *out = malloc(cap);
    if (!out) return;
    size_t w = 0;
    for (size_t r = 0; cmd[r] && w < cap - 1;) {
        int slot = -1;
        size_t adv = 0;
        if (cmd[r] == '[' && sscanf(cmd + r, "[paste#%d ", &slot) == 1) {
            const char *close = strchr(cmd + r, ']');
            if (close && slot >= 1 && slot <= npastes) adv = (size_t)(close - cmd - (ptrdiff_t)r + 1);
            else slot = -1;
        }
        if (slot >= 1 && adv) {
            const char *pc = pastes[slot - 1];
            while (*pc && w < cap - 1) out[w++] = *pc++;
            r += adv;
        } else out[w++] = cmd[r++];
    }
    out[w] = 0;
    memcpy(cmd, out, w + 1);
    free(out);
}

void tui_cleanup(void) {
    transcript_clear();
    free(items); items = NULL; cap_items = 0;
    for (int i = 0; i < hist_n; i++) { free(HIST[i]); HIST[i] = NULL; }
    hist_n = 0;
    for (int i = 0; i < npastes; i++) { free(pastes[i]); pastes[i] = NULL; }
    npastes = 0;
}

static void card_line(MdBuf *m, int inner_w, const char *body) {
    md_cat(m, DIM "│" RESET);
    int w = 0;
    const char *p = body;
    while (*p) {
        if (*p == '\033') {
            const char *s0 = p++;
            if (*p == '[') { p++; while (*p && !((unsigned char)*p >= 0x40 && (unsigned char)*p <= 0x7E)) p++; if (*p) p++; }
            else if (*p) p++;
            md_catn(m, s0, (size_t)(p - s0));
            continue;
        }
        int bl = 0;
        int cw = utf8_cell_width(p, (int)strlen(p), &bl);
        if (bl <= 0) { p++; continue; }
        if (w + cw > inner_w) break;
        md_catn(m, p, (size_t)bl);
        w += cw;
        p += bl;
    }
    while (w < inner_w) { md_cat(m, " "); w++; }
    md_cat(m, DIM "│" RESET "\n");
}

static void push_welcome_card(const Profile *prof) {
    /* Ping engine once for online badge + context_length */
    bool online = false;
    char *mj = http_get("/models");
    if (mj) {
        online = true;
        cJSON *root = cJSON_Parse(mj);
        cJSON *data = root ? cJSON_GetObjectItemCaseSensitive(root, "data") : NULL;
        cJSON *m0 = (data && cJSON_IsArray(data)) ? cJSON_GetArrayItem(data, 0) : NULL;
        cJSON *cl = m0 ? cJSON_GetObjectItemCaseSensitive(m0, "context_length") : NULL;
        if (!cl && m0) cl = cJSON_GetObjectItemCaseSensitive(m0, "max_model_len");
        if (cJSON_IsNumber(cl) && cl->valueint > 1024) g_stat.ctx_limit = cl->valueint;
        if (root) cJSON_Delete(root);
        free(mj);
    }

    char ctxs[32];
    fmt_toks(g_stat.ctx_limit, ctxs, sizeof ctxs);
    char proj_s[260];
    if (g_stat.git_branch[0])
        snprintf(proj_s, sizeof proj_s, "%s " CYAN "(⎇ %s)" RESET DIM " · %s" RESET,
                 g_stat.proj_name, g_stat.git_branch, prof->name);
    else
        snprintf(proj_s, sizeof proj_s, "%s " DIM "· %s" RESET, g_stat.proj_name, prof->name);

    int cw = (cols >= 72) ? 68 : (cols - 4);
    if (cw < 40) cw = 40;
    MdBuf card = {0};
    md_cat(&card, DIM "╭");
    for (int i = 0; i < cw; i++) md_cat(&card, "─");
    md_cat(&card, "╮" RESET "\n");

    char r1[256], r2[512], r3[512], r4[512], r5[256];
    snprintf(r1, sizeof r1, "    " CYAN "╭─┴─╮" RESET "     " CYAN BOLD "F L Y W H E E L" RESET "  " DIM "v" FW_VERSION RESET);
    snprintf(r2, sizeof r2, "  " CYAN "╭─┤ " YELLOW "◎" CYAN " ├─╮" RESET "   " DIM "model  " RESET " " BOLD "%s" RESET DIM " · %s ctx" RESET,
             g_cfg.model, ctxs);
    snprintf(r3, sizeof r3, "    " CYAN "╰─┬─╯" RESET "     " DIM "engine " RESET " %s" DIM " · %s" RESET,
             online ? (GREEN "● online" RESET) : (RED "○ offline" RESET), g_cfg.endpoint);
    snprintf(r4, sizeof r4, "   " YELLOW "⚡" RESET DIM " ───" RESET "     " DIM "project" RESET " %s", proj_s);
    snprintf(r5, sizeof r5, "              " DIM "tips    /help · click or ^O cmds · ↑↓ history" RESET);

    card_line(&card, cw, r1);
    card_line(&card, cw, r2);
    card_line(&card, cw, r3);
    card_line(&card, cw, r4);
    card_line(&card, cw, r5);

    md_cat(&card, DIM "╰");
    for (int i = 0; i < cw; i++) md_cat(&card, "─");
    md_cat(&card, "╯" RESET);

    push_raw(card.b);
    free(card.b);
}

/* Central key handler shared by the idle REPL loop and the busy pump.
   busy=true while the agent is working: typing edits the input box normally,
   Enter queues the message, Esc/^C abort the task, scrolling/expand all work. */
static void handle_key(unsigned char ch, bool busy) {
    unsigned char escbuf[32];
    if (ch == 27) {
        int escn = read_esc_seq(escbuf, sizeof escbuf);
        if (escn == 1) {
            if (busy) { g_abort = 1; qn = 0; set_status("aborting…"); render_screen(); return; }
            if (menu_count()) { menu_dismissed = true; render_screen(); }
            return;
        }
        int clicked = -1;
        if (handle_mouse_seq(escbuf, escn, &clicked)) {
            /* Click on an item in the open slash menu? */
            if (clicked >= 0 && slash_menu_top >= 0 &&
                clicked >= slash_menu_top && clicked < slash_menu_top + slash_menu_cnt) {
                const char *m[8];
                int nm = menu_matches(m, 8);
                int idx = clicked - slash_menu_top;
                if (idx < nm) {
                    const char *pick = m[idx];
                    ilen = icur = 0; inbuf[0] = 0; hpos = -1; menu_sel = 0; menu_dismissed = false;
if (busy) {
                        snprintf(inbuf, sizeof inbuf, "%s ", pick);
                        ilen = icur = (int)strlen(inbuf);
                        render_screen();
                        return;
                    }
                                        if (!strcmp(pick, "/exit") || !strcmp(pick, "/quit")) { want_exit = true; return; }
                    render_screen();
                    run_slash(pick);
                    render_screen();
                }
            }
            return;
        }
        if (escn >= 6 && !memcmp(escbuf, "\033[200~", 6)) { pasting = true; paste_start = icur; paste_bytes = 0; return; }
        if (escn >= 6 && !memcmp(escbuf, "\033[201~", 6)) { pasting = false; collapse_paste_if_big(); render_screen(); return; }
        if (escn == 2 && (escbuf[1] == '\r' || escbuf[1] == '\n')) {
            ins("\n", 1); menu_sel = 0; render_screen(); return;
        }
        if (escbuf[1] == '[' || escbuf[1] == 'O') {
            char k = (char)escbuf[escn - 1];
            int mc = menu_count();
            if (k == 'A') {   /* up */
                if (mc) { menu_sel = (menu_sel > 0) ? menu_sel - 1 : mc - 1; }
                else if (hpos < hist_n - 1) {
                    hpos++;
                    snprintf(inbuf, sizeof inbuf, "%s", HIST[hist_n - 1 - hpos]);
                    ilen = icur = (int)strlen(inbuf);
                }
            } else if (k == 'B') {   /* down */
                if (mc) { menu_sel = (menu_sel + 1) % mc; }
                else if (hpos >= 0) {
                    hpos--;
                    if (hpos < 0) inbuf[0] = ilen = icur = 0;
                    else { snprintf(inbuf, sizeof inbuf, "%s", HIST[hist_n - 1 - hpos]); ilen = icur = (int)strlen(inbuf); }
                }
            } else if (k == 'D') { icur = utf8_prev(inbuf, icur); }
            else if (k == 'C') { icur = utf8_next(inbuf, ilen, icur); }
            else if (k == 'H') icur = 0;
            else if (k == 'F') { icur = ilen; if (busy) scroll_off = 0; }
            else if (k == '~' && escn >= 3 && escbuf[2] == '3') {   /* delete */
                if (icur < ilen) {
                    int nxt = utf8_next(inbuf, ilen, icur);
                    memmove(inbuf + icur, inbuf + nxt, (size_t)(ilen - nxt));
                    ilen -= (nxt - icur);
                    inbuf[ilen] = 0;
                }
            } else if (k == '~' && escn >= 3 && escbuf[2] == '5') { /* PageUp */
                scroll_off += 8;
            } else if (k == '~' && escn >= 3 && escbuf[2] == '6') { /* PageDown */
                scroll_off -= 8;
            }
            render_screen();
            return;
        }
        return;
    }

    if (ch == 4 && ilen == 0 && !busy) { want_exit = true; return; }     /* ^D quit */
    if (ch == 3) {
        if (busy) { g_abort = 1; qn = 0; set_status("aborting…"); render_screen(); return; }
        ilen = icur = 0; inbuf[0] = 0; hpos = -1; menu_sel = 0; menu_dismissed = false;
        render_screen(); return;
    }
    if (ch == 15) { toggle_tool(-1); return; }      /* ^O expand/collapse last command */
    if (ch == 1) { icur = 0; render_screen(); return; }          /* ^A */
    if (ch == 5) { icur = ilen; render_screen(); return; }       /* ^E */
    if (ch == 11) { ilen = icur; inbuf[ilen] = 0; render_screen(); return; }  /* ^K */
    if (ch == 21) {   /* ^U */
        memmove(inbuf, inbuf + icur, (size_t)(ilen - icur));
        ilen -= icur; icur = 0; inbuf[ilen] = 0;
        render_screen(); return;
    }
    if (ch == 23) {   /* ^W */
        int s = icur;
        while (s > 0 && inbuf[s - 1] == ' ') s--;
        while (s > 0 && inbuf[s - 1] != ' ') s--;
        memmove(inbuf + s, inbuf + icur, (size_t)(ilen - icur));
        ilen -= icur - s; icur = s; inbuf[ilen] = 0;
        render_screen(); return;
    }
    if (ch == '\t') {   /* tab completes slash */
        const char *m[8];
        int nm = menu_matches(m, 8);
        if (nm) {
            const char *pick = m[menu_sel < nm ? menu_sel : 0];
            int plen = 0;
            while (plen < ilen && inbuf[plen] != ' ') plen++;
            int newlen = (int)strlen(pick);
            if (ilen - plen + newlen + 2 < (int)sizeof inbuf) {
                memmove(inbuf + newlen, inbuf + plen, (size_t)(ilen - plen));
                ilen += newlen - plen;
                memcpy(inbuf, pick, (size_t)newlen);
                icur = newlen;
                inbuf[ilen] = 0;
                if (!strcmp(pick, "/model")) ins(" ", 1);
            }
            menu_sel = 0;
            render_screen();
        }
        return;
    }
    if (ch == '\r' || ch == '\n') {
        if (pasting) { ins("\n", 1); paste_bytes++; return; }
        inbuf[ilen] = 0;
        if (!ilen) { render_screen(); return; }
        if (menu_count() && !strchr(inbuf, ' ')) {
            const char *m[8];
            int nm = menu_matches(m, 8);
            if (nm) {
                const char *pick = m[menu_sel < nm ? menu_sel : 0];
                int plen = 0;
                while (plen < ilen && inbuf[plen] != ' ') plen++;
                int newlen = (int)strlen(pick);
                if (ilen - plen + newlen + 1 < (int)sizeof inbuf) {
                    memmove(inbuf + newlen, inbuf + plen, (size_t)(ilen - plen));
                    ilen += newlen - plen;
                    memcpy(inbuf, pick, (size_t)newlen);
                    inbuf[ilen] = 0;
                    icur = ilen;
                }
            }
        }
        bool isexit = !strcmp(inbuf, "/exit") || !strcmp(inbuf, "/quit");
        if (hist_n == 0 || strcmp(HIST[hist_n - 1], inbuf)) {
            if (hist_n < MAXHIST) HIST[hist_n++] = str_dup(inbuf);
            else {
                free(HIST[0]);
                memmove(HIST, HIST + 1, sizeof(char *) * (MAXHIST - 1));
                HIST[MAXHIST - 1] = str_dup(inbuf);
            }
        }
        char cmd[16384];
        snprintf(cmd, sizeof cmd, "%s", inbuf);
        expand_pastes(cmd, sizeof cmd);
        ilen = icur = 0; inbuf[0] = 0; hpos = -1; menu_sel = 0; menu_dismissed = false;
        if (busy) {
            if (qn < 8) { snprintf(qmsg[qn], sizeof qmsg[qn], "%s", cmd); qn++; }
            render_screen();
            return;
        }
        if (isexit) { want_exit = true; return; }
        render_screen();
        if (cmd[0] == '/') run_slash(cmd);
        else tui_run_task(cmd);
        render_screen();
        return;
    }
    if (ch == 127 || ch == 8) {
        if (icur > 0) {
            int prev = utf8_prev(inbuf, icur);
            memmove(inbuf + prev, inbuf + icur, (size_t)(ilen - icur));
            ilen -= (icur - prev);
            icur = prev;
            inbuf[ilen] = 0;
            menu_dismissed = false;
        }
        render_screen(); return;
    }
    if (ch == 22) { paste_clipboard_image(); render_screen(); return; }  /* Cmd+V image / Ctrl+V */
    if (ch >= 32) {
        char c1 = (char)ch;
        ins(&c1, 1);
        if (pasting) { paste_bytes++; return; }
        render_screen(); return;
    }
}

/* Drain queued messages after a task completes. */
static void drain_queue(void) {
    while (qn > 0 && !g_abort) {
        char next[16384];
        snprintf(next, sizeof next, "%s", qmsg[0]);
        for (int i = 1; i < qn; i++) memcpy(qmsg[i - 1], qmsg[i], sizeof qmsg[i]);
        qn--;
        if (next[0] == '/') run_slash(next);
        else tui_run_task(next);
    }
    if (g_abort) qn = 0;
}

/* Input pump: process pending keystrokes while the agent is busy, throttle renders. */
static void tui_pump(void) {
    for (;;) {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(0, &rf);
        struct timeval tv = {0, 0};
        if (select(1, &rf, NULL, NULL, &tv) <= 0) break;
        unsigned char ch;
        if (read(0, &ch, 1) != 1) break;
        handle_key(ch, true);
    }
    static double lastr;
    double now = mono_now();
    if (now - lastr >= 0.08) { lastr = now; if (working) render_screen(); }
}

void tui_repl(void) {
    signal(SIGWINCH, on_winch);
    detect_project_meta();
    term_raw(true);
    get_size();

    const Profile *prof = profile_detect(g_cfg.cwd, g_cfg.profile);
    push_welcome_card(prof);

    if (!project_init_done()) {
        const char *opts[2] = {
            "Yes, initialize .flywheel.md and check engine",
            "No, skip for now"
        };
        char prompt[1200];
        snprintf(prompt, sizeof prompt, "No .flywheel.md or AGENTS.md in %s:", g_cfg.cwd);
        int pick = tui_choose_menu("Project setup", NULL, prompt, opts, 2, "yn");
        if (pick == 0) run_slash("/init");
    }

    render_screen();

    unsigned char escbuf_dummy[1]; (void)escbuf_dummy;

    want_exit = false;
    for (;;) {
        if (g_resized) { g_resized = 0; render_screen(); }

        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(0, &rf);
        struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};
        if (select(1, &rf, NULL, NULL, &tv) <= 0) continue;

        unsigned char ch;
        ssize_t n = read(0, &ch, 1);
        if (n <= 0) { if (n == 0) break; continue; }
        handle_key(ch, false);
        if (want_exit) break;
    }
    term_raw(false);
    printf("\033[r\033[%d;1H\n", rows);
    fflush(stdout);
}
