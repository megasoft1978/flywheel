#define _XOPEN_SOURCE 700
#define _DARWIN_C_SOURCE 1
#include "flywheel.h"
#include "image.h"
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>
#include <signal.h>
#include <wchar.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#ifdef __APPLE__
#include <libproc.h>
#endif

/* claude-code-style TUI v4 (Mica / libvterm & xterm compatible):
   - structured transcript buffer with atomic full-viewport rendering
     inside Mica synchronized output frames (CSI ?2026h / ?2026l)
   - collapsed Bash(...) command blocks by default; click (SGR mouse ?1000h/?1006h)
     or press ^O to expand/collapse in place
   - mouse wheel + PageUp/PageDown smooth transcript scrolling
   - /mouse turns mouse reporting off so the terminal can select text again;
     /copy puts the last reply on the clipboard (pbcopy, or OSC 52 over SSH)
   - interactive Claude-Code-style modal menu for bash approvals & multi-choice
     prompts (↑↓ + Enter, 1-9, y/a/n shortcuts, or mouse click)
   - rounded input box + slash menu below it + status bar pinned at bottom
   - UTF-8 / emoji width via wcwidth(), soft-wrapped input (up to 4 visible rows)
   - Alt+Enter (and Shift+Enter where the terminal sends it) multiline
   - bracketed paste (?2004h) taken literally, with [paste#N] collapse
   - SIGWINCH live resize with full transcript re-wrap; Esc aborts streams
   - the terminal is restored when a signal or a crash ends the process */

static struct termios saved_t;
static int rows = 24, cols = 80;
static char status[256] = "ready";
static volatile sig_atomic_t raw_on;   /* saved_t holds the mode to restore */
static volatile sig_atomic_t tui_up;   /* escape modes may be on */
static pid_t tui_pid;
static bool working;
static bool mouse_on = true;      /* mouse reporting wanted; toggled by /mouse */
/* one message (collapsed pastes expanded) may hold this much; anything larger
   is refused whole, with a notice in the status bar */
#define INPUT_MAX (1u << 20)
static char *inbuf;               /* grows on demand, NUL-terminated */
static size_t incap;
static int ilen, icur;
static char notice[96];           /* replaces the status bar until the next key */
static volatile sig_atomic_t g_resized = 0;

#define MAXHIST 128

static void handle_key(unsigned char ch, bool busy);
static void drain_queue(void);
static void tui_pump(void);
static char *HIST[MAXHIST];
static int hist_n, hpos = -1;

typedef struct {
    char *text;
    size_t len;
    char tok[48];                 /* what stands for text in the input box */
} Paste;
static Paste *pastes;
static int npastes, cap_pastes;

/* bracketed paste being received */
#define PASTE_END "\033[201~"
#define PASTE_IDLE_S 3.0          /* silence after which a lost end marker is assumed */
static bool pasting, paste_discard, paste_over;
/* a paste stopped without its end marker: later bytes may still be pasted ones,
   so approvals are locked until the marker, Esc or ^C arrives */
static bool paste_suspect;
static char *pbuf;
static size_t plen, pcap;
static char ptail[6];             /* last bytes seen, to find the end marker */
static double plast;

/* message queue for input typed while the agent is busy */
#define QMAX 8
static char *qmsg[QMAX];
static char *qscan[QMAX];         /* the same, as typed: pastes still collapsed */
static int qn;
static bool qheld;                /* one was not sent: the rest wait for the user */
static Images pending;            /* attached, waiting for the next message */
static bool want_exit;

static const struct { const char *cmd, *desc; } SLASH[] = {
    {"/init",   "write .flywheel.md project notes + check engine"},
    {"/clear",  "clear conversation and screen"},
    {"/model",  "show or switch model (/model NAME)"},
    {"/allow",  "list this project's permission rules"},
    {"/status", "engine, model, profile, conversation size"},
    {"/paste",  "attach the clipboard image to the next message"},
    {"/copy",   "copy the last reply to the clipboard"},
    {"/mouse",  "mouse on/off (off: select text natively)"},
    {"/help",   "keys, mouse, and commands"},
    {"/exit",   "quit flywheel"},
    {"/quit",   "quit flywheel"},
    {NULL, NULL}
};

#define MENU_MAX 16               /* room for every slash command */

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
static int slash_menu_off = 0;   /* first command shown when not all fit */

/* active modal menu (approval / multi-choice), NULL when normal input box is shown */
typedef struct {
    const char *title;
    const char *body;         /* e.g. command text, optional */
    const char *prompt;       /* e.g. "Do you want to proceed?" */
    const char **opts;
    int nopts;
    int sel;
    int opt_row_start;        /* 0-based screen row of option 0 (for mouse click) */
    bool approval;            /* every option but the last one grants something */
    int body_scroll, body_vis, body_total, body_w;
    int body_seen;            /* body lines 0..body_seen-1 have been on screen */
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

/* ---------- untrusted text ---------- */

static int utf8_cell_width(const char *s, int max, int *blen);

/* single-line variant into a fixed buffer */
static const char *clean_line_x(char *dst, size_t cap, const char *s, bool strict) {
    char *c = clean_text(s, false, strict);
    for (char *p = c; *p; p++) if (*p == '\n' || *p == '\t') *p = ' ';
    snprintf(dst, cap, "%s", c);
    free(c);
    return dst;
}

static const char *clean_line(char *dst, size_t cap, const char *s) {
    return clean_line_x(dst, cap, s, false);
}

/* bytes of s that fit in width terminal cells */
static int fit_bytes(const char *s, int width) {
    int len = (int)strlen(s), i = 0, w = 0;
    while (i < len) {
        int bl = 0;
        w += utf8_cell_width(s + i, len - i, &bl);
        if (w > width) break;
        i += bl > 0 ? bl : 1;
    }
    return i;
}

static void detect_project_meta(void) {
    const char *base = strrchr(g_cfg.cwd, '/');
    clean_line(g_stat.proj_name, sizeof g_stat.proj_name,
               (base && base[1]) ? base + 1 : g_cfg.cwd);
    g_stat.git_branch[0] = 0;
    char *br = run_bash("git rev-parse --abbrev-ref HEAD 2>/dev/null", g_cfg.cwd, 2);
    if (br) {
        char *nl = strchr(br, '\n');
        if (nl) *nl = 0;
        if (*br && strcmp(br, "HEAD") && strncmp(br, "(no output)", 11) && strncmp(br, "fatal:", 6) &&
            strncmp(br, "error:", 6) && !strstr(br, "exit ")) {
            clean_line(g_stat.git_branch, 61, br);
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

#define MOUSE_ON_SEQ  "\033[?1000h\033[?1006h"
#define MOUSE_OFF_SEQ "\033[?1006l\033[?1000l"

/* the modifier that makes the terminal select text while it reports the mouse */
static const char *select_key(void) {
    const char *t = getenv("TERM_PROGRAM");
    if (t && !strcmp(t, "Apple_Terminal")) return "Fn";
    if (t && !strcmp(t, "iTerm.app")) return "Option";
    return "Shift (iTerm2: Option, Terminal: Fn)";
}

static void term_raw(bool on) {
    if (on && !raw_on) {
        tcgetattr(0, &saved_t);
        struct termios t = saved_t;
        t.c_lflag &= ~(ICANON | ECHO | ISIG | IEXTEN);
        t.c_iflag &= ~(IXON | ICRNL);
        t.c_cc[VMIN] = 0; t.c_cc[VTIME] = 1;
        raw_on = true;   /* before the change: a signal from here on must undo it */
        tcsetattr(0, TCSANOW, &t);
        /* bracketed paste + SGR click/wheel mouse reporting */
        fputs("\033[?2004h", stdout);
        if (mouse_on) fputs(MOUSE_ON_SEQ, stdout);
        fflush(stdout);
    } else if (!on && raw_on) {
        fputs(MOUSE_OFF_SEQ "\033[?2004l", stdout);
        fflush(stdout);
        tcsetattr(0, TCSANOW, &saved_t);
        raw_on = false;
    }
}

/* CAN drops a half-written sequence; then sync, link, colors, mouse, paste,
   alternate screen and hidden cursor (a command writing to /dev/tty can leave
   those), scroll region, and the cursor to the last row. A pty nobody reads
   must not keep us alive: never block, and give up after half a second. */
static void modes_off(void) {
    static const char off[] = "\030\033[?2026l\033]8;;\033\\\033[0m" MOUSE_OFF_SEQ
                              "\033[?2004l\033[?1047l\033[?25h\033[r\033[999;1H\n";
    int fl = fcntl(1, F_GETFL);
    if (fl < 0) return;
    fcntl(1, F_SETFL, fl | O_NONBLOCK);
    size_t at = 0;
    for (int stalls = 0; at < sizeof off - 1 && stalls < 10;) {
        ssize_t w = write(1, off + at, sizeof off - 1 - at);
        if (w > 0) { at += (size_t)w; continue; }
        stalls++;
        struct pollfd p = {.fd = 1, .events = POLLOUT};
        poll(&p, 1, 50);
    }
    fcntl(1, F_SETFL, fl);   /* the shell shares this open file */
}

/* A fatal signal: turn every mode off, then die of the same signal. Only
   async-signal-safe calls (proc_listchildpids is a bare system call). */
static void on_fatal(int sig) {
    if (getpid() == tui_pid) {   /* not a forked child that has not exec'd yet */
#ifdef __APPLE__
        if (sig == SIGTERM || sig == SIGHUP) {
            /* each tool command leads its own group, so it would outlive us */
            pid_t kid[64] = {0};
            proc_listchildpids(tui_pid, kid, sizeof kid);
            for (size_t i = 0; i < sizeof kid / sizeof *kid; i++)
                if (kid[i] > 1 && getpgid(kid[i]) == kid[i]) killpg(kid[i], SIGKILL);
        }
#endif
        /* In the background the terminal is someone else's by now. An error
           (a dead or foreign tty) restores anyway. */
        pid_t fg = tcgetpgrp(0);
        if (fg < 0 || fg == getpgrp()) {
            if (raw_on) tcsetattr(0, TCSANOW, &saved_t);
            if (tui_up) modes_off();
        }
    }
    signal(sig, SIG_DFL);   /* macOS ignores SA_RESETHAND for SIGILL */
    raise(sig);             /* SA_NODEFER: the default action, now */
    _exit(128 + sig);
}

static void catch_fatal(void) {
    static const int sigs[] = {SIGTERM, SIGHUP, SIGQUIT, SIGSEGV, SIGBUS, SIGABRT, SIGFPE, SIGILL};
    static char stack[1 << 16];   /* a stack overflow leaves no room on the normal one */
    stack_t ss = {.ss_sp = stack, .ss_size = sizeof stack};
    sigaltstack(&ss, NULL);
    struct sigaction sa = {0};
    sa.sa_handler = on_fatal;
    sa.sa_flags = SA_RESETHAND | SA_NODEFER | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGTTOU);   /* tcsetattr from the background must not stop us */
    tui_pid = getpid();
    tui_up = 1;
    for (size_t i = 0; i < sizeof sigs / sizeof *sigs; i++) {
        struct sigaction old;
        if (sigaction(sigs[i], NULL, &old) == 0 && old.sa_handler != SIG_IGN)   /* keep nohup */
            sigaction(sigs[i], &sa, NULL);
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
        if (inbuf[i] == '\t') cw = 1;   /* drawn as one space */
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
    const char *m[MENU_MAX];
    return menu_matches(m, MENU_MAX);
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
    const char *link = NULL;   /* OSC 8 opener still open at the end of a row */
    size_t link_len = 0;
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
        if (link && lw + link_len + 16 < lcap - 64) {
            memcpy(line + lw, link, link_len); lw += link_len;
            lw += (size_t)snprintf(line + lw, lcap - lw, "\033[4m" CYAN);
            had_esc = true;
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
                if (lw + el < lcap - 64) {
                    memcpy(line + lw, s0, el); lw += el;
                    if (el > 5 && !memcmp(s0, "\033]8;", 4)) {
                        const char *u = memchr(s0 + 4, ';', el - 4);
                        bool opens = u && u[1] != '\033' && u[1] != '\007';
                        link = opens ? s0 : NULL;
                        link_len = opens ? el : 0;
                    }
                }
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
            int cw = utf8_cell_width(p, (int)strnlen(p, 8), &bl);   /* strlen here is quadratic */
            if (bl <= 0) { p++; continue; }
            if (col + cw > maxw && col > (pfx ? pc_w : 0)) break;
            if (lw + (size_t)bl < lcap - 64) { memcpy(line + lw, p, (size_t)bl); lw += (size_t)bl; }
            col += cw;
            p += bl;
        }
        if (link)   /* close now, reopen on the continuation row */
            lw += (size_t)snprintf(line + lw, lcap - lw, "\033]8;;\033\\\033[24m\033[39m");
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
            if (*p) md_cat(&row, "\033]8;;\033\\" RESET);   /* cut inside a link */
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
                    if ((int)llen > rule_w - 8) llen = (size_t)(rule_w > 8 ? rule_w - 8 : 0);
                    while (llen > 0 && ((unsigned char)lang[llen] & 0xC0) == 0x80) llen--;
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

static void build_item(VBuf *vb, const TItem *it, int i) {
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

            if (!it->out) return;
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
                    snprintf(hint, sizeof hint, "     " DIM "… +%d line%s (%s^O to expand)" RESET,
                             hidden, hidden == 1 ? "" : "s", mouse_on ? "click or " : "");
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
                    snprintf(hint, sizeof hint, "     " DIM "… truncated (%s^O to collapse)" RESET,
                             mouse_on ? "click or " : "");
                else
                    snprintf(hint, sizeof hint, "     " DIM "▴ %s^O to collapse" RESET,
                             mouse_on ? "click or " : "");
                vb_push(vb, hint, i);
            }
        }
}

static void build_transcript(VBuf *vb) {
    for (int i = 0; i < nitems; i++) {
        TItem v = items[i];
        if (v.kind == T_RAW) { build_item(vb, &v, i); continue; }
        v.text = clean_text(items[i].text, true, false);
        v.out = items[i].out ? clean_text(items[i].out, true, false) : NULL;
        build_item(vb, &v, i);
        free(v.text);
        free(v.out);
    }
}

/* Wrap the whole (already sanitized) modal body to width cells; nothing is cut. */
static void wrap_modal_body(VBuf *vb, const char *body, int width) {
    MdBuf row = {0};
    md_catn(&row, "", 0);
    int col = 0, len = (int)strlen(body);
    for (int i = 0; i < len;) {
        if (body[i] == '\n') {
            vb_push(vb, row.b, -1);
            row.n = 0; row.b[0] = 0; col = 0; i++;
            continue;
        }
        int bl = 1, cw = 1;
        if (body[i] != '\t') cw = utf8_cell_width(body + i, len - i, &bl);
        if (bl <= 0) bl = 1;
        if (col + cw > width && col > 0) {
            vb_push(vb, row.b, -1);
            row.n = 0; row.b[0] = 0; col = 0;
        }
        md_catn(&row, body[i] == '\t' ? " " : body + i, (size_t)bl);
        col += cw; i += bl;
    }
    if (row.n) vb_push(vb, row.b, -1);
    free(row.b);
}

/* lines of an approval body that were never on screen */
static int modal_unseen(const Modal *m) { return m->body_total - m->body_seen; }

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

/* Leads the bottom row in every state while commands run unsandboxed
   (--unsafe or no working sandbox). Returns the columns it took. */
static int draw_sandbox_badge(void) {
    if (sandbox_on()) return 0;
    static const char badge[] = " NOT SANDBOXED ";
    int n = fit_bytes(badge, cols - 1);
    printf(RED BOLD "\033[7m%.*s" RESET, n, badge);
    if (n >= cols - 1) return n;
    putchar(' ');
    return n + 1;
}

static void draw_status_bar(void) {
    char scroll_tag[64] = "";
    if (scroll_off > 0) snprintf(scroll_tag, sizeof scroll_tag, " · ↑%d lines · End to jump", scroll_off);
    char qtag[32] = "";
    if (qn > 0) snprintf(qtag, sizeof qtag, " · ⎿%d queued", qn);

    /* no autowrap: an overlong bar on the last row would scroll the screen */
    printf("\033[%d;1H" CLR_LINE "\033[?7l", rows);
    int used = draw_sandbox_badge();
    int room = cols - used;       /* columns left for the bar */
    if (notice[0]) {
        printf(YELLOW "%.*s" RESET "\033[?7h", fit_bytes(notice, room - 1), notice);
        return;
    }
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
        fputs("\033[?7h", stdout);
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
    if (room >= 64 && g_stat.last_ptoks > 0) {
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
    if (g_stat.sess_turns > 0 && room >= 72) {
        char tb[24];
        fmt_toks(g_stat.sess_toks, tb, sizeof tb);
        if (g_stat.last_tps >= 1.0)
            snprintf(stats, sizeof stats, DIM " · %dt · %s tok · " RESET YELLOW "⚡ %.0f tok/s" RESET,
                     g_stat.sess_turns, tb, g_stat.last_tps);
        else
            snprintf(stats, sizeof stats, DIM " · %dt · %s tok" RESET, g_stat.sess_turns, tb);
    }

    const char *hint = (room >= 92 && !scroll_tag[0]) ? (DIM " · ^O cmds · /help" RESET) : "";
    printf(GREEN "●" RESET " " DIM "%s" RESET "%s%s" DIM "%s%s" RESET "%s\033[?7h",
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
    VBuf mb = {0};
    int modal_blank = 0;

    if (active_modal) {
        Modal *m = active_modal;
        if (m->body && *m->body) {
            char *body = clean_text(m->body, false, true);
            wrap_modal_body(&mb, body, inner_w);
            free(body);
        }
        if (m->body_w != inner_w) { m->body_w = inner_w; m->body_scroll = m->body_seen = 0; }
        int fixed = 2 /*borders*/ + 1 /*prompt*/ + m->nopts + 1 /*status*/;
        int vis_b = rows - fixed;
        if (vis_b > mb.n) vis_b = mb.n;
        if (vis_b < 0) vis_b = 0;
        m->body_vis = vis_b;
        m->body_total = mb.n;
        if (m->body_scroll > mb.n - vis_b) m->body_scroll = mb.n - vis_b;
        if (m->body_scroll < 0) m->body_scroll = 0;
        modal_blank = mb.n > 0 && rows - fixed > vis_b;
        ch = fixed + vis_b + modal_blank;
        /* count lines as seen only if the real terminal can hold the modal */
        struct winsize ws;
        bool fits = ioctl(1, TIOCGWINSZ, &ws) != 0 || (ws.ws_row >= fixed + vis_b && ws.ws_col >= cols);
        if (fits && m->body_scroll <= m->body_seen && m->body_scroll + vis_b > m->body_seen)
            m->body_seen = m->body_scroll + vis_b;
    } else {
        nv = layout_input(vl, MAX_VLINES, inner_w, &cur_vl, &cur_col);
        vis = nv > 4 ? 4 : nv;
        if (cur_vl >= vis) vstart = cur_vl - vis + 1;
        if (vstart + vis > nv) vstart = nv - vis;
        if (vstart < 0) vstart = 0;
        mc = menu_count();
        ch = vis + 2 + mc + 1;
        if (ch > rows - 2) {      /* short window: show what fits */
            mc -= ch - (rows - 2);
            if (mc < 0) mc = 0;
            ch = vis + 3 + mc;
        }
        /* the selection runs over every match; the visible rows follow it */
        int total = menu_count();
        if (menu_sel >= total) menu_sel = total > 0 ? total - 1 : 0;
        if (mc == 0) menu_sel = 0;
        if (menu_sel < slash_menu_off) slash_menu_off = menu_sel;
        if (menu_sel >= slash_menu_off + mc) slash_menu_off = menu_sel - mc + 1;
        if (slash_menu_off > total - mc) slash_menu_off = total - mc;
        if (slash_menu_off < 0 || mc == 0) slash_menu_off = 0;
    }

    int view_h = rows - ch;
    if (view_h < 1) view_h = active_modal ? 0 : 1;

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

        for (int bi = 0; bi < m->body_vis; bi++, r++)
            printf("\033[%d;1H" CLR_LINE YELLOW "│" RESET " " BOLD "%s" RESET "\033[%d;%dH" YELLOW "│" RESET,
                   r, mb.v[m->body_scroll + bi].s, r, cols);
        if (modal_blank) {
            printf("\033[%d;1H" CLR_LINE YELLOW "│" RESET "\033[%d;%dH" YELLOW "│" RESET, r, r, cols);
            r++;
        }

        char line[4096];
        clean_line_x(line, sizeof line, m->prompt, true);
        printf("\033[%d;1H" CLR_LINE YELLOW "│" RESET " %.*s\033[%d;%dH" YELLOW "│" RESET,
               r, fit_bytes(line, inner_w), line, r, cols);
        r++;

        m->opt_row_start = r - 1;   /* 0-based screen row of option 0 */
        for (int i = 0; i < m->nopts; i++, r++) {
            int omax = inner_w - 6;
            if (omax < 10) omax = 10;
            clean_line_x(line, sizeof line, m->opts[i], true);
            if (i == m->sel)
                printf("\033[%d;1H" CLR_LINE YELLOW "│" RESET " " CYAN BOLD "▸ %d. %.*s" RESET "\033[%d;%dH" YELLOW "│" RESET,
                       r, i + 1, fit_bytes(line, omax), line, r, cols);
            else
                printf("\033[%d;1H" CLR_LINE YELLOW "│" RESET "   " DIM "%d. " RESET "%.*s\033[%d;%dH" YELLOW "│" RESET,
                       r, i + 1, fit_bytes(line, omax), line, r, cols);
        }

        printf("\033[%d;1H" CLR_LINE YELLOW "╰", r++);
        for (int i = 0; i < box_w; i++) fputs("─", stdout);
        fputs("╯" RESET, stdout);

        int below = m->body_total - m->body_scroll - m->body_vis;
        if (m->body_total > m->body_vis) {
            if (m->approval && modal_unseen(m) > 0)
                snprintf(line, sizeof line, " ▲%d ▼%d lines hidden · PgDn/Space%s · view all to allow",
                         m->body_scroll, below, mouse_on ? "/wheel" : "");
            else
                snprintf(line, sizeof line, " ▲%d ▼%d lines hidden · PgUp/PgDn · Enter · Esc cancel",
                         m->body_scroll, below);
        } else {
            snprintf(line, sizeof line, " ↑↓ choose · Enter/1-%d%s · Esc cancel", m->nopts,
                     mouse_on ? " or click" : "");
        }
        if (m->approval && paste_suspect)
            snprintf(line, sizeof line, " paste interrupted: Esc to deny");
        printf("\033[%d;1H" CLR_LINE, rows);
        int used = draw_sandbox_badge();
        printf(DIM "%.*s" RESET, fit_bytes(line, cols - 1 - used), line);
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
            for (int k = 0; k < l->len; k++)
                putchar(inbuf[l->start + k] == '\t' ? ' ' : inbuf[l->start + k]);
            printf("\033[%d;%dH" DIM "│" RESET, r, cols);
        }

        /* Input box bottom border */
        printf("\033[%d;1H" CLR_LINE, r++);
        draw_hline("╰", "╯", box_w);

        /* Slash menu below input box */
        if (mc > 0) {
            const char *m[MENU_MAX];
            int nm = menu_matches(m, MENU_MAX);
            slash_menu_top = r - 1;   /* 0-based */
            slash_menu_cnt = mc < nm ? mc : nm;
            for (int i = slash_menu_off; i < slash_menu_off + slash_menu_cnt; i++, r++) {
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
    vb_free(&mb);
}

static void set_status(const char *s) { clean_line(status, sizeof status, s); }

/* ---------- input buffer & paste ---------- */

static void set_notice(const char *s) { snprintf(notice, sizeof notice, "%s", s); }

/* make room for n bytes plus the NUL */
static bool in_reserve(size_t n) {
    if (n < incap) return true;
    size_t nc = incap ? incap : 1024;
    while (nc <= n) nc *= 2;
    char *p = realloc(inbuf, nc);
    if (!p) return false;
    if (!incap) p[0] = 0;
    inbuf = p;
    incap = nc;
    return true;
}

static bool ins(const char *s, int n) {
    if ((size_t)ilen + (size_t)n > INPUT_MAX || !in_reserve((size_t)ilen + (size_t)n)) {
        set_notice("input over 1 MB refused");
        return false;
    }
    memmove(inbuf + icur + n, inbuf + icur, (size_t)(ilen - icur));
    memcpy(inbuf + icur, s, (size_t)n);
    icur += n; ilen += n;
    inbuf[ilen] = 0;
    menu_dismissed = false;
    return true;
}

static void in_set(const char *s) {
    ilen = icur = 0;
    inbuf[0] = 0;
    ins(s, (int)strlen(s));
}

static void in_delete(int from, int to) {
    memmove(inbuf + from, inbuf + to, (size_t)(ilen - to));
    ilen -= to - from;
    icur = from;
    inbuf[ilen] = 0;
}

/* collapsed paste whose token starts at s (len bytes available), or -1 */
static int paste_at(const char *s, size_t len) {
    if (len == 0 || *s != '[') return -1;
    for (int i = 0; i < npastes; i++) {
        size_t tl = strlen(pastes[i].tok);
        if (tl <= len && !memcmp(s, pastes[i].tok, tl)) return i;
    }
    return -1;
}

/* start of the token that pos is strictly inside of, else pos */
static int token_start(int pos) {
    for (int i = pos - 1; i >= 0 && i > pos - (int)sizeof pastes->tok; i--) {
        int k = paste_at(inbuf + i, (size_t)(ilen - i));
        if (k >= 0 && i + (int)strlen(pastes[k].tok) > pos) return i;
    }
    return pos;
}

/* cursor steps: a token counts as one character */
static int in_prev(int pos) { return token_start(utf8_prev(inbuf, pos)); }
static int in_next(int pos) {
    int k = paste_at(inbuf + pos, (size_t)(ilen - pos));
    return k >= 0 ? pos + (int)strlen(pastes[k].tok) : utf8_next(inbuf, ilen, pos);
}

/* length of s with every token replaced by its text; writes it to out if given */
static size_t expand_into(char *out, const char *s) {
    size_t w = 0, len = strlen(s);
    for (size_t r = 0; r < len;) {
        int k = paste_at(s + r, len - r);
        if (k >= 0) {
            if (out) memcpy(out + w, pastes[k].text, pastes[k].len);
            w += pastes[k].len;
            r += strlen(pastes[k].tok);
        } else {
            if (out) out[w] = s[r];
            w++; r++;
        }
    }
    if (out) out[w] = 0;
    return w;
}

/* the message as the model gets it; NULL if it does not fit */
static char *expand_pastes(const char *s) {
    size_t n = expand_into(NULL, s);
    char *out = n <= INPUT_MAX ? malloc(n + 1) : NULL;
    if (out) expand_into(out, s);
    return out;
}

/* keep text, newlines and tabs; CR/CRLF become newlines; other control bytes
   and escape sequences are removed without touching what follows them */
static size_t paste_sanitize(char *b, size_t n) {
    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)b[i];
        unsigned char d = i + 1 < n ? (unsigned char)b[i + 1] : 0;
        if (c == '\r') {
            b[w++] = '\n';
            if (d == '\n') i++;
        } else if (c == 27) {
            if (d != '[') continue;
            size_t j = i + 2;
            while (j < n && b[j] >= 0x20 && b[j] <= 0x3F) j++;
            if (j < n && b[j] >= 0x40 && b[j] <= 0x7E) i = j;   /* complete CSI */
        } else if (c == 0xC2 && d >= 0x80 && d <= 0x9F) {
            i++;                                                /* C1 control */
        } else if ((c >= 32 && c != 127) || c == '\n' || c == '\t') {
            b[w++] = (char)c;
        }
    }
    return w;
}

/* put a finished paste into the input box, collapsed when it is big */
static void paste_insert(const char *text, size_t n) {
    if (expand_into(NULL, inbuf) + n > INPUT_MAX) {
        set_notice("paste refused: message would be over 1 MB");
        return;
    }
    size_t lines = 1;
    for (size_t i = 0; i < n; i++) if (text[i] == '\n') lines++;
    if (lines == 1 && n < 200) { ins(text, (int)n); return; }
    if (npastes == cap_pastes) {
        int nc = cap_pastes ? cap_pastes * 2 : 8;
        Paste *np = realloc(pastes, (size_t)nc * sizeof *np);
        if (!np) { set_notice("paste refused: out of memory"); return; }
        pastes = np;
        cap_pastes = nc;
    }
    Paste *e = &pastes[npastes];
    e->text = str_ndup(text, n);
    if (!e->text) { set_notice("paste refused: out of memory"); return; }
    e->len = n;
    snprintf(e->tok, sizeof e->tok, "[paste#%d +%zu lines]", npastes + 1, lines);
    if (ins(e->tok, (int)strlen(e->tok))) npastes++;
    else free(e->text);
}

/* discard: swallow the paste (a menu is open) */
static void paste_begin(bool discard) {
    pasting = true;
    paste_discard = discard;
    paste_over = false;
    plen = 0;
    memset(ptail, 0, sizeof ptail);
    plast = mono_now();
}

static void paste_finish(bool lost_end) {
    pasting = false;
    if (lost_end) paste_suspect = true;
    if (!paste_discard) {
        if (paste_over) set_notice("paste over 1 MB refused");
        else {
            size_t n = paste_sanitize(pbuf, plen);
            if (n) paste_insert(pbuf, n);
            if (lost_end && !notice[0]) set_notice("paste end marker missing: kept what arrived");
        }
        menu_sel = 0;
    }
    free(pbuf);
    pbuf = NULL;
    plen = pcap = 0;
    render_screen();
}

static void paste_feed(unsigned char ch) {
    plast = mono_now();
    memmove(ptail, ptail + 1, sizeof ptail - 1);
    ptail[sizeof ptail - 1] = (char)ch;
    if (!paste_discard && !paste_over) {
        if (plen == pcap) {
            size_t nc = pcap ? pcap * 2 : 4096;
            char *nb = plen < INPUT_MAX + sizeof ptail ? realloc(pbuf, nc) : NULL;
            if (nb) { pbuf = nb; pcap = nc; }
            else paste_over = true;
        }
        if (plen >= INPUT_MAX + sizeof ptail) paste_over = true;
        if (!paste_over) pbuf[plen++] = (char)ch;
    }
    if (!memcmp(ptail, PASTE_END, sizeof ptail)) {
        if (!paste_over && !paste_discard) plen -= sizeof ptail;
        paste_finish(false);
    }
}

/* call when no input is pending: an unterminated paste must not wedge the UI */
static void paste_tick(void) {
    if (pasting && mono_now() - plast > PASTE_IDLE_S) paste_finish(true);
}

static void queue_clear(void) {
    for (int i = 0; i < qn; i++) { free(qmsg[i]); free(qscan[i]); }
    qn = 0;
    qheld = false;
}

/* a pasted block that starts with '/' is a message, not a command */
static bool is_slash(const char *s) { return s[0] == '/' && !strchr(s, '\n'); }

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
    static int press_x, press_y;
    if (term != 'M') {
        /* a left drag is an attempt to select text, which reporting swallows */
        if (btn == 0 && (mx != press_x || my != press_y)) {
            char b[sizeof notice];
            snprintf(b, sizeof b, "to select: hold %s and drag, or /mouse", select_key());
            set_notice(b);
            render_screen();
        }
        return true;
    }
    if (btn == 0) { press_x = mx; press_y = my; }
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

/* a key that followed a lone Esc too late to be part of it */
static int esc_late = -1;

/* Collect one escape sequence after reading initial ESC (27). */
static int read_esc_seq(unsigned char *buf, int cap) {
    int n = 0;
    buf[n++] = 27;
    unsigned char c2;
    bool slow = false;
    esc_late = -1;
    while (n < cap - 1) {
        fd_set ef;
        FD_ZERO(&ef);
        FD_SET(0, &ef);
        /* a paste marker may arrive in pieces; do not give up on it early */
        bool marker = n >= 2 && n < 6 && !memcmp(buf, "\033[200~", (size_t)n);
        struct timeval etv = {.tv_sec = 0, .tv_usec = marker ? 500000 : 25000};
        int ready = select(1, &ef, NULL, NULL, &etv);
        if (ready == 0 && n == 1) {
            /* the '[' of a split marker may still be on its way */
            slow = true;
            FD_SET(0, &ef);
            etv = (struct timeval){.tv_sec = 0, .tv_usec = 75000};
            ready = select(1, &ef, NULL, NULL, &etv);
        }
        if (ready <= 0) break;
        if (read(0, &c2, 1) != 1) break;
        if (slow && n == 1 && c2 != '[') { esc_late = c2; break; }
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

/* drop what was typed ahead of an approval; a paste in it is tracked to its end
   so the rest of it cannot answer */
static void drain_typeahead(void) {
    for (;;) {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(0, &rf);
        struct timeval tv = {0, 0};
        unsigned char ch, eb[32];
        if (select(1, &rf, NULL, NULL, &tv) <= 0 || read(0, &ch, 1) != 1) return;
        if (pasting) paste_feed(ch);
        else if (ch == 27 && read_esc_seq(eb, sizeof eb) == 6) {
            if (!memcmp(eb, "\033[200~", 6)) paste_begin(true);
            else if (!memcmp(eb, PASTE_END, 6)) paste_suspect = false;
        }
    }
}

static void modal_scroll(Modal *m, int delta) {
    m->body_scroll += delta;   /* render_screen clamps */
    render_screen();
}

#define MODAL_GUARD_S 0.5

/* Reusable Claude-Code-style modal menu: returns chosen index 0..nopts-1, or -1 on Esc/cancel.
   approval=true: the last option (No) is preselected, input typed ahead or arriving
   just after opening is dropped, and the other options stay locked until the
   whole body has been on screen. */
static int tui_choose_menu(const char *title, const char *body, const char *prompt,
                           const char **opts, int nopts, const char *shortcuts, bool approval) {
    Modal m = {
        .title = title, .body = body, .prompt = prompt,
        .opts = opts, .nopts = nopts, .sel = approval ? nopts - 1 : 0, .opt_row_start = -1,
        .approval = approval
    };
    active_modal = &m;
    render_screen();
    if (approval) drain_typeahead();
    double opened = mono_now();

    int result = -1;
    for (;;) {
        if (g_resized) { g_resized = 0; render_screen(); }
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(0, &rf);
        struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};
        bool was_pasting = pasting;
        if (select(1, &rf, NULL, NULL, &tv) <= 0) {
            paste_tick();
            if (was_pasting && !pasting) opened = mono_now();
            continue;
        }

        unsigned char ch = 0;
        if (read(0, &ch, 1) != 1) continue;
        if (pasting) {   /* pasted text never answers a menu */
            paste_feed(ch);
            /* the marker may be part of the text: guard what follows it */
            if (!pasting) opened = mono_now();
            continue;
        }
        bool guard = approval && mono_now() - opened < MODAL_GUARD_S;
        if (guard) opened = mono_now();   /* approving takes this long without input */
        bool overflow = m.body_total > m.body_vis;
        int page = m.body_vis > 0 ? m.body_vis : 1;   /* never skips a line */
        int pick = -1;

        if (ch == 27) {
            unsigned char eb[32];
            int en = read_esc_seq(eb, sizeof eb);
            if (en == 1) { paste_suspect = false; result = -1; break; }
            if (en >= 6 && !memcmp(eb, PASTE_END, 6)) {
                paste_suspect = false;
                opened = mono_now();
                render_screen();
                continue;
            }
            if (en >= 6 && !memcmp(eb, "\033[200~", 6)) { paste_begin(true); continue; }
            if (overflow && en >= 6 && eb[1] == '[' && eb[2] == '<') {
                int btn = atoi((const char *)eb + 3);
                if (btn == 64 || btn == 65) {
                    int step = page < 3 ? page : 3;
                    modal_scroll(&m, btn == 64 ? -step : step);
                    continue;
                }
            }
            int clicked = -1;
            if (handle_mouse_seq(eb, en, &clicked)) {
                if (!guard && clicked >= m.opt_row_start && clicked < m.opt_row_start + m.nopts)
                    pick = clicked - m.opt_row_start;
            } else if (eb[1] == '[' || eb[1] == 'O') {
                char k = (char)eb[en - 1];
                bool pgup = k == '~' && en >= 3 && eb[2] == '5';
                bool pgdn = k == '~' && en >= 3 && eb[2] == '6';
                if (pgup || pgdn) {
                    if (overflow) modal_scroll(&m, pgup ? -page : page);
                    else { scroll_off += pgup ? 8 : -8; render_screen(); }
                }
                else if (guard) continue;
                else if (k == 'A') { m.sel = (m.sel > 0) ? m.sel - 1 : m.nopts - 1; render_screen(); }
                else if (k == 'B') { m.sel = (m.sel + 1) % m.nopts; render_screen(); }
            }
            if (pick < 0) continue;
        } else {
            if (ch == 3) { paste_suspect = false; result = -1; break; }   /* ^C cancels */
            if (ch == 15) { toggle_tool(-1); continue; }       /* ^O toggles last command */
            if (ch == ' ' && overflow) { modal_scroll(&m, page); continue; }
            if (guard) continue;
            if (ch == '\r' || ch == '\n') pick = m.sel;
            else if (ch >= '1' && ch < '1' + nopts) pick = ch - '1';
            else if (shortcuts) {
                for (int i = 0; i < nopts && shortcuts[i]; i++) {
                    if (ch == (unsigned char)shortcuts[i] ||
                        (shortcuts[i] >= 'a' && shortcuts[i] <= 'z' && ch == (unsigned char)(shortcuts[i] - 32))) {
                        pick = i;
                        break;
                    }
                }
            }
            if (pick < 0) continue;
        }
        if (approval && pick < nopts - 1 && (paste_suspect || modal_unseen(&m) > 0)) continue;
        result = pick;
        break;
    }
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
        char *c = clean_text(out, true, false);
        item_append(r, c);
        free(c);
    }
    render_screen();
}

static void ui_status(const char *s, void *ud) { (void)ud; set_status(s); render_screen(); }

static void ui_event(const char *kind, const char *detail, void *ud) {
    (void)ud;
    char b[512], safe_kind[64], safe_detail[480];
    kind = clean_line(safe_kind, sizeof safe_kind, kind);
    detail = clean_line(safe_detail, sizeof safe_detail, detail);
    if (!strcmp(kind, "prune")) snprintf(b, sizeof b, YELLOW "  ✂ loop pruned (%s)" RESET, detail);
    else if (!strcmp(kind, "reset")) snprintf(b, sizeof b, YELLOW "  ↺ context reset (%s)" RESET, detail);
    else if (!strcmp(kind, "gate")) snprintf(b, sizeof b, BLUE "  ○ %s" RESET, detail);
    else snprintf(b, sizeof b, "  %s %s", kind, detail);
    TItem *r = item_new(T_RAW);
    item_append(r, b);
    render_screen();
}

/* Would an "always" rule silence this prompt next time? Ask perm_allowed itself
   (it always prompts for shell metacharacters and mutating flags) with the rule
   added in memory only: without a cwd nothing is persisted. */
static bool can_remember(const char *cmd, const char *rule, bool gate) {
    if (!rule || !*rule) return false;
    perm_load();
    char *cwd = g_cfg.cwd;
    g_cfg.cwd = NULL;
    perm_add_rule(rule);
    g_cfg.cwd = cwd;
    bool ok = gate ? perm_gate_allowed(cmd) : perm_allowed(cmd);
    perm_free();              /* drop the probe; the next check reloads from disk */
    return ok;
}

/* agent.c puts this line ahead of a command that asks for the network. A
   command that merely starts with it gets the same, more cautious, prompt. */
#define NET_ASK_HEAD "# allow NETWORK access for this one command\n"

/* Claude-Code-style approval modal menu. */
static bool ui_approve(const char *cmd, bool gate, void *ud) {
    (void)ud;
    bool net = !gate && !strncmp(cmd, NET_ASK_HEAD, sizeof NET_ASK_HEAD - 1);
    /* OSC 9 notification for Mica attention indicator */
    printf("\033]9;flywheel: %s approval needed\007", net ? "network access" : "command");
    fflush(stdout);

    char *rule;
    if (gate) {   /* the whole command: nothing broader than what is shown */
        size_t len = strlen(GATE_PERM) + strlen(cmd) + 1;
        rule = malloc(len);
        snprintf(rule, len, "%s%s", GATE_PERM, cmd);
    } else rule = perm_prefix(cmd);
    bool remember = can_remember(cmd, rule, gate);
    char opt2[256];
    if (gate) snprintf(opt2, sizeof opt2, "Yes, and don't ask again for exactly this check");
    else snprintf(opt2, sizeof opt2, "Yes, and don't ask again for `%s` commands", rule ? rule : cmd);
    const char *opts[3];
    int n = 0;
    opts[n++] = "Yes";
    if (remember) opts[n++] = opt2;
    opts[n++] = "No";
    const char *title = gate ? "⚠ Project check (runs project code)"
                      : net ? "⚠ Network access request" : "⚠ Bash command";
    int pick = tui_choose_menu(title, net ? cmd + sizeof NET_ASK_HEAD - 1 : cmd,
                               net ? "Allow external network access for this command?"
                                   : "Do you want to proceed?", opts, n,
                               remember ? "yan" : "yn", true);
    if (pick == 0) {
        set_status("approved once");
        free(rule);
        return true;
    }
    if (remember && pick == 1) {
        perm_add_rule(rule);
        char b[300];
        snprintf(b, sizeof b, "always allowed: %s", rule);
        set_status(b);
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
    Images *att = &g_msgs->v[g_msgs->n - 1].images;
    *att = pending;
    pending = (Images){0};
    for (int i = 0; i < att->n; i++) {
        const char *src = att->v[i].source, *base = strrchr(src, '/');
        char b[400], name[256];
        snprintf(b, sizeof b, DIM "  image: %s · %zu KB" RESET,
                 clean_line(name, sizeof name, !strstr(src, "://") && base ? base + 1 : src),
                 (att->v[i].size + 1023) / 1024);
        item_append(item_new(T_RAW), b);
    }
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
        if (g_stat.last_final.check_skipped)
            snprintf(extras + strlen(extras), sizeof extras - strlen(extras),
                     " · " YELLOW "check not run" RESET);
        snprintf(done, sizeof done,
                 GREEN "✓ done" RESET DIM " · %d turn%s · %d bash · %s tok" RESET "%s%s" DIM " · %.1fs" RESET,
                 g_stat.last_final.turns, g_stat.last_final.turns == 1 ? "" : "s",
                 g_stat.last_final.calls, tb, tps_s, extras, wall_dt);
    } else {
        char why[200];
        snprintf(done, sizeof done, YELLOW "✗ %s" RESET DIM " · %.1fs" RESET,
                 clean_line(why, sizeof why, fin), wall_dt);
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

static void push_raw(const char *s) {
    TItem *r = item_new(T_RAW);
    item_append(r, s);
    render_screen();
}

/* ---------- /copy ---------- */

/* longest text sent by OSC 52: about 100,000 base64 bytes, a common terminal limit */
#define OSC52_MAX 74994
#define PBCOPY_TIMEOUT_S 5.0

/* bytes of the England, Scotland or Wales flag at p (U+1F3F4, tag letters,
   U+E007F), else 0: the only tag characters that are not hidden text */
static int flag_len(const unsigned char *p) {
    static const char *const FLAGS[] = {"gbeng", "gbsct", "gbwls"};
    for (size_t f = 0; f < sizeof FLAGS / sizeof *FLAGS; f++) {
        unsigned char seq[32] = {0xF0, 0x9F, 0x8F, 0xB4};
        int n = 4;
        for (const char *t = FLAGS[f]; *t; t++) {
            seq[n++] = 0xF3; seq[n++] = 0xA0; seq[n++] = 0x81; seq[n++] = (unsigned char)(0x80 + (*t - 0x40));
        }
        seq[n++] = 0xF3; seq[n++] = 0xA0; seq[n++] = 0x81; seq[n++] = 0xBF;
        if (!strncmp((const char *)p, (const char *)seq, (size_t)n)) return n;
    }
    return 0;
}

/* Malloc'd copy of s safe to paste anywhere: escape sequences, control
   characters (all but newline and tab), invalid UTF-8, bidi/zero-width and tag
   characters are removed, as are surrounding blank lines. */
static char *plain_text(const char *s) {
    size_t o = 0;
    char *d = malloc(strlen(s) + 1);
    if (!d) return NULL;
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        unsigned char c = *p;
        if (c == 27) {
            const unsigned char *q = p + 1;
            if (*q == '[') {                              /* CSI */
                q++;
                while (*q >= 0x20 && *q <= 0x3F) q++;
                if (*q >= 0x40 && *q <= 0x7E) q++;
            } else if (*q && strchr("]P_^X", *q)) {       /* string up to BEL or ST */
                const unsigned char *e = q + 1;
                while (*e && *e != 7 && *e != 27 && *e != '\n') e++;
                if (*e == 7) q = e + 1;
                else if (*e == 27 && e[1] == '\\') q = e + 2;
                else q++;                                 /* unterminated: keep the text */
            }   /* anything else: drop only ESC, as what follows may matter */
            p = q;
            continue;
        }
        if (c < 0x80) {
            if (c == '\n' || c == '\t' || (c >= 0x20 && c != 0x7F)) d[o++] = (char)c;
            p++;
            continue;
        }
        int len = c >= 0xC2 && c <= 0xDF ? 2 : (c & 0xF0) == 0xE0 ? 3 : c >= 0xF0 && c <= 0xF4 ? 4 : 0;
        int k = 1;
        while (k < len && (p[k] & 0xC0) == 0x80) k++;
        if (!len || k < len || (c == 0xE0 && p[1] < 0xA0) || (c == 0xED && p[1] > 0x9F) ||
            (c == 0xF0 && p[1] < 0x90) || (c == 0xF4 && p[1] > 0x8F)) { p++; continue; }
        unsigned cp = c & (0x7Fu >> len);
        for (int i = 1; i < len; i++) cp = (cp << 6) | (p[i] & 0x3F);
        int take = flag_len(p);
        /* ZWNJ joins Persian and Indic words: it is kept although is_hidden_cp flags it */
        if (!take && cp >= 0xA0 && !(cp >= 0xE0000 && cp <= 0xE007F) &&
            (cp == 0x200C || !is_hidden_cp(cp, false)))
            take = len;                                   /* below A0: C1 controls */
        memcpy(d + o, p, (size_t)take);
        o += (size_t)take;
        p += take ? take : len;
    }
    while (o && (d[o - 1] == '\n' || d[o - 1] == ' ' || d[o - 1] == '\t')) o--;
    d[o] = 0;
    size_t lead = strspn(d, "\n");
    memmove(d, d + lead, o - lead + 1);
    return d;
}

/* True if path is the project root or below it. Compared by device and inode
   on each parent, so firmlink and bind aliases of the same directory match. */
static bool path_within(const char *path, const struct stat *root) {
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s", path);
    for (;;) {
        struct stat st;
        if (!stat(p, &st) && st.st_dev == root->st_dev && st.st_ino == root->st_ino) return true;
        if (!strcmp(p, "/") || !*p) return false;
        char *slash = strrchr(p, '/');
        if (!slash) return false;
        if (slash == p) strcpy(p, "/");
        else *slash = 0;
    }
}

/* Project root for PATH checks: the nearest ancestor of cwd with a .git entry,
   else cwd. HOME or / as that ancestor means no repo, so cwd is used. */
static bool project_root(char root[PATH_MAX], struct stat *rst) {
    char dir[PATH_MAX], found[PATH_MAX] = "", home[PATH_MAX] = "";
    if (!realpath(g_cfg.cwd, dir)) return false;
    char cwd[PATH_MAX];
    snprintf(cwd, sizeof cwd, "%s", dir);
    const char *h = getenv("HOME");
    if (!h || !realpath(h, home)) home[0] = 0;
    for (;;) {
        char g[PATH_MAX + 8];
        struct stat st;
        snprintf(g, sizeof g, "%s/.git", dir);
        if (!stat(g, &st)) { snprintf(found, sizeof found, "%s", dir); break; }
        if (!strcmp(dir, "/")) break;
        char *slash = strrchr(dir, '/');
        if (slash == dir) strcpy(dir, "/");
        else *slash = 0;
    }
    bool use_repo = found[0] && strcmp(found, "/") && !(home[0] && !strcmp(found, home));
    snprintf(root, PATH_MAX, "%s", use_repo ? found : cwd);
    return !stat(root, rst);
}

/* First program of that name on PATH that the project cannot have supplied:
   empty and relative entries are skipped, as is anything resolving inside the
   project. */
static bool find_tool(const char *name, char out[PATH_MAX]) {
    char root[PATH_MAX];
    struct stat rst;
    const char *p = getenv("PATH");
    if (!p || !project_root(root, &rst)) return false;
    while (*p) {
        size_t n = strcspn(p, ":");
        char dir[PATH_MAX], file[PATH_MAX + 32], real_dir[PATH_MAX];
        struct stat st;
        if (n && n < sizeof dir && *p == '/') {
            memcpy(dir, p, n);
            dir[n] = 0;
            snprintf(file, sizeof file, "%s/%s", dir, name);
            if (realpath(dir, real_dir) && !path_within(real_dir, &rst) &&
                realpath(file, out) && !path_within(out, &rst) &&
                !stat(out, &st) && S_ISREG(st.st_mode) && !access(out, X_OK))
                return true;
        }
        p += n;
        if (*p == ':') p++;
    }
    return false;
}

/* Feed s to pbcopy (see find_tool, no shell). True only if it took everything
   and exited successfully. */
static bool run_pbcopy(const char *s, size_t n) {
    int fd[2];
    char prog[PATH_MAX];
    if (!find_tool("pbcopy", prog) || pipe(fd)) return false;
    pid_t pid = fork();
    if (pid < 0) { close(fd[0]); close(fd[1]); return false; }
    if (pid == 0) {
        dup2(fd[0], 0);
        close(fd[0]);
        close(fd[1]);
        int nul = open("/dev/null", O_WRONLY);
        if (nul >= 0) { dup2(nul, 1); dup2(nul, 2); }
        /* pbcopy decodes its input by locale; without this non-ASCII is mangled */
        unsetenv("LC_ALL");
        setenv("LC_CTYPE", "UTF-8", 1);
        execv(prog, (char *const[]){"pbcopy", NULL});
        _exit(127);
    }
    close(fd[0]);
    fcntl(fd[1], F_SETFL, O_NONBLOCK);
    double end = mono_now() + PBCOPY_TIMEOUT_S;
    struct timespec nap = {.tv_sec = 0, .tv_nsec = 5000000};
    size_t off = 0;
    while (off < n && mono_now() < end) {
        ssize_t w = write(fd[1], s + off, n - off);
        if (w > 0) off += (size_t)w;
        else if (w < 0 && errno != EAGAIN && errno != EINTR) break;
        else nanosleep(&nap, NULL);
    }
    close(fd[1]);
    int st = 0;
    pid_t r;
    while ((r = waitpid(pid, &st, WNOHANG)) == 0 && mono_now() < end) nanosleep(&nap, NULL);
    if (r == 0) { kill(pid, SIGKILL); waitpid(pid, &st, 0); return false; }
    return r == pid && off == n && WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

/* on this Mac's own terminal: over SSH its clipboard is not the user's */
static bool local_mac(void) {
#ifdef __APPLE__
    return !getenv("SSH_CONNECTION") && !getenv("SSH_TTY") && !getenv("SSH_CLIENT");
#else
    return false;
#endif
}

static void send_osc52(const char *s, size_t n) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    fputs("\033]52;c;", stdout);
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = (unsigned)(unsigned char)s[i] << 16;
        if (i + 1 < n) v |= (unsigned)(unsigned char)s[i + 1] << 8;
        if (i + 2 < n) v |= (unsigned char)s[i + 2];
        putchar(b64[v >> 18]);
        putchar(b64[(v >> 12) & 63]);
        putchar(i + 1 < n ? b64[(v >> 6) & 63] : '=');
        putchar(i + 2 < n ? b64[v & 63] : '=');
    }
    putchar('\a');
    fflush(stdout);
}

/* plain_text of items [from, to): the T_TEXT ones, joined as they streamed */
static char *reply_text(int from, int to) {
    size_t n = 0, o = 0;
    for (int i = from; i < to; i++)
        if (items[i].kind == T_TEXT) n += items[i].len;
    char *all = malloc(n + 1);
    if (!all) return NULL;
    for (int i = from; i < to; i++)
        if (items[i].kind == T_TEXT && items[i].len) {
            memcpy(all + o, items[i].text, items[i].len);
            o += items[i].len;
        }
    all[o] = 0;
    char *d = plain_text(all);
    free(all);
    return d;
}

static void copy_last_reply(void) {
    char *text = NULL;
    /* a reply is a run of text and reasoning items; anything else ends it */
    for (int end = nitems; end > 0 && !text; ) {
        int from = end;
        while (from > 0 && (items[from - 1].kind == T_TEXT || items[from - 1].kind == T_THINK)) from--;
        if (from == end) { end--; continue; }
        text = reply_text(from, end);
        if (text && !text[0]) { free(text); text = NULL; }
        end = from;
    }
    if (!text) { push_raw("  nothing to copy: no assistant reply yet"); return; }
    size_t n = strlen(text);
    bool local = local_mac();
    char b[320];
    bool sent = true;
    if (local && run_pbcopy(text, n)) {
        snprintf(b, sizeof b, GREEN "  ✓ copied the last reply" RESET " (%zu bytes, pbcopy)", n);
    } else {
        const char *failed = local ? "pbcopy failed. " : "";
        if (n > OSC52_MAX) {
            sent = false;
            snprintf(b, sizeof b, YELLOW "  not copied:" RESET
                     " %sThe reply is %zu bytes,\n  over the %d-byte OSC 52 limit.", failed, n, OSC52_MAX);
        } else {
            send_osc52(text, n);
            snprintf(b, sizeof b, YELLOW "  %sSent the last reply (%zu bytes) with OSC 52." RESET
                     "\n  Not confirmed: the terminal may ignore it, so paste to check.%s",
                     failed, n, getenv("TMUX") ? "\n  tmux needs set-clipboard on." : "");
        }
    }
    size_t lines = 1;
    for (const char *p = text; *p; p++) lines += *p == '\n';
    if (sent && lines > 1)
        snprintf(b + strlen(b), sizeof b - strlen(b),
                 "\n  It has several lines (%zu): check before pasting into a shell.", lines);
    free(text);
    push_raw(b);
}

static void toggle_mouse(void) {
    mouse_on = !mouse_on;
    fputs(mouse_on ? MOUSE_ON_SEQ : MOUSE_OFF_SEQ, stdout);
    fflush(stdout);
    char b[320];
    if (mouse_on)
        snprintf(b, sizeof b, "  mouse on: wheel scrolls, click expands.\n  To select text hold %s and drag.",
                 select_key());
    else
        snprintf(b, sizeof b, "  mouse off: drag to select text. The wheel no longer scrolls this view:\n"
                 "  use PgUp/PgDn. ^O expands the latest block. /mouse turns it back on.");
    push_raw(b);
}

/* ---------- images ----------
   Only the input box and the clipboard feed this: never model output, tool
   output or project files. */

#define CLIPBOARD_TIMEOUT_S 10.0

/* shows as busy while an image loads: typed messages queue (nothing here can be
   entered again) and Esc cancels */
static void load_begin(void) {
    g_abort = 0;
    working = true;
    g_stat.phase = "loading image";
    g_stat.task_toks = g_stat.stream_chunks = 0;
    clock_gettime(CLOCK_MONOTONIC, &g_stat.task_t0);
    set_status("loading image…");
    fw_tick_hook = tui_pump;
    render_screen();
}

static void load_end(void) {
    fw_tick_hook = NULL;
    working = false;
    set_status("ready");
    render_screen();
}

/* true only when /models says the current model cannot take images */
static bool vision_off(void) {
    char *mj = http_get("/models");
    cJSON *root = mj ? cJSON_Parse(mj) : NULL;
    free(mj);
    cJSON *data = root ? cJSON_GetObjectItemCaseSensitive(root, "data") : NULL, *el;
    int blind = 0, seeing = 0;
    const cJSON *mine = NULL;
    cJSON_ArrayForEach(el, data) {
        cJSON *id = cJSON_GetObjectItemCaseSensitive(el, "id");
        cJSON *v = cJSON_GetObjectItemCaseSensitive(el, "vision");
        if (cJSON_IsString(id) && !strcmp(id->valuestring, g_cfg.model)) mine = el;
        blind += cJSON_IsFalse(v);
        seeing += cJSON_IsTrue(v);
    }
    /* a name the server does not list: refuse only if nothing it serves sees */
    bool off = mine ? cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(mine, "vision"))
                    : blind && !seeing;
    cJSON_Delete(root);
    return off;
}

static void no_vision(char *why, size_t cap) {
    char m[200];
    snprintf(why, cap, "model %s is serving without vision.\n  Restart the engine without "
             "--language-only (stop it, then run flywheel setup)\n  or pick another with /model.",
             clean_line(m, sizeof m, g_cfg.model));
}

/* Load every reference into pending, all or none; false with the reason. */
static bool attach_refs(char **refs, int n, char *why, size_t cap) {
    Images got = images_copy(&pending);
    bool ok = true;
    for (int i = 0; ok && i < n; i++) {
        ImagePart p = {0};
        char err[256] = "";
        bool url = !strncasecmp(refs[i], "http://", 7) || !strncasecmp(refs[i], "https://", 8);
        ok = url ? image_from_url(refs[i], &p, err, sizeof err)
                 : image_from_file(g_cfg.cwd, refs[i], &p, err, sizeof err);
        if (fw_tick_hook) fw_tick_hook();       /* a quick load never ticked */
        const char *no = ok && !g_abort ? images_add(&got, &p, g_msgs) : NULL;
        if (g_abort) snprintf(err, sizeof err, "cancelled");
        else if (no) snprintf(err, sizeof err, "%s", no);
        if (g_abort || no) {
            if (ok) image_part_free(&p);
            ok = false;
        }
        if (!ok) {
            char name[300], e[256];
            snprintf(why, cap, "%s: %s", clean_line(name, sizeof name, refs[i]),
                     clean_line(e, sizeof e, err));
        }
    }
    if (ok) {
        images_free(&pending);
        pending = got;
    } else images_free(&got);
    return ok;
}

/* osascript writes the clipboard picture to path; no shell */
static bool run_clipboard(const char *path) {
    char prog[PATH_MAX];
    if (!find_tool("osascript", prog)) return false;
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        int nul = open("/dev/null", O_RDWR);
        if (nul >= 0) { dup2(nul, 0); dup2(nul, 1); dup2(nul, 2); }
        unsetenv("LC_ALL");
        setenv("LC_CTYPE", "UTF-8", 1);
        execv(prog, (char *const[]){
            "osascript", "-e", "on run argv",
            "-e", "set d to (the clipboard as «class PNGf»)",
            "-e", "set f to open for access (POSIX file (item 1 of argv)) with write permission",
            "-e", "write d to f", "-e", "close access f", "-e", "end run",
            (char *)path, NULL});
        _exit(127);
    }
    double end = mono_now() + CLIPBOARD_TIMEOUT_S;
    struct timespec nap = {.tv_sec = 0, .tv_nsec = 20000000};
    int st = 0;
    pid_t r;
    while ((r = waitpid(pid, &st, WNOHANG)) == 0 && mono_now() < end && !g_abort) {
        if (fw_tick_hook) fw_tick_hook();
        nanosleep(&nap, NULL);
    }
    if (r == 0) { kill(pid, SIGKILL); waitpid(pid, &st, 0); return false; }
    return r == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

static bool attach_clipboard(char *why, size_t cap) {
    const char *tmp = getenv("TMPDIR");
    char dir[1024], file[1100];
    snprintf(dir, sizeof dir, "%s/fw-clip-XXXXXX", tmp && *tmp == '/' ? tmp : "/tmp");
    if (!mkdtemp(dir)) { snprintf(why, cap, "cannot create a temporary directory"); return false; }
    snprintf(file, sizeof file, "%s/clipboard.png", dir);
    ImagePart p = {0};
    char err[256] = "";
    bool ran = run_clipboard(file);
    bool ok = ran && image_from_file(NULL, file, &p, err, sizeof err);
    unlink(file);
    rmdir(dir);
    if (g_abort) snprintf(why, cap, "cancelled");
    else if (!ran) snprintf(why, cap, "no image on the clipboard");
    else if (!ok) snprintf(why, cap, "%s", err);
    else {
        free(p.source);
        p.source = str_dup("clipboard");
        const char *no = images_add(&pending, &p, g_msgs);
        if (!no) return true;
        snprintf(why, cap, "%s", no);
    }
    if (ok) image_part_free(&p);
    return false;
}

static void say_attached(void) {
    char b[160];
    snprintf(b, sizeof b, GREEN "  ✓ %d image%s attached" RESET ": type your message (^C drops %s)",
             pending.n, pending.n == 1 ? "" : "s", pending.n == 1 ? "it" : "them");
    push_raw(b);
}

static void paste_clipboard(void) {
    if (!local_mac()) {
        push_raw("  /paste reads the clipboard of a local Mac session only.\n"
                 "  Drag the file in or give an image URL instead.");
        return;
    }
    char why[600];
    load_begin();
    bool ok = !vision_off();
    if (!ok) no_vision(why, sizeof why);
    else ok = attach_clipboard(why, sizeof why);
    load_end();
    if (ok) { say_attached(); return; }
    char b[700];
    snprintf(b, sizeof b, YELLOW "  not attached:" RESET " %s", why);
    push_raw(b);
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
        images_free(&pending);
        transcript_clear();
        if (qheld) {                /* not into the new conversation */
            queue_clear();
            set_notice("queued messages dropped");
        }
        render_screen();
    } else if (!strcmp(cmd, "/paste")) {
        paste_clipboard();
    } else if (!strcmp(cmd, "/copy")) {
        copy_last_reply();
    } else if (!strcmp(cmd, "/mouse")) {
        toggle_mouse();
    } else if (!strcmp(cmd, "/help")) {
        char b[900];
        snprintf(b, sizeof b,
                 "commands: /init /clear /model /allow /status /paste /copy /mouse /help /exit\n"
                 "keys: ↑↓ history · Alt+Enter newline (Shift+Enter if the terminal sends it) · ^O expand/collapse cmd · PgUp/PgDn%s scroll · Esc aborts · ^C clear · ^D quit\n"
                 "copy: /copy takes the last reply · /mouse lets the terminal select text\n"
                 "images: drag a file in or give an image URL · /paste takes the clipboard's\n"
                 "mouse on: hold %s and drag to select",
                 mouse_on ? " or wheel" : "", select_key());
        push_raw(b);
    } else if (!strncmp(cmd, "/model", 6)) {
        if (cmd[6] == ' ' && cmd[7]) {
            free(g_cfg.model);
            g_cfg.model = str_dup(cmd + 7);
            char b[300], m[256];
            snprintf(b, sizeof b, "  model: " CYAN "%s" RESET, clean_line(m, sizeof m, g_cfg.model));
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
                int pick = tui_choose_menu("Model", NULL, "Choose a model:", mnames, nm, NULL, false);
                if (pick >= 0 && pick < nm) {
                    free(g_cfg.model);
                    g_cfg.model = str_dup(mnames[pick]);
                }
            }
            char b[300], m[256];
            snprintf(b, sizeof b, "  model: " CYAN "%s" RESET, clean_line(m, sizeof m, g_cfg.model));
            push_raw(b);
            if (root) cJSON_Delete(root);
        }
    } else if (!strcmp(cmd, "/allow")) {
        char p[4096];
        char *c = perm_project_file(p, sizeof p) ? read_file(p) : NULL;
        if (c) {
            char *safe = clean_text(c, true, false);
            char b[8600], sp[4096];
            snprintf(b, sizeof b, "  permission rules (builtin read-only +) %s:\n%.3900s",
                     clean_line(sp, sizeof sp, p), safe);
            push_raw(b);
            free(safe);
            free(c);
        } else {
            push_raw("  permission rules for this project: (none yet — \"don't ask again\" adds one)");
        }
    } else if (!strcmp(cmd, "/status")) {
        char b[600];
        const Profile *prof = profile_detect(g_cfg.cwd, g_cfg.profile);
        char *models = http_get("/models");
        char e[200], m[200];
        snprintf(b, sizeof b, "  engine: %s %s · model: " CYAN "%s" RESET " · profile: %s · msgs: %d",
                 clean_line(e, sizeof e, g_cfg.endpoint), models ? GREEN "up" RESET : RED "down" RESET,
                 clean_line(m, sizeof m, g_cfg.model), prof->name, g_msgs->n);
        free(models);
        push_raw(b);
    } else {
        char b[300], c[201];
        snprintf(b, sizeof b, "  unknown command: %s (try /help)", clean_line(c, sizeof c, cmd));
        push_raw(b);
    }
}

void tui_cleanup(void) {
    transcript_clear();
    free(items); items = NULL; cap_items = 0;
    for (int i = 0; i < hist_n; i++) { free(HIST[i]); HIST[i] = NULL; }
    hist_n = 0;
    for (int i = 0; i < npastes; i++) free(pastes[i].text);
    free(pastes); pastes = NULL; npastes = cap_pastes = 0;
    queue_clear();
    images_free(&pending);
    free(pbuf); pbuf = NULL; plen = pcap = 0; pasting = false;
    free(inbuf); inbuf = NULL; incap = 0; ilen = icur = 0;
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
    char model_s[200], endp_s[200];
    clean_line(model_s, sizeof model_s, g_cfg.model);
    clean_line(endp_s, sizeof endp_s, g_cfg.endpoint);
    snprintf(r1, sizeof r1, "    " CYAN "╭─┴─╮" RESET "     " CYAN BOLD "F L Y W H E E L" RESET "  " DIM "v" FW_VERSION RESET);
    snprintf(r2, sizeof r2, "  " CYAN "╭─┤ " YELLOW "◎" CYAN " ├─╮" RESET "   " DIM "model  " RESET " " BOLD "%s" RESET DIM " · %s ctx" RESET,
             model_s, ctxs);
    snprintf(r3, sizeof r3, "    " CYAN "╰─┬─╯" RESET "     " DIM "engine " RESET " %s" DIM " · %s" RESET,
             online ? (GREEN "● online" RESET) : (RED "○ offline" RESET), endp_s);
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

/* what is searched for images: the input as typed, with one-line pastes (a long
   drag) filled in. A pasted block of several lines is quoted material. */
static char *scan_text(const char *s) {
    size_t len = strlen(s), w = 0;
    char *out = malloc(expand_into(NULL, s) + len + 1);
    if (!out) return NULL;
    for (size_t r = 0; r < len;) {
        int k = paste_at(s + r, len - r);
        if (k < 0) { out[w++] = s[r++]; continue; }
        size_t n = pastes[k].len, tl = strlen(pastes[k].tok);
        while (n && pastes[k].text[n - 1] == '\n') n--;
        bool block = memchr(pastes[k].text, '\n', n) != NULL;
        memcpy(out + w, block ? pastes[k].tok : pastes[k].text, block ? tl : n);
        w += block ? tl : n;
        r += tl;
    }
    out[w] = 0;
    return out;
}

static bool known_command(const char *s) {
    size_t n = strcspn(s, " ");
    for (int i = 0; SLASH[i].cmd; i++)
        if (strlen(SLASH[i].cmd) == n && !memcmp(SLASH[i].cmd, s, n)) return true;
    return false;
}

static bool history_has_images(void) {
    for (int i = 0; i < g_msgs->n; i++)
        if (g_msgs->v[i].images.n) return true;
    return false;
}

/* a message that was not sent goes back to the input box, above anything typed
   since */
static void keep_unsent(const char *raw) {
    if (!ilen) in_set(raw);
    else {
        icur = 0;
        if (ins("\n", 1)) { icur = 0; ins(raw, (int)strlen(raw)); }
        icur = ilen;
    }
}

/* Send one message the user entered: cmd as the model gets it, raw as typed.
   A path starts with '/' too, so known commands are told apart first. */
static void submit(const char *cmd, const char *raw) {
    if (is_slash(cmd) && known_command(cmd)) { run_slash(cmd); return; }
    char *refs[IMG_MAX_COUNT + 1], *scan = scan_text(raw);
    bool only = false;
    int n = scan ? image_find_refs(g_cfg.cwd, scan, refs, IMG_MAX_COUNT + 1, &only) : 0;
    free(scan);
    if (!n && is_slash(cmd)) { run_slash(cmd); return; }
    bool old = history_has_images();    /* they are sent again every turn */
    if (n || pending.n || old) {
        char why[600];
        load_begin();
        bool ok = !vision_off();
        tui_pump();                     /* /models does not tick: read an Esc */
        if (g_abort) {
            ok = false;
            snprintf(why, sizeof why, "cancelled");
        } else if (!ok) {
            no_vision(why, sizeof why);
            images_free(&pending);      /* the model changed under them */
        } else ok = attach_refs(refs, n, why, sizeof why);
        load_end();
        for (int i = 0; i < n; i++) free(refs[i]);
        if (!ok) {
            char b[800];
            snprintf(b, sizeof b, YELLOW "  not sent:" RESET " %s%s%s", why,
                     n ? "\n  To mention an image without attaching it, put it in `backticks`." : "",
                     old ? "\n  This conversation holds images: /clear drops them." : "");
            push_raw(b);
            keep_unsent(raw);
            qheld = !g_abort && qn;     /* a cancel drops the queue instead */
            if (qheld) {
                snprintf(b, sizeof b, YELLOW "  %d queued message%s held:" RESET
                         " sent after your next one (^C or /clear drops %s)",
                         qn, qn == 1 ? "" : "s", qn == 1 ? "it" : "them");
                push_raw(b);
            }
            render_screen();
            return;
        }
        if (only) { say_attached(); return; }
    }
    qheld = false;      /* held messages follow this one */
    tui_run_task(cmd);
}

/* Central key handler shared by the idle REPL loop and the busy pump.
   busy=true while the agent is working: typing edits the input box normally,
   Enter queues the message, Esc/^C abort the task, scrolling/expand all work. */
static void handle_key(unsigned char ch, bool busy) {
    unsigned char escbuf[32];
    if (pasting) { paste_feed(ch); return; }   /* nothing pasted acts as a key */
    notice[0] = 0;
    if (ch == 27) {
        int escn = read_esc_seq(escbuf, sizeof escbuf);
        if (escn == 1) {
            int late = esc_late;
            paste_suspect = false;
            if (busy) { g_abort = 1; queue_clear(); set_status("aborting…"); render_screen(); }
            else if (menu_count()) { menu_dismissed = true; render_screen(); }
            if (late >= 0) handle_key((unsigned char)late, busy);
            return;
        }
        int clicked = -1;
        if (handle_mouse_seq(escbuf, escn, &clicked)) {
            /* Click on an item in the open slash menu? */
            if (clicked >= 0 && slash_menu_top >= 0 &&
                clicked >= slash_menu_top && clicked < slash_menu_top + slash_menu_cnt) {
                const char *m[MENU_MAX];
                int nm = menu_matches(m, MENU_MAX);
                int idx = slash_menu_off + clicked - slash_menu_top;
                if (idx < nm) {
                    const char *pick = m[idx];
                    ilen = icur = 0; inbuf[0] = 0; hpos = -1; menu_sel = 0; menu_dismissed = false;
if (busy) {
                        in_set(pick);
                        ins(" ", 1);
                        render_screen();
                        return;
                    }
                                        if (!strcmp(pick, "/exit") || !strcmp(pick, "/quit")) { want_exit = true; return; }
                    render_screen();
                    run_slash(pick);
                    drain_queue();
                    render_screen();
                }
            }
            return;
        }
        if (escn >= 6 && !memcmp(escbuf, "\033[200~", 6)) { paste_begin(false); return; }
        if (escn >= 6 && !memcmp(escbuf, PASTE_END, 6)) { paste_suspect = false; return; }
        /* Alt+Enter, or Shift+Enter as CSI-u / modifyOtherKeys send it. Neither
           protocol is switched on: it would change how Ctrl and Esc arrive. */
        if ((escn == 2 && (escbuf[1] == '\r' || escbuf[1] == '\n')) ||
            !strcmp((char *)escbuf, "\033[13;2u") || !strcmp((char *)escbuf, "\033[27;2;13~")) {
            ins("\n", 1); menu_sel = 0; render_screen(); return;
        }
        if (escbuf[1] == '[' || escbuf[1] == 'O') {
            char k = (char)escbuf[escn - 1];
            int mc = menu_count();
            if (k == 'A') {   /* up */
                if (mc) { menu_sel = (menu_sel > 0) ? menu_sel - 1 : mc - 1; }
                else if (hpos < hist_n - 1) {
                    hpos++;
                    in_set(HIST[hist_n - 1 - hpos]);
                }
            } else if (k == 'B') {   /* down */
                if (mc) { menu_sel = (menu_sel + 1) % mc; }
                else if (hpos >= 0) {
                    hpos--;
                    in_set(hpos < 0 ? "" : HIST[hist_n - 1 - hpos]);
                }
            } else if (k == 'D') { icur = in_prev(icur); }
            else if (k == 'C') { icur = in_next(icur); }
            else if (k == 'H') icur = 0;
            else if (k == 'F') { icur = ilen; if (busy) scroll_off = 0; }
            else if (k == '~' && escn >= 3 && escbuf[2] == '3') {   /* delete */
                if (icur < ilen) in_delete(icur, in_next(icur));
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
        paste_suspect = false;
        if (busy) { g_abort = 1; queue_clear(); set_status("aborting…"); render_screen(); return; }
        ilen = icur = 0; inbuf[0] = 0; hpos = -1; menu_sel = 0; menu_dismissed = false;
        if (pending.n) {
            images_free(&pending);
            set_notice("attached images dropped");
        }
        if (qn) {                       /* held behind a message that failed */
            queue_clear();
            set_notice("queued messages dropped");
        }
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
        in_delete(token_start(s), icur);   /* a token has spaces in it */
        render_screen(); return;
    }
    if (ch == '\t') {   /* tab completes slash */
        const char *m[MENU_MAX];
        int nm = menu_matches(m, MENU_MAX);
        if (nm) {
            const char *pick = m[menu_sel < nm ? menu_sel : 0];
            int plen = 0;
            while (plen < ilen && inbuf[plen] != ' ') plen++;
            int newlen = (int)strlen(pick);
            if (in_reserve((size_t)(ilen - plen + newlen) + 1)) {
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
        inbuf[ilen] = 0;
        if (!ilen) { render_screen(); return; }
        if (menu_count() && !strchr(inbuf, ' ')) {
            const char *m[MENU_MAX];
            int nm = menu_matches(m, MENU_MAX);
            if (nm) {
                const char *pick = m[menu_sel < nm ? menu_sel : 0];
                int plen = 0;
                while (plen < ilen && inbuf[plen] != ' ') plen++;
                int newlen = (int)strlen(pick);
                if (in_reserve((size_t)(ilen - plen + newlen))) {
                    memmove(inbuf + newlen, inbuf + plen, (size_t)(ilen - plen));
                    ilen += newlen - plen;
                    memcpy(inbuf, pick, (size_t)newlen);
                    inbuf[ilen] = 0;
                    icur = ilen;
                }
            }
        }
        bool isexit = !strcmp(inbuf, "/exit") || !strcmp(inbuf, "/quit");
        /* refuse before anything is cleared, so the text stays in the box */
        char *cmd = NULL;
        if (busy && qn >= QMAX) set_notice("queue full (8): message kept in the input box");
        else if (!(cmd = expand_pastes(inbuf))) set_notice("message over 1 MB refused");
        if (!cmd) { render_screen(); return; }
        if (hist_n == 0 || strcmp(HIST[hist_n - 1], inbuf)) {
            if (hist_n < MAXHIST) HIST[hist_n++] = str_dup(inbuf);
            else {
                free(HIST[0]);
                memmove(HIST, HIST + 1, sizeof(char *) * (MAXHIST - 1));
                HIST[MAXHIST - 1] = str_dup(inbuf);
            }
        }
        char *raw = str_dup(inbuf);
        ilen = icur = 0; inbuf[0] = 0; hpos = -1; menu_sel = 0; menu_dismissed = false;
        if (busy) {
            qscan[qn] = raw;
            qmsg[qn++] = cmd;
            render_screen();
            return;
        }
        if (isexit) { want_exit = true; free(cmd); free(raw); return; }
        render_screen();
        submit(cmd, raw);
        free(cmd);
        free(raw);
        drain_queue();      /* typed while an image was loading */
        render_screen();
        return;
    }
    if (ch == 127 || ch == 8) {
        if (icur > 0) {
            in_delete(in_prev(icur), icur);
            menu_dismissed = false;
        }
        render_screen(); return;
    }
    if (ch >= 32) {
        char c1 = (char)ch;
        ins(&c1, 1);
        render_screen(); return;
    }
}

/* Drain queued messages after a task completes, up to one that is not sent. */
static void drain_queue(void) {
    while (qn > 0 && !g_abort && !qheld) {
        char *next = qmsg[0], *raw = qscan[0];
        qn--;
        memmove(qmsg, qmsg + 1, (size_t)qn * sizeof *qmsg);
        memmove(qscan, qscan + 1, (size_t)qn * sizeof *qscan);
        submit(next, raw);
        free(next);
        free(raw);
    }
    if (g_abort) queue_clear();
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
    paste_tick();
    static double lastr;
    double now = mono_now();
    if (now - lastr >= 0.08) { lastr = now; if (working) render_screen(); }
}

void tui_repl(void) {
    if (!in_reserve(0)) return;
    signal(SIGWINCH, on_winch);
    catch_fatal();
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
        int pick = tui_choose_menu("Project setup", NULL, prompt, opts, 2, "yn", false);
        if (pick == 0) run_slash("/init");
    }

    render_screen();

    want_exit = false;
    for (;;) {
        if (g_resized) { g_resized = 0; render_screen(); }

        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(0, &rf);
        struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};
        if (select(1, &rf, NULL, NULL, &tv) <= 0) { paste_tick(); continue; }

        unsigned char ch;
        ssize_t n = read(0, &ch, 1);
        if (n <= 0) { if (n == 0) break; continue; }
        handle_key(ch, false);
        if (want_exit) break;
    }
    term_raw(false);
    printf("\033[r\033[%d;1H\n", rows);
    fflush(stdout);
    tui_up = 0;
}
