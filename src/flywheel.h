#ifndef FLYWHEEL_H
#define FW_VERSION "0.2"
#define FLYWHEEL_H

#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../third_party/cjson/cJSON.h"

typedef struct {
    char *endpoint;      /* e.g. http://127.0.0.1:8312/v1 */
    char *model;
    char *cwd;           /* working dir for bash tool */
    char *profile;       /* ts|python|go|rust|generic|NULL=auto */
    char *prompt_file;   /* -f */
    char *once;          /* positional one-shot prompt */
    char *transcript;    /* path for JSONL transcript, NULL = off */
    int   maxturns;      /* default 60 */
    int   wall;          /* seconds, default 0=off */
    int   cmd_timeout;   /* default 30 */
    int   maxtok;        /* default 12000 */
    int   gate_every;    /* default 8, 0=off */
    int   max_gates;     /* default 1 */
    double temp;         /* default 0.0 */
    double top_p;        /* default 0.95 */
    double pp;           /* presence penalty, default 0.0 */
    double loop_temp;    /* escape temp, default 0.5 */
    int   think_budget;  /* 0=server default */
    bool  color;
    bool  quiet;         /* once-mode: minimal output */
    bool  yes;           /* auto-confirm setup prompts */
    char *sys_extra;     /* appended to system prompt */
} Cfg;

extern Cfg g_cfg;
extern volatile sig_atomic_t g_abort;   /* Esc pressed / SIGINT during request */
extern void (*fw_tick_hook)(void);      /* TUI render tick during streaming */

/* msgs.c — conversation store */
typedef struct {
    char *role;          /* system|user|assistant|tool */
    char *content;       /* may be NULL */
    char *tool_call_id;  /* tool msgs only */
    cJSON *tool_calls;   /* assistant msgs only: raw array, owned */
} Msg;

typedef struct { Msg *v; int n, cap; } Msgs;
void  msgs_init(Msgs *);
void  msgs_push(Msgs *, const char *role, const char *content);
void  msgs_push_tool(Msgs *, const char *tool_call_id, const char *content);
void  msgs_push_assistant(Msgs *, const char *content, cJSON *tool_calls);
void  msgs_insert(Msgs *, int at, const char *role, const char *content);
void  msgs_trunc(Msgs *, int n);
void  msgs_free(Msgs *);
cJSON *msgs_to_json(Msgs *);

/* http.c — one streamed (or plain) chat completion */
typedef struct {
    void (*on_text)(const char *piece, void *ud);   /* streamed content deltas */
    void (*on_think)(const char *piece, void *ud);  /* streamed reasoning deltas */
    void *ud;
    bool stream;
} StreamCb;

typedef struct {
    char *content;        /* final content (may be NULL) */
    char *reasoning;      /* may be NULL */
    cJSON *tool_calls;    /* array or NULL */
    char *finish;         /* "stop"|"length"|"tool_calls"|... */
    int   prompt_tokens, completion_tokens;
    double secs;
    char *error;          /* set on failure */
} ChatResp;

ChatResp *chat(Msgs *, StreamCb *);   /* NULL on curl/parse error -> ->error */
void      chat_resp_free(ChatResp *);
char     *http_get(const char *path); /* GET endpoint+path, malloc'd body or NULL */
char     *http_get_url(const char *url); /* GET absolute URL, malloc'd body or NULL */

/* tools.c */
char *run_bash(const char *cmd, const char *cwd, int timeout_s); /* never NULL */
char *deny_check(const char *cmd, const char *cwd);              /* NULL=ok, else static reason */
char *heredoc_fix(const char *cmd);                              /* returns new or copy */
bool  cmd_is_write(const char *cmd);

/* permission rules: builtin safe reads + ~/.config/flywheel/allow +
   ~/.config/flywheel/projects/<project>.allow (never read from the project) */
bool  perm_allowed(const char *cmd);   /* rule match — no prompt needed */
void  perm_load(void);                 /* load rule files once */
void  perm_add_rule(const char *rule); /* remember + persist per project */
bool  perm_project_file(char *out, size_t cap); /* path of this project's rules */
char *perm_prefix(const char *cmd);    /* derived prefix rule for "always" (malloc'd) */
void  perm_free(void);

/* args.c — lenient tool-call arg extraction */
char *args_extract_command(const char *raw_args_json);  /* malloc'd, never NULL ("" on fail) */
char *args_extract_key(const char *raw_args_json, const char *key);  /* malloc'd, never NULL */
const char *resolve_confined(const char *cwd, const char *path, char *out, size_t cap, bool for_write);
char *tool_write_file(const char *cwd, const char *path, const char *content);   /* malloc'd status */
char *tool_edit_file(const char *cwd, const char *path, const char *old_str, const char *new_str);
cJSON *args_parse_strict(const char *raw);  /* complete JSON object or NULL */
void  args_note_repair(const char *kind);               /* bumps repair stats */

/* sim.c */
double sim_ratio(const char *a, const char *b);         /* 0..1, caps at 700 chars each */

/* profile.c */
typedef struct {
    const char *name;
    const char *gate_cmd;        /* NULL = no gate */
    const char *persona;         /* system-prompt engineer phrase */
    const char *write_exts;      /* unused v1 */
} Profile;
const Profile *profile_detect(const char *cwd, const char *force);

/* agent.c — shared driver for --once and interactive tasks */
typedef struct {
    int turns, calls, prunes, gates, resets;
    int prompt_tokens;          /* latest request prompt tokens (context fill) */
    int completion_tokens;      /* cumulative completion tokens this task */
    double secs;                /* cumulative generation secs */
    double tok_per_sec;         /* latest/average generation tok/s */
    const char *finish;         /* NULL while running, else "done"|"aborted"|... */
} AgentStats;

typedef struct {
    void (*emit_text)(const char *, void *);        /* agent text to UI */
    void (*emit_think)(const char *, void *);
    void (*emit_tool)(const char *name, const char *detail, void *); /* about to run */
    void (*emit_out)(const char *out, void *);      /* tool result */
    void (*emit_status)(const char *, void *);      /* status-line text */
    void (*emit_event)(const char *kind, const char *detail, void *); /* prune/gate/reset/done */
    void (*emit_stats)(const AgentStats *, void *); /* live telemetry updates */
    bool (*approve_cmd)(const char *cmd, void *);   /* NULL = auto-approve (non-interactive) */
    void *ud;
    bool interactive;
} Ui;

/* runs the task to DONE/cap; returns finish string (static); out_summary filled if non-NULL */
const char *agent_run(Msgs *, Ui *, char *out_summary, size_t);

/* tui.c */
void tui_repl(void);
void tui_run_task(const char *prompt);              /* interactive-session task runner */
void tui_cleanup(void);
void g_msgs_link(Msgs *);                           /* share conversation with the TUI */

/* main.c — init/setup + system-prompt rebuild (TUI calls these) */
int   fw_do_init(void);
int   fw_do_setup(void);
char *fw_build_system(bool interactive);

/* bench.c — suite runner; argv[0]=suite-dir, argv[1]=tag, rest=task ids */
int   fw_copy_file(const char *src, const char *dst);  /* binary-safe, keeps mode */
int   fw_do_bench(int argc, char **argv);

/* util */
char *str_dup(const char *);
char *str_ndup(const char *, size_t);
char *read_file(const char *path);                  /* NULL on fail */
void  ftrim_mid(char *s, int head, int tail);       /* keep head+tail chars, mark middle */
void  utf8_sanitize(char *s);                       /* tools.c — JSON-safe bytes */
char *clean_text(const char *s, bool crlf, bool strict); /* terminal-safe copy, malloc'd */
char *tty_text(const char *s, bool crlf);           /* clean_text only if stdout is a tty */

#define DIM   "\033[2m"
#define BOLD  "\033[1m"
#define RED   "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE  "\033[34m"
#define CYAN  "\033[36m"
#define MAGENTA "\033[35m"
#define GRAY  "\033[90m"
#define RESET "\033[0m"
#define CLR_LINE "\033[2K\r"

bool safe_repo_filename(const char *s);
#endif
