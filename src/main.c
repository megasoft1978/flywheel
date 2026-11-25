#include "flywheel.h"
#include <curl/curl.h>
#include <locale.h>
#include <wchar.h>
#include <signal.h>
#include <sys/stat.h>
#include <dirent.h>

Cfg g_cfg;
volatile sig_atomic_t g_abort = 0;

static void on_sigint(int s) { (void)s; g_abort = 1; }

static void usage(FILE *f) {
    fprintf(f,
"flywheel — C agent harness for local OpenAI-compatible engines\n"
"\n"
"  flywheel                          interactive REPL (claude-code style)\n"
"  flywheel init                     set up .flywheel.md for this project\n"
"  flywheel setup                    install engine + download model (interactive)\n"
"  flywheel \"fix the bug in x.ts\"     one-shot task\n"
"  flywheel -f prompt.md             one-shot from file\n"
"  flywheel [flags] bench SUITE TAG [task-id ...]   run a bench suite\n"
"\n"
"config: ~/.config/flywheel/config (key=value: endpoint, model, profile,\n"
"        maxturns, wall, cmd_timeout, maxtok, temp, top_p, pp, think_budget)\n"
"\n"
"options:\n"
"  -e URL     endpoint          (def http://127.0.0.1:8312/v1, env FW_ENDPOINT)\n"
"  -m MODEL   model name        (def local/qwen-pi4, env FW_MODEL)\n"
"  -C DIR     working dir       (def cwd)\n"
"  -P PROF    ts|python|go|rust|generic (def auto-detect)\n"
"  -f FILE    prompt file\n"
"  -T N       max turns         (def 60)\n"
"  -W SEC     wall clock        (def 0=off)\n"
"  -t SEC     bash cmd timeout  (def 30)\n"
"  -K N       max tokens/resp   (def 12000)\n"
"  --temp X --topp X --pp X     sampling (def 0, 0.95, 0)\n"
"  --think N  thinking budget   (def 0=server default)\n"
"  --gates N  verify passes     (def 1)\n"
"  --transcript FILE            JSONL log\n"
"  --sys TEXT  extra system-prompt text\n"
"  -q         quiet (non-interactive)\n");
}

static char *build_system(const Profile *prof, bool interactive) {
    const char *gate = prof->gate_cmd ? prof->gate_cmd : "";
    char base[4096];
    if (interactive) {
        if (prof->gate_cmd)
            snprintf(base, sizeof base,
                "You are an expert %s helping the user interactively in their project directory. You have three tools: "
                "`write_file` (create/rewrite files — ALWAYS use this instead of heredocs/cat/echo for file writes), "
                "`edit_file` (surgical edits — ALWAYS use this instead of sed/perl), and `bash` (everything else: inspect, build, test, git). "
                "Answer questions directly and concisely without unnecessary tool calls. "
                "When asked to inspect or change code, use the tools (never use sleep/nohup, keep each command short), "
                "run `%s` after edits and fix any errors, then reply concisely with what you found or changed.",
                prof->persona, gate);
        else
            snprintf(base, sizeof base,
                "You are an expert %s helping the user interactively in their project directory. You have three tools: "
                "`write_file` (create/rewrite files — ALWAYS use this instead of heredocs/cat/echo for file writes), "
                "`edit_file` (surgical edits — ALWAYS use this instead of sed/perl), and `bash` (everything else: inspect, build, test, git). "
                "Answer questions directly and concisely without unnecessary tool calls. "
                "When asked to inspect or change code, use the tools (never use sleep/nohup, keep each command short), "
                "verify your changes, then reply concisely with what you found or changed.",
                prof->persona);
    } else if (prof->gate_cmd)
        snprintf(base, sizeof base,
            "You are an expert %s working in a project directory. You have three tools: "
            "`write_file` (create/rewrite files — ALWAYS use this instead of heredocs/cat/echo for file writes), "
            "`edit_file` (surgical edits — ALWAYS use this instead of sed/perl), and `bash` (everything else: inspect, build, test, git). "
            "Read the task, inspect existing files with bash, write the required files with write_file, "
            "then run `%s` and fix every error. You can also write short scripts or tests to check behaviour "
            "(never leave non-test scratch source files, never use sleep/nohup). Keep each command short. "
            "When finished and the check is clean, reply with the single word DONE and no tool call.",
            prof->persona, gate);
    else
        snprintf(base, sizeof base,
            "You are an expert %s working in a project directory. You have three tools: "
            "`write_file` (create/rewrite files — ALWAYS use this instead of heredocs/cat/echo for file writes), "
            "`edit_file` (surgical edits — ALWAYS use this instead of sed/perl), and `bash` (everything else: inspect, build, test, git). "
            "Read the task, inspect existing files with bash, write the required files with write_file, "
            "then verify them with scripts/tests you write yourself (never use sleep/nohup). Keep each command short. "
            "When finished, reply with the single word DONE and no tool call.",
            prof->persona);
    /* project instructions: .flywheel.md > AGENTS.md > CLAUDE.md */
    const char *files[] = {".flywheel.md", "AGENTS.md", "CLAUDE.md", NULL};
    char proj[4096] = {0};
    for (int i = 0; files[i]; i++) {
        char p[1024];
        snprintf(p, sizeof p, "%s/%s", g_cfg.cwd, files[i]);
        char *c = read_file(p);
        if (c) { snprintf(proj, sizeof proj, "\n\nProject instructions:\n%.3800s", c); free(c); break; }
    }
    char *sys = malloc(strlen(base) + strlen(proj) + (g_cfg.sys_extra ? strlen(g_cfg.sys_extra) : 0) + 8);
    sprintf(sys, "%s%s%s", base, proj, g_cfg.sys_extra ? g_cfg.sys_extra : "");
    return sys;
}

/* non-interactive output: plain, claude-code-ish glyphs */
static void p_text(const char *s, void *ud) { (void)ud; fputs(s, stdout); fflush(stdout); }
static void p_think(const char *s, void *ud) { (void)ud; if (!g_cfg.quiet) { printf(DIM "%s" RESET, s); fflush(stdout); } }
static void p_tool(const char *name, const char *c, void *ud) { (void)ud; if (!g_cfg.quiet) { printf(CYAN "⏺" RESET " %s(%.100s%s)\n", name ? name : "Bash", c, strlen(c) > 100 ? "…" : ""); fflush(stdout); } }
static void p_out(const char *o, void *ud) { (void)ud;
    if (g_cfg.quiet) return;
    int nl = 0; const char *s = o;
    for (const char *p = o; *p; p++) if (*p == '\n') nl++;
    if (nl > 8) { int k = nl - 8; while (k-- && (s = strchr(s, '\n'))) s++; }
    printf(GRAY "  ⎿  %.3000s" RESET "\n", s); fflush(stdout);
}
static void p_status(const char *s, void *ud) { (void)s; (void)ud; }
static void p_event(const char *k, const char *d, void *ud) { (void)ud;
    if (!strcmp(k, "prune")) printf(YELLOW "  ⚡ loop pruned (%s)" RESET "\n", d);
    else if (!strcmp(k, "reset")) printf(YELLOW "  ⚡ context reset (%s)" RESET "\n", d);
    fflush(stdout);
}

/* ~/.config/flywheel/config — KEY=value lines; lowest precedence. */
static void load_config(void) {
    const char *home = getenv("HOME");
    if (!home) return;
    char path[1024];
    snprintf(path, sizeof path, "%s/.config/flywheel/config", home);
    char *c = read_file(path);
    if (!c) return;
    for (char *ln = strtok(c, "\n"); ln; ln = strtok(NULL, "\n")) {
        if (*ln == '#' || !strchr(ln, '=')) continue;
        char *eq = strchr(ln, '=');
        *eq++ = 0;
        while (*eq == ' ') eq++;
        char *e = ln + strlen(ln) - 1;
        while (e > ln && (*e == ' ' || *e == '\r')) *e-- = 0;
        if (!strcmp(ln, "endpoint")) { free(g_cfg.endpoint); g_cfg.endpoint = str_dup(eq); }
        else if (!strcmp(ln, "model")) { free(g_cfg.model); g_cfg.model = str_dup(eq); }
        else if (!strcmp(ln, "profile")) g_cfg.profile = str_dup(eq);
        else if (!strcmp(ln, "maxturns")) g_cfg.maxturns = atoi(eq);
        else if (!strcmp(ln, "wall")) g_cfg.wall = atoi(eq);
        else if (!strcmp(ln, "cmd_timeout")) g_cfg.cmd_timeout = atoi(eq);
        else if (!strcmp(ln, "maxtok")) g_cfg.maxtok = atoi(eq);
        else if (!strcmp(ln, "temp")) g_cfg.temp = atof(eq);
        else if (!strcmp(ln, "top_p")) g_cfg.top_p = atof(eq);
        else if (!strcmp(ln, "pp")) g_cfg.pp = atof(eq);
        else if (!strcmp(ln, "think_budget")) g_cfg.think_budget = atoi(eq);
        else if (!strcmp(ln, "gates")) g_cfg.max_gates = atoi(eq);
    }
    free(c);
}

char *fw_build_system(bool interactive) {
    const Profile *prof = profile_detect(g_cfg.cwd, g_cfg.profile);
    return build_system(prof, interactive);
}

/* ---- setup: engine + model bootstrap, always confirmed first ---- */

#define MODEL_REPO "uub336/Qwen3.8-27B-pi-mlx-4bit"
#define DRAFT_REPO "z-lab/Qwen3.8-27B-DFlash2"

static bool have_cmd(const char *c) {
    char b[128];
    snprintf(b, sizeof b, "command -v %s >/dev/null 2>&1", c);
    return system(b) == 0;
}

static bool confirm(const char *q, bool dflt) {
    if (g_cfg.yes) return true;
    printf("%s [%s] ", q, dflt ? "Y/n" : "y/N");
    fflush(stdout);
    char l[16] = {0};
    if (!fgets(l, sizeof l, stdin)) return dflt;
    if (l[0] == '\n' || l[0] == 0) return dflt;
    return l[0] == 'y' || l[0] == 'Y';
}

/* find a downloaded model: ~/models/<short>/config.json first, then the
   HF cache snapshot dir for the repo id (models--a--b--c/snapshots). */
static bool find_model_dir(const char *hf_id, const char *short_name,
                           char *out, size_t cap) {
    const char *home = getenv("HOME") ? getenv("HOME") : "";
    char p[1200];
    snprintf(p, sizeof p, "%s/models/%s/config.json", home, short_name);
    if (access(p, F_OK) == 0) {
        snprintf(out, cap, "%s/models/%s", home, short_name);
        return true;
    }
    snprintf(p, sizeof p, "%s/.cache/huggingface/hub/models--%s/snapshots", home, hf_id);
    DIR *d = opendir(p);
    if (!d) return false;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char cj[1400];
        snprintf(cj, sizeof cj, "%s/%s/config.json", p, e->d_name);
        if (access(cj, F_OK) == 0) {
            snprintf(out, cap, "%s/%s", p, e->d_name);
            closedir(d);
            return true;
        }
    }
    closedir(d);
    return false;
}

/* enumerate repo files via HF API, download each with aria2c */
static int hf_download(const char *repo, const char *dir) {
    char api[512];
    snprintf(api, sizeof api, "https://huggingface.co/api/models/%s", repo);
    char *j = http_get_url(api);
    if (!j) { fprintf(stderr, "hf api unreachable\n"); return 1; }
    cJSON *meta = cJSON_Parse(j);
    free(j);
    if (!meta) { fprintf(stderr, "hf api: bad json\n"); return 1; }
    cJSON *sib = cJSON_GetObjectItemCaseSensitive(meta, "siblings");
    int rc = 0, n = 0;
    char mkdirp[1024];
    snprintf(mkdirp, sizeof mkdirp, "mkdir -p \"%s\"", dir);
    system(mkdirp);
    cJSON *f;
    cJSON_ArrayForEach(f, sib) {
        cJSON *name = cJSON_GetObjectItemCaseSensitive(f, "rfilename");
        if (!cJSON_IsString(name)) continue;
        if (strstr(name->valuestring, ".git")) continue;
        char cmd[2048];
        snprintf(cmd, sizeof cmd,
            "aria2c -x 4 -s 4 -k 1M -c -d \"%s\" -o \"%s\" \"https://huggingface.co/%s/resolve/main/%s\"",
            dir, name->valuestring, repo, name->valuestring);
        printf("↓ %s\n", name->valuestring);
        n++;
        if (system(cmd) != 0) { fprintf(stderr, "failed: %s\n", name->valuestring); rc = 1; break; }
    }
    cJSON_Delete(meta);
    if (!n) { fprintf(stderr, "no files listed for %s\n", repo); return 1; }
    return rc;
}

int fw_do_setup(void) {
    if (!isatty(0) && !g_cfg.yes) { fprintf(stderr, "setup is interactive (or pass --yes)\n"); return 1; }
    int rc = 0;

    /* 1. engine */
    if (!have_cmd("splash")) {
        printf("engine: splash not found\n");
        if (have_cmd("brew") && confirm("install `brew install incoai/tap/splash`?", true)) {
            if (system("brew install incoai/tap/splash") != 0) rc = 1;
        } else printf("skipped — install manually: brew install incoai/tap/splash\n");
    } else printf("engine: splash " GREEN "ok" RESET "\n");

    /* 2. model + drafter — prefer existing copy (models dir or HF cache) */
    const char *home = getenv("HOME") ? getenv("HOME") : "";
    char mdir[1024] = {0}, ddir[1024] = {0};
    if (!find_model_dir("uub336--Qwen3.8-27B-pi-mlx-4bit", "qwen27-pi4", mdir, sizeof mdir)) {
        snprintf(mdir, sizeof mdir, "%s/models/qwen27-pi4", home);
        printf("model: %s (~15GB) not found\n", MODEL_REPO);
        if (have_cmd("aria2c") && confirm("download it now via aria2c?", true))
            rc |= hf_download(MODEL_REPO, mdir);
        else printf("skipped — model required for serving\n");
    } else printf("model: %s " GREEN "ok" RESET "\n", mdir);
    if (!find_model_dir("z-lab--Qwen3.8-27B-DFlash2", "qwen27-dflash2", ddir, sizeof ddir)) {
        snprintf(ddir, sizeof ddir, "%s/models/qwen27-dflash2", home);
        printf("drafter: %s (~1GB) not found\n", DRAFT_REPO);
        if (have_cmd("aria2c") && confirm("download it for speculative decoding?", true))
            rc |= hf_download(DRAFT_REPO, ddir);
    } else printf("drafter: %s " GREEN "ok" RESET "\n", ddir);

    /* 3. serve */
    struct stat st;
    char cj[1200]; snprintf(cj, sizeof cj, "%s/config.json", mdir);
    if (have_cmd("splash") && stat(cj, &st) == 0) {
        char *models = http_get("/models");
        if (models && strstr(models, g_cfg.model)) {
            printf("serve: %s already " GREEN "up" RESET "\n", g_cfg.model);
            free(models);
        } else {
            free(models);
            char sc[2048];
            snprintf(sc, sizeof sc,
                "nohup splash serve --model %s --model-dir '%s' --draft-model '%s' "
                "--port 8312 --language-only --max-concurrent-requests 1 "
                "--thinking-token-budget 1024 --no-webui >/tmp/flywheel-serve.log 2>&1 &",
                g_cfg.model, mdir, ddir);
            if (confirm("start the server now? (detached, tuned flags)", true)) {
                system(sc);
                for (int i = 0; i < 90; i++) {
                    sleep(1);
                    char *m2 = http_get("/models");
                    bool ok = m2 && strstr(m2, g_cfg.model);
                    free(m2);
                    if (ok) { printf("serve: " GREEN "ready" RESET " :8312\n"); return rc; }
                }
                printf("serve: not ready in 90s — see /tmp/flywheel-serve.log\n");
                rc = 1;
            } else printf("start later: %s\n", sc + 6);
        }
    }
    if (!rc) printf("\nsetup complete — run: flywheel init\n");
    return rc;
}

int fw_do_init(void) {
    const Profile *prof = profile_detect(g_cfg.cwd, g_cfg.profile);
    printf("profile: %s\n", prof->name);
    printf("gate:    %s\n", prof->gate_cmd ? prof->gate_cmd : "(none)");
    char md[1024];
    snprintf(md, sizeof md, "%s/.flywheel.md", g_cfg.cwd);
    struct stat st;
    if (stat(md, &st) != 0) {
        const char *base = strrchr(g_cfg.cwd, '/');
        FILE *f = fopen(md, "w");
        if (f) {
            fprintf(f,
                "# %s — flywheel project notes\n\n"
                "Stack: %s\n"
                "Check command: `%s`\n\n"
                "## Conventions\n\n"
                "- build: \n- test: \n- style/gotchas: \n",
                base ? base + 1 : g_cfg.cwd, prof->persona,
                prof->gate_cmd ? prof->gate_cmd : "none");
            fclose(f);
            printf("wrote:   %s (edit to taste — loaded into the system prompt)\n", md);
        }
    } else printf("exists:  %s (left untouched)\n", md);
    char *models = http_get("/models");
    if (!models) {
        printf("engine:  %s — " RED "unreachable" RESET "\n", g_cfg.endpoint);
        if (isatty(0) && confirm("run `flywheel setup` to install engine + model?", true))
            return fw_do_setup();
    } else {
        bool found = strstr(models, g_cfg.model) != NULL;
        printf("engine:  %s — up, model '%s' %s\n", g_cfg.endpoint, g_cfg.model,
               found ? GREEN "found" RESET : YELLOW "NOT served" RESET);
        if (!found && isatty(0) && confirm("run `flywheel setup` to fetch/serve the model?", true))
            return fw_do_setup();
        free(models);
    }
    printf("\nnext: flywheel \"describe the codebase layout\"\n");
    return 0;
}

int main(int argc, char **argv) {
    setlocale(LC_CTYPE, "");
    /* GUI-launched terminals often have no LANG in env; fall back to explicit
       UTF-8 so wcwidth/mbrtowc decode emoji + box glyphs correctly */
    if (wcwidth(0x26A1) < 1) setlocale(LC_CTYPE, "en_US.UTF-8");
    memset(&g_cfg, 0, sizeof g_cfg);
    g_cfg.endpoint = str_dup("http://127.0.0.1:8312/v1");
    g_cfg.model = str_dup("local/qwen-pi4");
    g_cfg.maxturns = 60; g_cfg.wall = 0; g_cfg.cmd_timeout = 30;
    g_cfg.maxtok = 12000; g_cfg.gate_every = 8; g_cfg.max_gates = 1;
    g_cfg.temp = 0.0; g_cfg.top_p = 0.95; g_cfg.pp = 0.0; g_cfg.loop_temp = 0.5;
    g_cfg.color = isatty(1);
    char cwd[1024];
    if (!getcwd(cwd, sizeof cwd)) strcpy(cwd, ".");
    g_cfg.cwd = str_dup(cwd);
    load_config();
    if (getenv("FW_ENDPOINT")) { free(g_cfg.endpoint); g_cfg.endpoint = str_dup(getenv("FW_ENDPOINT")); }
    if (getenv("FW_MODEL")) { free(g_cfg.model); g_cfg.model = str_dup(getenv("FW_MODEL")); }

    const char *subcmd = NULL;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define REQ (i + 1 < argc ? argv[++i] : NULL)
        #define REQD(d) (i + 1 < argc ? argv[++i] : (d))
        if (!strcmp(a, "-e")) g_cfg.endpoint = str_dup(REQ);
        else if (!strcmp(a, "-m")) g_cfg.model = str_dup(REQ);
        else if (!strcmp(a, "-C")) { g_cfg.cwd = str_dup(REQ); }
        else if (!strcmp(a, "-P")) g_cfg.profile = str_dup(REQ);
        else if (!strcmp(a, "-f")) g_cfg.prompt_file = str_dup(REQ);
        else if (!strcmp(a, "-T")) g_cfg.maxturns = atoi(REQD("60"));
        else if (!strcmp(a, "-W")) g_cfg.wall = atoi(REQD("0"));
        else if (!strcmp(a, "-t")) g_cfg.cmd_timeout = atoi(REQD("30"));
        else if (!strcmp(a, "-K")) g_cfg.maxtok = atoi(REQD("12000"));
        else if (!strcmp(a, "--temp")) g_cfg.temp = atof(REQD("0"));
        else if (!strcmp(a, "--topp")) g_cfg.top_p = atof(REQD("0.95"));
        else if (!strcmp(a, "--pp")) g_cfg.pp = atof(REQD("0"));
        else if (!strcmp(a, "--think")) g_cfg.think_budget = atoi(REQD("0"));
        else if (!strcmp(a, "--gates")) g_cfg.max_gates = atoi(REQD("1"));
        else if (!strcmp(a, "--transcript")) g_cfg.transcript = str_dup(REQ);
        else if (!strcmp(a, "--sys")) g_cfg.sys_extra = str_dup(REQ);
        else if (!strcmp(a, "--no-color")) g_cfg.color = false;
        else if (!strcmp(a, "-q")) g_cfg.quiet = true;
        else if (!strcmp(a, "-y") || !strcmp(a, "--yes")) g_cfg.yes = true;
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(stdout); return 0; }
        else if (!strcmp(a, "init") || !strcmp(a, "setup")) subcmd = a;
        else if (!strcmp(a, "bench")) {
            signal(SIGINT, on_sigint);
            curl_global_init(CURL_GLOBAL_DEFAULT);
            int rc = fw_do_bench(argc - i - 1, argv + i + 1);
            curl_global_cleanup();
            return rc;
        }
        else if (a[0] != '-') g_cfg.once = str_dup(a);
        else { fprintf(stderr, "unknown flag: %s\n", a); usage(stderr); return 2; }
        #undef REQ
        #undef REQD
    }
    if (!g_cfg.color) {
        /* strip color: redefine as empty via env trick — simplest: codes stay but that's fine on pipe */
    }

    signal(SIGINT, on_sigint);
    curl_global_init(CURL_GLOBAL_DEFAULT);
    if (subcmd) return !strcmp(subcmd, "init") ? fw_do_init() : fw_do_setup();

    const Profile *prof = profile_detect(g_cfg.cwd, g_cfg.profile);

    char *prompt = NULL;
    if (g_cfg.prompt_file) prompt = read_file(g_cfg.prompt_file);
    else if (g_cfg.once) prompt = str_dup(g_cfg.once);
    else if (!isatty(0)) prompt = read_file("/dev/stdin");

    char *sysp = build_system(prof, prompt == NULL);

    if (prompt) {
        /* non-interactive one-shot */
        Msgs msgs; msgs_init(&msgs);
        msgs_push(&msgs, "system", sysp);
        msgs_push(&msgs, "user", prompt);
        Ui ui = {.emit_text = p_text, .emit_think = p_think, .emit_tool = p_tool,
                 .emit_out = p_out, .emit_status = p_status, .emit_event = p_event,
                 .interactive = false};
        char sum[256];
        const char *fin = agent_run(&msgs, &ui, sum, sizeof sum);
        printf("\n" GREEN "●" RESET " flywheel: %s\n", sum);
        msgs_free(&msgs);
        curl_global_cleanup();
        return !strcmp(fin, "done") ? 0 : 1;
    }

    /* interactive */
    static Msgs msgs;
    msgs_init(&msgs);
    msgs_push(&msgs, "system", sysp);
    free(sysp);
    g_msgs_link(&msgs);
    tui_repl();
    tui_cleanup();
    perm_free();
    msgs_free(&msgs);
    curl_global_cleanup();
    return 0;
}
