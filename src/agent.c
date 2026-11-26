#include "flywheel.h"
#include <time.h>

#define MAXRECENT 16
#define MAXPRUNES 8
#define MAXRESETS 2

typedef struct {
    char *cmds[MAXRECENT];
    int n;
} Recent;

static void rec_push(Recent *r, const char *c) {
    if (r->n == MAXRECENT) { free(r->cmds[0]); memmove(r->cmds, r->cmds + 1, (MAXRECENT - 1) * sizeof(char *)); r->n--; }
    r->cmds[r->n++] = str_dup(c);
}
static void rec_clear(Recent *r) { for (int i = 0; i < r->n; i++) free(r->cmds[i]); r->n = 0; }
static void rec_free(Recent *r) { rec_clear(r); }

static const char *detect_loop(Recent *r, int *clen) {
    int n = r->n;
    if (n >= 3 && sim_ratio(r->cmds[n-1], r->cmds[n-2]) > 0.82
              && sim_ratio(r->cmds[n-2], r->cmds[n-3]) > 0.82) { *clen = 3; return "p1"; }
    if (n >= 4 && sim_ratio(r->cmds[n-1], r->cmds[n-3]) > 0.82
              && sim_ratio(r->cmds[n-2], r->cmds[n-4]) > 0.82) { *clen = 4; return "p2"; }
    if (n >= 6 && sim_ratio(r->cmds[n-1], r->cmds[n-4]) > 0.82
              && sim_ratio(r->cmds[n-2], r->cmds[n-5]) > 0.82
              && sim_ratio(r->cmds[n-3], r->cmds[n-6]) > 0.82) { *clen = 6; return "p3"; }
    if (n >= 5) {
        int cnt = 0, lo = n - 8 < 0 ? 0 : n - 8;
        for (int i = lo; i < n - 1; i++)
            if (sim_ratio(r->cmds[i], r->cmds[n-1]) > 0.88) cnt++;
        if (cnt >= 3) { *clen = 3; return "rep"; }
    }
    return NULL;
}

static char *gate_out(const Profile *prof, const char *cwd) {
    if (!prof->gate_cmd) return str_dup("");
    return run_bash(prof->gate_cmd, cwd, g_cfg.cmd_timeout * 2);
}

static bool gate_fails(const Profile *prof, const char *out) {
    if (!prof->gate_cmd) return false;
    if (!strcmp(prof->name, "ts")) return strstr(out, "error TS") != NULL;
    return strstr(out, "error") != NULL || strstr(out, "Error") != NULL;
}

static void emit(Ui *ui, void (*fn)(const char *, void *), const char *s) {
    if (fn) fn(s, ui->ud);
}
static void event(Ui *ui, const char *kind, const char *detail) {
    if (ui->emit_event) ui->emit_event(kind, detail, ui->ud);
}

const char *agent_run(Msgs *msgs, Ui *ui, char *sum, size_t sumcap) {
    const Profile *prof = profile_detect(g_cfg.cwd, g_cfg.profile);
    Recent rec = {0};
    int *starts = malloc((g_cfg.maxturns + 8) * sizeof(int));
    int prunes = 0, gates = 0, resets = 0, toks = 0, ptoks = 0, calls = 0, turns = 0;
    double secs = 0;
    bool wrote = false;
    int escape_turns = 0;
    time_t wall0 = time(NULL);
    const char *finish = "turns";
    FILE *tr = g_cfg.transcript ? fopen(g_cfg.transcript, "a") : NULL;

    for (int turn = 0; turn < g_cfg.maxturns; turn++) {
        if (g_cfg.wall && time(NULL) - wall0 > g_cfg.wall) { finish = "wall"; break; }
        if (g_abort) { finish = "aborted"; break; }
        starts[turn] = msgs->n;
        double base_t = g_cfg.temp, base_pp = g_cfg.pp;
        if (escape_turns > 0) { g_cfg.temp = base_t > g_cfg.loop_temp ? base_t : g_cfg.loop_temp;
                                if (g_cfg.pp < 0.25) g_cfg.pp = 0.25; escape_turns--; }
        char stbuf[128];
        snprintf(stbuf, sizeof stbuf, "turn %d · %d tok", turn, toks);
        emit(ui, ui->emit_status, stbuf);

        StreamCb scb = {.on_text = ui->emit_text, .on_think = ui->emit_think,
                        .ud = ui->ud, .stream = ui->interactive};
        /* transient transport errors (server busy, connection reset, engine
           restart) must not kill a benchmark run — retry with backoff.
           user aborts and malformed-response errors stay fatal. */
        ChatResp *r = NULL;
        for (int attempt = 0; attempt < 4; attempt++) {
            r = chat(msgs, &scb);
            if (!r || !r->error) break;
            int transient = !strcmp(r->error, "aborted") ? 0 :
                (!strncmp(r->error, "http:", 5) || !strncmp(r->error, "curl:", 5) ||
                 strstr(r->error, "connect") || strstr(r->error, "timeout") ||
                 strstr(r->error, "read failed") || strstr(r->error, "closed") != NULL);
            if (!transient || attempt == 3) break;
            if (ui->emit_text) {
                char nb[160];
                snprintf(nb, sizeof nb, "\n[transport: %.60s — retry %d/3]\n", r->error, attempt + 1);
                ui->emit_text(nb, ui->ud);
            }
            chat_resp_free(r);
            r = NULL;
            struct timespec ts = {.tv_sec = 2 << attempt, .tv_nsec = 0};
            nanosleep(&ts, NULL);
            if (g_abort) break;
        }
        g_cfg.temp = base_t;
        g_cfg.pp = base_pp;
        if (!r || r->error) {
            static char ferr[96];
            snprintf(ferr, sizeof ferr, "error:%.80s", r && r->error ? r->error : "null");
            finish = ferr;
            if (r) chat_resp_free(r);
            break;
        }
        if (r->prompt_tokens > 0) ptoks = r->prompt_tokens;
        toks += r->completion_tokens;
        secs += r->secs;
        turns++;
        if (ui->emit_stats) {
            AgentStats st = {
                .turns = turns, .calls = calls, .prunes = prunes, .gates = gates, .resets = resets,
                .prompt_tokens = ptoks, .completion_tokens = toks, .secs = secs,
                .tok_per_sec = (r->secs > 0.05 && r->completion_tokens > 0)
                               ? (r->completion_tokens / r->secs)
                               : (secs > 0.05 ? toks / secs : 0.0),
                .finish = NULL
            };
            ui->emit_stats(&st, ui->ud);
        }
        cJSON *tcs = r->tool_calls ? cJSON_Duplicate(r->tool_calls, 1) : NULL;
        msgs_push_assistant(msgs, r->content, tcs);
        if (tr) {
            cJSON *e = cJSON_CreateObject();
            cJSON_AddNumberToObject(e, "turn", turn);
            cJSON_AddNumberToObject(e, "tokens", r->completion_tokens);
            cJSON_AddNumberToObject(e, "dt", r->secs);
            cJSON_AddStringToObject(e, "finish", r->finish);
            if (r->content) cJSON_AddStringToObject(e, "content", r->content);
            cJSON *ca = cJSON_CreateArray();
            cJSON *tc;
            if (r->tool_calls)
            cJSON_ArrayForEach(tc, r->tool_calls) {
                cJSON *fn = cJSON_GetObjectItemCaseSensitive(tc, "function");
                cJSON *ar = fn ? cJSON_GetObjectItemCaseSensitive(fn, "arguments") : NULL;
                if (cJSON_IsString(ar)) cJSON_AddItemToArray(ca, cJSON_CreateString(ar->valuestring));
            }
            cJSON_AddItemToObject(e, "calls", ca);
            char *line = cJSON_PrintUnformatted(e);
            fprintf(tr, "%s\n", line);
            free(line); cJSON_Delete(e);
        }

        int ntcs = tcs ? cJSON_GetArraySize(tcs) : 0;
        if (ntcs == 0) {
            /* no tool call this turn */
            char gbuf[4096];
            if (!ui->interactive && !wrote && turn < g_cfg.maxturns - 3) {
                msgs_push(msgs, "user",
                    "You have not written any implementation files yet. Write the required files now, test them, and run the type check.");
                chat_resp_free(r);
                continue;
            }
            if (prof->gate_cmd && (!ui->interactive || wrote)) {
                char *go = gate_out(prof, g_cfg.cwd);
                if (gate_fails(prof, go) && turn < g_cfg.maxturns - 2) {
                    snprintf(gbuf, sizeof gbuf,
                        "`%s` failed. Fix all errors and remove broken scratch files, then verify and reply DONE:\n%.1800s",
                        prof->gate_cmd, go);
                    msgs_push(msgs, "user", gbuf);
                    free(go); chat_resp_free(r);
                    continue;
                }
                free(go);
            }
            if ((!ui->interactive || wrote) && !strcmp(r->finish, "stop") && gates < g_cfg.max_gates && turn < g_cfg.maxturns - 4) {
                gates++;
                msgs_push(msgs, "user",
                    "Before finishing: list every requirement bullet in the task prompt and verify each one with a quick script or test run against your code (edge cases, error classes/shapes, concurrency, ordering, cleanup, defaults). Fix any mismatch, remove scratch files, make sure the type check is clean, then reply DONE.");
                event(ui, "gate", "verification pass");
                chat_resp_free(r);
                continue;
            }
            finish = !strcmp(r->finish, "stop") ? "done" : (r->finish[0] ? r->finish : "stop");
            chat_resp_free(r);
            break;
        }

        /* execute tool calls */
        cJSON *tc;
        cJSON_ArrayForEach(tc, tcs) {
            calls++;
            cJSON *fn = cJSON_GetObjectItemCaseSensitive(tc, "function");
            cJSON *ar = fn ? cJSON_GetObjectItemCaseSensitive(fn, "arguments") : NULL;
            cJSON *id = cJSON_GetObjectItemCaseSensitive(tc, "id");
            cJSON *nm = fn ? cJSON_GetObjectItemCaseSensitive(fn, "name") : NULL;
            const char *tname = cJSON_IsString(nm) ? nm->valuestring : "bash";
            const char *rawargs = cJSON_IsString(ar) ? ar->valuestring : "";
            char *out = NULL;
            char reckey[1200] = "";

            if (!strcmp(tname, "write_file") || !strcmp(tname, "edit_file")) {
                bool iswrite = !strcmp(tname, "write_file");
                char *path = args_extract_key(rawargs, "path");
                char *a = args_extract_key(rawargs, iswrite ? "content" : "old_string");
                char *b = iswrite ? NULL : args_extract_key(rawargs, "new_string");
                if (ui->emit_tool) ui->emit_tool(iswrite ? "Write" : "Edit", path, ui->ud);
                char permstr[1200];
                snprintf(permstr, sizeof permstr, "%s %s", tname, path);
                bool unapproved = ui->approve_cmd && !perm_allowed(permstr) && !ui->approve_cmd(permstr, ui->ud);
                if (!*path) out = str_dup("error: bad arguments, need \"path\"");
                else if (!*a) out = str_dup(iswrite
                    ? "error: bad arguments, need \"content\" — write the complete file content"
                    : "error: bad arguments, need \"old_string\"");
                else if (unapproved) out = str_dup("error: user denied this — adapt, explain why it is needed, or try another approach");
                else out = iswrite ? tool_write_file(g_cfg.cwd, path, a)
                                   : tool_edit_file(g_cfg.cwd, path, a, b ? b : "");
                if (!strncmp(out, "ok:", 3)) wrote = true;
                snprintf(reckey, sizeof reckey, "%s", permstr);
                free(path); free(a); free(b);
            } else if (!strcmp(tname, "bash") || !strcmp(tname, "shell")) {
                char *command = args_extract_command(rawargs);
                char *fixed = heredoc_fix(command);
                free(command);
                if (ui->emit_tool) ui->emit_tool("Bash", fixed, ui->ud);
                const char *denied = deny_check(fixed, g_cfg.cwd);
                bool unapproved = ui->approve_cmd && !perm_allowed(fixed) && !ui->approve_cmd(fixed, ui->ud);
                if (!*fixed) out = str_dup("error: bad arguments, need {\"command\": ...}");
                else if (denied) out = str_dup(denied);
                else if (unapproved) out = str_dup("error: user denied this command — adapt, explain why it is needed, or try another approach");
                else out = run_bash(fixed, g_cfg.cwd, g_cfg.cmd_timeout);
                if (cmd_is_write(fixed)) wrote = true;
                snprintf(reckey, sizeof reckey, "%.1100s", fixed);
                free(fixed);
            } else {
                char eb[200];
                snprintf(eb, sizeof eb, "error: unknown tool '%.40s' — use bash, write_file or edit_file", tname);
                out = str_dup(eb);
                snprintf(reckey, sizeof reckey, "unknown:%.40s", tname);
            }
            emit(ui, ui->emit_out, out);
            msgs_push_tool(msgs, cJSON_IsString(id) ? id->valuestring : "", out);
            rec_push(&rec, reckey);
            if (tr) {
                cJSON *e = cJSON_CreateObject();
                cJSON_AddStringToObject(e, "tool_out", out);
                char *line = cJSON_PrintUnformatted(e);
                fprintf(tr, "%s\n", line); free(line); cJSON_Delete(e);
            }
            free(out);
        }
        chat_resp_free(r);

        /* periodic gate */
        if (g_cfg.gate_every && wrote && turn % g_cfg.gate_every == g_cfg.gate_every - 1
            && turn < g_cfg.maxturns - 5 && prof->gate_cmd) {
            char *go = gate_out(prof, g_cfg.cwd);
            if (gate_fails(prof, go)) {
                char gb[4096];
                snprintf(gb, sizeof gb,
                    "Automatic type check: `%s` currently reports errors. Fix these first, they fail grading:\n%.1800s",
                    prof->gate_cmd, go);
                msgs_push(msgs, "user", gb);
                event(ui, "gate", "auto typecheck failed");
            }
            free(go);
        }

        /* loop detect */
        int clen = 0;
        const char *kind = detect_loop(&rec, &clen);
        if (kind && prunes < MAXPRUNES) {
            int cut = clen < turns ? clen : turns;
            int at = starts[turn - cut + 1];
            const char *lastout = msgs->n && !strcmp(msgs->v[msgs->n-1].role, "tool")
                                  && msgs->v[msgs->n-1].content ? msgs->v[msgs->n-1].content : "";
            char last600[640]; snprintf(last600, sizeof last600, "%.600s", lastout);
            msgs_trunc(msgs, at);
            prunes++;
            rec_clear(&rec);
            escape_turns = 2;
            char *go = gate_out(prof, g_cfg.cwd);
            char *files = run_bash(
                "find . -maxdepth 3 -path ./node_modules -prune -o -type f \\( -name '*.ts' -o -name '*.tsx' -o -name '*.py' -o -name '*.go' -o -name '*.rs' -o -name '*.js' \\) -print | head -25",
                g_cfg.cwd, 10);
            char pb[8192];
            if (prunes % 2 == 0 && resets < MAXRESETS) {
                resets++;
                /* context reset: keep system+task, then a reset msg */
                msgs_trunc(msgs, 2);
                snprintf(pb, sizeof pb,
                    "Context reset after repeated %s loop. Your saved files:\n%s\nCurrent type check:\n%.1000s\nRe-read the task prompt carefully. Inspect the existing files, find what is still missing or wrong versus the requirements, fix it with a different approach, verify the type check is clean, and reply DONE.",
                    kind, files, go);
                msgs_push(msgs, "user", pb);
                event(ui, "reset", kind);
            } else {
                snprintf(pb, sizeof pb,
                    "Loop detected (%s): your last %d turns repeated the same actions without progress and were pruned. Last output:\n%s\nFiles:\n%s\nCurrent type check:\n%.1000s\nDo NOT repeat that command cycle. Step back, diagnose the root cause differently, fix cleanly, and if checks pass, reply DONE.",
                    kind, clen, last600, files, go);
                msgs_push(msgs, "user", pb);
                event(ui, "prune", kind);
            }
            free(go); free(files);
            continue;
        }

        /* nudges */
        if (!wrote && (turn == 6 || turn == 12 || turn == 18))
            msgs_push(msgs, "user", "You have not written any file yet. Stop exploring: write the implementation now, then run the type check.");
        else if (turn == g_cfg.maxturns - 5)
            msgs_push(msgs, "user", "5 turns left. Make sure all required files exist, remove any broken scratch files, confirm the type check is clean, then reply DONE.");
    }

    if (ui->emit_stats) {
        AgentStats st = {
            .turns = turns, .calls = calls, .prunes = prunes, .gates = gates, .resets = resets,
            .prompt_tokens = ptoks, .completion_tokens = toks, .secs = secs,
            .tok_per_sec = secs > 0.05 ? (toks / secs) : 0.0,
            .finish = finish
        };
        ui->emit_stats(&st, ui->ud);
    }
    if (sum)
        snprintf(sum, sumcap,
                 "finish=%s turns=%d prunes=%d gates=%d resets=%d calls=%d tokens=%d secs=%.0f",
                 finish, turns, prunes, gates, resets, calls, toks, secs);
    if (tr) fclose(tr);
    rec_free(&rec);
    free(starts);
    return finish;
}
