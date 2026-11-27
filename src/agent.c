#include "flywheel.h"
#include <time.h>

#define MAXPRUNES 8
#define MAXRESETS 2

#define NOT_RUN "(not run: the user declined this check; its result is unknown, do not report it as passing)"

static void emit(Ui *ui, void (*fn)(const char *, void *), const char *s) {
    if (fn) fn(s, ui->ud);
}
static void event(Ui *ui, const char *kind, const char *detail) {
    if (ui->emit_event) ui->emit_event(kind, detail, ui->ud);
}

static bool timed_out(const char *gate_output) {
    return !strncmp(gate_output, "[timeout after", 14);
}

/* The gate runs project code, so an interactive user approves it first. A
   denial holds for the rest of the task (*denied). Never NULL; when not run,
   *failed is false and the text says so. *check is the outcome of the last
   check that did run: NULL when it passed, untouched when it did not run. */
static char *gate_out(const Profile *prof, Ui *ui, bool *denied, bool *failed,
                      const char **check) {
    *failed = false;
    if (!prof->gate_cmd) return str_dup("");
    if (!*denied && ui->approve_cmd) {
        /* gate_cmd is exactly what gate_run executes */
        if (!perm_gate_allowed(prof->gate_cmd) && !ui->approve_cmd(prof->gate_cmd, true, ui->ud)) {
            *denied = true;
            char what[256];
            snprintf(what, sizeof what, "check not run (denied): %s", prof->gate_cmd);
            event(ui, "gate", what);
        }
    }
    if (*denied) return str_dup(NOT_RUN);
    if (g_abort) return str_dup("(not run: aborted)");
    char *out = gate_run(prof, g_cfg.cwd, g_cfg.cmd_timeout * 2, failed);
    if (!g_abort)
        *check = !*failed ? NULL : timed_out(out) ? "check-timeout" : "check-failed";
    return out;
}

/* FNV-1a; the terminating NUL separates consecutive strings */
static unsigned long long fnv1a(unsigned long long h, const char *s) {
    do h = (h ^ (unsigned char)*s) * 1099511628211ULL; while (*s++);
    return h;
}

/* bash result for the model: output plus how the command ended, if not cleanly
   (a timeout is already announced at the top of the output) */
static char *bash_out(const char *cmd) {
    int code;
    char *out = run_bash_status(cmd, g_cfg.cwd, g_cfg.cmd_timeout, &code);
    if (!code || (code < 0 && (!strncmp(out, "[timeout after", 14) || !strcmp(out, "error: pipe failed"))))
        return out;
    char st[48] = "[killed by a signal]";
    if (code > 0) snprintf(st, sizeof st, "[exit status %d]", code);
    size_t n = strlen(out), cap = n + sizeof st + 2;
    char *r = malloc(cap);
    snprintf(r, cap, "%s%s%s", out, n && out[n - 1] == '\n' ? "" : "\n", st);
    free(out);
    return r;
}

static bool wall_over(time_t wall0) {
    return g_cfg.wall && time(NULL) - wall0 >= g_cfg.wall;
}

const char *agent_run(Msgs *msgs, Ui *ui, char *sum, size_t sumcap) {
    const Profile *prof = profile_detect(g_cfg.cwd, g_cfg.profile);
    Recent rec = {0};
    int prunes = 0, gates = 0, resets = 0, toks = 0, ptoks = 0, calls = 0, turns = 0;
    double secs = 0;
    const char *check = NULL;   /* set while the last check that ran did not pass */
    bool wrote = false, gate_denied = false;
    int escape_turns = 0, slow_gates = 0;
    time_t wall0 = time(NULL);
    const char *finish = "turns";
    /* the current task is the newest user message (a REPL has older ones) */
    int task = msgs->n - 1;
    while (task > 0 && strcmp(msgs->v[task].role, "user")) task--;
    char *taskmsg = str_dup(task >= 0 && msgs->v[task].content ? msgs->v[task].content : "");
    FILE *tr = g_cfg.transcript ? fopen(g_cfg.transcript, "a") : NULL;

    for (int turn = 0; turn < g_cfg.maxturns; turn++) {
        if (g_cfg.wall && time(NULL) - wall0 > g_cfg.wall) { finish = "wall"; break; }
        if (g_abort) { finish = "aborted"; break; }
        double base_t = g_cfg.temp, base_pp = g_cfg.pp;
        if (escape_turns > 0) { g_cfg.temp = base_t > g_cfg.loop_temp ? base_t : g_cfg.loop_temp;
                                if (g_cfg.pp < 0.25) g_cfg.pp = 0.25; escape_turns--; }
        char stbuf[128];
        snprintf(stbuf, sizeof stbuf, "turn %d · %d tok", turn, toks);
        emit(ui, ui->emit_status, stbuf);

        StreamCb scb = {.on_text = ui->emit_text, .on_think = ui->emit_think,
                        .ud = ui->ud, .stream = 1};
        /* transient transport errors (server busy, connection reset, engine
           restart) must not kill a benchmark run — retry with backoff.
           user aborts and malformed-response errors stay fatal. */
        ChatResp *r = NULL;
        for (int attempt = 0; attempt < 4; attempt++) {
            /* a request may not outlive the wall clock */
            long left = g_cfg.wall ? g_cfg.wall - (long)(time(NULL) - wall0) : 0;
            g_cfg.req_timeout = g_cfg.wall ? (left > 1 ? (int)left : 1) : 0;
            r = chat(msgs, &scb);
            if (!r || !r->error) break;
            int transient = !strcmp(r->error, "aborted") ? 0 :
                (!strncmp(r->error, "http:", 5) || !strncmp(r->error, "curl:", 5) ||
                 strstr(r->error, "connect") || strstr(r->error, "timeout") ||
                 strstr(r->error, "read failed") || strstr(r->error, "closed") != NULL);
            if (!transient || attempt == 3 || wall_over(wall0)) break;
            if (ui->emit_text) {
                char nb[160];
                snprintf(nb, sizeof nb, "\n[transport: %.60s — retry %d/3]\n", r->error, attempt + 1);
                ui->emit_text(nb, ui->ud);
            }
            chat_resp_free(r);
            r = NULL;
            struct timespec ts = {.tv_sec = 2 << attempt, .tv_nsec = 0};
            nanosleep(&ts, NULL);
            if (g_abort || wall_over(wall0)) break;
        }
        g_cfg.req_timeout = 0;
        g_cfg.temp = base_t;
        g_cfg.pp = base_pp;
        if (!r || r->error) {
            static char ferr[224];
            snprintf(ferr, sizeof ferr, "error:%.200s", r && r->error ? r->error : "null");
            finish = !g_abort && wall_over(wall0) ? "wall" : ferr;
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
                .finish = NULL, .check_skipped = gate_denied
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
            if (ui->deliverable && !wrote && turn < g_cfg.maxturns - 3) {
                msgs_push(msgs, "user",
                    "You have not written any implementation files yet. Write the required files now, test them, and run the type check.");
                chat_resp_free(r);
                continue;
            }
            if (prof->gate_cmd && (ui->deliverable || wrote)) {
                bool bad;
                char *go = gate_out(prof, ui, &gate_denied, &bad, &check);
                if (g_abort) { finish = "aborted"; free(go); chat_resp_free(r); break; }
                bool slow = bad && timed_out(go);
                /* a check that hangs is reported once, not retried until the cap */
                if (bad && !(slow && slow_gates++) && turn < g_cfg.maxturns - 2) {
                    snprintf(gbuf, sizeof gbuf,
                        "`%s` %s. Fix all errors, remove only broken scratch files you created yourself, then verify and reply DONE:\n%.1800s",
                        prof->gate_cmd, slow ? "timed out" : "failed", go);
                    msgs_push(msgs, "user", gbuf);
                    free(go); chat_resp_free(r);
                    continue;
                }
                free(go);
            }
            if ((ui->deliverable || wrote) && !strcmp(r->finish, "stop") && gates < g_cfg.max_gates && turn < g_cfg.maxturns - 4) {
                gates++;
                snprintf(gbuf, sizeof gbuf, "%s%s%s",
                    "Before finishing: list every requirement bullet in the task prompt and verify each one with a quick script or test run against your code (edge cases, error classes/shapes, concurrency, ordering, cleanup, defaults). Fix any mismatch, remove only scratch files you created yourself (never delete files you did not create), make sure the type check is clean, then reply DONE.",
                    gate_denied ? "\nThe automatic check was not run: " : "", gate_denied ? NOT_RUN : "");
                msgs_push(msgs, "user", gbuf);
                event(ui, "gate", "verification pass");
                chat_resp_free(r);
                continue;
            }
            static char fbuf[64];   /* r is freed below */
            snprintf(fbuf, sizeof fbuf, "%s", r->finish[0] ? r->finish : "stop");
            finish = strcmp(fbuf, "stop") ? fbuf : check ? check : "done";
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

            /* Esc stops the rest of the batch; a cut-off response is never run */
            const char *skip = g_abort ? "error: aborted by user — not executed"
                : !strcmp(r->finish, "length")
                ? "error: response was cut off (finish=length) — tool call not executed; resend a shorter, complete call"
                : NULL;
            if (skip) {
                out = str_dup(skip);
                snprintf(reckey, sizeof reckey, "skipped:%.40s", tname);
            } else if (!strcmp(tname, "write_file") || !strcmp(tname, "edit_file")) {
                bool iswrite = !strcmp(tname, "write_file");
                cJSON *args = args_parse_strict(rawargs);
                cJSON *jp = cJSON_GetObjectItemCaseSensitive(args, "path");
                cJSON *ja = cJSON_GetObjectItemCaseSensitive(args, iswrite ? "content" : "old_string");
                cJSON *jb = iswrite ? NULL : cJSON_GetObjectItemCaseSensitive(args, "new_string");
                const char *path = cJSON_IsString(jp) ? jp->valuestring : "";
                const char *a = cJSON_IsString(ja) ? ja->valuestring : "";
                if (ui->emit_tool) ui->emit_tool(iswrite ? "Write" : "Edit", path, ui->ud);
                size_t permlen = strlen(tname) + strlen(path) + 2;
                char *permstr = malloc(permlen);   /* approval sees the whole path */
                snprintf(permstr, permlen, "%s %s", tname, path);
                if (!args) out = str_dup("error: bad arguments: not complete valid JSON (truncated?) — nothing was changed; resend the whole call");
                else if (!*path) out = str_dup("error: bad arguments, need \"path\"");
                else if (iswrite ? !cJSON_IsString(ja) : !*a) out = str_dup(iswrite
                    ? "error: bad arguments, need \"content\" — write the complete file content"
                    : "error: bad arguments, need \"old_string\"");
                else if (!iswrite && !cJSON_IsString(jb)) out = str_dup("error: bad arguments, need \"new_string\"");
                else if (ui->approve_cmd && !perm_allowed(permstr) && !ui->approve_cmd(permstr, false, ui->ud))
                    out = str_dup("error: user denied this — adapt, explain why it is needed, or try another approach");
                else if (g_abort) out = str_dup("error: aborted by user — not executed");
                else out = iswrite ? tool_write_file(g_cfg.cwd, path, a)
                                   : tool_edit_file(g_cfg.cwd, path, a, jb->valuestring);
                if (!strncmp(out, "ok:", 3)) wrote = true;
                /* an edit that took effect is its text, not only its path; \001
                   makes the loop breaker compare these keys exactly. Failed
                   ones stay comparable by similarity, so retries are a loop */
                if (!strncmp(out, "ok:", 3)) {
                    unsigned long long h = fnv1a(fnv1a(fnv1a(14695981039346656037ULL, path), a),
                                                 cJSON_IsString(jb) ? jb->valuestring : "");
                    snprintf(reckey, sizeof reckey, "\001%016llx %.1100s", h, permstr);
                } else snprintf(reckey, sizeof reckey, "%.1100s", permstr);
                free(permstr);
                cJSON_Delete(args);
            } else if (!strcmp(tname, "bash") || !strcmp(tname, "shell")) {
                /* strict: an auto-closed or key-scanned command is never run */
                cJSON *args = args_parse_strict(rawargs);
                cJSON *jc = cJSON_GetObjectItemCaseSensitive(args, "command");
                char *fixed = heredoc_fix(cJSON_IsString(jc) ? jc->valuestring : "");
                cJSON_Delete(args);
                if (ui->emit_tool) ui->emit_tool("Bash", fixed, ui->ud);
                if (!*fixed) {
                    out = str_dup("error: bad arguments: need {\"command\": ...}, not complete valid JSON "
                                  "(truncated?) or empty — not executed; resend the whole call");
                    snprintf(reckey, sizeof reckey, "badargs:%.1100s", rawargs);
                } else {
                    const char *denied = deny_check(fixed, g_cfg.cwd);
                    /* never ask about a command that will be refused anyway */
                    bool unapproved = !denied && ui->approve_cmd && !perm_allowed(fixed) &&
                                      !ui->approve_cmd(fixed, false, ui->ud);
                    if (denied) out = str_dup(denied);
                    else if (unapproved) out = str_dup("error: user denied this command — adapt, explain why it is needed, or try another approach");
                    else if (g_abort) out = str_dup("error: aborted by user — not executed");
                    else {
                        out = bash_out(fixed);
                        if (cmd_is_write(fixed)) wrote = true;
                    }
                    snprintf(reckey, sizeof reckey, "%.1100s", fixed);
                }
                free(fixed);
            } else {
                char eb[200];
                snprintf(eb, sizeof eb, "error: unknown tool '%.40s' — use bash, write_file or edit_file", tname);
                out = str_dup(eb);
                snprintf(reckey, sizeof reckey, "unknown:%.40s", tname);
            }
            emit(ui, ui->emit_out, out);
            msgs_push_tool(msgs, cJSON_IsString(id) ? id->valuestring : "", out);
            rec_push(&rec, reckey, out);
            if (tr) {
                cJSON *e = cJSON_CreateObject();
                cJSON_AddStringToObject(e, "tool_out", out);
                char *line = cJSON_PrintUnformatted(e);
                fprintf(tr, "%s\n", line); free(line); cJSON_Delete(e);
            }
            free(out);
        }
        chat_resp_free(r);
        if (g_abort) { finish = "aborted"; break; }

        /* periodic gate */
        if (g_cfg.gate_every && wrote && turn % g_cfg.gate_every == g_cfg.gate_every - 1
            && turn < g_cfg.maxturns - 5 && prof->gate_cmd) {
            bool bad, was = gate_denied;
            char *go = gate_out(prof, ui, &gate_denied, &bad, &check);
            if (gate_denied && !was)
                msgs_push(msgs, "user", "The automatic check was not run: " NOT_RUN);
            if (bad) {
                char gb[4096];
                snprintf(gb, sizeof gb,
                    "Automatic type check: `%s` %s. Fix these first, they fail grading:\n%.1800s",
                    prof->gate_cmd, timed_out(go) ? "timed out" : "currently reports errors", go);
                msgs_push(msgs, "user", gb);
                event(ui, "gate", timed_out(go) ? "auto typecheck timed out" : "auto typecheck failed");
            }
            free(go);
        }

        /* loop detect */
        int clen = 0;
        const char *kind = detect_loop(&rec, &clen);
        if (kind && prunes < MAXPRUNES) {
            /* clen counts tool calls, and one turn may hold several: cut back to
               the turn that made the oldest of them, never into the task */
            int at = msgs->n, seen = 0, cut = 0;
            while (at > task + 1 && seen < clen)
                if (!strcmp(msgs->v[--at].role, "tool")) seen++;
            while (at > task + 1 && !strcmp(msgs->v[at].role, "tool")) at--;
            for (int k = at; k < msgs->n; k++)
                if (!strcmp(msgs->v[k].role, "assistant")) cut++;
            const char *lastout = msgs->n && !strcmp(msgs->v[msgs->n-1].role, "tool")
                                  && msgs->v[msgs->n-1].content ? msgs->v[msgs->n-1].content : "";
            char last600[640]; snprintf(last600, sizeof last600, "%.600s", lastout);
            msgs_trunc(msgs, at);
            prunes++;
            rec_clear(&rec);
            escape_turns = 2;
            bool bad;
            char *go = gate_out(prof, ui, &gate_denied, &bad, &check);
            char *files = run_bash(
                "find . -maxdepth 3 \\( -name node_modules -o -name .git \\) -prune -o -type f -print | head -40",
                g_cfg.cwd, 10);
            char pb[8192];
            if (prunes % 2 == 0 && resets < MAXRESETS) {
                resets++;
                /* context reset: keep system + current task, then a reset msg */
                msgs_trunc(msgs, task > 0 ? 1 : 0);
                msgs_push(msgs, "user", taskmsg);
                task = msgs->n - 1;
                snprintf(pb, sizeof pb,
                    "Context reset after repeated %s loop. Your saved files:\n%s\nCurrent type check:\n%.1000s\nRe-read the task prompt carefully. Inspect the existing files, find what is still missing or wrong versus the requirements, fix it with a different approach, verify the type check is clean, and reply DONE.",
                    kind, files, go);
                msgs_push(msgs, "user", pb);
                event(ui, "reset", kind);
            } else {
                snprintf(pb, sizeof pb,
                    "Loop detected (%s): your last %d turn(s) repeated the same actions without progress and were pruned. Last output:\n%s\nFiles:\n%s\nCurrent type check:\n%.1000s\nDo NOT repeat that command cycle. Step back, diagnose the root cause differently, fix cleanly, and if checks pass, reply DONE.",
                    kind, cut, last600, files, go);
                msgs_push(msgs, "user", pb);
                event(ui, "prune", kind);
            }
            free(go); free(files);
            continue;
        }

        /* nudges */
        if (ui->deliverable && !wrote && (turn == 6 || turn == 12 || turn == 18))
            msgs_push(msgs, "user", "You have not written any file yet. Stop exploring: write the implementation now, then run the type check.");
        else if (turn == g_cfg.maxturns - 5)
            msgs_push(msgs, "user", "5 turns left. Make sure all required files exist, remove any broken scratch files, confirm the type check is clean, then reply DONE.");
    }

    if (ui->emit_stats) {
        AgentStats st = {
            .turns = turns, .calls = calls, .prunes = prunes, .gates = gates, .resets = resets,
            .prompt_tokens = ptoks, .completion_tokens = toks, .secs = secs,
            .tok_per_sec = secs > 0.05 ? (toks / secs) : 0.0,
            .finish = finish, .check_skipped = gate_denied
        };
        ui->emit_stats(&st, ui->ud);
    }
    if (sum)
        snprintf(sum, sumcap,
                 "finish=%s turns=%d prunes=%d gates=%d resets=%d calls=%d tokens=%d secs=%.0f%s",
                 finish, turns, prunes, gates, resets, calls, toks, secs,
                 gate_denied ? " check=skipped" : "");
    if (tr) {
        cJSON *e = cJSON_CreateObject();
        cJSON_AddStringToObject(e, "run_finish", finish);
        if (gate_denied) cJSON_AddStringToObject(e, "check", "skipped");
        char *line = cJSON_PrintUnformatted(e);
        fprintf(tr, "%s\n", line);
        free(line); cJSON_Delete(e);
        fclose(tr);
    }
    rec_clear(&rec);
    free(taskmsg);
    return finish;
}
