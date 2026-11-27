#define _DARWIN_C_SOURCE 1

/* bench.c — run a task suite through the agent, grade, score.
 *
 * usage: flywheel [flags] bench <suite-dir> <tag> [task-id ...]
 *
 * suite layout:
 *   <suite>/suite.json            optional manifest:
 *     { "copy_files": [...], "clone_dirs": [...], "skip_deliverables": [...],
 *       "grade_script": "run_task.sh", "grade_timeout": 400 }
 *   <suite>/tasks/<id>/prompt.md  task prompt
 *   <suite>/tasks/<id>/starter/   optional, copied into the sandbox
 *   <suite>/<grade_script>        <id> <files_dir> -> one JSON line on stdout
 *
 * results: <suite>/runs/<tag>/{summary.json,<id>/{prompt.md,transcript.jsonl,files/}}
 */
#include "flywheel.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

/* ---------- small fs helpers ---------- */

static bool is_dir(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}
static bool is_file(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

static void mkdirs(const char *p) {
    char tmp[1400];
    snprintf(tmp, sizeof tmp, "%s", p);
    for (char *s = tmp + 1; *s; s++) {
        if (*s == '/') { *s = 0; mkdir(tmp, 0755); *s = '/'; }
    }
    mkdir(tmp, 0755);
}

int fw_copy_file(const char *src, const char *dst) {
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    struct stat st;
    int out = fstat(in, &st) ? -1 : open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out < 0) { close(in); return -1; }
    char buf[65536];
    ssize_t n;
    int rc = 0;
    while (!rc && (n = read(in, buf, sizeof buf)) != 0) {
        if (n < 0) { rc = -1; break; }
        for (ssize_t off = 0, w; off < n; off += w)
            if ((w = write(out, buf + off, (size_t)(n - off))) <= 0) { rc = -1; break; }
    }
    if (fchmod(out, st.st_mode & 07777)) rc = -1;
    close(in);
    if (close(out)) rc = -1;
    return rc;
}

/* recursive copy of directory contents (merge) */
static void copy_tree(const char *src, const char *dst) {
    DIR *d = opendir(src);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char sp[1400], dp[1400];
        snprintf(sp, sizeof sp, "%s/%s", src, e->d_name);
        snprintf(dp, sizeof dp, "%s/%s", dst, e->d_name);
        if (is_dir(sp)) { mkdirs(dp); copy_tree(sp, dp); }
        else if (is_file(sp)) fw_copy_file(sp, dp);
    }
    closedir(d);
}

/* ---------- manifest ---------- */

typedef struct {
    cJSON *copy_files;   /* arrays of strings, may be NULL */
    cJSON *clone_dirs;
    cJSON *skip;
    char grade_script[256];
    int grade_timeout;
} Manifest;

static void manifest_load(Manifest *m, const char *suite) {
    memset(m, 0, sizeof *m);
    strcpy(m->grade_script, "");
    m->grade_timeout = 400;
    char p[1400];
    snprintf(p, sizeof p, "%s/suite.json", suite);
    char *c = read_file(p);
    if (!c) return;
    cJSON *j = cJSON_Parse(c);
    free(c);
    if (!j) return;
    m->copy_files = cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(j, "copy_files"), 1);
    m->clone_dirs = cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(j, "clone_dirs"), 1);
    m->skip = cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(j, "skip_deliverables"), 1);
    cJSON *gs = cJSON_GetObjectItemCaseSensitive(j, "grade_script");
    if (cJSON_IsString(gs)) snprintf(m->grade_script, sizeof m->grade_script, "%s", gs->valuestring);
    cJSON *gt = cJSON_GetObjectItemCaseSensitive(j, "grade_timeout");
    if (cJSON_IsNumber(gt)) m->grade_timeout = gt->valueint;
    cJSON_Delete(j);
}

static void manifest_free(Manifest *m) {
    cJSON_Delete(m->copy_files);
    cJSON_Delete(m->clone_dirs);
    cJSON_Delete(m->skip);
}

static bool in_list(cJSON *arr, const char *s) {
    if (!arr) return false;
    cJSON *it;
    cJSON_ArrayForEach(it, arr)
        if (cJSON_IsString(it) && !strcmp(it->valuestring, s)) return true;
    return false;
}

/* ---------- sandbox ---------- */

static void setup_sandbox(const char *suite, const char *tid, const Manifest *m, char *out, size_t cap) {
    char tmpl[] = "/tmp/fwbench-XXXXXX";
    if (!mkdtemp(tmpl)) { snprintf(out, cap, "/tmp/fwbench-fail"); return; }
    snprintf(out, cap, "%s", tmpl);
    char src[1400], dst[1400], cmd[2800];
    cJSON *it;
    if (m->clone_dirs) cJSON_ArrayForEach(it, m->clone_dirs) {
        if (!cJSON_IsString(it)) continue;
        snprintf(src, sizeof src, "%s/%s", suite, it->valuestring);
        snprintf(dst, sizeof dst, "%s/%s", out, it->valuestring);
        snprintf(cmd, sizeof cmd, "cp -cR \"%s\" \"%s\" 2>/dev/null || cp -R \"%s\" \"%s\"", src, dst, src, dst);
        system(cmd);
    }
    if (m->copy_files) cJSON_ArrayForEach(it, m->copy_files) {
        if (!cJSON_IsString(it)) continue;
        snprintf(src, sizeof src, "%s/%s", suite, it->valuestring);
        snprintf(dst, sizeof dst, "%s/%s", out, it->valuestring);
        fw_copy_file(src, dst);
    }
    snprintf(src, sizeof src, "%s/tasks/%s/starter", suite, tid);
    if (is_dir(src)) copy_tree(src, out);
}

/* collect deliverables: recursive copy with skip rules (mirrors suite.py) */
static void collect_rec(const char *root, const char *rel, const char *dest, const Manifest *m) {
    char dir[1400];
    snprintf(dir, sizeof dir, "%s%s%s", root, rel[0] ? "/" : "", rel);
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char cr[1400];
        snprintf(cr, sizeof cr, "%s%s%s", rel, rel[0] ? "/" : "", e->d_name);
        char fp[1400];
        snprintf(fp, sizeof fp, "%s/%s", root, cr);
        /* first path component in skip list? */
        char first[512];
        snprintf(first, sizeof first, "%s", cr);
        char *slash = strchr(first, '/');
        if (slash) *slash = 0;
        if (in_list(m->skip, first)) continue;
        /* model-made links point anywhere: neither followed nor collected */
        struct stat st;
        if (lstat(fp, &st)) continue;
        if (S_ISDIR(st.st_mode)) { collect_rec(root, cr, dest, m); continue; }
        if (!S_ISREG(st.st_mode)) continue;
        if (strstr(e->d_name, ".test.") || strstr(e->d_name, ".spec.")) continue;
        char dp[1400];
        snprintf(dp, sizeof dp, "%s/%s", dest, cr);
        char dpar[1400];
        snprintf(dpar, sizeof dpar, "%s", dp);
        char *ls = strrchr(dpar, '/');
        if (ls) { *ls = 0; mkdirs(dpar); }
        fw_copy_file(fp, dp);
    }
    closedir(d);
}

/* ---------- grading ---------- */

/* runs grade script, returns parsed JSON result object (owned) — never NULL */
static cJSON *grade_task(const char *suite, const char *script, const char *tid,
                         const char *files, int timeout) {
    char sp[1400], errf[1400], cmd[3200];
    snprintf(sp, sizeof sp, "%s/%s", suite, script);
    snprintf(errf, sizeof errf, "/tmp/fwbench-grade-err-%d", getpid());
    snprintf(cmd, sizeof cmd,
        "perl -e 'alarm %d; exec @ARGV' bash \"%s\" \"%s\" \"%s\" 2>\"%s\"",
        timeout, sp, tid, files, errf);
    FILE *pp = popen(cmd, "r");
    char *out = NULL;
    size_t cap = 0, len = 0;
    if (pp) {
        char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof buf, pp))) {
            if (len + n + 1 > cap) { cap = (len + n + 1) * 2; out = realloc(out, cap); }
            memcpy(out + len, buf, n); len += n;
        }
        pclose(pp);
    }
    if (out) out[len] = 0;
    /* last line starting with '{' */
    cJSON *res = NULL;
    if (out) {
        char *last = NULL;
        for (char *ln = strtok(out, "\n"); ln; ln = strtok(NULL, "\n"))
            if (ln[0] == '{') last = ln;
        /* strtok destroyed spacing context but last ptr still valid inside out */
        if (last) {
            /* find it again unmodified: strtok already NUL-terminated the line in place */
            res = cJSON_Parse(last);
        }
    }
    if (!res) {
        char *errc = read_file(errf);
        res = cJSON_CreateObject();
        cJSON_AddStringToObject(res, "id", tid);
        cJSON_AddBoolToObject(res, "tsc_ok", 0);
        cJSON_AddNumberToObject(res, "tsc_errors", 0);
        cJSON_AddNumberToObject(res, "tests_total", 0);
        cJSON_AddNumberToObject(res, "tests_passed", 0);
        const char *tail = errc ? errc : (out ? out : "");
        size_t tl = strlen(tail);
        char snippet[301];
        snprintf(snippet, sizeof snippet, "%.300s", tail + (tl > 300 ? tl - 300 : 0));
        cJSON_AddStringToObject(res, "first_failure", snippet);
        free(errc);
    }
    free(out);
    unlink(errf);
    /* full_pass */
    cJSON *tt = cJSON_GetObjectItemCaseSensitive(res, "tests_total");
    cJSON *tp = cJSON_GetObjectItemCaseSensitive(res, "tests_passed");
    cJSON *ts = cJSON_GetObjectItemCaseSensitive(res, "tsc_ok");
    int total = cJSON_IsNumber(tt) ? tt->valueint : 0;
    int passed = cJSON_IsNumber(tp) ? tp->valueint : 0;
    bool tsc = cJSON_IsTrue(ts);
    cJSON_AddBoolToObject(res, "full_pass", total > 0 && passed == total && tsc);
    return res;
}

/* ---------- bench driver ---------- */

static void bench_status(const char *s, void *ud) { (void)s; (void)ud; }

int fw_do_bench(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: flywheel [flags] bench <suite-dir> <tag> [task-id ...]\n");
        return 2;
    }
    const char *suite = argv[0];
    const char *tag = argv[1];
    if (!is_dir(suite)) { fprintf(stderr, "bench: no such suite dir: %s\n", suite); return 2; }

    Manifest m;
    manifest_load(&m, suite);
    if (!m.grade_script[0]) {
        char p[1400];
        snprintf(p, sizeof p, "%s/grade_task.sh", suite);
        snprintf(m.grade_script, sizeof m.grade_script, "%s", is_file(p) ? "grade_task.sh" : "run_task.sh");
    }

    /* task list: explicit ids or scan tasks/ */
    char (*tasks)[256] = NULL;
    int ntasks = 0, tcap = 0;
    if (argc > 2) {
        tasks = malloc((size_t)(argc - 2) * sizeof *tasks);
        for (int i = 2; i < argc; i++, ntasks++)
            snprintf(tasks[ntasks], 256, "%s", argv[i]);
    } else {
        char td[1400];
        snprintf(td, sizeof td, "%s/tasks", suite);
        DIR *d = opendir(td);
        if (!d) { fprintf(stderr, "bench: no tasks/ in %s\n", suite); return 2; }
        /* collect then sort for stable order */
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.') continue;
            char p[1400];
            snprintf(p, sizeof p, "%s/%s", td, e->d_name);
            if (!is_dir(p)) continue;
            if (ntasks == tcap) tasks = realloc(tasks, (size_t)(tcap = tcap ? tcap * 2 : 64) * sizeof *tasks);
            snprintf(tasks[ntasks++], 256, "%s", e->d_name);
        }
        closedir(d);
        for (int i = 0; i < ntasks; i++)
            for (int j = i + 1; j < ntasks; j++)
                if (strcmp(tasks[i], tasks[j]) > 0) {
                    char t[256];
                    strcpy(t, tasks[i]); strcpy(tasks[i], tasks[j]); strcpy(tasks[j], t);
                }
    }

    char rundir[1400];
    snprintf(rundir, sizeof rundir, "%s/runs/%s", suite, tag);
    mkdirs(rundir);
    char sumpath[1400];
    snprintf(sumpath, sizeof sumpath, "%s/summary.json", rundir);

    cJSON *summary = cJSON_CreateArray();
    double wall_all = 0;
    for (int ti = 0; ti < ntasks; ti++) {
        const char *tid = tasks[ti];
        char pp[1400];
        snprintf(pp, sizeof pp, "%s/tasks/%s/prompt.md", suite, tid);
        char *prompt = read_file(pp);
        if (!prompt) { fprintf(stderr, "bench: no prompt for %s, skipping\n", tid); continue; }

        char sb[1400];
        setup_sandbox(suite, tid, &m, sb, sizeof sb);

        char td[1400];
        snprintf(td, sizeof td, "%s/%s", rundir, tid);
        mkdirs(td);
        char pcopy[1400];
        snprintf(pcopy, sizeof pcopy, "%s/prompt.md", td);
        fw_copy_file(pp, pcopy);

        /* per-task agent config */
        free(g_cfg.cwd);
        g_cfg.cwd = str_dup(sb);
        free(g_cfg.transcript);
        char trpath[1400];
        snprintf(trpath, sizeof trpath, "%s/transcript.jsonl", td);
        g_cfg.transcript = str_dup(trpath);

        char *sysp = fw_build_system(false);
        Msgs msgs;
        msgs_init(&msgs);
        msgs_push(&msgs, "system", sysp);
        msgs_push(&msgs, "user", prompt);
        Ui ui = {.emit_text = NULL, .emit_think = NULL, .emit_tool = NULL,
                 .emit_out = NULL, .emit_status = bench_status, .emit_event = NULL,
                 .interactive = false, .deliverable = true};

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        char sum[256];
        const char *fin = agent_run(&msgs, &ui, sum, sizeof sum);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double dt = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
        wall_all += dt;
        msgs_free(&msgs);
        free(sysp);

        /* count turns from transcript */
        int turns = 0;
        char *trc = read_file(trpath);
        if (trc) {
            for (char *s = trc; (s = strstr(s, "\"turn\"")); s++) turns++;
            free(trc);
        }

        /* deliverables + grade */
        char fdir[1400];
        snprintf(fdir, sizeof fdir, "%s/files", td);
        mkdirs(fdir);
        collect_rec(sb, "", fdir, &m);
        cJSON *res = grade_task(suite, m.grade_script, tid, fdir, m.grade_timeout);

        /* summary entry, python-compatible shape */
        cJSON *rec = cJSON_CreateObject();
        cJSON_AddStringToObject(rec, "id", tid);
        cJSON *atts = cJSON_CreateArray();
        cJSON *att = cJSON_CreateObject();
        cJSON_AddNumberToObject(att, "secs", ((int)(dt * 10)) / 10.0);
        cJSON_AddNumberToObject(att, "turns", turns);
        cJSON_AddNumberToObject(att, "rc", !strcmp(fin, "done") ? 0 : 1);
        cJSON_AddStringToObject(att, "fin", fin);
        /* merge grade fields */
        cJSON *it;
        cJSON_ArrayForEach(it, res) {
            if (cJSON_IsNumber(it)) cJSON_AddNumberToObject(att, it->string, it->valuedouble);
            else if (cJSON_IsString(it)) cJSON_AddStringToObject(att, it->string, it->valuestring);
            else if (cJSON_IsBool(it)) cJSON_AddBoolToObject(att, it->string, cJSON_IsTrue(it));
        }
        cJSON_AddItemToArray(atts, att);
        cJSON_AddItemToObject(rec, "attempts", atts);
        cJSON_AddItemToArray(summary, rec);
        cJSON_Delete(res);

        char *sj = cJSON_Print(summary);
        FILE *sf = fopen(sumpath, "w");
        if (sf) { fputs(sj, sf); fclose(sf); }
        free(sj);

        int passed = 0, total = 0;
        bool tsc = false;
        cJSON *g;
        cJSON_ArrayForEach(g, att) {
            if (!strcmp(g->string, "tests_passed")) passed = g->valueint;
            if (!strcmp(g->string, "tests_total")) total = g->valueint;
            if (!strcmp(g->string, "tsc_ok")) tsc = cJSON_IsTrue(g);
        }
        char line[1024];
        snprintf(line, sizeof line, "%s %s %d/%d tsc=%s turns=%d fin=%s %.0fs", tag, tid,
                 passed, total, tsc ? "true" : "false", turns, fin, dt);
        char *safe = clean_text(line, false, false);   /* fin carries server text */
        for (char *p = safe; *p; p++) if (*p == '\n') *p = ' ';
        puts(safe);
        free(safe);
        fflush(stdout);

        /* cleanup sandbox */
        char rm[1400];
        snprintf(rm, sizeof rm, "rm -rf \"%s\"", sb);
        system(rm);
        free(prompt);
        if (g_abort) { fprintf(stderr, "bench: aborted\n"); break; }
    }

    /* scoring, same math as flywheelrun */
    double gated = 0, raw = 0;
    int fulls = 0, counted = 0;
    cJSON *r;
    cJSON_ArrayForEach(r, summary) {
        cJSON *atts = cJSON_GetObjectItemCaseSensitive(r, "attempts");
        cJSON *a = cJSON_GetArrayItem(atts, 0);
        if (!a) continue;
        counted++;
        cJSON *tp = cJSON_GetObjectItemCaseSensitive(a, "tests_passed");
        cJSON *tt = cJSON_GetObjectItemCaseSensitive(a, "tests_total");
        cJSON *ts = cJSON_GetObjectItemCaseSensitive(a, "tsc_ok");
        cJSON *fp = cJSON_GetObjectItemCaseSensitive(a, "full_pass");
        int passed = cJSON_IsNumber(tp) ? tp->valueint : 0;
        int total = cJSON_IsNumber(tt) ? tt->valueint : 0;
        bool tsc = cJSON_IsTrue(ts);
        double frac = passed / (double)(total > 0 ? total : 1);
        raw += frac;
        if (tsc) gated += frac;
        if (cJSON_IsTrue(fp)) fulls++;
    }
    printf("%s DONE tasks=%d gated=%.2f raw=%.2f full_pass=%d secs=%.0f\n",
           tag, counted, gated, raw, fulls, wall_all);
    manifest_free(&m);
    free(tasks);
    cJSON_Delete(summary);
    return 0;
}
