#include "flywheel.h"
#include <sys/stat.h>

static const Profile PROFILES[] = {
    {"ts",
     "npx tsc --noEmit -p .",
     "TypeScript/React/Node engineer",
     "ts,tsx"},
    {"python",
     "python3 -I -m compileall -q -x '(venv|\\.venv|node_modules|__pycache__)' .",
     "Python engineer",
     "py"},
    {"go",
     "go vet -atomic ./...",
     "Go engineer",
     "go"},
    {"rust",
     "cargo check --message-format=short",
     "Rust engineer",
     "rs"},
    {"generic",
     NULL,
     "senior software engineer",
     NULL},
};

static bool exists(const char *cwd, const char *f) {
    char p[1024];
    snprintf(p, sizeof p, "%s/%s", cwd, f);
    struct stat st;
    return stat(p, &st) == 0;
}

const Profile *profile_detect(const char *cwd, const char *force) {
    if (force) {
        for (size_t i = 0; i < sizeof PROFILES / sizeof PROFILES[0]; i++)
            if (!strcmp(PROFILES[i].name, force)) return &PROFILES[i];
        return &PROFILES[4];
    }
    if (exists(cwd, "package.json")) return &PROFILES[0];
    if (exists(cwd, "pyproject.toml") || exists(cwd, "setup.py") || exists(cwd, "requirements.txt"))
        return &PROFILES[1];
    if (exists(cwd, "go.mod")) return &PROFILES[2];
    if (exists(cwd, "Cargo.toml")) return &PROFILES[3];
    return &PROFILES[4];
}

/* No pipe in gate_cmd: it would hide the exit status. 126/127 (tool not
   installed) and timeouts are not code errors. npx also exits non-zero
   without TypeScript installed, so ts additionally needs a diagnostic. */
char *gate_run(const Profile *prof, const char *cwd, int timeout_s, bool *failed) {
    *failed = false;
    if (!prof->gate_cmd) return str_dup("");
    int code;
    char *out = run_bash_status(prof->gate_cmd, cwd, timeout_s, &code);
    *failed = code > 0 && code != 126 && code != 127;
    if (!strcmp(prof->name, "ts")) *failed = *failed && strstr(out, "error TS");
    if (!strcmp(prof->name, "go")) *failed = *failed && !strstr(out, "no packages to vet");
    /* keep both ends: the messages quote about 1800 chars */
    size_t len = strlen(out);
    if (len > 1700) {
        static const char mark[] = "\n...[truncated]...\n";
        memcpy(out + 850, mark, sizeof mark - 1);
        memmove(out + 850 + sizeof mark - 1, out + len - 800, 801);
        utf8_sanitize(out);
    }
    return out;
}
