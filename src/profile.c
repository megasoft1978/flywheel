#include "flywheel.h"
#include <sys/stat.h>

static const Profile PROFILES[] = {
    {"ts",
     "npx tsc --noEmit -p .",
     "TypeScript/React/Node engineer",
     "ts,tsx"},
    {"python",
     "python3 -m compileall -q -x '(venv|\\.venv|node_modules|__pycache__)' . 2>&1 | head -30",
     "Python engineer",
     "py"},
    {"go",
     "go vet ./... 2>&1 | head -30",
     "Go engineer",
     "go"},
    {"rust",
     "cargo check --message-format=short 2>&1 | head -30",
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
