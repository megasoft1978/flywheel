/* Fuzz target: the command deny scan and heredoc rewrite (src/tools.c). The
   command is only analysed, never run. */
#include "../src/flywheel.h"
#include <stdint.h>

Cfg g_cfg;
volatile sig_atomic_t g_abort = 0;

const char *const fuzz_seeds[] = {
    "ls -la src && grep -rn 'x' . | head -5",
    "cat > a.txt <<EOF\nhello\nEOF\n",
    "cat <<-'EOT' > f\n\tEOT in text <<EOT\n\tEOT\n\tEOT\n",
    "for f in *.c; do sed -i '' 's/a/b/' \"$f\"; done",
    "echo $(echo `date`) ${HOME} $((1+2))",
    "bash -c 'sh -c \"rm -rf ./build\"'",
    "find . -name '*.o' -exec rm {} \\; ; rm -r {a,b}/c",
    "if true; then (cd /tmp && rm -f x{1..3}); fi",
    "case $x in a) cp a b ;; *) mv c d ;; esac",
    "xargs -I{} rm {} < list 2>&1 >/dev/null",
    NULL,
};

const char *const fuzz_tokens[] = {
    "rm ", "-rf ", "/", "~", "..", "sudo ", "sed ", "-i ", "find ", "-exec ", "-delete ",
    "xargs ", "bash -c ", "eval ", "git ", "clean ", "<<", "<<-", "<<<", "EOF", "END", "\n",
    "\t", " ", "'", "\"", "\\", "`", "$(", "${", "$((", "(", ")", "{", "}", "{a,b}", "..9}",
    "[", "]", ";", "|", "&&", "&", ">", ">>", "<", "#", "*", "?", "=", "if ", "then ",
    "case ", "in ", "esac", "do ", "done", "\xff", "\xc3",
    NULL,
};

static void check(bool ok) { if (!ok) abort(); }

static size_t lines(const char *s) {
    size_t n = 0;
    for (; *s; s++) n += *s == '\n';
    return n;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *cmd = malloc(size + 1);
    if (!cmd) return 0;
    memcpy(cmd, data, size);
    cmd[size] = 0;

    const char *cwd = "/nonexistent/fuzz-workdir";
    const char *why = deny_check(cmd, cwd);
    check(!why || *why);
    check(deny_check(cmd, cwd) == why);          /* same answer twice */

    char *fixed = heredoc_fix(cmd);
    check(fixed != NULL);
    check(lines(fixed) == lines(cmd));           /* only delimiters are renamed */
    deny_check(fixed, cwd);
    free(fixed);
    free(cmd);
    return 0;
}
