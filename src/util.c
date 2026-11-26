#include "flywheel.h"

char *str_dup(const char *s) { return s ? strdup(s) : NULL; }
char *str_ndup(const char *s, size_t n) { return s ? strndup(s, n) : NULL; }

/* reads in chunks: works for pipes (/dev/stdin) where the size is unknown */
char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 4096, len = 0, r;
    char *b = malloc(cap);
    while (b && (r = fread(b + len, 1, cap - len - 1, f)) > 0) {
        len += r;
        if (cap - len < 1024) {
            char *nb = realloc(b, cap *= 2);
            if (!nb) free(b);
            b = nb;
        }
    }
    if (b && ferror(f)) { free(b); b = NULL; }
    if (b) b[len] = 0;
    fclose(f);
    return b;
}

/* code points that reorder or hide text. ZWJ and VS16 build ordinary emoji,
   and tag characters flags, so those only show when strict. */
static bool is_hidden_cp(unsigned cp, bool strict) {
    if (cp == 0x200D || cp == 0xFE0F || (cp >= 0xE0000 && cp <= 0xE007F)) return strict;
    return cp == 0x061C || (cp >= 0x200B && cp <= 0x200F) || (cp >= 0x2028 && cp <= 0x202E) ||
           (cp >= 0x2060 && cp <= 0x2069) || cp == 0xFEFF;
}

/* Copy of s that is safe to print: C0, DEL, C1 and invalid UTF-8 become
   visible ^X / \xNN, bidi/zero-width characters <U+XXXX>. Newline and tab
   survive. CR is shown as ^M, except that with crlf a CR before a newline is
   dropped. Run this on anything from the model, a command, the server or the
   project BEFORE adding app styling. */
char *clean_text(const char *s, bool crlf, bool strict) {
    if (!s) s = "";
    char *out = malloc(strlen(s) * 4 + 1), *w = out;
    for (const unsigned char *p = (const unsigned char *)s; *p;) {
        unsigned char c = *p;
        if (c == '\n' || c == '\t' || (c >= 0x20 && c < 0x7F)) { *w++ = (char)c; p++; continue; }
        if (c == '\r' && crlf && p[1] == '\n') { p++; continue; }
        if (c < 0x20 || c == 0x7F) { *w++ = '^'; *w++ = (char)(c ^ 0x40); p++; continue; }
        int len = (c >= 0xC2 && c < 0xE0) ? 2 : (c >= 0xE0 && c < 0xF0) ? 3
                : (c >= 0xF0 && c < 0xF5) ? 4 : 0;
        for (int i = 1; i < len; i++)
            if ((p[i] & 0xC0) != 0x80) { len = 0; break; }
        if ((c == 0xE0 && len && p[1] < 0xA0) || (c == 0xED && len && p[1] > 0x9F) ||
            (c == 0xF0 && len && p[1] < 0x90) || (c == 0xF4 && len && p[1] > 0x8F)) len = 0;
        if (!len) { w += sprintf(w, "\\x%02X", c); p++; continue; }
        if (c == 0xC2 && p[1] < 0xA0) { w += sprintf(w, "\\x%02X", p[1]); p += 2; continue; }
        unsigned cp = c & (0x7Fu >> len);
        for (int i = 1; i < len; i++) cp = (cp << 6) | (p[i] & 0x3F);
        if (is_hidden_cp(cp, strict)) { w += sprintf(w, "<U+%04X>", cp); p += len; continue; }
        memcpy(w, p, (size_t)len);
        w += len; p += len;
    }
    *w = 0;
    return out;
}

/* for plain (non-TUI) output: sanitize for a terminal, pass pipes through */
char *tty_text(const char *s, bool crlf) {
    return isatty(1) ? clean_text(s, crlf, false) : str_dup(s ? s : "");
}

void ftrim_mid(char *s, int head, int tail) { (void)s; (void)head; (void)tail; }

void (*fw_tick_hook)(void);

/* server-supplied file names are interpolated into a shell command */
bool safe_repo_filename(const char *s) {
    if (!s || !*s || *s == '-' || *s == '/' || strstr(s, "..")) return false;
    return !s[strspn(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        "abcdefghijklmnopqrstuvwxyz0123456789._/-")];
}
