#include "flywheel.h"

char *str_dup(const char *s) { return s ? strdup(s) : NULL; }
char *str_ndup(const char *s, size_t n) { return s ? strndup(s, n) : NULL; }

char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc(n + 1);
    if (fread(b, 1, n, f) != (size_t)n) { fclose(f); free(b); return NULL; }
    b[n] = 0;
    fclose(f);
    return b;
}

void ftrim_mid(char *s, int head, int tail) { (void)s; (void)head; (void)tail; }

void (*fw_tick_hook)(void);
