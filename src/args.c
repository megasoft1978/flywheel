#include "flywheel.h"
#include <ctype.h>

static int repairs[4];
static const char *repair_names[4] = {"ctrlchar", "autoclose", "keyscan", "fail"};

void args_note_repair(const char *kind) {
    for (int i = 0; i < 4; i++)
        if (!strcmp(kind, repair_names[i])) { repairs[i]++; return; }
}

void args_repairs_report(char *buf, size_t n) {
    snprintf(buf, n, "ctrlchar=%d autoclose=%d keyscan=%d fail=%d",
             repairs[0], repairs[1], repairs[2], repairs[3]);
}

/* Escape raw control chars that appear inside JSON string regions.
   Models emit literal 0x0A/0x09 inside arguments -> invalid JSON.
   We scan byte-wise tracking string state; inside a string, bare
   <0x20 bytes become \\u00XX (or \\n/\\t shortcuts). */
static char *escape_ctrl_in_strings(const char *s, bool *changed) {
    size_t cap = strlen(s) * 6 + 1;   /* worst case: every byte -> \u00XX */
    char *out = malloc(cap);
    char *w = out;
    bool instr = false, esc = false;
    *changed = false;
    if (!out) return NULL;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        if (instr) {
            if (esc) { *w++ = (char)c; esc = false; continue; }
            if (c == '\\') { *w++ = (char)c; esc = true; continue; }
            if (c == '"') { instr = false; *w++ = (char)c; continue; }
            if (c < 0x20) {
                *changed = true;
                if (c == '\n') { *w++ = '\\'; *w++ = 'n'; }
                else if (c == '\t') { *w++ = '\\'; *w++ = 't'; }
                else if (c == '\r') { *w++ = '\\'; *w++ = 'r'; }
                else w += snprintf(w, 7, "\\u%04x", c);
                continue;
            }
            *w++ = (char)c;
        } else {
            if (c == '"') instr = true;
            *w++ = (char)c;
        }
    }
    *w = 0;
    return out;
}

/* If raw is truncated JSON, try appending closers until it parses.
   Repairs only when a string + braces can be closed — never fabricates
   payload content. */
static char *autoclose(const char *s) {
    bool instr = false, esc = false;
    int depth = 0;
    char last_open = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        if (instr) {
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"') instr = false;
        } else {
            if (c == '"') instr = true;
            else if (c == '{' || c == '[') { depth++; last_open = (char)c; }
            else if (c == '}' || c == ']') depth--;
        }
    }
    if (!instr && depth <= 0) return NULL;
    /* refuse when unbalanced opens > 2 or inside escape */
    if (esc || depth > 2) return NULL;
    char *out = malloc(strlen(s) + 8);
    if (!out) return NULL;
    strcpy(out, s);
    char *w = out + strlen(s);
    if (instr) *w++ = '"';
    while (depth-- > 0) *w++ = last_open == '[' ? ']' : '}';
    *w = 0;
    return out;
}

/* Fallback: pull a key's value with a raw scanner — skips JSON
   entirely. Finds "key", then reads the quoted string honoring escapes. */
static char *scan_key(const char *s, const char *key) {
    char pat[72];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *k = strstr(s, pat);
    if (!k) return NULL;
    const char *q = strchr(k + strlen(pat), '"');
    if (!q) return NULL;
    q++; /* opening quote of value */
    size_t cap = strlen(q) + 1;
    char *out = malloc(cap);
    if (!out) return NULL;
    char *w = out;
    for (const unsigned char *p = (const unsigned char *)q; *p; p++) {
        unsigned char c = *p;
        if (c == '\\' && p[1]) {
            p++;
            switch (*p) {
                case 'n': *w++ = '\n'; break;
                case 't': *w++ = '\t'; break;
                case 'r': *w++ = '\r'; break;
                case 'u': {
                    /* \uXXXX -> copy utf8-ish: only handle ascii range */
                    if (isxdigit(p[1]) && isxdigit(p[2]) && isxdigit(p[3]) && isxdigit(p[4])) {
                        int v = (int)strtol((char[]){p[1],p[2],p[3],p[4],0}, NULL, 16);
                        if (v > 0 && v < 128) *w++ = (char)v; else *w++ = '?';
                        p += 4;
                    } else *w++ = '?';   /* truncated escape: stop short */
                    break;
                }
                default: *w++ = (char)*p;
            }
            continue;
        }
        if (c == '"') break; /* closing quote */
        *w++ = (char)c;
    }
    *w = 0;
    return out;
}

/* No auto-close, no key scanning: for tools that change files, a truncated
   argument string must never be executed. Raw control chars are tolerated. */
cJSON *args_parse_strict(const char *raw) {
    if (!raw || !*raw) return NULL;
    bool changed;
    char *fixed = escape_ctrl_in_strings(raw, &changed);
    if (!fixed) return NULL;
    cJSON *j = cJSON_ParseWithOpts(fixed, NULL, 1);
    free(fixed);
    if (!cJSON_IsObject(j)) { cJSON_Delete(j); return NULL; }
    if (changed) args_note_repair("ctrlchar");
    return j;
}

char *args_extract_key(const char *raw, const char *key) {
    if (!raw || !*raw) return str_dup("");
    char *fixed = escape_ctrl_in_strings(raw, &(bool){0});
    if (!fixed) return str_dup("");

    cJSON *j = cJSON_Parse(fixed);
    if (!j) {
        char *ac = autoclose(fixed);
        if (ac) {
            j = cJSON_Parse(ac);
            if (j) { free(fixed); fixed = ac; args_note_repair("autoclose"); }
            else free(ac);
        }
    } else {
        if (strcmp(fixed, raw)) args_note_repair("ctrlchar");
    }
    if (j) {
        cJSON *c = cJSON_GetObjectItemCaseSensitive(j, key);
        if (cJSON_IsString(c) && c->valuestring) {
            char *r = str_dup(c->valuestring);
            cJSON_Delete(j); free(fixed);
            return r;
        }
        cJSON_Delete(j);
    }
    free(fixed);
    char *r = scan_key(raw, key);
    if (r) { args_note_repair("keyscan"); return r; }
    args_note_repair("fail");
    return str_dup("");
}

char *args_extract_command(const char *raw) {
    return args_extract_key(raw, "command");
}
