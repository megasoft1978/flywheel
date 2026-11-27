/* Fuzz target: tool-argument parsing and repair (src/args.c). */
#include "../src/flywheel.h"
#include <stdint.h>

Cfg g_cfg;
volatile sig_atomic_t g_abort = 0;

const char *const fuzz_seeds[] = {
    "{\"command\":\"ls -la\"}",
    "{\"path\":\"a.c\",\"content\":\"int x;\n\tint y;\"}",
    "{\"command\":\"echo \\\"hi\\\" \\u0041\"}",
    "{\"command\": \"cat <<EOF\\nx\\nEOF",
    "{\"a\":[{\"b\":1",
    "{\"path\":\"x\",\"old\":\"\\u00",
    NULL,
};

const char *const fuzz_tokens[] = {
    "{", "}", "[", "]", "\"", ":", ",", "\\", "\\u", "0041", "d800", "\"command\"",
    "\"path\"", "\"content\"", "null", "true", "1e999", " ", "\n", "\x01", "\x7f", "\xff",
    NULL,
};

static void check(bool ok) { if (!ok) abort(); }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *raw = malloc(size + 1);
    if (!raw) return 0;
    memcpy(raw, data, size);
    raw[size] = 0;

    cJSON *j = args_parse_strict(raw);
    if (j) {
        check(cJSON_IsObject(j));
        /* strict means complete: cut off the closing brace and it must fail */
        size_t n = strlen(raw);
        while (n && (unsigned char)raw[n - 1] <= ' ') n--;
        if (n && raw[n - 1] == '}') {
            char *cut = str_ndup(raw, n - 1);
            cJSON *k = args_parse_strict(cut);
            check(!k);
            free(cut);
        }
        cJSON_Delete(j);
    }

    static const char *const keys[] = {"command", "path", "content", "a", ""};
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        char *v = args_extract_key(raw, keys[i]);
        check(v != NULL);
        check(strlen(v) <= strlen(raw) * 6);
        free(v);
    }
    free(raw);
    return 0;
}
