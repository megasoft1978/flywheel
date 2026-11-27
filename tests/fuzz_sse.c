/* Fuzz target: SSE and chat-completion parsing. Includes http.c to reach its
   static parser. Checks that how a stream is sliced never changes the result. */
#define FW_MAX_RESPONSE ((size_t)6000)
#define FW_MAX_EVENT ((size_t)2000)
#include "../src/http.c"
#include <stdint.h>

Cfg g_cfg;
volatile sig_atomic_t g_abort = 0;

#define EV(delta) "data: {\"choices\":[{\"delta\":" delta "}]}\n\n"

const char *const fuzz_seeds[] = {
    EV("{\"content\":\"hel\"}") EV("{\"content\":\"lo\"}") "data: [DONE]\n\n",
    EV("{\"reasoning_content\":\"hm\"}")
    "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],"
    "\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":2}}\r\n\r\n",
    EV("{\"tool_calls\":[{\"index\":0,\"id\":\"a\",\"function\":{\"name\":\"bash\",\"arguments\":\"{\\\"c\"}}]}")
    EV("{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\":1}\"}}]}"),
    "{\"choices\":[{\"message\":{\"content\":\"x\",\"tool_calls\":[{\"id\":\"b\",\"function\":"
    "{\"name\":\"read\",\"arguments\":\"{}\"}}]},\"finish_reason\":\"tool_calls\"}]}",
    "{\"error\":{\"message\":\"nope\"}}",
    "data: {\"choices\":[]}\r\n\r\ndata:[DONE]",
    NULL,
};

const char *const fuzz_tokens[] = {
    "data: ", "\n", "\r", "\n\n", "\r\n\r\n", "[DONE]", "{", "}", "[", "]", "\"", ":", ",",
    "\"choices\"", "\"delta\"", "\"message\"", "\"tool_calls\"", "\"index\"", "\"function\"",
    "\"arguments\"", "\"name\"", "\"id\"", "\"content\"", "\"usage\"", "\"error\"",
    "\"finish_reason\"", "\"prompt_tokens\"", "null", "-1", "63", "64", "1e300", "0.5", " ",
    NULL,
};

static void check(bool ok) { if (!ok) abort(); }

static void on_piece(const char *s, void *ud) { *(size_t *)ud += strlen(s); }

typedef struct {
    char *content, *thinking, *tools, finish[64], err[256];
    int ptok, ctok;
    bool done, fatal;
} Out;

/* feed the bytes `slice` at a time (0: sizes drawn from the bytes themselves) */
static Out parse(const uint8_t *d, size_t n, size_t slice, bool stream) {
    size_t seen = 0;
    StreamCb cb = {.on_text = on_piece, .on_think = on_piece, .ud = &seen, .stream = stream};
    Acc a = {0};
    a.cb = &cb;
    a.limit = FW_MAX_RESPONSE;
    for (size_t at = 0; at < n;) {
        size_t k = slice ? slice : 1 + d[at] % 17u;
        if (k > n - at) k = n - at;
        if (on_data((char *)d + at, 1, k, &a) != k) break;
        at += k;
        check(a.scanned <= a.raw.len || !stream);
    }
    if (!a.fatal[0]) acc_finish(&a, stream);
    cJSON *tc = acc_take_tool_calls(&a);
    Out o = {0};
    o.content = str_dup(a.content.buf ? a.content.buf : "");
    o.thinking = str_dup(a.thinking.buf ? a.thinking.buf : "");
    o.tools = tc ? cJSON_PrintUnformatted(tc) : str_dup("");
    memcpy(o.finish, a.finish, sizeof o.finish);
    memcpy(o.err, a.err, sizeof o.err);
    o.ptok = a.ptok;
    o.ctok = a.ctok;
    o.done = a.done;
    o.fatal = a.fatal[0] != 0;
    check(a.ntcs >= 0 && a.ntcs <= MAX_TOOL_CALLS);
    check(o.ptok >= 0 && o.ctok >= 0);
    cJSON_Delete(tc);
    acc_free(&a);
    return o;
}

static void out_free(Out *o) {
    free(o->content);
    free(o->thinking);
    free(o->tools);
}

static void same(const Out *x, const Out *y) {
    /* a reply that hit a limit is discarded, and where it stops may differ */
    if (x->fatal || y->fatal) return;
    check(!strcmp(x->content, y->content));
    check(!strcmp(x->thinking, y->thinking));
    check(!strcmp(x->tools, y->tools));
    check(!strcmp(x->finish, y->finish));
    check(!strcmp(x->err, y->err));
    check(x->ptok == y->ptok && x->ctok == y->ctok && x->done == y->done);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    for (int stream = 0; stream < 2; stream++) {
        Out whole = parse(data, size, size ? size : 1, stream);
        Out bytes = parse(data, size, 1, stream);
        Out mixed = parse(data, size, 0, stream);
        same(&whole, &bytes);
        same(&whole, &mixed);
        out_free(&whole);
        out_free(&bytes);
        out_free(&mixed);
    }
    return 0;
}
