#include "flywheel.h"
#include <time.h>
#ifdef FW_MINI_HTTP
int fw_mini_post_stream(const char *url, const char *payload, int streaming,
                        size_t (*cb)(char *, size_t, size_t, void *), void *ud,
                        int timeout_s, int *status, char *errbuf, size_t errcap);
char *fw_mini_get(const char *url);
#else
#include <curl/curl.h>
#endif
#include <fcntl.h>
#include <sys/select.h>
#include <termios.h>

/* hard ceilings on what a server can make us buffer */
#ifndef FW_MAX_RESPONSE
#define FW_MAX_RESPONSE ((size_t)128 << 20)   /* all bytes of one chat reply */
#endif
#ifndef FW_MAX_EVENT
#define FW_MAX_EVENT ((size_t)16 << 20)       /* one SSE event (or line) */
#endif
#ifndef FW_MAX_GET
#define FW_MAX_GET ((size_t)16 << 20)         /* http_get_url body */
#endif
#define MAX_TOOL_CALLS 64

typedef struct {
    char *buf;
    size_t len, cap;
} SBuf;

static bool sb_cat(SBuf *s, const char *d, size_t n) {
    if (s->len + n + 1 > s->cap) {
        size_t cap = (s->len + n + 1) * 2;
        char *nb = realloc(s->buf, cap);
        if (!nb) return false;
        s->buf = nb;
        s->cap = cap;
    }
    memcpy(s->buf + s->len, d, n);
    s->len += n;
    s->buf[s->len] = 0;
    return true;
}

typedef struct {
    SBuf raw;              /* unparsed SSE remainder (stream) or whole body */
    SBuf content, thinking;
    cJSON *tcs[MAX_TOOL_CALLS];   /* accumulated tool calls by index */
    SBuf args[MAX_TOOL_CALLS];    /* their argument deltas, joined at the end */
    int ntcs;
    char finish[64];
    int ptok, ctok;
    StreamCb *cb;
    char err[256];
    bool done;             /* saw SSE [DONE] */
    size_t total, limit;   /* bytes received, and the most we accept */
    size_t scanned;        /* prefix of raw known to hold no event separator */
    char fatal[128];       /* local failure: outranks transport and server errors */
} Acc;

/* none of these messages may look transient to the agent's retry check */
static void acc_fail(Acc *a, const char *why) {
    if (!a->fatal[0]) snprintf(a->fatal, sizeof a->fatal, "%s", why);
}

static void acc_too_large(Acc *a, const char *what, size_t limit) {
    if (!a->fatal[0])
        snprintf(a->fatal, sizeof a->fatal, "%s too large (over %zu bytes)", what, limit);
}

static void acc_cat(Acc *a, SBuf *s, const char *d) {
    if (!sb_cat(s, d, strlen(d))) acc_fail(a, "out of memory");
}

static cJSON *new_tool_call(void) {
    cJSON *tc = cJSON_CreateObject();
    cJSON *fn = NULL;
    if (cJSON_AddStringToObject(tc, "id", "") && cJSON_AddStringToObject(tc, "type", "function") &&
        (fn = cJSON_AddObjectToObject(tc, "function")) != NULL &&
        cJSON_AddStringToObject(fn, "name", "") && cJSON_AddStringToObject(fn, "arguments", ""))
        return tc;
    cJSON_Delete(tc);
    return NULL;
}

static void set_string(Acc *a, cJSON *obj, const char *key, const char *val) {
    if (!cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(obj, key), val))
        acc_fail(a, "out of memory");
}

static void acc_tool_delta(Acc *a, cJSON *tcarr) {
    cJSON *tc;
    cJSON_ArrayForEach(tc, tcarr) {
        if (!cJSON_IsObject(tc)) continue;
        cJSON *idx = cJSON_GetObjectItemCaseSensitive(tc, "index");
        double d = cJSON_IsNumber(idx) ? idx->valuedouble : a->ntcs;
        /* range-check the double: converting 1e300 to int is undefined.
           Skipping a call would lose it silently, so the reply fails */
        if (!(d >= 0 && d < MAX_TOOL_CALLS)) {
            if (!a->fatal[0])
                snprintf(a->fatal, sizeof a->fatal,
                         "too many tool calls or bad tool-call index (limit %d)", MAX_TOOL_CALLS);
            return;
        }
        int i = (int)d;
        if (!a->tcs[i]) {
            a->tcs[i] = new_tool_call();
            if (!a->tcs[i]) { acc_fail(a, "out of memory"); return; }
            if (i >= a->ntcs) a->ntcs = i + 1;
        }
        cJSON *id = cJSON_GetObjectItemCaseSensitive(tc, "id");
        if (cJSON_IsString(id) && id->valuestring[0])
            set_string(a, a->tcs[i], "id", id->valuestring);
        cJSON *fn = cJSON_GetObjectItemCaseSensitive(tc, "function");
        if (fn) {
            cJSON *afn = cJSON_GetObjectItemCaseSensitive(a->tcs[i], "function");
            cJSON *nm = cJSON_GetObjectItemCaseSensitive(fn, "name");
            if (cJSON_IsString(nm) && nm->valuestring[0])
                set_string(a, afn, "name", nm->valuestring);
            cJSON *ar = cJSON_GetObjectItemCaseSensitive(fn, "arguments");
            if (cJSON_IsString(ar)) acc_cat(a, &a->args[i], ar->valuestring);
        }
    }
}

static int token_count(const cJSON *n) {
    double d = n->valuedouble;
    return d >= 0 && d < 2147483647.0 ? (int)d : 0;
}

static void acc_chunk(Acc *a, const char *json) {
    cJSON *j = cJSON_Parse(json);
    if (!j) return;
    cJSON *je = cJSON_GetObjectItemCaseSensitive(j, "error");
    if (je && !cJSON_IsNull(je) && !a->err[0]) {
        char *s = cJSON_PrintUnformatted(je);
        snprintf(a->err, sizeof a->err, "%s", s ? s : "server error");
        free(s);
    }
    cJSON *ch = cJSON_GetObjectItemCaseSensitive(j, "choices");
    cJSON *c0 = ch && cJSON_IsArray(ch) ? cJSON_GetArrayItem(ch, 0) : NULL;
    if (c0) {
        cJSON *d = cJSON_GetObjectItemCaseSensitive(c0, "delta");
        if (!d) d = cJSON_GetObjectItemCaseSensitive(c0, "message"); /* non-stream shape */
        if (d) {
            cJSON *ct = cJSON_GetObjectItemCaseSensitive(d, "content");
            if (cJSON_IsString(ct)) {
                acc_cat(a, &a->content, ct->valuestring);
                if (a->cb && a->cb->on_text) a->cb->on_text(ct->valuestring, a->cb->ud);
            }
            cJSON *rc = cJSON_GetObjectItemCaseSensitive(d, "reasoning_content");
            if (!rc) rc = cJSON_GetObjectItemCaseSensitive(d, "reasoning");
            if (cJSON_IsString(rc)) {
                acc_cat(a, &a->thinking, rc->valuestring);
                if (a->cb && a->cb->on_think) a->cb->on_think(rc->valuestring, a->cb->ud);
            }
            cJSON *tc = cJSON_GetObjectItemCaseSensitive(d, "tool_calls");
            if (tc && cJSON_IsArray(tc)) acc_tool_delta(a, tc);
        }
        cJSON *fr = cJSON_GetObjectItemCaseSensitive(c0, "finish_reason");
        if (cJSON_IsString(fr)) snprintf(a->finish, sizeof a->finish, "%s", fr->valuestring);
    }
    cJSON *u = cJSON_GetObjectItemCaseSensitive(j, "usage");
    if (u) {
        cJSON *p = cJSON_GetObjectItemCaseSensitive(u, "prompt_tokens");
        cJSON *c = cJSON_GetObjectItemCaseSensitive(u, "completion_tokens");
        if (cJSON_IsNumber(p)) a->ptok = token_count(p);
        if (cJSON_IsNumber(c)) a->ctok = token_count(c);
    }
    cJSON_Delete(j);
}

/* "data:" lines of one SSE event block (modified in place) */
static void sse_lines(Acc *a, char *block) {
    for (char *ln = block; ln && *ln;) {
        char *nl = strchr(ln, '\n');
        if (nl) *nl = 0;
        size_t ll = strlen(ln);
        if (ll && ln[ll - 1] == '\r') ln[ll - 1] = 0;
        if (!strncmp(ln, "data:", 5)) {
            const char *d = ln + 5;
            while (*d == ' ') d++;
            if (strcmp(d, "[DONE]")) acc_chunk(a, d);
            else a->done = true;
        }
        ln = nl ? nl + 1 : NULL;
    }
}

/* Consume complete SSE events (ended by "\n\n" or "\r\n\r\n"). One pass over
   the new bytes and one memmove per chunk, however the stream is sliced. */
static void sse_consume(Acc *a) {
    char *b = a->raw.buf;
    size_t len = a->raw.len, start = 0, at = a->scanned;
    while (at < len && !a->fatal[0]) {
        char *nl = memchr(b + at, '\n', len - at);
        if (!nl) { at = len; break; }
        size_t p = (size_t)(nl - b), end, next;
        if (p + 1 >= len) { at = p; break; }               /* need more bytes */
        if (b[p + 1] == '\n') {
            end = p;
            next = p + 2;
        } else if (p > start && b[p - 1] == '\r' && b[p + 1] == '\r') {
            if (p + 2 >= len) { at = p; break; }
            if (b[p + 2] != '\n') { at = p + 1; continue; }
            end = p - 1;
            next = p + 3;
        } else {
            at = p + 1;
            continue;
        }
        if (end - start > FW_MAX_EVENT) { acc_too_large(a, "SSE event", FW_MAX_EVENT); return; }
        b[end] = 0;
        sse_lines(a, b + start);
        start = at = next;
    }
    if (start) {
        memmove(b, b + start, len - start);
        a->raw.len = len - start;
        b[a->raw.len] = 0;
    }
    a->scanned = at - start;
    if (a->raw.len > FW_MAX_EVENT) acc_too_large(a, "SSE event", FW_MAX_EVENT);
}

/* write callback; returning less than n makes the transport stop */
static size_t on_data(char *ptr, size_t sz, size_t nm, void *ud) {
    Acc *a = ud;
    size_t n = sz * nm;
    if (a->fatal[0]) return 0;
    if (n > a->limit - a->total) { acc_too_large(a, "response", a->limit); return 0; }
    a->total += n;
    if (!sb_cat(&a->raw, ptr, n)) { acc_fail(a, "out of memory"); return 0; }
    if (a->cb && a->cb->stream) sse_consume(a);
    return a->fatal[0] ? 0 : n;
}

/* parse what is left once a 2xx body has fully arrived */
static void acc_finish(Acc *a, bool stream) {
    if (!stream) {
        acc_chunk(a, a->raw.buf ? a->raw.buf : "{}");
    } else if (a->raw.len) {
        /* last event without a blank line; a plain JSON body is not SSE */
        char *rest = str_dup(a->raw.buf);
        if (rest) sse_lines(a, rest);
        else acc_fail(a, "out of memory");
        free(rest);
    }
    /* long http errors land as JSON with error field */
    if (!a->err[0] && !a->content.len && !a->ntcs && a->raw.buf) {
        cJSON *j = cJSON_Parse(a->raw.buf);
        cJSON *e = j ? cJSON_GetObjectItemCaseSensitive(j, "error") : NULL;
        if (e) {
            char *s = cJSON_PrintUnformatted(e);
            snprintf(a->err, sizeof a->err, "%s", s ? s : "server error");
            free(s);
        }
        if (j) cJSON_Delete(j);
    }
}

/* the tool calls in index order, or NULL; ownership moves to the caller */
static cJSON *acc_take_tool_calls(Acc *a) {
    if (!a->ntcs) return NULL;
    cJSON *arr = cJSON_CreateArray();
    if (!arr) { acc_fail(a, "out of memory"); return NULL; }
    for (int i = 0; i < a->ntcs; i++) {
        if (!a->tcs[i]) continue;
        if (a->args[i].buf)
            set_string(a, cJSON_GetObjectItemCaseSensitive(a->tcs[i], "function"),
                       "arguments", a->args[i].buf);
        cJSON_AddItemToArray(arr, a->tcs[i]);
        a->tcs[i] = NULL;
    }
    return arr;
}

/* everything not handed over to a ChatResp */
static void acc_free(Acc *a) {
    free(a->raw.buf);
    free(a->content.buf);
    free(a->thinking.buf);
    for (int i = 0; i < MAX_TOOL_CALLS; i++) {
        free(a->args[i].buf);
        cJSON_Delete(a->tcs[i]);
    }
}


/* poll stdin for Esc/ctrl-c while a request streams (TUI) — sets g_abort */
#ifndef FW_MINI_HTTP
static int on_progress(void *ud, curl_off_t a, curl_off_t b, curl_off_t c, curl_off_t d) {
    (void)a;(void)b;(void)c;(void)d;(void)ud;
    if (g_abort) return 1;
    if (fw_tick_hook) fw_tick_hook();
    return g_abort ? 1 : 0;
}
#endif

/* a reply for a request that never left; NULL if even that cannot be built */
static ChatResp *chat_failed(const char *why) {
    ChatResp *r = calloc(1, sizeof *r);
    if (!r) return NULL;
    r->error = str_dup(why);
    r->finish = str_dup("stop");
    if (!r->error || !r->finish) { chat_resp_free(r); return NULL; }
    return r;
}

ChatResp *chat(Msgs *msgs, StreamCb *cb) {
    char url[512];
    snprintf(url, sizeof url, "%s/chat/completions", g_cfg.endpoint);

    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "model", g_cfg.model);
    cJSON_AddItemToObject(body, "messages", msgs_to_json(msgs));
    cJSON *tools = cJSON_CreateArray();
    cJSON *tool = cJSON_CreateObject();
    cJSON_AddStringToObject(tool, "type", "function");
    cJSON *fn = cJSON_CreateObject();
    cJSON_AddStringToObject(fn, "name", "bash");
    cJSON_AddStringToObject(fn, "description",
        "Run a bash command in the project directory. Returns stdout+stderr (truncated).");
    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "type", "object");
    cJSON *props = cJSON_CreateObject();
    cJSON *cmd = cJSON_CreateObject();
    cJSON_AddStringToObject(cmd, "type", "string");
    cJSON_AddItemToObject(props, "command", cmd);
    /* agent.c reads it only when commands are sandboxed */
    if (sandbox_on()) {
        cJSON *net = cJSON_CreateObject();
        cJSON_AddStringToObject(net, "type", "boolean");
        cJSON_AddStringToObject(net, "description",
            "Set to true only if this command needs external network access. The user must approve it every time; without it the command has no external network.");
        cJSON_AddItemToObject(props, "network", net);
    }
    cJSON_AddItemToObject(params, "properties", props);
    cJSON *req = cJSON_CreateArray();
    cJSON_AddItemToArray(req, cJSON_CreateString("command"));
    cJSON_AddItemToObject(params, "required", req);
    cJSON_AddItemToObject(fn, "parameters", params);
    cJSON_AddItemToObject(tool, "function", fn);
    cJSON_AddItemToArray(tools, tool);

    /* write_file — structured creation/rewrite, no shell quoting pitfalls */
    cJSON *tw = cJSON_CreateObject();
    cJSON_AddStringToObject(tw, "type", "function");
    cJSON *fw = cJSON_CreateObject();
    cJSON_AddStringToObject(fw, "name", "write_file");
    cJSON_AddStringToObject(fw, "description",
        "Write a file with the exact full content. ALWAYS prefer this over bash heredoc/cat/echo for creating or rewriting files — no quoting or escaping issues. Parent directories are created automatically. Path must be inside the project directory.");
    cJSON *pw = cJSON_CreateObject();
    cJSON_AddStringToObject(pw, "type", "object");
    cJSON *prw = cJSON_CreateObject();
    cJSON *p1 = cJSON_CreateObject(); cJSON_AddStringToObject(p1, "type", "string");
    cJSON_AddStringToObject(p1, "description", "file path, relative to the project directory");
    cJSON_AddItemToObject(prw, "path", p1);
    cJSON *p2 = cJSON_CreateObject(); cJSON_AddStringToObject(p2, "type", "string");
    cJSON_AddStringToObject(p2, "description", "the complete file content");
    cJSON_AddItemToObject(prw, "content", p2);
    cJSON_AddItemToObject(pw, "properties", prw);
    cJSON *rqw = cJSON_CreateArray();
    cJSON_AddItemToArray(rqw, cJSON_CreateString("path"));
    cJSON_AddItemToArray(rqw, cJSON_CreateString("content"));
    cJSON_AddItemToObject(pw, "required", rqw);
    cJSON_AddItemToObject(fw, "parameters", pw);
    cJSON_AddItemToObject(tw, "function", fw);
    cJSON_AddItemToArray(tools, tw);

    /* edit_file — unique-match replacement */
    cJSON *te = cJSON_CreateObject();
    cJSON_AddStringToObject(te, "type", "function");
    cJSON *fe = cJSON_CreateObject();
    cJSON_AddStringToObject(fe, "name", "edit_file");
    cJSON_AddStringToObject(fe, "description",
        "Replace exactly one occurrence of old_string with new_string in an existing file. old_string must match exactly one location, so include enough surrounding context. ALWAYS prefer this over sed/perl/awk for editing files.");
    cJSON *pe = cJSON_CreateObject();
    cJSON_AddStringToObject(pe, "type", "object");
    cJSON *pre2 = cJSON_CreateObject();
    cJSON *e1 = cJSON_CreateObject(); cJSON_AddStringToObject(e1, "type", "string");
    cJSON_AddItemToObject(pre2, "path", e1);
    cJSON *e2 = cJSON_CreateObject(); cJSON_AddStringToObject(e2, "type", "string");
    cJSON_AddItemToObject(pre2, "old_string", e2);
    cJSON *e3 = cJSON_CreateObject(); cJSON_AddStringToObject(e3, "type", "string");
    cJSON_AddItemToObject(pre2, "new_string", e3);
    cJSON_AddItemToObject(pe, "properties", pre2);
    cJSON *rqe = cJSON_CreateArray();
    cJSON_AddItemToArray(rqe, cJSON_CreateString("path"));
    cJSON_AddItemToArray(rqe, cJSON_CreateString("old_string"));
    cJSON_AddItemToArray(rqe, cJSON_CreateString("new_string"));
    cJSON_AddItemToObject(pe, "required", rqe);
    cJSON_AddItemToObject(fe, "parameters", pe);
    cJSON_AddItemToObject(te, "function", fe);
    cJSON_AddItemToArray(tools, te);

    cJSON_AddItemToObject(body, "tools", tools);
    cJSON_AddNumberToObject(body, "max_tokens", g_cfg.maxtok);
    cJSON_AddNumberToObject(body, "temperature", g_cfg.temp);
    if (g_cfg.temp > 0) cJSON_AddNumberToObject(body, "top_p", g_cfg.top_p);
    if (g_cfg.pp > 0) cJSON_AddNumberToObject(body, "presence_penalty", g_cfg.pp);
    if (g_cfg.think_budget > 0)
        cJSON_AddNumberToObject(body, "thinking_token_budget", g_cfg.think_budget);
    if (cb && cb->stream) {
        cJSON_AddTrueToObject(body, "stream");
        cJSON *so = cJSON_CreateObject();
        cJSON_AddTrueToObject(so, "include_usage");
        cJSON_AddItemToObject(body, "stream_options", so);
    }
    char *payload = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!payload) return chat_failed("out of memory");

    Acc a = {0};
    a.cb = cb;
    a.limit = FW_MAX_RESPONSE;
#ifndef FW_MINI_HTTP
    /* cached handle: TCP/TLS connection reuse across turns (localhost latency matters) */
    static CURL *hc;
    if (!hc) hc = curl_easy_init();
    CURL *h = hc;
    if (!h) { free(payload); return chat_failed("could not initialize libcurl"); }
    curl_easy_reset(h);
    struct curl_slist *hdrs = curl_slist_append(NULL, "Content-Type: application/json");
    if (hdrs && cb && cb->stream) {
        struct curl_slist *more = curl_slist_append(hdrs, "Accept: text/event-stream");
        if (!more) curl_slist_free_all(hdrs);
        hdrs = more;
    }
    if (!hdrs) { free(payload); return chat_failed("out of memory"); }
    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, on_data);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &a);
    curl_easy_setopt(h, CURLOPT_TIMEOUT, g_cfg.req_timeout > 0 ? (long)g_cfg.req_timeout : 3600L);
    curl_easy_setopt(h, CURLOPT_XFERINFOFUNCTION, on_progress);
    curl_easy_setopt(h, CURLOPT_XFERINFODATA, NULL);
    curl_easy_setopt(h, CURLOPT_NOPROGRESS, 0L);
#endif

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
#ifdef FW_MINI_HTTP
    char merr[256] = "";
    int status = 0;
    int mrc = fw_mini_post_stream(url, payload, cb && cb->stream, on_data, &a,
                                  g_cfg.req_timeout > 0 ? g_cfg.req_timeout : 3600,
                                  &status, merr, sizeof merr);
#else
    CURLcode rc = curl_easy_perform(h);
    long status = 0;
    curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &status);
#endif
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

#ifdef FW_MINI_HTTP
    bool broken = mrc != 0;
#else
    bool broken = rc != CURLE_OK;
#endif
    ChatResp *r = calloc(1, sizeof *r);
    if (!r) goto out;             /* the caller treats NULL as a failed request */
    r->secs = secs;
    const char *why = NULL;
    if (broken && g_abort) {
        why = "aborted";
    } else if (a.fatal[0]) {
        why = a.fatal;            /* we stopped the transfer ourselves */
    } else if (broken) {
#ifdef FW_MINI_HTTP
        /* -2: the minihttp reader rejected the response; retrying cannot help */
        snprintf(a.err, sizeof a.err, "%s%s", mrc == -2 ? "bad response: " : "http: ",
                 merr[0] ? merr : "transport error");
#else
        snprintf(a.err, sizeof a.err, "curl: %s", curl_easy_strerror(rc));
#endif
        why = a.err;
    } else if (status < 200 || status >= 300) {
        /* "http:" prefix marks it retryable; client errors are final */
        snprintf(a.err, sizeof a.err, "%sstatus %d %.180s",
                 status == 429 || status >= 500 ? "http: " : "", (int)status,
                 a.raw.buf ? a.raw.buf : "");
        why = a.err;
    } else {
        acc_finish(&a, cb && cb->stream);
        if (a.fatal[0]) why = a.fatal;
        else if (a.err[0]) why = a.err;
        else if (!a.finish[0] && !a.done)
            why = "http: response ended without finish_reason or [DONE]";
    }
    r->tool_calls = acc_take_tool_calls(&a);
    if (!why && a.fatal[0]) why = a.fatal;
    r->error = str_dup(why);
    r->content = a.content.buf;
    r->reasoning = a.thinking.buf;
    a.content.buf = a.thinking.buf = NULL;
    r->finish = str_dup(a.finish[0] ? a.finish : "stop");
    r->prompt_tokens = a.ptok;
    r->completion_tokens = a.ctok;
    /* the agent reads finish, and a failure must never look like success */
    if (!r->finish || (why && !r->error)) {
        chat_resp_free(r);
        r = NULL;
    }
out:
    acc_free(&a);
#ifndef FW_MINI_HTTP
    curl_slist_free_all(hdrs);
#endif
    free(payload);
    return r;
}

char *http_get(const char *path) {
    char url[512];
    snprintf(url, sizeof url, "%s%s", g_cfg.endpoint, path);
    return http_get_url(url);
}

char *http_get_url(const char *url) {
#ifdef FW_MINI_HTTP
    return fw_mini_get(url);
#else
    CURL *h = curl_easy_init();
    if (!h) return NULL;
    Acc a = {0};
    a.limit = FW_MAX_GET;
    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, on_data);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &a);
    curl_easy_setopt(h, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(h, CURLOPT_FAILONERROR, 1L);
    CURLcode rc = curl_easy_perform(h);
    curl_easy_cleanup(h);
    if (a.fatal[0]) fprintf(stderr, "http get: %s\n", a.fatal);
    if (rc != CURLE_OK || a.fatal[0]) { free(a.raw.buf); return NULL; }
    return a.raw.buf;
#endif
}

void chat_resp_free(ChatResp *r) {
    if (!r) return;
    free(r->content); free(r->reasoning); free(r->finish); free(r->error);
    if (r->tool_calls) cJSON_Delete(r->tool_calls);
    free(r);
}
