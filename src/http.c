#include "flywheel.h"
#include <curl/curl.h>
#include <fcntl.h>
#include <sys/select.h>
#include <termios.h>

typedef struct {
    char *buf;
    size_t len, cap;
} SBuf;

static void sb_cat(SBuf *s, const char *d, size_t n) {
    if (s->len + n + 1 > s->cap) {
        s->cap = (s->len + n + 1) * 2;
        s->buf = realloc(s->buf, s->cap);
    }
    memcpy(s->buf + s->len, d, n);
    s->len += n;
    s->buf[s->len] = 0;
}

typedef struct {
    SBuf raw;              /* unparsed SSE remainder (stream) or whole body */
    SBuf content, thinking;
    cJSON *tcs[64];        /* accumulated tool calls by index */
    int ntcs;
    char finish[64];
    int ptok, ctok;
    StreamCb *cb;
    char err[256];
} Acc;

static void acc_tool_delta(Acc *a, cJSON *tcarr) {
    cJSON *tc;
    cJSON_ArrayForEach(tc, tcarr) {
        cJSON *idx = cJSON_GetObjectItemCaseSensitive(tc, "index");
        int i = cJSON_IsNumber(idx) ? (int)idx->valuedouble : a->ntcs;
        if (i < 0 || i >= 64) continue;
        if (!a->tcs[i]) {
            a->tcs[i] = cJSON_CreateObject();
            cJSON_AddStringToObject(a->tcs[i], "id", "");
            cJSON_AddStringToObject(a->tcs[i], "type", "function");
            cJSON *fn = cJSON_CreateObject();
            cJSON_AddStringToObject(fn, "name", "");
            cJSON_AddStringToObject(fn, "arguments", "");
            cJSON_AddItemToObject(a->tcs[i], "function", fn);
            if (i >= a->ntcs) a->ntcs = i + 1;
        }
        cJSON *id = cJSON_GetObjectItemCaseSensitive(tc, "id");
        if (cJSON_IsString(id) && id->valuestring[0])
            cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(a->tcs[i], "id"), id->valuestring);
        cJSON *fn = cJSON_GetObjectItemCaseSensitive(tc, "function");
        if (fn) {
            cJSON *afn = cJSON_GetObjectItemCaseSensitive(a->tcs[i], "function");
            cJSON *nm = cJSON_GetObjectItemCaseSensitive(fn, "name");
            if (cJSON_IsString(nm) && nm->valuestring[0])
                cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(afn, "name"), nm->valuestring);
            cJSON *ar = cJSON_GetObjectItemCaseSensitive(fn, "arguments");
            if (cJSON_IsString(ar)) {
                cJSON *cur = cJSON_GetObjectItemCaseSensitive(afn, "arguments");
                size_t nl = strlen(cur->valuestring) + strlen(ar->valuestring) + 1;
                char *cat = malloc(nl);
                snprintf(cat, nl, "%s%s", cur->valuestring, ar->valuestring);
                cJSON_SetValuestring(cur, cat);
                free(cat);
            }
        }
    }
}

static void acc_chunk(Acc *a, const char *json) {
    cJSON *j = cJSON_Parse(json);
    if (!j) return;
    cJSON *ch = cJSON_GetObjectItemCaseSensitive(j, "choices");
    cJSON *c0 = ch && cJSON_IsArray(ch) ? cJSON_GetArrayItem(ch, 0) : NULL;
    if (c0) {
        cJSON *d = cJSON_GetObjectItemCaseSensitive(c0, "delta");
        if (!d) d = cJSON_GetObjectItemCaseSensitive(c0, "message"); /* non-stream shape */
        if (d) {
            cJSON *ct = cJSON_GetObjectItemCaseSensitive(d, "content");
            if (cJSON_IsString(ct)) {
                sb_cat(&a->content, ct->valuestring, strlen(ct->valuestring));
                if (a->cb && a->cb->on_text) a->cb->on_text(ct->valuestring, a->cb->ud);
            }
            cJSON *rc = cJSON_GetObjectItemCaseSensitive(d, "reasoning_content");
            if (!rc) rc = cJSON_GetObjectItemCaseSensitive(d, "reasoning");
            if (cJSON_IsString(rc)) {
                sb_cat(&a->thinking, rc->valuestring, strlen(rc->valuestring));
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
        if (cJSON_IsNumber(p)) a->ptok = (int)p->valuedouble;
        if (cJSON_IsNumber(c)) a->ctok = (int)c->valuedouble;
    }
    cJSON_Delete(j);
}

static size_t on_data(char *ptr, size_t sz, size_t nm, void *ud) {
    Acc *a = ud;
    size_t n = sz * nm;
    if (a->cb && a->cb->stream) {
        sb_cat(&a->raw, ptr, n);
        /* consume complete SSE events: lines ending \n\n, "data:"-prefixed */
        for (;;) {
            size_t sep = 2;
            char *e = strstr(a->raw.buf, "\n\n");
            char *e2 = strstr(a->raw.buf, "\r\n\r\n");
            if (e2 && (!e || e2 < e)) { e = e2; sep = 4; }
            if (!e) break;
            *e = 0;
            for (char *ln = a->raw.buf; ln && *ln;) {
                char *nl = strchr(ln, '\n');
                if (nl) *nl = 0;
                size_t ll = strlen(ln);
                if (ll && ln[ll - 1] == '\r') ln[ll - 1] = 0;
                if (!strncmp(ln, "data:", 5)) {
                    const char *d = ln + 5;
                    while (*d == ' ') d++;
                    if (strcmp(d, "[DONE]")) acc_chunk(a, d);
                }
                ln = nl ? nl + 1 : NULL;
            }
            size_t rest = a->raw.len - (size_t)(e - a->raw.buf) - sep;
            memmove(a->raw.buf, e + sep, rest);
            a->raw.len = rest;
            a->raw.buf[rest] = 0;
        }
    } else {
        sb_cat(&a->raw, ptr, n);
    }
    return n;
}


/* poll stdin for Esc/ctrl-c while a request streams (TUI) — sets g_abort */
static int on_progress(void *ud, curl_off_t a, curl_off_t b, curl_off_t c, curl_off_t d) {
    (void)a;(void)b;(void)c;(void)d;(void)ud;
    if (g_abort) return 1;
    if (fw_tick_hook) fw_tick_hook();
    return g_abort ? 1 : 0;
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

    Acc a = {0};
    a.cb = cb;
    /* cached handle: TCP/TLS connection reuse across turns (localhost latency matters) */
    static CURL *hc;
    if (!hc) hc = curl_easy_init();
    CURL *h = hc;
    curl_easy_reset(h);
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    if (cb && cb->stream)
        hdrs = curl_slist_append(hdrs, "Accept: text/event-stream");
    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, on_data);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &a);
    curl_easy_setopt(h, CURLOPT_TIMEOUT, 3600L);
    curl_easy_setopt(h, CURLOPT_XFERINFOFUNCTION, on_progress);
    curl_easy_setopt(h, CURLOPT_XFERINFODATA, NULL);
    curl_easy_setopt(h, CURLOPT_NOPROGRESS, 0L);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    CURLcode rc = curl_easy_perform(h);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    ChatResp *r = calloc(1, sizeof *r);
    r->secs = secs;
    if (rc != CURLE_OK) {
        if (g_abort) r->error = str_dup("aborted");
        else snprintf(a.err, sizeof a.err, "curl: %s", curl_easy_strerror(rc)),
             r->error = str_dup(a.err);
    } else if (!cb || !cb->stream) {
        acc_chunk(&a, a.raw.buf ? a.raw.buf : "{}");
    }
    /* long http errors land as JSON with error field */
    if (!r->error && !a.content.len && !a.ntcs && a.raw.buf) {
        cJSON *j = cJSON_Parse(a.raw.buf);
        cJSON *e = j ? cJSON_GetObjectItemCaseSensitive(j, "error") : NULL;
        if (e) {
            char *s = cJSON_PrintUnformatted(e);
            r->error = str_dup(s ? s : "server error");
            free(s);
        }
        if (j) cJSON_Delete(j);
    }
    r->content = a.content.buf;
    r->reasoning = a.thinking.buf;
    r->finish = str_dup(a.finish[0] ? a.finish : "stop");
    r->prompt_tokens = a.ptok;
    r->completion_tokens = a.ctok;
    if (a.ntcs) {
        cJSON *arr = cJSON_CreateArray();
        for (int i = 0; i < a.ntcs; i++)
            if (a.tcs[i]) cJSON_AddItemToArray(arr, a.tcs[i]);
        r->tool_calls = arr;
    }
    free(a.raw.buf);
    curl_slist_free_all(hdrs);
    /* handle cached — no cleanup (process-lifetime) */
    free(payload);
    return r;
}

char *http_get(const char *path) {
    char url[512];
    snprintf(url, sizeof url, "%s%s", g_cfg.endpoint, path);
    return http_get_url(url);
}

char *http_get_url(const char *url) {
    SBuf s = {0};
    CURL *h = curl_easy_init();
    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, on_data);
    Acc a = {0};
    a.cb = NULL;
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &a);
    curl_easy_setopt(h, CURLOPT_TIMEOUT, 5L);
    (void)s;
    CURLcode rc = curl_easy_perform(h);
    curl_easy_cleanup(h);
    if (rc != CURLE_OK) { free(a.raw.buf); return NULL; }
    return a.raw.buf;
}

void chat_resp_free(ChatResp *r) {
    if (!r) return;
    free(r->content); free(r->reasoning); free(r->finish); free(r->error);
    if (r->tool_calls) cJSON_Delete(r->tool_calls);
    free(r);
}
