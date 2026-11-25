#include "flywheel.h"

void msgs_init(Msgs *m) { m->v = NULL; m->n = m->cap = 0; }

static void grow(Msgs *m) {
    if (m->n < m->cap) return;
    m->cap = m->cap ? m->cap * 2 : 16;
    m->v = realloc(m->v, m->cap * sizeof(Msg));
}

static void push(Msgs *m, const char *role, const char *content,
                 const char *tcid, cJSON *tcs) {
    grow(m);
    Msg *x = &m->v[m->n++];
    x->role = str_dup(role);
    x->content = content ? str_dup(content) : NULL;
    if (x->content) utf8_sanitize(x->content);
    x->tool_call_id = tcid ? str_dup(tcid) : NULL;
    x->tool_calls = tcs;
}

void msgs_push(Msgs *m, const char *role, const char *content) {
    push(m, role, content, NULL, NULL);
}

void msgs_push_tool(Msgs *m, const char *tcid, const char *content) {
    push(m, "tool", content, tcid, NULL);
}

void msgs_push_assistant(Msgs *m, const char *content, cJSON *tcs) {
    push(m, "assistant", content, NULL, tcs);
}

void msgs_insert(Msgs *m, int at, const char *role, const char *content) {
    if (at < 0) at = 0;
    if (at > m->n) at = m->n;
    grow(m);
    memmove(&m->v[at + 1], &m->v[at], (m->n - at) * sizeof(Msg));
    m->n++;
    Msg *x = &m->v[at];
    x->role = str_dup(role);
    x->content = content ? str_dup(content) : NULL;
    x->tool_call_id = NULL;
    x->tool_calls = NULL;
}

static void msg_free(Msg *x) {
    free(x->role); free(x->content); free(x->tool_call_id);
    if (x->tool_calls) cJSON_Delete(x->tool_calls);
}

void msgs_trunc(Msgs *m, int n) {
    if (n < 0) n = 0;
    while (m->n > n) msg_free(&m->v[--m->n]);
}

void msgs_free(Msgs *m) {
    msgs_trunc(m, 0);
    free(m->v);
    m->v = NULL; m->cap = 0;
}

cJSON *msgs_to_json(Msgs *m) {
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < m->n; i++) {
        Msg *x = &m->v[i];
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "role", x->role);
        if (x->content) cJSON_AddStringToObject(o, "content", x->content);
        else if (!x->tool_calls) cJSON_AddStringToObject(o, "content", "");
        if (x->tool_calls) cJSON_AddItemToObject(o, "tool_calls", cJSON_Duplicate(x->tool_calls, 1));
        if (x->tool_call_id) cJSON_AddStringToObject(o, "tool_call_id", x->tool_call_id);
        cJSON_AddItemToArray(arr, o);
    }
    return arr;
}
