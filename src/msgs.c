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
    x->images = (Images){0};
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
    x->images = (Images){0};
}

static void msg_free(Msg *x) {
    free(x->role); free(x->content); free(x->tool_call_id);
    if (x->tool_calls) cJSON_Delete(x->tool_calls);
    images_free(&x->images);
}

void image_part_free(ImagePart *p) {
    free(p->url); free(p->source);
    *p = (ImagePart){0};
}

void images_free(Images *s) {
    for (int i = 0; i < s->n; i++) image_part_free(&s->v[i]);
    free(s->v);
    *s = (Images){0};
}

Images images_copy(const Images *s) {
    Images c = {0};
    if (!s->n) return c;
    c.v = malloc((size_t)s->n * sizeof *c.v);
    c.n = s->n;
    for (int i = 0; i < s->n; i++) {
        c.v[i] = s->v[i];
        c.v[i].url = str_dup(s->v[i].url);
        c.v[i].source = str_dup(s->v[i].source);
    }
    return c;
}

static void tally(const Images *s, int *count, size_t *bytes) {
    for (int i = 0; i < s->n; i++) { (*count)++; *bytes += strlen(s->v[i].url); }
}

const char *images_add(Images *set, ImagePart *p, const Msgs *conv) {
    int count = 0;
    size_t bytes = 0;
    if (!p->url) return "empty image";
    for (int i = 0; conv && i < conv->n; i++) tally(&conv->v[i].images, &count, &bytes);
    tally(set, &count, &bytes);
    if (count >= IMG_MAX_COUNT) return "too many images in this conversation (max 64)";
    if (bytes + strlen(p->url) > IMG_MAX_TOTAL)
        return "images in this conversation would exceed 32 MB";
    set->v = realloc(set->v, (size_t)(set->n + 1) * sizeof *set->v);
    set->v[set->n++] = *p;
    *p = (ImagePart){0};
    return NULL;
}

cJSON *images_log_json(const Images *s) {
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < s->n; i++) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "path", s->v[i].source ? s->v[i].source : "");
        cJSON_AddStringToObject(o, "sha256", s->v[i].sha256);
        cJSON_AddNumberToObject(o, "size", (double)s->v[i].size);
        cJSON_AddItemToArray(arr, o);
    }
    return arr;
}

static cJSON *content_parts(const Msg *x) {
    cJSON *arr = cJSON_CreateArray();
    if (x->content && *x->content) {
        cJSON *t = cJSON_CreateObject();
        cJSON_AddStringToObject(t, "type", "text");
        cJSON_AddStringToObject(t, "text", x->content);
        cJSON_AddItemToArray(arr, t);
    }
    for (int i = 0; i < x->images.n; i++) {
        cJSON *p = cJSON_CreateObject();
        cJSON_AddStringToObject(p, "type", "image_url");
        cJSON *u = cJSON_AddObjectToObject(p, "image_url");
        cJSON_AddStringToObject(u, "url", x->images.v[i].url);
        cJSON_AddItemToArray(arr, p);
    }
    return arr;
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
        if (x->images.n) cJSON_AddItemToObject(o, "content", content_parts(x));
        else if (x->content) cJSON_AddStringToObject(o, "content", x->content);
        else if (!x->tool_calls) cJSON_AddStringToObject(o, "content", "");
        if (x->tool_calls) cJSON_AddItemToObject(o, "tool_calls", cJSON_Duplicate(x->tool_calls, 1));
        if (x->tool_call_id) cJSON_AddStringToObject(o, "tool_call_id", x->tool_call_id);
        cJSON_AddItemToArray(arr, o);
    }
    return arr;
}
