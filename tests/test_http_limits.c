/* Limits and hostile replies in the HTTP layer, against a loopback server.
   Built with small caps (see "test-http" in the Makefile). */
#include "../src/flywheel.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

Cfg g_cfg;
volatile sig_atomic_t g_abort = 0;

static int pass, fail;
static void T(const char *name, bool ok) {
    if (ok) pass++;
    else { fail++; printf("FAIL %s\n", name); }
}

typedef struct { char *p; size_t len, cap; } Buf;

static void put_n(Buf *b, const char *s, size_t n) {
    if (b->len + n + 1 > b->cap) {
        b->cap = (b->len + n + 1) * 2;
        b->p = realloc(b->p, b->cap);
        if (!b->p) exit(2);
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = 0;
}
static void put(Buf *b, const char *s) { put_n(b, s, strlen(s)); }

/* answer one connection with the given bytes, `slice` of them per write */
static pid_t serve(const char *reply, size_t len, size_t slice) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {.sin_family = AF_INET};
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t sl = sizeof sa;
    if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sl) || listen(fd, 4) ||
        getsockname(fd, (struct sockaddr *)&sa, &sl)) exit(2);
    free(g_cfg.endpoint);
    char ep[64];
    snprintf(ep, sizeof ep, "http://127.0.0.1:%d/v1", ntohs(sa.sin_port));
    g_cfg.endpoint = str_dup(ep);
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) exit(2);
    if (pid == 0) {
        alarm(20);
        int c = accept(fd, NULL, NULL);
        if (c < 0) _exit(1);
        /* take the whole request so closing does not reset the reply */
        static char req[1 << 16];
        size_t got = 0, want = 0;
        while (got < sizeof req - 1) {
            ssize_t n = read(c, req + got, sizeof req - 1 - got);
            if (n <= 0) break;
            got += (size_t)n;
            req[got] = 0;
            char *body = strstr(req, "\r\n\r\n");
            if (body) {
                char *cl = strstr(req, "Content-Length:");
                want = (size_t)(body + 4 - req) + (cl ? strtoul(cl + 15, NULL, 10) : 0);
                if (got >= want) break;
            }
        }
        for (size_t at = 0; at < len;) {
            size_t n = len - at < slice ? len - at : slice;
            ssize_t w = write(c, reply + at, n);
            if (w <= 0) break;
            at += (size_t)w;
            if (slice < 64) usleep(200);
        }
        close(c);
        _exit(0);
    }
    close(fd);
    return pid;
}

static void stop(pid_t p) {
    kill(p, SIGKILL);
    waitpid(p, NULL, 0);
}

static ChatResp *ask(const char *reply, size_t len, size_t slice, bool stream) {
    pid_t p = serve(reply, len, slice);
    Msgs m;
    msgs_init(&m);
    msgs_push(&m, "user", "hi");
    StreamCb cb = {0};
    cb.stream = stream;
    ChatResp *r = chat(&m, &cb);
    msgs_free(&m);
    stop(p);
    return r;
}

/* these words make agent.c retry; a size or limit error must not be retried */
static bool retryable(const char *e) {
    return !strncmp(e, "http:", 5) || !strncmp(e, "curl:", 5) || strstr(e, "connect") ||
           strstr(e, "timeout") || strstr(e, "read failed") || strstr(e, "closed");
}

static void expect_error(const char *name, ChatResp *r, const char *frag) {
    bool ok = r && r->error && strstr(r->error, frag);
    T(name, ok);
    if (!ok) printf("     got: %s\n", r && r->error ? r->error : "(no error)");
    chat_resp_free(r);
}

static void expect_final_error(const char *name, ChatResp *r, const char *frag) {
    T(name, r && r->error && !retryable(r->error));
    expect_error(name, r, frag);
}

#define OK_HDR "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"
#define STOPPED "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"
#define END "data: [DONE]\n\n"

static void tool_event(Buf *b, const char *index, const char *name, const char *args) {
    put(b, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{");
    if (index) { put(b, "\"index\":"); put(b, index); put(b, ","); }
    put(b, "\"function\":{\"name\":\""); put(b, name);
    put(b, "\",\"arguments\":\""); put(b, args);
    put(b, "\"}}]}}]}\n\n");
}

static void calls_reply(Buf *b, int n) {
    put(b, OK_HDR);
    for (int i = 0; i < n; i++) {
        char idx[16];
        snprintf(idx, sizeof idx, "%d", i);
        tool_event(b, idx, "bash", "{}");
    }
    put(b, STOPPED END);
}

static void test_tool_calls(void) {
    Buf b = {0};
    calls_reply(&b, 64);
    ChatResp *r = ask(b.p, b.len, 4096, true);
    T("64 tool calls are all kept", r && !r->error && cJSON_GetArraySize(r->tool_calls) == 64);
    chat_resp_free(r);

    b.len = 0;
    calls_reply(&b, 65);
    expect_final_error("65th tool call is an error, not dropped", ask(b.p, b.len, 4096, true),
                       "too many tool calls");

    b.len = 0;
    put(&b, OK_HDR "{\"choices\":[{\"message\":{\"tool_calls\":[");
    for (int i = 0; i < 65; i++)
        put(&b, i ? ",{\"function\":{\"name\":\"bash\"}}" : "{\"function\":{\"name\":\"bash\"}}");
    put(&b, "]},\"finish_reason\":\"tool_calls\"}]}");
    expect_final_error("65 calls without index are an error", ask(b.p, b.len, 4096, false),
                       "too many tool calls");

    static const char *const bad[] = {"1e300", "-1", "64", NULL};
    for (int i = 0; bad[i]; i++) {
        b.len = 0;
        put(&b, OK_HDR);
        tool_event(&b, bad[i], "bash", "{}");
        put(&b, STOPPED END);
        expect_final_error(bad[i], ask(b.p, b.len, 4096, true), "tool-call index");
    }

    b.len = 0;
    put(&b, OK_HDR);
    Buf want = {0};
    for (int i = 0; i < 1500; i++) {
        char piece[16];
        snprintf(piece, sizeof piece, "%04d;", i);
        put(&want, piece);
        tool_event(&b, "0", i ? "" : "bash", piece);
    }
    put(&b, STOPPED END);
    r = ask(b.p, b.len, 4096, true);
    cJSON *call = r ? cJSON_GetArrayItem(r->tool_calls, 0) : NULL;
    cJSON *args = cJSON_GetObjectItemCaseSensitive(
        cJSON_GetObjectItemCaseSensitive(call, "function"), "arguments");
    T("argument fragments are joined in order",
      r && !r->error && cJSON_IsString(args) && !strcmp(args->valuestring, want.p));
    chat_resp_free(r);
    free(want.p);
    free(b.p);
}

static void test_sizes(void) {
    Buf b = {0};
    put(&b, OK_HDR);
    while (b.len < FW_MAX_RESPONSE + 4096)
        put(&b, "data: {\"choices\":[{\"delta\":{\"content\":\"xxxxxxxxxxxxxxxx\"}}]}\n\n");
    put(&b, STOPPED END);
    expect_final_error("oversized stream is an error", ask(b.p, b.len, 4096, true),
                       "response too large");

    b.len = 0;
    put(&b, OK_HDR "{\"choices\":[{\"message\":{\"content\":\"");
    while (b.len < FW_MAX_RESPONSE + 4096) put(&b, "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy");
    put(&b, "\"},\"finish_reason\":\"stop\"}]}");
    expect_final_error("oversized body is an error", ask(b.p, b.len, 4096, false),
                       "response too large");

    b.len = 0;
    put(&b, OK_HDR "data: ");
    while (b.len < FW_MAX_EVENT + 4096) put(&b, "zzzzzzzzzzzzzzzz");
    expect_final_error("endless SSE line is an error", ask(b.p, b.len, 4096, true),
                       "SSE event too large");
    put(&b, "\n\n" STOPPED END);
    expect_final_error("oversized SSE event is an error", ask(b.p, b.len, 65536, true),
                       "SSE event too large");
    free(b.p);
}

static void test_framing(void) {
    static const char crlf[] = OK_HDR
        "data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\r\n\r\n"
        ": comment\r\n\r\n"
        "data: {\"choices\":[{\"delta\":{\"content\":\"b\"},\"finish_reason\":\"stop\"}]}\r\n\r\n"
        "data: {\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":2}}\n\n" END;
    static const size_t slices[] = {1, 2, 3, 5, 4096};
    for (int i = 0; i < 5; i++) {
        ChatResp *r = ask(crlf, sizeof crlf - 1, slices[i], true);
        T("events split at any byte", r && !r->error && r->content && !strcmp(r->content, "ab") &&
          r->prompt_tokens == 7 && r->completion_tokens == 2);
        chat_resp_free(r);
    }

    static const char nul[] = OK_HDR ": \0 junk\n\n"
        "data: {\"choices\":[{\"delta\":{\"content\":\"after\"},\"finish_reason\":\"stop\"}]}\n\n" END;
    ChatResp *r = ask(nul, sizeof nul - 1, 4096, true);
    T("a NUL byte does not stall the stream",
      r && !r->error && r->content && !strcmp(r->content, "after"));
    chat_resp_free(r);

    static const char usage[] = OK_HDR
        "data: {\"usage\":{\"prompt_tokens\":1e300,\"completion_tokens\":-1e300}}\n\n" STOPPED END;
    r = ask(usage, sizeof usage - 1, 4096, true);
    T("absurd token counts are ignored", r && !r->error && !r->prompt_tokens && !r->completion_tokens);
    chat_resp_free(r);
}

static char *get(const char *reply, size_t len) {
    pid_t p = serve(reply, len, 4096);
    char *o = http_get("/models");
    stop(p);
    return o;
}

static void test_get(void) {
    static const char small[] = OK_HDR "{\"data\":[]}";
    char *o = get(small, sizeof small - 1);
    T("small GET body", o && !strcmp(o, "{\"data\":[]}"));
    free(o);

    Buf b = {0};
    put(&b, OK_HDR);
    while (b.len < FW_MAX_GET * 2) put(&b, "0123456789abcdef");
    o = get(b.p, b.len);
    T("oversized GET body is refused", o == NULL);
    free(o);
    free(b.p);
}

#ifdef FW_MINI_HTTP
static void test_mini(void) {
    static const char *const bad_length[] = {"-5", "99999999999999999999", "12abc", "", NULL};
    Buf b = {0};
    for (int i = 0; bad_length[i]; i++) {
        b.len = 0;
        put(&b, "HTTP/1.1 200 OK\r\nContent-Length: ");
        put(&b, bad_length[i]);
        put(&b, "\r\n\r\n" STOPPED END);
        expect_error("bad Content-Length", ask(b.p, b.len, 4096, true), "bad Content-Length");
    }

    b.len = 0;
    put(&b, "HTTP/1.1 200 OK\r\n");
    for (int i = 0; i < 1000; i++) put(&b, "X-Pad: 1\r\n");
    put(&b, "\r\n" STOPPED END);
    expect_error("header count is bounded", ask(b.p, b.len, 4096, true), "too many response headers");

    b.len = 0;
    put(&b, "HTTP/1.1 200 OK\r\nX-Pad: ");
    while (b.len < 20000) put(&b, "pppppppppppppppp");
    put(&b, "\r\n\r\n" STOPPED END);
    expect_error("header line is bounded", ask(b.p, b.len, 4096, true), "header line too long");

    static const char small[] = OK_HDR "ok";
    pid_t p = serve(small, sizeof small - 1, 4096);
    Buf url = {0};
    put(&url, g_cfg.endpoint);
    put(&url, "/");
    while (url.len < 2000) put(&url, "aaaaaaaaaaaaaaaa");
    char *o = http_get_url(url.p);
    T("an over-long path is not silently cut", o == NULL);
    free(o);
    stop(p);
    free(url.p);
    free(b.p);
}
#endif

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    g_cfg.model = str_dup("m");
    g_cfg.maxtok = 16;
    g_cfg.req_timeout = 10;
    test_tool_calls();
    test_sizes();
    test_framing();
    test_get();
#ifdef FW_MINI_HTTP
    test_mini();
#endif
    free(g_cfg.model);
    free(g_cfg.endpoint);
    printf("http limits: %d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
