#define _DARWIN_C_SOURCE 1
#include "mica.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <util.h>

static int g_passed = 0, g_failed = 0;

static void utf8_encode(uint32_t cp, char *out, size_t *len) {
    if (cp < 0x80) {
        out[(*len)++] = (char)cp;
    } else if (cp < 0x800) {
        out[(*len)++] = (char)(0xC0 | (cp >> 6));
        out[(*len)++] = (char)(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        out[(*len)++] = (char)(0xE0 | (cp >> 12));
        out[(*len)++] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[(*len)++] = (char)(0x80 | (cp & 0x3F));
    } else {
        out[(*len)++] = (char)(0xF0 | (cp >> 18));
        out[(*len)++] = (char)(0x80 | ((cp >> 12) & 0x3F));
        out[(*len)++] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[(*len)++] = (char)(0x80 | (cp & 0x3F));
    }
}

static void get_row_text(MicaSession *s, int row, char *buf, size_t cap) {
    int cols = mica_session_cols(s);
    size_t len = 0;
    for (int c = 0; c < cols && len + 16 < cap; c++) {
        MicaCell cell;
        if (!mica_session_get_cell(s, row, c, &cell)) continue;
        if (cell.width == 0) continue; /* continuation cell of wide char */
        if (cell.chars[0] == 0) {
            buf[len++] = ' ';
            continue;
        }
        for (size_t i = 0; i < VTERM_MAX_CHARS_PER_CELL && cell.chars[i] && len + 8 < cap; i++)
            utf8_encode(cell.chars[i], buf, &len);
    }
    while (len > 0 && buf[len - 1] == ' ') len--;
    buf[len] = 0;
}

static void dump_screen(MicaSession *s) {
    int rows = mica_session_rows(s), cols = mica_session_cols(s);
    int cr = 0, cc = 0;
    mica_session_cursor(s, &cr, &cc);
    fprintf(stderr, "--- MicaSession %dx%d cursor=(%d,%d) hist=%zu bp=%d sync=%d ---\n",
            rows, cols, cr, cc, mica_session_history_lines(s),
            mica_session_bracketed_paste(s), mica_session_sync_output_active(s));
    for (int r = 0; r < rows; r++) {
        char line[1024];
        get_row_text(s, r, line, sizeof line);
        fprintf(stderr, "%2d |%s|\n", r, line);
    }
    fprintf(stderr, "------------------------------------------------------------\n");
}

static int find_row(MicaSession *s, const char *needle) {
    int rows = mica_session_rows(s);
    for (int r = 0; r < rows; r++) {
        char line[1024];
        get_row_text(s, r, line, sizeof line);
        if (strstr(line, needle)) return r;
    }
    return -1;
}

static void pump(MicaSession *s, int ms) {
    struct timespec t0, now;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        mica_session_poll(s, 20);
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - t0.tv_sec) * 1000 + (now.tv_nsec - t0.tv_nsec) / 1000000;
        if (elapsed >= ms) break;
    }
}

static bool wait_for_text(MicaSession *s, const char *needle, int timeout_ms) {
    struct timespec t0, now;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        mica_session_poll(s, 25);
        if (find_row(s, needle) >= 0) return true;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - t0.tv_sec) * 1000 + (now.tv_nsec - t0.tv_nsec) / 1000000;
        if (elapsed >= timeout_ms) return false;
    }
}

static bool wait_for_exit(MicaSession *s, int timeout_ms) {
    struct timespec t0, now;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        mica_session_poll(s, 25);
        if (!mica_session_is_running(s)) return true;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - t0.tv_sec) * 1000 + (now.tv_nsec - t0.tv_nsec) / 1000000;
        if (elapsed >= timeout_ms) return false;
    }
}

#define CHECK(s, name, cond) do { \
    if (cond) { g_passed++; } \
    else { g_failed++; fprintf(stderr, "FAIL [%s:%d] %s\n", __FILE__, __LINE__, name); if (s) dump_screen(s); } \
} while (0)

/* ---------- deterministic local mock OpenAI SSE server ---------- */

static int g_srv_fd = -1;
static int g_srv_port = 0;
static volatile bool g_srv_stop = false;

static bool send_all(int fd, const char *s, size_t n) {
    while (n > 0) {
        ssize_t w = write(fd, s, n);
        if (w <= 0) return false;
        s += w; n -= (size_t)w;
    }
    return true;
}

static bool send_sse_chunk(int fd, const char *json) {
    char buf[2048];
    int n = snprintf(buf, sizeof buf, "data: %s\n\n", json);
    return send_all(fd, buf, (size_t)n);
}

/* escape for embedding inside a JSON string */
static void json_esc(const char *s, char *out, size_t cap) {
    size_t w = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p && w + 8 < cap; p++) {
        if (*p == '"' || *p == '\\') { out[w++] = '\\'; out[w++] = (char)*p; }
        else if (*p < 0x20) w += (size_t)snprintf(out + w, cap - w, "\\u%04x", *p);
        else out[w++] = (char)*p;
    }
    out[w] = 0;
}

static void reply(int cfd, const char *key, const char *val, bool tool) {
    static char a[4096], b[8192], j[12288];
    json_esc(val, a, sizeof a);
    if (tool) {
        static char args[4200];
        snprintf(args, sizeof args, "{\"command\":\"%s\"}", a);
        json_esc(args, b, sizeof b);
        snprintf(j, sizeof j, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c\",\"type\":\"function\","
                 "\"function\":{\"name\":\"bash\",\"arguments\":\"%s\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\ndata: [DONE]\n\n", b);
    } else {
        snprintf(j, sizeof j, "data: {\"choices\":[{\"delta\":{\"%s\":\"%s\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n", key, a);
    }
    send_all(cfd, j, strlen(j));
    close(cfd);
}

/* report what the model received: decoded length, newlines, control bytes, tail */
static bool handle_probe(int cfd, const char *last_msg) {
    const char *p = strstr(last_msg, "\"content\":\"");
    if (!p) return false;
    p += 11;
    if (strncmp(p, "PROBE", 5)) return false;
    size_t len = 0, nl = 0, ctl = 0;
    char tail[9] = "        ";
    while (*p && *p != '"') {
        char c = *p++;
        if (c == '\\' && *p) {
            char e = *p++;
            if (e == 'n') { c = '\n'; nl++; }
            else if (e == 't') c = '\t';
            else if (e == 'u') { c = '?'; ctl++; p += 4; }
            else if (e == 'r' || e == 'b' || e == 'f') { c = '?'; ctl++; }
            else c = e;
        }
        memmove(tail, tail + 1, 7);
        tail[7] = c == '\n' ? ' ' : c;
        len++;
    }
    char out[128];
    snprintf(out, sizeof out, "PROBE len=%zu nl=%zu ctl=%zu end=%s", len, nl, ctl, tail);
    reply(cfd, "content", out, false);
    return true;
}

/* hostile commands and model text; returns true if it answered */
static bool handle_security(int cfd, const char *last_msg) {
    static char cmd[2048];
    if (strstr(last_msg, "SEC_HIDE")) {
        size_t w = (size_t)snprintf(cmd, sizeof cmd, "true");
        for (int i = 0; i < 40; i++) w += (size_t)snprintf(cmd + w, sizeof cmd - w, "\n# step %d", i);
        snprintf(cmd + w, sizeof cmd - w, "\ntouch HIDDEN_PAYLOAD");
    } else if (strstr(last_msg, "SEC_WIDE")) {
        size_t w = (size_t)snprintf(cmd, sizeof cmd, "touch a; : ");
        memset(cmd + w, 'A', 170); w += 170;
        snprintf(cmd + w, sizeof cmd - w, "; touch WIDE_PAYLOAD");
    } else if (strstr(last_msg, "SEC_CTRL")) {
        snprintf(cmd, sizeof cmd, "ev\x1b[2Jil touch CR_PAYLOAD #\r\x1b[2K\x7f\xc2\x9b""31m ls");
    } else if (strstr(last_msg, "SEC_OPT")) {
        snprintf(cmd, sizeof cmd, "ev\x1b[2Jil arg");
    } else if (strstr(last_msg, "SEC_EARLY")) {
        snprintf(cmd, sizeof cmd, "touch EARLY_PAYLOAD");
    } else if (strstr(last_msg, "SEC_META")) {
        snprintf(cmd, sizeof cmd, "touch meta_a; touch meta_b");
    } else if (strstr(last_msg, "SEC_MUT")) {
        snprintf(cmd, sizeof cmd, "find . -name nothing-here -delete");
    } else if (strstr(last_msg, "SEC_TEXT")) {
        reply(cfd, "content", "a\x1b]52;c;aGk=\x07""b\x1b[2Jc\n```x\x1b[7mlang\ncode\x1b[8mhid\n```\n[l](ftp://u\x1b[5m)", false);
        return true;
    } else if (strstr(last_msg, "SEC_ZWBODY")) {
        snprintf(cmd, sizeof cmd, "touch zw\xe2\x80\xae\xe2\x80\x8b\xe2\x80\x8d\xef\xb8\x8f\xef\xbb\xbf.x");
    } else if (strstr(last_msg, "SEC_ZWTEXT")) {
        reply(cfd, "content", "z\xe2\x80\xae\xe2\x81\xa6\xe2\x80\x8f\xef\xbb\xbfw", false);
        return true;
    } else if (strstr(last_msg, "SEC_THINK")) {
        reply(cfd, "reasoning_content", "th\x1b[2Jink\xc2\x9b""end", false);
        return true;
    } else if (strstr(last_msg, "SEC_LINK")) {
        reply(cfd, "content", "- xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx "
              "[wrapping link label that runs over the right edge](https://wrap.example)\n\n"
              "| K | V |\n| - | - |\n| k | [a very long table link label that is certainly going to be truncated because it is far wider than the whole terminal](https://cell.example) |\n", false);
        return true;
    } else return false;
    reply(cfd, NULL, cmd, true);
    return true;
}

/* count the image parts of this request: in the last message and in all of them */
static bool handle_images(int cfd, const char *body, const char *last_msg) {
    if (strstr(last_msg, "SHOWPATH")) {          /* image paths in model text */
        reply(cfd, "content", "see ./shot.png", false);
        return true;
    }
    if (strstr(last_msg, "TOOLPATH")) {          /* and in tool output */
        reply(cfd, NULL, "echo ./shot.png", true);
        return true;
    }
    static const char PART[] = "\"type\":\"image_url\"";
    if (!strstr(last_msg, PART) && !strstr(last_msg, "IMGQ")) return false;
    int last = 0, all = 0;
    for (const char *p = last_msg; (p = strstr(p, PART)); p++) last++;
    for (const char *p = body; (p = strstr(p, PART)); p++) all++;
    char out[96];
    snprintf(out, sizeof out, "GOT last=%d all=%d png=%d", last, all,
             strstr(last_msg, "data:image/png;base64,iVBOR") != NULL);
    reply(cfd, "content", out, false);
    return true;
}

/* the flag of Scotland: U+1F3F4, tags "gbsct", U+E007F */
#define FLAG_SCT "\xf0\x9f\x8f\xb4\xf3\xa0\x81\xa7\xf3\xa0\x81\xa2\xf3\xa0\x81\xb3" \
                 "\xf3\xa0\x81\xa3\xf3\xa0\x81\xb4\xf3\xa0\x81\xbf"
#define SEG_PLAIN "FIRSTPART\necho safe  x#; id\nflag " FLAG_SCT " not \xf0\x9f\x8f\xb4 ok!"

static volatile int g_models_delay_ms;      /* hold /models, to press keys during it */

static volatile int g_net_schema = -1;     /* last chat request offered "network" */
static volatile int g_models_one;          /* /models lists a single model */
static volatile int g_models_fail;         /* /models answers 503 */
static char g_chat_model[64];              /* "model" of the last chat request */

static void handle_client(int cfd) {
    static char req[2 << 20];
    size_t got = 0;
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    /* Read HTTP headers + body */
    int content_len = -1;
    char *hdr_end = NULL;
    while (got + 1 < sizeof req) {
        ssize_t r = read(cfd, req + got, sizeof req - 1 - got);
        if (r <= 0) break;
        got += (size_t)r;
        req[got] = 0;
        if (!hdr_end) {
            hdr_end = strstr(req, "\r\n\r\n");
            if (hdr_end) {
                char *cl = strcasestr(req, "Content-Length:");
                if (cl) content_len = atoi(cl + 15);
                else content_len = 0;
            }
        }
        if (hdr_end && (int)(got - (size_t)(hdr_end + 4 - req)) >= content_len) break;
    }
    if (got == 0) { close(cfd); return; }

    if (!strncmp(req, "GET /v1/models", 14)) {
        const char *resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"
                           "{\"data\":[{\"id\":\"mock/qwen\",\"vision\":true},"
                           "{\"id\":\"mock/qwen-alt\",\"vision\":false}]}";
        if (g_models_delay_ms) usleep((useconds_t)g_models_delay_ms * 1000);
        if (g_models_one)
            resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"
                   "{\"data\":[{\"id\":\"mock/solo\"}]}";
        if (g_models_fail)
            resp = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send_all(cfd, resp, strlen(resp));
        close(cfd);
        return;
    }

    const char *body = hdr_end ? hdr_end + 4 : req;
    const char *sse_hdr = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n";
    send_all(cfd, sse_hdr, strlen(sse_hdr));

    g_net_schema = strstr(body, "\"network\":{\"type\":\"boolean\"") != NULL;
    const char *model = strstr(body, "\"model\":\"");
    if (model) snprintf(g_chat_model, sizeof g_chat_model, "%.*s",
                        (int)strcspn(model + 9, "\""), model + 9);

    /* Inspect only the LAST message in the conversation array */
    const char *last_msg = body;
    for (const char *p = body; (p = strstr(p, "\"role\":\"")); p += 8) last_msg = p;

    if (strstr(last_msg, "\"role\":\"tool\"")) {
        send_sse_chunk(cfd, "{\"choices\":[{\"delta\":{\"content\":\"DONE\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}");
        send_all(cfd, "data: [DONE]\n\n", 14);
        close(cfd);
        return;
    }

    if (handle_images(cfd, body, last_msg)) return;
    if (handle_probe(cfd, last_msg)) return;
    if (handle_security(cfd, last_msg)) return;

    if (strstr(last_msg, "PERSIAN_REPLY")) {   /* ZWNJ kept, ZWSP removed */
        reply(cfd, "content", "\xd8\xb3\xd9\x84\xd8\xa7\xd9\x85 \xd9\x85\xdb\x8c\xe2\x80\x8c\xe2\x80\x8b"
              "\xd8\xae\xd9\x88\xd8\xa7\xd9\x87\xd9\x85", false);
        return;
    }

    if (strstr(last_msg, "SEG_REPLY")) {   /* answer split by reasoning, with hidden text */
        static const char *const part[][2] = {
            {"content", "FIRSTPART\\n"},
            {"reasoning_content", "hmm"},
            {"content", "echo safe \xe2\x80\xae\xe2\x81\xa6 x\xf3\xa0\x81\x81\\u001b#; id\\n"},
            {"reasoning_content", "hmm"},
            {"content", "flag " FLAG_SCT " not \xf0\x9f\x8f\xb4\xf3\xa0\x81\xa1\xf3\xa0\x81\xbf "
                        "ok\xe0\x80\xaf\xed\xa0\x80\xf0\x80\x80\xaf!"},
        };
        for (size_t i = 0; i < sizeof part / sizeof *part; i++) {
            char j[512];
            snprintf(j, sizeof j, "{\"choices\":[{\"delta\":{\"%s\":\"%s\"}}]}", part[i][0], part[i][1]);
            send_sse_chunk(cfd, j);
        }
        send_all(cfd, "data: [DONE]\n\n", 14);
        close(cfd);
        return;
    }

    if (strstr(last_msg, "BIG_REPLY")) {       /* 100 lines of 1000 bytes */
        char j[1200], fill[1000];
        memset(fill, 'q', sizeof fill - 1);
        fill[sizeof fill - 1] = 0;
        for (int i = 0; i < 100; i++) {
            snprintf(j, sizeof j, "{\"choices\":[{\"delta\":{\"content\":\"%s\\n\"}}]}", fill);
            send_sse_chunk(cfd, j);
        }
        send_all(cfd, "data: [DONE]\n\n", 14);
        close(cfd);
        return;
    }

    if (strstr(last_msg, "STREAM_TEST")) {
        const char *think[] = {"Let", "'s", " take", " a", " look", NULL};
        for (int i = 0; think[i]; i++) {
            char j[256];
            snprintf(j, sizeof j, "{\"choices\":[{\"delta\":{\"reasoning_content\":\"%s\"}}]}", think[i]);
            send_sse_chunk(cfd, j);
            usleep(10000);
        }
        /* No trailing newline in reasoning_content: TUI must separate thinking from content */
        const char *txt[] = {"Hello", " world", " from", " flywheel!", NULL};
        for (int i = 0; txt[i]; i++) {
            char j[256];
            snprintf(j, sizeof j, "{\"choices\":[{\"delta\":{\"content\":\"%s\"}}]}", txt[i]);
            send_sse_chunk(cfd, j);
            usleep(10000);
        }
        /* Emit a tool call needing approval that produces 6 lines of output (collapsed by default) */
        send_sse_chunk(cfd, "{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"bash\",\"arguments\":\"{\\\"command\\\":\\\"seq 1 6 | sed 's/^/out-line-/'\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":20,\"completion_tokens\":15}}");
        send_all(cfd, "data: [DONE]\n\n", 14);
        close(cfd);
        return;
    }

    if (strstr(last_msg, "WANTNET")) {
        send_sse_chunk(cfd, "{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_n\",\"type\":\"function\",\"function\":{\"name\":\"bash\",\"arguments\":\"{\\\"command\\\":\\\"touch net-file\\\",\\\"network\\\":true}\"}}]},\"finish_reason\":\"tool_calls\"}]}");
        send_all(cfd, "data: [DONE]\n\n", 14);
        close(cfd);
        return;
    }

    if (strstr(last_msg, "ALWAYS_TEST")) {
        send_sse_chunk(cfd, "{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_2\",\"type\":\"function\",\"function\":{\"name\":\"bash\",\"arguments\":\"{\\\"command\\\":\\\"uname -s\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":10}}");
        send_all(cfd, "data: [DONE]\n\n", 14);
        close(cfd);
        return;
    }

    if (strstr(last_msg, "MD_TEST")) {
        const char *md =
            "# Project Overview\\n"
            "This has **boldtext**, *italics*, `inline_fn()`, and snake_case_ok plus [Mica](https://example.com).\\n"
            "- Bullet one\\n"
            "1. Step one\\n"
            "> Quoted note\\n"
            "---\\n"
            "```c\\n"
            "int x = 42;\\n"
            "```\\n"
            "| Key | Val |\\n"
            "| --- | --- |\\n"
            "| mode | fast |\\n";
        char j[2048];
        snprintf(j, sizeof j, "{\"choices\":[{\"delta\":{\"content\":\"%s\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":30}}", md);
        send_sse_chunk(cfd, j);
        send_all(cfd, "data: [DONE]\n\n", 14);
        close(cfd);
        return;
    }

    if (strstr(last_msg, "SCROLL_TEST")) {
        for (int i = 1; i <= 35; i++) {
            char j[256];
            snprintf(j, sizeof j, "{\"choices\":[{\"delta\":{\"content\":\"scroll-line-%02d\\n\"}}]}", i);
            send_sse_chunk(cfd, j);
        }
        send_sse_chunk(cfd, "{\"choices\":[{\"delta\":{\"content\":\"DONE\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":40}}");
        send_all(cfd, "data: [DONE]\n\n", 14);
        close(cfd);
        return;
    }

    if (strstr(last_msg, "SIG_TOOL")) {        /* a command that outlives the TUI unless swept */
        reply(cfd, "content", "echo $$ > sig.child; exec sleep 30", true);
        return;
    }

    if (strstr(last_msg, "SLOW_TEST")) {
        for (int i = 0; i < 60 && !g_srv_stop; i++) {
            char j[256];
            snprintf(j, sizeof j, "{\"choices\":[{\"delta\":{\"content\":\"tick-%d \"}}]}", i);
            if (!send_sse_chunk(cfd, j)) break;
            usleep(150000);
        }
        send_sse_chunk(cfd, "{\"choices\":[{\"delta\":{\"content\":\"DONE\"},\"finish_reason\":\"stop\"}]}");
        send_all(cfd, "data: [DONE]\n\n", 14);
        close(cfd);
        return;
    }

    send_sse_chunk(cfd, "{\"choices\":[{\"delta\":{\"content\":\"DONE\"},\"finish_reason\":\"stop\"}]}");
    send_all(cfd, "data: [DONE]\n\n", 14);
    close(cfd);
}

static void *server_thread(void *arg) {
    (void)arg;
    while (!g_srv_stop) {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(g_srv_fd, &rf);
        struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};
        if (select(g_srv_fd + 1, &rf, NULL, NULL, &tv) <= 0) continue;
        int cfd = accept(g_srv_fd, NULL, NULL);
        if (cfd >= 0) handle_client(cfd);
    }
    return NULL;
}

static void start_mock_server(pthread_t *th) {
    g_srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(g_srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(g_srv_fd, (struct sockaddr *)&addr, sizeof addr) == 0);
    socklen_t alen = sizeof addr;
    assert(getsockname(g_srv_fd, (struct sockaddr *)&addr, &alen) == 0);
    g_srv_port = ntohs(addr.sin_port);
    assert(listen(g_srv_fd, 16) == 0);
    pthread_create(th, NULL, server_thread, NULL);
}

static void stop_mock_server(pthread_t th) {
    g_srv_stop = true;
    pthread_join(th, NULL);
    close(g_srv_fd);
}

static void type_str(MicaSession *s, const char *str) {
    mica_session_write(s, str, strlen(str));
}

static int find_last_row(MicaSession *s, const char *needle) {
    int rows = mica_session_rows(s);
    for (int r = rows - 1; r >= 0; r--) {
        char line[1024];
        get_row_text(s, r, line, sizeof line);
        if (strstr(line, needle)) return r;
    }
    return -1;
}

static void assert_box_borders(MicaSession *s, const char *label) {
    int rows = mica_session_rows(s), cols = mica_session_cols(s);
    int top = find_last_row(s, "╭");
    int bot = find_last_row(s, "╰");
    CHECK(s, label, top >= 0 && bot > top && bot < rows);
    if (top < 0 || bot <= top) return;
    MicaCell c0, c1;
    mica_session_get_cell(s, top, 0, &c0);
    mica_session_get_cell(s, top, cols - 1, &c1);
    CHECK(s, "top border corners aligned", c0.chars[0] == 0x256D && c1.chars[0] == 0x256E);
    mica_session_get_cell(s, bot, 0, &c0);
    mica_session_get_cell(s, bot, cols - 1, &c1);
    CHECK(s, "bottom border corners aligned", c0.chars[0] == 0x2570 && c1.chars[0] == 0x256F);
    for (int r = top + 1; r < bot; r++) {
        mica_session_get_cell(s, r, 0, &c0);
        mica_session_get_cell(s, r, cols - 1, &c1);
        CHECK(s, "input row side borders aligned", c0.chars[0] == 0x2502 && c1.chars[0] == 0x2502);
    }
}

/* ---------- security regressions (own session) ---------- */

static void submit(MicaSession *s, const char *msg) {
    type_str(s, "/clear");
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    pump(s, 120);
    type_str(s, msg);
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
}

static bool open_modal(MicaSession *s, const char *msg) {
    submit(s, msg);
    return wait_for_text(s, "Do you want to proceed?", 4000);
}

static bool made(const char *dir, const char *name) {
    char p[1400];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    return access(p, F_OK) == 0;
}

static void close_modal(MicaSession *s) {
    if (find_row(s, "Do you want to proceed?") >= 0) mica_session_key(s, VTERM_KEY_ESCAPE, VTERM_MOD_NONE);
    wait_for_text(s, "ready", 3000);
    pump(s, 150);
}

/* every cell linking to uri must be a label character */
static bool link_confined(MicaSession *s, const char *uri, int *cells) {
    bool ok = true;
    *cells = 0;
    for (int r = 0; r < mica_session_rows(s); r++)
        for (int c = 0; c < mica_session_cols(s); c++) {
            MicaCell mc;
            if (!mica_session_get_cell(s, r, c, &mc) || !mc.hyperlink_id) continue;
            const char *u = mica_session_hyperlink_uri(s, mc.hyperlink_id);
            if (!u || strcmp(u, uri)) continue;
            (*cells)++;
            if (c < 2 || mc.chars[0] == 0x2502) ok = false;
        }
    return ok;
}

static void security_tests(const char *dir, const char *cmd) {
    MicaSession *s = mica_session_create(dir, cmd, 24, 80);
    assert(s != NULL);
    CHECK(s, "security session ready", wait_for_text(s, "ready", 3000));

    /* long command: full body scrollable, Yes locked until all of it was shown */
    CHECK(s, "hide: modal", open_modal(s, "SEC_HIDE"));
    pump(s, 600);
    CHECK(s, "hide: hidden-line count shown", find_row(s, "lines hidden") >= 0);
    CHECK(s, "hide: payload not yet on screen", find_row(s, "HIDDEN_PAYLOAD") < 0);
    type_str(s, "y");
    type_str(s, "1");
    pump(s, 400);
    CHECK(s, "hide: Yes refused while lines unseen",
          find_row(s, "Do you want to proceed?") >= 0 && !made(dir, "HIDDEN_PAYLOAD"));
    for (int i = 0; i < 6; i++) { type_str(s, "\033[6~"); pump(s, 80); }
    CHECK(s, "hide: scrolling reveals the payload", find_row(s, "touch HIDDEN_PAYLOAD") >= 0);
    type_str(s, "y");
    wait_for_text(s, "✓ done", 4000);
    CHECK(s, "hide: Yes accepted after viewing all", made(dir, "HIDDEN_PAYLOAD"));
    close_modal(s);

    CHECK(s, "wide: modal", open_modal(s, "SEC_WIDE"));
    pump(s, 150);
    CHECK(s, "wide: long line wraps, tail visible", find_row(s, "WIDE_PAYLOAD") >= 0);
    close_modal(s);

    CHECK(s, "ctrl: modal", open_modal(s, "SEC_CTRL"));
    pump(s, 150);
    CHECK(s, "ctrl: CR/ESC/DEL/C1 visible in body", find_row(s, "#^M^[[2K^?\\x9B31m ls") >= 0);
    CHECK(s, "ctrl: no always option for a CR command", find_row(s, "ask again") < 0);
    close_modal(s);
    CHECK(s, "esc option: modal", open_modal(s, "SEC_OPT"));
    pump(s, 150);
    CHECK(s, "esc option: body shows ESC visibly", find_row(s, "ev^[[2Jil arg") >= 0);
    CHECK(s, "esc option: no always option for an unlisted tool",
          find_row(s, "ask again") < 0 && find_row(s, "2. No") >= 0);
    close_modal(s);

    /* type-ahead */
    CHECK(s, "early: modal", open_modal(s, "SEC_EARLY"));
    type_str(s, "y");
    type_str(s, "1");
    pump(s, 800);
    CHECK(s, "early: keys right after open ignored",
          find_row(s, "Do you want to proceed?") >= 0 && !made(dir, "EARLY_PAYLOAD"));
    mica_session_paste(s, "y\n1\n", 4);
    pump(s, 300);
    CHECK(s, "early: pasted text cannot answer",
          find_row(s, "Do you want to proceed?") >= 0 && !made(dir, "EARLY_PAYLOAD"));
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    wait_for_text(s, "✓ done", 4000);
    CHECK(s, "early: Enter on default denies", !made(dir, "EARLY_PAYLOAD"));
    close_modal(s);

    CHECK(s, "meta: modal", open_modal(s, "SEC_META"));
    pump(s, 150);
    CHECK(s, "meta: no always option", find_row(s, "ask again") < 0 && find_row(s, "2. No") >= 0);
    close_modal(s);
    CHECK(s, "mutating: modal", open_modal(s, "SEC_MUT"));
    pump(s, 150);
    CHECK(s, "mutating: no always option", find_row(s, "ask again") < 0 && find_row(s, "2. No") >= 0);
    close_modal(s);

    CHECK(s, "zero-width: modal", open_modal(s, "SEC_ZWBODY"));
    pump(s, 150);
    CHECK(s, "zero-width: visible in modal body",
          find_row(s, "touch zw<U+202E><U+200B><U+200D><U+FE0F><U+FEFF>.x") >= 0);
    close_modal(s);
    submit(s, "SEC_ZWTEXT");
    wait_for_text(s, "✓ done", 4000);
    pump(s, 150);
    CHECK(s, "bidi: visible in transcript", find_row(s, "z<U+202E><U+2066><U+200F><U+FEFF>w") >= 0);

    submit(s, "SEC_TEXT");
    wait_for_text(s, "✓ done", 4000);
    pump(s, 150);
    CHECK(s, "text: OSC 52 / ED rendered inert", find_row(s, "a^[]52;c;aGk=^Gb^[[2Jc") >= 0);
    CHECK(s, "text: fence language sanitized", find_row(s, "x^[[7mlang") >= 0);
    CHECK(s, "text: code line sanitized", find_row(s, "code^[[8mhid") >= 0);
    CHECK(s, "text: link URL sanitized", find_row(s, "ftp://u^[[5m") >= 0);
    submit(s, "SEC_THINK");
    wait_for_text(s, "✓ done", 4000);
    pump(s, 150);
    mica_session_text(s, 'o', VTERM_MOD_CTRL);
    pump(s, 150);
    CHECK(s, "thinking sanitized", find_row(s, "th^[[2Jink\\x9Bend") >= 0);

    submit(s, "SEC_LINK");
    wait_for_text(s, "✓ done", 4000);
    pump(s, 150);
    int n = 0;
    CHECK(s, "wrapped link: closed per row, indent unlinked", link_confined(s, "https://wrap.example", &n));
    CHECK(s, "wrapped link: continuation still linked", n >= 40);
    CHECK(s, "truncated table link does not bleed", link_confined(s, "https://cell.example", &n) && n > 0 && n < 80);

    submit(s, "");
    pump(s, 100);
    mica_session_paste(s, "tab\there", 8);
    pump(s, 200);
    CHECK(s, "pasted tab kept", find_row(s, "tab here") >= 0);
    assert_box_borders(s, "borders intact with pasted tab");

    mica_session_destroy(s);
}

#define PS "\033[200~"
#define PE "\033[201~"

/* raw bytes in small chunks so Mica's pending-input limit is never hit */
static void send_big(MicaSession *s, const char *p, size_t n) {
    while (n > 0) {
        size_t k = n > 2048 ? 2048 : n;
        mica_session_write(s, p, k);
        p += k; n -= k;
        mica_session_poll(s, 2);
    }
}

/* bracketed paste of "PROBE " + fill + "END_TAIL", total bytes long */
static void paste_probe(MicaSession *s, size_t total) {
    char *b = malloc(total + 1);
    memset(b, 'z', total);
    memcpy(b, "PROBE ", 6);
    memcpy(b + total - 8, "END_TAIL", 8);
    type_str(s, PS);
    send_big(s, b, total);
    type_str(s, PE);
    free(b);
}

static void keys(MicaSession *s, const char *k) { type_str(s, k); pump(s, 200); }

static void fresh(MicaSession *s) {
    keys(s, "\x03");
    keys(s, "/clear\r");
}

static void input_tests(const char *dir, const char *cmd) {
    MicaSession *s = mica_session_create(dir, cmd, 24, 80);
    assert(s != NULL);
    CHECK(s, "input: ready", wait_for_text(s, "ready", 3000));
    pump(s, 150);

    /* large pastes reach the model intact, also when recalled from history */
    paste_probe(s, 12000);
    keys(s, "\r");
    CHECK(s, "big paste: 12000 bytes sent intact",
          wait_for_text(s, "PROBE len=12000 nl=0 ctl=0 end=END_TAIL", 5000));
    pump(s, 300);
    fresh(s);
    keys(s, "\033[A");          /* recalls /clear, which opens the menu */
    keys(s, "\033");            /* close it so Up keeps walking history */
    keys(s, "\033[A");
    keys(s, "\r");
    CHECK(s, "big paste: history recall resends it intact", wait_for_text(s, "PROBE len=12000", 5000));
    pump(s, 300);
    fresh(s);
    paste_probe(s, 600000);
    pump(s, 300);
    keys(s, "\r");
    CHECK(s, "big paste: 600000 bytes sent intact",
          wait_for_text(s, "PROBE len=600000 nl=0 ctl=0 end=END_TAIL", 20000));
    pump(s, 500);
    fresh(s);
    paste_probe(s, 1100000);
    CHECK(s, "over cap: visible notice", wait_for_text(s, "over 1 MB", 30000));
    CHECK(s, "over cap: nothing inserted", find_row(s, "Type a message") >= 0);

    /* pasted content is literal */
    fresh(s);
    keys(s, PS "ab\x03" "cd\x04\x15\x0b\x17\x0f\x01\x1b[31mef\x1b[0mgh\x7f\x1bij" PE);
    CHECK(s, "literal: control bytes and SGR never act", find_row(s, "› abcdefghij ") >= 0);
    CHECK(s, "literal: ^D in paste does not quit", mica_session_is_running(s));
    fresh(s);
    keys(s, PS "PROBE\raa\r\nbb" PE);
    CHECK(s, "literal: multiline paste collapses, not submitted",
          find_row(s, "+3 lines]") >= 0 && find_row(s, "PROBE len") < 0);
    keys(s, "\r");
    CHECK(s, "literal: CR and CRLF become one newline",
          wait_for_text(s, "PROBE len=11 nl=2 ctl=0", 4000));
    pump(s, 300);
    fresh(s);
    keys(s, "\033[20");
    keys(s, "0~SPLIT\x15X\033[2");
    keys(s, "01~");
    keys(s, "Y");
    CHECK(s, "split markers: paste recognised", find_row(s, "› SPLITXY ") >= 0);
    fresh(s);
    type_str(s, "\033");
    pump(s, 60);                  /* gap right after the ESC byte */
    keys(s, "[200~LATE\x15MARK" PE);
    CHECK(s, "split marker: gap after ESC", find_row(s, "› LATEMARK ") >= 0);
    fresh(s);
    type_str(s, PS "stuck-text");
    CHECK(s, "unterminated paste: notice after idle", wait_for_text(s, "paste end marker missing", 7000));
    CHECK(s, "unterminated paste: text kept", find_row(s, "› stuck-text") >= 0);
    keys(s, "\x03" "after");
    CHECK(s, "unterminated paste: keys work again",
          find_row(s, "› after") >= 0 && find_row(s, "stuck-text") < 0);

    /* Shift+Enter encodings */
    fresh(s);
    keys(s, "one\033[13;2utwo\033[27;2;13~three");
    int r = find_row(s, "› one");
    CHECK(s, "Shift+Enter: CSI-u and modifyOtherKeys insert newlines",
          r >= 0 && find_row(s, "  two") == r + 1 && find_row(s, "  three") == r + 2);

    /* collapsed tokens are atomic */
    fresh(s);
    keys(s, PS "L1\rL2" PE);
    keys(s, "\x7f");
    CHECK(s, "token: backspace removes it whole",
          find_row(s, "[paste#") < 0 && find_row(s, "Type a message") >= 0);
    keys(s, "\x03" PS "L1\rL2" PE);
    keys(s, "\x01\033[3~");
    CHECK(s, "token: delete removes it whole", find_row(s, "Type a message") >= 0);
    keys(s, "\x03" "word " PS "L1\rL2" PE);
    keys(s, "\x17");
    CHECK(s, "token: ^W removes it whole",
          find_row(s, "[paste#") < 0 && find_row(s, "lines]") < 0 && find_row(s, "› word") >= 0);
    keys(s, "\x03" "PROBE " PS "L1\rL2" PE);
    keys(s, "\033[Da\033[Cb");
    CHECK(s, "token: cursor steps over it",
          find_row(s, "PROBE a[paste#") >= 0 && find_row(s, "lines]b") >= 0);
    keys(s, "\r");
    CHECK(s, "token: expands intact after editing around it", wait_for_text(s, "PROBE len=13 nl=1", 4000));
    pump(s, 300);

    /* a full queue keeps the message */
    fresh(s);
    keys(s, "SLOW_TEST\r");
    CHECK(s, "queue: stream starts", wait_for_text(s, "tick-0", 3000));
    for (int i = 0; i < 8; i++) keys(s, "queued-msg\r");
    keys(s, "ninth-msg\r");
    CHECK(s, "queue full: visible notice", find_row(s, "queue full") >= 0);
    CHECK(s, "queue full: message stays in input", find_row(s, "› ninth-msg") >= 0);
    keys(s, "\x1b");
    CHECK(s, "queue: abort", wait_for_text(s, "error:aborted", 4000));
    pump(s, 300);
    fresh(s);
    keys(s, "SLOW_TEST\r");
    CHECK(s, "queue: second stream starts", wait_for_text(s, "tick-0", 3000));
    paste_probe(s, 20000);
    keys(s, "\r");
    CHECK(s, "queued big paste sent intact",
          wait_for_text(s, "PROBE len=20000 nl=0 ctl=0 end=END_TAIL", 20000));
    pump(s, 300);

    /* paste never answers the approval dialog */
    fresh(s);
    CHECK(s, "modal paste: modal", open_modal(s, "SEC_EARLY"));
    pump(s, 700);
    keys(s, PS "\x03" PE);
    CHECK(s, "modal paste: ^C ignored", find_row(s, "Do you want to proceed?") >= 0);
    keys(s, PS "x\x1b");
    keys(s, "1y\r" PE);
    keys(s, PS "x\x1b\x1b" PE);
    CHECK(s, "modal paste: ESC and digits ignored",
          find_row(s, "Do you want to proceed?") >= 0 && !made(dir, "EARLY_PAYLOAD"));
    pump(s, 700);                /* the guard restarts when a paste ends */
    keys(s, "\r");
    CHECK(s, "modal paste: real Enter still answers (default No)",
          wait_for_text(s, "✓ done", 4000) && !made(dir, "EARLY_PAYLOAD"));
    close_modal(s);
    fresh(s);
    type_str(s, "SEC_EARLY\r" PS "half");
    CHECK(s, "paste across modal open: modal", wait_for_text(s, "Do you want to proceed?", 4000));
    pump(s, 700);
    keys(s, "1y\r");
    keys(s, PE);
    CHECK(s, "paste across modal open: never answers",
          find_row(s, "Do you want to proceed?") >= 0 && !made(dir, "EARLY_PAYLOAD"));
    pump(s, 700);
    keys(s, "\r");
    wait_for_text(s, "✓ done", 4000);
    close_modal(s);

    /* a forged end marker inside the pasted text */
    fresh(s);
    CHECK(s, "forged end: modal", open_modal(s, "SEC_EARLY"));
    pump(s, 700);
    keys(s, PS "x" PE "1y\r" PE);
    CHECK(s, "forged end: following bytes never answer",
          find_row(s, "Do you want to proceed?") >= 0 && !made(dir, "EARLY_PAYLOAD"));
    close_modal(s);

    /* ... also when they keep streaming past the guard time */
    fresh(s);
    CHECK(s, "forged end stream: modal", open_modal(s, "SEC_EARLY"));
    pump(s, 700);
    type_str(s, PS "x" PE);
    for (int i = 0; i < 5; i++) { type_str(s, "z"); pump(s, 200); }
    keys(s, "y");
    pump(s, 500);
    CHECK(s, "forged end stream: later y never answers",
          find_row(s, "Do you want to proceed?") >= 0 && !made(dir, "EARLY_PAYLOAD"));
    close_modal(s);

    /* a stalled paste: the rest of it must not approve */
    fresh(s);
    CHECK(s, "stalled paste: modal", open_modal(s, "SEC_EARLY"));
    pump(s, 700);
    type_str(s, PS "half");
    pump(s, 4500);
    keys(s, "y");
    keys(s, "1");
    CHECK(s, "stalled paste: y and 1 run nothing",
          find_row(s, "Do you want to proceed?") >= 0 && !made(dir, "EARLY_PAYLOAD"));
    CHECK(s, "stalled paste: dialog says so", find_row(s, "paste interrupted") >= 0);
    keys(s, "\x1b");
    CHECK(s, "stalled paste: Esc denies",
          wait_for_text(s, "✓ done", 4000) && !made(dir, "EARLY_PAYLOAD"));

    mica_session_destroy(s);
}

/* ---------- /copy and /mouse ---------- */

/* SEC_TEXT's reply with every escape sequence and control byte removed */
#define SEC_PLAIN "abc\n```xlang\ncodehid\n```\n[l](ftp://u)"

static size_t slurp(const char *path, char *buf, size_t cap) {
    FILE *f = fopen(path, "r");
    size_t n = f ? fread(buf, 1, cap - 1, f) : 0;
    if (f) fclose(f);
    buf[n] = 0;
    return n;
}

static void ask(MicaSession *s, const char *msg) {
    submit(s, msg);
    wait_for_text(s, "✓ done", 8000);
    pump(s, 200);
}

/* every session here finds a fake pbcopy first on PATH: the real clipboard is never touched */
static void copy_tests(const char *dir, const char *cmd) {
    char bin[1100], script[1200], clip[1200], failflag[1200];
    char outside[] = "/tmp/fwcopy-XXXXXX";
    assert(mkdtemp(outside) != NULL);
    snprintf(bin, sizeof bin, "%s/fakebin", outside);
    snprintf(script, sizeof script, "%s/pbcopy", bin);
    snprintf(clip, sizeof clip, "%s/clip.txt", dir);
    snprintf(failflag, sizeof failflag, "%s/pbfail", dir);
    assert(mkdir(bin, 0700) == 0);
    FILE *f = fopen(script, "w");
    assert(f != NULL);
    fprintf(f, "#!/bin/sh\nif [ -e '%s' ]; then cat >/dev/null; exit 1; fi\nexec cat > '%s'\n", failflag, clip);
    fclose(f);
    assert(chmod(script, 0700) == 0);

    static char full[8192], got[1 << 17];
    snprintf(full, sizeof full, "unset SSH_CONNECTION SSH_TTY SSH_CLIENT TMUX; export TERM_PROGRAM=Apple_Terminal; "
             "export PATH='%s':\"$PATH\"; %s", bin, cmd);
    MicaSession *s = mica_session_create(dir, full, 24, 80);
    assert(s != NULL);
    CHECK(s, "copy: ready", wait_for_text(s, "ready", 3000));
    pump(s, 150);

    keys(s, "/");
    CHECK(s, "menu lists every command", find_row(s, "/copy") >= 0 && find_row(s, "/mouse") >= 0 &&
          find_row(s, "/help") >= 0 && find_row(s, "/quit") >= 0);
    keys(s, "\x03" "/help\r");
    CHECK(s, "help names /copy, /mouse and the select key",
          find_row(s, "/copy /mouse /help") >= 0 && find_row(s, "hold Fn") >= 0);

    keys(s, "/clear\r");
    keys(s, "/copy\r");
    CHECK(s, "copy: nothing to copy yet", wait_for_text(s, "nothing to copy", 2000));
    CHECK(s, "copy: pbcopy not run without a reply", access(clip, F_OK) != 0);

    ask(s, "SEC_TEXT");
    keys(s, "/copy\r");
    CHECK(s, "copy: reports pbcopy", wait_for_text(s, "copied the last reply", 3000));
    slurp(clip, got, sizeof got);
    CHECK(s, "copy: reply text without escapes or controls", !strcmp(got, SEC_PLAIN));
    char *osc = mica_session_take_clipboard_write(s);
    CHECK(s, "copy: no OSC 52 when pbcopy worked", osc == NULL);
    free(osc);

    ask(s, "BIG_REPLY");
    keys(s, "/copy\r");
    CHECK(s, "copy: big reply reported", wait_for_text(s, "(99999 bytes, pbcopy)", 5000));
    CHECK(s, "copy: big reply arrives whole", slurp(clip, got, sizeof got) == 99999);

    f = fopen(failflag, "w");
    assert(f != NULL);
    fclose(f);
    ask(s, "SEC_TEXT");
    keys(s, "/copy\r");
    CHECK(s, "copy: pbcopy failure is said, OSC 52 not confirmed",
          wait_for_text(s, "pbcopy failed. Sent", 3000) && find_row(s, "Not confirmed") >= 0);
    pump(s, 200);
    osc = mica_session_take_clipboard_write(s);
    CHECK(s, "copy: fallback OSC 52 carries the plain text", osc && !strcmp(osc, SEC_PLAIN));
    free(osc);

    /* mouse reporting off, then on */
    keys(s, "/clear\r");
    CHECK(s, "mouse: on at start", mica_session_reports_mouse(s));
    keys(s, "\033[<0;5;5M\033[<0;5;5m");
    CHECK(s, "mouse: a plain click shows no hint", find_row(s, "to select:") < 0);
    keys(s, "\033[<0;5;5M\033[<0;20;5m");
    CHECK(s, "mouse: a drag shows the select key", find_row(s, "to select: hold Fn and drag, or /mouse") >= 0);
    keys(s, "/mouse\r");
    CHECK(s, "mouse off: reporting disabled", !mica_session_reports_mouse(s));
    CHECK(s, "mouse off: says how to scroll and expand",
          find_row(s, "drag to select text") >= 0 && find_row(s, "PgUp/PgDn") >= 0 && find_row(s, "^O") >= 0);
    submit(s, "STREAM_TEST");
    CHECK(s, "mouse off: modal", wait_for_text(s, "Do you want to proceed?", 4000));
    pump(s, 700);
    CHECK(s, "mouse off: dialog does not offer clicking",
          find_row(s, "Esc cancel") >= 0 && find_row(s, "or click") < 0);
    keys(s, "y");
    CHECK(s, "mouse off: task completes", wait_for_text(s, "✓ done", 4000));
    pump(s, 200);
    CHECK(s, "mouse off: collapsed hint names only ^O",
          find_row(s, "(^O to expand)") >= 0 && find_row(s, "click or") < 0);
    CHECK(s, "mouse off: stays off across a task", !mica_session_reports_mouse(s));
    keys(s, "/mouse\r");
    CHECK(s, "mouse on again", mica_session_reports_mouse(s) && find_row(s, "mouse on:") >= 0);
    keys(s, "/mouse\r");
    keys(s, "/exit\r");
    CHECK(s, "mouse off: clean exit", wait_for_exit(s, 3000));
    pump(s, 100);
    CHECK(s, "mouse off: terminal restored", !mica_session_reports_mouse(s) && !mica_session_bracketed_paste(s));
    mica_session_destroy(s);

    /* over SSH: OSC 52 only, with a size cap */
    unlink(clip);
    unlink(failflag);
    snprintf(full, sizeof full, "unset SSH_TTY SSH_CLIENT TMUX; export SSH_CONNECTION='1 2 3 4'; "
             "export PATH='%s':\"$PATH\"; %s", bin, cmd);
    s = mica_session_create(dir, full, 24, 80);
    assert(s != NULL);
    CHECK(s, "ssh copy: ready", wait_for_text(s, "ready", 3000));
    pump(s, 150);
    ask(s, "SEC_TEXT");
    keys(s, "/copy\r");
    CHECK(s, "ssh copy: says unconfirmed", wait_for_text(s, "Not confirmed", 3000));
    pump(s, 200);
    osc = mica_session_take_clipboard_write(s);
    CHECK(s, "ssh copy: OSC 52 carries the plain text", osc && !strcmp(osc, SEC_PLAIN));
    free(osc);
    CHECK(s, "ssh copy: pbcopy not used", access(clip, F_OK) != 0);
    ask(s, "BIG_REPLY");
    keys(s, "/copy\r");
    CHECK(s, "ssh copy: over the cap is refused",
          wait_for_text(s, "not copied:", 3000) && find_row(s, "OSC 52 limit") >= 0);
    pump(s, 200);
    osc = mica_session_take_clipboard_write(s);
    CHECK(s, "ssh copy: nothing sent over the cap", osc == NULL);
    free(osc);
    keys(s, "/exit\r");
    CHECK(s, "mouse on: clean exit", wait_for_exit(s, 3000));
    pump(s, 100);
    CHECK(s, "mouse on: terminal restored", !mica_session_reports_mouse(s));
    mica_session_destroy(s);

    /* a project-supplied pbcopy never runs: relative, empty, absolute or symlinked
       PATH entries. PATH holds no system pbcopy, so the clipboard stays untouched */
    char evil[1200], inproj[1200], evil2[1300], linkdir[1200], linkfile[1300], hijack[1200];
    snprintf(evil, sizeof evil, "%s/pbcopy", dir);
    snprintf(inproj, sizeof inproj, "%s/inproj", dir);
    snprintf(evil2, sizeof evil2, "%s/pbcopy", inproj);
    snprintf(linkdir, sizeof linkdir, "%s/linkbin", outside);
    snprintf(linkfile, sizeof linkfile, "%s/pbcopy", linkdir);
    snprintf(hijack, sizeof hijack, "%s/HIJACKED", dir);
    assert(mkdir(inproj, 0700) == 0 && mkdir(linkdir, 0700) == 0);
    const char *const evils[] = {evil, evil2};
    for (int i = 0; i < 2; i++) {
        f = fopen(evils[i], "w");
        assert(f != NULL);
        fprintf(f, "#!/bin/sh\nexec /bin/cat > '%s'\n", hijack);
        fclose(f);
        assert(chmod(evils[i], 0700) == 0);
    }
    assert(symlink(evil, linkfile) == 0);

    unlink(clip);
    snprintf(full, sizeof full, "unset SSH_CONNECTION SSH_TTY SSH_CLIENT TMUX; "
             "export PATH='.::inproj:%s:%s:/bin'; %s", inproj, linkdir, cmd);
    s = mica_session_create(dir, full, 24, 80);
    assert(s != NULL);
    CHECK(s, "hijack: ready", wait_for_text(s, "ready", 3000));
    pump(s, 150);
    ask(s, "SEC_ZWTEXT");
    keys(s, "/copy\r");
    CHECK(s, "hijack: falls back to OSC 52", wait_for_text(s, "pbcopy failed. Sent", 3000));
    pump(s, 200);
    CHECK(s, "hijack: project pbcopy not run", access(hijack, F_OK) != 0);
    osc = mica_session_take_clipboard_write(s);
    CHECK(s, "copy: bidi and zero-width characters removed", osc && !strcmp(osc, "zw"));
    free(osc);
    mica_session_destroy(s);

    /* with a safe entry after the unsafe ones, that one is used */
    snprintf(full, sizeof full, "unset SSH_CONNECTION SSH_TTY SSH_CLIENT TMUX; "
             "export PATH='.::inproj:%s:%s:%s:/bin'; %s", inproj, linkdir, bin, cmd);
    s = mica_session_create(dir, full, 14, 80);
    assert(s != NULL);
    CHECK(s, "segments: ready", wait_for_text(s, "ready", 3000));
    pump(s, 150);
    ask(s, "SEG_REPLY");
    keys(s, "/copy\r");
    CHECK(s, "segments: says it has several lines", wait_for_text(s, "several lines (3)", 3000));
    CHECK(s, "segments: safe pbcopy used", access(hijack, F_OK) != 0);
    slurp(clip, got, sizeof got);
    CHECK(s, "segments: whole reply, hidden text removed", !strcmp(got, SEG_PLAIN));

    /* 14 rows: the menu scrolls to the last command */
    keys(s, "/clear\r");
    keys(s, "/");
    CHECK(s, "short menu: last command off screen", find_row(s, "/quit") < 0);
    for (int i = 0; i < 10; i++) keys(s, "\033[B");
    int quit = find_row(s, "/quit");
    CHECK(s, "short menu: arrows reach /quit", quit >= 0 && find_row(s, "\xe2\x96\xb8 /quit") == quit);
    CHECK(s, "short menu: first command scrolled away", find_row(s, "write .flywheel.md") < 0);
    keys(s, "\033[B");
    CHECK(s, "short menu: wraps to the top", find_row(s, "\xe2\x96\xb8 /init") >= 0);
    keys(s, "\033[A");
    keys(s, "\x03" "/mouse\r");
    keys(s, "/clear\r");
    keys(s, "/help\r");
    CHECK(s, "help: no wheel while the mouse is off",
          find_row(s, "PgUp/PgDn scroll") >= 0 && find_row(s, "or wheel") < 0);
    keys(s, "/mouse\r");
    keys(s, "/clear\r");
    keys(s, "/");
    for (int i = 0; i < 9; i++) keys(s, "\033[B");
    int row = find_row(s, "/exit");
    CHECK(s, "short menu: /exit visible", row >= 0);
    char click[32];
    snprintf(click, sizeof click, "\033[<0;5;%dM", row + 1);
    keys(s, click);
    CHECK(s, "short menu: click uses the scroll offset", wait_for_exit(s, 3000));
    mica_session_destroy(s);

    /* Persian with ZWNJ round-trips; ZWSP is still removed */
    unlink(clip);
    snprintf(full, sizeof full, "unset SSH_CONNECTION SSH_TTY SSH_CLIENT TMUX; "
             "export PATH='%s':\"$PATH\"; %s", bin, cmd);
    s = mica_session_create(dir, full, 24, 80);
    assert(s != NULL);
    CHECK(s, "persian: ready", wait_for_text(s, "ready", 3000));
    pump(s, 150);
    ask(s, "PERSIAN_REPLY");
    keys(s, "/copy\r");
    CHECK(s, "persian: reports pbcopy", wait_for_text(s, "copied the last reply", 3000));
    slurp(clip, got, sizeof got);
    CHECK(s, "persian: ZWNJ kept, ZWSP removed",
          !strcmp(got, "\xd8\xb3\xd9\x84\xd8\xa7\xd9\x85 \xd9\x85\xdb\x8c\xe2\x80\x8c"
                       "\xd8\xae\xd9\x88\xd8\xa7\xd9\x87\xd9\x85"));
    mica_session_destroy(s);

    /* a pbcopy reached through a firmlink alias of the project bin is not run,
       and a repo/bin pbcopy is not run from a repo subdirectory */
    char altbin[1200], alt_script[1300], alt_hit[1200], alt_path[1300];
    char repo[1200], repo_sub[1300], repo_bin[1300], repo_script[1400], repo_hit[1300];
    char real_dir[PATH_MAX], alias[PATH_MAX];
    snprintf(altbin, sizeof altbin, "%s/altbin", dir);
    snprintf(alt_script, sizeof alt_script, "%s/pbcopy", altbin);
    snprintf(alt_hit, sizeof alt_hit, "%s/ALT_HIJACK", dir);
    snprintf(repo, sizeof repo, "%s/repo", dir);
    snprintf(repo_sub, sizeof repo_sub, "%s/sub", repo);
    snprintf(repo_bin, sizeof repo_bin, "%s/bin", repo);
    snprintf(repo_script, sizeof repo_script, "%s/pbcopy", repo_bin);
    snprintf(repo_hit, sizeof repo_hit, "%s/REPO_HIJACK", dir);
    assert(realpath(dir, real_dir) != NULL);
    snprintf(alias, sizeof alias, "/System/Volumes/Data%s", real_dir);
    snprintf(alt_path, sizeof alt_path, "%s/altbin", alias);
    struct stat ast, dst;
    assert(stat(alias, &ast) == 0 && stat(dir, &dst) == 0);
    assert(ast.st_ino == dst.st_ino && ast.st_dev == dst.st_dev);
    assert(mkdir(altbin, 0700) == 0 && mkdir(repo, 0700) == 0 && mkdir(repo_bin, 0700) == 0);
    assert(mkdir(repo_sub, 0700) == 0);
    char gitdir[1300];
    snprintf(gitdir, sizeof gitdir, "%s/.git", repo);
    assert(mkdir(gitdir, 0700) == 0);
    const char *const scripts[] = {alt_script, repo_script};
    const char *const hits[] = {alt_hit, repo_hit};
    for (int i = 0; i < 2; i++) {
        f = fopen(scripts[i], "w");
        assert(f != NULL);
        fprintf(f, "#!/bin/sh\nexec /bin/cat > '%s'\n", hits[i]);
        fclose(f);
        assert(chmod(scripts[i], 0700) == 0);
    }

    unlink(clip);
    snprintf(full, sizeof full, "unset SSH_CONNECTION SSH_TTY SSH_CLIENT TMUX; "
             "export PATH='%s':/bin; %s", alt_path, cmd);
    s = mica_session_create(dir, full, 24, 80);
    assert(s != NULL);
    CHECK(s, "alias: ready", wait_for_text(s, "ready", 3000));
    pump(s, 150);
    ask(s, "SEC_ZWTEXT");
    keys(s, "/copy\r");
    CHECK(s, "alias: firmlink pbcopy not used", wait_for_text(s, "pbcopy failed. Sent", 3000));
    pump(s, 200);
    CHECK(s, "alias: pbcopy in project bin not run", access(alt_hit, F_OK) != 0);
    mica_session_destroy(s);

    snprintf(full, sizeof full, "unset SSH_CONNECTION SSH_TTY SSH_CLIENT TMUX; "
             "export PATH='%s':%s:/bin; %s", repo_bin, bin, cmd);
    s = mica_session_create(repo_sub, full, 24, 80);
    assert(s != NULL);
    CHECK(s, "repo: ready", wait_for_text(s, "ready", 3000));
    pump(s, 150);
    ask(s, "SEC_TEXT");
    keys(s, "/copy\r");
    CHECK(s, "repo: copy from subdirectory uses the safe pbcopy",
          wait_for_text(s, "copied the last reply", 3000));
    CHECK(s, "repo: repo/bin pbcopy not run", access(repo_hit, F_OK) != 0);
    mica_session_destroy(s);

    unlink(alt_script);
    unlink(repo_script);
    unlink(alt_hit);
    unlink(repo_hit);
    rmdir(altbin);
    rmdir(gitdir);
    rmdir(repo_sub);
    rmdir(repo_bin);
    rmdir(repo);

    unlink(evil);
    unlink(evil2);
    unlink(linkfile);
    unlink(script);
    unlink(clip);
    rmdir(inproj);
    rmdir(linkdir);
    rmdir(bin);
    rmdir(outside);
}

/* ---------- images ---------- */

static const unsigned char TINY_PNG[] = {   /* signature + 1x1 IHDR */
    0x89,'P','N','G','\r','\n',0x1a,'\n', 0,0,0,13,'I','H','D','R', 0,0,0,1, 0,0,0,1, 8,0,0,0,0};

static void put_file(const char *path, const void *d, size_t n, int mode) {
    FILE *f = fopen(path, "wb");
    assert(f != NULL);
    size_t w = fwrite(d, 1, n, f);
    fclose(f);
    assert(w == n && chmod(path, (mode_t)mode) == 0);
}

/* press Enter on msg and wait for the screen to say want */
static bool sends(MicaSession *s, const char *msg, const char *want) {
    type_str(s, msg);
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    bool ok = wait_for_text(s, want, 8000);
    pump(s, 300);
    return ok;
}

/* every session here finds a fake osascript first on PATH: the real clipboard
   is never read */
static void image_tests(const char *cmd) {
    char proj[] = "/tmp/fwimg-XXXXXX", outside[] = "/tmp/fwimgbin-XXXXXX";
    assert(mkdtemp(proj) != NULL && mkdtemp(outside) != NULL);
    char shot[1100], spaced[1100], bad[1100], md[1100], script[1100], slow[1100], hang[1100];
    snprintf(shot, sizeof shot, "%s/shot.png", proj);
    snprintf(spaced, sizeof spaced, "%s/my shot.png", proj);
    snprintf(bad, sizeof bad, "%s/bad.png", proj);
    snprintf(md, sizeof md, "%s/.flywheel.md", proj);
    put_file(shot, TINY_PNG, sizeof TINY_PNG, 0600);
    put_file(spaced, TINY_PNG, sizeof TINY_PNG, 0600);
    put_file(bad, "nope", 4, 0600);
    put_file(md, "# see ./shot.png\n", 17, 0600);
    snprintf(script, sizeof script, "%s/osascript", outside);
    snprintf(slow, sizeof slow, "%s/slow", outside);
    snprintf(hang, sizeof hang, "%s/hang", outside);
    char sh[4096];
    int n = snprintf(sh, sizeof sh, "#!/bin/sh\nfor a; do out=$a; done\n"
                     "[ -e '%s' ] && exec /bin/sleep 30\n[ -e '%s' ] && /bin/sleep 2\n"
                     "exec /bin/cp '%s' \"$out\"\n", hang, slow, shot);
    put_file(script, sh, (size_t)n, 0700);

    char full[8192], msg[2048];
    snprintf(full, sizeof full, "unset SSH_CONNECTION SSH_TTY SSH_CLIENT TMUX; "
             "export PATH='%s':\"$PATH\"; %s", outside, cmd);
    MicaSession *s = mica_session_create(proj, full, 30, 100);
    assert(s != NULL);
    CHECK(s, "image: ready", wait_for_text(s, "ready", 3000));
    pump(s, 150);

    /* a dragged file arrives as a paste of its shell-escaped path */
    snprintf(msg, sizeof msg, PS "%s/my\\ shot.png " PE, proj);
    CHECK(s, "image: dragged path alone is held", sends(s, msg, "1 image attached"));
    CHECK(s, "image: held image goes with the next message",
          sends(s, "IMGQ what is it", "GOT last=1 all=1 png=1"));
    CHECK(s, "image: transcript names it", find_row(s, "image: my shot.png") >= 0);

    keys(s, "/clear\r");
    snprintf(msg, sizeof msg, "describe '%s' please", spaced);
    CHECK(s, "image: quoted path in a message", sends(s, msg, "GOT last=1 all=1 png=1"));
    keys(s, "/clear\r");
    CHECK(s, "image: relative path in a message", sends(s, "describe ./shot.png", "GOT last=1 all=1"));

    /* only typed or pasted text is searched */
    keys(s, "/clear\r");
    CHECK(s, "image: model text reply", sends(s, "SHOWPATH", "see ./shot.png"));
    type_str(s, "TOOLPATH");
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    pump(s, 1500);
    if (find_row(s, "Do you want to proceed?") >= 0) keys(s, "y");
    pump(s, 800);
    CHECK(s, "image: model, tool and project text attach nothing",
          sends(s, "IMGQ", "GOT last=0 all=0"));

    keys(s, "/clear\r");
    type_str(s, "IMGQ " PS "log line\nopen ./shot.png\n" PE);
    CHECK(s, "image: a pasted block is not searched", sends(s, "", "GOT last=0 all=0"));
    keys(s, "/clear\r");
    CHECK(s, "image: backticks only mention", sends(s, "IMGQ `./shot.png`", "GOT last=0 all=0"));

    /* a failure sends nothing and keeps the text */
    keys(s, "/clear\r");
    CHECK(s, "image: bad file is said",
          sends(s, "IMGQ ./bad.png", "not a PNG, JPEG, GIF or WebP image"));
    CHECK(s, "image: nothing sent", find_row(s, "not sent:") >= 0 && find_row(s, "GOT ") < 0);
    CHECK(s, "image: text back in the input box",
          find_last_row(s, "IMGQ ./bad.png") > find_row(s, "not sent:"));
    keys(s, "\x03");
    keys(s, "/clear\r");
    CHECK(s, "image: private URL refused",
          sends(s, "IMGQ http://127.0.0.1/a.png", "local or private address"));
    CHECK(s, "image: private URL not sent", find_row(s, "GOT ") < 0);
    keys(s, "\x03");

    /* held images are dropped by /clear and ^C */
    keys(s, "/clear\r");
    CHECK(s, "image: held", sends(s, "./shot.png", "1 image attached"));
    keys(s, "/clear\r");
    CHECK(s, "image: /clear drops it", sends(s, "IMGQ", "GOT last=0 all=0"));
    keys(s, "/clear\r");
    CHECK(s, "image: held again", sends(s, "./shot.png", "1 image attached"));
    keys(s, "\x03");
    CHECK(s, "image: ^C says it dropped", find_row(s, "attached images dropped") >= 0);
    CHECK(s, "image: ^C drops it", sends(s, "IMGQ", "GOT last=0 all=0"));

    /* the clipboard */
    keys(s, "/clear\r");
    CHECK(s, "paste: attaches", sends(s, "/paste", "1 image attached"));
    CHECK(s, "paste: sent", sends(s, "IMGQ", "GOT last=1 all=1 png=1"));
    CHECK(s, "paste: named clipboard", find_row(s, "image: clipboard") >= 0);

    /* input during a load queues: nothing re-enters it */
    keys(s, "/clear\r");
    put_file(slow, "", 0, 0600);
    keys(s, "/paste\r");
    CHECK(s, "paste: shows loading", find_row(s, "loading image") >= 0);
    keys(s, "IMGQ queued\r");
    CHECK(s, "paste: message waits for the load", find_row(s, "GOT ") < 0);
    CHECK(s, "paste: queued message gets the image",
          wait_for_text(s, "GOT last=1 all=1", 8000));
    pump(s, 300);
    unlink(slow);

    keys(s, "/clear\r");
    put_file(hang, "", 0, 0600);
    keys(s, "/paste\r");
    keys(s, "\x1b");
    CHECK(s, "paste: Esc cancels", wait_for_text(s, "cancelled", 4000));
    unlink(hang);
    pump(s, 200);
    CHECK(s, "paste: nothing held after cancel", sends(s, "IMGQ", "GOT last=0 all=0"));

    /* a queued message that fails comes back and holds what was queued behind it */
    keys(s, "/clear\r");
    put_file(slow, "", 0, 0600);
    keys(s, "/paste\r");
    keys(s, "IMGQ ./bad.png\r");
    keys(s, "IMGQ follow\r");
    type_str(s, "draft");
    CHECK(s, "queue: failure is said", wait_for_text(s, "not sent:", 8000));
    pump(s, 600);
    CHECK(s, "queue: failed message kept above the draft",
          find_last_row(s, "IMGQ ./bad.png") > find_row(s, "not sent:") &&
          find_last_row(s, "draft") > find_last_row(s, "IMGQ ./bad.png"));
    CHECK(s, "queue: later message held", find_row(s, "GOT ") < 0);
    CHECK(s, "queue: hold is said", find_row(s, "1 queued message held") >= 0);
    unlink(slow);
    keys(s, "\x03");
    CHECK(s, "queue: ^C drops what was held", find_row(s, "queued messages dropped") >= 0);

    /* the same when the failure is drained from inside another message's turn */
    keys(s, "/clear\r");
    put_file(slow, "", 0, 0600);
    keys(s, "/paste\r");
    keys(s, "IMGQ first\r");
    keys(s, "IMGQ ./bad.png\r");
    keys(s, "IMGQ follow\r");
    CHECK(s, "queue: nested failure holds the rest",
          wait_for_text(s, "1 queued message held", 8000));
    pump(s, 600);
    CHECK(s, "queue: only the first was sent", find_row(s, "follow") < 0);
    unlink(slow);
    keys(s, "\x15/help\r");
    pump(s, 600);
    CHECK(s, "queue: /help leaves it held", find_row(s, "follow") < 0);
    CHECK(s, "queue: image alone is held", sends(s, "./shot.png", "1 image attached"));
    pump(s, 600);
    CHECK(s, "queue: image alone leaves it held", find_row(s, "follow") < 0);
    keys(s, "IMGQ fixed\r");
    CHECK(s, "queue: held goes after the next one",
          wait_for_text(s, "follow", 8000));
    pump(s, 600);

    /* /clear drops what was held: it must not run in the new conversation */
    keys(s, "/clear\r");
    put_file(slow, "", 0, 0600);
    keys(s, "/paste\r");
    keys(s, "IMGQ ./bad.png\r");
    keys(s, "IMGQ follow\r");
    CHECK(s, "queue: held before /clear", wait_for_text(s, "1 queued message held", 8000));
    unlink(slow);
    keys(s, "\x15/clear\r");
    pump(s, 600);
    CHECK(s, "queue: /clear says it dropped", find_row(s, "queued messages dropped") >= 0);
    CHECK(s, "queue: /clear did not send it", find_row(s, "follow") < 0);
    CHECK(s, "queue: sends after /clear", sends(s, "IMGQ", "GOT last=0 all=0"));
    pump(s, 600);
    CHECK(s, "queue: nothing left after /clear", find_row(s, "follow") < 0);

    /* a /clear queued ahead of a message still runs, then the message */
    put_file(slow, "", 0, 0600);
    keys(s, "/paste\r");
    keys(s, "/clear\r");
    keys(s, "IMGQ queued after clear\r");
    CHECK(s, "queue: message behind a queued /clear runs",
          wait_for_text(s, "GOT last=0 all=0", 8000));
    unlink(slow);
    pump(s, 600);

    /* Esc while the model is being asked about vision, images already held */
    keys(s, "/clear\r");
    CHECK(s, "cancel: held", sends(s, "./shot.png", "1 image attached"));
    g_models_delay_ms = 1500;
    keys(s, "IMGQ stop\r");
    keys(s, "\x1b");
    CHECK(s, "cancel: Esc during the model check", wait_for_text(s, "cancelled", 6000));
    g_models_delay_ms = 0;
    pump(s, 600);
    CHECK(s, "cancel: nothing sent", find_row(s, "GOT ") < 0);
    keys(s, "\x15");                    /* ^U: clear the box, keep the image */
    CHECK(s, "cancel: image still held", sends(s, "IMGQ", "GOT last=1 all=1"));

    /* images already in the conversation need a model that sees */
    keys(s, "/model mock/qwen-alt\r");
    CHECK(s, "history: refused without vision", sends(s, "IMGQ later", "serving without vision"));
    CHECK(s, "history: says how to go on", find_row(s, "/clear") >= 0);
    keys(s, "\x03");
    keys(s, "/model mock/qwen\r");
    CHECK(s, "history: goes with a seeing model", sends(s, "IMGQ back", "GOT last=0 all=1"));
    keys(s, "/model mock/qwen-alt\r");
    keys(s, "/clear\r");
    CHECK(s, "history: /clear frees the other model", sends(s, "IMGQ", "GOT last=0 all=0"));
    keys(s, "/model mock/qwen\r");
    keys(s, "/exit\r");
    CHECK(s, "image: clean exit", wait_for_exit(s, 3000));
    mica_session_destroy(s);

    /* a model without vision: cmd ends in the model name */
    strncat(full, "-alt", sizeof full - strlen(full) - 1);
    s = mica_session_create(proj, full, 30, 100);
    assert(s != NULL);
    CHECK(s, "no vision: ready", wait_for_text(s, "ready", 3000));
    pump(s, 150);
    CHECK(s, "no vision: path refused", sends(s, "IMGQ ./shot.png", "serving without vision"));
    CHECK(s, "no vision: nothing sent", find_row(s, "GOT ") < 0);
    keys(s, "\x03");
    keys(s, "/clear\r");
    CHECK(s, "no vision: /paste refused", sends(s, "/paste", "serving without vision"));
    CHECK(s, "no vision: plain text still works", sends(s, "IMGQ", "GOT last=0 all=0"));
    mica_session_destroy(s);

    char rm[1200];
    snprintf(rm, sizeof rm, "rm -rf '%s' '%s'", proj, outside);
    system(rm);
}

/* ---------- death by signal: the terminal must come back (own session each) ---------- */

static long read_num(const char *dir, const char *name) {
    char p[1400];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    FILE *f = fopen(p, "r");
    long v = -1;
    if (f) { if (fscanf(f, "%ld", &v) != 1) v = -1; fclose(f); }
    return v;
}

static void read_line(const char *dir, const char *name, char *out, size_t cap) {
    char p[1400];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    FILE *f = fopen(p, "r");
    out[0] = 0;
    if (f) { if (!fgets(out, (int)cap, f)) out[0] = 0; fclose(f); }
}

/* PENDIN is a state bit the kernel raises on its own when canonical mode comes
   back, not a setting; BSD `stty -g` carries it in lflag= */
static void drop_pendin(char *st, size_t cap) {
    char *p = strstr(st, "lflag="), *end = NULL;
    if (!p) return;
    unsigned long v = strtoul(p + 6, &end, 16);
    char tail[512];
    snprintf(tail, sizeof tail, "%s", end);
    snprintf(p, cap - (size_t)(p - st), "lflag=%lx%s", v & ~(unsigned long)PENDIN, tail);
}

static void write_file(const char *dir, const char *name, const char *body) {
    char p[1400];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    FILE *f = fopen(p, "w");
    assert(f != NULL);
    fputs(body, f);
    fclose(f);
}

static bool gone(pid_t p) {
    for (int i = 0; i < 100; i++) {
        if (kill(p, 0) < 0 && errno == ESRCH) return true;
        usleep(20000);
    }
    return false;
}

static double mono_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

enum sig_state { AT_IDLE, AT_DIALOG, AT_TOOL, AT_REQUEST };

static void signal_case(const char *dir, int sig, const char *signame, enum sig_state st) {
    static const char *const where[] = {"idle", "dialog", "tool", "request"};
    static const char *const stale[] = {"sig.pid", "sig.rc", "sig.before", "sig.after", "sig.child", "sig.inject"};
    for (size_t i = 0; i < sizeof stale / sizeof *stale; i++) {
        char p[1400];
        snprintf(p, sizeof p, "%s/%s", dir, stale[i]);
        unlink(p);
    }
    char label[128];
#define SCHECK(what, cond) do { \
        snprintf(label, sizeof label, "%s at %s: %s", signame, where[st], what); \
        CHECK(s, label, cond); \
    } while (0)

    /* no `exec` and no job control: the wrapper sees the status and the tty flywheel left */
    MicaSession *s = mica_session_create(dir, "exec /bin/sh ./sig.sh", 24, 80);
    assert(s != NULL);
    SCHECK("ready", wait_for_text(s, "ready", 3000));
    pump(s, 150);
    long fw = read_num(dir, "sig.pid"), child = -1;
    SCHECK("modes on before the signal", mica_session_reports_mouse(s) && mica_session_bracketed_paste(s));

    if (st == AT_DIALOG) SCHECK("dialog open", open_modal(s, "SEC_EARLY"));
    if (st == AT_REQUEST) {
        submit(s, "SLOW_TEST");
        SCHECK("reply streaming", wait_for_text(s, "tick-1", 3000));
    }
    if (st == AT_TOOL) {
        SCHECK("approval", open_modal(s, "SIG_TOOL"));
        pump(s, 700);
        type_str(s, "y");
        for (int i = 0; i < 150 && child < 0; i++) { pump(s, 20); child = read_num(dir, "sig.child"); }
        SCHECK("command running in its own group", child > 1 && getpgid((pid_t)child) == (pid_t)child);
    }

    assert(fw > 1);
    /* Frozen, so no frame of its own can undo what the terminal is told next: the
       states a command writing to /dev/tty can leave behind. */
    kill((pid_t)fw, SIGSTOP);
    double t0 = mono_s();
    write_file(dir, "sig.inject", "");
#define MODES_SET (!mica_session_cursor_visible(s) && mica_session_alt_screen(s) && \
                   mica_session_sync_output_active(s))
    for (int i = 0; i < 50 && !MODES_SET; i++) pump(s, 10);
    SCHECK("cursor hidden, alternate screen, sync open", MODES_SET);
#undef MODES_SET
    kill((pid_t)fw, sig);
    kill((pid_t)fw, SIGCONT);
    for (int i = 0; i < 200 && mica_session_sync_output_active(s); i++) pump(s, 10);
    /* mica gives up on an open frame after 1 s, so only an earlier end counts */
    SCHECK("sync output off", !mica_session_sync_output_active(s) && mono_s() - t0 < 0.9);
    SCHECK("process ended", wait_for_text(s, "SIG_DONE", 4000));
    pump(s, 100);
    SCHECK("died by that signal", read_num(dir, "sig.rc") == 128 + sig);
    char before[512], after[512];
    read_line(dir, "sig.before", before, sizeof before);
    read_line(dir, "sig.after", after, sizeof after);
    drop_pendin(before, sizeof before);
    drop_pendin(after, sizeof after);
    SCHECK("termios restored", before[0] && !strcmp(before, after));
    SCHECK("mouse reporting off", !mica_session_reports_mouse(s));
    SCHECK("bracketed paste off", !mica_session_bracketed_paste(s));
    SCHECK("cursor visible, main screen", mica_session_cursor_visible(s) && !mica_session_alt_screen(s));
    int hi = find_row(s, "FILL39"), lo = find_row(s, "FILL18");
    SCHECK("scroll region reset", lo >= 0 && hi - lo == 21);
    if (child > 1) {
        if (sig == SIGTERM || sig == SIGHUP) SCHECK("running command killed", gone((pid_t)child));
        kill(-(pid_t)child, SIGKILL);   /* never leave the sleep behind */
    }
    mica_session_destroy(s);
#undef SCHECK
}

/* A pty of our own, for what mica does not show: the raw bytes, a reader that
   stops, job control. A stand-in shell leads the session and runs flywheel. */
typedef struct {
    int master, slave, to, from;
    char name[128];
    pid_t leader, fw;
    char out[1 << 16];
    size_t len;
} RawTty;

static void raw_drain(RawTty *r, int ms) {
    struct pollfd p = {r->master, POLLIN, 0};
    for (double end = mono_s() + ms / 1000.0; mono_s() < end;) {
        if (poll(&p, 1, 10) <= 0) continue;
        if (r->len > sizeof r->out - 4097) {
            r->len /= 2;
            memmove(r->out, r->out + r->len, r->len);
        }
        ssize_t n = read(r->master, r->out + r->len, 4096);
        if (n <= 0) break;
        r->len += (size_t)n;
        r->out[r->len] = 0;
    }
}

static int raw_count(const RawTty *r, const char *needle) {
    int n = 0;
    size_t k = strlen(needle);
    for (size_t i = 0; i + k <= r->len; i++)
        if (!memcmp(r->out + i, needle, k)) n++;
    return n;
}

static bool raw_start(RawTty *r, const char *dir) {
    memset(r, 0, sizeof *r);
    char pidfile[1400];
    snprintf(pidfile, sizeof pidfile, "%s/sig.pid", dir);
    unlink(pidfile);
    struct winsize ws = {.ws_row = 24, .ws_col = 80};
    int to[2], from[2];
    assert(openpty(&r->master, &r->slave, r->name, NULL, &ws) == 0);
    assert(pipe(to) == 0 && pipe(from) == 0);
    r->leader = fork();
    assert(r->leader >= 0);
    if (r->leader == 0) {
        close(r->master); close(to[1]); close(from[0]);
        if (login_tty(r->slave) != 0 || chdir(dir) != 0) _exit(126);
        signal(SIGTTOU, SIG_IGN);
        pid_t job = fork();
        if (job == 0) {
            setpgid(0, 0);
            tcsetpgrp(0, getpid());
            signal(SIGTTOU, SIG_DFL);
            execl("/bin/sh", "sh", "./sig.run", (char *)NULL);
            _exit(127);
        }
        setpgid(job, job);
        tcsetpgrp(0, job);
        char c;
        while (read(to[0], &c, 1) == 1 && c == 'b') {   /* take the terminal back */
            tcsetpgrp(0, getpgrp());
            if (write(from[1], "k", 1) != 1) break;
        }
        int st = -1;
        waitpid(job, &st, 0);
        if (write(from[1], &st, sizeof st) == (ssize_t)sizeof st) pause();
        _exit(0);
    }
    close(to[0]); close(from[1]);
    r->to = to[1];
    r->from = from[0];
    for (int i = 0; i < 300 && !strstr(r->out, "ready"); i++) raw_drain(r, 10);
    bool ready = strstr(r->out, "ready") != NULL;
    raw_drain(r, 150);
    r->fw = (pid_t)read_num(dir, "sig.pid");
    return ready && r->fw > 1;
}

/* The job's wait status, or -1 if it has not ended in time. */
static int raw_wait(RawTty *r, bool drain) {
    if (write(r->to, "w", 1) != 1) return -1;
    struct pollfd p = {r->from, POLLIN, 0};
    for (double end = mono_s() + 4; mono_s() < end;) {
        if (drain) raw_drain(r, 10);
        if (poll(&p, 1, 10) > 0) {
            int st = -1;
            if (read(r->from, &st, sizeof st) != (ssize_t)sizeof st) return -1;
            if (drain) raw_drain(r, 100);
            return st;
        }
    }
    return -1;
}

static void raw_end(RawTty *r, int st) {
    if (st == -1 && r->fw > 1) kill(r->fw, SIGKILL);
    close(r->master);
    close(r->slave);
    kill(r->leader, SIGKILL);
    waitpid(r->leader, NULL, 0);
    close(r->to);
    close(r->from);
}

static bool died_by(int st, int sig) { return st != -1 && WIFSIGNALED(st) && WTERMSIG(st) == sig; }

static bool cooked(int fd) {
    struct termios t;
    return tcgetattr(fd, &t) == 0 && (t.c_lflag & ICANON) && (t.c_lflag & ECHO);
}

#define RESTORE_START "\030\033[?2026l"

static void raw_check(bool ok, const char *signame, const char *what) {
    char label[128];
    snprintf(label, sizeof label, "%s raw: %s", signame, what);
    CHECK((MicaSession *)NULL, label, ok);
}

static void once_case(const char *dir, int sig, const char *signame) {
    static RawTty r;
    raw_check(raw_start(&r, dir), signame, "ready");
    r.len = 0;
    kill(r.fw, sig);
    int st = raw_wait(&r, true);
    raw_check(died_by(st, sig), signame, "really died of the signal");
    raw_check(raw_count(&r, RESTORE_START) == 1, signame, "restore sequence written exactly once");
    /* the signal may land inside a status bar draw, which has autowrap off */
    const char *at = strstr(r.out, RESTORE_START);
    raw_check(at && strstr(at, "\033[?7h"), signame, "restore turns autowrap back on");
    raw_end(&r, st);
}

/* The status bar is drawn with autowrap off, and on again after it. */
static void wrap_case(const char *dir) {
    static RawTty r;
    raw_check(raw_start(&r, dir), "status bar", "ready");
    const char *off = strstr(r.out, "\033[?7l"), *on = off ? strstr(off, "\033[?7h") : NULL;
    raw_check(off != NULL, "status bar", "drawn with autowrap off");
    raw_check(on != NULL, "status bar", "autowrap back on after the draw");
    kill(r.fw, SIGTERM);
    raw_end(&r, raw_wait(&r, true));
}

/* Nobody reads the pty and its queue is full: one SIGTERM must still end it. */
static void stuck_case(const char *dir) {
    static RawTty r;
    raw_check(raw_start(&r, dir), "SIGTERM", "unread: ready");
    int fill = open(r.name, O_WRONLY | O_NONBLOCK | O_NOCTTY);
    assert(fill >= 0);
    char junk[1024];
    memset(junk, 'x', sizeof junk);
    while (write(fill, junk, sizeof junk) > 0) {}
    while (write(fill, junk, 1) > 0) {}
    close(fill);
    kill(r.fw, SIGTERM);
    int st = raw_wait(&r, false);
    raw_check(died_by(st, SIGTERM), "SIGTERM", "unread: process ended");
    raw_check(cooked(r.slave), "SIGTERM", "unread: termios restored");
    int fl = fcntl(r.slave, F_GETFL);   /* the same open file as its stdout */
    raw_check(fl >= 0 && !(fl & O_NONBLOCK), "SIGTERM", "unread: stdout left blocking");
    raw_end(&r, st);
}

/* In the background the terminal belongs to someone else: leave it alone. */
static void background_case(const char *dir) {
    static RawTty r;
    raw_check(raw_start(&r, dir), "SIGTERM", "background: ready");
    char c = 0;
    raw_check(write(r.to, "b", 1) == 1 && read(r.from, &c, 1) == 1, "SIGTERM", "background: moved");
    raw_drain(&r, 100);
    r.len = 0;
    kill(r.fw, SIGTERM);
    kill(r.fw, SIGCONT);   /* a read from the background may have stopped it */
    int st = raw_wait(&r, true);
    raw_check(died_by(st, SIGTERM), "SIGTERM", "background: process ended");
    raw_check(raw_count(&r, RESTORE_START) == 0, "SIGTERM", "background: no escapes written");
    raw_check(!cooked(r.slave), "SIGTERM", "background: termios untouched");
    raw_end(&r, st);
}

static void signal_tests(const char *dir, const char *cmd) {
    char run[2200];
    snprintf(run, sizeof run, "echo $$ > sig.pid\n%s\n", cmd);
    write_file(dir, "sig.run", run);
    write_file(dir, "sig.sh",
               "stty -g > sig.before\n"
               "( while [ ! -f sig.inject ]; do sleep 0.02; done\n"
               "  printf '\\030\\033[?1049h\\033[?25l\\033[?2026h' > /dev/tty ) &\n"
               "inj=$!\n"
               "/bin/sh ./sig.run\n"
               "echo $? > sig.rc\n"
               "kill $inj 2>/dev/null\n"
               "stty -g > sig.after\n"
               "i=0; while [ $i -lt 40 ]; do echo FILL$i; i=$((i+1)); done\n"
               "echo SIG_DONE\n"
               "exec sleep 30\n");

#define SIG(x) x, #x
    signal_case(dir, SIG(SIGTERM), AT_IDLE);
    signal_case(dir, SIG(SIGHUP), AT_IDLE);
    signal_case(dir, SIG(SIGQUIT), AT_IDLE);
    signal_case(dir, SIG(SIGSEGV), AT_IDLE);
    signal_case(dir, SIG(SIGBUS), AT_IDLE);
    signal_case(dir, SIG(SIGABRT), AT_IDLE);
    signal_case(dir, SIG(SIGFPE), AT_IDLE);
    signal_case(dir, SIG(SIGILL), AT_IDLE);
    signal_case(dir, SIG(SIGTERM), AT_DIALOG);
    signal_case(dir, SIG(SIGSEGV), AT_DIALOG);
    signal_case(dir, SIG(SIGTERM), AT_REQUEST);
    signal_case(dir, SIG(SIGHUP), AT_REQUEST);
    signal_case(dir, SIG(SIGTERM), AT_TOOL);
    signal_case(dir, SIG(SIGHUP), AT_TOOL);
    once_case(dir, SIG(SIGTERM));
    once_case(dir, SIG(SIGHUP));
    once_case(dir, SIG(SIGQUIT));
    once_case(dir, SIG(SIGSEGV));
    once_case(dir, SIG(SIGBUS));
    once_case(dir, SIG(SIGABRT));
    once_case(dir, SIG(SIGFPE));
    once_case(dir, SIG(SIGILL));
    wrap_case(dir);
    stuck_case(dir);
    background_case(dir);
#undef SIG
}

/* ---------- network approval, sandbox badge ---------- */

static bool bottom_has(MicaSession *s, const char *needle) {
    char line[1024];
    get_row_text(s, mica_session_rows(s) - 1, line, sizeof line);
    return strstr(line, needle) != NULL;
}

static void sandbox_tests(const char *dir, const char *cmd) {
    char full[2100];
    MicaSession *s;
    if (system("/usr/bin/sandbox-exec -p '(version 1)(allow default)' /usr/bin/true >/dev/null 2>&1")) {
        printf("SKIP sandboxed TUI checks: no working sandbox here\n");
    } else {
        s = mica_session_create(dir, cmd, 24, 80);
        assert(s != NULL);
        CHECK(s, "boxed: ready", wait_for_text(s, "ready", 3000));
        pump(s, 150);
        CHECK(s, "boxed: no sandbox badge", find_row(s, "NOT SANDBOXED") < 0);
        free(mica_session_take_notification(s));
        submit(s, "WANTNET");
        CHECK(s, "net: modal", wait_for_text(s, "Network access request", 4000));
        pump(s, 150);
        CHECK(s, "net: schema offers network", g_net_schema == 1);
        CHECK(s, "net: own title", find_row(s, "Network access request") >= 0 && find_row(s, "Bash command") < 0);
        CHECK(s, "net: shows the command", find_row(s, "touch net-file") >= 0);
        CHECK(s, "net: asks for external network", find_row(s, "external network access") >= 0);
        CHECK(s, "net: no internal header line", find_row(s, "# allow NETWORK") < 0);
        CHECK(s, "net: yes or no only, No selected",
              find_row(s, "\xe2\x96\xb8 2. No") >= 0 && find_row(s, "ask again") < 0);
        char *notif = mica_session_take_notification(s);
        CHECK(s, "net: notification names the network", notif && strstr(notif, "network") && strstr(notif, "approval"));
        free(notif);
        CHECK(s, "boxed: no badge in a modal", find_row(s, "NOT SANDBOXED") < 0);
        mica_session_key(s, VTERM_KEY_ESCAPE, VTERM_MOD_NONE);
        CHECK(s, "net: Esc denies", wait_for_text(s, "\xe2\x9c\x93 done", 4000));
        pump(s, 300);
        CHECK(s, "net: denied, not run", !made(dir, "net-file"));
        mica_session_destroy(s);

        /* a one-shot run has nobody to ask, so it is not offered either */
        snprintf(full, sizeof full, "cd '%s' && %s hello </dev/null >/dev/null 2>&1", dir, cmd);
        g_net_schema = -1;
        int rc = system(full);
        CHECK((MicaSession *)NULL, "one-shot: request reached the server", rc != -1 && g_net_schema >= 0);
        CHECK((MicaSession *)NULL, "one-shot: network not offered", g_net_schema == 0);
    }

    snprintf(full, sizeof full, "%s --unsafe", cmd);
    s = mica_session_create(dir, full, 24, 80);
    assert(s != NULL);
    CHECK(s, "unsafe: ready", wait_for_text(s, "ready", 3000));
    pump(s, 150);
    CHECK(s, "unsafe: badge on the idle bar", bottom_has(s, "NOT SANDBOXED") && bottom_has(s, "ready"));
    assert_box_borders(s, "unsafe: borders with badge");
    CHECK(s, "unsafe: modal", open_modal(s, "WANTNET"));
    pump(s, 150);
    CHECK(s, "unsafe: network not offered", g_net_schema == 0);
    CHECK(s, "unsafe: ordinary command prompt",
          find_row(s, "Bash command") >= 0 && find_row(s, "Network access request") < 0);
    CHECK(s, "unsafe: badge under a modal", bottom_has(s, "NOT SANDBOXED"));
    close_modal(s);
    pump(s, 300);
    CHECK(s, "unsafe: badge after the modal", bottom_has(s, "NOT SANDBOXED"));
    submit(s, "SLOW_TEST");
    CHECK(s, "unsafe: working", wait_for_text(s, "tick-3", 4000));
    CHECK(s, "unsafe: badge while working", bottom_has(s, "NOT SANDBOXED"));
    mica_session_key(s, VTERM_KEY_ESCAPE, VTERM_MOD_NONE);
    pump(s, 600);
    mica_session_destroy(s);

    /* narrow: the badge stays, the bar is clipped and never scrolls the screen */
    s = mica_session_create(dir, full, 24, 40);
    assert(s != NULL);
    CHECK(s, "narrow: ready", wait_for_text(s, "ready", 3000));
    pump(s, 150);
    CHECK(s, "narrow: badge", bottom_has(s, "NOT SANDBOXED"));
    assert_box_borders(s, "narrow: borders with badge");
    mica_session_destroy(s);
}

/* ---------- branch name in the input box ---------- */

/* A git of our own, first on PATH; --unsafe keeps PATH as it is. */
static void branch_case(const char *dir, const char *cmd, const char *name, const char *script,
                        const char *want) {
    char path[1300], full[3600], label[128];
    snprintf(path, sizeof path, "%s/fakebin", dir);
    mkdir(path, 0755);
    snprintf(path, sizeof path, "%s/fakebin/git", dir);
    FILE *f = fopen(path, "w");
    assert(f != NULL);
    fprintf(f, "#!/bin/sh\n%s\n", script);
    fclose(f);
    chmod(path, 0755);
    snprintf(full, sizeof full, "PATH='%s/fakebin':\"$PATH\"; export PATH; %s --unsafe", dir, cmd);
    MicaSession *s = mica_session_create(dir, full, 24, 80);
    assert(s != NULL);
    bool ready = wait_for_text(s, "ready", 6000);
    pump(s, 150);
    snprintf(label, sizeof label, "branch: %s", name);
    CHECK(s, label, ready && (want ? find_row(s, want) >= 0 : find_row(s, "\xe2\x8e\x87") < 0));
    mica_session_destroy(s);
    unlink(path);
}

static void branch_tests(const char *dir, const char *cmd) {
    branch_case(dir, cmd, "shown when git succeeds", "echo good-branch", "\xe2\x8e\x87 good-branch)");
    branch_case(dir, cmd, "none when git fails", "echo bogus; exit 1", NULL);
    branch_case(dir, cmd, "none when git hangs", "exec sleep 10", NULL);
}

/* ---------- first run: no model named, or no server ---------- */

static void startup_tests(const char *dir, const char *fw) {
    char cmd[2048];
    snprintf(cmd, sizeof cmd, "unset FW_MODEL FW_ENDPOINT; exec '%s' -e http://127.0.0.1:%d/v1",
             fw, g_srv_port);
    g_models_one = 1;
    MicaSession *s = mica_session_create(dir, cmd, 24, 80);
    assert(s != NULL);
    bool ready = wait_for_text(s, "ready", 6000);
    pump(s, 150);
    CHECK(s, "the only model served is used", ready && find_row(s, "mock/solo") >= 0);
    CHECK(s, "a reachable server draws no setup hint", find_row(s, "flywheel setup") < 0);
    mica_session_destroy(s);

    /* /models down at startup: the pick waits for an answer, and never
       replaces a model chosen with /model in the meantime */
    for (int chosen = 0; chosen < 2; chosen++) {
        g_models_fail = 1;
        s = mica_session_create(dir, cmd, 24, 80);
        assert(s != NULL);
        ready = wait_for_text(s, "ready", 6000);
        pump(s, 150);
        if (chosen) {
            type_str(s, "/model mock/chosen\r");
            ready = ready && wait_for_text(s, "model: mock/chosen", 3000);
        }
        g_models_fail = 0;
        g_chat_model[0] = 0;
        type_str(s, "hi");
        mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
        bool done = wait_for_text(s, "\xe2\x9c\x93 done", 8000);
        CHECK(s, chosen ? "an explicit /model choice survives a late /models answer"
                        : "a model listed after startup is used by the next task",
              ready && done && !strcmp(g_chat_model, chosen ? "mock/chosen" : "mock/solo"));
        mica_session_destroy(s);
    }
    g_models_one = 0;

    snprintf(cmd, sizeof cmd, "unset FW_MODEL FW_ENDPOINT; exec '%s' -e http://127.0.0.1:1/v1 -W 1", fw);
    s = mica_session_create(dir, cmd, 40, 80);
    assert(s != NULL);
    CHECK(s, "no server: said at startup", wait_for_text(s, "run `flywheel setup`", 6000) &&
          find_row(s, "cannot reach the server at http://127.0.0.1:1/v1") >= 0 &&
          find_row(s, "offline") >= 0);
    pump(s, 150);
    int first = find_last_row(s, "flywheel setup");
    type_str(s, "hi");
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    bool failed = wait_for_text(s, "\xe2\x9c\x97", 8000);
    pump(s, 300);
    CHECK(s, "no server: said again when a task fails",
          failed && find_last_row(s, "flywheel setup") > first);
    mica_session_destroy(s);
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    const char *fw_bin = (argc > 1) ? argv[1] : "./flywheel";
    char cwd[1024];
    assert(getcwd(cwd, sizeof cwd) != NULL);
    char abs_fw[1200];
    if (fw_bin[0] == '/') snprintf(abs_fw, sizeof abs_fw, "%s", fw_bin);
    else snprintf(abs_fw, sizeof abs_fw, "%s/%s", cwd, fw_bin);

    char testdir[] = "/tmp/fwmica-XXXXXX";
    assert(mkdtemp(testdir) != NULL);
    char mdpath[1200];
    snprintf(mdpath, sizeof mdpath, "%s/.flywheel.md", testdir);
    FILE *mf = fopen(mdpath, "w");
    fputs("# mica test project\n", mf);
    fclose(mf);

    pthread_t srv_th;
    start_mock_server(&srv_th);

    char cmd[2048];
    snprintf(cmd, sizeof cmd, "exec '%s' -e http://127.0.0.1:%d/v1 -m mock/qwen", abs_fw, g_srv_port);

    MicaSession *s = mica_session_create(testdir, cmd, 24, 80);
    assert(s != NULL);

    /* 1. Startup & initial layout */
    CHECK(s, "startup ready", wait_for_text(s, "ready", 3000));
    pump(s, 150);
    assert_box_borders(s, "startup borders");
    CHECK(s, "welcome card FLYWHEEL emblem visible", find_row(s, "F L Y W H E E L") >= 0 && find_row(s, "online") >= 0);
    CHECK(s, "status bar shows context gauge", find_row(s, "ctx") >= 0);
    CHECK(s, "bracketed paste enabled for Mica", mica_session_bracketed_paste(s));
    CHECK(s, "no leaked sync output frame", !mica_session_sync_output_active(s));

    int cr = 0, cc = 0;
    int input_row = find_last_row(s, "╭") + 1;
    mica_session_cursor(s, &cr, &cc);
    CHECK(s, "empty input cursor at (input_row, col 3)", cr == input_row && cc == 3);

    /* 2. Exact cursor placement & UTF-8 / emoji editing */
    type_str(s, "hello");
    pump(s, 150);
    mica_session_cursor(s, &cr, &cc);
    MicaCell at_prev, at_cur;
    mica_session_get_cell(s, cr, cc - 1, &at_prev);
    mica_session_get_cell(s, cr, cc, &at_cur);
    CHECK(s, "cursor AFTER last char 'o', not ON it",
          cr == input_row && cc == 8 && at_prev.chars[0] == 'o' && (at_cur.chars[0] == 0 || at_cur.chars[0] == ' '));

    mica_session_key(s, VTERM_KEY_LEFT, VTERM_MOD_NONE);
    mica_session_key(s, VTERM_KEY_LEFT, VTERM_MOD_NONE);
    type_str(s, "X");
    pump(s, 150);
    CHECK(s, "mid-line insert 'helXlo'", find_row(s, "helXlo") == input_row);
    mica_session_cursor(s, &cr, &cc);
    CHECK(s, "cursor after mid-line insert at col 7", cr == input_row && cc == 7);

    /* Clear with Ctrl+C and test emoji width + UTF-8 backspace */
    mica_session_text(s, 'c', VTERM_MOD_CTRL);
    pump(s, 120);
    type_str(s, "a\xF0\x9F\x9A\x80""b"); /* a🚀b */
    pump(s, 150);
    mica_session_cursor(s, &cr, &cc);
    CHECK(s, "emoji cursor width (a=1, 🚀=2, b=1 -> col 7)", cr == input_row && cc == 7);
    mica_session_key(s, VTERM_KEY_BACKSPACE, VTERM_MOD_NONE);
    mica_session_key(s, VTERM_KEY_BACKSPACE, VTERM_MOD_NONE);
    pump(s, 150);
    mica_session_cursor(s, &cr, &cc);
    CHECK(s, "UTF-8 backspace removes whole emoji -> col 4", cr == input_row && cc == 4);
    assert_box_borders(s, "borders after emoji edit");

    /* ^V is not a clipboard image paste: nothing is written into the project */
    mica_session_text(s, 'c', VTERM_MOD_CTRL);
    pump(s, 100);
    mica_session_text(s, 'v', VTERM_MOD_CTRL);
    pump(s, 1500);
    char pastedir[1200];
    snprintf(pastedir, sizeof pastedir, "%s/.flywheel", testdir);
    CHECK(s, "^V writes nothing into the project", access(pastedir, F_OK) != 0);
    CHECK(s, "^V reports no image paste", find_row(s, "image") < 0);

    /* 3. Long input soft-wrapping (must NOT break right border) */
    mica_session_text(s, 'c', VTERM_MOD_CTRL);
    pump(s, 100);
    type_str(s, "01234567890123456789012345678901234567890123456789012345678901234567890123456789ZZZZ");
    pump(s, 150);
    assert_box_borders(s, "borders intact after 84-char soft wrap");
    CHECK(s, "wrapped text visible on line 2", find_row(s, "ZZZZ") > find_last_row(s, "╭") + 1);
    mica_session_text(s, 'c', VTERM_MOD_CTRL);
    pump(s, 120);

    /* 4. Slash menu below input box (Claude Code style), non-destructive & zero ghosts */
    type_str(s, "/");
    pump(s, 150);
    int box_bot = find_last_row(s, "╰");
    int init_row = find_row(s, "/init");
    CHECK(s, "slash menu renders BELOW bottom border", init_row > box_bot);
    CHECK(s, "banner NOT overwritten when menu opens", find_row(s, "F L Y W H E E L") >= 0);

    /* Arrow down highlights /clear */
    mica_session_key(s, VTERM_KEY_DOWN, VTERM_MOD_NONE);
    pump(s, 120);
    CHECK(s, "arrow down selects /clear", find_row(s, "▸ /clear") > box_bot);

    /* Esc dismisses menu with zero ghost rows and restores banner position */
    mica_session_key(s, VTERM_KEY_ESCAPE, VTERM_MOD_NONE);
    pump(s, 150);
    CHECK(s, "Esc dismisses slash menu (no ghost /init)", find_row(s, "/init") < 0);
    assert_box_borders(s, "borders after menu dismiss");

    /* Repeatedly opening/closing slash menu must not push banner off screen */
    for (int k = 0; k < 4; k++) {
        mica_session_text(s, 'c', VTERM_MOD_CTRL);
        type_str(s, "/");
        pump(s, 80);
        mica_session_key(s, VTERM_KEY_BACKSPACE, VTERM_MOD_NONE);
        pump(s, 80);
    }
    CHECK(s, "banner still visible after 4x open/close menu", find_row(s, "F L Y W H E E L") >= 0);

    /* Filter /he + Enter executes /help cleanly, zero ghost rows */
    mica_session_text(s, 'c', VTERM_MOD_CTRL);
    pump(s, 100);
    type_str(s, "/he");
    pump(s, 150);
    CHECK(s, "filtered menu shows /help", find_row(s, "▸ /help") > find_last_row(s, "╰"));
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    CHECK(s, "/help output rendered", wait_for_text(s, "keys:", 1500));
    pump(s, 150);
    int keys_row = find_row(s, "keys:");
    int box_top = find_last_row(s, "╭");
    CHECK(s, "/help output above input box", keys_row >= 0 && keys_row < box_top);
    CHECK(s, "no stale menu rows after /help", find_row(s, "▸ /help") < 0 && find_row(s, "write .flywheel.md") < 0);

    /* 5. Shift+Enter multiline via Mica's exact key handler */
    type_str(s, "firstline");
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_SHIFT);
    type_str(s, "secondline");
    pump(s, 150);
    int r1 = find_row(s, "firstline"), r2 = find_row(s, "secondline");
    CHECK(s, "Shift+Enter multiline renders 2 rows", r1 >= 0 && r2 == r1 + 1);
    assert_box_borders(s, "borders intact on multiline");
    mica_session_text(s, 'c', VTERM_MOD_CTRL);
    pump(s, 120);

    /* 6. Bracketed paste via mica_session_paste() (Mica's Cmd+V path) */
    const char *big = "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\n";
    mica_session_paste(s, big, strlen(big));
    pump(s, 200);
    CHECK(s, "large bracketed paste collapses to [paste#1 ...]", find_row(s, "[paste#1") >= 0);
    assert_box_borders(s, "borders intact after paste collapse");
    mica_session_text(s, 'c', VTERM_MOD_CTRL);
    pump(s, 120);

    /* 7. Streaming continuity + Claude-Code approval modal menu + OSC 9 + collapsed command click-to-expand */
    CHECK(s, "mouse reporting enabled for Mica click/wheel", mica_session_reports_mouse(s));
    type_str(s, "STREAM_TEST");
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    CHECK(s, "approval modal menu appears", wait_for_text(s, "Do you want to proceed?", 4000));
    pump(s, 150);
    /* thinking collapses to a one-line summary once reasoning finishes (claude-code style) */
    CHECK(s, "thinking collapsed to summary line", find_row(s, "Thought for") >= 0);
    CHECK(s, "content streamed continuously (not word-per-line)", find_row(s, "Hello world from flywheel!") >= 0);
    CHECK(s, "modal shows titled border", find_row(s, "Bash command") >= 0);
    CHECK(s, "modal defaults to No", find_row(s, "▸ 2. No") >= 0);
    CHECK(s, "modal shows option 1 (Yes)", find_row(s, "1. Yes") >= 0);
    CHECK(s, "no always option for a piped command", find_row(s, "don't ask again") < 0);
    char *notif = mica_session_take_notification(s);
    CHECK(s, "Mica received OSC 9 approval notification", notif != NULL && strstr(notif, "approval") != NULL);
    free(notif);

    /* Navigate approval menu with arrow keys, then click option 1 with mouse */
    mica_session_key(s, VTERM_KEY_DOWN, VTERM_MOD_NONE);
    pump(s, 100);
    pump(s, 500);
    mica_session_key(s, VTERM_KEY_DOWN, VTERM_MOD_NONE);
    pump(s, 100);
    CHECK(s, "arrow down highlights option 1 in modal", find_row(s, "▸ 1. Yes") >= 0);
    int opt1_row = find_row(s, "1. Yes");
    CHECK(s, "option 1 row found for click", opt1_row >= 0);
    mica_session_mouse(s, opt1_row, 6, 1, true);
    mica_session_mouse(s, opt1_row, 6, 1, false);

    CHECK(s, "task completes after clicking Yes", wait_for_text(s, "✓ done", 4000));
    pump(s, 150);
    assert_box_borders(s, "borders intact after modal closes");
    CHECK(s, "completion pill shows turn & token stats", find_row(s, "tok") >= 0);
    {
        char sline[1024];
        get_row_text(s, mica_session_rows(s) - 1, sline, sizeof sline);
        CHECK(s, "status bar shows ctx gauge after task", strstr(sline, "ctx") && strstr(sline, "%"));
    }

    /* Command output MUST be collapsed by default (+4 lines hint, out-line-6 hidden) */
    CHECK(s, "command output collapsed by default", find_row(s, "click or ^O to expand") >= 0);
    CHECK(s, "collapsed preview shows line 1", find_row(s, "out-line-1") >= 0);
    CHECK(s, "collapsed hides line 6", find_row(s, "out-line-6") < 0);

    /* Click the collapsed command block to expand it */
    int cmd_row = find_row(s, "click or ^O to expand");
    mica_session_mouse(s, cmd_row, 8, 1, true);
    mica_session_mouse(s, cmd_row, 8, 1, false);
    pump(s, 150);
    CHECK(s, "click expands command output (line 6 visible)", find_row(s, "out-line-6") >= 0);
    CHECK(s, "expanded shows collapse hint", find_row(s, "click or ^O to collapse") >= 0);

    /* Click again to collapse */
    int exp_row = find_row(s, "click or ^O to collapse");
    mica_session_mouse(s, exp_row, 8, 1, true);
    mica_session_mouse(s, exp_row, 8, 1, false);
    pump(s, 150);
    CHECK(s, "second click collapses command output", find_row(s, "out-line-6") < 0 && find_row(s, "click or ^O to expand") >= 0);

    /* Ctrl+O also expands & collapses */
    mica_session_text(s, 'o', VTERM_MOD_CTRL);
    pump(s, 120);
    CHECK(s, "Ctrl+O expands command output", find_row(s, "out-line-6") >= 0);
    mica_session_text(s, 'o', VTERM_MOD_CTRL);
    pump(s, 120);
    CHECK(s, "Ctrl+O collapses command output", find_row(s, "out-line-6") < 0);

    /* 8. Multi-choice /model picker menu (arrow down + Enter selects mock/qwen-alt) */
    type_str(s, "/model");
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    CHECK(s, "/model opens multi-choice menu", wait_for_text(s, "Choose a model:", 2000));
    pump(s, 100);
    mica_session_key(s, VTERM_KEY_DOWN, VTERM_MOD_NONE);
    pump(s, 100);
    CHECK(s, "arrow down selects mock/qwen-alt", find_row(s, "▸ 2. mock/qwen-alt") >= 0);
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    CHECK(s, "model switched to mock/qwen-alt", wait_for_text(s, "model: mock/qwen-alt", 2000));
    pump(s, 100);

    /* 9. Option 2 (always-allow) persists rule and skips modal next time */
    type_str(s, "ALWAYS_TEST");
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    CHECK(s, "first uname opens approval modal", wait_for_text(s, "Do you want to proceed?", 3000));
    pump(s, 600);
    CHECK(s, "modal shows option 2 (always)", find_row(s, "2. Yes, and don't ask again") >= 0);
    CHECK(s, "modal shows option 3 (No) selected", find_row(s, "▸ 3. No") >= 0);
    type_str(s, "2");
    CHECK(s, "first ALWAYS_TEST finishes after pressing 2", wait_for_text(s, "ready", 4000));
    pump(s, 150);
    type_str(s, "/clear");
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    pump(s, 150);
    type_str(s, "ALWAYS_TEST");
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    CHECK(s, "second uname finishes WITHOUT modal", wait_for_text(s, "Darwin", 4000));
    CHECK(s, "no modal shown on second uname", find_row(s, "Do you want to proceed?") < 0);
    wait_for_text(s, "ready", 3000);
    pump(s, 100);

    type_str(s, "/allow");
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    bool listed = wait_for_text(s, "builtin read-only", 2000);
    pump(s, 150);
    CHECK(s, "/allow lists the per-project rule file", listed && find_row(s, "projects/") >= 0);
    pump(s, 100);

    /* 10. Esc aborts slow streaming request cleanly */
    type_str(s, "SLOW_TEST");
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    CHECK(s, "slow stream starts", wait_for_text(s, "tick-0", 3000));
    mica_session_key(s, VTERM_KEY_ESCAPE, VTERM_MOD_NONE);
    CHECK(s, "Esc aborts stream and returns to ready", wait_for_text(s, "error:aborted", 4000));
    pump(s, 150);

    /* 10b. CRITICAL: input stays alive while the agent is busy.
       Type during an active stream: characters must land in the input box,
       Enter must queue the message, scrolling must stay anchored. */
    type_str(s, "SLOW_TEST");
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    CHECK(s, "second slow stream starts", wait_for_text(s, "tick-0", 3000));
    type_str(s, "busy-typing");
    pump(s, 250);
    CHECK(s, "keystrokes reach input box while agent streams", find_row(s, "busy-typing") >= 0);
    /* queue it with Enter: input box clears, queued indicator appears */
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    pump(s, 250);
    CHECK(s, "input box cleared after queueing", find_row(s, "busy-typing") < 0);
    CHECK(s, "queued indicator in status bar", find_row(s, "queued") >= 0);
    /* Esc aborts; queue is cleared with the abort */
    mica_session_key(s, VTERM_KEY_ESCAPE, VTERM_MOD_NONE);
    CHECK(s, "Esc aborts busy stream", wait_for_text(s, "error:aborted", 4000));
    pump(s, 150);

    /* 11. Markdown rendering: headings, bold/italic/code, snake_case, bullets, code fence, table, OSC 8 link */
    type_str(s, "/clear");
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    pump(s, 120);
    type_str(s, "MD_TEST");
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    CHECK(s, "markdown test finishes", wait_for_text(s, "✓ done", 4000));
    pump(s, 150);
    int hrow = find_row(s, "Project Overview");
    CHECK(s, "heading rendered without raw #", hrow >= 0 && find_row(s, "# Project Overview") < 0);
    if (hrow >= 0) {
        MicaCell hc;
        mica_session_get_cell(s, hrow, 0, &hc);
        CHECK(s, "heading cell has bold attr", hc.attrs.bold != 0);
    }
    int prow = find_row(s, "boldtext");
    CHECK(s, "inline markdown strips **/*/` markers", prow >= 0 && find_row(s, "**boldtext**") < 0 && find_row(s, "snake_case_ok") >= 0);
    if (prow >= 0) {
        bool saw_bold = false, saw_italic = false, saw_link = false;
        for (int c = 0; c < mica_session_cols(s); c++) {
            MicaCell mc;
            if (!mica_session_get_cell(s, prow, c, &mc)) continue;
            if (mc.chars[0] == 'b' && mc.attrs.bold) saw_bold = true;
            if (mc.chars[0] == 'i' && mc.attrs.italic) saw_italic = true;
            if (mc.hyperlink_id) {
                const char *uri = mica_session_hyperlink_uri(s, mc.hyperlink_id);
                if (uri && !strcmp(uri, "https://example.com")) saw_link = true;
            }
        }
        CHECK(s, "bold attribute set on **boldtext**", saw_bold);
        CHECK(s, "italic attribute set on *italics*", saw_italic);
        CHECK(s, "OSC 8 clickable hyperlink registered in Mica", saw_link);
    }
    CHECK(s, "bullet rendered with •", find_row(s, "• Bullet one") >= 0);
    CHECK(s, "blockquote rendered with ▎", find_row(s, "▎ Quoted note") >= 0);
    CHECK(s, "fenced code block rendered with box + lang", find_row(s, "╭─ c ") >= 0 && find_row(s, "│ int x = 42;") >= 0);
    CHECK(s, "markdown table rendered with box-drawing", find_row(s, "│ Key") >= 0 && find_row(s, "│ mode") >= 0 && find_row(s, "┼") >= 0);

    /* 12. Mouse wheel scrolls transcript smoothly */
    type_str(s, "SCROLL_TEST");
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    CHECK(s, "scroll test finishes", wait_for_text(s, "scroll-line-35", 4000));
    pump(s, 150);

    /* Anchoring during live stream: with real overflow content present, scroll up
       mid-stream and verify incoming tokens don't yank the view to bottom */
    type_str(s, "SLOW_TEST");
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    CHECK(s, "anchor-test slow stream starts", wait_for_text(s, "tick-0", 3000));
    for (int w = 0; w < 4; w++) mica_session_wheel(s, 5, 10, -1);
    pump(s, 250);
    int anchored = find_row(s, "lines") >= 0;
    pump(s, 700);
    CHECK(s, "scroll position anchored while streaming (no yank-to-bottom)", anchored && find_row(s, "lines") >= 0);
    /* End key jumps back to bottom while busy */
    mica_session_key(s, VTERM_KEY_END, VTERM_MOD_NONE);
    pump(s, 250);
    mica_session_key(s, VTERM_KEY_ESCAPE, VTERM_MOD_NONE);
    CHECK(s, "Esc aborts anchor-test stream", wait_for_text(s, "error:aborted", 4000));
    pump(s, 150);
    for (int w = 0; w < 10; w++) mica_session_wheel(s, 5, 10, -1);
    pump(s, 200);
    CHECK(s, "mouse wheel scrolls up to earlier lines", find_row(s, "scroll-line-05") >= 0);
    CHECK(s, "scroll indicator shown in status bar", find_row(s, "lines") >= 0);
    for (int w = 0; w < 12; w++) mica_session_wheel(s, 5, 10, 1);
    pump(s, 200);
    CHECK(s, "mouse wheel scrolls back down to bottom", find_row(s, "scroll-line-35") >= 0);

    /* 11. Live window resize via mica_session_resize() */
    assert(mica_session_resize(s, 30, 100));
    pump(s, 250);
    assert_box_borders(s, "borders aligned after resize to 30x100");
    CHECK(s, "status on bottom row 29 after resize", find_row(s, "ready") == 29);

    assert(mica_session_resize(s, 20, 60));
    pump(s, 250);
    assert_box_borders(s, "borders aligned after resize to 20x60");
    CHECK(s, "status on bottom row 19 after resize", find_row(s, "ready") == 19);

    /* 12. Clean exit via /exit */
    type_str(s, "/exit");
    mica_session_key(s, VTERM_KEY_ENTER, VTERM_MOD_NONE);
    CHECK(s, "clean exit via /exit", wait_for_exit(s, 3000));
    CHECK(s, "exit status 0", mica_session_exit_status(s) == 0);

    mica_session_destroy(s);
    security_tests(testdir, cmd);
    input_tests(testdir, cmd);
    copy_tests(testdir, cmd);
    image_tests(cmd);
    signal_tests(testdir, cmd);
    sandbox_tests(testdir, cmd);
    branch_tests(testdir, cmd);
    startup_tests(testdir, abs_fw);
    stop_mock_server(srv_th);

    char rm[1200];
    snprintf(rm, sizeof rm, "rm -rf '%s'", testdir);
    system(rm);

    printf("mica-tui: %d passed, %d failed\n", g_passed, g_failed);
    return g_failed ? 1 : 0;
}
