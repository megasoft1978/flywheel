#define _DARWIN_C_SOURCE 1
#include "mica.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

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

static void handle_client(int cfd) {
    char req[65536];
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
                           "{\"data\":[{\"id\":\"mock/qwen\"},{\"id\":\"mock/qwen-alt\"}]}";
        send_all(cfd, resp, strlen(resp));
        close(cfd);
        return;
    }

    const char *body = hdr_end ? hdr_end + 4 : req;
    const char *sse_hdr = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n";
    send_all(cfd, sse_hdr, strlen(sse_hdr));

    /* Inspect only the LAST message in the conversation array */
    const char *last_msg = body;
    for (const char *p = body; (p = strstr(p, "\"role\":\"")); p += 8) last_msg = p;

    if (strstr(last_msg, "\"role\":\"tool\"")) {
        send_sse_chunk(cfd, "{\"choices\":[{\"delta\":{\"content\":\"DONE\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}");
        send_all(cfd, "data: [DONE]\n\n", 14);
        close(cfd);
        return;
    }

    if (handle_security(cfd, last_msg)) return;

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
    stop_mock_server(srv_th);

    char rm[1200];
    snprintf(rm, sizeof rm, "rm -rf '%s'", testdir);
    system(rm);

    printf("mica-tui: %d passed, %d failed\n", g_passed, g_failed);
    return g_failed ? 1 : 0;
}
