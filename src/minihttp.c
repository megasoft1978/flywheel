/* minihttp.c — minimal pure-C HTTP/1.1 client for static/embedded builds.
   Plain HTTP only (the engine is a localhost/LAN OpenAI-compatible server).
   Supports chunked transfer-encoding, Content-Length and close-delimited bodies,
   abort/tick polling in the read loop. Enabled with -DFW_MINI_HTTP. */

#include "flywheel.h"
#ifdef FW_MINI_HTTP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* parse http://host[:port][/path] — returns port or <0 on error */
static int parse_url(const char *url, char *host, size_t hcap, int *port, char *path, size_t pcap) {
    const char *p = url;
    if (!strncmp(p, "http://", 7)) p += 7;
    /* no https: this client is plain-HTTP by design */
    const char *slash = strchr(p, '/');
    const char *colon = NULL;
    for (const char *q = p; *q && *q != '/'; q++) if (*q == ':') colon = q;
    size_t hl = colon ? (size_t)(colon - p) : (slash ? (size_t)(slash - p) : strlen(p));
    if (hl == 0 || hl >= hcap) return -1;
    memcpy(host, p, hl);
    host[hl] = 0;
    *port = 80;
    if (colon) {
        *port = atoi(colon + 1);
        if (*port <= 0 || *port > 65535) return -1;
    }
    snprintf(path, pcap, "%s", slash ? slash : "/");
    return 0;
}

static int tcp_connect(const char *host, int port, int timeout_s) {
    char ps[16];
    snprintf(ps, sizeof ps, "%d", port);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, ps, &hints, &res) != 0) return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    (void)timeout_s;
    return fd;
}

typedef struct {
    char *buf;
    size_t len, cap;
} MBuf;

static int mb_putc(MBuf *b, char c) {
    if (b->len + 1 >= b->cap) {
        b->cap = b->cap ? b->cap * 2 : 256;
        b->buf = realloc(b->buf, b->cap);
        if (!b->buf) return -1;
    }
    b->buf[b->len++] = c;
    b->buf[b->len] = 0;
    return 0;
}

/* read one byte with select-timeout; returns 1 byte-read, 0 eof, -1 error/abort, -2 timeout-idle */
static int read_byte(int fd, char *out, int idle_s) {
    fd_set rf;
    FD_ZERO(&rf);
    FD_SET(fd, &rf);
    struct timeval tv = {.tv_sec = idle_s, .tv_usec = 0};
    if (fw_tick_hook) fw_tick_hook();
    if (g_abort) return -1;
    int sr = select(fd + 1, &rf, NULL, NULL, &tv);
    if (sr < 0) return -1;
    if (sr == 0) return -2;
    ssize_t n = read(fd, out, 1);
    if (n == 1) return 1;
    if (n == 0) return 0;
    return -1;
}

/* read a header/line up to and including \n */
static int read_line(int fd, MBuf *line, int idle_s) {
    line->len = 0;
    if (line->buf) line->buf[0] = 0;
    for (;;) {
        char c;
        int r = read_byte(fd, &c, idle_s);
        if (r != 1) return r;
        mb_putc(line, c);
        if (c == '\n') return 1;
        if (line->len > 8192) return -1; /* pathological header */
    }
}

/* feed body bytes to the write callback, honoring aborts */
static int feed(size_t (*cb)(char *, size_t, size_t, void *), void *ud,
                const char *data, size_t n) {
    if (!cb) return 1;
    size_t got = cb((char *)data, 1, n, ud);
    return got == n ? 1 : -1;
}

/* Core request: method POST/GET. Streams body through cb as it arrives.
   Returns 0 on success (regardless of status code), -1 transport error/abort.
   status_out receives the HTTP status code. */
static int mini_request(const char *method, const char *url, const char *payload,
                        int streaming, size_t (*cb)(char *, size_t, size_t, void *),
                        void *ud, int timeout_s, int *status_out, char *errbuf, size_t errcap) {
    char host[256], path[1024];
    int port;
    if (parse_url(url, host, sizeof host, &port, path, sizeof path) < 0) {
        snprintf(errbuf, errcap, "bad url");
        return -1;
    }
    int fd = tcp_connect(host, port, timeout_s);
    if (fd < 0) {
        snprintf(errbuf, errcap, "connect failed");
        return -1;
    }

    MBuf req = {0};
    const char *fmt = "%s %s HTTP/1.1\r\nHost: %s\r\n";
    char head[2048];
    char hostport[300];
    if (port != 80) snprintf(hostport, sizeof hostport, "%s:%d", host, port);
    else snprintf(hostport, sizeof hostport, "%s", host);
    int hl = snprintf(head, sizeof head, fmt, method, path, hostport);
    mb_putc(&req, 0); req.len = 0;
    for (int i = 0; i < hl; i++) mb_putc(&req, head[i]);
    /* POSTs always carry JSON; streaming adds the SSE accept header */
    const char *extra;
    if (payload)
        extra = streaming
            ? "Content-Type: application/json\r\nAccept: text/event-stream\r\n"
            : "Content-Type: application/json\r\nAccept: application/json\r\n";
    else
        extra = "Accept: application/json\r\n";
    for (const char *p = extra; *p; p++) mb_putc(&req, *p);
    if (payload) {
        char cl[64];
        snprintf(cl, sizeof cl, "Content-Length: %zu\r\n", strlen(payload));
        for (const char *p = cl; *p; p++) mb_putc(&req, *p);
    }
    const char *conn = "Connection: close\r\n\r\n";
    for (const char *p = conn; *p; p++) mb_putc(&req, *p);

    size_t bodylen = payload ? strlen(payload) : 0;
    size_t total = req.len + bodylen;
    /* single writev-ish: header then payload */
    size_t sent = 0;
    while (sent < req.len) {
        ssize_t n = write(fd, req.buf + sent, req.len - sent);
        if (n <= 0) { close(fd); free(req.buf); snprintf(errbuf, errcap, "write failed"); return -1; }
        sent += (size_t)n;
    }
    sent = 0;
    while (sent < bodylen) {
        ssize_t n = write(fd, payload + sent, bodylen - sent);
        if (n <= 0) { close(fd); free(req.buf); snprintf(errbuf, errcap, "write failed"); return -1; }
        sent += (size_t)n;
    }
    free(req.buf);

    /* ---- read status line + headers ---- */
    MBuf line = {0};
    int status = 0, chunked = 0;
    long content_length = -1;
    int idle = timeout_s < 60 ? timeout_s : 60; /* idle ceiling per read; streaming stays warm */
    int rc = 0;
    int header_lines = 0;
    for (;;) {
        int r = read_line(fd, &line, idle);
        if (r != 1) { rc = -1; snprintf(errbuf, errcap, "header read failed"); goto done; }
        if (header_lines == 0) {
            unsigned u = 0;
            if (sscanf(line.buf, "HTTP/%*s %u", &u) == 1) status = (int)u;
        } else if (!strncasecmp(line.buf, "Transfer-Encoding:", 18) && strstr(line.buf, "chunked")) {
            chunked = 1;
        } else if (!strncasecmp(line.buf, "Content-Length:", 15)) {
            content_length = atol(line.buf + 15);
        }
        header_lines++;
        if (!strcmp(line.buf, "\r\n") || !strcmp(line.buf, "\n")) break;
    }
    if (status_out) *status_out = status;

    /* ---- read body ---- */
    int ret = 0;
    if (chunked) {
        for (;;) {
            /* chunk size line */
            int r = read_line(fd, &line, idle);
            if (r != 1) { ret = -1; snprintf(errbuf, errcap, "chunk header read failed"); break; }
            long csize = strtol(line.buf, NULL, 16);
            if (csize < 0) { ret = -1; break; }
            if (csize == 0) {
                /* trailers then final CRLF — drain a couple of lines */
                for (int i = 0; i < 8; i++) {
                    int rr = read_line(fd, &line, 2);
                    if (rr != 1) break;
                    if (!strcmp(line.buf, "\r\n") || !strcmp(line.buf, "\n")) break;
                }
                break;
            }
            /* stream the chunk data to cb in slices */
            long left = csize;
            while (left > 0) {
                char buf[8192];
                int want = left > (long)sizeof buf ? (int)sizeof buf : (int)left;
                /* direct socket read for bulk bytes, but keep tick/abort responsiveness */
                fd_set rf;
                FD_ZERO(&rf);
                FD_SET(fd, &rf);
                struct timeval tv = {.tv_sec = idle, .tv_usec = 0};
                if (fw_tick_hook) fw_tick_hook();
                if (g_abort) { ret = -1; snprintf(errbuf, errcap, "aborted"); goto done; }
                if (select(fd + 1, &rf, NULL, NULL, &tv) <= 0) { ret = -1; snprintf(errbuf, errcap, "read timeout"); goto done; }
                ssize_t n = read(fd, buf, (size_t)want);
                if (n <= 0) { ret = -1; snprintf(errbuf, errcap, "connection closed mid-chunk"); goto done; }
                if (feed(cb, ud, buf, (size_t)n) < 0) { ret = -1; snprintf(errbuf, errcap, "aborted"); goto done; }
                left -= n;
            }
            /* trailing CRLF after chunk data */
            char t[2];
            for (int i = 0; i < 2; i++) {
                int rr = read_byte(fd, &t[i], idle);
                if (rr != 1) { ret = -1; goto done; }
            }
        }
    } else if (content_length >= 0) {
        long left = content_length;
        while (left > 0) {
            char buf[8192];
            int want = left > (long)sizeof buf ? (int)sizeof buf : (int)left;
            fd_set rf;
            FD_ZERO(&rf);
            FD_SET(fd, &rf);
            struct timeval tv = {.tv_sec = idle, .tv_usec = 0};
            if (fw_tick_hook) fw_tick_hook();
            if (g_abort) { ret = -1; snprintf(errbuf, errcap, "aborted"); goto done; }
            if (select(fd + 1, &rf, NULL, NULL, &tv) <= 0) { ret = -1; snprintf(errbuf, errcap, "read timeout"); goto done; }
            ssize_t n = read(fd, buf, (size_t)want);
            if (n <= 0) break;
            if (feed(cb, ud, buf, (size_t)n) < 0) { ret = -1; snprintf(errbuf, errcap, "aborted"); goto done; }
            left -= n;
        }
    } else {
        /* read until close */
        for (;;) {
            char buf[8192];
            fd_set rf;
            FD_ZERO(&rf);
            FD_SET(fd, &rf);
            struct timeval tv = {.tv_sec = idle, .tv_usec = 0};
            if (fw_tick_hook) fw_tick_hook();
            if (g_abort) { ret = -1; snprintf(errbuf, errcap, "aborted"); goto done; }
            int sr = select(fd + 1, &rf, NULL, NULL, &tv);
            if (sr < 0) { ret = -1; goto done; }
            if (sr == 0) { ret = -1; snprintf(errbuf, errcap, "read timeout"); goto done; }
            ssize_t n = read(fd, buf, sizeof buf);
            if (n < 0) { ret = -1; goto done; }
            if (n == 0) break;
            if (feed(cb, ud, buf, (size_t)n) < 0) { ret = -1; snprintf(errbuf, errcap, "aborted"); goto done; }
        }
    }

done:
    free(line.buf);
    close(fd);
    if (rc) return rc;
    return ret;
}

/* ---- public surface used by http.c when FW_MINI_HTTP ---- */

int fw_mini_post_stream(const char *url, const char *payload, int streaming,
                        size_t (*cb)(char *, size_t, size_t, void *), void *ud,
                        char *errbuf, size_t errcap) {
    int status = 0;
    int rc = mini_request("POST", url, payload, streaming, cb, ud, 3600, &status, errbuf, errcap);
    if (rc == 0 && status >= 400) {
        /* body already streamed into the accumulator; http.c parses error json there */
    }
    return rc;
}

size_t fw_mini_acc_cb(char *, size_t, size_t, void *);

char *fw_mini_get(const char *url) {
    struct acc {
        char *buf; size_t len, cap;
    } a = {0};
    char err[128] = "";
    int rc = mini_request("GET", url, NULL, 0, fw_mini_acc_cb, &a, 8, NULL, err, sizeof err);
    if (rc != 0) { free(a.buf); return NULL; }
    return a.buf ? a.buf : str_dup("");
}

size_t fw_mini_acc_cb(char *ptr, size_t sz, size_t nm, void *ud) {
    struct acc {
        char *buf; size_t len, cap;
    } *a = ud;
    size_t n = sz * nm;
    if (a->len + n + 1 > a->cap) {
        a->cap = (a->len + n + 1) * 2;
        a->buf = realloc(a->buf, a->cap);
    }
    memcpy(a->buf + a->len, ptr, n);
    a->len += n;
    a->buf[a->len] = 0;
    return n;
}

#endif /* FW_MINI_HTTP */
