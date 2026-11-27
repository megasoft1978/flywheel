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
#include <ctype.h>
#include <strings.h>
#include <fcntl.h>
#include <netdb.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef FW_MAX_GET
#define FW_MAX_GET ((size_t)16 << 20)   /* fw_mini_get body, as in http.c */
#endif
#define MAX_LINE 8192                   /* header or chunk-size line */
#define MAX_HEADERS 256

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
    int n = snprintf(path, pcap, "%s", slash ? slash : "/");
    return n >= 0 && (size_t)n < pcap ? 0 : -1;   /* never request a cut path */
}

/* whole-request deadline (CLOCK_MONOTONIC), set by mini_request */
static double deadline;

static double now_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

/* select on fd for at most idle_s, never past the deadline; as select() */
static int wait_fd(int fd, bool for_write, double idle_s) {
    double left = deadline - now_s();
    if (left <= 0) return 0;
    if (left > idle_s) left = idle_s;
    fd_set f;
    FD_ZERO(&f);
    FD_SET(fd, &f);
    struct timeval tv = {.tv_sec = (time_t)left, .tv_usec = (suseconds_t)((left - (time_t)left) * 1e6)};
    return select(fd + 1, for_write ? NULL : &f, for_write ? &f : NULL, NULL, &tv);
}

static int connect_within(int fd, const struct sockaddr *sa, socklen_t len, int timeout_s) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK)) return -1;
    if (connect(fd, sa, len)) {
        int err = 0;
        socklen_t el = sizeof err;
        if (errno != EINPROGRESS || wait_fd(fd, true, timeout_s) <= 0 ||
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) || err) return -1;
    }
    return fcntl(fd, F_SETFL, fl) ? -1 : 0;
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
        if (connect_within(fd, ai->ai_addr, ai->ai_addrlen, timeout_s) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

typedef struct {
    char *buf;
    size_t len, cap;
} MBuf;

/* append n bytes, kept NUL-terminated; -1 (buffer untouched) when out of memory */
static int mb_cat(MBuf *b, const char *d, size_t n) {
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        while (cap < b->len + n + 1) cap *= 2;
        char *nb = realloc(b->buf, cap);
        if (!nb) return -1;
        b->buf = nb;
        b->cap = cap;
    }
    memcpy(b->buf + b->len, d, n);
    b->len += n;
    b->buf[b->len] = 0;
    return 0;
}

/* read one byte with select-timeout; returns 1 byte-read, 0 eof, -1 error/abort, -2 timeout-idle */
static int read_byte(int fd, char *out, int idle_s) {
    if (fw_tick_hook) fw_tick_hook();
    if (g_abort) return -1;
    int sr = wait_fd(fd, false, idle_s);
    if (sr < 0) return -1;
    if (sr == 0) return -2;
    ssize_t n = read(fd, out, 1);
    if (n == 1) return 1;
    if (n == 0) return 0;
    return -1;
}

/* read a header/line up to and including \n; -3: too long or out of memory */
static int read_line(int fd, MBuf *line, int idle_s) {
    line->len = 0;
    if (line->buf) line->buf[0] = 0;
    for (;;) {
        char c;
        int r = read_byte(fd, &c, idle_s);
        if (r != 1) return r;
        if (mb_cat(line, &c, 1)) return -3;
        if (c == '\n') return 1;
        if (line->len > MAX_LINE) return -3; /* pathological header */
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
   Returns 0 when the whole body arrived (regardless of status code), -1 on
   transport error, truncated/malformed framing or abort.
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
    deadline = now_s() + timeout_s;
    int fd = tcp_connect(host, port, timeout_s);
    if (fd < 0) {
        snprintf(errbuf, errcap, "connect failed");
        return -1;
    }

    MBuf req = {0};
    char head[2048];
    char hostport[300];
    if (port != 80) snprintf(hostport, sizeof hostport, "%s:%d", host, port);
    else snprintf(hostport, sizeof hostport, "%s", host);
    int hl = snprintf(head, sizeof head, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, path, hostport);
    /* POSTs always carry JSON; streaming adds the SSE accept header */
    const char *extra;
    if (payload)
        extra = streaming
            ? "Content-Type: application/json\r\nAccept: text/event-stream\r\n"
            : "Content-Type: application/json\r\nAccept: application/json\r\n";
    else
        extra = "Accept: application/json\r\n";
    char cl[64] = "";
    if (payload) snprintf(cl, sizeof cl, "Content-Length: %zu\r\n", strlen(payload));
    const char *conn = "Connection: close\r\n\r\n";
    if (mb_cat(&req, head, (size_t)hl) || mb_cat(&req, extra, strlen(extra)) ||
        mb_cat(&req, cl, strlen(cl)) || mb_cat(&req, conn, strlen(conn))) {
        close(fd);
        free(req.buf);
        snprintf(errbuf, errcap, "out of memory");
        return -1;
    }

    size_t bodylen = payload ? strlen(payload) : 0;
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
    /* idle ceiling per read: streaming SSE stays warm with token deltas, but a
       non-streaming or pre-first-byte wait must tolerate long server-side generation
       (a 12k-token response at 200tok/s is 60s before the first byte). */
    int idle = timeout_s < 240 ? timeout_s : 240;
    int rc = 0;
    int header_lines = 0;
    for (;;) {
        int r = read_line(fd, &line, idle);
        if (r == -3) { rc = -1; snprintf(errbuf, errcap, "response header line too long"); goto done; }
        if (r != 1) { rc = -1; snprintf(errbuf, errcap, "header read failed"); goto done; }
        if (header_lines > MAX_HEADERS) { rc = -1; snprintf(errbuf, errcap, "too many response headers"); goto done; }
        if (header_lines == 0) {
            unsigned u = 0;
            if (sscanf(line.buf, "HTTP/%*s %u", &u) == 1) status = (int)u;
        } else if (!strncasecmp(line.buf, "Transfer-Encoding:", 18) && strstr(line.buf, "chunked")) {
            chunked = 1;
        } else if (!strncasecmp(line.buf, "Content-Length:", 15)) {
            char *end = line.buf + 15;
            errno = 0;
            content_length = strtol(line.buf + 15, &end, 10);
            if (errno || end == line.buf + 15 || content_length < 0 || end[strspn(end, " \t\r\n")]) {
                rc = -1; snprintf(errbuf, errcap, "bad Content-Length"); goto done;
            }
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
            char *end = line.buf;
            errno = 0;
            long csize = isxdigit((unsigned char)line.buf[0]) ? strtol(line.buf, &end, 16) : -1;
            if (csize < 0 || errno || !*end || !strchr("\r\n; \t", *end)) {
                ret = -1; snprintf(errbuf, errcap, "bad chunk size"); break;
            }
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
                if (fw_tick_hook) fw_tick_hook();
                if (g_abort) { ret = -1; snprintf(errbuf, errcap, "aborted"); goto done; }
                if (wait_fd(fd, false, idle) <= 0) { ret = -1; snprintf(errbuf, errcap, "read timeout"); goto done; }
                ssize_t n = read(fd, buf, (size_t)want);
                if (n <= 0) { ret = -1; snprintf(errbuf, errcap, "connection closed mid-chunk"); goto done; }
                if (feed(cb, ud, buf, (size_t)n) < 0) { ret = -1; snprintf(errbuf, errcap, "aborted"); goto done; }
                left -= n;
            }
            /* trailing CRLF after chunk data */
            char t[2];
            for (int i = 0; i < 2; i++) {
                int rr = read_byte(fd, &t[i], idle);
                if (rr != 1) { ret = -1; snprintf(errbuf, errcap, "chunk truncated"); goto done; }
            }
            if (t[0] != '\r' || t[1] != '\n') { ret = -1; snprintf(errbuf, errcap, "bad chunk framing"); break; }
        }
    } else if (content_length >= 0) {
        long left = content_length;
        while (left > 0) {
            char buf[8192];
            int want = left > (long)sizeof buf ? (int)sizeof buf : (int)left;
            if (fw_tick_hook) fw_tick_hook();
            if (g_abort) { ret = -1; snprintf(errbuf, errcap, "aborted"); goto done; }
            if (wait_fd(fd, false, idle) <= 0) { ret = -1; snprintf(errbuf, errcap, "read timeout"); goto done; }
            ssize_t n = read(fd, buf, (size_t)want);
            if (n <= 0) { ret = -1; snprintf(errbuf, errcap, "connection closed: short body"); goto done; }
            if (feed(cb, ud, buf, (size_t)n) < 0) { ret = -1; snprintf(errbuf, errcap, "aborted"); goto done; }
            left -= n;
        }
    } else {
        /* read until close */
        for (;;) {
            char buf[8192];
            if (fw_tick_hook) fw_tick_hook();
            if (g_abort) { ret = -1; snprintf(errbuf, errcap, "aborted"); goto done; }
            int sr = wait_fd(fd, false, idle);
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
                        int timeout_s, int *status, char *errbuf, size_t errcap) {
    return mini_request("POST", url, payload, streaming, cb, ud, timeout_s, status, errbuf, errcap);
}

typedef struct {
    MBuf body;
    const char *fatal;
} GetAcc;

static size_t get_cb(char *ptr, size_t sz, size_t nm, void *ud) {
    GetAcc *a = ud;
    size_t n = sz * nm;
    if (n > FW_MAX_GET - a->body.len) a->fatal = "response too large";
    else if (mb_cat(&a->body, ptr, n)) a->fatal = "out of memory";
    return a->fatal ? 0 : n;
}

char *fw_mini_get(const char *url) {
    GetAcc a = {{0}, NULL};
    char err[128] = "";
    int status = 0;
    int rc = mini_request("GET", url, NULL, 0, get_cb, &a, 8, &status, err, sizeof err);
    if (a.fatal) fprintf(stderr, "http get: %s (limit %zu bytes)\n", a.fatal, (size_t)FW_MAX_GET);
    if (rc != 0 || a.fatal || status < 200 || status >= 300) { free(a.body.buf); return NULL; }
    return a.body.buf ? a.body.buf : str_dup("");
}

#endif /* FW_MINI_HTTP */
