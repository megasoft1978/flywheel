/* image.c — load, check, downscale and encode image attachments */
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#include "image.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <spawn.h>
#include <stdint.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#ifndef FW_MINI_HTTP
#include <curl/curl.h>
#endif

static bool fail(char *err, size_t cap, const char *why) {
    if (err && cap) snprintf(err, cap, "%s", why);
    return false;
}

/* ---------- format ---------- */

const char *image_mime(const unsigned char *d, size_t n) {
    if (n >= 8 && !memcmp(d, "\x89PNG\r\n\x1a\n", 8)) return "image/png";
    if (n >= 3 && !memcmp(d, "\xFF\xD8\xFF", 3)) return "image/jpeg";
    if (n >= 6 && (!memcmp(d, "GIF87a", 6) || !memcmp(d, "GIF89a", 6))) return "image/gif";
    if (n >= 12 && !memcmp(d, "RIFF", 4) && !memcmp(d + 8, "WEBP", 4)) return "image/webp";
    return NULL;
}

static long be16(const unsigned char *p) { return p[0] << 8 | p[1]; }
static long le16(const unsigned char *p) { return p[1] << 8 | p[0]; }
static long le24(const unsigned char *p) { return (long)p[2] << 16 | le16(p); }
static long be32(const unsigned char *p) { return (long)((uint32_t)be16(p) << 16 | (uint32_t)be16(p + 2)); }

bool image_dims(const unsigned char *d, size_t n, long *w, long *h) {
    const char *m = image_mime(d, n);
    *w = *h = 0;
    if (!m) return false;
    if (!strcmp(m, "image/png")) {
        if (n >= 24 && !memcmp(d + 12, "IHDR", 4)) { *w = be32(d + 16); *h = be32(d + 20); }
    } else if (!strcmp(m, "image/gif")) {
        if (n >= 10) { *w = le16(d + 6); *h = le16(d + 8); }
    } else if (!strcmp(m, "image/webp")) {
        if (n >= 30 && !memcmp(d + 12, "VP8X", 4)) {
            *w = le24(d + 24) + 1; *h = le24(d + 27) + 1;
        } else if (n >= 30 && !memcmp(d + 12, "VP8 ", 4)) {
            *w = le16(d + 26) & 0x3FFF; *h = le16(d + 28) & 0x3FFF;
        } else if (n >= 25 && !memcmp(d + 12, "VP8L", 4)) {
            uint32_t b = (uint32_t)le16(d + 21) | (uint32_t)le16(d + 23) << 16;
            *w = (long)(b & 0x3FFF) + 1; *h = (long)(b >> 14 & 0x3FFF) + 1;
        }
    } else {
        /* JPEG: walk the segments to the first start-of-frame */
        for (size_t i = 2; i + 9 <= n && d[i] == 0xFF;) {
            unsigned c = d[i + 1];
            if (c == 0xFF) { i++; continue; }
            if (c == 0x01 || (c >= 0xD0 && c <= 0xD9)) { i += 2; continue; }
            if (c >= 0xC0 && c <= 0xCF && c != 0xC4 && c != 0xC8 && c != 0xCC) {
                *h = be16(d + i + 5); *w = be16(d + i + 7);
                break;
            }
            i += 2 + (size_t)be16(d + i + 2);
        }
    }
    return *w > 0 && *h > 0;
}

/* ---------- sha256 + base64 (no crypto dependency in the static build) ---------- */

static uint32_t ror(uint32_t x, int n) { return x >> n | x << (32 - n); }

static void sha256_block(uint32_t s[8], const unsigned char *p) {
    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64], v[8];
    for (int i = 0; i < 16; i++) w[i] = (uint32_t)be32(p + 4 * i);
    for (int i = 16; i < 64; i++)
        w[i] = w[i-16] + (ror(w[i-15], 7) ^ ror(w[i-15], 18) ^ w[i-15] >> 3)
             + w[i-7] + (ror(w[i-2], 17) ^ ror(w[i-2], 19) ^ w[i-2] >> 10);
    memcpy(v, s, sizeof v);
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = v[7] + (ror(v[4], 6) ^ ror(v[4], 11) ^ ror(v[4], 25))
                    + ((v[4] & v[5]) ^ (~v[4] & v[6])) + K[i] + w[i];
        uint32_t t2 = (ror(v[0], 2) ^ ror(v[0], 13) ^ ror(v[0], 22))
                    + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
        memmove(v + 1, v, 7 * sizeof *v);
        v[4] += t1;
        v[0] = t1 + t2;
    }
    for (int i = 0; i < 8; i++) s[i] += v[i];
}

static void sha256_hex(const unsigned char *d, size_t n, char out[65]) {
    uint32_t s[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t i = 0;
    for (; i + 64 <= n; i += 64) sha256_block(s, d + i);
    unsigned char t[128] = {0};
    size_t rest = n - i, len = rest < 56 ? 64 : 128;
    memcpy(t, d + i, rest);
    t[rest] = 0x80;
    uint64_t bits = (uint64_t)n * 8;
    for (int k = 0; k < 8; k++) t[len - 1 - k] = (unsigned char)(bits >> (8 * k));
    for (size_t k = 0; k < len; k += 64) sha256_block(s, t + k);
    for (int k = 0; k < 8; k++) snprintf(out + 8 * k, 9, "%08x", (unsigned)s[k]);
}

static char *data_uri(const char *mime, const unsigned char *d, size_t n) {
    static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t head = strlen("data:;base64,") + strlen(mime);
    char *out = malloc(head + (n + 2) / 3 * 4 + 1);
    if (!out) return NULL;
    snprintf(out, head + 1, "data:%s;base64,", mime);
    char *w = out + head;
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = (unsigned)d[i] << 16;
        if (i + 1 < n) v |= (unsigned)d[i + 1] << 8;
        if (i + 2 < n) v |= d[i + 2];
        *w++ = A[v >> 18];
        *w++ = A[v >> 12 & 63];
        *w++ = i + 1 < n ? A[v >> 6 & 63] : '=';
        *w++ = i + 2 < n ? A[v & 63] : '=';
    }
    *w = 0;
    return out;
}

/* ---------- files ---------- */

/* whole regular file of at most IMG_FILE_MAX bytes; NULL with a reason */
static unsigned char *load(const char *path, size_t *len, char *err, size_t errcap) {
    /* O_NONBLOCK: a FIFO must not hang the UI before fstat rejects it */
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) { fail(err, errcap, strerror(errno)); return NULL; }
    struct stat st;
    unsigned char *b = NULL;
    size_t n = 0;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) fail(err, errcap, "not a regular file");
    else if (st.st_size > IMG_FILE_MAX) fail(err, errcap, "image is larger than 10 MB");
    else if (!(b = malloc(IMG_FILE_MAX + 1))) fail(err, errcap, "out of memory");
    else {
        ssize_t r = 0;
        while (n <= IMG_FILE_MAX && (r = read(fd, b + n, IMG_FILE_MAX + 1 - n)) != 0) {
            if (r < 0 && errno == EINTR) continue;
            if (r < 0) break;
            n += (size_t)r;
        }
        if (r < 0 || n > IMG_FILE_MAX) {   /* read error, or it grew */
            fail(err, errcap, r < 0 ? "read failed" : "image is larger than 10 MB");
            free(b);
            b = NULL;
        }
    }
    close(fd);
    *len = n;
    return b;
}

#ifdef __APPLE__
extern char **environ;

/* argv directly, no shell; killed after 30 s or on abort */
static bool run_quiet(char *const argv[]) {
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    for (int fd = 0; fd < 3; fd++)
        posix_spawn_file_actions_addopen(&fa, fd, "/dev/null", fd ? O_WRONLY : O_RDONLY, 0);
    pid_t pid;
    int rc = posix_spawn(&pid, argv[0], &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    if (rc) return false;
    for (int i = 0; i < 1500 && !g_abort; i++) {
        int st;
        pid_t w = waitpid(pid, &st, WNOHANG);
        if (w == pid) return WIFEXITED(st) && !WEXITSTATUS(st);
        if (w < 0 && errno != EINTR) return false;
        if (fw_tick_hook) fw_tick_hook();
        struct timespec ts = {0, 20000000};
        nanosleep(&ts, NULL);
    }
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    return false;
}

/* replace *d with a copy whose longer side is IMG_MAX_DIM; sips only ever sees
   our private copy. GIF and WebP come back as PNG. */
static bool downscale(unsigned char **d, size_t *n, const char *mime, char *err, size_t errcap) {
    bool jpeg = !strcmp(mime, "image/jpeg");
    const char *ext = jpeg ? "jpg" : mime + strlen("image/");
    const char *tmp = getenv("TMPDIR");
    char dir[1024], in[1100], out[1100], max[16];
    snprintf(dir, sizeof dir, "%s/fw-img-XXXXXX", tmp && *tmp == '/' ? tmp : "/tmp");
    if (!mkdtemp(dir)) return fail(err, errcap, "cannot create a temporary directory");
    snprintf(in, sizeof in, "%s/in.%s", dir, ext);
    snprintf(out, sizeof out, "%s/out.%s", dir, jpeg ? "jpg" : "png");
    snprintf(max, sizeof max, "%d", IMG_MAX_DIM);
    bool ok = false;
    int fd = open(in, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd >= 0) {
        size_t off = 0;
        while (off < *n) {
            ssize_t w = write(fd, *d + off, *n - off);
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) break;
            off += (size_t)w;
        }
        ok = !close(fd) && off == *n;
    }
    char *argv[] = {"/usr/bin/sips", "-s", "format", jpeg ? "jpeg" : "png",
                    "-Z", max, in, "--out", out, NULL};
    if (!ok || !run_quiet(argv)) ok = fail(err, errcap, "could not downscale the image (sips failed)");
    else {
        size_t sn;
        unsigned char *s = load(out, &sn, err, errcap);
        if ((ok = s != NULL)) { free(*d); *d = s; *n = sn; }
        else fail(err, errcap, "could not downscale the image (sips failed)");
    }
    unlink(in);
    unlink(out);
    rmdir(dir);
    return ok;
}
#endif

/* takes ownership of d */
static bool make_part(unsigned char *d, size_t n, const char *source, ImagePart *out,
                      char *err, size_t errcap) {
    const char *mime = image_mime(d, n);
    if (!mime) { free(d); return fail(err, errcap, "not a PNG, JPEG, GIF or WebP image"); }
#ifdef __APPLE__
    long w, h;
    /* sips -Z also enlarges, so only call it for oversized images */
    if (image_dims(d, n, &w, &h) && (w > IMG_MAX_DIM || h > IMG_MAX_DIM)) {
        if (!downscale(&d, &n, mime, err, errcap)) { free(d); return false; }
        mime = image_mime(d, n);
        if (!mime) { free(d); return fail(err, errcap, "downscaled image is invalid"); }
    }
#endif
    out->url = data_uri(mime, d, n);
    out->source = str_dup(source);
    if (out->source) utf8_sanitize(out->source);
    sha256_hex(d, n, out->sha256);
    out->size = n;
    free(d);
    if (!out->url || !out->source) {
        image_part_free(out);
        return fail(err, errcap, "out of memory");
    }
    return true;
}

/* ---------- dragged paths ---------- */

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    c |= 32;
    return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

static bool is_blank(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

static char *trimmed(const char *s) {
    while (is_blank(*s)) s++;
    size_t n = strlen(s);
    while (n && is_blank(s[n - 1])) {
        /* "name\ " ends in an escaped space, which is part of the name */
        size_t bs = 0;
        while (bs + 1 < n && s[n - 2 - bs] == '\\') bs++;
        if (bs % 2) break;
        n--;
    }
    return str_ndup(s, n);
}

/* one shell word with quotes and backslashes removed; NULL if there are more
   words or a quote is left open. Nothing is expanded. */
static char *unshell(const char *s) {
    char *out = malloc(strlen(s) + 1), *w = out;
    char q = 0;
    for (; *s; s++) {
        if (q == '\'') {
            if (*s == q) q = 0;
            else *w++ = *s;
        } else if (*s == '\\' && s[1] && (!q || strchr("\"\\$`", s[1]))) {
            *w++ = *++s;
        } else if (*s == '"' || (!q && *s == '\'')) {
            q = q ? 0 : *s;
        } else if (!q && is_blank(*s)) {
            goto bad;
        } else *w++ = *s;
    }
    if (q) goto bad;
    *w = 0;
    return out;
bad:
    free(out);
    return NULL;
}

/* path of a file: URL with %XX undone; NULL for another host or %00 */
static char *from_file_url(const char *s) {
    s += strlen("file://");
    if (!strncasecmp(s, "localhost/", 10)) s += 9;
    if (*s != '/') return NULL;
    char *out = malloc(strlen(s) + 1), *w = out;
    while (*s) {
        int hi, lo;
        if (*s == '%' && (hi = hexval(s[1])) >= 0 && (lo = hexval(s[2])) >= 0) {
            if (!(hi | lo)) { free(out); return NULL; }
            *w++ = (char)(hi << 4 | lo);
            s += 3;
        } else *w++ = *s++;
    }
    *w = 0;
    return out;
}

static char *expand_path(char *p) {   /* consumes p */
    if (!p) return NULL;
    char *r = p;
    const char *home = getenv("HOME");
    if (!strncasecmp(p, "file://", 7)) r = from_file_url(p);
    else if (!strncmp(p, "~/", 2) && home) {
        size_t n = strlen(home) + strlen(p);
        r = malloc(n);
        snprintf(r, n, "%s%s", home, p + 1);
    }
    if (r != p) free(p);
    if (r && !*r) { free(r); r = NULL; }
    return r;
}

char *image_path_parse(const char *s) {
    char *t = trimmed(s ? s : "");
    char *w = unshell(t);
    free(t);
    return expand_path(w);
}

static char *under(const char *cwd, char *p) {   /* consumes p */
    if (!p || *p == '/' || !cwd) return p;
    size_t n = strlen(cwd) + strlen(p) + 2;
    char *r = malloc(n);
    snprintf(r, n, "%s/%s", cwd, p);
    free(p);
    return r;
}

bool image_from_file(const char *cwd, const char *spec, ImagePart *out, char *err, size_t errcap) {
    *out = (ImagePart){0};
    /* a typed path with unescaped spaces or a literal backslash names the file
       as it stands; otherwise read it as a shell word */
    char *path = under(cwd, expand_path(trimmed(spec ? spec : "")));
    struct stat st;
    if (!path || stat(path, &st)) {
        free(path);
        path = under(cwd, image_path_parse(spec));
    }
    if (!path) return fail(err, errcap, "not a single file path");
    size_t n;
    unsigned char *d = load(path, &n, err, errcap);
    bool ok = d && make_part(d, n, path, out, err, errcap);
    free(path);
    return ok;
}

/* ---------- URLs ---------- */

#ifdef FW_IMAGE_TEST
int image_test_port;
#endif

static bool v4_blocked(uint32_t a) {
    static const struct { uint32_t net; int bits; } B[] = {
        {0x00000000, 8},  {0x0A000000, 8},  {0x64400000, 10}, {0x7F000000, 8},
        {0xA9FE0000, 16}, {0xAC100000, 12}, {0xC0000000, 24}, {0xC0000200, 24},
        {0xC0586300, 24}, {0xC0A80000, 16}, {0xC6120000, 15}, {0xC6336400, 24},
        {0xCB007100, 24}, {0xE0000000, 4},  {0xF0000000, 4},
    };
    for (size_t i = 0; i < sizeof B / sizeof *B; i++)
        if (!((a ^ B[i].net) >> (32 - B[i].bits))) return true;
    return false;
}

bool image_addr_blocked(const struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const void *)sa;
        return v4_blocked(ntohl(in->sin_addr.s_addr));
    }
    if (sa->sa_family == AF_INET6) {
        const unsigned char *a = ((const struct sockaddr_in6 *)(const void *)sa)->sin6_addr.s6_addr;
        /* allow only global unicast 2000::/3: this drops ::, ::1, IPv4-mapped
           and -compatible, NAT64, ULA, link-local and multicast */
        if ((a[0] & 0xE0) != 0x20) return true;
        if (a[0] == 0x20 && a[1] == 0x01 && a[2] < 2) return true;          /* 2001::/23 */
        if (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x0D && a[3] == 0xB8) return true;
        if (a[0] == 0x20 && a[1] == 0x02) return true;                      /* 6to4 */
        if (a[0] == 0x3F && a[1] == 0xFF && !(a[2] & 0xF0)) return true;    /* docs */
        return false;
    }
    return true;
}

#ifdef FW_MINI_HTTP
bool image_from_url(const char *url, ImagePart *out, char *err, size_t errcap) {
    (void)url;
    *out = (ImagePart){0};
    return fail(err, errcap, "image URLs are not supported in this build; download the file "
                             "and attach it by path");
}
#else
typedef struct {
    unsigned char *d;
    size_t n;
    bool too_big, blocked;
} Fetch;

static size_t on_bytes(char *p, size_t sz, size_t nm, void *ud) {
    Fetch *f = ud;
    size_t n = sz * nm;
    if (n > IMG_FILE_MAX - f->n) { f->too_big = true; return 0; }
    memcpy(f->d + f->n, p, n);
    f->n += n;
    return n;
}

/* called with the very address curl is about to connect to, so a name that
   resolves differently a second time (DNS rebinding) cannot get past it */
static curl_socket_t open_public(void *ud, curlsocktype purpose, struct curl_sockaddr *a) {
    (void)purpose;
    bool blocked = image_addr_blocked(&a->addr);
#ifdef FW_IMAGE_TEST
    if (image_test_port && a->family == AF_INET) {
        const struct sockaddr_in *in = (const void *)&a->addr;
        if (ntohl(in->sin_addr.s_addr) == INADDR_LOOPBACK && ntohs(in->sin_port) == image_test_port)
            blocked = false;
    }
#endif
    if (blocked) {
        ((Fetch *)ud)->blocked = true;
        return CURL_SOCKET_BAD;
    }
    curl_socket_t s = socket(a->family, a->socktype, a->protocol);
    if (s != CURL_SOCKET_BAD) fcntl(s, F_SETFD, FD_CLOEXEC);
    return s;
}

static int on_tick(void *ud, curl_off_t a, curl_off_t b, curl_off_t c, curl_off_t d) {
    (void)ud; (void)a; (void)b; (void)c; (void)d;
    if (!g_abort && fw_tick_hook) fw_tick_hook();
    return g_abort ? 1 : 0;
}

/* http(s) with a host and without credentials */
static bool url_ok(const char *url) {
    if (strncasecmp(url, "http://", 7) && strncasecmp(url, "https://", 8)) return false;
    CURLU *u = curl_url();
    char *user = NULL, *pass = NULL, *host = NULL;
    bool ok = u && !curl_url_set(u, CURLUPART_URL, url, 0)
              && !curl_url_get(u, CURLUPART_HOST, &host, 0);
    if (ok) {
        curl_url_get(u, CURLUPART_USER, &user, 0);
        curl_url_get(u, CURLUPART_PASSWORD, &pass, 0);
        ok = !user && !pass;
    }
    curl_free(user); curl_free(pass); curl_free(host);
    curl_url_cleanup(u);
    return ok;
}

bool image_from_url(const char *url, ImagePart *out, char *err, size_t errcap) {
    *out = (ImagePart){0};
    char *u = trimmed(url ? url : "");
    if (!url_ok(u)) {
        free(u);
        return fail(err, errcap, "only http:// and https:// URLs without credentials are allowed");
    }
    Fetch f = {.d = malloc(IMG_FILE_MAX)};
    CURL *h = curl_easy_init();
    if (!f.d || !h) {
        free(f.d); free(u);
        if (h) curl_easy_cleanup(h);
        return fail(err, errcap, "out of memory");
    }
    curl_easy_setopt(h, CURLOPT_URL, u);
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(h, CURLOPT_PROTOCOLS_STR, "http,https");
#else
    curl_easy_setopt(h, CURLOPT_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L);
    /* a proxy would resolve the name itself, past the address check */
    curl_easy_setopt(h, CURLOPT_PROXY, "");
    curl_easy_setopt(h, CURLOPT_OPENSOCKETFUNCTION, open_public);
    curl_easy_setopt(h, CURLOPT_OPENSOCKETDATA, &f);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, on_bytes);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &f);
    curl_easy_setopt(h, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)IMG_FILE_MAX);
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(h, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(h, CURLOPT_XFERINFOFUNCTION, on_tick);
    curl_easy_setopt(h, CURLOPT_NOPROGRESS, 0L);
    CURLcode rc = curl_easy_perform(h);
    long status = 0;
    curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(h);

    char why[160] = "";
    if (f.too_big || rc == CURLE_FILESIZE_EXCEEDED)
        snprintf(why, sizeof why, "image is larger than 10 MB");
    else if (rc != CURLE_OK && f.blocked)
        snprintf(why, sizeof why, "refusing to fetch from a local or private address");
    else if (rc != CURLE_OK)
        snprintf(why, sizeof why, "fetch failed: %s", curl_easy_strerror(rc));
    else if (status >= 300 && status < 400)
        snprintf(why, sizeof why, "the URL redirects (status %ld); use the final URL", status);
    else if (status != 200)
        snprintf(why, sizeof why, "fetch failed: status %ld", status);

    bool ok;
    if (*why) { free(f.d); ok = fail(err, errcap, why); }
    else ok = make_part(f.d, f.n, u, out, err, errcap);
    free(u);
    return ok;
}
#endif
