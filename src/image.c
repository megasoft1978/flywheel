/* image.c — load, check, downscale and encode image attachments; read the
   clipboard and show a held image with the system's own programs */
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#include "image.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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

/* a new private file holding d */
static bool write_new(const char *path, const unsigned char *d, size_t n) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, d + off, n - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) break;
        off += (size_t)w;
    }
    return !close(fd) && off == n;
}

/* a fresh 0700 directory under TMPDIR (if absolute) or /tmp */
static bool temp_dir(char *dir, size_t cap, const char *kind) {
    const char *tmp = getenv("TMPDIR");
    snprintf(dir, cap, "%s/fw-%s-XXXXXX", tmp && *tmp == '/' ? tmp : "/tmp", kind);
    return mkdtemp(dir) != NULL;
}

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
    char dir[1024], in[1100], out[1100], max[16];
    if (!temp_dir(dir, sizeof dir, "img")) return fail(err, errcap, "cannot create a temporary directory");
    snprintf(in, sizeof in, "%s/in.%s", dir, ext);
    snprintf(out, sizeof out, "%s/out.%s", dir, jpeg ? "jpg" : "png");
    snprintf(max, sizeof max, "%d", IMG_MAX_DIM);
    bool ok = write_new(in, *d, *n);
    char *argv[] = {"/usr/bin/sips", "-s", "format", jpeg ? "jpeg" : "png",
                    "-Z", max, in, "--out", out, NULL};
    if (!ok) fail(err, errcap, "could not write the temporary copy to downscale");
    else if (!run_quiet(argv))
        ok = fail(err, errcap, g_abort ? "cancelled" : "could not downscale the image (sips failed)");
    else {
        size_t sn;
        char why[128];
        unsigned char *s = load(out, &sn, why, sizeof why);
        if ((ok = s != NULL)) { free(*d); *d = s; *n = sn; }
        else if (err && errcap)
            snprintf(err, errcap, "could not downscale the image (sips output: %s)", why);
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

/* ---------- clipboard ---------- */

#define CLIPBOARD_TIMEOUT_S 10

#ifdef FW_IMAGE_TEST
int image_test_clip_s;
#endif

typedef enum { RUN_OK, RUN_FAIL, RUN_TIMEOUT, RUN_TOO_BIG } RunResult;

static bool oversized(const char *path) {
    struct stat st;
    return !stat(path, &st) && st.st_size > IMG_FILE_MAX;
}

/* One clipboard program, no shell, run in dir, killed on timeout, abort or once
   file passes IMG_FILE_MAX. With to_stdout its output goes to the new file;
   else it is discarded (osascript writes file itself). */
static RunResult run_clip(const char *prog, char *const argv[], const char *dir,
                          const char *file, bool to_stdout) {
    int limit = CLIPBOARD_TIMEOUT_S;
#ifdef FW_IMAGE_TEST
    if (image_test_clip_s) limit = image_test_clip_s;
#endif
    pid_t pid = fork();
    if (pid < 0) return RUN_FAIL;
    if (pid == 0) {
        setpgid(0, 0);           /* its helpers die with it */
        int nul = open("/dev/null", O_RDWR);
        if (nul >= 0) { dup2(nul, 0); dup2(nul, 1); dup2(nul, 2); }
        if (to_stdout) {
            int fd = open(file, O_WRONLY | O_CREAT | O_EXCL, 0600);
            if (fd < 0 || dup2(fd, 1) < 0) _exit(126);
        } else {
            unsetenv("LC_ALL");
            setenv("LC_CTYPE", "UTF-8", 1);
        }
        if (chdir(dir)) _exit(127);
        for (int k = 3; k < 256; k++) close(k);
        execv(prog, argv);
        _exit(127);
    }
    struct timespec t0, t, nap = {0, 20000000};
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int st = 0;
    pid_t r;
    bool late = false;
    while ((r = waitpid(pid, &st, WNOHANG)) == 0 && !g_abort && !oversized(file)) {
        clock_gettime(CLOCK_MONOTONIC, &t);
        if ((late = t.tv_sec - t0.tv_sec >= limit)) break;
        if (fw_tick_hook) fw_tick_hook();
        nanosleep(&nap, NULL);
    }
    if (r == 0) { kill(-pid, SIGKILL); kill(pid, SIGKILL); waitpid(pid, &st, 0); }
    if (oversized(file)) return RUN_TOO_BIG;   /* also if it exited between polls */
    if (r == 0) return late ? RUN_TIMEOUT : RUN_FAIL;
    return r == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0 ? RUN_OK : RUN_FAIL;
}

ClipResult image_from_clipboard(bool mac, ImageFind find, ImagePart *out, char *err, size_t errcap) {
    *out = (ImagePart){0};
    static const struct { const char *name; bool mac; } TOOLS[] = {
        {"osascript", true}, {"wl-paste", false}, {"xclip", false}};
    char prog[3][PATH_MAX], dir[1024], file[1100];
    bool have[3] = {false}, any = false;
    for (int i = 0; i < 3; i++)
        if (TOOLS[i].mac == mac && find(TOOLS[i].name, prog[i])) have[i] = any = true;
    if (!any) {
        fail(err, errcap, mac ? "osascript was not found"
                              : "reading the clipboard needs wl-paste (wl-clipboard) or xclip");
        return CLIP_NO_TOOL;
    }
    if (!temp_dir(dir, sizeof dir, "clip")) {
        fail(err, errcap, "cannot create a temporary directory");
        return CLIP_ERR;
    }
    snprintf(file, sizeof file, "%s/clipboard.png", dir);
    ClipResult res = CLIP_NONE;
    for (int i = 0; i < 3 && res == CLIP_NONE && !g_abort; i++) {
        if (!have[i]) continue;
        char *const script[] = {
            "osascript", "-e", "on run argv",
            "-e", "set d to (the clipboard as «class PNGf»)",
            "-e", "set f to open for access (POSIX file (item 1 of argv)) with write permission",
            "-e", "write d to f", "-e", "close access f", "-e", "end run",
            file, NULL};
        char *const wl[] = {"wl-paste", "--no-newline", "--type", "image/png", NULL};
        char *const x[] = {"xclip", "-selection", "clipboard", "-t", "image/png", "-o", NULL};
        RunResult ran = run_clip(prog[i], i == 0 ? script : i == 1 ? wl : x, dir, file, !mac);
        if (ran == RUN_TOO_BIG || ran == RUN_TIMEOUT) {
            fail(err, errcap, ran == RUN_TOO_BIG ? "image is larger than 10 MB"
                                                 : "clipboard program timed out");
            res = CLIP_ERR;
        } else if (ran == RUN_OK && !g_abort) {
            size_t n;
            unsigned char *d = load(file, &n, err, errcap);
            if (!d) res = CLIP_ERR;
            else if (!mac && !image_mime(d, n)) free(d);   /* text, say */
            else res = make_part(d, n, "clipboard", out, err, errcap) ? CLIP_OK : CLIP_ERR;
        }
        unlink(file);
    }
    rmdir(dir);
    if (g_abort) {
        image_part_free(out);
        fail(err, errcap, "cancelled");
        return CLIP_ERR;
    }
    if (res == CLIP_NONE) fail(err, errcap, "no image on the clipboard");
    return res;
}

/* ---------- preview ---------- */

#define PREVIEW_KEEP 8

/* the copies still on disk; live is set only once both names are complete */
static struct { char dir[1024], file[1100]; volatile sig_atomic_t live; } previews[PREVIEW_KEEP];
static int preview_next;
static pid_t preview_owner;

static void preview_drop(int i) {
    if (!previews[i].live) return;
    unlink(previews[i].file);
    rmdir(previews[i].dir);
    previews[i].live = 0;
}

void image_preview_cleanup(void) {
    if (getpid() != preview_owner) return;
    for (int i = 0; i < PREVIEW_KEEP; i++) preview_drop(i);
}

/* the bytes of a data: URI made by data_uri; malloc'd, NULL if it is not one */
static unsigned char *data_bytes(const char *url, size_t *n) {
    const char *s = url ? strchr(url, ',') : NULL;
    if (!s) return NULL;
    unsigned char *d = malloc(strlen(++s) / 4 * 3 + 3);
    if (!d) return NULL;
    unsigned v = 0;
    int bits = 0;
    *n = 0;
    for (; *s && *s != '='; s++) {
        int c = *s >= 'A' && *s <= 'Z' ? *s - 'A' : *s >= 'a' && *s <= 'z' ? *s - 'a' + 26
              : *s >= '0' && *s <= '9' ? *s - '0' + 52 : *s == '+' ? 62 : *s == '/' ? 63 : -1;
        if (c < 0) { free(d); return NULL; }
        v = (v << 6 | (unsigned)c) & 0xFFFFFF;
        if ((bits += 6) >= 8) d[(*n)++] = (unsigned char)(v >> (bits -= 8));
    }
    return d;
}

/* argv directly, no shell, in its own session with no terminal. Not waited for:
   after a double fork the viewer is not our child, so it leaves no zombie. The
   pipe closes on exec and carries a byte if the viewer could not start. */
static bool launch(const char *prog, char *const argv[], const char *path, const char *cwd) {
    int fd[2];
    if (pipe(fd)) return false;
    fcntl(fd[0], F_SETFD, FD_CLOEXEC);
    fcntl(fd[1], F_SETFD, FD_CLOEXEC);
    pid_t pid = fork();
    if (pid < 0) { close(fd[0]); close(fd[1]); return false; }
    if (pid == 0) {
        setsid();
        pid_t viewer = fork();
        if (viewer > 0) _exit(0);
        if (!viewer) {
            int nul = open("/dev/null", O_RDWR);
            if (nul >= 0 && dup2(nul, 0) >= 0 && dup2(nul, 1) >= 0 && dup2(nul, 2) >= 0 && !chdir(cwd)) {
                if (path) setenv("PATH", path, 1);
                for (int k = 3; k < 256; k++)
                    if (k != fd[1]) close(k);
                execv(prog, argv);
            }
        }
        ssize_t w = write(fd[1], "x", 1);
        _exit(w == 1 ? 127 : 126);
    }
    close(fd[1]);
    char c;
    ssize_t r;
    while ((r = read(fd[0], &c, 1)) < 0 && errno == EINTR) {}
    close(fd[0]);
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
    return r == 0;
}

bool image_preview(const ImagePart *p, const char *prog, const char *opt, const char *path,
                   char *err, size_t errcap) {
    size_t n;
    unsigned char *d = data_bytes(p->url, &n);
    const char *mime = d ? image_mime(d, n) : NULL;
    if (!mime) { free(d); return fail(err, errcap, "the image cannot be decoded"); }
    if (!preview_owner) atexit(image_preview_cleanup);
    preview_owner = getpid();
    int i = preview_next++ % PREVIEW_KEEP;
    preview_drop(i);
    if (!temp_dir(previews[i].dir, sizeof previews[i].dir, "view")) {
        free(d);
        return fail(err, errcap, "cannot create a temporary directory");
    }
    /* the name comes from the detected type only */
    snprintf(previews[i].file, sizeof previews[i].file, "%s/image.%s", previews[i].dir,
             !strcmp(mime, "image/jpeg") ? "jpg" : mime + strlen("image/"));
    previews[i].live = 1;
    bool ok = write_new(previews[i].file, d, n);
    free(d);
    char *argv[4] = {(char *)prog};
    int a = 1;
    if (opt) argv[a++] = (char *)opt;
    argv[a] = previews[i].file;
    if (ok && launch(prog, argv, path, previews[i].dir)) return true;
    preview_drop(i);
    return fail(err, errcap, ok ? "cannot start the viewer" : "could not write the temporary copy");
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

/* ---------- references in a message ---------- */

static bool image_ext(const char *s, size_t n) {
    static const char *const EXT[] = {".png", ".jpg", ".jpeg", ".gif", ".webp"};
    for (size_t i = 0; i < sizeof EXT / sizeof *EXT; i++) {
        size_t l = strlen(EXT[i]);
        if (n > l && !strncasecmp(s + n - l, EXT[i], l)) return true;
    }
    return false;
}

static bool path_like(const char *s) {
    return *s == '/' || !strncmp(s, "~/", 2) || !strncmp(s, "./", 2) ||
           !strncmp(s, "../", 3) || !strncasecmp(s, "file://", 7);
}

/* end of the shell word starting at s. Quotes count only in a word that starts
   with one, so an apostrophe in prose does not swallow what follows. */
static const char *word_end(const char *s) {
    bool quoted = *s == '"' || *s == '\'';
    const char *p = s;
    char q = 0;
    for (; *p; p++) {
        if (q) {
            if (q == '"' && *p == '\\' && p[1]) p++;
            else if (*p == q) q = 0;
        } else if (is_blank(*p)) break;
        else if (*p == '\\' && p[1]) p++;
        else if (quoted && (*p == '"' || *p == '\'')) q = *p;
    }
    if (q) for (p = s; *p && !is_blank(*p); p++) {}
    return p;
}

static bool regular(const char *path) {
    struct stat st;
    return path && !stat(path, &st) && S_ISREG(st.st_mode);
}

/* the reference one parsed word names, trailing punctuation dropped; NULL if
   none. Consumes p. */
static char *as_ref(const char *cwd, char *p, bool url) {
    if (!p) return NULL;
    for (size_t n = strlen(p); n; p[--n] = 0) {
        bool punct = strchr(".,;:!?)]}>", p[n - 1]) != NULL;
        if (url) {
            const char *host = strstr(p, "//");
            const char *path = host ? strchr(host + 2, '/') : NULL;
            if (!punct && path && image_ext(path, strcspn(path, "?#"))) return p;
        } else if (image_ext(p, n)) {
            char *full = under(cwd, str_dup(p));
            if (regular(full)) { free(p); return full; }
            free(full);
        }
        if (!punct) break;
    }
    free(p);
    return NULL;
}

/* blank out code spans and fences: what they quote is only mentioned. A run of
   backticks is closed by the next run of the same length (a fence of three or
   more also by a longer one). A fence opened at the start of a line and never
   closed runs to the end; any other unclosed or escaped run is plain text. True
   if anything was blanked. */
static bool blank_code(char *s) {
    const char *text = s;
    bool any = false;
    while (*s) {
        if (*s == '\\' && s[1]) { s += 2; continue; }
        if (*s != '`') { s++; continue; }
        size_t n = strspn(s, "`"), m = 0;
        char *p = s + n;
        for (; (p = strchr(p, '`')); p += m) {
            m = strspn(p, "`");
            if (m == n || (n >= 3 && m > n)) break;
        }
        if (!p) {
            const char *b = s;
            while (b > text && (b[-1] == ' ' || b[-1] == '\t')) b--;
            if (n < 3 || (b > text && b[-1] != '\n')) { s += n; continue; }
            memset(s, ' ', strlen(s));
            return true;
        }
        memset(s, ' ', (size_t)(p + m - s));
        s = p + m;
        any = true;
    }
    return any;
}

int image_find_refs(const char *cwd, const char *msg, char **refs, int max, bool *only) {
    *only = false;
    if (max <= 0) return 0;
    /* the whole message as one unescaped path, spaces and all */
    char *t = trimmed(msg);
    if (path_like(t) && image_ext(t, strlen(t))) {
        char *full = under(cwd, expand_path(str_dup(t)));
        if (regular(full)) {
            free(t);
            refs[0] = full;
            *only = true;
            return 1;
        }
        free(full);
    }
    free(t);

    char *text = str_dup(msg);
    if (!text) return 0;
    int n = 0;
    bool other = blank_code(text);
    for (const char *s = text; *s;) {
        if (is_blank(*s)) { s++; continue; }
        const char *e = word_end(s);
        char *word = str_ndup(s, (size_t)(e - s));
        const char *head = word + (*word == '"' || *word == '\'');
        char *ref = NULL;
        if (!strncasecmp(head, "http://", 7) || !strncasecmp(head, "https://", 8))
            ref = as_ref(cwd, image_path_parse(word), true);
        else if (path_like(head))
            ref = as_ref(cwd, image_path_parse(word), false);
        free(word);
        s = e;
        if (!ref) { other = true; continue; }
        int i = 0;
        while (i < n && strcmp(refs[i], ref)) i++;
        if (i < n || n == max) free(ref);
        else refs[n++] = ref;
    }
    free(text);
    *only = n && !other;
    return n;
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
        {0xA83F8110, 32},   /* 168.63.129.16, Azure's host service address */
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

/* one terminal-safe line for a message about user input */
static void one_line(char *dst, size_t cap, const char *s) {
    char *c = clean_text(s, false, false);
    for (char *p = c; *p; p++) if (*p == '\n' || *p == '\t') *p = ' ';
    snprintf(dst, cap, "%s", c);
    free(c);
}

/* Load every reference into set, all or none: on failure set is unchanged and
   why says which reference and what was wrong. conv (may be NULL) is the
   conversation the limits count against. Shared by the TUI and one-shot mode. */
bool image_attach_refs(const char *cwd, char **refs, int n, Images *set, const Msgs *conv,
                       char *why, size_t cap) {
    Images got = images_copy(set);
    bool ok = true;
    for (int i = 0; ok && i < n; i++) {
        ImagePart p = {0};
        char err[256] = "";
        bool url = !strncasecmp(refs[i], "http://", 7) || !strncasecmp(refs[i], "https://", 8);
        ok = url ? image_from_url(refs[i], &p, err, sizeof err)
                 : image_from_file(cwd, refs[i], &p, err, sizeof err);
        if (fw_tick_hook) fw_tick_hook();       /* a quick load never ticked */
        const char *no = ok && !g_abort ? images_add(&got, &p, conv) : NULL;
        if (g_abort) snprintf(err, sizeof err, "cancelled");
        else if (no) snprintf(err, sizeof err, "%s", no);
        if (g_abort || no) {
            if (ok) image_part_free(&p);
            ok = false;
        }
        if (!ok) {
            char name[300], e[256];
            one_line(name, sizeof name, refs[i]);
            one_line(e, sizeof e, err);
            snprintf(why, cap, "%s: %s", name, e);
        }
    }
    if (ok) {
        images_free(set);
        *set = got;
    } else images_free(&got);
    return ok;
}

/* a refusal for the size of the conversation, which no image caused alone */
static bool context_overflow(const char *err) {
    /* also covers "maximum context length" and "exceed_context_size" */
    for (; *err; err++)
        if (!strncasecmp(err, "context", 7)) return true;
    return false;
}

/* The server refused a request that carried images (400, 413, 415, 422). The
   newest message with images it has not accepted before is the likeliest cause:
   its images go, its text stays, so later requests stop failing. A refusal again
   drops the next one. note gets what was dropped for the user. False if nothing
   was dropped. */
bool image_drop_rejected(Msgs *msgs, const char *err, char *note, size_t cap) {
    int code = 0;
    if (!err || strncmp(err, "status ", 7) || sscanf(err + 7, "%d", &code) != 1) return false;
    if (code != 400 && code != 413 && code != 415 && code != 422) return false;
    if (context_overflow(err)) return false;
    for (int i = msgs->n - 1; i >= 0; i--) {
        Images *imgs = &msgs->v[i].images;
        if (!imgs->n || msgs->v[i].images_seen) continue;
        const char *src = imgs->v[0].source ? imgs->v[0].source : "image";
        bool url = !strncasecmp(src, "http://", 7) || !strncasecmp(src, "https://", 8);
        const char *base = url ? NULL : strrchr(src, '/');
        char name[200];
        one_line(name, sizeof name, base ? base + 1 : src);
        snprintf(note, cap, "server refused the image %s (status %d): dropped %d from the message; "
                 "the text stays", name, code, imgs->n);
        images_free(imgs);
        return true;
    }
    return false;
}
