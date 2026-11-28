#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
/* image loading, URL guards and image message parts. Loopback only. */
#include "../src/image.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

Cfg g_cfg;
volatile sig_atomic_t g_abort;

static int passed, failed;
#define T(name, cond) do { if (cond) { passed++; } else { failed++; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, name); } } while (0)

static char dir[512];

static const unsigned char TINY[] = {   /* PNG signature + 1x1 IHDR */
    0x89,'P','N','G','\r','\n',0x1a,'\n', 0,0,0,13,'I','H','D','R', 0,0,0,1, 0,0,0,1, 8,0,0,0,0};

static void put(const char *name, const void *d, size_t n) {
    char p[800];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    FILE *f = fopen(p, "wb");
    if (!f || fwrite(d, 1, n, f) != n) { printf("cannot write %s\n", p); exit(1); }
    fclose(f);
}

static void drop(const char *name) {
    char p[800];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    unlink(p);
}

static void test_magic(void) {
    long w, h;
    T("png", image_mime(TINY, sizeof TINY) && !strcmp(image_mime(TINY, sizeof TINY), "image/png"));
    T("png dims", image_dims(TINY, sizeof TINY, &w, &h) && w == 1 && h == 1);
    const unsigned char jpg[] = {0xFF,0xD8, 0xFF,0xE0,0,4,0,0, 0xFF,0xC0,0,11,8, 1,0x2C, 7,0xD0, 1,1,0x11,0};
    T("jpeg", image_mime(jpg, sizeof jpg) && !strcmp(image_mime(jpg, sizeof jpg), "image/jpeg"));
    T("jpeg dims", image_dims(jpg, sizeof jpg, &w, &h) && w == 2000 && h == 300);
    const unsigned char gif[] = {'G','I','F','8','9','a', 0xD0,7, 5,0};
    T("gif", image_dims(gif, sizeof gif, &w, &h) && w == 2000 && h == 5);
    unsigned char webp[30] = "RIFF\0\0\0\0WEBPVP8X";
    webp[24] = 0xCF; webp[25] = 7; webp[27] = 9;
    T("webp", image_mime(webp, 30) && !strcmp(image_mime(webp, 30), "image/webp"));
    T("webp dims", image_dims(webp, 30, &w, &h) && w == 2000 && h == 10);
    T("text rejected", !image_mime((const unsigned char *)"<svg></svg>!", 12));
    T("short rejected", !image_mime(TINY, 4));
    T("truncated has no dims", !image_dims(TINY, 12, &w, &h));
    T("truncated jpeg", !image_dims(jpg, 9, &w, &h));
}

static void parses(const char *in, const char *want) {
    char *r = image_path_parse(in);
    T(in, want ? r && !strcmp(r, want) : !r);
    free(r);
}

static void test_paths(void) {
    parses("/a\\ b.png", "/a b.png");
    parses("/a\\ b.png \n", "/a b.png");
    parses("'x y.png'", "x y.png");
    parses("\"x \\\"q\\\".png\"", "x \"q\".png");
    parses("'it'\\''s.png'", "it's.png");
    parses("/p/\\(1\\).png", "/p/(1).png");
    parses("/end\\ ", "/end ");
    parses("file:///tmp/a%20b.png", "/tmp/a b.png");
    parses("'file://localhost/tmp/a.png'", "/tmp/a.png");
    parses("file://otherhost/a.png", NULL);
    parses("file:///a%00.png", NULL);
    parses("a.png b.png", NULL);
    parses("'open.png", NULL);
    parses("", NULL);
    parses("$HOME/`id`.png", "$HOME/`id`.png");
}

/* msg (with %s = dir) names exactly the references in want, in order */
static void finds(const char *name, const char *fmt, const char *want1, const char *want2, bool only_want) {
    char msg[2000], w[2][800], *refs[4];
    bool only;
    snprintf(msg, sizeof msg, fmt, dir, dir);
    const char *want[2] = {want1, want2};
    int expect = !!want1 + !!want2;
    int n = image_find_refs(dir, msg, refs, 4, &only);
    bool ok = n == expect && only == only_want;
    for (int i = 0; ok && i < n; i++) {
        snprintf(w[i], sizeof w[i], want[i], dir);
        ok = !strcmp(refs[i], w[i]);
    }
    T(name, ok);
    for (int i = 0; i < n; i++) free(refs[i]);
}

static void test_refs(void) {
    put("a b.png", TINY, sizeof TINY);
    put("c.JPG", TINY, sizeof TINY);
    put("it's.png", TINY, sizeof TINY);
    put("t.txt", TINY, sizeof TINY);
    finds("escaped path in prose", "look at %s/a\\ b.png please", "%s/a b.png", NULL, false);
    finds("dragged escaped path", "%s/a\\ b.png ", "%s/a b.png", NULL, true);
    finds("quoted path", "'%s/a b.png'", "%s/a b.png", NULL, true);
    finds("double-quoted path", "what is \"%s/a b.png\"?", "%s/a b.png", NULL, false);
    finds("quote inside a quoted word", "'%s/it'\\''s.png'", "%s/it's.png", NULL, true);
    finds("whole message with raw spaces", "%s/a b.png", "%s/a b.png", NULL, true);
    finds("two files", "%s/a\\ b.png %s/c.JPG", "%s/a b.png", "%s/c.JPG", true);
    finds("duplicates collapse", "%s/c.JPG %s/c.JPG", "%s/c.JPG", NULL, true);
    finds("file url", "file://%s/a%%20b.png", "%s/a b.png", NULL, true);
    finds("relative and punctuation", "compare ./c.JPG.", "%s/./c.JPG", NULL, false);
    finds("apostrophe in prose", "don't skip %s/c.JPG", "%s/c.JPG", NULL, false);
    finds("image url", "see https://example.invalid/p/a.PNG?x=1, thanks",
          "https://example.invalid/p/a.PNG?x=1", NULL, false);
    finds("quoted url", "'http://example.invalid/a.webp'", "http://example.invalid/a.webp", NULL, true);
    finds("url that is no image", "https://example.invalid/page https://example.png", NULL, NULL, false);
    finds("bare name is text", "rename c.JPG to d.png", NULL, NULL, false);
    finds("missing file is text", "write %s/new.png for me", NULL, NULL, false);
    finds("not an image name", "%s/t.txt", NULL, NULL, false);
    finds("directory is text", "%s/", NULL, NULL, false);
    finds("inline code span", "run `cat ./c.JPG | wc` now", NULL, NULL, false);
    finds("code fence", "```\nopen ./c.JPG\n```", NULL, NULL, false);
    finds("url in a code span", "try `curl https://example.invalid/a.png -o x`", NULL, NULL, false);
    finds("url in a fence", "```sh\ncurl https://example.invalid/a.png\n```\n", NULL, NULL, false);
    finds("double backticks hold single ones", "``a ` ./c.JPG ` b``", NULL, NULL, false);
    finds("longer run closes a fence", "```\n./c.JPG\n````", NULL, NULL, false);
    finds("span beside a path", "`ls -l` %s/c.JPG", "%s/c.JPG", NULL, false);
    finds("unmatched backtick", "a ` %s/c.JPG", "%s/c.JPG", NULL, false);
    finds("escaped backticks", "\\` %s/c.JPG \\`", "%s/c.JPG", NULL, false);
    finds("unclosed fence", "see\n```\nopen ./c.JPG\n", NULL, NULL, false);
    finds("unclosed indented fence", "  ```sh\ncurl https://example.invalid/a.png", NULL, NULL, false);
    finds("unclosed run inside a line", "a ``` %s/c.JPG", "%s/c.JPG", NULL, false);
    char *one[1];
    bool only;
    char msg[2000];
    snprintf(msg, sizeof msg, "%s/c.JPG %s/it\\'s.png", dir, dir);
    int n = image_find_refs(dir, msg, one, 1, &only);
    T("max respected", n == 1);
    if (n == 1) free(one[0]);
    drop("a b.png"); drop("c.JPG"); drop("it's.png"); drop("t.txt");
}

static void test_load(void) {
    ImagePart p;
    char err[256];
    put("a b.png", TINY, sizeof TINY);
    T("raw path with space", image_from_file(dir, "a b.png", &p, err, sizeof err));
    T("data uri", p.url && !strncmp(p.url, "data:image/png;base64,iVBORw0KGgo", 32));
    T("size", p.size == sizeof TINY);
    T("source resolved", p.source && strstr(p.source, "/a b.png"));
    image_part_free(&p);
    T("escaped path", image_from_file(dir, "a\\ b.png ", &p, err, sizeof err));
    image_part_free(&p);

    /* known answers (shasum -a 256, base64) */
    put("k.gif", "GIF89a\1\0\1\0", 10);
    T("gif load", image_from_file(dir, "k.gif", &p, err, sizeof err));
    T("base64 padding", p.url && !strcmp(p.url, "data:image/gif;base64,R0lGODlhAQABAA=="));
    T("sha256", !strcmp(p.sha256, "fb6567d497606314a968515ebf9063dcee9fcff777897c384ed8e6a26dbd7190"));
    image_part_free(&p);
    /* 100 bytes: the padding spills into a second sha256 block */
    char long_gif[100] = "GIF89a";
    put("l.gif", long_gif, sizeof long_gif);
    T("sha256 multi-block", image_from_file(dir, "l.gif", &p, err, sizeof err)
                            && !strcmp(p.sha256, "81c7c25c7402523148f2870759ece8d1432707b370dacc530490b88f5e5a322c"));
    image_part_free(&p);

    put("n.png", "not an image", 12);
    T("magic enforced", !image_from_file(dir, "n.png", &p, err, sizeof err) && strstr(err, "PNG") && !p.url);
    T("missing", !image_from_file(dir, "none.png", &p, err, sizeof err));
    T("directory", !image_from_file(NULL, dir, &p, err, sizeof err) && strstr(err, "regular"));
    char fifo[800];
    snprintf(fifo, sizeof fifo, "%s/fifo", dir);
    T("mkfifo", !mkfifo(fifo, 0600));
    T("fifo does not hang", !image_from_file(dir, "fifo", &p, err, sizeof err));
    unsigned char *big = calloc(1, IMG_FILE_MAX + 1);
    memcpy(big, TINY, sizeof TINY);
    put("big.png", big, IMG_FILE_MAX + 1);
    T("over 10 MB", !image_from_file(dir, "big.png", &p, err, sizeof err) && strstr(err, "10 MB"));
    put("big.png", big, IMG_FILE_MAX);
    T("exactly 10 MB", image_from_file(dir, "big.png", &p, err, sizeof err) && p.size == IMG_FILE_MAX);
    image_part_free(&p);
    free(big);
    drop("a b.png"); drop("k.gif"); drop("l.gif"); drop("n.png"); drop("fifo"); drop("big.png");
}

#ifdef __APPLE__
static void be(unsigned char *p, uint32_t v) {
    p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

static size_t chunk(unsigned char *out, const char *type, const unsigned char *d, size_t n) {
    be(out, (uint32_t)n);
    memcpy(out + 4, type, 4);
    if (n) memcpy(out + 8, d, n);
    uint32_t c = ~0u;
    for (size_t i = 4; i < 8 + n; i++) {
        c ^= out[i];
        for (int k = 0; k < 8; k++) c = c >> 1 ^ (0xEDB88320u & -(c & 1));
    }
    be(out + 8 + n, ~c);
    return n + 12;
}

/* real grayscale PNG, all black, one stored deflate block (raw < 64 KB) */
static void write_png(const char *name, int w, int h) {
    static unsigned char png[70000], z[66000];
    size_t raw = (size_t)(w + 1) * h, n = 8;
    unsigned char ihdr[13] = {0};
    be(ihdr, w); be(ihdr + 4, h); ihdr[8] = 8;
    memset(z, 0, sizeof z);
    z[0] = 0x78; z[1] = 1; z[2] = 1;
    z[3] = raw & 255; z[4] = raw >> 8; z[5] = ~z[3]; z[6] = ~z[4];
    be(z + 7 + raw, (uint32_t)((raw % 65521) << 16 | 1));   /* adler32 of zeros */
    memcpy(png, TINY, 8);
    n += chunk(png + n, "IHDR", ihdr, 13);
    n += chunk(png + n, "IDAT", z, raw + 11);
    n += chunk(png + n, "IEND", NULL, 0);
    put(name, png, n);
}

/* leading bytes of a data URI, decoded */
static size_t head_of(const char *url, unsigned char *out, size_t cap) {
    const char *A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n = 0;
    unsigned acc = 0, bits = 0;
    for (const char *b = strchr(url, ',') + 1; *b && *b != '=' && n < cap; b++) {
        acc = (acc << 6 | (unsigned)(strchr(A, *b) - A)) & 0xFFFFFF;
        if ((bits += 6) >= 8) { bits -= 8; out[n++] = (unsigned char)(acc >> bits); }
    }
    return n;
}

static size_t solid_webp(unsigned char *b, int w, int h) {
    memset(b, 0, 40);
    memcpy(b, "RIFF\0\0\0\0WEBPVP8L", 16);
    b[20] = 0x2F;
    size_t bit = 21 * 8;
#define BITS(v, n) for (int k_ = 0; k_ < (n); k_++, bit++) b[bit / 8] |= (unsigned char)((((v) >> k_) & 1) << (bit % 8))
    BITS(w - 1, 14); BITS(h - 1, 14); BITS(0, 4);     /* size, no alpha, version 0 */
    BITS(0, 3);                                       /* no transform, cache or meta codes */
    for (int code = 0; code < 5; code++) {            /* green, red, blue, alpha, distance */
        BITS(1, 1); BITS(0, 1); BITS(1, 1);           /* simple, one symbol, 8 bits */
        BITS(code == 3 ? 255 : code == 4 ? 0 : 128, 8);
    }
#undef BITS
    size_t data = (bit + 7) / 8 - 20, n = 20 + data + (data & 1);
    b[16] = (unsigned char)data;
    b[4] = (unsigned char)(n - 8);
    return n;
}

static void test_downscale(void) {
    ImagePart p;
    char err[256], cmd[2000];
    long w, h;
    write_png("wide.png", 2000, 20);
    snprintf(cmd, sizeof cmd, "cd '%s' && sips -s format jpeg wide.png --out wide.jpg >/dev/null "
             "&& sips -s format gif wide.png --out wide.gif >/dev/null", dir);
    T("fixtures", system(cmd) == 0);
    const char *names[] = {"wide.png", "wide.jpg", "wide.gif"};
    const char *prefix[] = {"data:image/png;", "data:image/jpeg;", "data:image/png;"};
    for (int i = 0; i < 3; i++) {
        char path[800];
        snprintf(path, sizeof path, "%s/%s", dir, names[i]);
        struct stat before, after;
        T("fixture exists", !stat(path, &before));
        bool ok = image_from_file(dir, names[i], &p, err, sizeof err);
        T(names[i], ok && !strncmp(p.url, prefix[i], strlen(prefix[i])));
        T("original untouched", !stat(path, &after) && after.st_size == before.st_size);
        /* the dimensions of what would be sent */
        static unsigned char head[65536];   /* sips puts the JPEG frame after Exif/ICC */
        T("scaled to 1568", ok && image_dims(head, head_of(p.url, head, sizeof head), &w, &h)
                            && w == IMG_MAX_DIM && h < 20);
        image_part_free(&p);
    }
    write_png("small.png", 40, 30);
    T("small kept", image_from_file(dir, "small.png", &p, err, sizeof err));
    struct stat st;
    snprintf(cmd, sizeof cmd, "%s/small.png", dir);
    T("small not rewritten", !stat(cmd, &st) && p.size == (size_t)st.st_size);
    image_part_free(&p);
    put("broken.png", "\x89PNG\r\n\x1a\n\0\0\0\15IHDR\0\0\x10\0\0\0\x10\0", 24);
    T("sips failure reported", !image_from_file(dir, "broken.png", &p, err, sizeof err) && strstr(err, "sips"));
    g_abort = 1;
    T("abort is not reported as a sips failure",
      !image_from_file(dir, "wide.png", &p, err, sizeof err) && !strcmp(err, "cancelled"));
    g_abort = 0;
    /* lossless WebP of one colour: every pixel code is zero bits long */
    unsigned char webp[40];
    size_t wn = solid_webp(webp, 2000, 20);
    put("wide.webp", webp, wn);
    long ww, wh;
    T("webp fixture is oversized", image_dims(webp, wn, &ww, &wh) && ww == 2000 && wh == 20);
    static unsigned char whead[65536];
    bool wok = image_from_file(dir, "wide.webp", &p, err, sizeof err);
    if (!wok) printf("  webp: %s\n", err);
    T("oversized webp scaled to a 1568 PNG", wok && !strncmp(p.url, "data:image/png;", 15) &&
      image_dims(whead, head_of(p.url, whead, sizeof whead), &ww, &wh) && ww == IMG_MAX_DIM && wh < 20);
    image_part_free(&p);
    drop("wide.webp");
    drop("wide.png"); drop("wide.jpg"); drop("wide.gif"); drop("small.png"); drop("broken.png");
}
#endif

static bool blocked(const char *ip) {
    struct sockaddr_in a = {.sin_family = AF_INET};
    struct sockaddr_in6 b = {.sin6_family = AF_INET6};
    if (inet_pton(AF_INET, ip, &a.sin_addr) == 1) return image_addr_blocked((struct sockaddr *)&a);
    if (inet_pton(AF_INET6, ip, &b.sin6_addr) != 1) { printf("bad test ip %s\n", ip); exit(1); }
    return image_addr_blocked((struct sockaddr *)&b);
}

static void test_addresses(void) {
    const char *bad[] = {"0.0.0.0", "10.1.2.3", "100.64.0.1", "100.127.255.255", "127.0.0.1",
        "127.9.9.9", "169.254.169.254", "172.16.0.1", "172.31.255.255", "192.168.1.1",
        "168.63.129.16", "198.18.0.1", "224.0.0.1", "239.255.255.250", "255.255.255.255",
        "::", "::1", "::ffff:127.0.0.1", "::ffff:8.8.8.8", "::127.0.0.1", "64:ff9b::7f00:1",
        "fc00::1", "fd12::1", "fe80::1", "fec0::1", "ff02::1", "2001::1", "2001:db8::1",
        "2002:7f00:1::1"};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) T(bad[i], blocked(bad[i]));
    const char *good[] = {"8.8.8.8", "1.1.1.1", "100.128.0.1", "172.32.0.1", "172.15.0.1", "168.63.129.17",
        "2606:4700:4700::1111", "2001:4860:4860::8888"};
    for (size_t i = 0; i < sizeof good / sizeof *good; i++) T(good[i], !blocked(good[i]));
}

#ifdef FW_MINI_HTTP
static void test_url(void) {
    ImagePart p;
    char err[256];
    T("mini refuses", !image_from_url("https://example.invalid/a.png", &p, err, sizeof err)
                      && strstr(err, "not supported") && !p.url);
}
#else
static void say(int c, const void *d, size_t n) {
    if (write(c, d, n) < 0) close(c);
}

/* answers by path; one request per connection */
static void serve(int ls) {
    for (;;) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) _exit(0);
        char req[2048] = {0};
        if (read(c, req, sizeof req - 1) <= 0) { close(c); continue; }
        const char *head = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
        if (strstr(req, "GET /redirect"))
            head = "HTTP/1.1 302 Found\r\nLocation: /ok\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        else if (strstr(req, "GET /missing"))
            head = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        else if (strstr(req, "GET /declared"))
            head = "HTTP/1.1 200 OK\r\nContent-Length: 20000000\r\nConnection: close\r\n\r\n";
        say(c, head, strlen(head));
        if (strstr(req, "GET /ok")) say(c, TINY, sizeof TINY);
        else if (strstr(req, "GET /html")) say(c, "<html></html>", 13);
        else if (strstr(req, "GET /endless")) {   /* no length: cap while streaming */
            static char junk[65536];
            memcpy(junk, TINY, sizeof TINY);
            for (int i = 0; i < 400; i++)
                if (write(c, junk, sizeof junk) <= 0) break;
        }
        close(c);
    }
}

static bool fetch(const char *host, int port, const char *path, ImagePart *p, char *err) {
    char url[256];
    snprintf(url, sizeof url, "http://%s:%d%s", host, port, path);
    return image_from_url(url, p, err, 256);
}

static void test_url(void) {
    ImagePart p;
    char err[256];
    signal(SIGPIPE, SIG_IGN);
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof a;
    if (ls < 0 || bind(ls, (struct sockaddr *)&a, sizeof a) || listen(ls, 8)
        || getsockname(ls, (struct sockaddr *)&a, &al)) {
        T("local server", false);
        return;
    }
    int port = ntohs(a.sin_port);
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) serve(ls);
    close(ls);
    /* an environment proxy must be ignored */
    setenv("http_proxy", "http://192.0.2.1:9", 1);

    /* the server is listening, so only the address filter can refuse these */
    const char *hosts[] = {"127.0.0.1", "localhost", "2130706433", "0x7f.1",
                           "[::1]", "[::ffff:127.0.0.1]", "0.0.0.0"};
    for (size_t i = 0; i < sizeof hosts / sizeof *hosts; i++)
        T(hosts[i], !fetch(hosts[i], port, "/ok", &p, err) && strstr(err, "private") && !p.url);

    image_test_port = port;
    T("fetch", fetch("127.0.0.1", port, "/ok", &p, err));
    T("fetched part", p.url && !strncmp(p.url, "data:image/png;base64,", 22)
                      && p.size == sizeof TINY && strstr(p.source, "/ok"));
    image_part_free(&p);
    T("no redirects", !fetch("127.0.0.1", port, "/redirect", &p, err) && strstr(err, "redirect"));
    T("status", !fetch("127.0.0.1", port, "/missing", &p, err) && strstr(err, "404"));
    T("magic", !fetch("127.0.0.1", port, "/html", &p, err) && strstr(err, "PNG"));
    T("streaming cap", !fetch("127.0.0.1", port, "/endless", &p, err) && strstr(err, "10 MB"));
    T("declared cap", !fetch("127.0.0.1", port, "/declared", &p, err) && strstr(err, "10 MB"));
    image_test_port = 0;
    unsetenv("http_proxy");

    T("ftp", !image_from_url("ftp://example.invalid/a.png", &p, err, sizeof err));
    T("file scheme", !image_from_url("file:///etc/passwd", &p, err, sizeof err));
    T("no scheme", !image_from_url("example.invalid/a.png", &p, err, sizeof err));
    T("credentials", !image_from_url("http://u:p@example.invalid/a.png", &p, err, sizeof err)
                     && strstr(err, "credentials"));
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}
#endif

static ImagePart part(size_t urllen) {
    ImagePart p = {.source = str_dup("/x/y.png"), .size = 3};
    p.url = malloc(urllen + 1);
    memset(p.url, 'A', urllen);
    memcpy(p.url, "data:", 5);
    p.url[urllen] = 0;
    memset(p.sha256, 'f', 64);
    return p;
}

static void test_msgs_parts(void) {
    Msgs m;
    msgs_init(&m);
    msgs_push(&m, "system", "sys");
    msgs_push(&m, "user", "look");
    msgs_push_assistant(&m, NULL, NULL);
    msgs_push_tool(&m, "c1", "out");
    cJSON *j = msgs_to_json(&m);
    char *s = cJSON_PrintUnformatted(j);
    T("text-only request unchanged", !strcmp(s,
        "[{\"role\":\"system\",\"content\":\"sys\"},{\"role\":\"user\",\"content\":\"look\"},"
        "{\"role\":\"assistant\",\"content\":\"\"},"
        "{\"role\":\"tool\",\"content\":\"out\",\"tool_call_id\":\"c1\"}]"));
    free(s); cJSON_Delete(j);

    Images pending = {0};
    ImagePart p = part(12);
    T("add", !images_add(&pending, &p, &m) && !p.url && pending.n == 1);
    m.v[1].images = pending;
    pending = (Images){0};
    j = msgs_to_json(&m);
    s = cJSON_PrintUnformatted(cJSON_GetArrayItem(j, 1));
    T("parts array", !strcmp(s, "{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"look\"},"
        "{\"type\":\"image_url\",\"image_url\":{\"url\":\"data:AAAAAAA\"}}]}"));
    free(s); cJSON_Delete(j);

    cJSON *log = images_log_json(&m.v[1].images);
    s = cJSON_PrintUnformatted(log);
    T("log has metadata", strstr(s, "/x/y.png") && strstr(s, "ffff") && strstr(s, "\"size\":3"));
    T("log has no data", !strstr(s, "data:") && !strstr(s, "AAAA"));
    free(s); cJSON_Delete(log);

    /* what a context reset does */
    Images keep = images_copy(&m.v[1].images);
    msgs_trunc(&m, 1);
    msgs_push(&m, "user", "");
    m.v[1].images = keep;
    msgs_insert(&m, 1, "user", "before");
    T("insert has no images", m.v[1].images.n == 0 && m.v[2].images.n == 1);
    T("copy survives trunc", !strcmp(m.v[2].images.v[0].url, "data:AAAAAAA"));
    j = msgs_to_json(&m);
    T("no empty text part", cJSON_GetArraySize(cJSON_GetObjectItem(cJSON_GetArrayItem(j, 2), "content")) == 1);
    cJSON_Delete(j);

    /* 64 images across conversation (1) and pending set */
    int added = 0;
    for (; added < IMG_MAX_COUNT - 1; added++) {
        p = part(8);
        if (images_add(&pending, &p, &m)) { image_part_free(&p); break; }
    }
    T("63 more fit", added == IMG_MAX_COUNT - 1);
    p = part(8);
    const char *why = images_add(&pending, &p, &m);
    T("65th refused", why && strstr(why, "64") && p.url);
    image_part_free(&p);
    images_free(&pending);

    p = part(IMG_MAX_TOTAL - 12);   /* plus the 12 in the conversation */
    T("exactly 32 MB", !images_add(&pending, &p, &m));
    p = part(8);
    why = images_add(&pending, &p, &m);
    T("over 32 MB refused", why && strstr(why, "32 MB"));
    image_part_free(&p);
    images_free(&pending);
    msgs_free(&m);
}

/* the all-or-none loader shared by the TUI and one-shot mode */
static void test_attach(void) {
    put("ok.png", TINY, sizeof TINY);
    char good[600], gone[600];
    snprintf(good, sizeof good, "%s/ok.png", dir);
    snprintf(gone, sizeof gone, "%s/missing.png", dir);
    Images set = {0};
    char why[600] = "";
    char *refs[2] = {str_dup(good), str_dup(gone)};
    T("missing file refuses the lot", !image_attach_refs(dir, refs, 2, &set, NULL, why, sizeof why));
    T("all-or-none: nothing kept", set.n == 0);
    T("reason names the file", strstr(why, "missing.png") != NULL);
    free(refs[0]); free(refs[1]);
    refs[0] = str_dup(good); refs[1] = str_dup(good);
    T("two good refs attach", image_attach_refs(dir, refs, 2, &set, NULL, why, sizeof why));
    T("both kept, sources set", set.n == 2 && set.v[0].url && set.v[1].source
                                && !strcmp(set.v[1].source, good));
    free(refs[0]); free(refs[1]);
    images_free(&set);
    drop("ok.png");
}

/* a rejected request drops the newest image, keeps the text, says so */
static void test_drop_rejected(void) {
    Msgs m;
    msgs_init(&m);
    msgs_push(&m, "system", "sys");
    msgs_push(&m, "user", "first");
    msgs_push(&m, "user", "second");
    msgs_push(&m, "user", "third");
    ImagePart p = part(8), q = part(8);
    T("image on first", !images_add(&m.v[1].images, &p, NULL));
    T("image on third", !images_add(&m.v[3].images, &q, NULL));
    char note[300] = "";
    T("client status 500 is not an image refusal", !image_drop_rejected(&m, "status 500 boom", note, sizeof note));
    T("transient http error is not one", !image_drop_rejected(&m, "http: status 503", note, sizeof note));
    T("auth error is not one", !image_drop_rejected(&m, "status 401 no key", note, sizeof note));
    T("aborted is not one", !image_drop_rejected(&m, "aborted", note, sizeof note));
    T("nothing dropped by those", m.v[1].images.n == 1 && m.v[3].images.n == 1);
    T("400 drops the newest image", image_drop_rejected(&m, "status 400 bad image", note, sizeof note));
    T("newest image gone", m.v[3].images.n == 0);
    T("older image kept", m.v[1].images.n == 1);
    T("text kept", !strcmp(m.v[3].content, "third") && !strcmp(m.v[3].role, "user"));
    T("note says what was dropped", strstr(note, "image y.png ") && !strstr(note, "/x/")
                                    && strstr(note, "the text stays"));
    T("413 drops the next one", image_drop_rejected(&m, "status 413 too large", note, sizeof note));
    T("oldest gone too", m.v[1].images.n == 0 && m.v[1].content && !strcmp(m.v[1].content, "first"));
    T("no images left: nothing to drop", !image_drop_rejected(&m, "status 400 x", note, sizeof note));
    msgs_free(&m);
}

/* push one user message holding one image named source (may be NULL) */
static void with_image(Msgs *m, const char *source) {
    msgs_push(m, "user", "text");
    ImagePart p = part(8);
    free(p.source);
    p.source = source ? str_dup(source) : NULL;
    T("image added", !images_add(&m->v[m->n - 1].images, &p, NULL));
}

static void test_drop_kept(void) {
    Msgs m;
    msgs_init(&m);
    char note[300] = "";
    with_image(&m, "/x/old.png");
    T("new message not seen", !m.v[0].images_seen);
    m.v[0].images_seen = true;
    T("accepted image then 400 is kept",
      !image_drop_rejected(&m, "status 400 bad", note, sizeof note) && m.v[0].images.n == 1);
    with_image(&m, "/x/new.png");
    const char *full[] = {
        "status 400 {\"error\":\"request exceeds the available context size\"}",
        "status 400 This model's Maximum Context Length is 8192 tokens",
        "status 413 {\"type\":\"exceed_context_size_error\"}"};
    for (int i = 0; i < 3; i++)
        T(full[i], !image_drop_rejected(&m, full[i], note, sizeof note) && m.v[1].images.n == 1);
    T("unaccepted one still dropped",
      image_drop_rejected(&m, "status 400 bad", note, sizeof note) && !m.v[1].images.n
      && m.v[0].images.n == 1);
    msgs_insert(&m, 1, "user", "inserted");
    T("inserted message not seen", !m.v[1].images_seen);

    with_image(&m, "/d/a\x1b[31m\nb.png");
    T("hostile file name", image_drop_rejected(&m, "status 400 x", note, sizeof note)
                           && !strchr(note, '\x1b') && !strchr(note, '\n') && !strstr(note, "/d/"));
    with_image(&m, "https://example.invalid/p/\x1b]0;t\n.png");
    T("hostile url", image_drop_rejected(&m, "status 400 x", note, sizeof note)
                     && !strchr(note, '\x1b') && !strchr(note, '\n')
                     && strstr(note, "https://example.invalid/p/"));
    with_image(&m, NULL);
    T("no source", image_drop_rejected(&m, "status 400 x", note, sizeof note)
                   && strstr(note, "the image image "));
    msgs_free(&m);
}

/* a stub endpoint for runs of the real binary: every POST body is appended to
   a log, and the mode decides the answers */
enum { STUB_OK, STUB_BLIND, STUB_REFUSE, STUB_THEN_REFUSE, STUB_RESET_THEN_REFUSE };

#define REQ_MARK "\n==REQ==\n"
#define SSE_HEAD "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"
#define SSE_DONE SSE_HEAD "data: {\"choices\":[{\"delta\":{\"content\":\"DONE\"}," \
                 "\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
#define SSE_TOOL SSE_HEAD "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c\"," \
                 "\"function\":{\"name\":\"bash\",\"arguments\":\"{\\\"command\\\":\\\"echo hi\\\"}\"}}]}," \
                 "\"finish_reason\":\"tool_calls\"}]}\n\ndata: [DONE]\n\n"
#define REFUSAL "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n{\"error\":\"bad image\"}"

static void stub(int ls, int mode, const char *logf) {
    static char req[1 << 20];
    int posts = 0;
    for (;;) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) _exit(0);
        size_t n = 0, want = 0;
        char *body = NULL;
        while (n < sizeof req - 1) {
            ssize_t k = read(c, req + n, sizeof req - 1 - n);
            if (k <= 0) break;
            req[n += (size_t)k] = 0;
            if (!body && (body = strstr(req, "\r\n\r\n"))) {
                body += 4;
                const char *cl = strstr(req, "Content-Length:");
                want = cl && cl < body ? strtoul(cl + 15, NULL, 10) : 0;
                if (strstr(req, "Expect: 100-continue") &&
                    write(c, "HTTP/1.1 100 Continue\r\n\r\n", 25) < 0) break;
            }
            if (body && n >= (size_t)(body - req) + want) break;
        }
        const char *r = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        if (n && body && !strncmp(req, "POST ", 5)) {
            FILE *f = fopen(logf, "a");
            if (f) { fprintf(f, REQ_MARK "%s", body); fclose(f); }
            posts++;
            bool refuse = mode == STUB_REFUSE || (mode == STUB_THEN_REFUSE && posts > 1)
                          || (mode == STUB_RESET_THEN_REFUSE && strstr(body, "Context reset after"));
            bool tool = mode == STUB_THEN_REFUSE || mode == STUB_RESET_THEN_REFUSE;
            r = refuse ? REFUSAL : tool ? SSE_TOOL : SSE_DONE;
        } else if (n && mode == STUB_BLIND && !strncmp(req, "GET ", 4))
            r = SSE_HEAD "{\"data\":[{\"id\":\"m\",\"vision\":false}]}";
        if (write(c, r, strlen(r)) < 0) _exit(1);
        close(c);
    }
}

typedef struct { int code; char out[16384], err[4096], log[1 << 18]; } Run;

static void slurp(const char *name, char *buf, size_t cap) {
    char p[800];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    FILE *f = fopen(p, "rb");
    size_t n = f ? fread(buf, 1, cap - 1, f) : 0;
    if (f) fclose(f);
    buf[n] = 0;
}

/* run the binary against the stub; extra is a NULL-terminated argument list,
   input (may be NULL) is piped to stdin */
static bool run_bin(const char *bin, int mode, const char *const *extra, const char *input, Run *r) {
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof a;
    if (ls < 0 || bind(ls, (struct sockaddr *)&a, sizeof a) || listen(ls, 8)
        || getsockname(ls, (struct sockaddr *)&a, &al)) return false;
    char logf[800], url[64], outf[800], errf[800], inf[800];
    snprintf(logf, sizeof logf, "%s/req.log", dir);
    snprintf(outf, sizeof outf, "%s/run.out", dir);
    snprintf(errf, sizeof errf, "%s/run.err", dir);
    snprintf(inf, sizeof inf, "%s/run.in", dir);
    snprintf(url, sizeof url, "http://127.0.0.1:%d/v1", ntohs(a.sin_port));
    drop("req.log");
    if (input) put("run.in", input, strlen(input));
    fflush(stdout);
    pid_t srv = fork();
    if (srv == 0) stub(ls, mode, logf);
    close(ls);
    pid_t pid = fork();
    if (pid == 0) {
        const char *av[32] = {bin, "--unsafe", "-q", "-C", dir, "-e", url, "-m", "m", "-W", "30"};
        int n = 11;
        for (int i = 0; extra[i] && n < 31; i++) av[n++] = extra[i];
        int in = open(input ? inf : "/dev/null", O_RDONLY);
        int out = open(outf, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        int err = open(errf, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (in < 0 || out < 0 || err < 0) _exit(126);
        dup2(in, 0); dup2(out, 1); dup2(err, 2);
        setenv("HOME", dir, 1);
        unsetenv("http_proxy");
        execv(bin, (char *const *)av);
        _exit(127);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    kill(srv, SIGKILL);
    waitpid(srv, NULL, 0);
    r->code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    slurp("run.out", r->out, sizeof r->out);
    slurp("run.err", r->err, sizeof r->err);
    slurp("req.log", r->log, sizeof r->log);
    drop("req.log"); drop("run.out"); drop("run.err"); drop("run.in");
    return true;
}

/* one-shot mode attaches the image named in a typed prompt, and only there; a
   refused request drops it, an accepted one keeps it. Needs FW_BIN. */
static void test_oneshot(void) {
    const char *bin = getenv("FW_BIN");
    if (!bin) { printf("SKIP one-shot image test: FW_BIN not set\n"); return; }
    static Run r;
    put("shot.png", TINY, sizeof TINY);
    put("bad.png", "not an image", 12);

    const char *typed[] = {"-T", "2", "describe ./shot.png", NULL};
    T("one-shot: run", run_bin(bin, STUB_OK, typed, NULL, &r));
    T("one-shot: image attached notice on stderr", strstr(r.err, "1 image attached") != NULL);
    T("one-shot: exit 0", r.code == 0);
    T("one-shot: image in the request", strstr(r.log, "\"image_url\"") != NULL);

    /* text the user did not type on the command line is never searched */
    const char *text = "compare ./shot.png with ./bad.png\n";
    put("task.txt", text, strlen(text));
    const char *file[] = {"-T", "2", "-f", NULL, NULL};
    char task[800];
    snprintf(task, sizeof task, "%s/task.txt", dir);
    file[3] = task;
    const char *piped[] = {"-T", "2", NULL};
    const char *lines[] = {"-T", "2", "look:\n./shot.png ./bad.png", NULL};
    const char *oneline_file[] = {"-T", "2", "-f", task, NULL};
    const struct { const char *name; const char *const *args; const char *in; } src[] = {
        {"-f", file, NULL}, {"stdin", piped, "compare ./shot.png with ./bad.png"},
        {"multi-line argv", lines, NULL}, {"one-line -f", oneline_file, NULL}};
    for (int i = 0; i < 4; i++) {
        if (i == 3) put("task.txt", "describe ./shot.png", 19);
        for (int mode = STUB_OK; mode <= STUB_BLIND; mode++) {
            char name[80];
            snprintf(name, sizeof name, "%s attaches nothing (%s)", src[i].name,
                     mode == STUB_BLIND ? "no vision" : "bad image");
            T(name, run_bin(bin, mode, src[i].args, src[i].in, &r) && r.code == 0
                    && strstr(r.log, REQ_MARK) && !strstr(r.log, "\"image_url\"")
                    && !strstr(r.err, "attached") && !strstr(r.err, "not sent"));
        }
    }

    /* the agent wiring: refused request -> image dropped -> `image` event */
    T("refused: run", run_bin(bin, STUB_REFUSE, typed, NULL, &r));
    T("refused: image was sent", strstr(r.log, "\"image_url\"") != NULL);
    T("refused: exit 1", r.code == 1);
    T("refused: image event", strstr(r.out, "server refused the image shot.png (status 400)")
                              && strstr(r.out, "dropped 1 from the message; the text stays"));

    const char *longer[] = {"-T", "30", "describe ./shot.png", NULL};
    T("accepted then refused: run", run_bin(bin, STUB_THEN_REFUSE, longer, NULL, &r));
    const char *second = strstr(r.log, REQ_MARK);
    second = second ? strstr(second + 1, REQ_MARK) : NULL;
    T("accepted then refused: image still sent", second && strstr(second, "\"image_url\""));
    T("accepted then refused: kept", r.code == 1 && !strstr(r.out, "server refused"));

    T("reset then refused: run", run_bin(bin, STUB_RESET_THEN_REFUSE, longer, NULL, &r));
    const char *reset = strstr(r.log, "Context reset after");
    T("reset then refused: reset happened", reset != NULL);
    while (reset && reset > r.log && strncmp(reset, REQ_MARK, strlen(REQ_MARK))) reset--;
    T("reset then refused: image survives the reset", reset && strstr(reset, "\"image_url\""));
    T("reset then refused: kept", r.code == 1 && !strstr(r.out, "server refused"));

    drop("shot.png");
    drop("bad.png");
    drop("task.txt");
}

int main(void) {
    const char *tmp = getenv("TMPDIR");
    snprintf(dir, sizeof dir, "%s/fw-test-image-XXXXXX", tmp && *tmp ? tmp : "/tmp");
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    test_magic();
    test_paths();
    test_refs();
    test_load();
#ifdef __APPLE__
    test_downscale();
#endif
    test_addresses();
    test_url();
    test_msgs_parts();
    test_attach();
    test_drop_rejected();
    test_drop_kept();
    test_oneshot();
    rmdir(dir);
    printf("image: %d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
