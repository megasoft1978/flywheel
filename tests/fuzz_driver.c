/* Deterministic mutation driver for the fuzz targets, for toolchains without
   libFuzzer (Apple clang). The targets use the libFuzzer entry point, so they
   also build with -fsanitize=fuzzer instead of this file.

   usage: fuzz_x              run FUZZ_RUNS inputs from FUZZ_SEED
          fuzz_x FILE         replay one saved input
   A failing input is saved to $FUZZ_CRASH (default "fuzz-crash.bin"). */
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern const char *const fuzz_seeds[];    /* starting inputs, NULL-ended */
extern const char *const fuzz_tokens[];   /* grammar pieces, NULL-ended */

#define CAP 8192
#define PER_INPUT_SECS 5

static uint8_t cur[CAP];
static size_t cur_len;
static const char *crash_path = "fuzz-crash.bin";
static uint64_t state;

static unsigned rnd(unsigned n) {   /* xorshift64: same inputs on every run */
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return n ? (unsigned)(state % n) : 0;
}

static void save_input(int sig) {
    static const char msg[] = "fuzz: failing input saved (see FUZZ_CRASH)\n";
    int fd = open(crash_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        ssize_t w = write(fd, cur, cur_len);
        close(fd);
        if (w >= 0) w = write(2, msg, sizeof msg - 1);
        (void)w;
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

static void splice(const char *p, size_t n) {
    if (!n || n > CAP - cur_len) return;
    size_t at = rnd((unsigned)cur_len + 1);
    memmove(cur + at + n, cur + at, cur_len - at);
    memcpy(cur + at, p, n);
    cur_len += n;
}

static void mutate(unsigned nseeds, unsigned ntokens) {
    switch (rnd(8)) {
    case 0: if (cur_len) cur[rnd((unsigned)cur_len)] ^= (uint8_t)(1u << rnd(8)); break;
    case 1: if (cur_len) cur[rnd((unsigned)cur_len)] = (uint8_t)rnd(256); break;
    case 2: {                                    /* delete a span */
        if (!cur_len) break;
        size_t at = rnd((unsigned)cur_len), n = 1 + rnd(16);
        if (n > cur_len - at) n = cur_len - at;
        memmove(cur + at, cur + at + n, cur_len - at - n);
        cur_len -= n;
        break;
    }
    case 3: {                                    /* repeat a span many times */
        if (!cur_len) break;
        char tmp[32];
        size_t at = rnd((unsigned)cur_len), n = 1 + rnd(sizeof tmp);
        if (n > cur_len - at) n = cur_len - at;
        memcpy(tmp, cur + at, n);
        for (unsigned i = 0, k = 1 + rnd(rnd(8) ? 4 : 200); i < k; i++) splice(tmp, n);
        break;
    }
    case 4: if (cur_len) cur_len = rnd((unsigned)cur_len); break;   /* truncate */
    case 5: { const char *s = fuzz_seeds[rnd(nseeds)]; splice(s, strlen(s)); break; }
    default: { const char *t = fuzz_tokens[rnd(ntokens)]; splice(t, strlen(t)); break; }
    }
}

static void run_one(void) {
    /* an exactly-sized copy, so reads past the end are caught */
    uint8_t *copy = malloc(cur_len ? cur_len : 1);
    if (!copy) exit(2);
    memcpy(copy, cur, cur_len);
    alarm(PER_INPUT_SECS);               /* a hang or blow-up is a finding */
    LLVMFuzzerTestOneInput(copy, cur_len);
    alarm(0);
    free(copy);
}

int main(int argc, char **argv) {
    if (getenv("FUZZ_CRASH")) crash_path = getenv("FUZZ_CRASH");
    signal(SIGABRT, save_input);
    signal(SIGALRM, save_input);
    if (argc > 1) {
        FILE *f = fopen(argv[1], "rb");
        if (!f) { perror(argv[1]); return 2; }
        cur_len = fread(cur, 1, CAP, f);
        fclose(f);
        run_one();
        printf("replayed %zu bytes\n", cur_len);
        return 0;
    }
    long runs = getenv("FUZZ_RUNS") ? atol(getenv("FUZZ_RUNS")) : 20000;
    long secs = getenv("FUZZ_SECONDS") ? atol(getenv("FUZZ_SECONDS")) : 30;
    state = getenv("FUZZ_SEED") ? strtoull(getenv("FUZZ_SEED"), NULL, 10) : 1;
    if (!state) state = 1;
    unsigned nseeds = 0, ntokens = 0;
    while (fuzz_seeds[nseeds]) nseeds++;
    while (fuzz_tokens[ntokens]) ntokens++;

    time_t start = time(NULL);
    long done = 0;
    for (; done < runs && time(NULL) - start < secs; done++) {
        const char *s = fuzz_seeds[done < (long)nseeds ? (unsigned)done : rnd(nseeds)];
        cur_len = strlen(s) < CAP ? strlen(s) : CAP;
        memcpy(cur, s, cur_len);
        if (done >= (long)nseeds)        /* the first pass is the seeds as written */
            for (unsigned i = 0, k = 1 + rnd(8); i < k; i++) mutate(nseeds, ntokens);
        run_one();
    }
    printf("%s: %ld inputs, no findings\n", argv[0], done);
    return 0;
}
