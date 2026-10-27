#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(USE_LZRW1)
#define TRUE 1
#define FALSE 0
#include "lzrw1.c"
#else
#include "port.h"
#include "compress.h"
#include "fast_copy.h"
#if defined(USE_LZRW1A)
#include "lzrw1-a.c"
#elif defined(USE_LZRW2)
#include "lzrw2.c"
#elif defined(USE_LZRW3)
#include "lzrw3.c"
#elif defined(USE_LZRW3A)
#include "lzrw3-a.c"
#endif
#endif

static unsigned char *read_file(const char *path, unsigned long *len) {
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    long n;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    n = ftell(f);
    if (n < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *len = (unsigned long)n;
    return buf;
}

#define MAX_ALLOC ((size_t)2 << 30)

int main(int argc, char **argv) {
    unsigned char *in, *out, *wrk = NULL;
    unsigned long n = 0, olen = 0;
    size_t capacity;
    FILE *f;
    if (argc != 4) return 2;
    in = read_file(argv[2], &n);
    if (!in) return 2;
    if (argv[1][0] == 'c') {
        if ((size_t)n > MAX_ALLOC / 2) return 3;
        capacity = (size_t)n + (size_t)n / 8 + 65536;
    } else {
        // LZRW matches expand by at most 9x; 10x leaves headroom while
        // accepting a 64 MiB incompressible stream (FLAG_COPY adds 4 bytes).
        if ((size_t)n > (MAX_ALLOC - 4096) / 10) return 3;
        capacity = (size_t)n * 10 + 4096;
    }
    if (capacity > MAX_ALLOC) return 3;
    out = malloc(capacity);
    if (!out) return 2;
#if defined(USE_LZRW1)
    if (argv[1][0] == 'c') lzrw1_compress(in, n, out, &olen);
    else lzrw1_decompress(in, n, out, &olen);
#else
    wrk = calloc(1, 1 << 20);
    if (!wrk) return 2;
    if (argv[1][0] == 'c') compress_compress(wrk, in, n, out, &olen);
    else compress_decompress(wrk, in, n, out, &olen);
#endif
    f = fopen(argv[3], "wb");
    if (!f) return 2;
    if (fwrite(out, 1, olen, f) != olen || fclose(f) != 0) return 2;
    return 0;
}
