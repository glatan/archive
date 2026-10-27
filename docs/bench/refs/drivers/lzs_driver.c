#include <stdio.h>
#include <stdlib.h>
#include "lzs.h"

static unsigned char *read_file(const char *path, size_t *len) {
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
    *len = (size_t)n;
    return buf;
}

int main(int argc, char **argv) {
    unsigned char *in, *out;
    size_t n = 0, olen = 0;
    FILE *f;
    if (argc != 4) return 2;
    in = read_file(argv[2], &n);
    if (!in) return 2;
    out = malloc(256u << 20);
    if (!out) return 2;
    if (argv[1][0] == 'c') olen = lzs_compress(out, 256u << 20, in, n);
    else olen = lzs_decompress(out, 256u << 20, in, n);
    if (olen == 0 && n != 0) return 3;
    f = fopen(argv[3], "wb");
    if (!f) return 2;
    fwrite(out, 1, olen, f);
    fclose(f);
    return 0;
}
