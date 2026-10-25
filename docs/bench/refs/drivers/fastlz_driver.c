/*
 * Benchmark driver for FastLZ. This is not part of the archive crate and
 * is used only to measure the reference implementation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fastlz.h"

#define MAX_OUTPUT (256u * 1024u * 1024u)

static unsigned char *read_file(const char *path, size_t *size) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        perror(path);
        exit(2);
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        exit(2);
    }
    long length = ftell(file);
    if (length < 0 || fseek(file, 0, SEEK_SET) != 0) {
        exit(2);
    }
    unsigned char *data = malloc((size_t)length + 1);
    if (!data) {
        exit(2);
    }
    if (fread(data, 1, (size_t)length, file) != (size_t)length) {
        exit(2);
    }
    fclose(file);
    *size = (size_t)length;
    return data;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s encode|decode input output\n", argv[0]);
        return 2;
    }
    size_t input_size = 0;
    unsigned char *input = read_file(argv[2], &input_size);
    unsigned char *output = NULL;
    size_t output_size = 0;

    if (strcmp(argv[1], "encode") == 0) {
        output_size = input_size * 2 + 64;
        output = malloc(output_size);
        if (!output) {
            return 2;
        }
        int written = fastlz_compress(input, (int)input_size, output);
        if (written <= 0 && input_size != 0) {
            fprintf(stderr, "fastlz_compress failed\n");
            return 2;
        }
        output_size = (size_t)written;
    } else if (strcmp(argv[1], "decode") == 0) {
        output = malloc(MAX_OUTPUT);
        if (!output) {
            return 2;
        }
        int written = fastlz_decompress(input, (int)input_size, output, MAX_OUTPUT);
        if (written <= 0 && input_size != 0) {
            fprintf(stderr, "fastlz_decompress failed\n");
            return 2;
        }
        output_size = (size_t)written;
    } else {
        return 2;
    }

    FILE *file = fopen(argv[3], "wb");
    if (!file) {
        perror(argv[3]);
        return 2;
    }
    if (fwrite(output, 1, output_size, file) != output_size) {
        return 2;
    }
    fclose(file);
    free(input);
    free(output);
    return 0;
}
