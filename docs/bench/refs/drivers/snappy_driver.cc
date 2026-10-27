/*
 * Benchmark driver for Google Snappy raw blocks. This is not part of the
 * archive crate and is used only to measure the reference implementation.
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "snappy.h"

static std::string read_file(const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        perror(path);
        exit(2);
    }
    std::string data;
    char buffer[65536];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        data.append(buffer, n);
    }
    fclose(file);
    return data;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s encode|decode input output\n", argv[0]);
        return 2;
    }
    std::string input = read_file(argv[2]);
    std::string output;
    if (strcmp(argv[1], "encode") == 0) {
        snappy::Compress(input.data(), input.size(), &output);
    } else if (strcmp(argv[1], "decode") == 0) {
        if (!snappy::Uncompress(input.data(), input.size(), &output)) {
            fprintf(stderr, "snappy::Uncompress failed\n");
            return 2;
        }
    } else {
        return 2;
    }
    FILE *file = fopen(argv[3], "wb");
    if (!file) {
        perror(argv[3]);
        return 2;
    }
    if (fwrite(output.data(), 1, output.size(), file) != output.size()) {
        return 2;
    }
    fclose(file);
    return 0;
}
