#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_mem.h>
#include "../tests/lib/acutest/acutest.h"
#include "bench_config.h"
#include <stdio.h>
#include <stdlib.h>

static char *read_file(const char *path, size_t *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(size + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, size, f) != (size_t)size) {
        fclose(f);
        free(buf);
        return NULL;
    }
    fclose(f);
    buf[size] = '\0';
    if (out_size) *out_size = size;
    return buf;
}

static void test_pack_compare(void)
{
    char *json;
    size_t len;
    char *out1; size_t size1; int root1;
    char *out2; size_t size2; int root2;

    char path[512];
    snprintf(path, sizeof(path), "%s/sample.json", FLB_BENCHMARKS_DATA_PATH);
    json = read_file(path, &len);
    TEST_CHECK(json != NULL);

    TEST_CHECK(flb_pack_json(json, len, &out1, &size1, &root1, NULL) == 0);
    TEST_CHECK(flb_pack_json_simd(json, len, &out2, &size2, &root2, NULL) == 0);

    TEST_CHECK(size1 == size2);
    TEST_CHECK(root1 == root2);
    TEST_CHECK(memcmp(out1, out2, size1) == 0);

    flb_free(out1);
    flb_free(out2);
    free(json);
}

#define N_ITERATIONS 10000

static double time_diff(struct timespec *start, struct timespec *end) {
    return (end->tv_sec - start->tv_sec) + (end->tv_nsec - start->tv_nsec) / 1e9;
}

static void benchmark_pack_compare(void)
{
    char *json;
    size_t len;
    char *out;
    size_t size;
    int root;

    struct timespec t_start, t_end;
    double elapsed_json = 0.0, elapsed_simd = 0.0;

    char path[512];
    snprintf(path, sizeof(path), "%s/sample.json", FLB_BENCHMARKS_DATA_PATH);
    json = read_file(path, &len);
    if (!json) {
        fprintf(stderr, "Failed to load JSON sample.\n");
        exit(1);
    }

    // Benchmark flb_pack_json
    for (int i = 0; i < N_ITERATIONS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t_start);
        flb_pack_json(json, len, &out, &size, &root, NULL);
        clock_gettime(CLOCK_MONOTONIC, &t_end);
        elapsed_json += time_diff(&t_start, &t_end);
        flb_free(out);
    }

    // Benchmark flb_pack_json_simd
    for (int i = 0; i < N_ITERATIONS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t_start);
        flb_pack_json_simd(json, len, &out, &size, &root, NULL);
        clock_gettime(CLOCK_MONOTONIC, &t_end);
        elapsed_simd += time_diff(&t_start, &t_end);
        flb_free(out);
    }

    free(json);

    printf("Benchmark Results (average over %d iterations):\n", N_ITERATIONS);
    printf("flb_pack_json       : %.6f sec total, %.6f sec/iter\n", elapsed_json, elapsed_json / N_ITERATIONS);
    printf("flb_pack_json_simd  : %.6f sec total, %.6f sec/iter\n", elapsed_simd, elapsed_simd / N_ITERATIONS);
}

TEST_LIST = {
    {"pack_compare_simd", test_pack_compare},
    {"pack_benchmark_simd", benchmark_pack_compare},
    {0, 0}
};
