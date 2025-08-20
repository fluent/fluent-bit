#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <fluent-bit.h>
#include <fluent-bit/flb_pack_json.h>

#define ITERATIONS 100000

static long diff_ns(struct timespec *s, struct timespec *e)
{
    return (e->tv_sec - s->tv_sec) * 1000000000L + (e->tv_nsec - s->tv_nsec);
}

static int compare_encoders_output(char *json, size_t len)
{
    int ret;

    int root_type1;
    char *out_buf1;
    size_t out_size1 = 0;

    int root_type2;
    char *out_buf2;
    size_t out_size2 = 0;

    struct flb_pack_opts opts = {0};

    /* jsmn */
    opts.backend = FLB_PACK_JSON_BACKEND_JSMN;
    ret = flb_pack_json_ext(json, len, &out_buf1, &out_size1, &root_type1, &opts);
    if (ret != 0) {
        fprintf(stderr, "error jsmn\n");
        return -1;
    }
    fprintf(stderr, "jsmn records count: %d\n", flb_mp_count(out_buf1, out_size1));

    /* yyjson */
    opts.backend = FLB_PACK_JSON_BACKEND_YYJSON;
    ret = flb_pack_json_ext(json, len, &out_buf2, &out_size2, &root_type2, &opts);
    if (ret != 0) {
        fprintf(stderr, "error yyjson\n");
        flb_free(out_buf1);
        return -1;
    }

    if (out_size1 != out_size2 || memcmp(out_buf1, out_buf2, out_size1) != 0) {
        fprintf(stderr, "msgpack mismatch between jsmn and yyjson\n");
        fprintf(stderr, "jsmn size: %zu, yyjson size: %zu\n", out_size1, out_size2);
        flb_free(out_buf1);
        flb_free(out_buf2);
        return -1;
    }

    flb_free(out_buf1);
    flb_free(out_buf2);
    return 0;
}

int main(int argc, char **argv)
{
    int i;
    int ret;
    size_t len;
    struct timespec ts, te;
    long d_jsmn, d_yyjson;
    char *mp_buf;
    size_t mp_size;
    struct flb_pack_opts opts = {0};
    int root_type;
    char *json;
    int iterations = 100;
    char *log_file = NULL;
    int opt;
    uint64_t total_bytes;
    double mibps_jsmn;
    double mibps_yyjson;
    double ratio;
    double reduction;

    /* Parse command-line options */
    while ((opt = getopt(argc, argv, "i:f:")) != -1) {
        switch (opt) {
        case 'i':
            iterations = atoi(optarg);
            if (iterations <= 0) {
                fprintf(stderr, "Invalid value for -i (iterations): %s\n", optarg);
                return 1;
            }
            break;
        case 'f':
            log_file = optarg;
            break;
        default:
            fprintf(stderr, "Usage: %s -f log_file [-i iterations]\n", argv[0]);
            return 1;
        }
    }

    if (log_file == NULL) {
        fprintf(stderr, "Error: log file (-f) is required.\n");
        fprintf(stderr, "Usage: %s -f log_file [-i iterations]\n", argv[0]);
        return 1;
    }

    ret = flb_utils_read_file(log_file, &json, &len);
    if (ret != 0) {
        fprintf(stderr, "error reading %s\n", log_file);
        return 1;
    }

    printf("Comparing encoders output: ");
    ret = compare_encoders_output(json, len);
    if (ret != 0) {
        printf("failed\n");
        free(json);
        exit(EXIT_FAILURE);
    }
    printf("ok\n\n");

    printf("Benchmarking JSON packing to msgpack\n");
    printf("-------------------------------------------\n\n");
    printf("Iterations   : %d\n", iterations);
    printf("JSON size    : %zu bytes\n", len);
    printf("-------------------------------------------\n\n");

    /* JSMN */
    opts.backend = FLB_PACK_JSON_BACKEND_JSMN;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    for (i = 0; i < iterations; i++) {
        ret = flb_pack_json_ext(json, len, &mp_buf, &mp_size, &root_type, &opts);
        if (ret != 0) {
            fprintf(stderr, "error jsmn\n");
            free(json);
            return 1;
        }
        flb_free(mp_buf);
    }
    clock_gettime(CLOCK_MONOTONIC, &te);
    d_jsmn = diff_ns(&ts, &te);

    /* YYJSON */
    opts.backend = FLB_PACK_JSON_BACKEND_YYJSON;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    for (i = 0; i < iterations; i++) {
        ret = flb_pack_json_ext(json, len, &mp_buf, &mp_size, &root_type, &opts);
        if (ret != 0) {
            fprintf(stderr, "error yyjson\n");
            free(json);
            return 1;
        }
        flb_free(mp_buf);
    }
    clock_gettime(CLOCK_MONOTONIC, &te);
    d_yyjson = diff_ns(&ts, &te);


    total_bytes = (uint64_t) len * (uint64_t) iterations;

    mibps_jsmn   = (double) total_bytes / d_jsmn * 1e9 / (1024.0 * 1024.0);
    mibps_yyjson = (double) total_bytes / d_yyjson * 1e9 / (1024.0 * 1024.0);

    ratio      = (double) d_jsmn / (double) d_yyjson;
    reduction  = (double) (d_jsmn - d_yyjson) * 100.0 / (double) d_jsmn;

    printf("-------------------------------------------\n");
    printf("old encoder  : %ld ns  | %.2f MiB/s\n", d_jsmn,   mibps_jsmn);
    printf("new encoder  : %ld ns  | %.2f MiB/s\n", d_yyjson, mibps_yyjson);
    printf("-------------------------------------------\n");
    printf("Speedup      : %.2fx  (time -%.2f%%)\n", ratio, reduction);

    free(json);
    return 0;
}
