/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

#include <string.h>

#ifdef _WIN32
#include <io.h>
#define flb_test_close  _close
#define flb_test_dup    _dup
#define flb_test_dup2   _dup2
#define flb_test_fileno _fileno
#else
#include <unistd.h>
#define flb_test_close  close
#define flb_test_dup    dup
#define flb_test_dup2   dup2
#define flb_test_fileno fileno
#endif

/* Test data */
#include "data/common/json_invalid.h" /* JSON_INVALID */
#include "data/common/json_long.h"    /* JSON_LONG    */
#include "data/common/json_small.h"   /* JSON_SMALL   */

static int run_counter_and_capture(const char *payload, size_t payload_size,
                                   char *buffer, size_t buffer_size)
{
    int i;
    int ret;
    int bytes;
    int in_ffd;
    int out_ffd;
    int stdout_fd;
    FILE *capture;
    flb_ctx_t *ctx;
    size_t bytes_read;

    capture = tmpfile();
    if (capture == NULL) {
        return -1;
    }

    fflush(stdout);

    stdout_fd = flb_test_dup(flb_test_fileno(stdout));
    if (stdout_fd == -1) {
        fclose(capture);
        return -1;
    }

    if (flb_test_dup2(flb_test_fileno(capture), flb_test_fileno(stdout)) == -1) {
        flb_test_close(stdout_fd);
        fclose(capture);
        return -1;
    }

    ctx = flb_create();
    if (ctx == NULL) {
        ret = -1;
        goto restore_stdout;
    }

    flb_service_set(ctx, "Flush", "0.2", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    if (in_ffd < 0) {
        ret = -1;
        goto destroy_ctx;
    }

    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "counter", NULL);
    if (out_ffd < 0) {
        ret = -1;
        goto destroy_ctx;
    }

    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    ret = flb_start(ctx);
    if (ret != 0) {
        goto destroy_ctx;
    }

    for (i = 0; i < (int) payload_size; i++) {
        bytes = flb_lib_push(ctx, in_ffd, (char *) payload + i, 1);
        if (bytes != 1) {
            ret = -1;
            goto stop_ctx;
        }
    }

    sleep(1);
    ret = 0;

stop_ctx:
    flb_stop(ctx);

destroy_ctx:
    flb_destroy(ctx);

restore_stdout:
    fflush(stdout);
    flb_test_dup2(stdout_fd, flb_test_fileno(stdout));
    flb_test_close(stdout_fd);

    rewind(capture);
    bytes_read = fread(buffer, 1, buffer_size - 1, capture);
    buffer[bytes_read] = '\0';

    fclose(capture);
    return ret;
}

/* Test functions */
void flb_test_counter_json_invalid(void);
void flb_test_counter_json_long(void);
void flb_test_counter_json_small(void);

/* Test list */
TEST_LIST = {
    {"json_invalid",    flb_test_counter_json_invalid },
    {"json_long",       flb_test_counter_json_long    },
    {"json_small",      flb_test_counter_json_small   },
    {NULL, NULL}
};

void flb_test_counter_json_invalid(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_INVALID;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "counter", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_INVALID) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* It writes a very long JSON map (> 100KB) byte by byte */
void flb_test_counter_json_long(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_LONG;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "counter", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_LONG) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_counter_json_small(void)
{
    int ret;
    int parsed;
    unsigned long serialized_events;
    unsigned long log_records;
    unsigned long total;
    double timestamp;
    char output[256];

    ret = run_counter_and_capture((const char *) JSON_SMALL,
                                  sizeof(JSON_SMALL) - 1,
                                  output, sizeof(output));
    TEST_CHECK(ret == 0);
    TEST_CHECK(output[0] == '{');

    parsed = sscanf(output,
                    "{\"ts\":%lf,\"serialized_events\":%lu,"
                    "\"log_records\":%lu,\"total\":%lu}",
                    &timestamp,
                    &serialized_events,
                    &log_records,
                    &total);
    TEST_CHECK(parsed == 4);
    TEST_CHECK(timestamp > 0.0);
    TEST_CHECK(serialized_events == 1);
    TEST_CHECK(log_records == 1);
    TEST_CHECK(total == 1);
}
