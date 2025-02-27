/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include "flb_tests_runtime.h"

/* Test data */

/* Test functions */
void flb_test_filter_grep_regex(void);
void flb_test_filter_grep_exclude(void);
void flb_test_filter_grep_invalid(void);

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int  num_output = 0;

static int cb_count_msgpack(void *record, size_t size, void *data)
{
    msgpack_unpacked result;
    size_t off = 0;

    if (!TEST_CHECK(data != NULL)) {
        flb_error("data is NULL");
    }

    /* Iterate each item array and apply rules */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, record, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        pthread_mutex_lock(&result_mutex);
        num_output++;
        pthread_mutex_unlock(&result_mutex);
    }
    msgpack_unpacked_destroy(&result);

    flb_free(record);
    return 0;
}

static void clear_output_num()
{
    pthread_mutex_lock(&result_mutex);
    num_output = 0;
    pthread_mutex_unlock(&result_mutex);
}

static int get_output_num()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

void flb_test_filter_grep_regex(void)
{
    int i;
    int ret;
    int bytes;
    char p[100];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "Regex", "val 1", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 256; i++) {
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"END_KEY\": \"JSON_END\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_filter_grep_exclude(void)
{
    int i;
    int ret;
    int bytes;
    char p[100];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "Exclude", "val 1", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 256; i++) {
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"END_KEY\": \"JSON_END\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_filter_grep_invalid(void)
{
    int i;
    int ret;
    int bytes;
    char p[100];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "Regex", "val", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "Exclude", "val", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == -1);

    for (i = 0; i < 256; i++) {
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"END_KEY\": \"JSON_END\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == -1);
    }

    if (ret == 0) {
        flb_stop(ctx);
    }
    flb_destroy(ctx);
}

/* filter_grep supports multiple 'Exclude's.
 * If user sets multiple 'Exclude's, fluent-bit uses as OR conditions.
 */
void flb_test_filter_grep_multi_exclude(void)
{
    int i;
    int ret;
    int bytes;
    char p[512];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    int got;
    int n_loop = 256;
    int not_used = 0;
    struct flb_lib_out_cb cb_data;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Exclude", "log deprecated",
                         "Exclude", "log hoge",
                         NULL);
    TEST_CHECK(ret == 0);

    clear_output_num();

    ret = flb_start(ctx);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        exit(EXIT_FAILURE);
    }

    /* Ingest 2 records per loop. One of them should be excluded. */
    for (i = 0; i < n_loop; i++) {
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"log\": \"Using deprecated option\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));

        /* Below record will be included */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"log\": \"Using option\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500); /* waiting flush */

    got = get_output_num();
    if (!TEST_CHECK(got == n_loop)) {
        TEST_MSG("expect: %d got: %d", n_loop, got);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_filter_grep_unknown_property(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    int not_used = 0;
    struct flb_lib_out_cb cb_data;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "UNKNOWN_PROPERTY", "aaaaaa", NULL);
    TEST_CHECK(ret == 0);

    clear_output_num();

    ret = flb_start(ctx);
    if(!TEST_CHECK(ret != 0)) {
        TEST_MSG("flb_start should be failed");
        exit(EXIT_FAILURE);
    }

    flb_destroy(ctx);
}

/*
 * https://github.com/fluent/fluent-bit/issues/5209 
 * To support /REGEX/ style.
 */
void flb_test_issue_5209(void)
{
    int i;
    int ret;
    int bytes;
    char p[512];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    int got;
    int n_loop = 256;
    int not_used = 0;
    struct flb_lib_out_cb cb_data;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "Exclude", "log /Using deprecated option/", NULL);
    TEST_CHECK(ret == 0);

    clear_output_num();

    ret = flb_start(ctx);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        exit(EXIT_FAILURE);
    }

    /* Ingest 2 records per loop. One of them should be excluded. */
    for (i = 0; i < n_loop; i++) {
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"END_KEY\": \"JSON_END\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));

        /* Below record will be excluded */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"log\": \"Using deprecated option\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500); /* waiting flush */

    got = get_output_num();
    if (!TEST_CHECK(got == n_loop)) {
        TEST_MSG("expect: %d got: %d", n_loop, got);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}


/* filter_grep supports multiple 'Regex's.
 * If user sets multiple 'Regex's, fluent-bit uses as AND conditions.
 */
void flb_test_filter_grep_multi_regex(void)
{
    int i;
    int ret;
    int bytes;
    char p[512];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    int got;
    int n_loop = 256;
    int not_used = 0;
    struct flb_lib_out_cb cb_data;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Regex", "log deprecated",
                         "Regex", "log option",
                         NULL);
    TEST_CHECK(ret == 0);

    clear_output_num();

    ret = flb_start(ctx);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        exit(EXIT_FAILURE);
    }

    /* Ingest 2 records per loop. One of them should be excluded. */
    for (i = 0; i < n_loop; i++) {
        memset(p, '\0', sizeof(p));
        /* Below record will be included */
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"log\": \"Using deprecated option\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));

        /* Below record will be excluded */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"log\": \"Using option\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500); /* waiting flush */

    got = get_output_num();
    if (!TEST_CHECK(got == n_loop)) {
        TEST_MSG("expect: %d got: %d", n_loop, got);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_error_AND_regex_exclude(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Regex",   "val 1",
                         "Exclude", "val2 3",
                         "Logical_Op", "AND",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);

    if (ret == 0) {
        flb_stop(ctx);
    }
    flb_destroy(ctx);
}

void flb_test_error_OR_regex_exclude(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Regex",   "val 1",
                         "Exclude", "val2 3",
                         "Logical_Op", "OR",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);

    if (ret == 0) {
        flb_stop(ctx);
    }
    flb_destroy(ctx);
}

void flb_test_AND_regex(void)
{
    int i;
    int ret;
    int bytes;
    char p[512];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    int got;
    int n_loop = 256;
    int not_used = 0;
    struct flb_lib_out_cb cb_data;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Regex", "log deprecated",
                         "Regex", "log option",
                         "Logical_Op", "AND",
                         NULL);
    TEST_CHECK(ret == 0);

    clear_output_num();

    ret = flb_start(ctx);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        exit(EXIT_FAILURE);
    }

    /* Ingest 2 records per loop. One of them should be excluded. */
    for (i = 0; i < n_loop; i++) {
        memset(p, '\0', sizeof(p));
        /* Below record will be included */
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"log\": \"Using deprecated option\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));

        /* Below record will be excluded */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"log\": \"Using option\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500); /* waiting flush */

    got = get_output_num();
    if (!TEST_CHECK(got == n_loop)) {
        TEST_MSG("expect: %d got: %d", n_loop, got);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_OR_regex(void)
{
    int i;
    int ret;
    int bytes;
    char p[512];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    int got;
    int n_loop = 256;
    int not_used = 0;
    struct flb_lib_out_cb cb_data;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Regex", "log deprecated",
                         "Regex", "log option",
                         "Logical_Op", "OR",
                         NULL);
    TEST_CHECK(ret == 0);

    clear_output_num();

    ret = flb_start(ctx);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        exit(EXIT_FAILURE);
    }

    /* Ingest 2 records per loop. One of them should be excluded. */
    for (i = 0; i < n_loop; i++) {
        memset(p, '\0', sizeof(p));
        /* Below record will be included */
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"log\": \"Using deprecated option\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));

        /* Below record will be excluded */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"log\": \"Using option\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500); /* waiting flush */

    got = get_output_num();
    if (!TEST_CHECK(got == n_loop * 2)) {
        TEST_MSG("expect: %d got: %d", n_loop * 2, got);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_AND_exclude(void)
{
    int i;
    int ret;
    int bytes;
    char p[512];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    int got;
    int n_loop = 256;
    int not_used = 0;
    struct flb_lib_out_cb cb_data;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Exclude", "log deprecated",
                         "Exclude", "log option",
                         "Logical_Op", "AND",
                         NULL);
    TEST_CHECK(ret == 0);

    clear_output_num();

    ret = flb_start(ctx);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        exit(EXIT_FAILURE);
    }

    /* Ingest 2 records per loop. One of them should be excluded. */
    for (i = 0; i < n_loop; i++) {
        memset(p, '\0', sizeof(p));
        /* Below record will be included */
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"log\": \"Using deprecated option\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));

        /* Below record will be excluded */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"log\": \"Using option\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500); /* waiting flush */

    got = get_output_num();
    if (!TEST_CHECK(got == n_loop)) {
        TEST_MSG("expect: %d got: %d", n_loop, got);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_OR_exclude(void)
{
    int i;
    int ret;
    int bytes;
    char p[512];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    int got;
    int n_loop = 256;
    int not_used = 0;
    struct flb_lib_out_cb cb_data;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Exclude", "log deprecated",
                         "Exclude", "log other",
                         "Logical_Op", "OR",
                         NULL);
    TEST_CHECK(ret == 0);

    clear_output_num();

    ret = flb_start(ctx);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        exit(EXIT_FAILURE);
    }

    /* Ingest 2 records per loop. One of them should be excluded. */
    for (i = 0; i < n_loop; i++) {
        memset(p, '\0', sizeof(p));
        /* Below record will be included */
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"log\": \"Using deprecated option\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));

        /* Below record will be excluded */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"log\": \"Using option\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500); /* waiting flush */

    got = get_output_num();
    if (!TEST_CHECK(got == n_loop)) {
        TEST_MSG("expect: %d got: %d", n_loop, got);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"regex",   flb_test_filter_grep_regex   },
    {"exclude", flb_test_filter_grep_exclude },
    {"invalid", flb_test_filter_grep_invalid },
    {"multi_regex", flb_test_filter_grep_multi_regex },
    {"multi_exclude", flb_test_filter_grep_multi_exclude },
    {"unknown_property", flb_test_filter_grep_unknown_property },
    {"AND_regex", flb_test_AND_regex},
    {"OR_regex", flb_test_OR_regex},
    {"AND_exclude", flb_test_AND_exclude},
    {"OR_exclude", flb_test_OR_exclude},
    {"error_OR_regex_exclude", flb_test_error_OR_regex_exclude},
    {"error_AND_regex_exclude", flb_test_error_AND_regex_exclude},
    {"error_OR_regex_exclude", flb_test_error_OR_regex_exclude},
    {"issue_5209", flb_test_issue_5209 },
    {NULL, NULL}
};
