/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

struct filter_test {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd */
};

/* Callback to check expected results */
static int cb_check_result(void *record, size_t size, void *data)
{
    char *p;
    char *expected;
    char *result;

    expected = (char *) data;
    result = (char *) record;

    p = strstr(result, expected);
    TEST_CHECK(p != NULL);

    if (!p) {
        flb_error("Expected to find: '%s' in result '%s'",
                  expected, result);
    }
    /*
     * If you want to debug your test
     *
     * printf("Expect: '%s' in result '%s'", expected, result);
     */

    flb_free(record);
    return 0;
}



static struct filter_test *filter_test_create(struct flb_lib_out_cb *data)
{
    int i_ffd;
    int f_ffd;
    int o_ffd;
    struct filter_test *ctx;

    ctx = flb_malloc(sizeof(struct filter_test));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* Service config */
    ctx->flb = flb_create();
    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    NULL);

    /* Input */
    i_ffd = flb_input(ctx->flb, (char *) "lib", NULL);
    TEST_CHECK(i_ffd >= 0);
    flb_input_set(ctx->flb, i_ffd, "tag", "test", NULL);
    ctx->i_ffd = i_ffd;

    /* Filter configuration */
    f_ffd = flb_filter(ctx->flb, (char *) "modify", NULL);
    TEST_CHECK(f_ffd >= 0);
    flb_filter_set(ctx->flb, f_ffd, "match", "*", NULL);
    ctx->f_ffd = f_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    TEST_CHECK(o_ffd >= 0);
    flb_output_set(ctx->flb, o_ffd,
                   "match", "test",
                   "format", "json",
                   NULL);

    return ctx;
}

static void filter_test_destroy(struct filter_test *ctx)
{
    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

/* Operation: SET / append new record */
static void flb_test_op_set_append()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "set", "test_key test_value",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"test_key\":\"test_value\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"k\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Operation: SET / replace value of existing key */
static void flb_test_op_set_replace()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "set", "k test_value",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"k\":\"test_value\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"k\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Operation: REMOVE */
static void flb_test_op_remove()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "remove", "remove",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"k\":\"sample\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"k\":\"sample\",\"remove\":\"sample to remove\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Operation: REMOVE_WILDCARD */
static void flb_test_op_remove_wildcard()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "remove_wildcard", "k",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"a3\":\"sample3\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"sample1\",\"k2\":\"sample2\",\"a3\":\"sample3\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Operation: REMOVE_REGEX */
static void flb_test_op_remove_regex()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "remove_regex", "^[a-z][0-9]$",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"A3\":\"sample3\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"sample1\",\"k2\":\"sample2\",\"A3\":\"sample3\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/*
 * Operation: RENAME / Try to rename Key where 'renamed' key already
 * exists: do nothing.
 */
static void flb_test_op_rename_exists()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "rename", "A3 k2",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"k1\":\"sample1\",\"k2\":\"sample2\",\"A3\":\"sample3\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"sample1\",\"k2\":\"sample2\",\"A3\":\"sample3\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Operation: RENAME / Rename when key DON'T exists */
static void flb_test_op_rename_no_exists()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "rename", "A3 a3",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"k1\":\"sample1\",\"k2\":\"sample2\",\"a3\":\"sample3\"";
    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"sample1\",\"k2\":\"sample2\",\"A3\":\"sample3\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/*
 * Operation: HARD_RENAME / Try to rename Key where 'renamed' key already
 * exists: do nothing.
 */
static void flb_test_op_hard_rename_exists()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "hard_rename", "k2 k1",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"k1\":\"sample2\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"sample1\",\"k2\":\"sample2\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Operation: HARD_RENAME / Rename when key DON'T exists */
static void flb_test_op_hard_rename_no_exists()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "hard_rename", "k2 k3",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"k3\":\"sample2\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"sample1\",\"k2\":\"sample2\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Operation: COPY / Target key already exists, do nothing */
static void flb_test_op_copy_exists()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "copy", "k1 k2",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"k1\":\"sample1\",\"k2\":\"sample2\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"sample1\",\"k2\":\"sample2\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Operation: COPY / Target key no exists, make a copy */
static void flb_test_op_copy_no_exists()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "copy", "k1 k3",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"k3\":\"sample1\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"sample1\",\"k2\":\"sample2\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Operation: HARD_COPY / if target key exists, replace value */
static void flb_test_op_hard_copy_exists()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "hard_copy", "k1 k2",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"k1\":\"sample1\",\"k2\":\"sample1\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"k1\":\"sample1\",\"k2\":\"sample2\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Operation: HARD_COPY / if key don't exists make a copy */
static void flb_test_op_hard_copy_no_exists()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "hard_copy", "k1 k3",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"k3\":\"sample1\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"sample1\",\"k2\":\"sample2\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}


/* Condition: KEY_EXISTS / If key exists, make a copy */
static void flb_test_cond_key_exists()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition", "key_exists k1",
                         "copy", "k1 k3_copy",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"k3_copy\":\"sample1\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"sample1\",\"k2\":\"sample2\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Condition: KEY_EXISTS / If nested key exists, make a copy */
static void flb_test_cond_key_exists_nest()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition", "key_exists $nest['k1']",
                         "add", "key found",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"key\":\"found\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"sample1\",\"k2\":\"sample2\", \"nest\":{\"k1\":\"nest\"}}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Condition: KEY_DOES_NOT_EXISTS / If key does not exists, add a dummy key */
static void flb_test_cond_key_does_not_exist()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition", "key_does_not_exist k3",
                         "copy", "k1 k3",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"k3\":\"sample1\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"sample1\",\"k2\":\"sample2\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Condition: KEY_DOES_NOT_EXISTS / If key does not exists, add a dummy key */
static void flb_test_cond_key_does_not_exist_nest()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition", "key_does_not_exist $nest['k1']",
                         "add", "key not_found",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"key\":\"not_found\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"sample1\",\"k2\":\"sample2\", \"nest\":{\"k\":\"sample\"}}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Condition: A_KEY_MATCHES / If key matches, add a dummy key */
static void flb_test_cond_a_key_matches()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition", "a_key_matches ^[a-z][0-9]$",
                         "copy", "c1 c1_matched",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"c1_matched\":\"sample3\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"aa\":\"sample1\",\"bb\":\"sample2\",\"c1\":\"sample3\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Condition: NO_KEY_MATCHES / If no key matches, add a dummy key */
static void flb_test_cond_no_key_matches()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition", "no_key_matches ^[0-9]$",
                         "copy", "c1 no_matches",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"no_matches\":\"sample3\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"aa\":\"sample1\",\"bb\":\"sample2\",\"c1\":\"sample3\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Condition: KEY_VALUE_EQUALS / If key value matches, add a dummy key */
static void flb_test_cond_key_value_equals()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition", "key_value_equals bb sample2",
                         "copy", "c1 no_matches",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"no_matches\":\"sample3\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"aa\":\"sample1\",\"bb\":\"sample2\",\"c1\":\"sample3\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Condition: KEY_VALUE_EQUALS / If key value matches, add a dummy key */
static void flb_test_cond_key_value_equals_nest()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition", "key_value_equals $nest['k1'] sample2",
                         "add", "key found",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"key\":\"found\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"aa\":\"sample1\",\"bb\":\"sample2\",\"c1\":\"sample3\", \"nest\":{\"k1\":\"sample2\"}}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Condition: KEY_VALUE_DOES_NOT_EQUAL / If key value mismatch, add a key */
static void flb_test_cond_key_value_does_not_equal()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition", "key_value_does_not_equal bb sample3",
                         "copy", "c1 no_matches",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"no_matches\":\"sample3\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"aa\":\"sample1\",\"bb\":\"sample2\",\"c1\":\"sample3\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Condition: KEY_VALUE_DOES_NOT_EQUAL / If key value mismatch, add a key */
static void flb_test_cond_key_value_does_not_equal_nest()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition", "key_value_does_not_equal $nest['k1'] sample2",
                         "add", "key not_found",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"key\":\"not_found\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"aa\":\"sample1\",\"bb\":\"sample2\",\"c1\":\"sample3\", \"nest\":{\"k1\":\"sample3\"}}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Condition: KEY_VALUE_MATCHES / If key match, add a key */
static void flb_test_cond_key_value_matches()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition", "key_value_matches k2 ^[a-z][0-9]$",
                         "copy", "k1 matches",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"matches\":\"sample1\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"sample1\",\"k2\":\"z2\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Condition: KEY_VALUE_MATCHES / If key match, add a key */
static void flb_test_cond_key_value_matches_nest()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition", "key_value_matches $nest['k2'] ^[a-z][0-9]$",
                         "add", "kv matches",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"kv\":\"matches\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"sample1\",\"k2\":\"z2\", \"nest\":{\"k2\":\"z2\"}}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Condition: KEY_VALUE_DOES_NOT_MATCH / If key mismatch, add a key */
static void flb_test_cond_key_value_does_not_match()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition", "key_value_does_not_match k2 ^[a-z][0-9]$",
                         "copy", "k1 no_matches",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"no_matches\":\"sample1\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"sample1\",\"k2\":\"22\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Condition: KEY_VALUE_DOES_NOT_MATCH / If key mismatch, add a key */
static void flb_test_cond_key_value_does_not_match_nest()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition", "key_value_does_not_match $nest['k2'] ^[a-z][0-9]$",
                         "add", "kv no_matches",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"kv\":\"no_matches\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"sample1\",\"k2\":\"22\",\"nest\":{\"k2\":\"22\"}}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Condition: MATCHING_KEYS_HAVE_MATCHING_VALUES / If key match, add a key */
static void flb_test_cond_matching_keys_have_matching_values()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition",
                         "matching_keys_have_matching_values "\
                         "^[a-z][0-9]$ ^[a-z][0-9]$",
                         "copy", "k1 matches",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"matches\":\"n1\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"n1\",\"k2\":\"n3\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Condition: MATCHING_KEYS_DOES_NOT_HAVE_MATCHING_VALUES */
static void flb_test_cond_matching_keys_do_not_have_matching_values()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition",
                         "matching_keys_do_not_have_matching_values "\
                         "^[a-z][0-9]$ ^[a-z][0-9]$",
                         "copy", "k1 no_matches",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"no_matches\":\"aa\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"aa\",\"k2\":\"bb\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Test all operations */
static void flb_test_cond_chain()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition", "key_exists k1",
                         "condition", "key_does_not_exist k2",
                         "add", "k2 sample_2",
                         "condition", "a_key_matches ^[a-z]1$",
                         "add", "k3 3",
                         "condition", "no_key_matches ^[0-9]$",
                         "condition", "key_value_equals k1 sample",
                         "add", "k4 4",
                         "condition", "key_value_does_not_equal k1 sampl",
                         "condition", "key_value_matches k1 ^[a-z]+$",
                         "condition", "key_value_does_not_match k1 aa",

                         "condition",
                         "matching_keys_have_matching_values " \
                         "^[a-z][0-9]$ ^[a-z]+$",

                         "condition",
                         "matching_keys_do_not_have_matching_values "   \
                         "^[a-z][0-9]$ ^[a-z][0-9]$",

                         "add", "k5 5",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"k5\":\"5\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"k1\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}


pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int  num_output = 0;


static void add_output_num()
{
    pthread_mutex_lock(&result_mutex);
    num_output++;
    pthread_mutex_unlock(&result_mutex);
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

static int callback_count(void* data, size_t size, void* cb_data)
{
    if (size > 0) {
        flb_debug("[test_filter_modify] received message: %s", (char*)data);
        add_output_num(); /* success */
        flb_free(data);
    }
    return 0;
}


// to check issue https://github.com/fluent/fluent-bit/issues/1077
static void flb_test_not_drop_multi_event()
{
    int count = 0;
    int expected = 3;

    char *p;
    int len;
    int ret;
    int bytes;

    struct filter_test *ctx;
    struct flb_lib_out_cb cb_data;


    clear_output_num();
    cb_data.cb = callback_count;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition", "key_value_equals cond true",
                         "add", "data matched",
                         NULL);
    TEST_CHECK(ret == 0);

        /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest multiple events */
    p = "[0, {\"cond\":\"false\", \"data\": \"something\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    p = "[0, {\"cond\":\"true\", \"data\": \"something\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    p = "[0, {\"data\": \"something\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    sleep(1); /* waiting flush */
    count = get_output_num();

    TEST_CHECK_(count == expected, "Expected number of events %d, got %d", expected, count );


    filter_test_destroy(ctx);

}

/* to check issue https://github.com/fluent/fluent-bit/issues/4319 */
static void flb_test_issue_4319()
{
    char *p;
    int len;
    int ret;
    int bytes;

    struct filter_test *ctx;
    struct flb_lib_out_cb cb_data;


    clear_output_num();

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"ok\":\"sample\"";

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         /* set key which doesn't exist */
                         "condition", "key_value_does_not_equal aaa sample",
                         "rename", "ok error",
                         NULL);
    TEST_CHECK(ret == 0);

        /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest event */
    p = "[0, {\"ok\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    sleep(1); /* waiting flush */

    filter_test_destroy(ctx);
}


/*
 * to check issue https://github.com/fluent/fluent-bit/issues/4319
   Key_value_does_not_match case
*/
static void flb_test_issue_4319_2()
{
    char *p;
    int len;
    int ret;
    int bytes;

    struct filter_test *ctx;
    struct flb_lib_out_cb cb_data;


    clear_output_num();

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"ok\":\"sample\"";

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         /* set key which doesn't exist */
                         "condition", "key_value_does_not_match aaa sample",
                         "rename", "ok error",
                         NULL);
    TEST_CHECK(ret == 0);

        /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest event */
    p = "[0, {\"ok\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    sleep(1); /* waiting flush */

    filter_test_destroy(ctx);
}

/* https://github.com/fluent/fluent-bit/issues/1225 */
static void flb_test_issue_1225()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "condition", "key_value_matches \"key 1\" \".*with spaces.*\"",
                         "add", "\"key 2\" \"second value with spaces\"",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"key 1\":\"first value with spaces\","\
                   "\"key 2\":\"second value with spaces\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0,{\"key 1\":\"first value with spaces\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}


/*
 * to check issue https://github.com/fluent/fluent-bit/issues/7075
*/
static void flb_test_issue_7075()
{
    char *p;
    int len;
    int ret;
    int bytes;

    struct filter_test *ctx;
    struct flb_lib_out_cb cb_data;

    clear_output_num();

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"matched\":true";

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         /* set key which doesn't exist */
                         "condition", "key_value_matches ok true",
                         "rename", "ok matched",
                         NULL);
    TEST_CHECK(ret == 0);

        /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest event */
    p = "[0, {\"ok\":true}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    sleep(1); /* waiting flush */

    filter_test_destroy(ctx);
}

static void flb_test_issue_7368()
{
    int ret;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "remove_wildcard", "*s3",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"r1\":\"someval\"";

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret != 0);

    if (ret == 0) {
        filter_test_destroy(ctx);
    }
    else {
        flb_destroy(ctx->flb);
        flb_free(ctx);
    }
}

TEST_LIST = {
    /* Operations / Commands */
    {"op_set_append"            , flb_test_op_set_append },
    {"op_set_replace"           , flb_test_op_set_replace },
    {"op_remove"                , flb_test_op_remove },
    {"op_remove_wildcard"       , flb_test_op_remove_wildcard },
    {"op_remove_regex"          , flb_test_op_remove_regex },
    {"op_rename_exists"         , flb_test_op_rename_exists },
    {"op_rename_no_exists"      , flb_test_op_rename_no_exists },
    {"op_hard_rename_exists"    , flb_test_op_hard_rename_exists },
    {"op_hard_rename_no_exists" , flb_test_op_hard_rename_no_exists },
    {"op_copy_exists"           , flb_test_op_copy_exists },
    {"op_copy_no_exists"        , flb_test_op_copy_no_exists },
    {"op_hard_copy_exists"      , flb_test_op_hard_copy_exists },
    {"op_hard_copy_no_exists"   , flb_test_op_hard_copy_no_exists },

    /* Conditions (nested) */
    {"cond_key_value_matches_nest", flb_test_cond_key_value_matches_nest },
    {"cond_key_value_does_not_match_nest", flb_test_cond_key_value_does_not_match_nest },
    {"cond_key_exists_nest", flb_test_cond_key_exists_nest },
    {"cond_key_does_not_exist_nest", flb_test_cond_key_does_not_exist_nest },
    {"cond_key_value_equals_nest", flb_test_cond_key_value_equals_nest },
    {"cond_key_value_does_not_equal_nest", flb_test_cond_key_value_does_not_equal_nest },

    /* Conditions */
    {"cond_key_exists", flb_test_cond_key_exists },
    {"cond_key_does_not_exist", flb_test_cond_key_does_not_exist },
    {"cond_a_key_matches", flb_test_cond_a_key_matches },
    {"cond_no_key_matches", flb_test_cond_no_key_matches },
    {"cond_key_value_equals", flb_test_cond_key_value_equals },
    {"cond_key_value_does_not_equal", flb_test_cond_key_value_does_not_equal },
    {"cond_key_value_matches", flb_test_cond_key_value_matches },
    {"cond_key_value_does_not_match", flb_test_cond_key_value_does_not_match },
    {"cond_matching_keys_have_matching_values",
     flb_test_cond_matching_keys_have_matching_values },
    {"cond_matching_keys_do_not_have_matching_values",
     flb_test_cond_matching_keys_do_not_have_matching_values },
    {"cond_chain", flb_test_cond_chain },

    /* Bug fixes */
    {"multiple events are not dropped", flb_test_not_drop_multi_event },
    {"cond_key_value_does_not_equal and key does not exist", flb_test_issue_4319 },
    {"cond_key_value_does_not_matches and key does not exist", flb_test_issue_4319_2 },
    {"Key_value_matches and value is bool type", flb_test_issue_7075},
    {"operation_with_whitespace", flb_test_issue_1225 },
    {"invalid_wildcard", flb_test_issue_7368 },

    {NULL, NULL}
};
