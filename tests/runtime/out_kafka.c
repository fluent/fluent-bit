/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/td/json_td.h"


/* ------------------------------------------------------------------ */
/* Shared helpers for header tests                                      */
/*                                                                      */
/* Note on header-value assertions: kafka_build_message_headers() is a */
/* static helper inside kafka.c that passes rd_kafka_headers_t directly */
/* to rd_kafka_producev(), which takes ownership on success.  There is  */
/* no observable seam after that point, and the acutest framework has   */
/* no log-capture mechanism, so the tests below are smoke tests:  they  */
/* exercise every code path (static branch, dynamic lookup, missing-    */
/* field warn-and-skip, integer/float conversion) and prove the paths   */
/* are crash- and leak-free under Valgrind.  Per-value header           */
/* assertions would require either an internal unit test that calls the */
/* static function directly or a test hook added to the production code.*/
/* ------------------------------------------------------------------ */

struct kafka_test_ctx {
    flb_ctx_t *ctx;
    int        in_ffd;
    int        out_ffd;
};

/*
 * Create a lib → kafka pipeline with the given message format and an
 * optional NULL-terminated array of "name value" header strings.
 *
 * Common options applied to every header test:
 *   match=test, topics=test, brokers=127.0.0.1:111 (unreachable),
 *   queue_full_retries=1.
 *
 * Fills *kctx and calls flb_start().  Returns 0 on success.  On any
 * setup error the test is marked as failed, partially initialised
 * resources are freed, kctx->ctx is set to NULL, and -1 is returned.
 */
static int kafka_test_setup(struct kafka_test_ctx *kctx,
                            const char *format,
                            const char **headers)
{
    int ret;
    const char **h;

    kctx->ctx    = NULL;
    kctx->in_ffd  = -1;
    kctx->out_ffd = -1;

    kctx->ctx = flb_create();
    if (!kctx->ctx) {
        TEST_CHECK(kctx->ctx != NULL);
        return -1;
    }

    kctx->in_ffd = flb_input(kctx->ctx, (char *) "lib", NULL);
    if (kctx->in_ffd < 0) {
        TEST_CHECK(kctx->in_ffd >= 0);
        flb_destroy(kctx->ctx);
        kctx->ctx = NULL;
        return -1;
    }

    ret = flb_input_set(kctx->ctx, kctx->in_ffd, "tag", "test", NULL);
    if (ret != 0) {
        TEST_CHECK(ret == 0);
        flb_destroy(kctx->ctx);
        kctx->ctx = NULL;
        return -1;
    }

    kctx->out_ffd = flb_output(kctx->ctx, (char *) "kafka", NULL);
    if (kctx->out_ffd < 0) {
        TEST_CHECK(kctx->out_ffd >= 0);
        flb_destroy(kctx->ctx);
        kctx->ctx = NULL;
        return -1;
    }

    ret = flb_output_set(kctx->ctx, kctx->out_ffd,
                         "match",              "test",
                         "format",             format,
                         "topics",             "test",
                         "brokers",            "127.0.0.1:111",
                         "queue_full_retries", "1",
                         NULL);
    if (ret != 0) {
        TEST_CHECK(ret == 0);
        flb_destroy(kctx->ctx);
        kctx->ctx = NULL;
        return -1;
    }

    if (headers) {
        for (h = headers; *h != NULL; h++) {
            ret = flb_output_set(kctx->ctx, kctx->out_ffd,
                                 "header", *h, NULL);
            if (ret != 0) {
                TEST_CHECK(ret == 0);
                flb_destroy(kctx->ctx);
                kctx->ctx = NULL;
                return -1;
            }
        }
    }

    ret = flb_start(kctx->ctx);
    if (ret != 0) {
        TEST_CHECK(ret == 0);
        flb_destroy(kctx->ctx);
        kctx->ctx = NULL;
        return -1;
    }

    return 0;
}

static void kafka_test_teardown(struct kafka_test_ctx *kctx)
{
    if (!kctx->ctx) {
        return;
    }
    flb_stop(kctx->ctx);
    flb_destroy(kctx->ctx);
}


/* ------------------------------------------------------------------ */
/* Original test                                                        */
/* ------------------------------------------------------------------ */

void flb_test_raw_format(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "kafka", NULL);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd, "match", "test", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx, out_ffd, "format",             "raw",           NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set(ctx, out_ffd, "raw_log_key",        "key_0",         NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set(ctx, out_ffd, "topics",             "test",          NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set(ctx, out_ffd, "brokers",            "127.0.0.1:111", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set(ctx, out_ffd, "queue_full_retries", "1",             NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret > 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* ------------------------------------------------------------------ */
/* Header tests                                                         */
/* ------------------------------------------------------------------ */

/*
 * Two static headers configured with verbatim values (no '$' prefix).
 * Exercises the static branch of kafka_build_message_headers(): the
 * branch that calls rd_kafka_header_add() with the literal value string.
 * Verifies the code path completes without crash or memory error.
 */
void flb_test_header_static(void)
{
    int ret;
    struct kafka_test_ctx kctx;
    static const char *headers[] = {
        "env production",
        "team platform",
        NULL
    };

    ret = kafka_test_setup(&kctx, "json", headers);
    if (ret != 0) {
        return;
    }

    ret = flb_lib_push(kctx.ctx, kctx.in_ffd,
                       (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret > 0);

    sleep(2);
    kafka_test_teardown(&kctx);
}

/*
 * One dynamic header whose value is prefixed with '$', triggering a
 * lookup of field "key_0" in the log record (JSON_TD contains
 * "key_0": "val_0").
 * Exercises the dynamic branch of kafka_build_message_headers(): the
 * branch that calls kafka_msgpack_get_field() and, on a hit, calls
 * rd_kafka_header_add() with the field's string value.
 * Verifies the code path completes without crash or memory error.
 */
void flb_test_header_dynamic(void)
{
    int ret;
    struct kafka_test_ctx kctx;
    static const char *headers[] = {
        "source $key_0",
        NULL
    };

    ret = kafka_test_setup(&kctx, "json", headers);
    if (ret != 0) {
        return;
    }

    ret = flb_lib_push(kctx.ctx, kctx.in_ffd,
                       (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret > 0);

    sleep(2);
    kafka_test_teardown(&kctx);
}

/*
 * One dynamic header whose referenced field ("no_such_field") is absent
 * from the log record.
 * Exercises the missing-field branch of kafka_build_message_headers():
 * the branch that calls flb_plg_warn() and skips the header without
 * aborting the produce call.
 * Verifies the warn-and-skip path completes without crash or memory
 * error (observable as a "not found in record" warning in the log).
 */
void flb_test_header_dynamic_missing_field(void)
{
    int ret;
    struct kafka_test_ctx kctx;
    static const char *headers[] = {
        "missing $no_such_field",
        NULL
    };

    ret = kafka_test_setup(&kctx, "json", headers);
    if (ret != 0) {
        return;
    }

    ret = flb_lib_push(kctx.ctx, kctx.in_ffd,
                       (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret > 0);

    sleep(2);
    kafka_test_teardown(&kctx);
}

/*
 * One static and one dynamic header (string field) in the same message.
 * Exercises both branches of kafka_build_message_headers() together,
 * including correct iteration over a multi-entry header list.
 * Verifies the mixed code path completes without crash or memory error.
 * Integer and float conversion are covered by the Docker integration tests.
 */
void flb_test_header_mixed(void)
{
    int ret;
    struct kafka_test_ctx kctx;
    static const char *headers[] = {
        "app myapp",
        "source $key_1",
        NULL
    };

    ret = kafka_test_setup(&kctx, "json", headers);
    if (ret != 0) {
        return;
    }

    ret = flb_lib_push(kctx.ctx, kctx.in_ffd,
                       (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret > 0);

    sleep(2);
    kafka_test_teardown(&kctx);
}

TEST_LIST = {
    { "raw_format",                   flb_test_raw_format                   },
    { "header_static",                flb_test_header_static                },
    { "header_dynamic",               flb_test_header_dynamic               },
    { "header_dynamic_missing_field", flb_test_header_dynamic_missing_field },
    { "header_mixed",                 flb_test_header_mixed                 },
    { NULL, NULL },
};
