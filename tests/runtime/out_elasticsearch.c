/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/es/json_es.h" /* JSON_ES */

/* Test functions */
void flb_test_es_json_es(void);

/* Test list */
TEST_LIST = {
    {"json_es", flb_test_es_json_es },
    {NULL, NULL}
};

void flb_test_es_json_es(void)
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "es", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    flb_stop(ctx);
    flb_destroy(ctx);
}
