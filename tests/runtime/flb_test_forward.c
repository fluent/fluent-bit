/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/common/json_long.h"    /* JSON_LONG    */

/* Test functions */
void flb_test_fluentd_json_long(void);

/* Test list */
TEST_LIST = {
    {"json_long",       flb_test_fluentd_json_long    },
    {NULL, NULL}
};

void flb_test_fluentd_json_long(void)
{
    int ret;
    int size = sizeof(JSON_LONG) - 1;
    int bytes;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "forward://127.0.0.1:24224", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, (char *)JSON_LONG, size);
    TEST_CHECK(bytes == size);

    flb_stop(ctx);
    flb_destroy(ctx);
}
