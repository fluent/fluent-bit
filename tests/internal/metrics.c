/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_metrics.h>

#include "flb_tests_internal.h"

static void test_create_usage()
{
    int ret;
    int id_1;
    int id_2;
    int id_3;
    struct flb_metric *m;
    struct flb_metrics *ctx;

    /* Create and destroy */
    ctx = flb_metrics_create("metrics");
    TEST_CHECK(ctx != NULL);
    ret = flb_metrics_destroy(ctx);
    TEST_CHECK(ret == 0);

    /* Register one metric */
    ctx = flb_metrics_create("metrics");
    id_1 = flb_metrics_add(-1, "sample", ctx);
    TEST_CHECK(id_1 == 0);
    ret = flb_metrics_destroy(ctx);
    TEST_CHECK(ret == 1);

    /* Duplicate metric ID, it should fail */
    ctx = flb_metrics_create("metrics");
    id_1 = flb_metrics_add(-1, "sample 1", ctx);
    id_2 = flb_metrics_add(0, "sample 2", ctx);
    TEST_CHECK(id_2 == -1);
    ret = flb_metrics_destroy(ctx);
    TEST_CHECK(ret == 1);

    /* Auto ID  */
    ctx = flb_metrics_create("ctx");
    id_1 = flb_metrics_add(-1, "sample 1", ctx);
    id_2 = flb_metrics_add(-1, "sample 2", ctx);
    id_3 = flb_metrics_add(-1, "sample 3", ctx);
    TEST_CHECK(id_1 == 0);
    TEST_CHECK(id_2 == 1);
    TEST_CHECK(id_3 == 2);
    ret = flb_metrics_destroy(ctx);
    TEST_CHECK(ret == 3);

    /* Update values */
    ctx = flb_metrics_create("ctx");
    id_1 = flb_metrics_add(-1, "sample 1", ctx);
    id_2 = flb_metrics_add(-1, "sample 2", ctx);
    id_3 = flb_metrics_add(5, "sample 3", ctx);
    TEST_CHECK(id_1 == 0);
    TEST_CHECK(id_2 == 1);
    TEST_CHECK(id_3 == 5);

    ret = flb_metrics_sum(id_1, 2001, ctx);
    TEST_CHECK(ret == 0);

    ret = flb_metrics_sum(id_2, 2017, ctx);
    TEST_CHECK(ret == 0);

    ret = flb_metrics_sum(1234, 0, ctx);
    TEST_CHECK(ret == -1);

    ret = flb_metrics_sum(id_3, 1, ctx);
    TEST_CHECK(ret == 0);

    m = flb_metrics_get_id(id_3, ctx);
    TEST_CHECK(m != NULL);
    TEST_CHECK(m->val == 1);

    ret = flb_metrics_destroy(ctx);
    TEST_CHECK(ret == 3);
}

TEST_LIST = {
    { "create_usage", test_create_usage},
    { 0 }
};
