/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_config_format.h>

#include "flb_tests_internal.h"

#define FLB_000 FLB_TESTS_DATA_PATH "/data/config_format/fluent-bit.yaml"

/* data/config_format/fluent-bit.yaml */
void test_basic()
{
	struct flb_cf *cf;

    cf = flb_cf_yaml_create(FLB_000, NULL, 0);
    TEST_CHECK(cf != NULL);
    if (!cf) {
        exit(EXIT_FAILURE);
    }

    /* Total number of sections */
    TEST_CHECK(mk_list_size(&cf->sections) == 9);

	/* SERVICE check */
    TEST_CHECK(cf->service != NULL);

    if (cf->service) {
        TEST_CHECK(mk_list_size(&cf->service->properties) == 3);
    }

    /* Check number sections per list */
    TEST_CHECK(mk_list_size(&cf->parsers) == 0);
    TEST_CHECK(mk_list_size(&cf->multiline_parsers) == 0);
    TEST_CHECK(mk_list_size(&cf->customs) == 1);
    TEST_CHECK(mk_list_size(&cf->inputs) == 3);
    TEST_CHECK(mk_list_size(&cf->filters) == 1);
    TEST_CHECK(mk_list_size(&cf->outputs) == 2);
    TEST_CHECK(mk_list_size(&cf->others) == 1);

    printf("\n");
    flb_cf_dump(cf);

    flb_cf_destroy(cf);


}

TEST_LIST = {
    { "basic"    , test_basic},
    { 0 }
};
