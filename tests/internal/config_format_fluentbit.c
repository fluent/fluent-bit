/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_config_format.h>

#include "flb_tests_internal.h"

#define FLB_000 FLB_TESTS_DATA_PATH "/data/config_format/classic/fluent-bit.conf"
#define FLB_GLOB FLB_TESTS_DATA_PATH "/data/config_format/classic/fluent-bit-include-order.conf"

/* data/config_format/fluent-bit.conf */
void test_basic()
{
    struct mk_list *head;
	struct flb_cf *cf;
    struct flb_cf_section *s;
    struct flb_cf_group *g;

    cf = flb_cf_fluentbit_create(NULL, FLB_000, NULL, 0);
    TEST_CHECK(cf != NULL);

    /* Total number of sections */
    TEST_CHECK(mk_list_size(&cf->sections) == 8);

	/* SERVICE check */
    TEST_CHECK(cf->service != NULL);
    if (cf->service) {
        TEST_CHECK(mk_list_size(&cf->service->properties) == 3);
    }

    /* Meta commands */
    TEST_CHECK(mk_list_size(&cf->metas) == 2);

    /* Check number sections per list */
    TEST_CHECK(mk_list_size(&cf->parsers) == 1);
    TEST_CHECK(mk_list_size(&cf->multiline_parsers) == 1);
    TEST_CHECK(mk_list_size(&cf->customs) == 1);
    TEST_CHECK(mk_list_size(&cf->inputs) == 1);
    TEST_CHECK(mk_list_size(&cf->filters) == 1);
    TEST_CHECK(mk_list_size(&cf->outputs) == 1);
    TEST_CHECK(mk_list_size(&cf->others) == 1);

    /* groups */
    s = flb_cf_section_get_by_name(cf, "input");
    TEST_CHECK(s != NULL);
    TEST_CHECK(mk_list_size(&s->groups) == 2);

    mk_list_foreach(head, &s->groups) {
        g = mk_list_entry(head, struct flb_cf_group, _head);
        TEST_CHECK(mk_list_size(&g->properties) == 2);
    }

    printf("\n");
    flb_cf_dump(cf);

    flb_cf_destroy(cf);
}

/* data/config_format/fluent-bit-include-order.conf */
void test_include_glob_order()
{
    struct mk_list *head;
	struct flb_cf *cf;
    struct flb_cf_section *filter;
    char tmp[3];
    char *alias;
    int idx = 0;

    cf = flb_cf_fluentbit_create(NULL, FLB_GLOB, NULL, 0);
    TEST_CHECK(cf != NULL);

    /* Total number of sections */
    TEST_CHECK(mk_list_size(&cf->sections) == 6);

    /* Check number of filters */
    TEST_CHECK(mk_list_size(&cf->filters) == 3);

    mk_list_foreach(head, &cf->filters) {
        filter = mk_list_entry(head, struct flb_cf_section, _head_section);
        sprintf(tmp, "f%i", ++idx);
        alias = flb_cf_section_property_get(cf, filter, "alias");
        TEST_CHECK(strcmp(tmp, alias) == 0);
    }

    printf("\n");
    flb_cf_dump(cf);

    flb_cf_destroy(cf);
}

TEST_LIST = {
    { "basic"                      , test_basic},
    { "test_include_glob_order"    , test_include_glob_order},
    { 0 }
};
