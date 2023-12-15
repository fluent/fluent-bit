/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_config_format.h>

#include <cfl/cfl.h>
#include <cfl/cfl_list.h>

#include "flb_tests_internal.h"

#define FLB_TESTS_CONF_PATH FLB_TESTS_DATA_PATH "/data/config_format/yaml"
#define FLB_000 FLB_TESTS_CONF_PATH "/fluent-bit.yaml"
#define FLB_001 FLB_TESTS_CONF_PATH "/issue_7559.yaml"
#define FLB_002 FLB_TESTS_CONF_PATH "/processors.yaml"

/*
 * Configurations to test:
 *  * basic single input to single output
 *  * basic single input to single output with a filter
 *  * includes
 *  * slist
 *  * conf parsers
 *  * yaml parsers
 *  * customs
 *  * service
 *  * env
 */

/* data/config_format/fluent-bit.yaml */
static void test_basic()
{
    struct mk_list *head;
    struct flb_cf *cf;
    struct flb_cf_section *s;
    struct flb_cf_group *g;
    struct cfl_variant *v;
    int idx = 0;

    cf = flb_cf_yaml_create(NULL, FLB_000, NULL, 0);
    TEST_CHECK(cf != NULL);
    if (!cf) {
        exit(EXIT_FAILURE);
    }

    /* Total number of sections */
    TEST_CHECK(mk_list_size(&cf->sections) == 9);

    /* SERVICE check */
    TEST_CHECK(cf->service != NULL);
    if (cf->service) {
        TEST_CHECK(cfl_list_size(&cf->service->properties->list) == 3);
    }

    /* Check number sections per list */
    TEST_CHECK(mk_list_size(&cf->parsers) == 0);
    TEST_CHECK(mk_list_size(&cf->multiline_parsers) == 0);
    TEST_CHECK(mk_list_size(&cf->customs) == 1);
    TEST_CHECK(mk_list_size(&cf->inputs) == 3);
    TEST_CHECK(mk_list_size(&cf->filters) == 1);
    TEST_CHECK(mk_list_size(&cf->outputs) == 2);
    TEST_CHECK(mk_list_size(&cf->others) == 1);

    /* check inputs */
    idx = 0;
    mk_list_foreach(head, &cf->inputs) {
        s = mk_list_entry(head, struct flb_cf_section, _head_section);
        switch (idx) {
        case 0:
            v = flb_cf_section_property_get(cf, s, "name");
            TEST_CHECK(v->type == CFL_VARIANT_STRING);
            TEST_CHECK(strcmp(v->data.as_string, "dummy") == 0);
            break;
        case 1:
            v = flb_cf_section_property_get(cf, s, "name");
            TEST_CHECK(v->type == CFL_VARIANT_STRING);
            TEST_CHECK(strcmp(v->data.as_string, "tail") == 0);
            v = flb_cf_section_property_get(cf, s, "path");
            TEST_CHECK(v->type == CFL_VARIANT_STRING);
            TEST_CHECK(strcmp(v->data.as_string, "./test.log") == 0);
            break;
        case 2:
            v = flb_cf_section_property_get(cf, s, "name");
            TEST_CHECK(v->type == CFL_VARIANT_STRING);
            TEST_CHECK(strcmp(v->data.as_string, "tail") == 0);
            v = flb_cf_section_property_get(cf, s, "path");
            TEST_CHECK(v->type == CFL_VARIANT_STRING);
            TEST_CHECK(strcmp(v->data.as_string, "./test.log") == 0);
            break;
        }
        idx++;
    }

    /* check outputs */
    idx = 0;
    mk_list_foreach(head, &cf->outputs) {
        s = mk_list_entry(head, struct flb_cf_section, _head_section);
        switch (idx) {
        case 0:
            v = flb_cf_section_property_get(cf, s, "name");
            TEST_CHECK(v->type == CFL_VARIANT_STRING);
            TEST_CHECK(strcmp(v->data.as_string, "stdout") == 0);
            break;
        case 1:
            v = flb_cf_section_property_get(cf, s, "name");
            TEST_CHECK(v->type == CFL_VARIANT_STRING);
            TEST_CHECK(strcmp(v->data.as_string, "stdout") == 0);
            break;
        }
        idx++;
    }

    /* check filters */
    idx = 0;
    mk_list_foreach(head, &cf->filters) {
        s = mk_list_entry(head, struct flb_cf_section, _head_section);
        switch (idx) {
        case 0:
            v = flb_cf_section_property_get(cf, s, "name");
            TEST_CHECK(v->type == CFL_VARIANT_STRING);
            TEST_CHECK(strcmp(v->data.as_string, "record_modifier") == 0);
            break;
        }
        idx++;
    }

    /* groups */
    s = flb_cf_section_get_by_name(cf, "input");
    TEST_CHECK(s != NULL);
    TEST_CHECK(mk_list_size(&s->groups) == 1);

    mk_list_foreach(head, &s->groups) {
        g = mk_list_entry(head, struct flb_cf_group, _head);
        TEST_CHECK(cfl_list_size(&g->properties->list) == 2);
    }

    printf("\n");
    flb_cf_dump(cf);
    flb_cf_destroy(cf);
}

/* https://github.com/fluent/fluent-bit/issues/7559 */
static void test_customs_section()
{
    struct flb_cf *cf;
    struct flb_cf_section *s;

    cf = flb_cf_yaml_create(NULL, FLB_001, NULL, 0);
    TEST_CHECK(cf != NULL);
    if (!cf) {
        exit(EXIT_FAILURE);
    }

    /* Total number of sections */
    if(!TEST_CHECK(mk_list_size(&cf->sections) == 3)) {
        TEST_MSG("Section number error. Got=%d expect=3", mk_list_size(&cf->sections));
    }

    s = flb_cf_section_get_by_name(cf, "customs");
    TEST_CHECK(s != NULL);
    if (!TEST_CHECK(s->type == FLB_CF_CUSTOM)) {
        TEST_MSG("Section type error. Got=%d expect=%d", s->type, FLB_CF_CUSTOM);
    }

    flb_cf_dump(cf);
    flb_cf_destroy(cf);
}

static void test_slist_even()
{
    struct flb_cf *cf;
    struct flb_cf_section *s;
    struct cfl_variant *v;
    struct mk_list *head;

    cf = flb_cf_yaml_create(NULL, FLB_TESTS_CONF_PATH "/pipelines/slist/even.yaml", NULL, 0);
    TEST_CHECK(cf != NULL);
    if (!cf) {
        exit(EXIT_FAILURE);
    }

    /* Total number of inputs */
    if(!TEST_CHECK(mk_list_size(&cf->inputs) == 1)) {
        TEST_MSG("Section number error. Got=%d expect=1", mk_list_size(&cf->inputs));
    }

    mk_list_foreach(head, &cf->inputs) {
        s = mk_list_entry(head, struct flb_cf_section, _head_section);
        TEST_CHECK(s != NULL);

        v = flb_cf_section_property_get(cf, s, "success_header");
        TEST_CHECK(v->type == CFL_VARIANT_ARRAY);
        if (!TEST_CHECK(v->data.as_array->entry_count == 2)) {
            TEST_MSG("Section number error. Got=%lud expect=2", v->data.as_array->entry_count);
        }
    }

    flb_cf_dump(cf);
    flb_cf_destroy(cf);
}

static void test_slist_odd()
{
    struct flb_cf *cf;
    struct flb_cf_section *s;
    struct cfl_variant *v;
    struct mk_list *head;

    cf = flb_cf_yaml_create(NULL, FLB_TESTS_CONF_PATH "/pipelines/slist/odd.yaml", NULL, 0);
    TEST_CHECK(cf != NULL);
    if (!cf) {
        exit(EXIT_FAILURE);
    }

    /* Total number of inputs */
    if(!TEST_CHECK(mk_list_size(&cf->inputs) == 1)) {
        TEST_MSG("Section number error. Got=%d expect=1", mk_list_size(&cf->inputs));
    }

    mk_list_foreach(head, &cf->inputs) {
        s = mk_list_entry(head, struct flb_cf_section, _head_section);
        TEST_CHECK(s != NULL);

        v = flb_cf_section_property_get(cf, s, "success_header");
        TEST_CHECK(v->type == CFL_VARIANT_ARRAY);
        if (!TEST_CHECK(v->data.as_array->entry_count == 3)) {
            TEST_MSG("Section number error. Got=%lud expect=3", v->data.as_array->entry_count);
        }
    }

    flb_cf_dump(cf);
    flb_cf_destroy(cf);
}


static void test_parser_conf()
{
    struct flb_cf *cf;
    struct flb_config *config;
    int ret;
    int cnt;

    cf = flb_cf_yaml_create(NULL, FLB_TESTS_CONF_PATH "/parsers/parsers-conf.yaml", NULL, 0);
    TEST_CHECK(cf != NULL);
    if (!cf) {
        exit(EXIT_FAILURE);
    }

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    config->conf_path = flb_strdup(FLB_TESTS_CONF_PATH "/parsers/");

    // count the parsers registered automatically by fluent-bit
    cnt = mk_list_size(&config->parsers);
    // load the parsers from the configuration
    ret = flb_config_load_config_format(config, cf);
    if (ret != 0) {
        exit(EXIT_FAILURE);;
    }

    /* Total number of inputs */
    if(!TEST_CHECK(mk_list_size(&config->parsers) == cnt+1)) {
        TEST_MSG("Section number error. Got=%d expect=%d", 
            mk_list_size(&config->parsers),
            cnt+1);
    }

    flb_cf_dump(cf);
    flb_cf_destroy(cf);
    flb_config_exit(config);
}

static inline int check_camel_to_snake(char *input, char *output)
{
    int len;
    int ret = -1;
    flb_sds_t out;
    struct flb_cf *cf;

    cf = flb_cf_create();
    flb_cf_set_origin_format(cf, FLB_CF_YAML);

    len = strlen(input);
    out = flb_cf_key_translate(cf, input, len);

    ret = strcmp(out, output);
    flb_sds_destroy(out);

    flb_cf_destroy(cf);

    if (ret == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}


static void test_camel_case_key()
{
    /* normal conversion */
    TEST_CHECK(check_camel_to_snake("a", "a") == FLB_TRUE);
    TEST_CHECK(check_camel_to_snake("aB", "a_b") == FLB_TRUE);
    TEST_CHECK(check_camel_to_snake("aBc", "a_bc") == FLB_TRUE);
    TEST_CHECK(check_camel_to_snake("aBcA", "a_bc_a") == FLB_TRUE);
    TEST_CHECK(check_camel_to_snake("aBCD", "a_b_c_d") == FLB_TRUE);
    TEST_CHECK(check_camel_to_snake("intervalSec", "interval_sec") == FLB_TRUE);

    /* unsupported conversion, we force lowercase in Yaml */
    TEST_CHECK(check_camel_to_snake("AA", "AA") == FLB_TRUE);
    TEST_CHECK(check_camel_to_snake("Interval_Sec", "Interval_Sec") == FLB_TRUE);

}

/* data/config_format/processors.yaml */
static void test_processors()
{
    struct mk_list *head;
    struct flb_cf *cf;
    struct flb_cf_section *s;
    struct flb_cf_group *g;
    struct cfl_variant *v;
    struct cfl_variant *logs;
    struct cfl_variant *record_modifier_filter;
    struct cfl_variant *records;
    struct cfl_variant *record;
    int idx = 0;

    cf = flb_cf_yaml_create(NULL, FLB_002, NULL, 0);
    TEST_CHECK(cf != NULL);
    if (!cf) {
        exit(EXIT_FAILURE);
    }

    /* Total number of sections */
    TEST_CHECK(mk_list_size(&cf->sections) == 2);

    /* Check number sections per list */
    TEST_CHECK(mk_list_size(&cf->parsers) == 0);
    TEST_CHECK(mk_list_size(&cf->multiline_parsers) == 0);
    TEST_CHECK(mk_list_size(&cf->customs) == 0);
    TEST_CHECK(mk_list_size(&cf->inputs) == 1);
    TEST_CHECK(mk_list_size(&cf->filters) == 0);
    TEST_CHECK(mk_list_size(&cf->outputs) == 1);
    TEST_CHECK(mk_list_size(&cf->others) == 0);

    /* check inputs */
    idx = 0;
    mk_list_foreach(head, &cf->inputs) {
        s = mk_list_entry(head, struct flb_cf_section, _head_section);
        switch (idx) {
        case 0:
            v = flb_cf_section_property_get(cf, s, "name");
            TEST_CHECK(v->type == CFL_VARIANT_STRING);
            TEST_CHECK(strcmp(v->data.as_string, "dummy") == 0);
            break;
        }
        idx++;
    }

    /* check outputs */
    idx = 0;
    mk_list_foreach(head, &cf->outputs) {
        s = mk_list_entry(head, struct flb_cf_section, _head_section);
        switch (idx) {
        case 0:
            v = flb_cf_section_property_get(cf, s, "name");
            TEST_CHECK(v->type == CFL_VARIANT_STRING);
            TEST_CHECK(strcmp(v->data.as_string, "stdout") == 0);
            break;
        }
        idx++;
    }

    /* groups */
    s = flb_cf_section_get_by_name(cf, "input");
    TEST_CHECK(s != NULL);
    TEST_CHECK(mk_list_size(&s->groups) == 1);

    mk_list_foreach(head, &s->groups) {
        g = mk_list_entry(head, struct flb_cf_group, _head);
        TEST_CHECK(cfl_list_size(&g->properties->list) == 1);
        TEST_CHECK(strcmp(g->name, "processors") == 0);

        logs = cfl_kvlist_fetch(g->properties, "logs");
        TEST_CHECK(logs != NULL);
        if (logs == NULL) {
            continue;
        }

        TEST_CHECK(logs->type == CFL_VARIANT_ARRAY);
        if (logs->type == CFL_VARIANT_ARRAY) {
            TEST_CHECK(logs->data.as_array->entry_count == 1);

            record_modifier_filter = cfl_array_fetch_by_index(logs->data.as_array, 0);
            TEST_CHECK(record_modifier_filter != NULL);

            if (record_modifier_filter) {
                TEST_CHECK(record_modifier_filter->type == CFL_VARIANT_KVLIST);

                records = cfl_kvlist_fetch(record_modifier_filter->data.as_kvlist, "record");
                TEST_CHECK(records->type == CFL_VARIANT_ARRAY);
                TEST_CHECK(records->data.as_array->entry_count == 2);

                for (idx = 0; idx < 2; idx++) {
                    record = cfl_array_fetch_by_index(records->data.as_array, idx);
                    TEST_CHECK(record->type == CFL_VARIANT_STRING);

                    if (record->type != CFL_VARIANT_STRING) {
                        continue;
                    }

                    switch (idx) {
                    case 0:
                        TEST_CHECK(strcmp(record->data.as_string, "filtered_by record_modifier") == 0);
                        break;
                    case 1:
                        TEST_CHECK(strcmp(record->data.as_string, "powered_by calyptia") == 0);
                        break;
                    }
                }
            }
        }
    }

    flb_cf_destroy(cf);
}

TEST_LIST = {
    { "basic"    , test_basic},
    { "customs section", test_customs_section},
    { "slist odd", test_slist_odd},
    { "slist even", test_slist_even},
    { "parsers file conf", test_parser_conf},
    { "camel_case_key", test_camel_case_key},
    { "processors", test_processors},
    { 0 }
};
