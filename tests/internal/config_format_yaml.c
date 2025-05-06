/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_config_format.h>

#include <cfl/cfl.h>
#include <cfl/cfl_list.h>

#include "flb_tests_internal.h"

#ifdef _WIN32
#define FLB_TESTS_CONF_PATH FLB_TESTS_DATA_PATH "\\data\\config_format\\yaml"
#else
#define FLB_TESTS_CONF_PATH FLB_TESTS_DATA_PATH "/data/config_format/yaml"
#endif

#define FLB_000 FLB_TESTS_CONF_PATH "/fluent-bit.yaml"
#define FLB_001 FLB_TESTS_CONF_PATH "/issue_7559.yaml"
#define FLB_002 FLB_TESTS_CONF_PATH "/processors.yaml"

#ifdef _WIN32
#define FLB_003 FLB_TESTS_CONF_PATH "\\parsers_and_multiline_parsers.yaml"
#else
#define FLB_003 FLB_TESTS_CONF_PATH "/parsers_and_multiline_parsers.yaml"
#endif

#define FLB_004 FLB_TESTS_CONF_PATH "/stream_processor.yaml"
#define FLB_005 FLB_TESTS_CONF_PATH "/plugins.yaml"
#define FLB_006 FLB_TESTS_CONF_PATH "/upstream.yaml"

#define FLB_000_WIN FLB_TESTS_CONF_PATH "\\fluent-bit-windows.yaml"
#define FLB_BROKEN_PLUGIN_VARIANT FLB_TESTS_CONF_PATH "/broken_plugin_variant.yaml"

#ifdef _WIN32
#define FLB_BASIC FLB_000_WIN
#else
#define FLB_BASIC FLB_000
#endif

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

    cf = flb_cf_yaml_create(NULL, FLB_BASIC, NULL, 0);
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

static void test_broken_plugin_variant_yaml()
{
    struct flb_cf *cf;

    cf = flb_cf_yaml_create(NULL, FLB_BROKEN_PLUGIN_VARIANT, NULL, 0);
    TEST_CHECK(cf == NULL);

    if (cf != NULL) {
        TEST_CHECK_(cf != NULL, "somewhat config_format is created wrongly");
        flb_cf_dump(cf);
        flb_cf_destroy(cf);
    }
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

static void test_parsers_and_multiline_parsers()
{
    int idx = 0;
    flb_sds_t str;
    struct mk_list *head;
    struct mk_list *rule_head;
    struct flb_cf *cf;
    struct flb_cf_section *s;
    struct flb_cf_group *g;
    struct cfl_variant *v;
    struct cfl_variant *tmp;

    cf = flb_cf_yaml_create(NULL, FLB_003, NULL, 0);
    TEST_CHECK(cf != NULL);
    if (!cf) {
        exit(EXIT_FAILURE);
    }

    /* Total number of sections */
    TEST_CHECK(mk_list_size(&cf->sections) == 8);

    /* Check number sections per list */
    TEST_CHECK(mk_list_size(&cf->parsers) == 3);
    TEST_CHECK(mk_list_size(&cf->multiline_parsers) == 2);
    TEST_CHECK(mk_list_size(&cf->customs) == 0);
    TEST_CHECK(mk_list_size(&cf->inputs) == 1);
    TEST_CHECK(mk_list_size(&cf->filters) == 0);
    TEST_CHECK(mk_list_size(&cf->outputs) == 1);
    TEST_CHECK(mk_list_size(&cf->others) == 0);

    /* check parsers */
    idx = 0;
    mk_list_foreach(head, &cf->parsers) {
        s = mk_list_entry(head, struct flb_cf_section, _head_section);
        switch (idx) {
        case 0:
            v = flb_cf_section_property_get(cf, s, "name");
            TEST_CHECK(v->type == CFL_VARIANT_STRING);
            TEST_CHECK(strcmp(v->data.as_string, "json-2") == 0);
            break;
        case 1:
            v = flb_cf_section_property_get(cf, s, "name");
            TEST_CHECK(v->type == CFL_VARIANT_STRING);
            TEST_CHECK(strcmp(v->data.as_string, "json") == 0);
            break;

        case 2:
            v = flb_cf_section_property_get(cf, s, "name");
            TEST_CHECK(v->type == CFL_VARIANT_STRING);
            TEST_CHECK(strcmp(v->data.as_string, "docker") == 0);
            break;
        }
        idx++;
    }

    /* check multiline parsers */
    idx = 0;
    head = NULL;
    mk_list_foreach(head, &cf->multiline_parsers) {
        s = mk_list_entry(head, struct flb_cf_section, _head_section);
        str = flb_cf_section_property_get_string(cf, s, "name");

        switch (idx) {
            case 0:
                TEST_CHECK(strcmp(str, "exception_test-2") == 0);
                break;
            case 1:
                TEST_CHECK(strcmp(str, "exception_test") == 0);
                break;
        };
        flb_sds_destroy(str);

        /* check rules (groups) */
        TEST_CHECK(mk_list_size(&s->groups) == 2);

        idx = 0;
        mk_list_foreach(rule_head, &s->groups) {
            g = mk_list_entry(rule_head, struct flb_cf_group, _head);
            TEST_CHECK(strcmp(g->name, "rule") == 0);

            if (idx == 0) {
                /* get initial state "start_state" */
                tmp = cfl_kvlist_fetch(g->properties, "state");
                TEST_CHECK(tmp != NULL);

                TEST_CHECK(tmp->type == CFL_VARIANT_STRING);
                TEST_CHECK(strcmp(tmp->data.as_string, "start_state") == 0);
            }
            else if (idx == 1) {
                /* get initial state "start_state" */
                tmp = cfl_kvlist_fetch(g->properties, "state");
                TEST_CHECK(tmp != NULL);

                TEST_CHECK(tmp->type == CFL_VARIANT_STRING);
                TEST_CHECK(strcmp(tmp->data.as_string, "cont") == 0);
            }
            idx++;
        }
    }

    flb_cf_destroy(cf);
}

static void test_stream_processor()
{
    int idx = 0;
    struct mk_list *head;
    struct flb_cf *cf;
    struct flb_cf_section *s;
    struct cfl_variant *v;

    cf = flb_cf_yaml_create(NULL, FLB_004, NULL, 0);
    TEST_CHECK(cf != NULL);
    if (!cf) {
        exit(EXIT_FAILURE);
    }

    /* Total number of sections */
    TEST_CHECK(mk_list_size(&cf->sections) == 5);

    /* Check number sections per list */
    TEST_CHECK(mk_list_size(&cf->parsers) == 0);
    TEST_CHECK(mk_list_size(&cf->multiline_parsers) == 0);
    TEST_CHECK(mk_list_size(&cf->customs) == 0);
    TEST_CHECK(mk_list_size(&cf->inputs) == 1);
    TEST_CHECK(mk_list_size(&cf->filters) == 0);
    TEST_CHECK(mk_list_size(&cf->outputs) == 1);
    TEST_CHECK(mk_list_size(&cf->others) == 0);

    /* check others */
    idx = 0;
    mk_list_foreach(head, &cf->stream_processors) {
        s = mk_list_entry(head, struct flb_cf_section, _head_section);

        switch (idx) {
            case 0:
                v = flb_cf_section_property_get(cf, s, "name");
                TEST_CHECK(v->type == CFL_VARIANT_STRING);
                TEST_CHECK(strcmp(v->data.as_string, "create_results") == 0);

                v = flb_cf_section_property_get(cf, s, "exec");
                TEST_CHECK(v->type == CFL_VARIANT_STRING);
                TEST_CHECK(strncmp(v->data.as_string, "CREATE STREAM results", 21) == 0);
                break;
            case 1:
                v = flb_cf_section_property_get(cf, s, "name");
                TEST_CHECK(v->type == CFL_VARIANT_STRING);
                TEST_CHECK(strcmp(v->data.as_string, "select_results") == 0);

                v = flb_cf_section_property_get(cf, s, "exec");
                TEST_CHECK(v->type == CFL_VARIANT_STRING);
                TEST_CHECK(strncmp(v->data.as_string, "SELECT * FROM", 13) == 0);
                break;
        };
        idx++;

        /* check groups */
        TEST_CHECK(mk_list_size(&s->groups) == 0);
    }

    flb_cf_destroy(cf);
}

static void test_plugins()
{
    int idx = 0;
    struct mk_list *head;
    struct flb_cf *cf;
    struct flb_cf_section *s;

    struct cfl_kvpair *path;
    struct cfl_list *path_head;

    cf = flb_cf_yaml_create(NULL, FLB_005, NULL, 0);
    TEST_CHECK(cf != NULL);
    if (!cf) {
        exit(EXIT_FAILURE);
    }

    /* Total number of sections */
    TEST_CHECK(mk_list_size(&cf->sections) == 4);

    /* Check number sections per list */
    TEST_CHECK(mk_list_size(&cf->plugins) == 1);
    TEST_CHECK(mk_list_size(&cf->parsers) == 0);
    TEST_CHECK(mk_list_size(&cf->multiline_parsers) == 0);
    TEST_CHECK(mk_list_size(&cf->customs) == 0);
    TEST_CHECK(mk_list_size(&cf->inputs) == 1);
    TEST_CHECK(mk_list_size(&cf->filters) == 0);
    TEST_CHECK(mk_list_size(&cf->outputs) == 1);
    TEST_CHECK(mk_list_size(&cf->others) == 0);


    mk_list_foreach(head, &cf->plugins) {
        s = mk_list_entry(head, struct flb_cf_section, _head_section);

        idx = 0;
        cfl_list_foreach(path_head, &s->properties->list) {
            path = cfl_list_entry(path_head, struct cfl_kvpair, _head);

            switch (idx) {
                case 0:
                    TEST_CHECK(strcmp(path->key, "/path/to/out_gstdout.so") == 0);
                    break;
                case 1:
                    TEST_CHECK(strcmp(path->key, "/path/to/out_fluent.so") == 0);
                    break;
            };
            idx++;
        }
    }

    flb_cf_destroy(cf);
}

static void test_upstream_servers()
{
    int idx = 0;
    int g_idx = 0;
    struct mk_list *head;
    struct mk_list *g_head;
    struct flb_cf *cf;
    struct flb_cf_section *s;
    struct cfl_variant *v;
    struct flb_cf_group *group;

    cf = flb_cf_yaml_create(NULL, FLB_006, NULL, 0);
    TEST_CHECK(cf != NULL);
    if (!cf) {
        exit(EXIT_FAILURE);
    }

    /* Total number of sections */
    TEST_CHECK(mk_list_size(&cf->sections) == 4);

    /* Check number sections per list */
    TEST_CHECK(mk_list_size(&cf->upstream_servers) == 2);
    TEST_CHECK(mk_list_size(&cf->parsers) == 0);
    TEST_CHECK(mk_list_size(&cf->multiline_parsers) == 0);
    TEST_CHECK(mk_list_size(&cf->customs) == 0);
    TEST_CHECK(mk_list_size(&cf->inputs) == 1);
    TEST_CHECK(mk_list_size(&cf->filters) == 0);
    TEST_CHECK(mk_list_size(&cf->outputs) == 1);
    TEST_CHECK(mk_list_size(&cf->others) == 0);

    /* check upstream servers */
    idx = 0;
    mk_list_foreach(head, &cf->upstream_servers) {
        s = mk_list_entry(head, struct flb_cf_section, _head_section);

        switch (idx) {
            case 0:
                v = flb_cf_section_property_get(cf, s, "name");
                TEST_CHECK(v->type == CFL_VARIANT_STRING);
                TEST_CHECK(strcmp(v->data.as_string, "forward-balancing") == 0);

                /* iterate node/groups */
                TEST_CHECK(mk_list_size(&s->groups) == 3);

                g_idx = 0;
                mk_list_foreach(g_head, &s->groups) {
                    group = mk_list_entry(g_head, struct flb_cf_group, _head);
                    TEST_CHECK(group != NULL);
                    TEST_CHECK(strcmp(group->name, "upstream_node") == 0);

                    switch (g_idx) {
                        case 0:
                            v = cfl_kvlist_fetch(group->properties, "name");
                            TEST_CHECK(v != NULL);
                            TEST_CHECK(v->type == CFL_VARIANT_STRING);
                            TEST_CHECK(strcmp(v->data.as_string, "node-1") == 0);

                            v = cfl_kvlist_fetch(group->properties, "host");
                            TEST_CHECK(v != NULL);
                            TEST_CHECK(v->type == CFL_VARIANT_STRING);
                            TEST_CHECK(strcmp(v->data.as_string, "127.0.0.1") == 0);

                            v = cfl_kvlist_fetch(group->properties, "port");
                            TEST_CHECK(v != NULL);
                            TEST_CHECK(v->type == CFL_VARIANT_STRING);
                            TEST_CHECK(strcmp(v->data.as_string, "43000") == 0);
                            break;

                        case 1:
                            v = cfl_kvlist_fetch(group->properties, "name");
                            TEST_CHECK(v != NULL);
                            TEST_CHECK(v->type == CFL_VARIANT_STRING);
                            TEST_CHECK(strcmp(v->data.as_string, "node-2") == 0);

                            v = cfl_kvlist_fetch(group->properties, "host");
                            TEST_CHECK(v != NULL);
                            TEST_CHECK(v->type == CFL_VARIANT_STRING);
                            TEST_CHECK(strcmp(v->data.as_string, "127.0.0.1") == 0);

                            v = cfl_kvlist_fetch(group->properties, "port");
                            TEST_CHECK(v != NULL);
                            TEST_CHECK(v->type == CFL_VARIANT_STRING);
                            TEST_CHECK(strcmp(v->data.as_string, "44000") == 0);
                            break;
                        case 2:
                            v = cfl_kvlist_fetch(group->properties, "name");
                            TEST_CHECK(v != NULL);

                            TEST_CHECK(v->type == CFL_VARIANT_STRING);
                            TEST_CHECK(strcmp(v->data.as_string, "node-3") == 0);
                            break;
                    };
                    g_idx++;
                }
                break;
            case 1:
                v = flb_cf_section_property_get(cf, s, "name");
                TEST_CHECK(v->type == CFL_VARIANT_STRING);
                TEST_CHECK(strcmp(v->data.as_string, "forward-balancing-2") == 0);

                g_idx = 0;
                mk_list_foreach(g_head, &s->groups) {
                    group = mk_list_entry(g_head, struct flb_cf_group, _head);
                    TEST_CHECK(group != NULL);
                    TEST_CHECK(strcmp(group->name, "upstream_node") == 0);

                    switch (g_idx) {
                        case 0:
                            v = cfl_kvlist_fetch(group->properties, "name");
                            TEST_CHECK(v != NULL);
                            TEST_CHECK(v->type == CFL_VARIANT_STRING);
                            TEST_CHECK(strcmp(v->data.as_string, "node-A") == 0);

                            v = cfl_kvlist_fetch(group->properties, "host");
                            TEST_CHECK(v != NULL);
                            TEST_CHECK(v->type == CFL_VARIANT_STRING);
                            TEST_CHECK(strcmp(v->data.as_string, "192.168.1.10") == 0);

                            v = cfl_kvlist_fetch(group->properties, "port");
                            TEST_CHECK(v != NULL);
                            TEST_CHECK(v->type == CFL_VARIANT_STRING);
                            TEST_CHECK(strcmp(v->data.as_string, "50000") == 0);

                            break;
                        case 1:
                            v = cfl_kvlist_fetch(group->properties, "name");
                            TEST_CHECK(v != NULL);
                            TEST_CHECK(v->type == CFL_VARIANT_STRING);
                            TEST_CHECK(strcmp(v->data.as_string, "node-B") == 0);

                            v = cfl_kvlist_fetch(group->properties, "host");
                            TEST_CHECK(v != NULL);
                            TEST_CHECK(v->type == CFL_VARIANT_STRING);
                            TEST_CHECK(strcmp(v->data.as_string, "192.168.1.11") == 0);

                            v = cfl_kvlist_fetch(group->properties, "port");
                            TEST_CHECK(v != NULL);
                            TEST_CHECK(v->type == CFL_VARIANT_STRING);
                            TEST_CHECK(strcmp(v->data.as_string, "51000") == 0);
                            break;
                    };
                    g_idx++;
                }

                break;
        };
        idx++;
    }

    flb_cf_destroy(cf);
}

static void test_invalid_property()
{
    char* test_cases[] = {
        FLB_TESTS_CONF_PATH "/invalid_input_property.yaml",
        FLB_TESTS_CONF_PATH "/invalid_output_property.yaml",
        NULL,
    };

    struct flb_cf *cf;
    struct flb_config *config;
    int ret;
    int i;

    for (i = 0; test_cases[i] != NULL; i++) {
        cf = flb_cf_yaml_create(NULL, test_cases[i], NULL, 0);
        TEST_ASSERT(cf != NULL);

        config = flb_config_init();
        TEST_ASSERT(config != NULL);

        ret = flb_config_load_config_format(config, cf);
        TEST_ASSERT_(ret == -1, "expected invalid property to return an error in file %s", test_cases[i]);

        flb_config_exit(config);
        flb_cf_destroy(cf);
    }
}

TEST_LIST = {
    { "basic"    , test_basic},
    { "customs section", test_customs_section},
    { "broken_plugin_variant_yaml", test_broken_plugin_variant_yaml},
    { "slist odd", test_slist_odd},
    { "slist even", test_slist_even},
    { "parsers file conf", test_parser_conf},
    { "camel_case_key", test_camel_case_key},
    { "processors", test_processors},
    { "parsers_and_multiline_parsers", test_parsers_and_multiline_parsers},
    { "stream_processor", test_stream_processor},
    { "plugins", test_plugins},
    { "upstream_servers", test_upstream_servers},
    { "invalid_input_property", test_invalid_property},
    { 0 }
};
