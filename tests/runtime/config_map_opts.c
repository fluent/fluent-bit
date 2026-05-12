/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit.h>
#include <fluent-bit/flb_help.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_scheduler.h>
#include <stdio.h>
#include <string.h>
#include "flb_tests_runtime.h"

/* Test functions */
void flb_test_config_map_opts(void);
void flb_test_config_map_required_schema(void);

/* Test list */
TEST_LIST = {
    {"config_map_opts",             flb_test_config_map_opts },
    {"config_map_required_schema",  flb_test_config_map_required_schema },
    {NULL, NULL}
};

static int schema_option_required(flb_sds_t schema, const char *component_type,
                                  const char *plugin_name, const char *option_name,
                                  int expected)
{
    char plugin_marker[160];
    char option_marker[128];
    char required_marker[32];
    char *plugin;
    char *plugin_end;
    char *option;
    char *next_option;
    char *required;
    int ret;

    ret = snprintf(plugin_marker, sizeof(plugin_marker),
                   "\"type\":\"%s\",\"name\":\"%s\"", component_type, plugin_name);
    if (ret < 0 || (size_t) ret >= sizeof(plugin_marker)) {
        return -1;
    }

    ret = snprintf(option_marker, sizeof(option_marker),
                   "\"name\":\"%s\"", option_name);
    if (ret < 0 || (size_t) ret >= sizeof(option_marker)) {
        return -1;
    }

    if (expected == FLB_TRUE) {
        snprintf(required_marker, sizeof(required_marker), "\"required\":true");
    }
    else {
        snprintf(required_marker, sizeof(required_marker), "\"required\":false");
    }

    plugin = schema;

    while ((plugin = strstr(plugin, plugin_marker)) != NULL) {
        plugin_end = strstr(plugin + strlen(plugin_marker), "},{\"type\":\"");
        option = strstr(plugin, option_marker);

        while (option && (!plugin_end || option < plugin_end)) {
            next_option = strstr(option + 1, "\"name\":\"");
            required = strstr(option, "\"required\":");

            if (required && (!next_option || required < next_option)) {
                if (strncmp(required, required_marker, strlen(required_marker)) == 0) {
                    return 0;
                }
                return -1;
            }

            option = strstr(option + 1, option_marker);
        }

        plugin += strlen(plugin_marker);
    }

    return -1;
}

void flb_test_config_map_opts(void)
{
    flb_ctx_t    *ctx    = NULL;
    int in_ffd, r;

    flb_init_env();
    flb_sched_ctx_init();

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "tail", NULL);
    r = flb_input_property_check(ctx, in_ffd, "invalid_option", "invalid value");
    TEST_CHECK(r != 0);

    in_ffd = flb_filter(ctx, (char *) "kubernetes", NULL);
    r = flb_filter_property_check(ctx, in_ffd, "invalid_option", "invalid value");
    TEST_CHECK(r != 0);

    in_ffd = flb_output(ctx, (char *) "stdout", NULL);
    r = flb_output_property_check(ctx, in_ffd, "invalid_option", "invalid value");
    TEST_CHECK(r != 0);

    flb_destroy(ctx);
}

void flb_test_config_map_required_schema(void)
{
    flb_ctx_t *ctx = NULL;
    flb_sds_t schema;

    flb_init_env();
    flb_sched_ctx_init();

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        return;
    }

    schema = flb_help_build_json_schema(ctx->config);
    TEST_CHECK(schema != NULL);
    if (!schema) {
        flb_destroy(ctx);
        return;
    }

    TEST_CHECK(strstr(schema, "\"schema_version\":\"1\"") != NULL);
    TEST_CHECK(strstr(schema, "\"required\":true") != NULL);
    TEST_CHECK(strstr(schema, "\"required\":false") != NULL);
    TEST_CHECK(strstr(schema, "\"required\":\"") == NULL);

    TEST_CHECK(schema_option_required(schema, "input", "tail",
                                      "path", FLB_TRUE) == 0);
    TEST_CHECK(schema_option_required(schema, "filter", "parser",
                                      "Key_Name", FLB_TRUE) == 0);
    TEST_CHECK(schema_option_required(schema, "filter", "rewrite_tag",
                                      "rule", FLB_TRUE) == 0);
    TEST_CHECK(schema_option_required(schema, "output", "s3",
                                      "bucket", FLB_TRUE) == 0);
    TEST_CHECK(schema_option_required(schema, "processor", "sql",
                                      "query", FLB_TRUE) == 0);
    TEST_CHECK(schema_option_required(schema, "output", "oracle_log_analytics",
                                      "config_file_location", FLB_TRUE) == 0);
    TEST_CHECK(schema_option_required(schema, "output", "stdout",
                                      "format", FLB_FALSE) == 0);

    flb_sds_destroy(schema);
    flb_destroy(ctx);
}
