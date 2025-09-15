/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/calyptia/calyptia_constants.h>
#include "flb_tests_runtime.h"
#include "../../plugins/in_calyptia_fleet/in_calyptia_fleet.h"

flb_sds_t fleet_config_filename(struct flb_in_calyptia_fleet_config *ctx, char *fname);
int get_calyptia_fleet_config(struct flb_in_calyptia_fleet_config *ctx);

/* Test context structure */
struct test_context {
    struct flb_in_calyptia_fleet_config *ctx;
    struct flb_config *config;
};

/* Initialize test context */
static struct test_context *init_test_context()
{
    struct test_context *t_ctx = flb_calloc(1, sizeof(struct test_context));
    if (!t_ctx) {
        return NULL;
    }

    t_ctx->config = flb_config_init();
    if (!t_ctx->config) {
        flb_free(t_ctx);
        return NULL;
    }

    t_ctx->ctx = flb_calloc(1, sizeof(struct flb_in_calyptia_fleet_config));
    if (!t_ctx->ctx) {
        flb_config_exit(t_ctx->config);
        flb_free(t_ctx);
        return NULL;
    }

    /* Initialize plugin instance for logging */
    t_ctx->ctx->ins = flb_calloc(1, sizeof(struct flb_input_instance));
    if (!t_ctx->ctx->ins) {
        flb_free(t_ctx->ctx);
        flb_config_exit(t_ctx->config);
        flb_free(t_ctx);
        return NULL;
    }

    /* Initialize test values in ctx */
    t_ctx->ctx->api_key = flb_strdup("test_api_key");
    t_ctx->ctx->fleet_id = flb_strdup("test_fleet_id");

    t_ctx->ctx->fleet_name = flb_strdup("test_fleet");
    t_ctx->ctx->machine_id = flb_strdup("test_machine_id");

    t_ctx->ctx->fleet_config_legacy_format = FLB_TRUE;

    return t_ctx;
}

static void cleanup_test_context(struct test_context *t_ctx)
{
    if (!t_ctx) {
        return;
    }

    if (t_ctx->ctx) {
        if (t_ctx->ctx->api_key) flb_free(t_ctx->ctx->api_key);
        if (t_ctx->ctx->fleet_id) flb_free(t_ctx->ctx->fleet_id);

        if (t_ctx->ctx->fleet_name) flb_free(t_ctx->ctx->fleet_name);
        if (t_ctx->ctx->machine_id) flb_free(t_ctx->ctx->machine_id);
        if (t_ctx->ctx->fleet_files_url) flb_free(t_ctx->ctx->fleet_files_url);

        if (t_ctx->ctx->ins) flb_free(t_ctx->ctx->ins);
        flb_free(t_ctx->ctx);
    }

    if (t_ctx->config) {
        /* Destroy the config which will cleanup any remaining instances */
        flb_config_exit(t_ctx->config);
    }

    flb_free(t_ctx);
}

static void test_in_fleet_format() {
    struct test_context *t_ctx = init_test_context();
    TEST_CHECK(t_ctx != NULL);

    /* Ensure we create TOML files by default */
    char expectedValue[CALYPTIA_MAX_DIR_SIZE];
    int ret = sprintf(expectedValue, "%s/%s/%s/test.conf", FLEET_DEFAULT_CONFIG_DIR, t_ctx->ctx->machine_id, t_ctx->ctx->fleet_name);
    TEST_CHECK(ret > 0);

    flb_sds_t value = fleet_config_filename( t_ctx->ctx, "test" );
    TEST_CHECK(value != NULL);
    TEST_MSG("fleet_config_filename expected=%s got=%s", expectedValue, value);
    TEST_CHECK(value && strcmp(value, expectedValue) == 0);
    flb_sds_destroy(value);
    value = NULL;

    /* Ensure we create YAML files if configured to do so */
    t_ctx->ctx->fleet_config_legacy_format = FLB_FALSE;

    ret = sprintf(expectedValue, "%s/%s/%s/test.yaml", FLEET_DEFAULT_CONFIG_DIR, t_ctx->ctx->machine_id, t_ctx->ctx->fleet_name);
    TEST_CHECK(ret > 0);

    value = fleet_config_filename( t_ctx->ctx, "test" );
    TEST_CHECK(value != NULL);
    TEST_MSG("fleet_config_filename expected=%s got=%s", expectedValue, value);
    TEST_CHECK(value && strcmp(value, expectedValue) == 0);
    flb_sds_destroy(value);
    value = NULL;

    cleanup_test_context(t_ctx);
}

/* Define test list */
TEST_LIST = {
    {"in_calyptia_fleet_format", test_in_fleet_format},
    {NULL, NULL}
};