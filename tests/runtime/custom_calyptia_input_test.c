#include <stdio.h>
#include <string.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_custom_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/calyptia/calyptia_constants.h>
#include "flb_tests_runtime.h"
#include "../../plugins/custom_calyptia/calyptia.h"

const char *flb_input_get_property(const char *key,
                                   struct flb_input_instance *ins);
struct flb_input_instance *flb_input_new(struct flb_config *config,
                                         const char *input, void *data,
                                         int public_only);
void flb_input_instance_destroy(struct flb_input_instance *ins);

flb_sds_t agent_config_filename(struct calyptia *ctx, char *fname);
flb_sds_t get_machine_id(struct calyptia *ctx);

/* Test context structure */
struct test_context {
    struct calyptia *ctx;
    struct flb_input_instance *fleet;
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

    t_ctx->ctx = flb_calloc(1, sizeof(struct calyptia));
    if (!t_ctx->ctx) {
        flb_config_exit(t_ctx->config);
        flb_free(t_ctx);
        return NULL;
    }

    /* Initialize plugin instance for logging */
    t_ctx->ctx->ins = flb_calloc(1, sizeof(struct flb_custom_instance));
    if (!t_ctx->ctx->ins) {
        flb_free(t_ctx->ctx);
        flb_config_exit(t_ctx->config);
        flb_free(t_ctx);
        return NULL;
    }

    mk_list_init(&t_ctx->ctx->ins->net_properties);

    /* Initialize test values in ctx */
    t_ctx->ctx->api_key = flb_strdup("test_api_key");
    t_ctx->ctx->fleet_config_dir = flb_strdup("/test/config/dir");
    t_ctx->ctx->fleet_id = flb_strdup("test_fleet_id");
    t_ctx->ctx->fleet_name = flb_strdup("test_fleet");
    t_ctx->ctx->machine_id = flb_strdup("test_machine_id");
    t_ctx->ctx->fleet_max_http_buffer_size = flb_strdup("1024");
    t_ctx->ctx->fleet_interval_sec = flb_strdup("60");
    t_ctx->ctx->fleet_interval_nsec = flb_strdup("500000000");
    t_ctx->ctx->fleet_config_legacy_format = FLB_TRUE;

    t_ctx->fleet = flb_input_new(t_ctx->config, "calyptia_fleet", NULL, FLB_FALSE);
    if (!t_ctx->fleet) {
        if (t_ctx->ctx->ins) flb_free(t_ctx->ctx->ins);
        flb_free(t_ctx->ctx);
        flb_config_exit(t_ctx->config);
        flb_free(t_ctx);
        return NULL;
    }

    return t_ctx;
}

static void cleanup_test_context(struct test_context *t_ctx)
{
    if (!t_ctx) {
        return;
    }

    if (t_ctx->fleet) {
        /* Input instance cleanup */
        flb_input_instance_destroy(t_ctx->fleet);
    }

    if (t_ctx->ctx) {
        if (t_ctx->ctx->api_key) flb_free(t_ctx->ctx->api_key);
        if (t_ctx->ctx->fleet_config_dir) flb_free(t_ctx->ctx->fleet_config_dir);
        if (t_ctx->ctx->fleet_id) flb_free(t_ctx->ctx->fleet_id);
        if (t_ctx->ctx->fleet_name) flb_free(t_ctx->ctx->fleet_name);
        if (t_ctx->ctx->machine_id) flb_free(t_ctx->ctx->machine_id);
        if (t_ctx->ctx->fleet_max_http_buffer_size) flb_free(t_ctx->ctx->fleet_max_http_buffer_size);
        if (t_ctx->ctx->fleet_interval_sec) flb_free(t_ctx->ctx->fleet_interval_sec);
        if (t_ctx->ctx->fleet_interval_nsec) flb_free(t_ctx->ctx->fleet_interval_nsec);
        if (t_ctx->ctx->ins) flb_free(t_ctx->ctx->ins);
        flb_free(t_ctx->ctx);
    }

    if (t_ctx->config) {
        /* Destroy the config which will cleanup any remaining instances */
        flb_config_exit(t_ctx->config);
    }

    flb_free(t_ctx);
}

void test_set_fleet_input_properties()
{
    struct test_context *t_ctx = init_test_context();
    TEST_CHECK(t_ctx != NULL);

    /* Test setting properties */
    int ret = set_fleet_input_properties(t_ctx->ctx, t_ctx->fleet);
    TEST_CHECK(ret == 0);

    /* Verify properties were set correctly */
    const char *value;

    /* Check api_key */
    value = flb_input_get_property("api_key", t_ctx->fleet);
    TEST_CHECK(value != NULL);
    TEST_MSG("api_key expected=%s got=%s", t_ctx->ctx->api_key, value);
    TEST_CHECK(value && strcmp(value, t_ctx->ctx->api_key) == 0);

    /* Check config_dir */
    value = flb_input_get_property("config_dir", t_ctx->fleet);
    TEST_CHECK(value != NULL);
    TEST_MSG("config_dir expected=%s got=%s", t_ctx->ctx->fleet_config_dir, value);
    TEST_CHECK(value && strcmp(value, t_ctx->ctx->fleet_config_dir) == 0);

    /* Check fleet_id */
    value = flb_input_get_property("fleet_id", t_ctx->fleet);
    TEST_CHECK(value != NULL);
    TEST_MSG("fleet_id expected=%s got=%s", t_ctx->ctx->fleet_id, value);
    TEST_CHECK(value && strcmp(value, t_ctx->ctx->fleet_id) == 0);

    /* Check fleet_name */
    value = flb_input_get_property("fleet_name", t_ctx->fleet);
    TEST_CHECK(value != NULL);
    TEST_MSG("fleet_name expected=%s got=%s", t_ctx->ctx->fleet_name, value);
    TEST_CHECK(value && strcmp(value, t_ctx->ctx->fleet_name) == 0);

    /* Check machine_id */
    value = flb_input_get_property("machine_id", t_ctx->fleet);
    TEST_CHECK(value != NULL);
    TEST_MSG("machine_id expected=%s got=%s", t_ctx->ctx->machine_id, value);
    TEST_CHECK(value && strcmp(value, t_ctx->ctx->machine_id) == 0);

    /* Check max_http_buffer_size */
    value = flb_input_get_property("max_http_buffer_size", t_ctx->fleet);
    TEST_CHECK(value != NULL);
    TEST_MSG("max_http_buffer_size expected=%s got=%s", t_ctx->ctx->fleet_max_http_buffer_size, value);
    TEST_CHECK(value && strcmp(value, t_ctx->ctx->fleet_max_http_buffer_size) == 0);

    /* Check interval_sec */
    value = flb_input_get_property("interval_sec", t_ctx->fleet);
    TEST_CHECK(value != NULL);
    TEST_MSG("interval_sec expected=%s got=%s", t_ctx->ctx->fleet_interval_sec, value);
    TEST_CHECK(value && strcmp(value, t_ctx->ctx->fleet_interval_sec) == 0);

    /* Check interval_nsec */
    value = flb_input_get_property("interval_nsec", t_ctx->fleet);
    TEST_CHECK(value != NULL);
    TEST_MSG("interval_nsec expected=%s got=%s", t_ctx->ctx->fleet_interval_nsec, value);
    TEST_CHECK(value && strcmp(value, t_ctx->ctx->fleet_interval_nsec) == 0);

    ret = set_fleet_input_properties(t_ctx->ctx, NULL);
    TEST_CHECK(ret == -1);

    cleanup_test_context(t_ctx);
}

static struct test_context * update_config_dir(struct test_context * t_ctx, const char* new_config_dir) {
    if (!t_ctx || !new_config_dir) {
        return NULL;
    }

    if (t_ctx->ctx) {
        if (t_ctx->ctx->fleet_config_dir) {
            flb_free(t_ctx->ctx->fleet_config_dir);
        }
        t_ctx->ctx->fleet_config_dir = flb_strdup(new_config_dir);
        return t_ctx;
    }

    cleanup_test_context(t_ctx);
    return NULL;
}

static void test_calyptia_machine_id_generation() {
    struct test_context *t_ctx = init_test_context();
    TEST_CHECK(t_ctx != NULL);

    /* Set config directory to default */
    t_ctx = update_config_dir(t_ctx, FLEET_DEFAULT_CONFIG_DIR);
    TEST_CHECK(t_ctx != NULL);

    /* Test setting properties */
    int ret = set_fleet_input_properties(t_ctx->ctx, t_ctx->fleet);
    TEST_CHECK(ret == 0);

    /* Verify properties were set correctly */
    const char *value;

    /* Check config_dir */
    value = flb_input_get_property("config_dir", t_ctx->fleet);
    TEST_CHECK(value != NULL);
    TEST_MSG("config_dir expected=%s got=%s", FLEET_DEFAULT_CONFIG_DIR, value);
    TEST_CHECK(value && strcmp(value, FLEET_DEFAULT_CONFIG_DIR) == 0);

    /**
     * Initial generation should create a new UUID
     * Subsequent generation should reuse the previous one
     * Repeat with custom directory to confirm that works too
    */
    char expectedValue[CALYPTIA_MAX_DIR_SIZE];
    ret = sprintf(expectedValue, "%s/machine-id.conf", FLEET_DEFAULT_CONFIG_DIR);
    TEST_CHECK(ret > 0);

    flb_sds_t filename = machine_id_fleet_config_filename(t_ctx->ctx);
    TEST_CHECK(filename != NULL);
    TEST_MSG("machine_id filename expected=%s got=%s", expectedValue, filename);
    TEST_CHECK(filename && strcmp(filename, expectedValue) == 0);
    flb_sds_destroy(filename);

    /* generate a new machine ID and verify it is not null then store for later use */
    flb_sds_t machine_id = get_machine_id(t_ctx->ctx);
    TEST_CHECK(machine_id != NULL);

    /* repeat to confirm existing UUID is maintained */
    flb_sds_t new_machine_id = get_machine_id(t_ctx->ctx);
    TEST_CHECK(new_machine_id != NULL);
    TEST_MSG("machine_id changed, expected=%s got=%s", machine_id, new_machine_id);
    TEST_CHECK(value && strcmp(new_machine_id, machine_id) == 0);
    flb_sds_destroy(new_machine_id);

    /* repeat with new config directory */
    t_ctx = update_config_dir(t_ctx, "/tmp/config/fleet");
    TEST_CHECK(t_ctx != NULL);

    /* check we use the new directory for the filename */
    ret = sprintf(expectedValue, "/tmp/config/fleet/machine-id.conf");
    TEST_CHECK(ret > 0);

    filename = machine_id_fleet_config_filename(t_ctx->ctx);
    TEST_CHECK(filename != NULL);
    TEST_MSG("machine_id filename expected=%s got=%s", expectedValue, filename);
    TEST_CHECK(filename && strcmp(filename, expectedValue) == 0);
    flb_sds_destroy(filename);

    /* check we generate a new value */
    new_machine_id = get_machine_id(t_ctx->ctx);
    TEST_CHECK(new_machine_id != NULL);
    TEST_MSG("machine_id did not change, expected!=%s got=%s", machine_id, new_machine_id);
    TEST_CHECK(new_machine_id && strcmp(new_machine_id, machine_id) != 0);

    flb_sds_destroy(machine_id);
    machine_id = new_machine_id;

    /* repeat to confirm existing UUID is maintained */
    new_machine_id = get_machine_id(t_ctx->ctx);
    TEST_CHECK(new_machine_id != NULL);
    TEST_MSG("machine_id changed, expected=%s got=%s", machine_id, new_machine_id);
    TEST_CHECK(new_machine_id && strcmp(new_machine_id, machine_id) == 0);

    flb_sds_destroy(new_machine_id);
    flb_sds_destroy(machine_id);
    cleanup_test_context(t_ctx);
}

/* Define test list */
TEST_LIST = {
    {"set_fleet_input_properties", test_set_fleet_input_properties},
    {"machine_id_generation", test_calyptia_machine_id_generation},
    {NULL, NULL}
};