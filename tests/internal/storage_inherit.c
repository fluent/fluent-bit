/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include "chunkio/chunkio.h"

#include "flb_tests_internal.h"

static void test_storage_inherit_enabled()
{
    struct flb_config *config;
    struct flb_input_instance *in;
    struct cio_ctx *cio;
    struct cio_options opts = {0};
    int ret;

    /* Create config */
    config = flb_config_init();
    TEST_CHECK(config != NULL);

    /* Set global storage configuration */
    config->storage_type = flb_strdup("filesystem");
    config->storage_inherit = FLB_TRUE;
    config->storage_path = flb_strdup("/tmp/flb-test");

    /* Create CIO context */
    cio_options_init(&opts);
    opts.root_path = "/tmp/flb-test";
    opts.flags = CIO_OPEN;
    cio = cio_create(&opts);
    TEST_CHECK(cio != NULL);
    config->cio = cio;

    /* Create an input instance without explicit storage.type */
    in = flb_input_new(config, "dummy", NULL, FLB_FALSE);
    TEST_CHECK(in != NULL);

    /* Initialize storage - this should inherit filesystem from config */
    ret = flb_storage_input_create(config->cio, in);
    TEST_CHECK(ret == 0);
    
    /* Verify storage type was inherited */
    TEST_CHECK(in->storage_type == FLB_STORAGE_FS);

    /* Cleanup */
    flb_input_exit_all(config);
    if (cio) {
        cio_destroy(cio);
    }
    flb_config_exit(config);
}

static void test_storage_inherit_disabled()
{
    struct flb_config *config;
    struct flb_input_instance *in;
    struct cio_ctx *cio;
    struct cio_options opts = {0};
    int ret;

    /* Create config */
    config = flb_config_init();
    TEST_CHECK(config != NULL);

    /* Set storage type but disable inheritance */
    config->storage_type = flb_strdup("filesystem");
    config->storage_inherit = FLB_FALSE;
    config->storage_path = flb_strdup("/tmp/flb-test");

    /* Create CIO context */
    cio_options_init(&opts);
    opts.root_path = "/tmp/flb-test";
    opts.flags = CIO_OPEN;
    cio = cio_create(&opts);
    TEST_CHECK(cio != NULL);
    config->cio = cio;

    /* Create an input instance without explicit storage.type */
    in = flb_input_new(config, "dummy", NULL, FLB_FALSE);
    TEST_CHECK(in != NULL);

    /* Initialize storage - this should use default memory */
    ret = flb_storage_input_create(config->cio, in);
    TEST_CHECK(ret == 0);
    
    /* Verify storage type defaults to memory */
    TEST_CHECK(in->storage_type == FLB_STORAGE_MEM);

    /* Cleanup */
    flb_input_exit_all(config);
    if (cio) {
        cio_destroy(cio);
    }
    flb_config_exit(config);
}

static void test_storage_explicit_override()
{
    struct flb_config *config;
    struct flb_input_instance *in;
    struct cio_ctx *cio;
    struct cio_options opts = {0};
    int ret;

    /* Create config */
    config = flb_config_init();
    TEST_CHECK(config != NULL);

    /* Set global storage configuration */
    config->storage_type = flb_strdup("filesystem");
    config->storage_inherit = FLB_TRUE;
    config->storage_path = flb_strdup("/tmp/flb-test");

    /* Create CIO context */
    cio_options_init(&opts);
    opts.root_path = "/tmp/flb-test";
    opts.flags = CIO_OPEN;
    cio = cio_create(&opts);
    TEST_CHECK(cio != NULL);
    config->cio = cio;

    /* Create an input instance with explicit storage.type */
    in = flb_input_new(config, "dummy", NULL, FLB_FALSE);
    TEST_CHECK(in != NULL);

    /* Add explicit storage.type property */
    flb_kv_item_create(&in->properties, "storage.type", "memory");

    /* Process the property to set storage_type */
    ret = flb_input_set_property(in, "storage.type", "memory");
    TEST_CHECK(ret == 0);

    /* Initialize storage - this should use explicit memory type */
    ret = flb_storage_input_create(config->cio, in);
    TEST_CHECK(ret == 0);
    
    /* Verify explicit storage type overrides inheritance */
    TEST_CHECK(in->storage_type == FLB_STORAGE_MEM);

    /* Cleanup */
    flb_input_exit_all(config);
    if (cio) {
        cio_destroy(cio);
    }
    flb_config_exit(config);
}

static void test_storage_inherit_invalid_type()
{
    struct flb_config *config;
    struct flb_input_instance *in;
    struct cio_ctx *cio;
    struct cio_options opts = {0};
    int ret;

    /* Create config */
    config = flb_config_init();
    TEST_CHECK(config != NULL);

    /* Set invalid global storage type */
    config->storage_type = flb_strdup("invalid_type");
    config->storage_inherit = FLB_TRUE;
    config->storage_path = flb_strdup("/tmp/flb-test");

    /* Create CIO context */
    cio_options_init(&opts);
    opts.root_path = "/tmp/flb-test";
    opts.flags = CIO_OPEN;
    cio = cio_create(&opts);
    TEST_CHECK(cio != NULL);
    config->cio = cio;

    /* Create an input instance without explicit storage.type */
    in = flb_input_new(config, "dummy", NULL, FLB_FALSE);
    TEST_CHECK(in != NULL);

    /* Initialize storage - should fallback to memory for invalid type */
    ret = flb_storage_input_create(config->cio, in);
    TEST_CHECK(ret == 0);
    
    /* Verify invalid type falls back to memory */
    TEST_CHECK(in->storage_type == FLB_STORAGE_MEM);

    /* Cleanup */
    flb_input_exit_all(config);
    if (cio) {
        cio_destroy(cio);
    }
    flb_config_exit(config);
}

TEST_LIST = {
    {"storage_inherit_enabled",      test_storage_inherit_enabled},
    {"storage_inherit_disabled",     test_storage_inherit_disabled},
    {"storage_explicit_override",    test_storage_explicit_override},
    {"storage_inherit_invalid_type", test_storage_inherit_invalid_type},
    {0}
};