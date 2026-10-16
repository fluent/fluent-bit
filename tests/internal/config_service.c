/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_format.h>

#include "flb_tests_internal.h"

#define UNKNOWN_YAML_CONFIG \
    FLB_TESTS_DATA_PATH "/data/config_format/yaml/unknown_service.yaml"

static void test_service_property_validation(void)
{
    TEST_CHECK(flb_config_service_property_is_valid("flush") == FLB_TRUE);
    TEST_CHECK(flb_config_service_property_is_valid("Log_Level") == FLB_TRUE);
    TEST_CHECK(flb_config_service_property_is_valid("log_livel") == FLB_FALSE);
    TEST_CHECK(flb_config_service_property_is_valid("another_param") == FLB_FALSE);
}

static void test_unknown_service_property_compatibility(void)
{
    int ret;
    int verbose;
    struct flb_log *log;
    struct flb_config *config;

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config == NULL) {
        return;
    }

    log = config->log;
    verbose = config->verbose;

    ret = flb_config_set_property(config, "log_livel", "debug");
    TEST_CHECK(ret == 0);
    TEST_CHECK(config->log == log);
    TEST_CHECK(config->verbose == verbose);

    flb_config_exit(config);
}

static void test_section_name_validation(void)
{
    struct flb_cf *cf;
    struct flb_cf_section *section;

    cf = flb_cf_create();
    TEST_CHECK(cf != NULL);
    if (cf == NULL) {
        return;
    }

    section = flb_cf_section_create(cf, "SERVIC", 0);
    TEST_CHECK(section != NULL);
    TEST_CHECK(section->type == FLB_CF_OTHER);
    TEST_CHECK(cf->service == NULL);

    flb_cf_destroy(cf);
}

static void test_classic_unknown_configuration_load(void)
{
    int ret;
    struct cfl_variant *property;
    struct flb_cf *cf;
    struct flb_cf_section *section;
    struct flb_config *config;

    cf = flb_cf_create();
    TEST_CHECK(cf != NULL);
    if (cf == NULL) {
        return;
    }

    flb_cf_set_origin_format(cf, FLB_CF_CLASSIC);

    section = flb_cf_section_create(cf, "service", 0);
    TEST_CHECK(section != NULL);
    property = flb_cf_section_property_add(cf, section->properties,
                                           "another_param", 0, "0", 0);
    TEST_CHECK(property != NULL);

    section = flb_cf_section_create(cf, "something", 0);
    TEST_CHECK(section != NULL);

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config != NULL) {
        ret = flb_config_load_config_format(config, cf);
        TEST_CHECK(ret == 0);
        flb_config_exit(config);
    }

    flb_cf_destroy(cf);
}

#ifdef FLB_HAVE_LIBYAML
static void test_yaml_unknown_configuration_load(void)
{
    int ret;
    struct flb_cf *cf;
    struct flb_config *config;

    cf = flb_cf_yaml_create(NULL, UNKNOWN_YAML_CONFIG, NULL, 0);
    TEST_CHECK(cf != NULL);
    if (cf == NULL) {
        return;
    }

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config != NULL) {
        ret = flb_config_load_config_format(config, cf);
        TEST_CHECK(ret == 0);
        flb_config_exit(config);
    }

    flb_cf_destroy(cf);
}
#endif

TEST_LIST = {
    { "service_property_validation", test_service_property_validation },
    { "unknown_service_property_compatibility",
      test_unknown_service_property_compatibility },
    { "section_name_validation", test_section_name_validation },
    { "classic_unknown_configuration_load", test_classic_unknown_configuration_load },
#ifdef FLB_HAVE_LIBYAML
    { "yaml_unknown_configuration_load", test_yaml_unknown_configuration_load },
#endif
    { 0 }
};
