/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_config_format.h>
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_reload.h>

#include <cfl/cfl.h>
#include <cfl/cfl_variant.h>
#include <cfl/cfl_kvlist.h>

#include "flb_tests_internal.h"

#define FLB_YAML    FLB_TESTS_DATA_PATH "/data/reload/yaml/processor.yaml"
#define FLB_CLASSIC FLB_TESTS_DATA_PATH "/data/reload/fluent-bit.conf"

void test_reconstruct_cf()
{
    struct flb_cf *cf;
    struct flb_cf_section *s_tmp;
    struct flb_cf_section *service;
    struct flb_cf_group *g_tmp;
    struct cfl_variant *ret;
    struct flb_kv *meta;
    struct flb_cf *new_cf;
    int status;


    /* create context */
    cf = flb_cf_create();
    TEST_CHECK(cf != NULL);

    /* create service section */
    service = flb_cf_section_create(cf, "SERVICE", 7);
    TEST_CHECK(service != NULL);

    /* add a property */
    ret = flb_cf_section_property_add(cf, service->properties, "key", 3, "val", 3);
    TEST_CHECK(ret != NULL);

    /* add a property with empty spaces on left/right */
    ret = flb_cf_section_property_add(cf, service->properties, " key ", 5, " val   ", 7);
    TEST_CHECK(ret != NULL);

    /* add an invalid property */
    ret = flb_cf_section_property_add(cf, service->properties, "   ", 3, "", 0);
    TEST_CHECK(ret == NULL);

    /* try to add another 'SERVICE' section, it should return the same one */
    s_tmp = flb_cf_section_create(cf, "SERVICE", 7);
    TEST_CHECK(s_tmp == service);

    /* add a valid section */
    s_tmp = flb_cf_section_create(cf, "INPUT", 5);
    TEST_CHECK(s_tmp != NULL);

    TEST_CHECK(mk_list_size(&cf->inputs) == 1);

    /* add property to the section recently created */
    ret = flb_cf_section_property_add(cf, s_tmp->properties, "key", 3, "val", 3);
    TEST_CHECK(ret != NULL);

    /* groups: add groups to the last section created */
    g_tmp = flb_cf_group_create(cf, s_tmp, "FLUENT GROUP", 12);
    TEST_CHECK(g_tmp != NULL);

    /* add properties to the group */
    ret = flb_cf_section_property_add(cf, g_tmp->properties, "key", 3, "val", 3);
    TEST_CHECK(ret != NULL);

    /* groups: invalid group */
    g_tmp = flb_cf_group_create(cf, s_tmp, "", 0);
    TEST_CHECK(g_tmp == NULL);

    /* Meta commands */
    meta = flb_cf_meta_property_add(cf, "@SET        a=1     ", 20);

    TEST_CHECK(meta != NULL);
    TEST_CHECK(flb_sds_len(meta->key) == 3 && strcmp(meta->key, "SET") == 0);
    TEST_CHECK(flb_sds_len(meta->val) == 3 && strcmp(meta->val, "a=1") == 0);

    /* create new context */
    new_cf = flb_cf_create();
    TEST_CHECK(cf != NULL);

    status = flb_reload_reconstruct_cf(cf, new_cf);
    TEST_CHECK(status == 0);
    TEST_CHECK(new_cf != NULL);

    TEST_CHECK(mk_list_size(&new_cf->inputs) == 1);
    TEST_CHECK(mk_list_size(&new_cf->sections) == 2);
    TEST_CHECK(mk_list_size(&new_cf->metas) == 1);

    printf("\n");
    flb_cf_dump(new_cf);

    /* destroy context */
    flb_cf_destroy(cf);
    flb_cf_destroy(new_cf);
}

/* data/reload/fluent-bit.conf */
void test_reload()
{
    struct flb_cf *cf = NULL;
    struct flb_cf *cf_opts;
    struct flb_cf_section *section;
    struct cfl_variant *ret;
    flb_ctx_t *ctx;
    int status;

    /* create context */
    cf_opts = flb_cf_create();
    TEST_CHECK(cf_opts != NULL);

    /* add a valid section (input) */
    section = flb_cf_section_create(cf_opts, "INPUT", 5);
    TEST_CHECK(section != NULL);

    /* add property to the section recently created */
    ret = flb_cf_section_property_add(cf_opts, section->properties, "name", 0, "dummy", 0);
    TEST_CHECK(ret != NULL);

    TEST_CHECK(mk_list_size(&cf_opts->inputs) == 1);

    ctx = flb_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("flb_create failed");
        exit(EXIT_FAILURE);
    }

    cf = ctx->config->cf_main;

    status = flb_reload_reconstruct_cf(cf_opts, cf);
    TEST_CHECK(status == 0);

    /* Mimic operation like as service_configure() */
    cf = flb_cf_create_from_file(cf, FLB_CLASSIC);
    TEST_CHECK(cf != NULL);

    ctx->config->conf_path_file = flb_sds_create(FLB_CLASSIC);
    ctx->config->enable_hot_reload = FLB_TRUE;

    status = flb_config_load_config_format(ctx->config, cf);
    TEST_CHECK(status == 0);

    /* Start the engine */
    status = flb_start(ctx);
    TEST_CHECK(status == 0);
    TEST_CHECK(mk_list_size(&ctx->config->inputs) == 2);

    sleep(2);

    status = flb_reload(ctx, cf_opts);
    TEST_CHECK(status == 0);

    sleep(2);

    /* flb context should be replaced with flb_reload() */
    ctx = flb_context_get();

    TEST_CHECK(mk_list_size(&ctx->config->cf_opts->inputs) == 1);
    TEST_CHECK(mk_list_size(&ctx->config->inputs) == 2);

    flb_cf_destroy(cf_opts);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* data/reload/yaml/processor.yaml */
void test_reload_yaml()
{
    struct flb_cf *cf = NULL;
    struct flb_cf *cf_opts;
    struct flb_cf_section *section;
    struct cfl_variant *ret;
    flb_ctx_t *ctx;
    int status;

    /* create context */
    cf_opts = flb_cf_create();
    TEST_CHECK(cf_opts != NULL);

    /* add a valid section (input) */
    section = flb_cf_section_create(cf_opts, "INPUT", 5);
    TEST_CHECK(section != NULL);

    /* add property to the section recently created */
    ret = flb_cf_section_property_add(cf_opts, section->properties, "name", 0, "dummy", 0);
    TEST_CHECK(ret != NULL);

    TEST_CHECK(mk_list_size(&cf_opts->inputs) == 1);

    ctx = flb_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("flb_create failed");
        exit(EXIT_FAILURE);
    }

    cf = ctx->config->cf_main;

    status = flb_reload_reconstruct_cf(cf_opts, cf);
    TEST_CHECK(status == 0);

    /* Mimic operation like as service_configure() */
    cf = flb_cf_create_from_file(cf, FLB_YAML);
    TEST_CHECK(cf != NULL);

    ctx->config->conf_path_file = flb_sds_create(FLB_YAML);
    ctx->config->enable_hot_reload = FLB_TRUE;

    status = flb_config_load_config_format(ctx->config, cf);
    TEST_CHECK(status == 0);

    /* Start the engine */
    status = flb_start(ctx);
    TEST_CHECK(status == 0);
    TEST_CHECK(mk_list_size(&ctx->config->inputs) == 2);

    sleep(2);

    status = flb_reload(ctx, cf_opts);
    TEST_CHECK(status == 0);

    sleep(2);

    /* flb context should be replaced with flb_reload() */
    ctx = flb_context_get();

    TEST_CHECK(mk_list_size(&ctx->config->cf_opts->inputs) == 1);
    TEST_CHECK(mk_list_size(&ctx->config->inputs) == 2);
    TEST_CHECK(mk_list_size(&ctx->config->filters) == 0);
    TEST_CHECK(mk_list_size(&ctx->config->outputs) == 1);

    flb_cf_destroy(cf_opts);

    flb_stop(ctx);
    flb_destroy(ctx);
}

TEST_LIST = {
    { "reconstruct_cf" , test_reconstruct_cf},
    { "reload"         , test_reload},
    { "reload_yaml"    , test_reload_yaml},
    { 0 }
};
