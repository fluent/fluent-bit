/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_custom.h>
#include "flb_tests_runtime.h"

const char *flb_input_get_property(const char *key,
                                   struct flb_input_instance *ins);
struct flb_input_instance *flb_input_new(struct flb_config *config,
                                         const char *input, void *data,
                                         int public_only);

flb_sds_t custom_calyptia_pipeline_config_get(struct flb_config *ctx);

void flb_custom_calyptia_pipeline_config_get_test()
{
    const char *cfg_str = "[INPUT]\n    name dummy.0\n[INPUT]\n    name fluentbit_metrics.1\n    tag _calyptia_cloud\n    scrape_on_start true\n    scrape_interval 30\n\n\n[OUTPUT]\n    name  stdout.0\n    match *\n    retry_limit 1\n\n";
    flb_ctx_t *ctx;
    int in_ffd_dummy;
    int in_ffd_metrics;
    int out_ffd;
    struct flb_custom_instance *calyptia;
    flb_sds_t cfg;

    ctx = flb_create();
    flb_sched_ctx_init();

    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    in_ffd_dummy = flb_input(ctx, (char *) "dummy", NULL);
    TEST_CHECK(in_ffd_dummy >= 0);

    in_ffd_metrics = flb_input(ctx, (char *) "fluentbit_metrics", NULL);
    TEST_CHECK(in_ffd_metrics >= 0);
    flb_input_set(ctx, in_ffd_metrics,
                  "tag", "_calyptia_cloud",
                  "scrape_on_start", "true",
                  "scrape_interval", "30",
                  NULL);

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);

    calyptia = flb_custom_new(ctx->config, (char *)"calyptia", NULL);
    TEST_CHECK(calyptia != NULL);
    flb_custom_set_property(calyptia, "api_key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    flb_custom_set_property(calyptia, "log_level", "debug");
    flb_custom_set_property(calyptia, "log_level", "7DDD2941-3ED6-4B8C-9F84-DD04C4A018A4");
    flb_custom_set_property(calyptia, "add_label", "pipeline_id 7DDD2941-3ED6-4B8C-9F84-DD04C4A018A4");
    flb_custom_set_property(calyptia, "calyptia_host", "cloud-api.calyptia.com");
    flb_custom_set_property(calyptia, "calyptia_port", "443");

    cfg = custom_calyptia_pipeline_config_get(ctx->config);
    TEST_CHECK(strcmp(cfg, cfg_str) == 0);

    // fix a thread local storage bug on macos
    flb_output_prepare();
    flb_sds_destroy(cfg);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"get_config_test", flb_custom_calyptia_pipeline_config_get_test},
    {NULL, NULL}
};
