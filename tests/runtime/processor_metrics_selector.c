/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include "flb_tests_runtime.h"

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int  num_output = 0;

static int cb_count_metrics_msgpack(void *record, size_t size, void *data)
{
    int i;
    int ret;
    size_t off = 0;
    cfl_sds_t text = NULL;
    struct cmt *cmt = NULL;
    char *p;

    if (!TEST_CHECK(data != NULL)) {
        flb_error("data is NULL");
    }

    /* get cmetrics context */
    ret = cmt_decode_msgpack_create(&cmt, (char *) record, size, &off);
    if (ret != 0) {
        flb_error("could not process metrics payload");
        return -1;
    }

    /* convert to text representation */
    text = cmt_encode_text_create(cmt);
    /* To inspect the metrics from the callback, just comment out below: */
    /* flb_info("[filter_grep][test] text = %s", text); */
    for (i = 0; i < strlen(text); i++) {
        p = (char *)(text + i);
        if (*p == '\n') {
            num_output++;
        }
    }

    if (record) {
        flb_free(record);
    }

    /* destroy cmt context */
    cmt_destroy(cmt);

    cmt_encode_text_destroy(text);

    return 0;
}


static void clear_output_num()
{
    pthread_mutex_lock(&result_mutex);
    num_output = 0;
    pthread_mutex_unlock(&result_mutex);
}

static int get_output_num()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

#ifdef FLB_HAVE_METRICS
void flb_test_selector_regex_include(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct cfl_variant var = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "/storage/",
    };
    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "include",
    };
    int got;
    int n_metrics = 12;
    int not_used = 0;
    struct flb_lib_out_cb cb_data;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_metrics_msgpack;
    cb_data.data = &not_used;

    ctx = flb_create();
    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "2",
                    NULL);

    proc = flb_processor_create(ctx->config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_METRICS, "metrics_selector");
    TEST_CHECK(pu != NULL);
    ret = flb_processor_unit_set_property(pu, "metric_name", &var);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu, "action", &action);
    TEST_CHECK(ret == 0);


    /* Input */
    in_ffd = flb_input(ctx, (char *) "fluentbit_metrics", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "scrape_on_start", "true", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "scrape_interval", "1", NULL);
    TEST_CHECK(ret == 0);

    /* set up processor */
    ret = flb_input_set_processor(ctx, in_ffd, proc);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    clear_output_num();

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500); /* waiting flush */

    got = get_output_num();
    if (!TEST_CHECK(got >= n_metrics)) {
        TEST_MSG("expect: %d >= %d, got: %d < %d", got, n_metrics, got, n_metrics);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_selector_regex_exclude(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct cfl_variant var = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "/input/",
    };
    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "exclude",
    };
    int got;
    int n_metrics = 19;
    int not_used = 0;
    struct flb_lib_out_cb cb_data;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_metrics_msgpack;
    cb_data.data = &not_used;

    ctx = flb_create();
    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "2",
                    NULL);

    proc = flb_processor_create(ctx->config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_METRICS, "metrics_selector");
    TEST_CHECK(pu != NULL);
    ret = flb_processor_unit_set_property(pu, "metric_name", &var);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu, "action", &action);
    TEST_CHECK(ret == 0);


    /* Input */
    in_ffd = flb_input(ctx, (char *) "fluentbit_metrics", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "scrape_on_start", "true", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "scrape_interval", "1", NULL);
    TEST_CHECK(ret == 0);

    /* set up processor */
    ret = flb_input_set_processor(ctx, in_ffd, proc);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    clear_output_num();

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500); /* waiting flush */

    got = get_output_num();
    if (!TEST_CHECK(got >= n_metrics)) {
        TEST_MSG("expect: %d >= %d, got: %d < %d", got, n_metrics, got, n_metrics);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_selector_prefix_include(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct cfl_variant var = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "fluentbit_input",
    };
    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "include",
    };
    struct cfl_variant op_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "prefix",
    };
    int got;
    int n_metrics = 11;
    int not_used = 0;
    struct flb_lib_out_cb cb_data;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_metrics_msgpack;
    cb_data.data = &not_used;

    ctx = flb_create();
    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "2",
                    NULL);

    proc = flb_processor_create(ctx->config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_METRICS, "metrics_selector");
    TEST_CHECK(pu != NULL);
    ret = flb_processor_unit_set_property(pu, "metric_name", &var);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu, "operation_type", &op_type);
    TEST_CHECK(ret == 0);


    /* Input */
    in_ffd = flb_input(ctx, (char *) "fluentbit_metrics", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "scrape_on_start", "true", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "scrape_interval", "1", NULL);
    TEST_CHECK(ret == 0);

    /* set up processor */
    ret = flb_input_set_processor(ctx, in_ffd, proc);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    clear_output_num();

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500); /* waiting flush */

    got = get_output_num();
    if (!TEST_CHECK(got >= n_metrics)) {
        TEST_MSG("expect: %d >= %d, got: %d < %d", got, n_metrics, got, n_metrics);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_selector_prefix_exclude(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct cfl_variant var = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "fluentbit_storage",
    };
    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "exclude",
    };
    struct cfl_variant op_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "prefix",
    };
    int got;
    int n_metrics = 25;
    int not_used = 0;
    struct flb_lib_out_cb cb_data;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_metrics_msgpack;
    cb_data.data = &not_used;

    ctx = flb_create();
    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "2",
                    NULL);

    proc = flb_processor_create(ctx->config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_METRICS, "metrics_selector");
    TEST_CHECK(pu != NULL);
    ret = flb_processor_unit_set_property(pu, "metric_name", &var);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu, "operation_type", &op_type);
    TEST_CHECK(ret == 0);


    /* Input */
    in_ffd = flb_input(ctx, (char *) "fluentbit_metrics", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "scrape_on_start", "true", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "scrape_interval", "1", NULL);
    TEST_CHECK(ret == 0);

    /* set up processor */
    ret = flb_input_set_processor(ctx, in_ffd, proc);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    clear_output_num();

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500); /* waiting flush */

    got = get_output_num();
    if (!TEST_CHECK(got >= n_metrics)) {
        TEST_MSG("expect: %d >= %d, got: %d < %d", got, n_metrics, got, n_metrics);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_selector_substring_include(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct cfl_variant var = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "dropped",
    };
    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "include",
    };
    struct cfl_variant op_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "substring",
    };
    int got;
    int n_metrics = 1;
    int not_used = 0;
    struct flb_lib_out_cb cb_data;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_metrics_msgpack;
    cb_data.data = &not_used;

    ctx = flb_create();
    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "2",
                    NULL);

    proc = flb_processor_create(ctx->config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_METRICS, "metrics_selector");
    TEST_CHECK(pu != NULL);
    ret = flb_processor_unit_set_property(pu, "metric_name", &var);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu, "operation_type", &op_type);
    TEST_CHECK(ret == 0);


    /* Input */
    in_ffd = flb_input(ctx, (char *) "fluentbit_metrics", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "scrape_on_start", "true", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "scrape_interval", "1", NULL);
    TEST_CHECK(ret == 0);

    /* set up processor */
    ret = flb_input_set_processor(ctx, in_ffd, proc);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    clear_output_num();

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500); /* waiting flush */

    got = get_output_num();
    if (!TEST_CHECK(got >= n_metrics)) {
        TEST_MSG("expect: %d >= %d, got: %d < %d", got, n_metrics, got, n_metrics);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_selector_substring_exclude(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct cfl_variant var = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "connections",
    };
    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "exclude",
    };
    struct cfl_variant op_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "substring",
    };
    int got;
    int n_metrics = 28;
    int not_used = 0;
    struct flb_lib_out_cb cb_data;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_metrics_msgpack;
    cb_data.data = &not_used;

    ctx = flb_create();
    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "2",
                    NULL);

    proc = flb_processor_create(ctx->config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_METRICS, "metrics_selector");
    TEST_CHECK(pu != NULL);
    ret = flb_processor_unit_set_property(pu, "metric_name", &var);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu, "operation_type", &op_type);
    TEST_CHECK(ret == 0);


    /* Input */
    in_ffd = flb_input(ctx, (char *) "fluentbit_metrics", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "scrape_on_start", "true", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "scrape_interval", "1", NULL);
    TEST_CHECK(ret == 0);

    /* set up processor */
    ret = flb_input_set_processor(ctx, in_ffd, proc);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    clear_output_num();

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500); /* waiting flush */

    got = get_output_num();
    if (!TEST_CHECK(got >= n_metrics)) {
        TEST_MSG("expect: %d >= %d, got: %d < %d", got, n_metrics, got, n_metrics);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_selector_can_modify_output(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct cfl_variant var = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "/kubernetes/",
    };
    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "include",
    };

    ctx = flb_create();
    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "2",
                    NULL);

    proc = flb_processor_create(ctx->config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_METRICS, "metrics_selector");
    TEST_CHECK(pu != NULL);
    ret = flb_processor_unit_set_property(pu, "metric_name", &var);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu, "action", &action);
    TEST_CHECK(ret == 0);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "event_type", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "type", "metrics", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "interval_sec", "1", NULL);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd, "match", "test", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set(ctx, out_ffd, "format", "msgpack", NULL);
    TEST_CHECK(ret == 0);

    /* set up processor */
    ret = flb_output_set_processor(ctx, out_ffd, proc);
    TEST_CHECK(ret == 0);

    clear_output_num();

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}


void flb_test_selector_context_delete_label_value(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct cfl_variant var = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "delete_label_value",
    };
    struct cfl_variant label_pair = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "name lib.0",
    };
    int got;
    int n_metrics = 20;
    int not_used = 0;
    struct flb_lib_out_cb cb_data;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_metrics_msgpack;
    cb_data.data = &not_used;

    ctx = flb_create();
    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "2",
                    NULL);

    proc = flb_processor_create(ctx->config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_METRICS, "metrics_selector");
    TEST_CHECK(pu != NULL);
    ret = flb_processor_unit_set_property(pu, "context", &var);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu, "label", &label_pair);
    TEST_CHECK(ret == 0);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "fluentbit_metrics", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "scrape_on_start", "true", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "scrape_interval", "1", NULL);
    TEST_CHECK(ret == 0);

    /* set up processor */
    ret = flb_input_set_processor(ctx, in_ffd, proc);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    clear_output_num();

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500); /* waiting flush */

    got = get_output_num();
    if (!TEST_CHECK(got >= n_metrics)) {
        TEST_MSG("expect: %d >= %d, got: %d < %d", got, n_metrics, got, n_metrics);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}
#endif

/* Test list */
TEST_LIST = {
#ifdef FLB_HAVE_METRICS
    {"regex_include", flb_test_selector_regex_include},
    {"regex_exclude", flb_test_selector_regex_exclude},
    {"prefix_include", flb_test_selector_prefix_include},
    {"prefix_exclude", flb_test_selector_prefix_exclude},
    {"substring_include", flb_test_selector_substring_include},
    {"substring_exclude", flb_test_selector_substring_exclude},
    {"can_modify_output", flb_test_selector_can_modify_output},
    {"context_delete_label_value", flb_test_selector_context_delete_label_value},
#endif
    {NULL, NULL}
};
