/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_time.h>
#include <pthread.h>

#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_encode_text.h>

#include "flb_tests_runtime.h"

static pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
static int metrics_condition_met = FLB_FALSE;

static void set_metrics_condition_met(int value)
{
    pthread_mutex_lock(&result_mutex);
    metrics_condition_met = value;
    pthread_mutex_unlock(&result_mutex);
}

static int get_metrics_condition_met(void)
{
    int result;

    pthread_mutex_lock(&result_mutex);
    result = metrics_condition_met;
    pthread_mutex_unlock(&result_mutex);

    return result;
}

static double find_metric_value(const char *text,
                                const char *metric_name,
                                const char *output_name)
{
    char *line;
    char *next;
    size_t prefix_size;
    double value;
    char prefix[256];

    snprintf(prefix, sizeof(prefix), "%s{name=\"%s\"} ",
             metric_name, output_name);
    prefix_size = strlen(prefix);

    line = (char *) text;
    while (line != NULL && *line != '\0') {
        next = strchr(line, '\n');

        if (strncmp(line, prefix, prefix_size) == 0) {
            value = strtod(line + prefix_size, NULL);
            return value;
        }

        if (next == NULL) {
            break;
        }

        line = next + 1;
    }

    return -1.0;
}

static int cb_check_output_processor_counters(void *record, size_t size, void *data)
{
    int ret;
    size_t off = 0;
    struct cmt *cmt;
    cfl_sds_t text;
    double proc_records;
    double dropped_records;

    (void) data;

    cmt = NULL;
    text = NULL;

    ret = cmt_decode_msgpack_create(&cmt, (char *) record, size, &off);
    if (ret != 0) {
        if (record != NULL) {
            flb_free(record);
        }

        return -1;
    }

    text = cmt_encode_text_create(cmt);
    if (text != NULL) {
        proc_records = find_metric_value(text,
                                         "fluentbit_output_proc_records_total",
                                         "stdout.0");
        dropped_records = find_metric_value(text,
                                            "fluentbit_output_dropped_records_total",
                                            "stdout.0");

        if (proc_records == 0.0 && dropped_records > 0.0) {
            set_metrics_condition_met(FLB_TRUE);
        }

        cmt_encode_text_destroy(text);
    }

    cmt_destroy(cmt);

    if (record != NULL) {
        flb_free(record);
    }

    return 0;
}

void flb_test_output_processor_drop_counters(void)
{
    int ret;
    int in_ffd;
    int metrics_in_ffd;
    int out_ffd;
    int metrics_out_ffd;
    int wait_cycles;
    flb_ctx_t *ctx;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct flb_lib_out_cb cb_data;
    struct cfl_variant call_property = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "cb_drop",
    };
    struct cfl_variant code_property = {
        .type = CFL_VARIANT_STRING,
        .data.as_string =
        "function cb_drop(tag, timestamp, record)\n"
        "  return -1, timestamp, record\n"
        "end",
    };

    cb_data.cb = cb_check_output_processor_counters;
    cb_data.data = NULL;

    set_metrics_condition_met(FLB_FALSE);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "2",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "dummy", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd,
                        "tag", "dummy.data",
                        "rate", "10",
                        NULL);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);

    proc = flb_processor_create(ctx->config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_LOGS, "lua");
    TEST_CHECK(pu != NULL);

    ret = flb_processor_unit_set_property(pu, "call", &call_property);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu, "code", &code_property);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_processor(ctx, out_ffd, proc);
    TEST_CHECK(ret == 0);

    metrics_in_ffd = flb_input(ctx, (char *) "fluentbit_metrics", NULL);
    TEST_CHECK(metrics_in_ffd >= 0);
    ret = flb_input_set(ctx, metrics_in_ffd,
                        "tag", "fb.metrics",
                        "scrape_on_start", "true",
                        "scrape_interval", "1",
                        NULL);
    TEST_CHECK(ret == 0);

    metrics_out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(metrics_out_ffd >= 0);
    ret = flb_output_set(ctx, metrics_out_ffd, "match", "fb.metrics", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (wait_cycles = 0;
         wait_cycles < 30 && get_metrics_condition_met() == FLB_FALSE;
         wait_cycles++) {
        flb_time_msleep(200);
    }

    TEST_CHECK(get_metrics_condition_met() == FLB_TRUE);

    flb_stop(ctx);
    flb_destroy(ctx);
}

TEST_LIST = {
#if defined(FLB_HAVE_METRICS) && defined(FLB_FILTER_LUA)
    {"output_processor_drop_counters", flb_test_output_processor_drop_counters},
#endif
    {NULL, NULL}
};
