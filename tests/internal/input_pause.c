/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_thread.h>
#include <fluent-bit/flb_socket.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_gauge.h>

#include <string.h>

#include "flb_tests_internal.h"

struct input_pause_test_context {
    int pause_calls;
    int resume_calls;
    int result;
};

static int checked_pause(void *data, struct flb_config *config)
{
    struct input_pause_test_context *context;

    (void) config;

    context = data;
    context->pause_calls++;

    return context->result;
}

static int checked_resume(void *data, struct flb_config *config)
{
    struct input_pause_test_context *context;

    (void) config;

    context = data;
    context->resume_calls++;

    return context->result;
}

static int input_pause_test_metrics_init(struct flb_input_instance *instance)
{
    int ret;
    char *label_keys[] = {"name"};
    char *label_values[] = {instance->name};

    instance->cmt = cmt_create();
    if (instance->cmt == NULL) {
        return -1;
    }

    instance->cmt_ingestion_paused = cmt_gauge_create(
        instance->cmt,
        "fluentbit", "input", "ingestion_paused",
        "Is the input paused or not?", 1, label_keys);
    if (instance->cmt_ingestion_paused == NULL) {
        cmt_destroy(instance->cmt);
        instance->cmt = NULL;
        return -1;
    }

    ret = cmt_gauge_set(instance->cmt_ingestion_paused, 0, 0, 1, label_values);
    if (ret != 0) {
        cmt_destroy(instance->cmt);
        instance->cmt = NULL;
        instance->cmt_ingestion_paused = NULL;
    }

    return ret;
}

static double input_pause_test_metric_value(struct flb_input_instance *instance)
{
    int ret;
    double value;
    char *label_values[] = {instance->name};

    value = -1;
    ret = cmt_gauge_get_val(instance->cmt_ingestion_paused, 1, label_values, &value);
    TEST_CHECK(ret == 0);

    return value;
}

static void input_pause_test_metrics_destroy(struct flb_input_instance *instance)
{
    cmt_destroy(instance->cmt);
    instance->cmt = NULL;
    instance->cmt_ingestion_paused = NULL;
}

static void test_checked_pause_resume_result_and_metric()
{
    int ret;
    struct flb_input_plugin plugin;
    struct flb_input_instance instance;
    struct input_pause_test_context context;

    memset(&plugin, 0, sizeof(plugin));
    memset(&instance, 0, sizeof(instance));
    memset(&context, 0, sizeof(context));

    plugin.cb_pause_checked = checked_pause;
    plugin.cb_resume_checked = checked_resume;
    instance.p = &plugin;
    instance.context = &context;
    strncpy(instance.name, "test.0", sizeof(instance.name) - 1);

    ret = input_pause_test_metrics_init(&instance);
    if (!TEST_CHECK(ret == 0)) {
        return;
    }

    context.result = -1;
    ret = flb_input_plugin_pause(&instance);
    TEST_CHECK(ret == -1);
    TEST_CHECK(context.pause_calls == 1);
    TEST_CHECK(input_pause_test_metric_value(&instance) == 0);

    context.result = 0;
    ret = flb_input_plugin_pause(&instance);
    TEST_CHECK(ret == 0);
    TEST_CHECK(context.pause_calls == 2);
    TEST_CHECK(input_pause_test_metric_value(&instance) == 1);

    context.result = -1;
    ret = flb_input_plugin_resume(&instance);
    TEST_CHECK(ret == -1);
    TEST_CHECK(context.resume_calls == 1);
    TEST_CHECK(input_pause_test_metric_value(&instance) == 1);

    context.result = 0;
    ret = flb_input_plugin_resume(&instance);
    TEST_CHECK(ret == 0);
    TEST_CHECK(context.resume_calls == 2);
    TEST_CHECK(input_pause_test_metric_value(&instance) == 0);

    input_pause_test_metrics_destroy(&instance);
}

static void test_threaded_dispatch_failure_preserves_state()
{
    int ret;
    struct flb_input_plugin plugin;
    struct flb_input_instance instance;
    struct flb_input_thread_instance thread_instance;
    struct input_pause_test_context context;

    memset(&plugin, 0, sizeof(plugin));
    memset(&instance, 0, sizeof(instance));
    memset(&thread_instance, 0, sizeof(thread_instance));
    memset(&context, 0, sizeof(context));

    plugin.cb_pause_checked = checked_pause;
    plugin.cb_resume_checked = checked_resume;
    instance.p = &plugin;
    instance.context = &context;
    instance.is_threaded = FLB_TRUE;
    instance.thi = &thread_instance;
    thread_instance.ch_parent_events[1] = FLB_INVALID_SOCKET;
    strncpy(instance.name, "threaded.0", sizeof(instance.name) - 1);

    ret = input_pause_test_metrics_init(&instance);
    if (!TEST_CHECK(ret == 0)) {
        return;
    }

    ret = flb_input_pause(&instance);
    TEST_CHECK(ret == -1);
    TEST_CHECK(context.pause_calls == 0);
    TEST_CHECK(input_pause_test_metric_value(&instance) == 0);

    ret = cmt_gauge_set(instance.cmt_ingestion_paused, 0, 1, 1,
                        (char *[]) {instance.name});
    TEST_CHECK(ret == 0);

    ret = flb_input_resume(&instance);
    TEST_CHECK(ret == -1);
    TEST_CHECK(context.resume_calls == 0);
    TEST_CHECK(input_pause_test_metric_value(&instance) == 1);

    input_pause_test_metrics_destroy(&instance);
}

TEST_LIST = {
    { "checked_pause_resume_result_and_metric",
      test_checked_pause_resume_result_and_metric },
    { "threaded_dispatch_failure_preserves_state",
      test_threaded_dispatch_failure_preserves_state },
    { 0 }
};
