/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_input.h>

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

static void test_checked_pause_resume_result()
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

    context.result = -1;
    ret = flb_input_plugin_pause(&instance);
    TEST_CHECK(ret == -1);
    TEST_CHECK(context.pause_calls == 1);

    ret = flb_input_plugin_resume(&instance);
    TEST_CHECK(ret == -1);
    TEST_CHECK(context.resume_calls == 1);

    context.result = 0;
    ret = flb_input_plugin_pause(&instance);
    TEST_CHECK(ret == 0);
    TEST_CHECK(context.pause_calls == 2);

    ret = flb_input_plugin_resume(&instance);
    TEST_CHECK(ret == 0);
    TEST_CHECK(context.resume_calls == 2);
}

TEST_LIST = {
    { "checked_pause_resume_result", test_checked_pause_resume_result },
    { 0 }
};
