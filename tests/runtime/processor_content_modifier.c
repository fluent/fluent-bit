/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>
#include "flb_tests_runtime.h"

struct processor_test {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd */
    int o_ffd;         /* Output fd */
    int type; /* logs/metrics/traces */
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
};

struct expect_str {
    char *str;
    int  found;
};


/* Callback to check expected results */
static int cb_check_result(void *record, size_t size, void *data)
{
    char *p;
    char *result;
    struct expect_str *expected;

    expected = (struct expect_str*)data;
    result = (char *) record;

    if (!TEST_CHECK(expected != NULL)) {
        flb_error("expected is NULL");
    }
    if (!TEST_CHECK(result != NULL)) {
        flb_error("result is NULL");
    }

    while(expected != NULL && expected->str != NULL) {
        if (expected->found == FLB_TRUE) {
            p = strstr(result, expected->str);
            if(!TEST_CHECK(p != NULL)) {
                flb_error("Expected to find: '%s' in result '%s'",
                          expected->str, result);
            }
        }
        else {
            p = strstr(result, expected->str);
            if(!TEST_CHECK(p == NULL)) {
                flb_error("'%s' should be removed in result '%s'",
                          expected->str, result);
            }
        }

        /*
         * If you want to debug your test
         *
         * printf("Expect: '%s' in result '%s'", expected, result);
         */

        expected++;
    }

    flb_free(record);
    return 0;
}

static int cb_check_metadata_result(void *record, size_t size, void *data)
{
    int ret;
    char *p;
    flb_sds_t result;
    size_t result_size = 1024;
    struct expect_str *expected;
    struct flb_log_event event;
    struct flb_log_event_decoder decoder;

    expected = (struct expect_str *) data;
    result = NULL;

    ret = flb_log_event_decoder_init(&decoder, (char *) record, size);
    if (!TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS)) {
        return -1;
    }

    flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);

    ret = flb_log_event_decoder_next(&decoder, &event);
    if (!TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS)) {
        flb_log_event_decoder_destroy(&decoder);
        return -1;
    }

    result = flb_sds_create_size(result_size);
    if (!TEST_CHECK(result != NULL)) {
        flb_log_event_decoder_destroy(&decoder);
        return -1;
    }

    ret = flb_msgpack_to_json(result, result_size, event.metadata, FLB_TRUE);
    if (!TEST_CHECK(ret >= 0)) {
        flb_sds_destroy(result);
        flb_log_event_decoder_destroy(&decoder);
        return -1;
    }

    while(expected != NULL && expected->str != NULL) {
        if (expected->found == FLB_TRUE) {
            p = strstr(result, expected->str);
            if(!TEST_CHECK(p != NULL)) {
                flb_error("Expected to find: '%s' in metadata '%s'",
                          expected->str, result);
            }
        }
        else {
            p = strstr(result, expected->str);
            if(!TEST_CHECK(p == NULL)) {
                flb_error("'%s' should be removed from metadata '%s'",
                          expected->str, result);
            }
        }

        expected++;
    }

    flb_sds_destroy(result);
    flb_log_event_decoder_destroy(&decoder);

    return 0;
}

static int init_logs(struct processor_test *ctx, struct flb_lib_out_cb *data)
{
    int i_ffd;
    int o_ffd;
    int ret;

    /* Input */
    i_ffd = flb_input(ctx->flb, (char *) "lib", NULL);
    if(!TEST_CHECK(i_ffd >= 0)) {
        TEST_MSG("flb_input failed");
        return -1;
    }
    flb_input_set(ctx->flb, i_ffd, "tag", "test", NULL);
    ctx->i_ffd = i_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    if(!TEST_CHECK(o_ffd >= 0)) {
        TEST_MSG("flb_output failed");
        return -1;
    }
    flb_output_set(ctx->flb, o_ffd,
                   "match", "test",
                   NULL);
    ctx->o_ffd = o_ffd;

    ctx->pu = flb_processor_unit_create(ctx->proc, ctx->type, "content_modifier");
    if(!TEST_CHECK(ctx->pu != NULL)) {
        TEST_MSG("flb_processor_unit_create failed");
        return -1;
    }

    ret = flb_input_set_processor(ctx->flb, i_ffd, ctx->proc);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_input_set_processor faild");
        return -1;
    }

    return 0;
}

static struct processor_test *processor_test_create(int type, struct flb_lib_out_cb *data)
{
    struct processor_test *ctx;
    int ret = -1;

    ctx = flb_malloc(sizeof(struct processor_test));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->proc = NULL;
    ctx->i_ffd = -1;
    ctx->f_ffd = -1;

    /* Service config */
    ctx->flb = flb_create();
    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    ctx->proc = flb_processor_create(ctx->flb->config, "unit_test", NULL, 0);
    if (!TEST_CHECK(ctx->proc != NULL)) {
        TEST_MSG("flb_processor_create failed");
        flb_destroy(ctx->flb);
        flb_free(ctx);
        return NULL;
    }

    ctx->type = type;
    switch (type) {
    case FLB_PROCESSOR_LOGS:
        ret = init_logs(ctx, data);
        break;
    default:
        flb_error("not implemented");
    }


    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("init failed");
        flb_destroy(ctx->flb);
        flb_free(ctx);
        return NULL;
    }

    return ctx;
}

static void processor_test_destroy(struct processor_test *ctx)
{
    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

static void flb_logs_action_insert()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"new_key\":\"new_value\"", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "insert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "new_key",
    };
    struct cfl_variant value = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "new_value",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "value", &value);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[[0, {}], {\"k\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_delete()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"key\":\"value\"", FLB_FALSE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "delete",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "key",
    };
    struct cfl_variant value = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "value",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "value", &value);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"key\":\"value\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_rename()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"key\":\"value\"", FLB_FALSE},
      {"\"new_key\":\"value\"", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "rename",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "key",
    };
    struct cfl_variant value = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "new_key",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "value", &value);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"key\":\"value\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_upsert()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"key\":\"new_value\"", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "upsert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "key",
    };
    struct cfl_variant value = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "new_value",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "value", &value);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"key\":\"value\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_hash()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"key\":\"value\"", FLB_FALSE},
      {"\"key\":\"cd42404d52ad55ccfa9aca4adc828aa5800ad9d385a0671fbcbf724118320619\"", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "hash",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "key",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);


    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"key\":\"value\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_extract()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"k\":\"sample\"", FLB_TRUE},
      {"\"log\":\"exception occurred\"", FLB_TRUE},
      {"\"date\":\"2024/03/15\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "extract",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "key",
    };
    struct cfl_variant pattern = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "/(?<date>\\d{4}\\/\\d{2}\\/\\d{2}) (?<log>.+)/",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "pattern", &pattern);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"key\":\"2024/03/15 exception occurred\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_string_to_int()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"str\":100", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "str",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "int",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"str\":\"100\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_int_to_string()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"i_key\":\"-100\"", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "i_key",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "string",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"i_key\":-100}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_string_to_double()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"str\":123.456", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "str",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "double",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"str\":\"123.456\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_double_to_string()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"d_key\":\"123.456\"", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "d_key",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "string",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"d_key\":123.456}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_string_to_boolean()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"str\":false", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "str",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "boolean",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"str\":\"false\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_int_to_boolean()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"i_key\":true", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "i_key",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "boolean",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"i_key\":-100}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_int_to_double()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"i_key\":-100.0", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "i_key",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "double",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"i_key\":-100}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_double_to_int()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"d_key\":123", FLB_TRUE},
      {"\"d_key\":123.", FLB_FALSE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "d_key",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "int",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"d_key\":123.456}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_double_to_boolean()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"d_key\":true", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "d_key",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "boolean",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"d_key\":123.456}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_null_to_string()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"n_key\":\"null\"", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "n_key",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "string",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"n_key\":null}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_null_to_int()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"n_key\":0", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "n_key",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "int",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"n_key\":null}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_null_to_double()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"n_key\":0.0", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "n_key",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "double",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"n_key\":null}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_otel_log_attributes_insert()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"otlp\":{\"attributes\":{\"my_otlp_attr\":\"my_otlp_value\"}}", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "insert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "otel_log_attributes",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "my_otlp_attr",
    };
    struct cfl_variant value = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "my_otlp_value",
    };

    cb_data.cb = cb_check_metadata_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "data_mode", "chunk",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "value", &value);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[[0, {}], {\"k\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_otel_log_attributes_upsert()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    struct flb_processor_unit *pu_upsert;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"my_otlp_attr\":\"old_value\"", FLB_FALSE},
      {"\"my_otlp_attr\":\"new_value\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action_insert = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "insert",
    };
    struct cfl_variant action_upsert = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "upsert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "otel_log_attributes",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "my_otlp_attr",
    };
    struct cfl_variant value_insert = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "old_value",
    };
    struct cfl_variant value_upsert = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "new_value",
    };

    cb_data.cb = cb_check_metadata_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "data_mode", "chunk",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action_insert);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "value", &value_insert);
    TEST_CHECK(ret == 0);

    pu_upsert = flb_processor_unit_create(ctx->proc, ctx->type, "content_modifier");
    if (!TEST_CHECK(pu_upsert != NULL)) {
        TEST_MSG("failed to create second processor unit");
        processor_test_destroy(ctx);
        return;
    }

    ret = flb_processor_unit_set_property(pu_upsert, "action", &action_upsert);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu_upsert, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu_upsert, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu_upsert, "value", &value_upsert);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[[0, {}], {\"k\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_otel_log_attributes_delete()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    struct flb_processor_unit *pu_delete;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"my_otlp_attr\"", FLB_FALSE},
      {"\"otlp\":{\"attributes\":{}}", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action_insert = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "insert",
    };
    struct cfl_variant action_delete = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "delete",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "otel_log_attributes",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "my_otlp_attr",
    };
    struct cfl_variant value_insert = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "my_otlp_value",
    };

    cb_data.cb = cb_check_metadata_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "data_mode", "chunk",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action_insert);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "value", &value_insert);
    TEST_CHECK(ret == 0);

    pu_delete = flb_processor_unit_create(ctx->proc, ctx->type, "content_modifier");
    if (!TEST_CHECK(pu_delete != NULL)) {
        TEST_MSG("failed to create second processor unit");
        processor_test_destroy(ctx);
        return;
    }

    ret = flb_processor_unit_set_property(pu_delete, "action", &action_delete);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu_delete, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu_delete, "key", &key);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[[0, {}], {\"k\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_otel_log_attributes_invalid_otlp_metadata()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"otlp\":\"broken\"", FLB_TRUE},
      {"\"my_otlp_attr\"", FLB_FALSE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "insert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "otel_log_attributes",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "my_otlp_attr",
    };
    struct cfl_variant value = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "my_otlp_value",
    };

    cb_data.cb = cb_check_metadata_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "data_mode", "chunk",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "value", &value);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[[0, {\"otlp\":\"broken\"}], {\"k\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

TEST_LIST = {
    {"logs.action.insert"           , flb_logs_action_insert },
    {"logs.action.delete"           , flb_logs_action_delete },
    {"logs.action.rename"           , flb_logs_action_rename },
    {"logs.action.upsert"           , flb_logs_action_upsert },
    {"logs.action.hash"             , flb_logs_action_hash },
    {"logs.action.extract"          , flb_logs_action_extract },
    {"logs.action.convert_from_string_to_int" , flb_logs_action_convert_from_string_to_int },
    {"logs.action.convert_from_int_to_string" , flb_logs_action_convert_from_int_to_string },
    {"logs.action.convert_from_string_to_double" , flb_logs_action_convert_from_string_to_double },
    {"logs.action.convert_from_double_to_string" , flb_logs_action_convert_from_double_to_string },
    {"logs.action.convert_from_string_to_boolean" , flb_logs_action_convert_from_string_to_boolean },
    {"logs.action.convert_from_int_to_boolean" , flb_logs_action_convert_from_int_to_boolean },
    {"logs.action.convert_from_int_to_double" , flb_logs_action_convert_from_int_to_double },
    {"logs.action.convert_from_double_to_int" , flb_logs_action_convert_from_double_to_int },
    {"logs.action.convert_from_double_to_boolean" , flb_logs_action_convert_from_double_to_boolean },
    {"logs.action.convert_from_null_to_string" , flb_logs_action_convert_from_null_to_string },
    {"logs.action.convert_from_null_to_int" , flb_logs_action_convert_from_null_to_int },
    {"logs.action.convert_from_null_to_double" , flb_logs_action_convert_from_null_to_double },
    {"logs.otel_log_attributes.insert" , flb_logs_otel_log_attributes_insert },
    {"logs.otel_log_attributes.upsert" , flb_logs_otel_log_attributes_upsert },
    {"logs.otel_log_attributes.delete" , flb_logs_otel_log_attributes_delete },
    {"logs.otel_log_attributes.invalid_otlp_metadata",
     flb_logs_otel_log_attributes_invalid_otlp_metadata },
    {NULL, NULL}
};
