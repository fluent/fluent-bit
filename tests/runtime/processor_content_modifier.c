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

    p = "[0, {\"k\":\"sample\"}]";
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
    {NULL, NULL}
};
