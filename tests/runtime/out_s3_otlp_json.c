/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit.h>
#include "flb_tests_runtime.h"
#include "../../plugins/in_opentelemetry/opentelemetry.h"
#include "../../plugins/in_opentelemetry/opentelemetry_logs.h"

#define OTLP_LOGS_JSON "{\"resourceLogs\":[{\"resource\":{\"attributes\":[{\"key\":\"service.name\",\"value\":{\"stringValue\":\"my.service\"}}]},\"scopeLogs\":[{\"scope\":{\"name\":\"my.library\",\"version\":\"1.0.0\"},\"logRecords\":[{\"timeUnixNano\":\"1774877764000000000\",\"observedTimeUnixNano\":\"1774877764000000000\",\"severityNumber\":2,\"severityText\":\"INFO\",\"body\":{\"stringValue\":\"otlp runtime test\"}}]}]}]}"

static struct flb_input_instance *get_opentelemetry_instance(flb_ctx_t *flb_ctx)
{
    struct mk_list *head;
    struct flb_input_instance *ins;

    mk_list_foreach(head, &flb_ctx->config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        if (ins->p && strcmp(ins->p->name, "opentelemetry") == 0) {
            return ins;
        }
    }

    return NULL;
}

static int inject_otlp_json(flb_ctx_t *flb_ctx, const char *json_data, size_t json_size)
{
    struct flb_input_instance *ins;
    struct flb_opentelemetry *otel_ctx;
    flb_sds_t content_type;
    flb_sds_t tag;
    int ret;

    ins = get_opentelemetry_instance(flb_ctx);
    if (!ins || !ins->context) {
        return -1;
    }

    otel_ctx = (struct flb_opentelemetry *) ins->context;
    tag = flb_sds_create("opentelemetry.0");
    content_type = flb_sds_create("application/json");

    ret = opentelemetry_process_logs(otel_ctx, content_type, tag, flb_sds_len(tag),
                                     (void *) json_data, json_size);

    flb_sds_destroy(content_type);
    flb_sds_destroy(tag);

    return ret;
}

void flb_test_s3_format_otlp_json(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char store_dir[] = "/tmp/flb-s3-test-otlp-json-XXXXXX";

    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "opentelemetry.0", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "port", "4330", NULL);
    TEST_CHECK(in_ffd >= 0);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "format", "otlp_json", NULL);
    flb_output_set(ctx, out_ffd, "use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "6s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = inject_otlp_json(ctx, OTLP_LOGS_JSON, sizeof(OTLP_LOGS_JSON) - 1);
    TEST_CHECK(ret == 0);
    sleep(10);

    call_count_str = getenv("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 PutObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_format_otlp_json_with_compression(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char store_dir[] = "/tmp/flb-s3-test-otlp-comp-XXXXXX";

    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "opentelemetry.0", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "port", "4330", NULL);
    TEST_CHECK(in_ffd >= 0);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "format", "otlp_json", NULL);
    flb_output_set(ctx, out_ffd, "compression", "gzip", NULL);
    flb_output_set(ctx, out_ffd, "use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "6s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = inject_otlp_json(ctx, OTLP_LOGS_JSON, sizeof(OTLP_LOGS_JSON) - 1);
    TEST_CHECK(ret == 0);
    sleep(10);

    call_count_str = getenv("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 PutObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

TEST_LIST = {
    {"format_otlp_json", flb_test_s3_format_otlp_json },
    {"format_otlp_json_with_compression", flb_test_s3_format_otlp_json_with_compression },
    {NULL, NULL}
};
