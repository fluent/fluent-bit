/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include "flb_tests_runtime.h"

/* iterate in the text per line, and count the number of matches */
static int count_metrics_matches(char *metrics_text, const char *pattern)
{
    int len;
    int count = 0;
    char *line_start;
    char *line_end;
    char buf[1024];

    line_start = metrics_text;

    /* Iterate through the text to find lines */
    while (*line_start != '\0') {
        /* Find the end of the current line */
        line_end = strchr(line_start, '\n');
        if (line_end == NULL) {
            line_end = line_start + strlen(line_start);
        }

        /* copy the text line to a temporary buffer */
        len = line_end - line_start;
        strncpy(buf, line_start, len);
        buf[len] = '\0';

        /* Check if the pattern exists in the current line */
        if (strstr(buf, pattern) != NULL) {
            count++;
        }

        /* Move to the next line */
        if (*line_end == '\0') {
            break;
        }
        line_start = line_end + 1;
    }

    return count;
}

static int cb_insert_labels(void *record, size_t size, void *data)
{
    int ret;
    size_t off = 0;
    cfl_sds_t text = NULL;
    struct cmt *cmt = NULL;

    /* get cmetrics context */
    ret = cmt_decode_msgpack_create(&cmt, (char *) record, size, &off);
    if (ret != 0) {
        flb_error("could not process metrics payload");
        return -1;
    }

    /* convert to text representation */
    text = cmt_encode_text_create(cmt);
    TEST_CHECK(text != NULL);

    TEST_CHECK(count_metrics_matches(text, "static=\"ok\"") == 9);
    TEST_CHECK(count_metrics_matches(text, "dynamic=\"test\"") == 9);

    if (record) {
        flb_free(record);
    }

    /* destroy cmt context */
    cmt_destroy(cmt);
    cmt_encode_text_destroy(text);

    return 0;
}

static void insert_label()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct flb_lib_out_cb cb_data;

    struct cfl_variant var_static = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "static ok",
    };
    struct cfl_variant var_dynamic = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "dynamic $TAG",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_insert_labels;
    cb_data.data = NULL;

    /* Create context */
    ctx = flb_create();
    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "2",
                    NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "event_type", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "type", "metrics", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "interval_sec", "1", NULL);
    TEST_CHECK(ret == 0);

    /* Processor */
    proc = flb_processor_create(ctx->config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_METRICS, "labels");
    TEST_CHECK(pu != NULL);

    ret = flb_processor_unit_set_property(pu, "insert", &var_static);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(pu, "insert", &var_dynamic);
    TEST_CHECK(ret == 0);

    /* set up processor */
    ret = flb_input_set_processor(ctx, in_ffd, proc);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);


    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

static int cb_update_labels(void *record, size_t size, void *data)
{
    int ret;
    size_t off = 0;
    cfl_sds_t text = NULL;
    struct cmt *cmt = NULL;

    /* get cmetrics context */
    ret = cmt_decode_msgpack_create(&cmt, (char *) record, size, &off);
    if (ret != 0) {
        flb_error("could not process metrics payload");
        return -1;
    }

    /* convert to text representation */
    text = cmt_encode_text_create(cmt);
    TEST_CHECK(text != NULL);

    /* it should only update the metrics which contains a label with the name 'hostname' */
    TEST_CHECK(count_metrics_matches(text, "hostname=\"updated\"") == 2);

    /* now check the updated value of 'app' which should include the dynamic tag */
    TEST_CHECK(count_metrics_matches(text, "app=\"mytag.test\"") == 2);

    if (record) {
        flb_free(record);
    }

    /* destroy cmt context */
    cmt_destroy(cmt);
    cmt_encode_text_destroy(text);

    return 0;
}

static void update_label()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct flb_lib_out_cb cb_data;

    struct cfl_variant var_static = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "hostname updated",
    };
    struct cfl_variant var_dynamic = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "app mytag.$TAG",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_update_labels;
    cb_data.data = NULL;

    /* Create context */
    ctx = flb_create();
    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "2",
                    NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "event_type", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "type", "metrics", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "interval_sec", "1", NULL);
    TEST_CHECK(ret == 0);

    /* Processor */
    proc = flb_processor_create(ctx->config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_METRICS, "labels");
    TEST_CHECK(pu != NULL);

    ret = flb_processor_unit_set_property(pu, "update", &var_static);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(pu, "update", &var_dynamic);
    TEST_CHECK(ret == 0);

    /* set up processor */
    ret = flb_input_set_processor(ctx, in_ffd, proc);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);


    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

static int cb_upsert_labels(void *record, size_t size, void *data)
{
    int ret;
    size_t off = 0;
    cfl_sds_t text = NULL;
    struct cmt *cmt = NULL;

    /* get cmetrics context */
    ret = cmt_decode_msgpack_create(&cmt, (char *) record, size, &off);
    if (ret != 0) {
        flb_error("could not process metrics payload");
        return -1;
    }

    /* convert to text representation */
    text = cmt_encode_text_create(cmt);
    TEST_CHECK(text != NULL);

    /* it should only update the metrics which contains a label with the name 'hostname' */
    TEST_CHECK(count_metrics_matches(text, "hostname=\"updated-2\"") == 8);

    /* now check the updated value of 'app' which should include the dynamic tag */
    TEST_CHECK(count_metrics_matches(text, "dynamic-host=\"test\"") == 9);
    if (record) {
        flb_free(record);
    }

    /* destroy cmt context */
    cmt_destroy(cmt);
    cmt_encode_text_destroy(text);

    return 0;
}

static void upsert_label()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct flb_lib_out_cb cb_data;

    struct cfl_variant var_static = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "hostname updated-2",
    };
    struct cfl_variant var_dynamic = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "dynamic-host $TAG",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_upsert_labels;
    cb_data.data = NULL;

    /* Create context */
    ctx = flb_create();
    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "2",
                    NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "event_type", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "type", "metrics", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "interval_sec", "1", NULL);
    TEST_CHECK(ret == 0);

    /* Processor */
    proc = flb_processor_create(ctx->config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_METRICS, "labels");
    TEST_CHECK(pu != NULL);

    ret = flb_processor_unit_set_property(pu, "upsert", &var_static);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(pu, "upsert", &var_dynamic);
    TEST_CHECK(ret == 0);

    /* set up processor */
    ret = flb_input_set_processor(ctx, in_ffd, proc);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);


    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

static int cb_delete_labels(void *record, size_t size, void *data)
{
    int ret;
    size_t off = 0;
    cfl_sds_t text = NULL;
    struct cmt *cmt = NULL;

    /* get cmetrics context */
    ret = cmt_decode_msgpack_create(&cmt, (char *) record, size, &off);
    if (ret != 0) {
        flb_error("could not process metrics payload");
        return -1;
    }

    /* convert to text representation */
    text = cmt_encode_text_create(cmt);
    TEST_CHECK(text != NULL);

    /* it should only update the metrics which contains a label with the name 'hostname' */
    TEST_CHECK(count_metrics_matches(text, "hostname=\"") == 0);

    if (record) {
        flb_free(record);
    }

    /* destroy cmt context */
    cmt_destroy(cmt);
    cmt_encode_text_destroy(text);

    return 0;
}

static void delete_label()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct flb_lib_out_cb cb_data;

    struct cfl_variant var_static = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "hostname",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_delete_labels;
    cb_data.data = NULL;

    /* Create context */
    ctx = flb_create();
    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "2",
                    NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "event_type", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "type", "metrics", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "interval_sec", "1", NULL);
    TEST_CHECK(ret == 0);

    /* Processor */
    proc = flb_processor_create(ctx->config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_METRICS, "labels");
    TEST_CHECK(pu != NULL);

    ret = flb_processor_unit_set_property(pu, "delete", &var_static);
    TEST_CHECK(ret == 0);

    /* set up processor */
    ret = flb_input_set_processor(ctx, in_ffd, proc);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);


    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}


static int cb_hash_labels(void *record, size_t size, void *data)
{
    int ret;
    size_t off = 0;
    cfl_sds_t text = NULL;
    struct cmt *cmt = NULL;

    /* get cmetrics context */
    ret = cmt_decode_msgpack_create(&cmt, (char *) record, size, &off);
    if (ret != 0) {
        flb_error("could not process metrics payload");
        return -1;
    }

    /* convert to text representation */
    text = cmt_encode_text_create(cmt);
    TEST_CHECK(text != NULL);

    /* it should only update the metrics which contains a label with the name 'hostname' */
    TEST_CHECK(count_metrics_matches(text, "hostname=\"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763\"") == 2);

    if (record) {
        flb_free(record);
    }

    /* destroy cmt context */
    cmt_destroy(cmt);
    cmt_encode_text_destroy(text);

    return 0;
}

static void hash_label()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct flb_lib_out_cb cb_data;

    struct cfl_variant var_static = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "hostname",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_hash_labels;
    cb_data.data = NULL;

    /* Create context */
    ctx = flb_create();
    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "2",
                    NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "event_type", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "type", "metrics", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "interval_sec", "1", NULL);
    TEST_CHECK(ret == 0);

    /* Processor */
    proc = flb_processor_create(ctx->config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_METRICS, "labels");
    TEST_CHECK(pu != NULL);

    ret = flb_processor_unit_set_property(pu, "hash", &var_static);
    TEST_CHECK(ret == 0);

    /* set up processor */
    ret = flb_input_set_processor(ctx, in_ffd, proc);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "lib", &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);


    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

TEST_LIST = {
#ifdef FLB_HAVE_METRICS
    {"insert_label", insert_label},
    {"update_label", update_label},
    {"upsert_label", upsert_label},
    {"delete_label", delete_label},
    {"hash_label",   hash_label},
#endif
    {NULL, NULL}
};

