/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/es/json_es.h" /* JSON_ES */

static void cb_check_write_op_index(void *ctx, int ffd,
                                    int res_ret, void *res_data,
                                    size_t res_size, void *data)
{
    char *p;
    char *out_js = res_data;
    char *index_line = "{\"index\":{";

    p = strstr(out_js, index_line);
    TEST_CHECK(p == out_js);

    flb_sds_destroy(res_data);
}

static void cb_check_write_op_create(void *ctx, int ffd,
                                     int res_ret, void *res_data,
                                     size_t res_size, void *data)
{
    char *p;
    char *out_js = res_data;
    char *index_line = "{\"create\":{";

    p = strstr(out_js, index_line);
    TEST_CHECK(p == out_js);

    flb_sds_destroy(res_data);
}

static void cb_check_write_op_update(void *ctx, int ffd,
                                     int res_ret, void *res_data,
                                     size_t res_size, void *data)
{
    char *p;
    char *b;
    char *out_js = res_data;
    char *index_line = "{\"update\":{";
    char *body = "{\"doc\":";

    p = strstr(out_js, index_line);
    TEST_CHECK(p == out_js);
    b = strstr(out_js, body);
    TEST_CHECK(b != NULL);

    flb_sds_destroy(res_data);
}

static void cb_check_write_op_upsert(void *ctx, int ffd,
                                     int res_ret, void *res_data,
                                     size_t res_size, void *data)
{
    char *p;
    char *b;
    char *out_js = res_data;
    char *index_line = "{\"update\":{";
    char *body = "{\"doc_as_upsert\":true,\"doc\":";

    p = strstr(out_js, index_line);
    TEST_CHECK(p == out_js);
    b = strstr(out_js, body);
    TEST_CHECK(b != NULL);

    flb_sds_destroy(res_data);
}

static void cb_check_index_type(void *ctx, int ffd,
                                int res_ret, void *res_data, size_t res_size,
                                void *data)
{
    char *p;
    char *out_js = res_data;
    char *index_line = "{\"create\":{\"_index\":\"index_test\",\"_type\":\"type_test\"}";

    p = strstr(out_js, index_line);
    TEST_CHECK(p != NULL);

    flb_sds_destroy(res_data);
}

static void cb_check_index_record_accessor(void *ctx, int ffd,
                                           int res_ret, void *res_data, size_t res_size,
                                           void *data)
{
    char *p;
    char *out_js = res_data;
    char *index_line = "{\"create\":{\"_index\":\"abc\",\"_type\":\"def\"}";

    p = strstr(out_js, index_line);
    TEST_CHECK(p != NULL);

    flb_sds_destroy(res_data);
}

static void cb_check_index_record_accessor_suppress_type(void *ctx, int ffd,
                                                         int res_ret, void *res_data, size_t res_size,
                                                         void *data)
{
    char *p;
    char *out_js = res_data;
    char *index_line = "{\"create\":{\"_index\":\"abc\"}";

    p = strstr(out_js, index_line);
    TEST_CHECK(p != NULL);

    flb_sds_destroy(res_data);
}

static void cb_check_index_record_accessor_id_key(void *ctx, int ffd,
                                           int res_ret, void *res_data, size_t res_size,
                                           void *data)
{
    char *p;
    char *out_js = res_data;
    char *index_line = "{\"create\":{\"_index\":\"abc\",\"_type\":\"def\",\"_id\":\"something\"}}";

    p = strstr(out_js, index_line);
    TEST_CHECK(p != NULL);

    flb_sds_destroy(res_data);
}

static void cb_check_index_record_accessor_generate_id(void *ctx, int ffd,
                                           int res_ret, void *res_data, size_t res_size,
                                           void *data)
{
    char *p;
    char *out_js = res_data;
    char *index_line = "{\"create\":{\"_index\":\"code\",\"_type\":\"def\",\"_id\":\"";
    char *id = NULL;
    char c;
    int i;

    // check that index is working
    p = strstr(out_js, index_line);
    TEST_CHECK(p != NULL);

    // check that we have a UUID
    id = p + strlen(index_line);
    TEST_CHECK(strlen(id) > 36);
    for (i = 0; i < strlen(id) && i < 36; i++) {
        c = (*(id+i));
        TEST_CHECK(
            (c >= 'A' && c <= 'F') ||
            (*(id+i)) == '-' ||
            (c >= '0' && c <= '9')
        );
    }

    flb_sds_destroy(res_data);
}

static void cb_check_logstash_format(void *ctx, int ffd,
                                     int res_ret, void *res_data, size_t res_size,
                                     void *data)
{
    char *p;
    char *out_js = res_data;
    char *index_line = "{\"create\":{\"_index\":\"prefix-2015-11-24\",\"_type\":\"_doc\"}";

    p = strstr(out_js, index_line);
    TEST_CHECK(p != NULL);

    flb_sds_destroy(res_data);
}

static void cb_check_logstash_prefix_separator(void *ctx, int ffd,
                                               int res_ret, void *res_data, size_t res_size,
                                               void *data)
{
    char *p;
    char *out_js = res_data;
    char *index_line = "{\"create\":{\"_index\":\"prefixSEP2015-11-24\",\"_type\":\"_doc\"}";

    p = strstr(out_js, index_line);
    if(!TEST_CHECK(p != NULL)) {
        TEST_MSG("Got: %s", out_js);
    }
    flb_sds_destroy(res_data);
}

static void cb_check_logstash_format_nanos(void *ctx, int ffd,
                                           int res_ret, void *res_data, size_t res_size,
                                           void *data)
{
    char *p;
    char *out_js = res_data;
    char *index_line = "\"@timestamp\":\"2015-11-24T22:15:40.000000000Z\"";

    p = strstr(out_js, index_line);
    TEST_CHECK(p != NULL);

    flb_sds_destroy(res_data);
}

static void cb_check_tag_key(void *ctx, int ffd,
                             int res_ret, void *res_data, size_t res_size,
                             void *data)
{
    char *p;
    char *out_js = res_data;
    char *record = "\"mytag\":\"test\"";

    p = strstr(out_js, record);
    TEST_CHECK(p != NULL);
    flb_sds_destroy(res_data);
}

static void cb_check_replace_dots(void *ctx, int ffd,
                                  int res_ret, void *res_data, size_t res_size,
                                  void *data)
{
    char *p;
    char *out_js = res_data;
    char *record = "\"_o_k\":[{\"_b_ar\"";

    p = strstr(out_js, record);
    TEST_CHECK(p != NULL);

    flb_sds_destroy(res_data);
}

static void cb_check_id_key(void *ctx, int ffd,
                            int res_ret, void *res_data, size_t res_size,
                            void *data)
{
    char *p;
    char *out_js = res_data;
    char *record = "\"_id\":\"some string\""; // see data/es/json_es.h

    p = strstr(out_js, record);
    TEST_CHECK(p != NULL);

    flb_sds_destroy(res_data);
}

void flb_test_write_operation_index()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "opensearch", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "write_operation", "index",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_write_op_index,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_write_operation_create()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "opensearch", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "write_operation", "create",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_write_op_create,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}


void flb_test_write_operation_update()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "opensearch", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "Write_Operation", "Update",
                   "Generate_Id", "True",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_write_op_update,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}


void flb_test_write_operation_upsert()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "opensearch", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "Write_Operation", "Upsert",
                   "Generate_Id", "True",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_write_op_upsert,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_index_type()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "opensearch", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "index", "index_test",
                   "type", "type_test",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_index_type,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_index_record_accessor()
{
    int ret;
    int len;
    int in_ffd;
    int out_ffd;
    char *record = "[1448403340, {\"key\": \"something\", \"myindex\": \"abc\"}]";

    flb_ctx_t *ctx;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "opensearch", NULL);

    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "index", "$myindex",
                   "type", "def",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_index_record_accessor,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    len = strlen(record);
    flb_lib_push(ctx, in_ffd, record, len);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_index_record_accessor_suppress_type()
{
    int ret;
    int len;
    int in_ffd;
    int out_ffd;
    char *record = "[1448403340, {\"key\": \"something\", \"myindex\": \"abc\"}]";

    flb_ctx_t *ctx;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "opensearch", NULL);

    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "index", "$myindex",
                   "suppress_type_name", "true",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_index_record_accessor_suppress_type,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    len = strlen(record);
    flb_lib_push(ctx, in_ffd, record, len);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_index_record_accessor_with_id_key()
{
    int ret;
    int len;
    int in_ffd;
    int out_ffd;
    char *record = "[1448403340, {\"key\": \"something\", \"myindex\": \"abc\"}]";

    flb_ctx_t *ctx;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "opensearch", NULL);

    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "index", "$myindex",
                   "type", "def",
                   "id_key", "key",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_index_record_accessor_id_key,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    len = strlen(record);
    flb_lib_push(ctx, in_ffd, record, len);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_index_record_accessor_with_generate_id()
{
    int ret;
    int len;
    int in_ffd;
    int out_ffd;
    char *record = "[1448403340, {\"key\": \"xul\", \"myindex\": \"code\"}]";

    flb_ctx_t *ctx;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "opensearch", NULL);

    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "index", "$myindex",
                   "type", "def",
                   "generate_id", "true",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_index_record_accessor_generate_id,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    len = strlen(record);
    flb_lib_push(ctx, in_ffd, record, len);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_logstash_format()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "opensearch", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "logstash_format", "on",
                   "logstash_prefix", "prefix",
                   "logstash_dateformat", "%Y-%m-%d",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_logstash_format,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_logstash_format_nanos()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "opensearch", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "logstash_format", "on",
                   "logstash_prefix", "prefix",
                   "logstash_dateformat", "%Y-%m-%d",
                   "time_key_nanos", "on",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_logstash_format_nanos,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_tag_key()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "opensearch", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "include_tag_key", "on",
                   "tag_key", "mytag",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_tag_key,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_replace_dots()
{
    int ret;
    int size = sizeof(JSON_DOTS) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "opensearch", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "replace_dots", "on",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_replace_dots,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_DOTS, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_id_key()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "opensearch", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "id_key", "key_2",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_id_key,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* no check */
static void cb_check_nothing(void *ctx, int ffd,
                            int res_ret, void *res_data, size_t res_size,
                            void *data)
{
    flb_sds_destroy(res_data);
}

/* https://github.com/fluent/fluent-bit/issues/3905 */
void flb_test_div0()
{
    int ret;
    char record[8000];
    char record_header[] = "[1448403340,{\"key\":\"";
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int i;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "opensearch", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_nothing,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* create json */
    strncpy(&record[0], &record_header[0], strlen(record_header));
    for(i=strlen(record_header); i<sizeof(record)-4; i++) {
        record[i] = 'a';
    }
    record[sizeof(record)-4] = '"';
    record[sizeof(record)-3] = '}';
    record[sizeof(record)-2] = ']';
    record[sizeof(record)-1] = '\0';
    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) &record[0], strlen(record));

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}


static void cb_check_long_index(void *ctx, int ffd,
                                int res_ret, void *res_data, size_t res_size,
                                void *data)
{
    char *p;
    char *out_js = res_data;
    char long_index[256] = {0};
    int i;

    for (i=0; i<sizeof(long_index)-1; i++) {
        long_index[i] = '0' + (i%10);
    }

    p = strstr(out_js, &long_index[0]);
    TEST_CHECK(p != NULL);
    flb_sds_destroy(res_data);
}

/* https://github.com/fluent/fluent-bit/issues/4311 */
void flb_test_long_index()
{
    int ret;
    int size = sizeof(JSON_ES) -1;
    char long_index[256] = {0};
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int i;

    for (i=0; i<sizeof(long_index)-1; i++) {
        long_index[i] = '0' + (i%10);
    }

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "opensearch", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "generate_id", "true",
                   "index", &long_index[0],
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_long_index,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *)JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_logstash_prefix_separator()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "opensearch", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "logstash_format", "on",
                   "logstash_prefix", "prefix",
                   "logstash_prefix_separator", "SEP",
                   "logstash_dateformat", "%Y-%m-%d",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_logstash_prefix_separator,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"long_index"            , flb_test_long_index },
    {"div0_error"            , flb_test_div0 },
    {"write_operation_index" , flb_test_write_operation_index },
    {"write_operation_create", flb_test_write_operation_create },
    {"write_operation_update", flb_test_write_operation_update },
    {"write_operation_upsert", flb_test_write_operation_upsert },
    {"index_type"            , flb_test_index_type },
    {"index_record_accessor" , flb_test_index_record_accessor},
    {"index_record_accessor_suppress_type" , flb_test_index_record_accessor_suppress_type},
    {"index_record_accessor_id_key", flb_test_index_record_accessor_with_id_key},
    {"index_record_accessor_generate_id", flb_test_index_record_accessor_with_generate_id},
    {"logstash_format"       , flb_test_logstash_format },
    {"logstash_format_nanos" , flb_test_logstash_format_nanos },
    {"tag_key"               , flb_test_tag_key },
    {"replace_dots"          , flb_test_replace_dots },
    {"id_key"                , flb_test_id_key },
    {"logstash_prefix_separator" , flb_test_logstash_prefix_separator },
    {NULL, NULL}
};
