/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/es/json_es.h" /* JSON_ES */

/*
 * Include plugin headers to get the definition of structure used as flush context
 * and to know how to extract that structure from plugin context.
 */
#include "../../plugins/out_es/es.h"

static const char * const es_upstream_section_property_prefix = "    ";
static const char * const es_upstream_section_value_prefix    = " ";

static char *create_upstream_conf_file(const char *first_property, ...)
{
    char *upstream_conf_filename;
    FILE *upstream_conf_file;
    int ret;
    const char *arg;
    int arg_idx;
    va_list args;

    upstream_conf_filename = (char *) flb_malloc(L_tmpnam);
    if (!upstream_conf_filename) {
        return NULL;
    }

    if (!tmpnam(upstream_conf_filename)) {
        flb_free(upstream_conf_filename);
        return NULL;
    }

    upstream_conf_file = fopen(upstream_conf_filename, "w");
    if (upstream_conf_file == NULL) {
        flb_free(upstream_conf_filename);
        return NULL;
    }

    ret = fprintf(upstream_conf_file, "%s\n%s%s%s%s\n%s\n%s%s%s%s\n%s%s%s%s\n%s%s%s%s\n",
                  "[UPSTREAM]",
                  es_upstream_section_property_prefix,
                  "name", es_upstream_section_value_prefix, "es-balancing",
                  "[NODE]",
                  es_upstream_section_property_prefix,
                  "name", es_upstream_section_value_prefix, "node1",
                  es_upstream_section_property_prefix,
                  "host", es_upstream_section_value_prefix, FLB_ES_DEFAULT_HOST,
                  es_upstream_section_property_prefix,
                  "port", es_upstream_section_value_prefix, "9200");
    if (ret < 0) {
        fclose(upstream_conf_file);
        remove(upstream_conf_filename);
        flb_free(upstream_conf_filename);
        return NULL;
    }

    arg = first_property;
    arg_idx = 0;
    va_start(args, first_property);
    while (arg != NULL) {
        if (arg_idx == 0) {
            ret = fprintf(upstream_conf_file, "%s%s",
                          es_upstream_section_property_prefix, arg);
        }
        else {
            if (strlen(arg) > 0) {
                ret = fprintf(upstream_conf_file, "%s%s\n",
                              es_upstream_section_value_prefix, arg);
            }
            else {
                ret = fprintf(upstream_conf_file, "\n");
            }
        }
        if (ret < 0) {
            va_end(args);
            fclose(upstream_conf_file);
            remove(upstream_conf_filename);
            flb_free(upstream_conf_filename);
            return NULL;
        }
        arg = va_arg(args, const char *);
        arg_idx ^= 1;
    }
    va_end(args);

    if (arg_idx != 0) {
        ret = fprintf(upstream_conf_file, "\n");
        if (ret < 0) {
            fclose(upstream_conf_file);
            remove(upstream_conf_filename);
            flb_free(upstream_conf_filename);
            return NULL;
        }
    }

    ret = fclose(upstream_conf_file);
    if (ret != 0) {
        remove(upstream_conf_filename);
        flb_free(upstream_conf_filename);
        return NULL;
    }

    return upstream_conf_filename;
}

static void *cb_flush_context(struct flb_config *config, struct flb_input_instance *ins,
                              void *plugin_context, void *flush_ctx)
{
    struct flb_upstream_node *node;
    struct flb_elasticsearch *ctx = plugin_context;
    (void) config;
    (void) ins;
    (void) flush_ctx;
    return flb_elasticsearch_target(ctx, &node);
}

static void cb_check_http_api_key(void *ctx, int ffd,
                                int res_ret, void *res_data,
                                size_t res_size, void *data)
{
    char *api_key = data;

    TEST_CHECK(api_key != NULL);
    TEST_CHECK(strlen(api_key) > 0);

    TEST_CHECK(strcmp(api_key, "my-api-key-for-elasticsearch") == 0);

    flb_free(res_data);
}


static void cb_check_write_op_index(void *ctx, int ffd,
                                    int res_ret, void *res_data,
                                    size_t res_size, void *data)
{
    char *p;
    char *out_js = res_data;
    char *index_line = "{\"index\":{";

    p = strstr(out_js, index_line);
    TEST_CHECK(p == out_js);

    flb_free(res_data);
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

    flb_free(res_data);
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

    flb_free(res_data);
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

    flb_free(res_data);
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

    flb_free(res_data);
}

static void cb_check_logstash_format(void *ctx, int ffd,
                                     int res_ret, void *res_data, size_t res_size,
                                     void *data)
{
    char *p;
    char *out_js = res_data;
    char *index_line = "{\"create\":{\"_index\":\"prefix-2015-11-24\",\"_type\":\"_doc\"}";

    p = strstr(out_js, index_line);
    if(!TEST_CHECK(p != NULL)) {
        TEST_MSG("Got: %s", out_js);
    }
    flb_free(res_data);
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
    flb_free(res_data);
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
    flb_free(res_data);
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
    flb_free(res_data);
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
    flb_free(res_data);
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
    flb_free(res_data);
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
    out_ffd = flb_output(ctx, (char *) "es", NULL);
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
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

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
    out_ffd = flb_output(ctx, (char *) "es", NULL);
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
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

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
    out_ffd = flb_output(ctx, (char *) "es", NULL);
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
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

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
    out_ffd = flb_output(ctx, (char *) "es", NULL);
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
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_null_index()
{
    int ret;
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
    out_ffd = flb_output(ctx, (char *) "es", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "index", "",
                   "type", "type_test",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_index_type,
                              NULL, NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == -1);

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
    out_ffd = flb_output(ctx, (char *) "es", NULL);
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
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

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
    out_ffd = flb_output(ctx, (char *) "es", NULL);
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
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

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
    out_ffd = flb_output(ctx, (char *) "es", NULL);
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
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

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
    out_ffd = flb_output(ctx, (char *) "es", NULL);
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
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

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
    out_ffd = flb_output(ctx, (char *) "es", NULL);
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
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

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
    out_ffd = flb_output(ctx, (char *) "es", NULL);
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
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

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
    flb_free(res_data);
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
    out_ffd = flb_output(ctx, (char *) "es", NULL);
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
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

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

void flb_test_http_api_key()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *api_key = "my-api-key-for-elasticsearch";

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "es", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Configure http_api_key */
    flb_output_set(ctx, out_ffd,
                   "http_api_key", api_key,
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_http_api_key,
                              api_key, NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

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
    flb_free(res_data);
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
    out_ffd = flb_output(ctx, (char *) "es", NULL);
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
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

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
    out_ffd = flb_output(ctx, (char *) "es", NULL);
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
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_upstream_write_operation()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *upstream_conf_filename;

    /* Override write_operation to index at upstream node level */
    upstream_conf_filename = create_upstream_conf_file("write_operation", "index", NULL);
    TEST_ASSERT(upstream_conf_filename != NULL);

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "es", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "Write_Operation", "Upsert",
                   "Generate_Id", "True",
                   NULL);

    /* Use upstream servers */
    flb_output_set(ctx, out_ffd,
                   "Upstream", upstream_conf_filename,
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_write_op_index,
                              NULL, NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);

    /* Cleanup temporary configuration file */
    TEST_CHECK(remove(upstream_conf_filename) == 0);
    flb_free(upstream_conf_filename);
}

void flb_test_upstream_null_index()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *upstream_conf_filename;

    /* Override index at upstream node level */
    upstream_conf_filename = create_upstream_conf_file("generate_id", "off", NULL);
    TEST_ASSERT(upstream_conf_filename != NULL);

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "es", NULL);
    flb_output_set(ctx, out_ffd,
                   "index", "",
                   "generate_id", "on",
                   "match", "test",
                   NULL);

    /* Use upstream servers */
    flb_output_set(ctx, out_ffd,
                   "Upstream", upstream_conf_filename,
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_write_op_index,
                              NULL, NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == -1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);

    /* Cleanup temporary configuration file */
    TEST_CHECK(remove(upstream_conf_filename) == 0);
    flb_free(upstream_conf_filename);
}

void flb_test_upstream_index_type()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *upstream_conf_filename;

    /* Override default index and type at upstream node level */
    upstream_conf_filename = create_upstream_conf_file("index", "index_test",
                                                       "type", "type_test",
                                                       NULL);
    TEST_ASSERT(upstream_conf_filename != NULL);


    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "es", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Use upstream servers */
    flb_output_set(ctx, out_ffd,
                   "Upstream", upstream_conf_filename,
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter", cb_check_index_type,
                              NULL, NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);

    /* Cleanup temporary configuration file */
    TEST_CHECK(remove(upstream_conf_filename) == 0);
    flb_free(upstream_conf_filename);
}

void flb_test_upstream_logstash_format()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *upstream_conf_filename;

    /* Specify Logstash format at upstream node level */
    upstream_conf_filename = create_upstream_conf_file("logstash_format", "on",
                                                       "logstash_prefix", "prefix",
                                                       "logstash_prefix_separator", "SEP",
                                                       "logstash_dateformat", "%Y-%m-%d",
                                                       NULL);
    TEST_ASSERT(upstream_conf_filename != NULL);

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "es", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Use configuration different from upstream node configuration */
    flb_output_set(ctx, out_ffd,
                   "logstash_format", "off",
                   "logstash_prefix", "logstash",
                   "logstash_prefix_separator", "-",
                   "logstash_dateformat", "%Y.%m.%d",
                   NULL);

    /* Use upstream servers */
    flb_output_set(ctx, out_ffd,
                   "Upstream", upstream_conf_filename,
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_logstash_prefix_separator,
                              NULL, NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);

    /* Cleanup temporary configuration file */
    TEST_CHECK(remove(upstream_conf_filename) == 0);
    flb_free(upstream_conf_filename);
}

void flb_test_upstream_replace_dots()
{
    int ret;
    int size = sizeof(JSON_DOTS) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *upstream_conf_filename;

    /* Specify Logstash format at upstream node level */
    upstream_conf_filename = create_upstream_conf_file("replace_dots", "on",
                                                       NULL);
    TEST_ASSERT(upstream_conf_filename != NULL);

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "es", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Use configuration different from upstream node configuration */
    flb_output_set(ctx, out_ffd,
                   "replace_dots", "off",
                   NULL);

    /* Use upstream servers */
    flb_output_set(ctx, out_ffd,
                   "Upstream", upstream_conf_filename,
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter", cb_check_replace_dots,
                              NULL, NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_DOTS, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);

    /* Cleanup temporary configuration file */
    TEST_CHECK(remove(upstream_conf_filename) == 0);
    flb_free(upstream_conf_filename);
}

void flb_test_upstream_id_key()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *upstream_conf_filename;

    /* Specify Logstash format at upstream node level */
    upstream_conf_filename = create_upstream_conf_file("id_key", "key_2", NULL);
    TEST_ASSERT(upstream_conf_filename != NULL);

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "es", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Use upstream servers */
    flb_output_set(ctx, out_ffd,
                   "Upstream", upstream_conf_filename,
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter", cb_check_id_key,
                              NULL, NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set_test_flush_ctx_callback(ctx, out_ffd, "formatter",
                                                 cb_flush_context, NULL);
    TEST_CHECK(ret == 0);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);

    /* Cleanup temporary configuration file */
    TEST_CHECK(remove(upstream_conf_filename) == 0);
    flb_free(upstream_conf_filename);
}

static void cb_check_response_success(void *ctx, int ffd,
                                     int res_ret, void *res_data,
                                     size_t res_size, void *data)
{
    TEST_CHECK(res_ret == 1);
}

void flb_test_response_success()
{
    int ret;
    char *response = "{\"took\":1,\"errors\":false,\"items\":[]}";
    int size = 37;
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
    out_ffd = flb_output(ctx, (char *) "es", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "write_operation", "create",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_http_test(ctx, out_ffd, "response",
                                   cb_check_response_success,
                                   NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_response(ctx, out_ffd, 200, response, size);
    TEST_CHECK(ret == 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_response_successes()
{
    int ret;
    char *response = JSON_RESPONSE_SUCCESSES;
    int size = JSON_RESPONSE_SUCCESSES_SIZE;
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
    out_ffd = flb_output(ctx, (char *) "es", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "write_operation", "create",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_http_test(ctx, out_ffd, "response",
                                   cb_check_response_success,
                                   NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_response(ctx, out_ffd, 200, response, size);
    TEST_CHECK(ret == 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_response_partially_success(void *ctx, int ffd,
                                                int res_ret, void *res_data,
                                                size_t res_size, void *data)
{
    int composed_ret = 0;
    composed_ret |= (1 << 0);
    composed_ret |= (1 << 7);

    TEST_CHECK(res_ret == composed_ret);
    /* Check whether contains a success flag or not */
    TEST_CHECK((res_ret & (1 << 0)));
}

void flb_test_response_partially_success()
{
    int ret;
    char *response = JSON_RESPONSE_PARTIALLY_SUCCESS;
    int size = JSON_RESPONSE_PARTIALLY_SUCCESS_SIZE;
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
    out_ffd = flb_output(ctx, (char *) "es", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "write_operation", "create",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_http_test(ctx, out_ffd, "response",
                                   cb_check_response_partially_success,
                                   NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_response(ctx, out_ffd, 200, response, size);
    TEST_CHECK(ret == 0);

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
    {"null_index"            , flb_test_null_index },
    {"index_type"            , flb_test_index_type },
    {"logstash_format"       , flb_test_logstash_format },
    {"logstash_format_nanos" , flb_test_logstash_format_nanos },
    {"tag_key"               , flb_test_tag_key },
    {"replace_dots"          , flb_test_replace_dots },
    {"id_key"                , flb_test_id_key },
    {"http_api_key"          , flb_test_http_api_key },
    {"logstash_prefix_separator" , flb_test_logstash_prefix_separator },
    {"response_success"      , flb_test_response_success },
    {"response_successes", flb_test_response_successes },
    {"response_partially_success" , flb_test_response_partially_success },
    {"upstream_write_operation"  , flb_test_upstream_write_operation },
    {"upstream_null_index"       , flb_test_upstream_null_index },
    {"upstream_index_type"       , flb_test_upstream_index_type },
    {"upstream_logstash_format"  , flb_test_upstream_logstash_format },
    {"upstream_replace_dots"     , flb_test_upstream_replace_dots },
    {"upstream_id_key"           , flb_test_upstream_id_key },
    {NULL, NULL}
};
