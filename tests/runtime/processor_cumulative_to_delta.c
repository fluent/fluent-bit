/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_encode_opentelemetry.h>
#include <cmetrics/cmt_encode_text.h>

#include <fluent-bit.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_time.h>

#include "flb_tests_runtime.h"

#define PORT_OTEL 4318
#define V1_ENDPOINT_METRICS "/v1/metrics"
#define OTLP_CONTENT_TYPE "application/x-protobuf"

#define MAX_CAPTURED_VALUES 32
#define MAX_CAPTURE_METRICS 8

struct http_client_ctx {
    struct flb_upstream *upstream;
    struct flb_connection *connection;
    struct flb_config *config;
    struct mk_event_loop *event_loop;
};

struct rt_ctx {
    flb_ctx_t *flb;
    int input_ffd;
    int output_ffd;
    struct flb_processor *processor;
    struct http_client_ctx *http;
};

struct metric_capture {
    const char *line_prefix;
    double values[MAX_CAPTURED_VALUES];
    int value_count;
};

struct observation_state {
    int callback_count;
    int capture_count;
    struct metric_capture captures[MAX_CAPTURE_METRICS];
};

static pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct observation_state observed;

static int find_metric_value(const char *text,
                             const char *line_prefix,
                             double *value)
{
    const char *match;
    const char *cursor;
    const char *line_start;
    const char *line_end;
    const char *equal_sign;

    line_start = text;

    while (line_start != NULL && *line_start != '\0') {
        line_end = strchr(line_start, '\n');
        if (line_end == NULL) {
            line_end = line_start + strlen(line_start);
        }

        match = strstr(line_start, line_prefix);
        if (match != NULL && match < line_end) {
            equal_sign = NULL;

            for (cursor = match; cursor < line_end; cursor++) {
                if (*cursor == '=') {
                    equal_sign = cursor;
                }
            }

            if (equal_sign != NULL) {
                equal_sign++;

                while (equal_sign < line_end && *equal_sign == ' ') {
                    equal_sign++;
                }

                if (equal_sign < line_end &&
                    ((*equal_sign >= '0' && *equal_sign <= '9') ||
                     *equal_sign == '-' || *equal_sign == '+')) {
                    *value = strtod(equal_sign, NULL);
                    return 0;
                }
            }
        }

        if (*line_end == '\0') {
            break;
        }

        line_start = line_end + 1;
    }

    return -1;
}

static void observation_reset(void)
{
    pthread_mutex_lock(&state_mutex);
    memset(&observed, 0, sizeof(observed));
    pthread_mutex_unlock(&state_mutex);
}

static int observation_add_capture(const char *line_prefix)
{
    int index;

    pthread_mutex_lock(&state_mutex);

    index = observed.capture_count;

    if (index >= MAX_CAPTURE_METRICS) {
        pthread_mutex_unlock(&state_mutex);
        return -1;
    }

    observed.captures[index].line_prefix = line_prefix;
    observed.captures[index].value_count = 0;
    observed.capture_count++;

    pthread_mutex_unlock(&state_mutex);

    return index;
}

static int observation_get_callback_count(void)
{
    int count;

    pthread_mutex_lock(&state_mutex);
    count = observed.callback_count;
    pthread_mutex_unlock(&state_mutex);

    return count;
}

static int observation_get_value_count(int capture_index)
{
    int count;

    pthread_mutex_lock(&state_mutex);

    if (capture_index < 0 || capture_index >= observed.capture_count) {
        count = 0;
    }
    else {
        count = observed.captures[capture_index].value_count;
    }

    pthread_mutex_unlock(&state_mutex);

    return count;
}

static double observation_get_value(int capture_index, int value_index)
{
    double value;

    pthread_mutex_lock(&state_mutex);

    if (capture_index < 0 ||
        capture_index >= observed.capture_count ||
        value_index < 0 ||
        value_index >= observed.captures[capture_index].value_count) {
        value = 0.0;
    }
    else {
        value = observed.captures[capture_index].values[value_index];
    }

    pthread_mutex_unlock(&state_mutex);

    return value;
}

static int wait_for_callback_growth(int baseline, int timeout_ms)
{
    int waited;

    waited = 0;

    while (waited < timeout_ms) {
        if (observation_get_callback_count() > baseline) {
            return 0;
        }

        flb_time_msleep(50);
        waited += 50;
    }

    return -1;
}

static int wait_for_value_count(int capture_index, int expected_count, int timeout_ms)
{
    int waited;

    waited = 0;

    while (waited < timeout_ms) {
        if (observation_get_value_count(capture_index) >= expected_count) {
            return 0;
        }

        flb_time_msleep(50);
        waited += 50;
    }

    return -1;
}

static struct http_client_ctx *http_client_ctx_create(void)
{
    struct http_client_ctx *context;
    struct mk_event_loop *event_loop;

    context = flb_calloc(1, sizeof(struct http_client_ctx));
    if (context == NULL) {
        flb_errno();
        return NULL;
    }

    event_loop = mk_event_loop_create(16);
    if (event_loop == NULL) {
        flb_free(context);
        return NULL;
    }

    context->event_loop = event_loop;

    flb_engine_evl_init();
    flb_engine_evl_set(event_loop);

    context->config = flb_config_init();
    if (context->config == NULL) {
        mk_event_loop_destroy(event_loop);
        flb_free(context);
        return NULL;
    }

    context->upstream = flb_upstream_create(context->config,
                                            "127.0.0.1",
                                            PORT_OTEL,
                                            0,
                                            NULL);
    if (context->upstream == NULL) {
        flb_config_exit(context->config);
        mk_event_loop_destroy(event_loop);
        flb_free(context);
        return NULL;
    }

    context->connection = flb_upstream_conn_get(context->upstream);
    if (context->connection == NULL) {
        flb_upstream_destroy(context->upstream);
        flb_config_exit(context->config);
        mk_event_loop_destroy(event_loop);
        flb_free(context);
        return NULL;
    }

    context->connection->upstream = context->upstream;

    return context;
}

static void http_client_ctx_destroy(struct http_client_ctx *context)
{
    if (context == NULL) {
        return;
    }

    if (context->upstream != NULL) {
        flb_upstream_destroy(context->upstream);
    }

    if (context->config != NULL) {
        flb_config_exit(context->config);
    }

    if (context->event_loop != NULL) {
        mk_event_loop_destroy(context->event_loop);
    }

    flb_free(context);
}

static int cb_capture_metrics(void *record, size_t size, void *data)
{
    int ret;
    int index;
    double value;
    size_t offset;
    cfl_sds_t text;
    struct cmt *context;

    (void) data;

    offset = 0;
    text = NULL;
    context = NULL;

    ret = cmt_decode_msgpack_create(&context, (char *) record, size, &offset);
    if (ret != CMT_DECODE_MSGPACK_SUCCESS) {
        if (record != NULL) {
            flb_free(record);
        }

        return -1;
    }

    text = cmt_encode_text_create(context);

    pthread_mutex_lock(&state_mutex);

    observed.callback_count++;

    if (text != NULL) {
        for (index = 0; index < observed.capture_count; index++) {
            if (find_metric_value(text,
                                  observed.captures[index].line_prefix,
                                  &value) == 0) {
                if (observed.captures[index].value_count < MAX_CAPTURED_VALUES) {
                    observed.captures[index].values[
                        observed.captures[index].value_count] = value;
                    observed.captures[index].value_count++;
                }
            }
        }
    }

    pthread_mutex_unlock(&state_mutex);

    if (text != NULL) {
        cmt_encode_text_destroy(text);
    }

    cmt_destroy(context);

    if (record != NULL) {
        flb_free(record);
    }

    return 0;
}

static struct rt_ctx *rt_ctx_create(const char *drop_first,
                                    const char *drop_on_reset)
{
    int ret;
    struct rt_ctx *context;
    struct flb_processor_unit *unit;
    struct flb_lib_out_cb cb_data;

    context = flb_calloc(1, sizeof(struct rt_ctx));
    if (context == NULL) {
        flb_errno();
        return NULL;
    }

    cb_data.cb = cb_capture_metrics;
    cb_data.data = NULL;

    context->flb = flb_create();
    if (context->flb == NULL) {
        flb_free(context);
        return NULL;
    }

    flb_service_set(context->flb,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    context->input_ffd = flb_input(context->flb, (char *) "opentelemetry", NULL);
    if (context->input_ffd < 0) {
        flb_destroy(context->flb);
        flb_free(context);
        return NULL;
    }

    ret = flb_input_set(context->flb,
                        context->input_ffd,
                        "tag", "test",
                        "tag_from_uri", "false",
                        NULL);
    if (ret != 0) {
        flb_destroy(context->flb);
        flb_free(context);
        return NULL;
    }

    context->processor = flb_processor_create(context->flb->config,
                                              "unit_test",
                                              NULL,
                                              0);
    if (context->processor == NULL) {
        flb_destroy(context->flb);
        flb_free(context);
        return NULL;
    }

    unit = flb_processor_unit_create(context->processor,
                                     FLB_PROCESSOR_METRICS,
                                     "cumulative_to_delta");
    if (unit == NULL) {
        flb_destroy(context->flb);
        flb_free(context);
        return NULL;
    }

    if (drop_first != NULL) {
        ret = flb_processor_unit_set_property_str(unit,
                                                  "drop_first",
                                                  (char *) drop_first);
        if (ret != 0) {
            flb_destroy(context->flb);
            flb_free(context);
            return NULL;
        }
    }

    if (drop_on_reset != NULL) {
        ret = flb_processor_unit_set_property_str(unit,
                                                  "drop_on_reset",
                                                  (char *) drop_on_reset);
        if (ret != 0) {
            flb_destroy(context->flb);
            flb_free(context);
            return NULL;
        }
    }

    ret = flb_input_set_processor(context->flb,
                                  context->input_ffd,
                                  context->processor);
    if (ret != 0) {
        flb_destroy(context->flb);
        flb_free(context);
        return NULL;
    }

    context->output_ffd = flb_output(context->flb, (char *) "lib", &cb_data);
    if (context->output_ffd < 0) {
        flb_destroy(context->flb);
        flb_free(context);
        return NULL;
    }

    ret = flb_output_set(context->flb,
                         context->output_ffd,
                         "match", "*",
                         NULL);
    if (ret != 0) {
        flb_destroy(context->flb);
        flb_free(context);
        return NULL;
    }

    ret = flb_start(context->flb);
    if (ret != 0) {
        flb_destroy(context->flb);
        flb_free(context);
        return NULL;
    }

    context->http = http_client_ctx_create();
    if (context->http == NULL) {
        flb_stop(context->flb);
        flb_destroy(context->flb);
        flb_free(context);
        return NULL;
    }

    return context;
}

static void rt_ctx_destroy(struct rt_ctx *context)
{
    if (context == NULL) {
        return;
    }

    if (context->http != NULL) {
        flb_upstream_conn_release(context->http->connection);
        http_client_ctx_destroy(context->http);
    }

    if (context->flb != NULL) {
        flb_stop(context->flb);
        flb_destroy(context->flb);
    }

    flb_free(context);
}

static struct cmt *create_counter_context(const char *name,
                                          uint64_t timestamp,
                                          double value,
                                          int allow_reset,
                                          int label_count,
                                          char **label_keys,
                                          char **label_values)
{
    struct cmt *context;
    struct cmt_counter *counter;

    context = cmt_create();
    if (context == NULL) {
        return NULL;
    }

    counter = cmt_counter_create(context,
                                 "",
                                 "",
                                 (char *) name,
                                 "help",
                                 label_count,
                                 label_keys);
    if (counter == NULL) {
        cmt_destroy(context);
        return NULL;
    }

    counter->aggregation_type = CMT_AGGREGATION_TYPE_CUMULATIVE;

    if (allow_reset == FLB_TRUE) {
        cmt_counter_allow_reset(counter);
    }

    if (cmt_counter_set(counter,
                        timestamp,
                        value,
                        label_count,
                        label_values) != 0) {
        cmt_destroy(context);
        return NULL;
    }

    return context;
}

static int send_metrics_context(struct rt_ctx *context, struct cmt *metrics_context)
{
    int ret;
    size_t bytes_sent;
    cfl_sds_t payload;
    struct flb_http_client *client;

    payload = cmt_encode_opentelemetry_create(metrics_context);
    if (payload == NULL) {
        return -1;
    }

    client = flb_http_client(context->http->connection,
                             FLB_HTTP_POST,
                             V1_ENDPOINT_METRICS,
                             payload,
                             cfl_sds_len(payload),
                             "127.0.0.1",
                             PORT_OTEL,
                             NULL,
                             0);
    if (client == NULL) {
        cmt_encode_opentelemetry_destroy(payload);
        return -1;
    }

    ret = flb_http_add_header(client,
                              FLB_HTTP_HEADER_CONTENT_TYPE,
                              strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              OTLP_CONTENT_TYPE,
                              strlen(OTLP_CONTENT_TYPE));
    if (ret != 0) {
        flb_http_client_destroy(client);
        cmt_encode_opentelemetry_destroy(payload);
        return -1;
    }

    ret = flb_http_do(client, &bytes_sent);

    if (ret != 0 || bytes_sent == 0 || client->resp.status != 201) {
        flb_http_client_destroy(client);
        cmt_encode_opentelemetry_destroy(payload);
        return -1;
    }

    flb_http_client_destroy(client);
    cmt_encode_opentelemetry_destroy(payload);

    return 0;
}

static void flb_test_runtime_counter_default_behaviors(void)
{
    int baseline;
    int count_before;
    int metric_index;
    struct cmt *context;
    struct rt_ctx *rt;

    observation_reset();
    metric_index = observation_add_capture("rt_counter_total");
    TEST_CHECK(metric_index >= 0);

    rt = rt_ctx_create("true", "true");
    TEST_CHECK(rt != NULL);

    context = create_counter_context("rt_counter_total", 100, 1.0,
                                     FLB_FALSE, 0, NULL, NULL);
    TEST_CHECK(context != NULL);
    baseline = observation_get_callback_count();
    TEST_CHECK(send_metrics_context(rt, context) == 0);
    cmt_destroy(context);
    TEST_CHECK(wait_for_callback_growth(baseline, 2000) == 0);
    TEST_CHECK(observation_get_value_count(metric_index) == 0);

    context = create_counter_context("rt_counter_total", 200, 2.0,
                                     FLB_FALSE, 0, NULL, NULL);
    TEST_CHECK(context != NULL);
    TEST_CHECK(send_metrics_context(rt, context) == 0);
    cmt_destroy(context);
    TEST_CHECK(wait_for_value_count(metric_index, 1, 2000) == 0);
    TEST_CHECK(fabs(observation_get_value(metric_index, 0) - 1.0) < 0.0001);

    context = create_counter_context("rt_counter_total", 300, 3.0,
                                     FLB_FALSE, 0, NULL, NULL);
    TEST_CHECK(context != NULL);
    TEST_CHECK(send_metrics_context(rt, context) == 0);
    cmt_destroy(context);
    TEST_CHECK(wait_for_value_count(metric_index, 2, 2000) == 0);
    TEST_CHECK(fabs(observation_get_value(metric_index, 1) - 1.0) < 0.0001);

    count_before = observation_get_value_count(metric_index);
    context = create_counter_context("rt_counter_total", 400, 1.0,
                                     FLB_FALSE, 0, NULL, NULL);
    TEST_CHECK(context != NULL);
    TEST_CHECK(send_metrics_context(rt, context) == 0);
    cmt_destroy(context);
    flb_time_msleep(500);
    TEST_CHECK(observation_get_value_count(metric_index) == count_before);

    context = create_counter_context("rt_counter_total", 250, 5.0,
                                     FLB_FALSE, 0, NULL, NULL);
    TEST_CHECK(context != NULL);
    TEST_CHECK(send_metrics_context(rt, context) == 0);
    cmt_destroy(context);
    flb_time_msleep(500);
    TEST_CHECK(observation_get_value_count(metric_index) == count_before);

    context = create_counter_context("rt_counter_total", 500, 7.0,
                                     FLB_FALSE, 0, NULL, NULL);
    TEST_CHECK(context != NULL);
    TEST_CHECK(send_metrics_context(rt, context) == 0);
    cmt_destroy(context);
    TEST_CHECK(wait_for_value_count(metric_index, 3, 2000) == 0);
    TEST_CHECK(fabs(observation_get_value(metric_index, 2) - 6.0) < 0.0001);

    rt_ctx_destroy(rt);
}

static void flb_test_runtime_counter_reset_keep_and_first_sample(void)
{
    int metric_index;
    struct cmt *context;
    struct rt_ctx *rt;

    observation_reset();
    metric_index = observation_add_capture("rt_counter_keep_total");
    TEST_CHECK(metric_index >= 0);

    rt = rt_ctx_create("false", "false");
    TEST_CHECK(rt != NULL);

    context = create_counter_context("rt_counter_keep_total", 100, 10.0,
                                     FLB_FALSE, 0, NULL, NULL);
    TEST_CHECK(context != NULL);
    TEST_CHECK(send_metrics_context(rt, context) == 0);
    cmt_destroy(context);
    TEST_CHECK(wait_for_value_count(metric_index, 1, 2000) == 0);
    TEST_CHECK(fabs(observation_get_value(metric_index, 0) - 10.0) < 0.0001);

    context = create_counter_context("rt_counter_keep_total", 200, 2.0,
                                     FLB_FALSE, 0, NULL, NULL);
    TEST_CHECK(context != NULL);
    TEST_CHECK(send_metrics_context(rt, context) == 0);
    cmt_destroy(context);
    TEST_CHECK(wait_for_value_count(metric_index, 2, 2000) == 0);
    TEST_CHECK(fabs(observation_get_value(metric_index, 1) - 2.0) < 0.0001);

    rt_ctx_destroy(rt);
}

static void flb_test_runtime_multi_series(void)
{
    int index_a;
    int index_b;
    char *label_keys[1];
    char *label_values_a[1];
    char *label_values_b[1];
    struct cmt *context;
    struct rt_ctx *rt;

    label_keys[0] = "instance";
    label_values_a[0] = "a";
    label_values_b[0] = "b";

    observation_reset();

    index_a = observation_add_capture("rt_series_total{instance=\"a\"}");
    index_b = observation_add_capture("rt_series_total{instance=\"b\"}");
    TEST_CHECK(index_a >= 0);
    TEST_CHECK(index_b >= 0);

    rt = rt_ctx_create("true", "true");
    TEST_CHECK(rt != NULL);

    context = create_counter_context("rt_series_total", 100, 1.0,
                                     FLB_FALSE, 1,
                                     label_keys, label_values_a);
    TEST_CHECK(context != NULL);
    TEST_CHECK(send_metrics_context(rt, context) == 0);
    cmt_destroy(context);

    context = create_counter_context("rt_series_total", 100, 10.0,
                                     FLB_FALSE, 1,
                                     label_keys, label_values_b);
    TEST_CHECK(context != NULL);
    TEST_CHECK(send_metrics_context(rt, context) == 0);
    cmt_destroy(context);

    context = create_counter_context("rt_series_total", 200, 3.0,
                                     FLB_FALSE, 1,
                                     label_keys, label_values_a);
    TEST_CHECK(context != NULL);
    TEST_CHECK(send_metrics_context(rt, context) == 0);
    cmt_destroy(context);

    context = create_counter_context("rt_series_total", 200, 15.0,
                                     FLB_FALSE, 1,
                                     label_keys, label_values_b);
    TEST_CHECK(context != NULL);
    TEST_CHECK(send_metrics_context(rt, context) == 0);
    cmt_destroy(context);

    TEST_CHECK(wait_for_value_count(index_a, 1, 2000) == 0);
    TEST_CHECK(wait_for_value_count(index_b, 1, 2000) == 0);

    TEST_CHECK(fabs(observation_get_value(index_a, 0) - 2.0) < 0.0001);
    TEST_CHECK(fabs(observation_get_value(index_b, 0) - 5.0) < 0.0001);

    rt_ctx_destroy(rt);
}

static void flb_test_runtime_non_monotonic_sum_passthrough(void)
{
    int metric_index;
    struct cmt *context;
    struct rt_ctx *rt;

    observation_reset();
    metric_index = observation_add_capture("rt_non_monotonic_total");
    TEST_CHECK(metric_index >= 0);

    rt = rt_ctx_create("true", "true");
    TEST_CHECK(rt != NULL);

    context = create_counter_context("rt_non_monotonic_total",
                                     100, 10.0,
                                     FLB_TRUE,
                                     0, NULL, NULL);
    TEST_CHECK(context != NULL);
    TEST_CHECK(send_metrics_context(rt, context) == 0);
    cmt_destroy(context);
    TEST_CHECK(wait_for_value_count(metric_index, 1, 2000) == 0);
    TEST_CHECK(fabs(observation_get_value(metric_index, 0) - 10.0) < 0.0001);

    context = create_counter_context("rt_non_monotonic_total",
                                     200, 3.0,
                                     FLB_TRUE,
                                     0, NULL, NULL);
    TEST_CHECK(context != NULL);
    TEST_CHECK(send_metrics_context(rt, context) == 0);
    cmt_destroy(context);
    TEST_CHECK(wait_for_value_count(metric_index, 2, 2000) == 0);
    TEST_CHECK(fabs(observation_get_value(metric_index, 1) - 3.0) < 0.0001);

    rt_ctx_destroy(rt);
}

TEST_LIST = {
    {"counter_default_behaviors", flb_test_runtime_counter_default_behaviors},
    {"counter_reset_keep_and_first_sample", flb_test_runtime_counter_reset_keep_and_first_sample},
    {"multi_series", flb_test_runtime_multi_series},
    {"non_monotonic_sum_passthrough", flb_test_runtime_non_monotonic_sum_passthrough},
    {NULL, NULL}
};
