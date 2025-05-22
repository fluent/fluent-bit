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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_http_client.h>

#include "flb_tests_runtime.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define TCP_PLUGIN_NAME "my_tcp_instance"

/* Helper function to fetch metrics */
static flb_sds_t fetch_metrics(const char *metrics_port, const char *uri)
{
    struct flb_http_client *client;
    struct flb_http_response *response;
    flb_sds_t metrics_data = NULL;
    int ret;
    size_t b_sent;

    client = flb_http_client_create("127.0.0.1", atoi(metrics_port), FLB_FALSE, NULL, NULL);
    if (!client) {
        flb_test_printf("Failed to create HTTP client for metrics\n");
        return NULL;
    }

    response = flb_http_client_request(client,
                                       FLB_HTTP_GET, uri,
                                       NULL, 0,  /* Body */
                                       NULL, 0,  /* Headers */
                                       &b_sent);

    if (!response) {
        flb_test_printf("Failed to get HTTP response from metrics endpoint %s\n", uri);
        flb_http_client_destroy(client);
        return NULL;
    }

    if (response->status == 200 && response->payload_size > 0) {
        metrics_data = flb_sds_create_len(response->payload, response->payload_size);
    }
    else {
        flb_test_printf("Metrics request to %s failed with status %d\n", uri, response->status);
        if(response->payload_size > 0) {
            flb_test_printf("Response payload: %.*s\n", (int)response->payload_size, response->payload);
        }
    }

    flb_http_client_response_destroy(response);
    flb_http_client_destroy(client);

    return metrics_data;
}

/* Helper function to parse Prometheus metric value */
/* A very basic parser, assumes metric format: metric_name{label_name="label_value"} value */
static long parse_prometheus_metric(const char *metrics_buffer,
                                    const char *metric_name_prefix, /* e.g., "fluentbit_input_connections_total" */
                                    const char *label_key,          /* e.g., "name" */
                                    const char *label_val)          /* e.g., "my_tcp_instance" */
{
    const char *line;
    const char *p;
    char search_str[256];
    long value = -1;

    if (!metrics_buffer) {
        return -1;
    }

    snprintf(search_str, sizeof(search_str) -1, "%s{%s=\"%s\"}",
             metric_name_prefix, label_key, label_val);

    line = strstr(metrics_buffer, search_str);
    if (line) {
        p = strrchr(line, ' '); /* Find the last space before the value */
        if (p) {
            value = atol(p + 1);
        }
    }
    return value;
}

/* Test function */
void test_input_connections_metric()
{
    flb_ctx_t *flb;
    char *config_str;
    int ret;
    flb_sds_t metrics_output;
    long metric_value;
    int client_fd1 = -1, client_fd2 = -1;
    char metrics_port_str[16];
    char tcp_port_str[16];
    int metrics_port;
    int tcp_port;

    flb_test_printf("--- Test: input_connections_total metric ---\n");

    metrics_port = flb_test_get_free_port();
    tcp_port = flb_test_get_free_port();

    TEST_ASSERT(metrics_port > 0);
    TEST_ASSERT(tcp_port > 0);

    snprintf(metrics_port_str, sizeof(metrics_port_str), "%d", metrics_port);
    snprintf(tcp_port_str, sizeof(tcp_port_str), "%d", tcp_port);

    /* Define Fluent Bit configuration */
    config_str = flb_sds_printf(
        "[SERVICE]\n"
        "    Flush        1\n"
        "    Daemon       Off\n"
        "    Log_Level    debug\n"
        "    HTTP_Server  On\n"
        "    HTTP_Listen  0.0.0.0\n"
        "    HTTP_Port    %s\n"
        "\n"
        "[INPUT]\n"
        "    Name         tcp\n"
        "    Alias        %s\n"
        "    Listen       0.0.0.0\n"
        "    Port         %s\n"
        "    Chunk_Size   32\n"
        "    Buffer_Size  64\n"
        "    Format       none\n"
        "    Separator    \\n\n"
        "\n"
        "[OUTPUT]\n"
        "    Name         null\n"
        "    Match        *\n",
        metrics_port_str, TCP_PLUGIN_NAME, tcp_port_str
    );

    /* Start Fluent Bit */
    flb = flb_test_setup_conf(config_str);
    TEST_ASSERT(flb != NULL);
    flb_sds_destroy(config_str);

    ret = flb_start(flb);
    TEST_ASSERT(ret == 0);

    /* Wait for Fluent Bit to initialize (e.g. HTTP server to be up) */
    flb_time_msleep(1500); /* Adjust as needed */

    /* Initial Check: Metric should be 0 */
    flb_test_printf("Checking initial metric value...\n");
    metrics_output = fetch_metrics(metrics_port_str, "/api/v1/metrics/prometheus");
    TEST_ASSERT(metrics_output != NULL);
    if (metrics_output) {
        metric_value = parse_prometheus_metric(metrics_output, "fluentbit_input_connections_total", "name", TCP_PLUGIN_NAME);
        flb_test_printf("Initial fluentbit_input_connections_total{name=\"%s\"} = %ld\n", TCP_PLUGIN_NAME, metric_value);
        TEST_ASSERT(metric_value == 0);
        flb_sds_destroy(metrics_output);
        metrics_output = NULL;
    }

    /* Simulate one connection */
    flb_test_printf("Simulating one connection...\n");
    client_fd1 = flb_test_tcp_client_create("127.0.0.1", tcp_port_str, FLB_FALSE, NULL);
    TEST_ASSERT(client_fd1 >= 0);
    flb_time_msleep(1000); /* Give time for FB to process */

    metrics_output = fetch_metrics(metrics_port_str, "/api/v1/metrics/prometheus");
    TEST_ASSERT(metrics_output != NULL);
    if (metrics_output) {
        metric_value = parse_prometheus_metric(metrics_output, "fluentbit_input_connections_total", "name", TCP_PLUGIN_NAME);
        flb_test_printf("After 1 conn: fluentbit_input_connections_total{name=\"%s\"} = %ld\n", TCP_PLUGIN_NAME, metric_value);
        TEST_ASSERT(metric_value == 1);
        flb_sds_destroy(metrics_output);
        metrics_output = NULL;
    }

    /* Simulate a second connection */
    flb_test_printf("Simulating second connection...\n");
    client_fd2 = flb_test_tcp_client_create("127.0.0.1", tcp_port_str, FLB_FALSE, NULL);
    TEST_ASSERT(client_fd2 >= 0);
    flb_time_msleep(1000); /* Give time for FB to process */

    metrics_output = fetch_metrics(metrics_port_str, "/api/v1/metrics/prometheus");
    TEST_ASSERT(metrics_output != NULL);
    if (metrics_output) {
        metric_value = parse_prometheus_metric(metrics_output, "fluentbit_input_connections_total", "name", TCP_PLUGIN_NAME);
        flb_test_printf("After 2 conns: fluentbit_input_connections_total{name=\"%s\"} = %ld\n", TCP_PLUGIN_NAME, metric_value);
        TEST_ASSERT(metric_value == 2);
        flb_sds_destroy(metrics_output);
        metrics_output = NULL;
    }

    /* Simulate one disconnection */
    flb_test_printf("Simulating one disconnection (fd1)...\n");
    flb_socket_close(client_fd1);
    client_fd1 = -1;
    flb_time_msleep(1000); /* Give time for FB to process */

    metrics_output = fetch_metrics(metrics_port_str, "/api/v1/metrics/prometheus");
    TEST_ASSERT(metrics_output != NULL);
    if (metrics_output) {
        metric_value = parse_prometheus_metric(metrics_output, "fluentbit_input_connections_total", "name", TCP_PLUGIN_NAME);
        flb_test_printf("After 1 disconn: fluentbit_input_connections_total{name=\"%s\"} = %ld\n", TCP_PLUGIN_NAME, metric_value);
        TEST_ASSERT(metric_value == 1);
        flb_sds_destroy(metrics_output);
        metrics_output = NULL;
    }

    /* Simulate second disconnection */
    flb_test_printf("Simulating second disconnection (fd2)...\n");
    flb_socket_close(client_fd2);
    client_fd2 = -1;
    flb_time_msleep(1000); /* Give time for FB to process */

    metrics_output = fetch_metrics(metrics_port_str, "/api/v1/metrics/prometheus");
    TEST_ASSERT(metrics_output != NULL);
    if (metrics_output) {
        metric_value = parse_prometheus_metric(metrics_output, "fluentbit_input_connections_total", "name", TCP_PLUGIN_NAME);
        flb_test_printf("After 2 disconns: fluentbit_input_connections_total{name=\"%s\"} = %ld\n", TCP_PLUGIN_NAME, metric_value);
        TEST_ASSERT(metric_value == 0);
        flb_sds_destroy(metrics_output);
        metrics_output = NULL;
    }

    /* Cleanup */
    if (client_fd1 >= 0) {
        flb_socket_close(client_fd1);
    }
    if (client_fd2 >= 0) {
        flb_socket_close(client_fd2);
    }

    flb_stop(flb);
    flb_destroy(flb);
    flb_test_printf("--- Test finished ---\n");
}

TEST_LIST = {
    { "test_input_connections_metric", test_input_connections_metric },
    { NULL, NULL }
};

int main(int argc, char **argv)
{
    return flb_tests_main_mod(argc, argv, TEST_LIST);
}
