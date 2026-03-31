/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_time.h>
#include "metrics.h"

#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/http_server/flb_hs.h>
#include <fluent-bit/http_server/flb_hs_utils.h>
#include <msgpack.h>

#define null_check(x) do { if (!x) { goto error; } else {sds = x;} } while (0)

/* Return the newest metrics buffer */
static struct flb_hs_buf *metrics_get_latest(struct flb_hs *hs)
{
    if (hs->metrics.data == NULL || hs->metrics.raw_data == NULL) {
        return NULL;
    }
    return &hs->metrics;
}

int string_cmp(const void* a_arg, const void* b_arg) {
  char *a = *(char **)a_arg;
  char *b = *(char **)b_arg;

  return strcmp(a, b);
}

size_t extract_metric_name_end_position(char *s) {
    int i;

    for (i = 0; i < flb_sds_len(s); i++) {
        if (s[i] == '{') {
          return i;
        }
    }
    return 0;
}

int is_same_metric(char *s1, char *s2) {
    int i;
    int p1 = extract_metric_name_end_position(s1);
    int p2 = extract_metric_name_end_position(s2);

    if (p1 != p2) {
        return 0;
    }

    for (i = 0; i < p1; i++) {
        if (s1[i] != s2[i]) {
            return 0;
        }
    }
    return 1;
}

/* derive HELP text from metricname */
/* if help text length > 128, increase init memory for metric_helptxt */
flb_sds_t metrics_help_txt(char *metric_name, flb_sds_t *metric_helptxt)
{
    if (strstr(metric_name, "input_bytes")) {
        return flb_sds_cat(*metric_helptxt, " Number of input bytes.\n", 24);
    }
    else if (strstr(metric_name, "input_records")) {
        return flb_sds_cat(*metric_helptxt, " Number of input records.\n", 26);
    }
    else if (strstr(metric_name, "output_bytes")) {
        return flb_sds_cat(*metric_helptxt, " Number of output bytes.\n", 25);
    }
    else if (strstr(metric_name, "output_records")) {
        return flb_sds_cat(*metric_helptxt, " Number of output records.\n", 27);
    }
    else if (strstr(metric_name, "output_errors")) {
        return flb_sds_cat(*metric_helptxt, " Number of output errors.\n", 26);
    }
    else if (strstr(metric_name, "output_retries_failed")) {
        return flb_sds_cat(*metric_helptxt, " Number of abandoned batches because the maximum number of re-tries was reached.\n", 81);
    }
    else if (strstr(metric_name, "output_retries")) {
        return flb_sds_cat(*metric_helptxt, " Number of output retries.\n", 27);
    }
    else if (strstr(metric_name, "output_proc_records")) {
        return flb_sds_cat(*metric_helptxt, " Number of processed output records.\n", 37);
    }
    else if (strstr(metric_name, "output_proc_bytes")) {
        return flb_sds_cat(*metric_helptxt, " Number of processed output bytes.\n", 35);
    }
    else if (strstr(metric_name, "output_dropped_records")) {
        return flb_sds_cat(*metric_helptxt, " Number of dropped records.\n", 28);
    }
    else if (strstr(metric_name, "output_retried_records")) {
        return flb_sds_cat(*metric_helptxt, " Number of retried records.\n", 28);
    }
    else {
        return (flb_sds_cat(*metric_helptxt, " Fluentbit metrics.\n", 20));
    }
}

/* API: expose metrics in Prometheus format /api/v1/metrics/prometheus */
static int cb_metrics_prometheus(struct flb_hs *hs,
                                 struct flb_http_request *request,
                                 struct flb_http_response *response)
{
    int i;
    int j;
    int m;
    int len;
    int time_len;
    int start_time_len;
    uint64_t uptime;
    size_t index;
    size_t num_metrics = 0;
    long now;
    flb_sds_t sds;
    flb_sds_t sds_metric;
    flb_sds_t tmp_sds;
    struct flb_sds *metric_helptxt_head;
    flb_sds_t metric_helptxt;
    size_t off = 0;
    struct flb_hs_buf *buf;
    msgpack_unpacked result;
    msgpack_object map;
    char tmp[32];
    char time_str[64];
    char start_time_str[64];
    char* *metrics_arr;
    struct flb_time tp;
    struct flb_config *config = hs->config;

    (void) request;

    buf = metrics_get_latest(hs);
    if (!buf) {
        flb_http_response_set_status(response, 404);
        return flb_http_response_commit(response);
    }

    /* ref count */
    buf->users++;

    /* Compose outgoing buffer string */
    sds = flb_sds_create_size(1024);
    if (!sds) {
        flb_http_response_set_status(response, 500);
        flb_http_response_commit(response);
        flb_hs_buf_release(buf, NULL);
        return 0;
    }

    /* length of HELP text */
    metric_helptxt = flb_sds_create_size(128);
    if (!metric_helptxt) {
        flb_sds_destroy(sds);
        flb_http_response_set_status(response, 500);
        flb_http_response_commit(response);
        flb_hs_buf_release(buf, NULL);
        return 0;
    }
    metric_helptxt_head = FLB_SDS_HEADER(metric_helptxt);

    /*
     * fluentbit_input_records[name="cpu0", hostname="${HOSTNAME}"] NUM TIMESTAMP
     * fluentbit_input_bytes[name="cpu0", hostname="${HOSTNAME}"] NUM TIMESTAMP
     */
    index = 0;
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, buf->raw_data, buf->raw_size, &off);
    map = result.data;

    /* we need to know number of exposed metrics to reserve a memory */
    for (i = 0; i < map.via.map.size; i++) {
        msgpack_object v = map.via.map.ptr[i].val;
        /* Iterate sub-map */
        for (j = 0; j < v.via.map.size; j++) {
            msgpack_object sv = v.via.map.ptr[j].val;
            for (m = 0; m < sv.via.map.size; m++) {
                num_metrics++;
            }
        }
    }
    metrics_arr = flb_malloc(num_metrics * sizeof(char*));
    if (!metrics_arr) {
        flb_errno();

        flb_hs_buf_release(buf, NULL);
        flb_http_response_set_status(response, 500);
        flb_http_response_commit(response);

        flb_sds_destroy(sds);
        flb_sds_destroy(metric_helptxt);
        msgpack_unpacked_destroy(&result);
        return 0;
    }

    flb_time_get(&tp);
    now = flb_time_to_nanosec(&tp) / 1000000; /* in milliseconds */
    time_len = snprintf(time_str, sizeof(time_str) - 1, "%lu", now);

    for (i = 0; i < map.via.map.size; i++) {
        msgpack_object k;
        msgpack_object v;

        /* Keys: input, output */
        k = map.via.map.ptr[i].key;
        v = map.via.map.ptr[i].val;

        /* Iterate sub-map */
        for (j = 0; j < v.via.map.size; j++) {
            msgpack_object sk;
            msgpack_object sv;

            /* Keys: plugin name , values: metrics */
            sk = v.via.map.ptr[j].key;
            sv = v.via.map.ptr[j].val;

            for (m = 0; m < sv.via.map.size; m++) {
                msgpack_object mk;
                msgpack_object mv;

                mk = sv.via.map.ptr[m].key;
                mv = sv.via.map.ptr[m].val;

                /* Convert metric value to string */
                len = snprintf(tmp, sizeof(tmp) - 1, "%" PRIu64 " ", mv.via.u64);
                if (len < 0) {
                    goto error;
                }

                /* Allocate buffer */
                sds_metric = flb_sds_create_size(k.via.str.size
                                                 + mk.via.str.size
                                                 + sk.via.str.size
                                                 + len + time_len + 28);
                if (sds_metric == NULL) {
                    goto error;
                }

                sds_metric = flb_sds_cat(sds_metric, "fluentbit_", 10);
                sds_metric = flb_sds_cat(sds_metric, k.via.str.ptr, k.via.str.size);
                sds_metric = flb_sds_cat(sds_metric, "_", 1);
                sds_metric = flb_sds_cat(sds_metric, mk.via.str.ptr, mk.via.str.size);
                sds_metric = flb_sds_cat(sds_metric, "_total{name=\"", 13);
                sds_metric = flb_sds_cat(sds_metric, sk.via.str.ptr, sk.via.str.size);
                sds_metric = flb_sds_cat(sds_metric, "\"} ", 3);
                sds_metric = flb_sds_cat(sds_metric, tmp, len);
                sds_metric = flb_sds_cat(sds_metric, time_str, time_len);
                sds_metric = flb_sds_cat(sds_metric, "\n", 1);
                metrics_arr[index] = sds_metric;
                index++;
            }
        }
    }

    /*  Sort metrics in alphabetic order, so we can group them later. */
    qsort(metrics_arr, num_metrics, sizeof(char *), string_cmp);

    /* When a new metric starts add HELP and TYPE annotation. */
    tmp_sds = flb_sds_cat(sds, "# HELP ", 7);
    null_check(tmp_sds);
    tmp_sds = flb_sds_cat(sds, metrics_arr[0], extract_metric_name_end_position(metrics_arr[0]));
    null_check(tmp_sds);
    if (!metrics_help_txt(metrics_arr[0], &metric_helptxt)) {
        goto error;
    }
    tmp_sds = flb_sds_cat(sds, metric_helptxt, metric_helptxt_head->len);
    null_check(tmp_sds);
    tmp_sds = flb_sds_cat(sds, "# TYPE ", 7);
    null_check(tmp_sds);
    tmp_sds = flb_sds_cat(sds, metrics_arr[0], extract_metric_name_end_position(metrics_arr[0]));
    null_check(tmp_sds);
    tmp_sds = flb_sds_cat(sds, " counter\n", 9);
    null_check(tmp_sds);

    for (i = 0; i < num_metrics; i++) {
        tmp_sds = flb_sds_cat(sds, metrics_arr[i], strlen(metrics_arr[i]));
        null_check(tmp_sds);
        if ((i != num_metrics - 1) && (is_same_metric(metrics_arr[i], metrics_arr[i+1]) == 0)) {
            tmp_sds = flb_sds_cat(sds, "# HELP ", 7);
            null_check(tmp_sds);
            tmp_sds = flb_sds_cat(sds, metrics_arr[i+1], extract_metric_name_end_position(metrics_arr[i+1]));
            null_check(tmp_sds);
            metric_helptxt_head->len = 0;
            if (!metrics_help_txt(metrics_arr[i+1], &metric_helptxt)) {
                goto error;
            }
            tmp_sds = flb_sds_cat(sds, metric_helptxt, metric_helptxt_head->len);
            null_check(tmp_sds);
            tmp_sds = flb_sds_cat(sds, "# TYPE ", 7);
            null_check(tmp_sds);
            tmp_sds = flb_sds_cat(sds, metrics_arr[i+1], extract_metric_name_end_position(metrics_arr[i+1]));
            null_check(tmp_sds);
            tmp_sds = flb_sds_cat(sds, " counter\n", 9);
            null_check(tmp_sds);
        }
    }

    /* Attach uptime */
    uptime = time(NULL) - config->init_time;
    len = snprintf(time_str, sizeof(time_str) - 1, "%lu", uptime);

    tmp_sds = flb_sds_cat(sds,
                          "# HELP fluentbit_uptime Number of seconds that Fluent Bit has "
                          "been running.\n", 76);
    null_check(tmp_sds);
    tmp_sds = flb_sds_cat(sds, "# TYPE fluentbit_uptime counter\n", 32);
    null_check(tmp_sds);

    tmp_sds = flb_sds_cat(sds, "fluentbit_uptime ", 17);
    null_check(tmp_sds);
    tmp_sds = flb_sds_cat(sds, time_str, len);
    null_check(tmp_sds);
    tmp_sds = flb_sds_cat(sds, "\n", 1);
    null_check(tmp_sds);

    /* Attach process_start_time_seconds metric. */
    start_time_len = snprintf(start_time_str, sizeof(start_time_str) - 1,
                              "%lu", config->init_time);

    tmp_sds = flb_sds_cat(sds, "# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.\n", 89);
    null_check(tmp_sds);
    tmp_sds = flb_sds_cat(sds, "# TYPE process_start_time_seconds gauge\n", 40);
    null_check(tmp_sds);

    tmp_sds = flb_sds_cat(sds, "process_start_time_seconds ", 27);
    null_check(tmp_sds);
    tmp_sds = flb_sds_cat(sds, start_time_str, start_time_len);
    null_check(tmp_sds);
    tmp_sds = flb_sds_cat(sds, "\n", 1);
    null_check(tmp_sds);

    /* Attach fluentbit_build_info metric. */
    tmp_sds = flb_sds_cat(sds, "# HELP fluentbit_build_info Build version information.\n", 55);
    null_check(tmp_sds);
    tmp_sds = flb_sds_cat(sds, "# TYPE fluentbit_build_info gauge\n", 34);
    null_check(tmp_sds);
    tmp_sds = flb_sds_cat(sds, "fluentbit_build_info{version=\"", 30);
    null_check(tmp_sds);
    tmp_sds = flb_sds_cat(sds, FLB_VERSION_STR, sizeof(FLB_VERSION_STR) - 1);
    null_check(tmp_sds);
    tmp_sds = flb_sds_cat(sds, "\",edition=\"", 11);
    null_check(tmp_sds);
#ifdef FLB_ENTERPRISE
    tmp_sds = flb_sds_cat(sds, "Enterprise\"} 1\n", 15);
    null_check(tmp_sds);
#else
    tmp_sds = flb_sds_cat(sds, "Community\"} 1\n", 14);
    null_check(tmp_sds);
#endif

    msgpack_unpacked_destroy(&result);
    flb_hs_buf_release(buf, NULL);

    flb_hs_response_set_payload(response, 200,
                                FLB_HS_CONTENT_TYPE_PROMETHEUS,
                                sds, flb_sds_len(sds));
    for (i = 0; i < num_metrics; i++) {
      flb_sds_destroy(metrics_arr[i]);
    }
    flb_free(metrics_arr);
    flb_sds_destroy(sds);
    flb_sds_destroy(metric_helptxt);

    return 0;

error:
    flb_http_response_set_status(response, 500);
    flb_http_response_commit(response);
    flb_hs_buf_release(buf, NULL);

    for (i = 0; i < index; i++) {
      flb_sds_destroy(metrics_arr[i]);
    }
    flb_free(metrics_arr);
    flb_sds_destroy(sds);
    flb_sds_destroy(metric_helptxt);
    msgpack_unpacked_destroy(&result);
    return 0;
}

/* API: expose built-in metrics /api/v1/metrics */
static int cb_metrics(struct flb_hs *hs,
                      struct flb_http_request *request,
                      struct flb_http_response *response)
{
    struct flb_hs_buf *buf;

    (void) request;

    buf = metrics_get_latest(hs);
    if (!buf) {
        flb_http_response_set_status(response, 404);
        return flb_http_response_commit(response);
    }

    buf->users++;

    flb_hs_response_set_payload(response, 200,
                                FLB_HS_CONTENT_TYPE_JSON,
                                buf->data, flb_sds_len(buf->data));

    flb_hs_buf_release(buf, NULL);
    return 0;
}

/* Perform registration */
int api_v1_metrics(struct flb_hs *hs)
{
    int ret;

    ret = flb_hs_register_endpoint(hs, "/api/v1/metrics/prometheus",
                                   FLB_HS_ROUTE_EXACT, cb_metrics_prometheus);
    if (ret != 0) {
        return ret;
    }

    return flb_hs_register_endpoint(hs, "/api/v1/metrics",
                                    FLB_HS_ROUTE_EXACT, cb_metrics);
}
