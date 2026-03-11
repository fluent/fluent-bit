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

#define null_check(x) do { if (!x) { goto error; } else {sds = x;} } while (0)

/* Return the newest metrics buffer */
static struct flb_hs_buf *metrics_get_latest(struct flb_hs *hs)
{
    if (hs->metrics_v2.raw_data == NULL) {
        return NULL;
    }
    return &hs->metrics_v2;
}

/* API: expose metrics in Prometheus format /api/v2/metrics/prometheus */
static int cb_metrics_prometheus(struct flb_hs *hs,
                                 struct flb_http_request *request,
                                 struct flb_http_response *response)
{
    struct cmt *cmt;
    struct flb_hs_buf *buf;
    cfl_sds_t payload;

    (void) request;

    buf = metrics_get_latest(hs);
    if (!buf) {
        flb_http_response_set_status(response, 404);
        return flb_http_response_commit(response);
    }

    buf->users++;
    cmt = (struct cmt *) buf->raw_data;

    /* convert CMetrics to text */
    payload = cmt_encode_prometheus_create(cmt, CMT_FALSE);
    if (!payload) {
        flb_hs_buf_release(buf, flb_hs_cmt_buffer_destroy);
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    flb_hs_response_set_payload(response, 200,
                                FLB_HS_CONTENT_TYPE_PROMETHEUS,
                                payload, cfl_sds_len(payload));

    cmt_encode_prometheus_destroy(payload);

    flb_hs_buf_release(buf, flb_hs_cmt_buffer_destroy);
    return 0;
}

/* API: expose built-in metrics /api/v1/metrics (JSON format) */
static int cb_metrics(struct flb_hs *hs,
                      struct flb_http_request *request,
                      struct flb_http_response *response)
{
    struct cmt *cmt;
    struct flb_hs_buf *buf;
    cfl_sds_t payload;

    (void) request;

    buf = metrics_get_latest(hs);
    if (!buf) {
        flb_http_response_set_status(response, 404);
        return flb_http_response_commit(response);
    }

    buf->users++;
    cmt = (struct cmt *) buf->raw_data;

    /* convert CMetrics to text */
    payload = cmt_encode_text_create(cmt);
    if (!payload) {
        flb_hs_buf_release(buf, flb_hs_cmt_buffer_destroy);
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    flb_hs_response_set_payload(response, 200,
                                FLB_HS_CONTENT_TYPE_OTHER,
                                payload, cfl_sds_len(payload));

    cmt_encode_text_destroy(payload);

    flb_hs_buf_release(buf, flb_hs_cmt_buffer_destroy);
    return 0;
}

/* Perform registration */
int api_v2_metrics(struct flb_hs *hs)
{
    int ret;

    ret = flb_hs_register_endpoint(hs, "/api/v2/metrics/prometheus",
                                   FLB_HS_ROUTE_EXACT, cb_metrics_prometheus);
    if (ret != 0) {
        return ret;
    }

    return flb_hs_register_endpoint(hs, "/api/v2/metrics",
                                    FLB_HS_ROUTE_EXACT, cb_metrics);
}
