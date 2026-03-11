/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/http_server/flb_hs.h>
#include <fluent-bit/http_server/flb_hs_utils.h>

#include <errno.h>

/* v1 */
#include "api/v1/register.h"
#include "api/v1/health.h"

/* v2 */
#include "api/v2/register.h"

static int flb_hs_route_matches(struct flb_hs_route *route, cfl_sds_t path)
{
    size_t route_length;
    size_t path_length;

    if (route == NULL || route->path == NULL || path == NULL) {
        return FLB_FALSE;
    }

    route_length = strlen(route->path);
    path_length = cfl_sds_len(path);

    if (route->match_type == FLB_HS_ROUTE_PREFIX) {
        if (path_length < route_length) {
            return FLB_FALSE;
        }

        return strncmp(route->path, path, route_length) == 0;
    }

    if (route_length != path_length) {
        return FLB_FALSE;
    }

    return strncmp(route->path, path, route_length) == 0;
}

static void flb_hs_destroy_cmt_buffer(void *data)
{
    cmt_destroy((struct cmt *) data);
}

void flb_hs_cmt_buffer_destroy(void *data)
{
    flb_hs_destroy_cmt_buffer(data);
}

static int cb_root(struct flb_hs *hs,
                   struct flb_http_request *request,
                   struct flb_http_response *response)
{
    (void) request;

    return flb_hs_response_set_payload(response,
                                       200,
                                       FLB_HS_CONTENT_TYPE_JSON,
                                       hs->ep_root_buf,
                                       hs->ep_root_size);
}

static int flb_hs_request_handler(struct flb_http_request *request,
                                  struct flb_http_response *response)
{
    struct mk_list *head;
    struct flb_hs *hs;
    struct flb_hs_route *route;

    hs = response->stream->user_data;
    if (hs == NULL) {
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    mk_list_foreach(head, &hs->routes) {
        route = mk_list_entry(head, struct flb_hs_route, _head);

        if (flb_hs_route_matches(route, request->path)) {
            return route->callback(hs, request, response);
        }
    }

    flb_http_response_set_status(response, 404);
    return flb_http_response_commit(response);
}

static void flb_hs_buf_cleanup(struct flb_hs_buf *buffer,
                               void (*raw_free)(void *))
{
    if (buffer == NULL) {
        return;
    }

    if (buffer->users > 0) {
        buffer->pending_free = FLB_TRUE;
        return;
    }

    if (buffer->data != NULL) {
        flb_sds_destroy(buffer->data);
        buffer->data = NULL;
    }

    if (buffer->raw_data != NULL) {
        if (raw_free != NULL) {
            raw_free(buffer->raw_data);
        }
        else {
            flb_free(buffer->raw_data);
        }
        buffer->raw_data = NULL;
    }

    buffer->raw_size = 0;
    buffer->pending_free = FLB_FALSE;
    buffer->users = 0;
}

void flb_hs_buf_release(struct flb_hs_buf *buffer, void (*raw_free)(void *))
{
    if (buffer == NULL || buffer->users <= 0) {
        return;
    }

    buffer->users--;

    if (buffer->users == 0 && buffer->pending_free == FLB_TRUE) {
        flb_hs_buf_cleanup(buffer, raw_free);
    }
}

int flb_hs_register_endpoint(struct flb_hs *hs,
                             const char *path,
                             int match_type,
                             flb_hs_endpoint_callback callback)
{
    struct flb_hs_route *route;

    route = flb_calloc(1, sizeof(struct flb_hs_route));
    if (route == NULL) {
        flb_errno();
        return -1;
    }

    /* Registered endpoints are static literals owned by the caller/module. */
    route->path = path;
    route->match_type = match_type;
    route->callback = callback;

    mk_list_add(&route->_head, &hs->routes);

    return 0;
}

/* Ingest health metrics into the web service context */
int flb_hs_push_health_metrics(struct flb_hs *hs, void *data, size_t size)
{
    struct flb_hs_hc_buf *buf;
    int error_count;
    int retry_failure_count;

    if (hs == NULL) {
        return -1;
    }

    read_metrics(data, size, &error_count, &retry_failure_count);

    hs->health_counter.period_counter++;

    while (hs->health_counter.period_counter > hs->health_counter.period_limit &&
           mk_list_size(&hs->health_metrics) > 0) {
        buf = mk_list_entry_first(&hs->health_metrics, struct flb_hs_hc_buf, _head);
        if (buf->users > 0) {
            break;
        }
        mk_list_del(&buf->_head);
        flb_free(buf);
        hs->health_counter.period_counter--;
    }

    buf = flb_calloc(1, sizeof(struct flb_hs_hc_buf));
    if (buf == NULL) {
        flb_errno();
        return -1;
    }

    buf->error_count = error_count;
    buf->retry_failure_count = retry_failure_count;

    hs->health_counter.error_counter = error_count;
    hs->health_counter.retry_failure_counter = retry_failure_count;

    mk_list_add(&buf->_head, &hs->health_metrics);

    return 0;
}

/* Ingest pipeline metrics into the web service context */
int flb_hs_push_pipeline_metrics(struct flb_hs *hs, void *data, size_t size)
{
    flb_sds_t json_buffer;
    void *raw_buffer;

    if (hs == NULL) {
        return -1;
    }

    json_buffer = flb_msgpack_raw_to_json_sds(data, size, FLB_TRUE);
    if (json_buffer == NULL) {
        return -1;
    }

    raw_buffer = flb_malloc(size);
    if (raw_buffer == NULL) {
        flb_errno();
        flb_sds_destroy(json_buffer);
        return -1;
    }

    memcpy(raw_buffer, data, size);

    flb_hs_buf_cleanup(&hs->metrics, NULL);
    if (hs->metrics.pending_free == FLB_TRUE) {
        flb_sds_destroy(json_buffer);
        flb_free(raw_buffer);
        return -1;
    }

    hs->metrics.data = json_buffer;
    hs->metrics.raw_data = raw_buffer;
    hs->metrics.raw_size = size;

    return 0;
}

/* Ingest pipeline metrics into the web service context */
int flb_hs_push_metrics(struct flb_hs *hs, void *data, size_t size)
{
    int ret;
    size_t off = 0;
    struct cmt *cmt;

    if (hs == NULL) {
        return -1;
    }

    ret = cmt_decode_msgpack_create(&cmt, data, size, &off);
    if (ret != 0) {
        return -1;
    }

    flb_hs_buf_cleanup(&hs->metrics_v2, flb_hs_destroy_cmt_buffer);
    if (hs->metrics_v2.pending_free == FLB_TRUE) {
        flb_hs_destroy_cmt_buffer(cmt);
        return -1;
    }

    hs->metrics_v2.raw_data = cmt;

    return 0;
}

/* Ingest storage metrics into the web service context */
int flb_hs_push_storage_metrics(struct flb_hs *hs, void *data, size_t size)
{
    flb_sds_t json_buffer;
    void *raw_buffer;

    if (hs == NULL) {
        return -1;
    }

    json_buffer = flb_msgpack_raw_to_json_sds(data, size, FLB_TRUE);
    if (json_buffer == NULL) {
        return -1;
    }

    raw_buffer = flb_malloc(size);
    if (raw_buffer == NULL) {
        flb_errno();
        flb_sds_destroy(json_buffer);
        return -1;
    }

    memcpy(raw_buffer, data, size);

    flb_hs_buf_cleanup(&hs->storage_metrics, NULL);
    if (hs->storage_metrics.pending_free == FLB_TRUE) {
        flb_sds_destroy(json_buffer);
        flb_free(raw_buffer);
        return -1;
    }

    hs->storage_metrics.data = json_buffer;
    hs->storage_metrics.raw_data = raw_buffer;
    hs->storage_metrics.raw_size = size;

    return 0;
}

/* Create ROOT endpoints */
struct flb_hs *flb_hs_create(const char *listen, const char *tcp_port,
                             struct flb_config *config)
{
    int ret;
    char *end;
    long port;
    struct flb_hs *hs;
    struct flb_http_server_options options;

    hs = flb_calloc(1, sizeof(struct flb_hs));
    if (!hs) {
        flb_errno();
        return NULL;
    }

    hs->config = config;
    mk_list_init(&hs->routes);
    mk_list_init(&hs->health_metrics);

    hs->health_counter.error_limit = config->hc_errors_count;
    hs->health_counter.retry_failure_limit = config->hc_retry_failure_count;
    hs->health_counter.period_limit = config->health_check_period;

    /* Setup endpoint specific data */
    flb_hs_endpoints(hs);

    flb_http_server_options_init(&options);
    options.protocol_version = HTTP_PROTOCOL_VERSION_AUTODETECT;
    options.flags = 0;
    options.request_callback = flb_hs_request_handler;
    options.user_data = hs;
    options.address = (char *) listen;
    errno = 0;
    port = strtol(tcp_port, &end, 10);
    if (errno == ERANGE || end == tcp_port || *end != '\0' ||
        port <= 0 || port > 65535) {
        flb_error("[http_server] invalid monitoring tcp_port '%s'", tcp_port);
        flb_free(hs);
        return NULL;
    }
    options.port = (int) port;
    options.networking_flags = 0;
    flb_net_setup_init(&hs->net_setup);
    options.networking_setup = &hs->net_setup;
    options.event_loop = config->evl;
    options.system_context = config;
    options.use_caller_event_loop = FLB_TRUE;

    ret = flb_http_server_init_with_options(&hs->server, &options);
    if (ret != 0) {
        flb_free(hs);
        return NULL;
    }

    /* Register endpoints for /api/v1 */
    ret = api_v1_registration(hs);
    if (ret != 0) {
        flb_hs_destroy(hs);
        return NULL;
    }

    /* Register endpoints for /api/v2 */
    ret = api_v2_registration(hs);
    if (ret != 0) {
        flb_hs_destroy(hs);
        return NULL;
    }

    /* Root */
    ret = flb_hs_register_endpoint(hs, "/", FLB_HS_ROUTE_EXACT, cb_root);
    if (ret != 0) {
        flb_hs_destroy(hs);
        return NULL;
    }

    return hs;
}

int flb_hs_start(struct flb_hs *hs)
{
    int ret;
    struct flb_config *config = hs->config;

    ret = flb_http_server_start(&hs->server);

    if (ret == 0) {
        flb_info("[http_server] listen iface=%s tcp_port=%s",
                 config->http_listen, config->http_port);
    }

    return ret;
}

int flb_hs_destroy(struct flb_hs *hs)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_hs_route *route;
    struct flb_hs_hc_buf *health_buffer;

    if (!hs) {
        return 0;
    }

    flb_hs_health_destroy();
    flb_http_server_destroy(&hs->server);

    flb_hs_buf_cleanup(&hs->metrics, NULL);
    flb_hs_buf_cleanup(&hs->metrics_v2, flb_hs_destroy_cmt_buffer);
    flb_hs_buf_cleanup(&hs->storage_metrics, NULL);

    mk_list_foreach_safe(head, tmp, &hs->health_metrics) {
        health_buffer = mk_list_entry(head, struct flb_hs_hc_buf, _head);
        mk_list_del(&health_buffer->_head);
        flb_free(health_buffer);
    }

    mk_list_foreach_safe(head, tmp, &hs->routes) {
        route = mk_list_entry(head, struct flb_hs_route, _head);
        mk_list_del(&route->_head);
        flb_free(route);
    }

    flb_hs_endpoints_free(hs);
    flb_free(hs);

    return 0;
}
