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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_http_server.h>

#include <monkey/mk_lib.h>

/* v1 */
#include "api/v1/register.h"
#include "api/v1/health.h"

/* v2 */
#include "api/v2/register.h"

static void cb_root(mk_request_t *request, void *data)
{
    struct flb_hs *hs = data;

    mk_http_status(request, 200);
    flb_hs_add_content_type_to_req(request, FLB_HS_CONTENT_TYPE_JSON);
    mk_http_send(request, hs->ep_root_buf, hs->ep_root_size, NULL);
    mk_http_done(request);
}

/* Ingest health metrics into the web service context */
int flb_hs_push_health_metrics(struct flb_hs *hs, void *data, size_t size)
{
    return mk_mq_send(hs->ctx, hs->qid_health, data, size);
}

/* Ingest pipeline metrics into the web service context */
int flb_hs_push_pipeline_metrics(struct flb_hs *hs, void *data, size_t size)
{
    return mk_mq_send(hs->ctx, hs->qid_metrics, data, size);
}

/* Ingest pipeline metrics into the web service context */
int flb_hs_push_metrics(struct flb_hs *hs, void *data, size_t size)
{
    return mk_mq_send(hs->ctx, hs->qid_metrics_v2, data, size);
}

/* Ingest storage metrics into the web service context */
int flb_hs_push_storage_metrics(struct flb_hs *hs, void *data, size_t size)
{
    return mk_mq_send(hs->ctx, hs->qid_storage, data, size);
}

/* Create ROOT endpoints */
struct flb_hs *flb_hs_create(const char *listen, const char *tcp_port,
                             struct flb_config *config)
{
    int vid;
    /* Accept IPv6 and IPv4 address */
    char tmp[46];
    struct flb_hs *hs;

    hs = flb_calloc(1, sizeof(struct flb_hs));
    if (!hs) {
        flb_errno();
        return NULL;
    }
    hs->config = config;

    /* Setup endpoint specific data */
    flb_hs_endpoints(hs);

    /* Create HTTP server context */
    hs->ctx = mk_create();
    if (!hs->ctx) {
        flb_error("[http_server] could not create context");
        flb_free(hs);
        return NULL;
    }

    /* Compose listen address */
    snprintf(tmp, sizeof(tmp) -1, "%s:%s", listen, tcp_port);
    mk_config_set(hs->ctx, "Listen", tmp, NULL);
    vid = mk_vhost_create(hs->ctx, NULL);
    hs->vid = vid;

    /* Setup virtual host */
    mk_vhost_set(hs->ctx, vid,
                 "Name", "fluent-bit",
                 NULL);


    /* Register endpoints for /api/v1 */
    api_v1_registration(hs);

    /* Register endpoints for /api/v2 */
    api_v2_registration(hs);

    /* Root */
    mk_vhost_handler(hs->ctx, vid, "/", cb_root, hs);

    return hs;
}

int flb_hs_start(struct flb_hs *hs)
{
    int ret;
    struct flb_config *config = hs->config;

    ret = mk_start(hs->ctx);

    if (ret == 0) {
        flb_info("[http_server] listen iface=%s tcp_port=%s",
                 config->http_listen, config->http_port);
    }
    return ret;
}

int flb_hs_destroy(struct flb_hs *hs)
{
    if (!hs) {
        return 0;
    }
    flb_hs_health_destroy();
    mk_stop(hs->ctx);
    mk_destroy(hs->ctx);

    flb_hs_endpoints_free(hs);
    flb_free(hs);


    return 0;
}
