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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_oauth2.h>

#include <msgpack.h>

#include "gce_metadata.h"
#include "stackdriver.h"
#include "stackdriver_conf.h"


static int fetch_metadata(struct flb_stackdriver *ctx,
                          struct flb_upstream *upstream, char *uri,
                          char *payload)
{
    int ret;
    int ret_code;
    size_t b_sent;
    struct flb_connection *metadata_conn;
    struct flb_http_client *c;

    /* If runtime test mode is enabled, add test data */
    if (ctx->ins->test_mode == FLB_TRUE) {
        if (strcmp(uri, FLB_STD_METADATA_PROJECT_ID_URI) == 0) {
            flb_sds_cat(payload, "fluent-bit-test", 15);
            return 0;
        }
        else if (strcmp(uri, FLB_STD_METADATA_ZONE_URI) == 0) {
            flb_sds_cat(payload, "projects/0123456789/zones/fluent", 32);
            return 0;
        }
        else if (strcmp(uri, FLB_STD_METADATA_INSTANCE_ID_URI) == 0) {
            flb_sds_cat(payload, "333222111", 9);
            return 0;
        }
        return -1;
    }

    /* Get metadata connection */
    metadata_conn = flb_upstream_conn_get(upstream);
    if (!metadata_conn) {
        flb_plg_error(ctx->ins, "failed to create metadata connection");
        return -1;
    }

    /* Compose HTTP Client request */
    c = flb_http_client(metadata_conn, FLB_HTTP_GET, uri,
                        "", 0, NULL, 0, NULL, 0);

    flb_http_buffer_size(c, FLB_STD_METADATA_TOKEN_SIZE_MAX);

    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Content-Type", 12, "application/text", 16);
    flb_http_add_header(c, "Metadata-Flavor", 15, "Google", 6);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);

    /* validate response */
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "http_do=%i", ret);
        ret_code = -1;
    }
    else {
        /* The request was issued successfully, validate the 'error' field */
        flb_plg_debug(ctx->ins, "HTTP Status=%i", c->resp.status);
        if (c->resp.status == 200) {
            ret_code = 0;
            flb_sds_copy(payload, c->resp.payload, c->resp.payload_size);
        }
        else {
            if (c->resp.payload_size > 0) {
                /* we got an error */
                flb_plg_warn(ctx->ins, "error\n%s", c->resp.payload);
            }
            else {
                flb_plg_debug(ctx->ins, "response\n%s", c->resp.payload);
            }
            ret_code = -1;
        }
    }

    /* Cleanup */
    flb_http_client_destroy(c);
    flb_upstream_conn_release(metadata_conn);

    return ret_code;
}

int gce_metadata_read_token(struct flb_stackdriver *ctx)
{
    int ret;
    flb_sds_t uri = flb_sds_create(FLB_STD_METADATA_SERVICE_ACCOUNT_URI);
    flb_sds_t payload = flb_sds_create_size(FLB_STD_METADATA_TOKEN_SIZE_MAX);

    uri = flb_sds_cat(uri, ctx->client_email, flb_sds_len(ctx->client_email));
    uri = flb_sds_cat(uri, "/token", 6);
    ret = fetch_metadata(ctx, ctx->metadata_u, uri, payload);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "can't fetch token from the metadata server");
        flb_sds_destroy(payload);
        flb_sds_destroy(uri);
        return -1;
    }

    ret = flb_oauth2_parse_json_response(payload, flb_sds_len(payload), ctx->o);
    flb_sds_destroy(payload);
    flb_sds_destroy(uri);

    if (ret != 0) {
        flb_plg_error(ctx->ins, "unable to parse token body");
        return -1;
    }
    ctx->o->expires_at = time(NULL) + ctx->o->expires_in;
    return 0;
}

int gce_metadata_read_zone(struct flb_stackdriver *ctx)
{
    int ret;
    int i;
    int j;
    int part = 0;
    flb_sds_t payload = flb_sds_create_size(4096);
    flb_sds_t zone = NULL;

    ret = fetch_metadata(ctx, ctx->metadata_u, FLB_STD_METADATA_ZONE_URI,
                         payload);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "can't fetch zone from the metadata server");
        flb_sds_destroy(payload);
        return -1;
    }

    /* Data returned in the format projects/{project-id}/zones/{name} */
    for (i = 0; i < flb_sds_len(payload); ++i) {
        if (payload[i] == '/') {
            part++;
        }
        if (part == 3) {
            i++;
            break;
        }
    }

    if (part != 3) {
        flb_plg_error(ctx->ins, "wrong format of zone response");
        flb_sds_destroy(payload);
        return -1;
    }

    zone = flb_sds_create_size(flb_sds_len(payload) - i);

    j = 0;
    while (i != flb_sds_len(payload)) {
        zone[j] = payload[i];
        i++;
        j++;
    }
    zone[j] = '\0';
    ctx->zone = flb_sds_create(zone);
    flb_sds_destroy(zone);
    flb_sds_destroy(payload);

    return 0;
}

int gce_metadata_read_project_id(struct flb_stackdriver *ctx)
{
    int ret;
    flb_sds_t payload = flb_sds_create_size(4096);

    ret = fetch_metadata(ctx, ctx->metadata_u,
                         FLB_STD_METADATA_PROJECT_ID_URI, payload);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "can't fetch project id from the metadata server");
        flb_sds_destroy(payload);
        return -1;
    }
    ctx->project_id = flb_sds_create(payload);
    flb_sds_destroy(payload);
    return 0;
}

int gce_metadata_read_instance_id(struct flb_stackdriver *ctx)
{
    int ret;
    flb_sds_t payload = flb_sds_create_size(4096);

    ret = fetch_metadata(ctx, ctx->metadata_u,
                         FLB_STD_METADATA_INSTANCE_ID_URI, payload);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "can't fetch instance id from the metadata server");
        flb_sds_destroy(payload);
        return -1;
    }
    ctx->instance_id = flb_sds_create(payload);
    flb_sds_destroy(payload);
    return 0;
}
