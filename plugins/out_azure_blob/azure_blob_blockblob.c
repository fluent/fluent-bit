/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_sds.h>

#include <math.h>

#include "azure_blob.h"
#include "azure_blob_conf.h"
#include "azure_blob_uri.h"
#include "azure_blob_http.h"

flb_sds_t azb_block_blob_uri(struct flb_azure_blob *ctx, char *tag,
                             char *blockid, uint64_t ms)
{
    int len;
    flb_sds_t uri;
    char *ext;
    char *encoded_blockid;

    len = strlen(blockid);
    encoded_blockid = azb_uri_encode(blockid, len);
    if (!encoded_blockid) {
        return NULL;
    }

    uri = azb_uri_container(ctx);
    if (!uri) {
        flb_sds_destroy(encoded_blockid);
        return NULL;
    }

    if (ctx->compress_blob == FLB_TRUE) {
        ext = ".gz";
    }
    else {
        ext = "";
    }

    if (ctx->path) {
        flb_sds_printf(&uri, "/%s/%s.%" PRIu64 "%s?blockid=%s&comp=block",
                       ctx->path, tag, ms, ext, encoded_blockid);
    }
    else {
        flb_sds_printf(&uri, "/%s.%" PRIu64 "%s?blockid=%s&comp=block",
                       tag, ms, ext, encoded_blockid);
    }

    flb_sds_destroy(encoded_blockid);
    return uri;
}

flb_sds_t azb_block_blob_uri_commit(struct flb_azure_blob *ctx,
                                    char *tag, uint64_t ms)
{
    char *ext;
    flb_sds_t uri;

    uri = azb_uri_container(ctx);
    if (!uri) {
        return NULL;
    }

    if (ctx->compress_blob == FLB_TRUE) {
        ext = ".gz";
    }
    else {
        ext = "";
    }

    if (ctx->path) {
        flb_sds_printf(&uri, "/%s/%s.%" PRIu64 "%s?comp=blocklist", ctx->path, tag,
                       ms, ext);
    }
    else {
        flb_sds_printf(&uri, "/%s.%" PRIu64 "%s?comp=blocklist", tag, ms, ext);
    }

    return uri;
}

/* Generate a block id */
char *azb_block_blob_id(uint64_t *ms)
{
    int len;
    int ret;
    double now;
    char tmp[32];
    size_t size;
    size_t o_len;
    char *b64;
    struct flb_time tm;

    /* Get current time */
    flb_time_get(&tm);

    /*
     * Set outgoing time in milliseconds: this is used as a suffix for the
     * block name
     */
    *ms = ((tm.tm.tv_sec * 1000) + (tm.tm.tv_nsec / 1000000));

    /* Convert time to double to format the block id */
    now = flb_time_to_double(&tm);
    len = snprintf(tmp, sizeof(tmp), "flb-%.4f.id", now);

    /* Allocate space for the outgoing base64 buffer */
    size = (4 * ceil(((double) len / 3) + 1));
    b64 = flb_malloc(size);
    if (!b64) {
        return NULL;
    }

    /* base64 encode block id */
    ret = flb_base64_encode((unsigned char *) b64, size, &o_len,
                            (unsigned char *) tmp, len);
    if (ret != 0) {
        flb_free(b64);
        return NULL;
    }
    return b64;
}

int azb_block_blob_commit(struct flb_azure_blob *ctx, char *blockid, char *tag,
                          uint64_t ms)
{
    int ret;
    size_t b_sent;
    flb_sds_t uri = NULL;
    flb_sds_t payload;
    struct flb_http_client *c;
    struct flb_connection *u_conn;

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins,
                      "cannot create upstream connection for blockblob commit");
        return FLB_RETRY;
    }

    /* Compose commit URI */
    uri = azb_block_blob_uri_commit(ctx, tag, ms);
    if (!uri) {
        flb_upstream_conn_release(u_conn);
        return FLB_ERROR;
    }

    payload = flb_sds_create_size(256);
    if (!payload) {
        flb_sds_destroy(uri);
        flb_upstream_conn_release(u_conn);
        return FLB_ERROR;
    }

    flb_sds_printf(&payload,
                   "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                   "<BlockList>"
                   "  <Latest>%s</Latest>"
                   "</BlockList>",
                   blockid);

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_PUT,
                        uri,
                        payload, flb_sds_len(payload), NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        flb_sds_destroy(payload);
        flb_sds_destroy(uri);
        flb_upstream_conn_release(u_conn);
        return FLB_RETRY;
    }

    /* Prepare headers and authentication */
    azb_http_client_setup(ctx, c, flb_sds_len(payload),
                          FLB_FALSE,
                          AZURE_BLOB_CT_NONE, AZURE_BLOB_CE_NONE);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);
    flb_sds_destroy(uri);
    flb_sds_destroy(payload);

    /* Validate HTTP status */
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error sending append_blob");
        return FLB_RETRY;
    }

    if (c->resp.status == 201) {
        flb_plg_info(ctx->ins, "blob id %s committed successfully", blockid);
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return FLB_OK;
    }
    else if (c->resp.status == 404) {
        flb_plg_info(ctx->ins, "blob not found: %s", c->uri);
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return FLB_RETRY;
    }
    else if (c->resp.payload_size > 0) {
        flb_plg_error(ctx->ins, "cannot commit blob id %s\n%s",
                      blockid, c->resp.payload);
        if (strstr(c->resp.payload, "must be 0 for Create Append")) {
            flb_http_client_destroy(c);
            flb_upstream_conn_release(u_conn);
            return FLB_RETRY;
        }
    }
    else {
        flb_plg_error(ctx->ins, "cannot append content to blob");
    }
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    return FLB_OK;
}
