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
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_crypto_constants.h>
#include <fluent-bit/flb_compression.h>

#include <math.h>

#include "azure_blob.h"
#include "azure_blob_conf.h"
#include "azure_blob_uri.h"
#include "azure_blob_http.h"

static const char *azb_blob_extension(struct flb_azure_blob *ctx)
{
    if (ctx->compress_blob != FLB_TRUE) {
        return "";
    }

    if (ctx->compression == FLB_COMPRESSION_ALGORITHM_ZSTD) {
        return ".zst";
    }

    return ".gz";
}

flb_sds_t azb_block_blob_blocklist_uri(struct flb_azure_blob *ctx, char *name)
{
    flb_sds_t uri;

    uri = azb_uri_container(ctx);
    if (!uri) {
        return NULL;
    }

    if (ctx->path) {
        flb_sds_printf(&uri, "/%s/%s?comp=blocklist",
                       ctx->path, name);
    }
    else {
        flb_sds_printf(&uri, "/%s?comp=blocklist", name);
    }

    if (ctx->atype == AZURE_BLOB_AUTH_SAS && ctx->sas_token) {
        flb_sds_printf(&uri, "&%s", ctx->sas_token);
    }

    return uri;
}

flb_sds_t azb_block_blob_uri(struct flb_azure_blob *ctx, char *name,
                             char *blockid, uint64_t ms, char *random_str)
{
    int len;
    flb_sds_t uri;
    const char *ext;
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

    ext = azb_blob_extension(ctx);

    if (ctx->path) {
        if (ms > 0) {
            flb_sds_printf(&uri, "/%s/%s.%s.%" PRIu64 "%s?blockid=%s&comp=block",
                    ctx->path, name, random_str, ms, ext, encoded_blockid);
        }
        else {
            flb_sds_printf(&uri, "/%s/%s.%s%s?blockid=%s&comp=block",
                    ctx->path, name, random_str, ext, encoded_blockid);
        }
    }
    else {
        if (ms > 0) {
            flb_sds_printf(&uri, "/%s.%s.%" PRIu64 "%s?blockid=%s&comp=block",
                    name, random_str, ms, ext, encoded_blockid);
        }
        else {
            flb_sds_printf(&uri, "/%s.%s%s?blockid=%s&comp=block",
                    name, random_str, ext, encoded_blockid);
        }
    }

    if (ctx->atype == AZURE_BLOB_AUTH_SAS && ctx->sas_token) {
        flb_sds_printf(&uri, "&%s", ctx->sas_token);
    }

    flb_sds_destroy(encoded_blockid);
    return uri;
}

flb_sds_t azb_block_blob_uri_commit(struct flb_azure_blob *ctx,
                                    char *tag, uint64_t ms, char *str)
{
    const char *ext;
    flb_sds_t uri;

    uri = azb_uri_container(ctx);
    if (!uri) {
        return NULL;
    }

    ext = azb_blob_extension(ctx);

    if (ctx->path) {
        flb_sds_printf(&uri, "/%s/%s.%s.%" PRIu64 "%s?comp=blocklist", ctx->path, tag, str,
                ms, ext);
    }
    else {
        flb_sds_printf(&uri, "/%s.%s.%" PRIu64 "%s?comp=blocklist", tag, str, ms, ext);
    }

    if (ctx->atype == AZURE_BLOB_AUTH_SAS && ctx->sas_token) {
        flb_sds_printf(&uri, "&%s", ctx->sas_token);
    }

    return uri;
}

/*
 * Generate a block id for log type events, we always submit one chunk as a block, so
 * we just use the current time in milliseconds as a suffix.
 */
char *azb_block_blob_id_logs(uint64_t *ms)
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

/*
 * Generate a block id for blob type events:
 *
 * Azure Blob requires that Blobs IDs do not exceed 64 bytes, so we generate a MD5
 * of the path and append the part number to it, we add some zeros for padding since
 * all blocks id MUST have the same length.
 */
char *azb_block_blob_id_blob(struct flb_azure_blob *ctx, char *path, int64_t part_id)
{
    int i;
    int len;
    int ret;
    unsigned char md5[16] = {0};
    char tmp[128];
    flb_sds_t md5_hex;
    size_t size;
    size_t o_len;
    char *b64;

    /*
     * block ids in base64 cannot exceed 64 bytes, so we hash the path to avoid
     * exceeding the lenght and then just append the part number.
     */
    ret = flb_hash_simple(FLB_HASH_MD5, (unsigned char *) path, strlen(path),
                          md5, sizeof(md5));
    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot hash block id for path %s", path);
        return NULL;
    }

    /* convert md5 to hex string (32 byte hex string) */
    md5_hex = flb_sds_create_size(32);
    if (!md5_hex) {
        return NULL;
    }

    for (i = 0; i < 16; i++) {
        snprintf(md5_hex + (i * 2), 3, "%02x", md5[i]);
    }
    flb_sds_len_set(md5_hex, 32);

    /* append part number */
    len = snprintf(tmp, sizeof(tmp) - 1, "%s.flb-part.%06ld", md5_hex, part_id);
    flb_sds_destroy(md5_hex);

    size = 64 + 1;
    b64 = flb_calloc(1, size);
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

int azb_block_blob_put_block_list(struct flb_azure_blob *ctx, flb_sds_t uri, flb_sds_t payload)
{
    int ret;
    size_t b_sent;
    struct flb_http_client *c;
    struct flb_connection *u_conn;

    if (ctx->buffering_enabled == FLB_TRUE){
        ctx->u->base.flags &= ~(FLB_IO_ASYNC);
        ctx->u->base.net.io_timeout = ctx->io_timeout;
    }

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins,
                      "cannot create upstream connection for blockblob commit");
        return FLB_RETRY;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_PUT,
                        uri,
                        payload, flb_sds_len(payload), NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        flb_upstream_conn_release(u_conn);
        return FLB_RETRY;
    }

    /* Prepare headers and authentication */
    azb_http_client_setup(ctx, c, flb_sds_len(payload),
                          FLB_FALSE,
                          AZURE_BLOB_CT_NONE, AZURE_BLOB_CE_NONE);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);

    /* Validate HTTP status */
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error sending block_blob");
        return FLB_RETRY;
    }

    if (c->resp.status == 201) {
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return FLB_OK;
    }
    else if (c->resp.status == 404) {
        /* delete "&sig=..." in the c->uri for security */
        char *p = strstr(c->uri, "&sig=");
        if (p) {
            *p = '\0';
        }

        flb_plg_info(ctx->ins, "blob not found: %s", c->uri);
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return FLB_RETRY;
    }
    else if (c->resp.payload_size > 0) {
        // flb_plg_error(ctx->ins, "cannot commit blob id %s\n%s",
        //               blockid, c->resp.payload);
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

/* Commit a single block */
int azb_block_blob_commit_block(struct flb_azure_blob *ctx, char *blockid, char *tag, uint64_t ms, char *str)
{
    int ret;
    flb_sds_t uri = NULL;
    flb_sds_t payload;

    /* Compose commit URI */
    uri = azb_block_blob_uri_commit(ctx, tag, ms, str);
    if (!uri) {
        return FLB_ERROR;
    }

    payload = flb_sds_create_size(256);
    if (!payload) {
        flb_sds_destroy(uri);
        return FLB_ERROR;
    }

    flb_sds_printf(&payload,
                   "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                   "<BlockList>"
                   "  <Latest>%s</Latest>"
                   "</BlockList>",
                   blockid);

    ret = azb_block_blob_put_block_list(ctx, uri, payload);
    flb_sds_destroy(uri);
    flb_sds_destroy(payload);

    if (ret == FLB_OK) {
        flb_plg_info(ctx->ins, "blob id %s committed successfully", blockid);
    }

    return ret;
}

int azb_block_blob_commit_file_parts(struct flb_azure_blob *ctx, uint64_t file_id, cfl_sds_t path, cfl_sds_t part_ids)
{
    int ret;
    uint64_t id;
    char *block_id;
    cfl_sds_t payload;
    flb_sds_t uri;
    struct mk_list *list;
    struct mk_list *head;
    struct flb_split_entry *sentry;

    /* split parts in a list */
    list = flb_utils_split(part_ids, ',', -1);
    if (!list) {
        flb_plg_error(ctx->ins, "cannot split parts list for file id=%" PRIu64 " name %s", file_id, path);
        return -1;
    }

    payload = flb_sds_create_size(1024);
    if (!payload) {
        flb_utils_split_free(list);
        return -1;
    }

    /*
     * Compose XML with list of blocks
     * https://learn.microsoft.com/en-us/rest/api/storageservices/put-block-list?tabs=microsoft-entra-id#request-body
     */
    cfl_sds_printf(&payload,
                   "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                   "<!-- %s -->\n"
                   "<BlockList>\n",
                   path);

    mk_list_foreach(head, list) {
        sentry = mk_list_entry(head, struct flb_split_entry, _head);

        id = atol(sentry->value);
        block_id = azb_block_blob_id_blob(ctx, path, id);

        cfl_sds_cat_safe(&payload, "  ", 2);
        cfl_sds_cat_safe(&payload, "<Uncommitted>", 13);
        cfl_sds_cat_safe(&payload, block_id, strlen(block_id));
        cfl_sds_cat_safe(&payload, "</Uncommitted>", 14);
        cfl_sds_cat_safe(&payload, "\n", 1);

        flb_free(block_id);
    }

    cfl_sds_cat_safe(&payload, "</BlockList>", 12);
    flb_utils_split_free(list);

    uri = azb_block_blob_blocklist_uri(ctx, path);
    if (!uri) {
        flb_sds_destroy(payload);
        return -1;
    }

    ret = azb_block_blob_put_block_list(ctx, uri, payload);
    flb_sds_destroy(uri);
    flb_sds_destroy(payload);

    return ret;
}
