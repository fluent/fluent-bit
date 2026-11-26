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

#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_compression.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_gcp_auth.h>
#include <fluent-bit/flb_utils.h>

#include <inttypes.h>
#include <stdlib.h>

#include "gcs.h"

/* Percent-encode every byte that is not unreserved (RFC 3986), '/' included */
flb_sds_t in_gcs_uri_encode(const char *value, size_t len)
{
    size_t i;
    size_t o = 0;
    unsigned char c;
    char *buffer;
    flb_sds_t out;
    const char hex[] = "0123456789ABCDEF";

    if (!value || len > (((size_t) -1) - 1) / 3) {
        return NULL;
    }

    buffer = flb_malloc((len * 3) + 1);
    if (!buffer) {
        flb_errno();
        return NULL;
    }

    for (i = 0; i < len; i++) {
        c = (unsigned char) value[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            buffer[o++] = (char) c;
        }
        else {
            buffer[o++] = '%';
            buffer[o++] = hex[c >> 4];
            buffer[o++] = hex[c & 0x0f];
        }
    }
    buffer[o] = '\0';

    out = flb_sds_create_len(buffer, o);
    flb_free(buffer);
    return out;
}

/* Append '&key=<encoded value>' (or '?key=...' for the first parameter) */
static int gcs_uri_add_param(flb_sds_t *uri, const char *key, const char *value, size_t len)
{
    flb_sds_t encoded;
    flb_sds_t tmp;

    encoded = in_gcs_uri_encode(value, len);
    if (!encoded) {
        return -1;
    }

    tmp = flb_sds_printf(uri, "%c%s=%s", strchr(*uri, '?') ? '&' : '?', key, encoded);
    flb_sds_destroy(encoded);
    if (!tmp) {
        return -1;
    }
    *uri = tmp;
    return 0;
}

static void gcs_items_free_array(struct gcs_item *list, int count)
{
    int i;

    for (i = 0; i < count; i++) {
        if (list[i].name) {
            flb_sds_destroy(list[i].name);
        }
        if (list[i].generation) {
            flb_sds_destroy(list[i].generation);
        }
    }
    flb_free(list);
}

void in_gcs_items_destroy(struct flb_in_gcs *ctx)
{
    if (ctx->items) {
        gcs_items_free_array(ctx->items, ctx->items_count);
    }
    ctx->items = NULL;
    ctx->items_count = 0;
    ctx->items_index = 0;
}

/* Release the object in progress and its buffers */
void in_gcs_current_clear(struct flb_in_gcs *ctx)
{
    if (ctx->current.name) {
        flb_sds_destroy(ctx->current.name);
    }
    if (ctx->current.generation) {
        flb_sds_destroy(ctx->current.generation);
    }
    memset(&ctx->current, 0, sizeof(ctx->current));
    ctx->has_current = FLB_FALSE;

    if (ctx->buf) {
        flb_free(ctx->buf);
    }
    ctx->buf = NULL;
    ctx->buf_len = 0;
    ctx->buf_off = 0;

    if (ctx->tag) {
        flb_sds_destroy(ctx->tag);
    }
    ctx->tag = NULL;
}

static void gcs_response_release(struct gcs_response *r)
{
    if (r->client) {
        flb_http_client_destroy(r->client);
    }
    if (r->conn) {
        flb_upstream_conn_release(r->conn);
    }
    memset(r, 0, sizeof(struct gcs_response));
}

static void gcs_set_error(struct flb_in_gcs *ctx, struct gcs_response *r)
{
    int len = 0;
    int i;

    if (r->client && r->client->resp.payload_size > 0 && r->client->resp.payload) {
        len = r->client->resp.payload_size > 256 ? 256 : (int) r->client->resp.payload_size;
    }
    snprintf(ctx->last_error, sizeof(ctx->last_error), "status=%d body=%.*s",
             r->status, len, len > 0 ? r->client->resp.payload : "");

    /* keep the message on one line */
    for (i = 0; ctx->last_error[i] != '\0'; i++) {
        if (ctx->last_error[i] == '\n' || ctx->last_error[i] == '\r') {
            ctx->last_error[i] = ' ';
        }
    }
}

/*
 * Perform a GET request. On a response (any status) 'r' keeps the client alive: the
 * caller must release it with gcs_response_release().
 */
static int gcs_get(struct flb_in_gcs *ctx, flb_sds_t uri, size_t limit, struct gcs_response *r)
{
    int ret;
    size_t b_sent;
    flb_sds_t auth;

    memset(r, 0, sizeof(struct gcs_response));

    auth = flb_gcp_auth_get_header(ctx->auth);
    if (!auth) {
        snprintf(ctx->last_error, sizeof(ctx->last_error), "could not get an access token");
        return FLB_GCS_REQ_TRANSIENT;
    }

    r->conn = flb_upstream_conn_get(ctx->upstream);
    if (!r->conn) {
        flb_sds_destroy(auth);
        snprintf(ctx->last_error, sizeof(ctx->last_error), "could not connect to %s:%d",
                 ctx->host, ctx->port);
        return FLB_GCS_REQ_TRANSIENT;
    }

    r->client = flb_http_client(r->conn, FLB_HTTP_GET, uri, NULL, 0,
                                ctx->host, ctx->port, NULL, 0);
    if (!r->client) {
        flb_sds_destroy(auth);
        gcs_response_release(r);
        snprintf(ctx->last_error, sizeof(ctx->last_error), "could not create the request");
        return FLB_GCS_REQ_TRANSIENT;
    }

    /* the minimum accepted by the client is its default buffer size */
    if (limit < FLB_HTTP_DATA_SIZE_MAX) {
        limit = FLB_HTTP_DATA_SIZE_MAX;
    }
    ret = flb_http_buffer_size(r->client, limit);
    if (ret == -1) {
        flb_sds_destroy(auth);
        gcs_response_release(r);
        snprintf(ctx->last_error, sizeof(ctx->last_error), "invalid response buffer size");
        return FLB_GCS_REQ_ERROR;
    }

    flb_http_add_header(r->client, "Authorization", 13, auth, flb_sds_len(auth));
    flb_http_add_header(r->client, "User-Agent", 10, "Fluent-Bit", 10);
    flb_sds_destroy(auth);

    ret = flb_http_do(r->client, &b_sent);
    if (ret != 0) {
        gcs_response_release(r);
        snprintf(ctx->last_error, sizeof(ctx->last_error),
                 "request to %s:%d failed (connection error or response too large)",
                 ctx->host, ctx->port);
        return FLB_GCS_REQ_TRANSIENT;
    }

    r->status = r->client->resp.status;
    if (r->status == 200) {
        return FLB_GCS_REQ_OK;
    }

    gcs_set_error(ctx, r);
    flb_plg_debug(ctx->ins, "request failed: %s", ctx->last_error);

    if (r->status == 401) {
        return FLB_GCS_REQ_UNAUTHORIZED;
    }
    if (r->status == 403) {
        return FLB_GCS_REQ_FORBIDDEN;
    }
    if (r->status == 404) {
        return FLB_GCS_REQ_NOT_FOUND;
    }
    if (r->status == 429 || r->status >= 500) {
        return FLB_GCS_REQ_TRANSIENT;
    }
    return FLB_GCS_REQ_ERROR;
}

static int gcs_obj_get_string(const msgpack_object *map, const char *key, flb_sds_t *out)
{
    uint32_t i;
    char tmp[32];
    const msgpack_object_kv *kv;

    for (i = 0; i < map->via.map.size; i++) {
        kv = &map->via.map.ptr[i];
        if (kv->key.type != MSGPACK_OBJECT_STR ||
            kv->key.via.str.size != strlen(key) ||
            strncmp(kv->key.via.str.ptr, key, kv->key.via.str.size) != 0) {
            continue;
        }

        if (kv->val.type == MSGPACK_OBJECT_STR) {
            *out = flb_sds_create_len(kv->val.via.str.ptr, kv->val.via.str.size);
        }
        else if (kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            snprintf(tmp, sizeof(tmp), "%" PRIu64, (uint64_t) kv->val.via.u64);
            *out = flb_sds_create(tmp);
        }
        else {
            return 0;
        }
        return *out ? 1 : -1;
    }

    return 0;
}

/* Parse the JSON of an objects.list response into the items of the context */
static int gcs_parse_listing(struct flb_in_gcs *ctx, const char *body, size_t len)
{
    int ret;
    int root_type;
    int found;
    uint32_t i;
    size_t off = 0;
    size_t out_size = 0;
    char *out_buf = NULL;
    flb_sds_t size_str;
    flb_sds_t next_token = NULL;
    msgpack_unpacked result;
    const msgpack_object *root;
    const msgpack_object *items = NULL;
    const msgpack_object *entry;
    const msgpack_object_kv *kv;
    struct gcs_item *list = NULL;
    int count = 0;

    ret = flb_pack_json(body, len, &out_buf, &out_size, &root_type, NULL);
    if (ret != 0) {
        snprintf(ctx->last_error, sizeof(ctx->last_error), "invalid JSON in the listing");
        return -1;
    }

    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, out_buf, out_size, &off) != MSGPACK_UNPACK_SUCCESS ||
        result.data.type != MSGPACK_OBJECT_MAP) {
        snprintf(ctx->last_error, sizeof(ctx->last_error), "unexpected listing format");
        goto error;
    }
    root = &result.data;

    for (i = 0; i < root->via.map.size; i++) {
        kv = &root->via.map.ptr[i];
        if (kv->key.type != MSGPACK_OBJECT_STR) {
            continue;
        }
        if (kv->key.via.str.size == 5 && strncmp(kv->key.via.str.ptr, "items", 5) == 0 &&
            kv->val.type == MSGPACK_OBJECT_ARRAY) {
            items = &kv->val;
        }
    }

    ret = gcs_obj_get_string(root, "nextPageToken", &next_token);
    if (ret == -1) {
        goto error;
    }

    if (items && items->via.array.size > 0) {
        list = flb_calloc(items->via.array.size, sizeof(struct gcs_item));
        if (!list) {
            flb_errno();
            goto error;
        }

        for (i = 0; i < items->via.array.size; i++) {
            entry = &items->via.array.ptr[i];
            if (entry->type != MSGPACK_OBJECT_MAP) {
                continue;
            }

            found = gcs_obj_get_string(entry, "name", &list[count].name);
            if (found == -1) {
                count++;
                goto error;
            }
            if (found != 1) {
                continue;
            }
            list[count].generation = NULL;
            found = gcs_obj_get_string(entry, "generation", &list[count].generation);
            if (found == -1) {
                count++;
                goto error;
            }
            if (!list[count].generation) {
                list[count].generation = flb_sds_create("");
            }

            size_str = NULL;
            found = gcs_obj_get_string(entry, "size", &size_str);
            if (found == 1) {
                list[count].size = strtoull(size_str, NULL, 10);
                flb_sds_destroy(size_str);
            }
            else if (found == -1) {
                count++;
                goto error;
            }
            count++;
        }
    }

    in_gcs_items_destroy(ctx);
    ctx->items = list;
    ctx->items_count = count;
    ctx->items_index = 0;

    if (ctx->page_token) {
        flb_sds_destroy(ctx->page_token);
    }
    ctx->page_token = next_token;
    ctx->has_more_pages = next_token ? FLB_TRUE : FLB_FALSE;

    msgpack_unpacked_destroy(&result);
    flb_free(out_buf);
    return 0;

error:
    if (list) {
        gcs_items_free_array(list, count);
    }
    if (next_token) {
        flb_sds_destroy(next_token);
    }
    msgpack_unpacked_destroy(&result);
    flb_free(out_buf);
    return -1;
}

/* Fetch the page of the listing identified by ctx->page_token */
int in_gcs_list_page(struct flb_in_gcs *ctx)
{
    int ret;
    flb_sds_t uri;
    flb_sds_t bucket;
    flb_sds_t tmp;
    size_t limit;
    char max[32];
    struct gcs_response r;

    ctx->last_error[0] = '\0';
    bucket = in_gcs_uri_encode(ctx->bucket, flb_sds_len(ctx->bucket));
    if (!bucket) {
        return FLB_GCS_REQ_ERROR;
    }

    uri = flb_sds_create_size(256);
    if (!uri) {
        flb_sds_destroy(bucket);
        return FLB_GCS_REQ_ERROR;
    }
    tmp = flb_sds_printf(&uri, "%s/storage/v1/b/%s/o", ctx->base_path, bucket);
    flb_sds_destroy(bucket);
    if (!tmp) {
        flb_sds_destroy(uri);
        return FLB_GCS_REQ_ERROR;
    }
    uri = tmp;

    ret = 0;
    if (ctx->prefix) {
        ret |= gcs_uri_add_param(&uri, "prefix", ctx->prefix, flb_sds_len(ctx->prefix));
    }
    if (ctx->start_offset) {
        ret |= gcs_uri_add_param(&uri, "startOffset", ctx->start_offset,
                                 flb_sds_len(ctx->start_offset));
    }
    if (ctx->end_offset) {
        ret |= gcs_uri_add_param(&uri, "endOffset", ctx->end_offset,
                                 flb_sds_len(ctx->end_offset));
    }
    if (ctx->page_token) {
        ret |= gcs_uri_add_param(&uri, "pageToken", ctx->page_token,
                                 flb_sds_len(ctx->page_token));
    }
    snprintf(max, sizeof(max), "%d", ctx->page_size);
    ret |= gcs_uri_add_param(&uri, "maxResults", max, strlen(max));
    /* only the metadata that is used: keeps the pages small */
    ret |= gcs_uri_add_param(&uri, "fields", "nextPageToken,items(name,generation,size)",
                             strlen("nextPageToken,items(name,generation,size)"));
    if (ret != 0) {
        flb_sds_destroy(uri);
        return FLB_GCS_REQ_ERROR;
    }

    /*
     * Worst case of a page entry: a name of 1024 bytes where every byte is escaped as
     * \u00XX (6 bytes) plus the other fields. Clamp instead of overflowing.
     */
    if ((size_t) ctx->page_size > (SIZE_MAX - 65536) / FLB_GCS_LIST_ENTRY_MAX) {
        limit = SIZE_MAX;
    }
    else {
        limit = ((size_t) ctx->page_size * FLB_GCS_LIST_ENTRY_MAX) + 65536;
    }

    ret = gcs_get(ctx, uri, limit, &r);
    flb_sds_destroy(uri);
    if (ret != FLB_GCS_REQ_OK) {
        gcs_response_release(&r);
        return ret;
    }

    ret = gcs_parse_listing(ctx, r.client->resp.payload, r.client->resp.payload_size);
    gcs_response_release(&r);
    if (ret == -1) {
        return FLB_GCS_REQ_ERROR;
    }
    return FLB_GCS_REQ_OK;
}

static int gcs_is_gzip(struct flb_in_gcs *ctx, const char *data, size_t len)
{
    if (ctx->compression == FLB_GCS_COMPRESSION_GZIP) {
        return FLB_TRUE;
    }
    if (ctx->compression == FLB_GCS_COMPRESSION_AUTO && len >= 2 &&
        (unsigned char) data[0] == 0x1f && (unsigned char) data[1] == 0x8b) {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

/* Download ctx->current into ctx->buf (decompressed when needed) */
int in_gcs_download_object(struct flb_in_gcs *ctx)
{
    int ret;
    flb_sds_t uri;
    flb_sds_t bucket;
    flb_sds_t name;
    flb_sds_t tmp;
    void *out = NULL;
    size_t out_size = 0;
    struct gcs_response r;
    const char *payload;
    size_t payload_size;

    memset(&r, 0, sizeof(r));
    ctx->last_error[0] = '\0';
    bucket = in_gcs_uri_encode(ctx->bucket, flb_sds_len(ctx->bucket));
    name = in_gcs_uri_encode(ctx->current.name, flb_sds_len(ctx->current.name));
    uri = flb_sds_create_size(256);
    if (!bucket || !name || !uri) {
        ret = FLB_GCS_REQ_ERROR;
        goto cleanup_uri;
    }

    tmp = flb_sds_printf(&uri, "%s/storage/v1/b/%s/o/%s", ctx->base_path, bucket, name);
    if (!tmp) {
        ret = FLB_GCS_REQ_ERROR;
        goto cleanup_uri;
    }
    uri = tmp;

    ret = gcs_uri_add_param(&uri, "alt", "media", 5);
    if (ret == 0 && flb_sds_len(ctx->current.generation) > 0) {
        ret = gcs_uri_add_param(&uri, "generation", ctx->current.generation,
                                flb_sds_len(ctx->current.generation));
    }
    if (ret != 0) {
        ret = FLB_GCS_REQ_ERROR;
        goto cleanup_uri;
    }

    /* the buffer also holds the HTTP headers */
    ret = gcs_get(ctx, uri, ctx->max_object_size + FLB_GCS_HEADERS_ROOM, &r);

cleanup_uri:
    if (bucket) {
        flb_sds_destroy(bucket);
    }
    if (name) {
        flb_sds_destroy(name);
    }
    if (uri) {
        flb_sds_destroy(uri);
    }
    if (ret != FLB_GCS_REQ_OK) {
        if (ret == FLB_GCS_REQ_ERROR && r.client == NULL && ctx->last_error[0] == '\0') {
            snprintf(ctx->last_error, sizeof(ctx->last_error), "could not build the request");
        }
        gcs_response_release(&r);
        return ret;
    }

    payload = r.client->resp.payload;
    payload_size = r.client->resp.payload_size;

    if (payload_size > ctx->max_object_size) {
        snprintf(ctx->last_error, sizeof(ctx->last_error),
                 "object content (%zu bytes) exceeds 'max_object_size' (%zu)",
                 payload_size, ctx->max_object_size);
        gcs_response_release(&r);
        return FLB_GCS_REQ_ERROR;
    }

    if (payload_size > 0 && gcs_is_gzip(ctx, payload, payload_size) == FLB_TRUE) {
        ret = flb_decompress_buffer(FLB_COMPRESSION_ALGORITHM_GZIP, (void *) payload,
                                    payload_size, ctx->max_object_size, &out, &out_size);
        gcs_response_release(&r);
        if (ret != FLB_DECOMPRESSOR_SUCCESS) {
            snprintf(ctx->last_error, sizeof(ctx->last_error),
                     "cannot decompress the object (corrupt gzip data or content bigger "
                     "than 'max_object_size'), code=%d", ret);
            return FLB_GCS_REQ_ERROR;
        }
        ctx->buf = out;
        ctx->buf_len = out_size;
    }
    else {
        if (payload_size > 0) {
            ctx->buf = flb_malloc(payload_size);
            if (!ctx->buf) {
                flb_errno();
                gcs_response_release(&r);
                snprintf(ctx->last_error, sizeof(ctx->last_error), "out of memory");
                return FLB_GCS_REQ_ERROR;
            }
            memcpy(ctx->buf, payload, payload_size);
        }
        ctx->buf_len = payload_size;
        gcs_response_release(&r);
    }
    ctx->buf_off = 0;

    ctx->tag = in_gcs_tag_from_name(ctx, ctx->current.name, flb_sds_len(ctx->current.name));
    return FLB_GCS_REQ_OK;
}
