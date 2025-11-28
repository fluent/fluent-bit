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
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_sqldb.h>
#include <fluent-bit/flb_input_blob.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_notification.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_record_accessor.h>

#include <msgpack.h>
#include <string.h>

#include "azure_blob.h"
#include "azure_blob_db.h"
#include "azure_blob_uri.h"
#include "azure_blob_conf.h"
#include "azure_blob_appendblob.h"
#include "azure_blob_blockblob.h"
#include "azure_blob_http.h"
#include "azure_blob_store.h"

#define CREATE_BLOB  1337
#define AZB_UUID_PLACEHOLDER "$UUID"

/* thread_local_storage for workers */

struct worker_info {
    int active_upload;
};

FLB_TLS_DEFINE(struct worker_info, worker_info);

static int create_blob(struct flb_azure_blob *ctx, const char *path_prefix, char *name);

static int azure_blob_format(struct flb_config *config,
                             struct flb_input_instance *ins,
                             void *plugin_context,
                             void *flush_ctx,
                             int event_type,
                             const char *tag, int tag_len,
                             const void *data, size_t bytes,
                             void **out_data, size_t *out_size)
{
    flb_sds_t out_buf;
    struct flb_azure_blob *ctx = plugin_context;

    out_buf = flb_pack_msgpack_to_json_format(data, bytes,
                                              FLB_PACK_JSON_FORMAT_LINES,
                                              FLB_PACK_JSON_DATE_ISO8601,
                                              ctx->date_key,
                                              config->json_escape_unicode);
    if (!out_buf) {
        return -1;
    }

    *out_data = out_buf;
    *out_size = flb_sds_len(out_buf);
    return 0;
}

/*
 * Either new_data or chunk can be NULL, but not both
 */
static int construct_request_buffer(struct flb_azure_blob *ctx, flb_sds_t new_data,
                                    struct azure_blob_file *upload_file,
                                    char **out_buf, size_t *out_size)
{
    char *body;
    char *tmp;
    size_t body_size = 0;
    char *buffered_data = NULL;
    size_t buffer_size = 0;
    int ret;

    if (new_data == NULL && upload_file == NULL) {
        flb_plg_error(ctx->ins, "[construct_request_buffer] Something went wrong"
                                " both chunk and new_data are NULL");
        return -1;
    }

    if (upload_file) {
        ret = azure_blob_store_file_upload_read(ctx, upload_file->fsf, &buffered_data, &buffer_size);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Could not read locally buffered data %s",
                          upload_file->fsf->name);
            return -1;
        }

        /*
         * lock the upload_file from buffer list
         */
        azure_blob_store_file_lock(upload_file);
        body = buffered_data;
        body_size = buffer_size;
    }

    flb_plg_debug(ctx->ins, "[construct_request_buffer] size of buffer file read %zu", buffer_size);

    /*
     * If new data is arriving, increase the original 'buffered_data' size
     * to append the new one.
     */
    if (new_data) {
        body_size += flb_sds_len(new_data);
        flb_plg_debug(ctx->ins, "[construct_request_buffer] size of new_data %zu", body_size);

        tmp = flb_realloc(buffered_data, body_size + 1);
        if (!tmp) {
            flb_errno();
            flb_free(buffered_data);
            if (upload_file) {
                azure_blob_store_file_unlock(upload_file);
            }
            return -1;
        }
        body = buffered_data = tmp;
        memcpy(body + buffer_size, new_data, flb_sds_len(new_data));
        if (ctx->compress_gzip == FLB_FALSE){
            body[body_size] = '\0';
        }
    }

    flb_plg_debug(ctx->ins, "[construct_request_buffer] final increased %zu", body_size);

    *out_buf = body;
    *out_size = body_size;

    return 0;
}

/**
 * Populate the provided buffer with pseudo-random alphanumeric characters.
 * The buffer must have room for `length + 1` bytes to include the terminator.
 */
void generate_random_string_blob(char *str, size_t length)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const size_t charset_size = sizeof(charset) - 1;
    size_t i;
    size_t index;

    /* Seed the random number generator with multiple sources of entropy */
    unsigned int seed = (unsigned int)(time(NULL) ^ clock() ^ getpid());
    srand(seed);

    for (i = 0; i < length; ++i) {
        index = (size_t)rand() % charset_size;
        str[i] = charset[index];
    }

    str[length] = '\0';
}

/**
 * Replace all "$UUID" placeholders in the path with the same random suffix.
 * Returns a newly allocated SDS string and frees the original `path` value.
 */
static flb_sds_t azb_replace_uuid(flb_sds_t path)
{
    char random_buf[9] = {0};
    const size_t token_len = strlen(AZB_UUID_PLACEHOLDER);
    size_t occurrences = 0;
    size_t path_len;
    size_t result_len;
    char *cursor;
    char *match;
    char *dst;
    flb_sds_t result;

    if (!path) {
        return NULL;
    }

    cursor = path;
    while ((match = strstr(cursor, AZB_UUID_PLACEHOLDER)) != NULL) {
        occurrences++;
        cursor = match + token_len;
    }

    if (occurrences == 0) {
        return path;
    }

    generate_random_string_blob(random_buf, 8);

    path_len = flb_sds_len(path);
    result_len = path_len + occurrences * (8 - token_len);

    result = flb_sds_create_size(result_len + 1);
    if (!result) {
        flb_errno();
        flb_sds_destroy(path);
        return NULL;
    }

    dst = result;
    cursor = path;
    while ((match = strstr(cursor, AZB_UUID_PLACEHOLDER)) != NULL) {
        size_t segment_len;

        segment_len = (size_t)(match - cursor);
        if (segment_len > 0) {
            memcpy(dst, cursor, segment_len);
            dst += segment_len;
        }

        memcpy(dst, random_buf, 8);
        dst += 8;

        cursor = match + token_len;
    }

    if (cursor < path + path_len) {
        size_t tail_len;

        tail_len = (size_t)((path + path_len) - cursor);
        if (tail_len > 0) {
            memcpy(dst, cursor, tail_len);
            dst += tail_len;
        }
    }

    *dst = '\0';
    flb_sds_len_set(result, result_len);

    flb_sds_destroy(path);
    return result;
}

/**
 * Replace the first occurrence of `token` with `replacement` in the SDS input.
 * The original string is destroyed and a new SDS instance is returned.
 */
static flb_sds_t azb_simple_replace(flb_sds_t input,
                                    const char *token,
                                    const char *replacement)
{
    char *pos;
    size_t token_len;
    size_t replace_len;
    size_t prefix_len;
    size_t suffix_len;
    flb_sds_t result;

    if (!input || !token) {
        return input;
    }

    pos = strstr(input, token);
    if (!pos) {
        return input;
    }

    token_len = strlen(token);
    replace_len = strlen(replacement);
    prefix_len = (size_t)(pos - input);
    suffix_len = flb_sds_len(input) - prefix_len - token_len;

    result = flb_sds_create_size(prefix_len + replace_len + suffix_len + 1);
    if (!result) {
        flb_errno();
        flb_sds_destroy(input);
        return NULL;
    }

    if (prefix_len > 0) {
        memcpy(result, input, prefix_len);
    }
    if (replace_len > 0) {
        memcpy(result + prefix_len, replacement, replace_len);
    }
    if (suffix_len > 0) {
        memcpy(result + prefix_len + replace_len, pos + token_len, suffix_len);
    }
    result[prefix_len + replace_len + suffix_len] = '\0';
    flb_sds_len_set(result, prefix_len + replace_len + suffix_len);

    flb_sds_destroy(input);
    return result;
}

/**
 * Expand millisecond and nanosecond custom tokens within the blob path.
 */
static flb_sds_t azb_apply_time_tokens(flb_sds_t path, const struct flb_time *timestamp)
{
    char ms_buf[4];
    char ns_buf[10];
    flb_sds_t tmp;

    if (!path || !timestamp) {
        return path;
    }

    snprintf(ms_buf, sizeof(ms_buf), "%03lu",
             (unsigned long)(timestamp->tm.tv_nsec / 1000000));
    snprintf(ns_buf, sizeof(ns_buf), "%09lu",
             (unsigned long)timestamp->tm.tv_nsec);

    /* Replace %3N with milliseconds */
    tmp = azb_simple_replace(path, "%3N", ms_buf);
    if (!tmp) {
        return NULL;
    }
    path = tmp;

    /* Replace %9N with nanoseconds */
    tmp = azb_simple_replace(path, "%9N", ns_buf);
    if (!tmp) {
        return NULL;
    }
    path = tmp;

    /* Replace %L with nanoseconds */
    tmp = azb_simple_replace(path, "%L", ns_buf);
    if (!tmp) {
        return NULL;
    }

    return tmp;
}

/**
 * Apply `strftime` formatting using the provided event timestamp.
 */
static flb_sds_t azb_apply_strftime(flb_sds_t path, const struct flb_time *timestamp)
{
    struct flb_time now;
    const struct flb_time *ref;
    struct tm tm_utc;
    time_t seconds;
    size_t path_len;
    size_t empty_threshold;
    size_t buf_size;
    size_t out_len;
    char *buf;
    char *tmp_buf;
    flb_sds_t result;

    if (!path) {
        return NULL;
    }

    if (timestamp) {
        ref = timestamp;
    }
    else {
        flb_time_get(&now);
        ref = &now;
    }

    seconds = ref->tm.tv_sec;
    if (!gmtime_r(&seconds, &tm_utc)) {
        flb_sds_destroy(path);
        return NULL;
    }

    path_len = flb_sds_len(path);
    empty_threshold = path_len > 0 ? path_len * 2 : 2;
    buf_size = path_len + 64;
    buf = flb_malloc(buf_size + 1);
    if (!buf) {
        flb_errno();
        flb_sds_destroy(path);
        return NULL;
    }

    buf[0] = '\0';

    while (1) {
        out_len = strftime(buf, buf_size + 1, path, &tm_utc);
        if (out_len > 0) {
            break;
        }

        if (buf_size > empty_threshold) {
            break;
        }

        if (buf_size > 4096) {
            break;
        }

        buf_size *= 2;
        tmp_buf = flb_realloc(buf, buf_size + 1);
        if (!tmp_buf) {
            flb_errno();
            flb_free(buf);
            flb_sds_destroy(path);
            return NULL;
        }
        buf = tmp_buf;
    }

    result = flb_sds_create_len(buf, out_len);
    if (!result) {
        flb_errno();
        flb_free(buf);
        flb_sds_destroy(path);
        return NULL;
    }

    flb_free(buf);
    flb_sds_destroy(path);

    return result;
}

/**
 * Remove leading and trailing slashes to avoid double separators in URIs.
 */
static void azb_trim_slashes(flb_sds_t path)
{
    size_t len;
    size_t start = 0;
    char *buf;

    if (!path) {
        return;
    }

    buf = path;
    len = flb_sds_len(path);

    while (start < len && buf[start] == '/') {
        start++;
    }

    if (start > 0) {
        memmove(buf, buf + start, len - start + 1);
        len -= start;
        flb_sds_len_set(path, len);
    }

    while (len > 0 && buf[len - 1] == '/') {
        len--;
    }
    buf[len] = '\0';
    flb_sds_len_set(path, len);
}

/**
 * Build the final blob path by applying record accessors and time templating.
 */
int azb_resolve_path(struct flb_azure_blob *ctx,
                     const char *tag,
                     int tag_len,
                     const struct flb_time *timestamp,
                     flb_sds_t *out_path)
{
    flb_sds_t path;
    struct flb_time now;
    msgpack_sbuffer sbuf;
    msgpack_packer pk;
    msgpack_unpacked result;
    msgpack_object root;
    struct flb_record_accessor *temp_ra;
    flb_sds_t expanded;

    if (!out_path) {
        return -1;
    }

    *out_path = NULL;

    if (!ctx->path_templating_enabled) {
        return 0;
    }

    if (!timestamp) {
        flb_time_get(&now);
        timestamp = &now;
    }

    /* Start with the original path template */
    path = flb_sds_create_len(ctx->path, flb_sds_len(ctx->path));
    if (!path) {
        flb_errno();
        return -1;
    }

    /* Apply UUID replacement before record accessor step.
     * Unknown $ tokens get stripped otherwise.
     */
    path = azb_replace_uuid(path);
    if (!path) {
        return -1;
    }

    /* Apply time tokens (%3N, %9N, %L) */
    path = azb_apply_time_tokens(path, timestamp);
    if (!path) {
        return -1;
    }

    /* Apply strftime */
    path = azb_apply_strftime(path, timestamp);
    if (!path) {
        return -1;
    }

    /* Now use record accessor to expand $TAG and $TAG[n] */
    /* Create empty msgpack map for record accessor */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&pk, 0);

    /* Unpack to get msgpack_object */
    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result,
                            sbuf.data,
                            sbuf.size,
                            NULL) != MSGPACK_UNPACK_SUCCESS) {
        msgpack_sbuffer_destroy(&sbuf);
        msgpack_unpacked_destroy(&result);
        flb_sds_destroy(path);
        return -1;
    }
    root = result.data;

    /* Create a temporary record accessor for the partially-processed path */
    temp_ra = flb_ra_create(path, FLB_TRUE);
    if (!temp_ra) {
        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&sbuf);
        flb_sds_destroy(path);
        return -1;
    }

    /* Use record accessor to expand $TAG and $TAG[n] */
    expanded = flb_ra_translate(temp_ra, (char *)tag, tag_len, root, NULL);

    flb_ra_destroy(temp_ra);
    msgpack_unpacked_destroy(&result);
    msgpack_sbuffer_destroy(&sbuf);
    flb_sds_destroy(path);

    if (!expanded) {
        return -1;
    }

    azb_trim_slashes(expanded);

    if (flb_sds_len(expanded) == 0) {
        flb_sds_destroy(expanded);
        return 0;
    }

    *out_path = expanded;
    return 0;
}

static int azb_create_blob_with_tag(struct flb_azure_blob *ctx,
                                    const char *tag,
                                    int tag_len,
                                    const char *blob_name)
{
    flb_sds_t prefix = NULL;
    int ret;

    if (azb_resolve_path(ctx, tag, tag_len, NULL, &prefix) != 0) {
        if (prefix) {
            flb_sds_destroy(prefix);
        }
        return FLB_RETRY;
    }

    ret = create_blob(ctx, prefix, (char *) blob_name);

    if (prefix) {
        flb_sds_destroy(prefix);
    }

    return ret;
}

static int create_blob(struct flb_azure_blob *ctx, const char *path_prefix, char *name)
{
    int ret;
    size_t b_sent;
    flb_sds_t uri = NULL;
    struct flb_http_client *c;
    struct flb_connection *u_conn;

    uri = azb_uri_create_blob(ctx, path_prefix, name);
    if (!uri) {
        return FLB_RETRY;
    }

    if (ctx->buffering_enabled == FLB_TRUE){
        ctx->u->base.flags &= ~(FLB_IO_ASYNC);
        ctx->u->base.net.io_timeout = ctx->io_timeout;
    }

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins,
                      "cannot create upstream connection for create_append_blob");
        flb_sds_destroy(uri);
        return FLB_RETRY;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_PUT,
                        uri,
                        NULL, 0, NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(uri);
        return FLB_RETRY;
    }

    /* Prepare headers and authentication */
    azb_http_client_setup(ctx, c, -1, FLB_TRUE,
                          AZURE_BLOB_CT_NONE, AZURE_BLOB_CE_NONE);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);
    flb_sds_destroy(uri);

    if (ret == -1) {
        flb_plg_error(ctx->ins, "error sending append_blob");
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return FLB_RETRY;
    }

    if (c->resp.status == 201) {
        /* delete "&sig=..." in the c->uri for security */
        char *p = strstr(c->uri, "&sig=");
        if (p) {
            *p = '\0';
        }
        flb_plg_info(ctx->ins, "blob created successfully: %s", c->uri);
    }
    else {
        if (c->resp.payload_size > 0) {
            flb_plg_error(ctx->ins, "http_status=%i cannot create append blob\n%s",
                          c->resp.status, c->resp.payload);
        }
        else {
            flb_plg_error(ctx->ins, "http_status=%i cannot create append blob",
                          c->resp.status);
        }
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return FLB_RETRY;
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);
    return FLB_OK;
}

static int delete_blob(struct flb_azure_blob *ctx, char *name)
{
    int ret;
    size_t b_sent;
    flb_sds_t uri = NULL;
    struct flb_http_client *c;
    struct flb_connection *u_conn;

    uri = azb_uri_create_blob(ctx, NULL, name);
    if (!uri) {
        return FLB_RETRY;
    }

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins,
                      "cannot create upstream connection for create_append_blob");
        flb_sds_destroy(uri);
        return FLB_RETRY;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_DELETE,
                        uri,
                        NULL, 0, NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(uri);
        return FLB_RETRY;
    }

    /* Prepare headers and authentication */
    azb_http_client_setup(ctx, c, -1, FLB_TRUE,
                          AZURE_BLOB_CT_NONE, AZURE_BLOB_CE_NONE);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);
    flb_sds_destroy(uri);

    if (ret == -1) {
        flb_plg_error(ctx->ins, "error sending append_blob");
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return FLB_RETRY;
    }

    if (c->resp.status == 201) {
        /* delete "&sig=..." in the c->uri for security */
        char *p = strstr(c->uri, "&sig=");
        if (p) {
            *p = '\0';
        }
        flb_plg_info(ctx->ins, "blob deleted successfully: %s", c->uri);
    }
    else {
        if (c->resp.payload_size > 0) {
            flb_plg_error(ctx->ins, "http_status=%i cannot delete append blob\n%s",
                          c->resp.status, c->resp.payload);
        }
        else {
            flb_plg_error(ctx->ins, "http_status=%i cannot delete append blob",
                          c->resp.status);
        }
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return FLB_RETRY;
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);
    return FLB_OK;
}

static int http_send_blob(struct flb_config *config, struct flb_azure_blob *ctx,
                          flb_sds_t ref_name,
                          flb_sds_t uri,
                          flb_sds_t block_id,
                          int event_type,
                          void *data, size_t bytes)
{
    int ret;
    int compressed = FLB_FALSE;
    int content_encoding = FLB_FALSE;
    int content_type = FLB_FALSE;
    size_t b_sent;
    void *payload_buf;
    size_t payload_size;
    struct flb_http_client *c;
    struct flb_connection *u_conn;

    flb_plg_debug(ctx->ins, "generated blob uri ::: %s", uri);

    if (ctx->buffering_enabled == FLB_TRUE){
        ctx->u->base.flags &= ~(FLB_IO_ASYNC);
        ctx->u->base.net.io_timeout = ctx->io_timeout;
    }

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins,
                      "cannot create TCP upstream connection");
        return FLB_RETRY;
    }

    payload_buf = data;
    payload_size = bytes;

    /* Handle compression requests */
    if (ctx->compress_gzip == FLB_TRUE || ctx->compress_blob == FLB_TRUE) {
        ret = flb_gzip_compress((void *) data, bytes, &payload_buf, &payload_size);
        if (ret == 0) {
            compressed = FLB_TRUE;
        }
        else {
            flb_plg_warn(ctx->ins,
                        "cannot gzip payload, disabling compression");
            payload_buf = data;
            payload_size = bytes;
        }
    }

    /* set http header flags */
    if (ctx->compress_blob == FLB_TRUE) {
        content_encoding = AZURE_BLOB_CE_NONE;
        content_type = AZURE_BLOB_CT_GZIP;
    }
    else if (compressed == FLB_TRUE) {
        content_encoding = AZURE_BLOB_CE_GZIP;
        content_type = AZURE_BLOB_CT_JSON;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_PUT,
                        uri,
                        payload_buf, payload_size, NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        if (compressed == FLB_TRUE) {
            flb_free(payload_buf);
        }
        flb_upstream_conn_release(u_conn);
        return FLB_RETRY;
    }

    /* Prepare headers and authentication */
    azb_http_client_setup(ctx, c, (ssize_t) payload_size, FLB_FALSE,
                          content_type, content_encoding);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);

    /* Release compressed buffer */
    if (compressed == FLB_TRUE) {
        flb_free(payload_buf);
    }

    flb_upstream_conn_release(u_conn);

    /* Validate HTTP status */
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error sending append_blob for %s", ref_name);
        return FLB_RETRY;
    }

    if (c->resp.status == 201) {
        flb_plg_info(ctx->ins, "content uploaded successfully: %s", ref_name);
        flb_http_client_destroy(c);
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
        return CREATE_BLOB;
    }
    else if (c->resp.payload_size > 0) {
        flb_plg_error(ctx->ins, "http_status=%i cannot append content to blob\n%s",
                      c->resp.status, c->resp.payload);
        if (strstr(c->resp.payload, "must be 0 for Create Append")) {
            flb_http_client_destroy(c);
            return CREATE_BLOB;
        }
    }
    else {
        flb_plg_error(ctx->ins, "cannot upload %s content to blob (http_status=%i)",
                      ref_name, c->resp.status);
    }
    flb_http_client_destroy(c);

    return FLB_RETRY;
}

static int send_blob(struct flb_config *config,
                     struct flb_input_instance *i_ins,
                     struct flb_azure_blob *ctx,
                     int event_type,
                     int blob_type, char *name, uint64_t part_id,
                     char *tag, int tag_len, void *data, size_t bytes)
{
    int ret;
    uint64_t ms = 0;
    flb_sds_t uri = NULL;
    flb_sds_t block_id = NULL;
    flb_sds_t ref_name = NULL;
    flb_sds_t path_prefix = NULL;
    void *payload_buf = data;
    size_t payload_size = bytes;
    char *generated_random_string;
    struct flb_time now;

    flb_time_get(&now);

    if (azb_resolve_path(ctx, tag, tag_len, &now, &path_prefix) != 0) {
        return FLB_RETRY;
    }

    ref_name = flb_sds_create_size(256);
    if (!ref_name) {
        if (path_prefix) {
            flb_sds_destroy(path_prefix);
        }
        return FLB_RETRY;
    }

    /* Allocate memory for the random string dynamically */
    generated_random_string = flb_malloc(ctx->blob_uri_length + 1);
    if (!generated_random_string) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot allocate memory for random string");
        flb_sds_destroy(ref_name);
        if (path_prefix) {
            flb_sds_destroy(path_prefix);
        }
        return FLB_RETRY;
    }

    if (blob_type == AZURE_BLOB_APPENDBLOB) {
        uri = azb_append_blob_uri(ctx, path_prefix, tag);
    }
    else if (blob_type == AZURE_BLOB_BLOCKBLOB) {
        generate_random_string_blob(generated_random_string, ctx->blob_uri_length); /* Generate the random string */
        if (event_type == FLB_EVENT_TYPE_LOGS) {
            block_id = azb_block_blob_id_logs(&ms);
            if (!block_id) {
                flb_plg_error(ctx->ins, "could not generate block id");
                flb_free(generated_random_string);
                flb_sds_destroy(ref_name);
                if (path_prefix) {
                    flb_sds_destroy(path_prefix);
                }
                return FLB_RETRY;
            }
            uri = azb_block_blob_uri(ctx, path_prefix, tag,
                                     block_id, ms, generated_random_string);
            ref_name = flb_sds_printf(&ref_name, "file=%s.%" PRIu64, name, ms);
        }
        else if (event_type == FLB_EVENT_TYPE_BLOBS) {
            block_id = azb_block_blob_id_blob(ctx, name, part_id);
            uri = azb_block_blob_uri(ctx, path_prefix, name,
                                     block_id, 0, generated_random_string);
            ref_name = flb_sds_printf(&ref_name, "file=%s:%" PRIu64, name, part_id);
        }
    }

    if (!uri) {
        flb_free(generated_random_string);
        if (block_id != NULL) {
            flb_free(block_id);
        }
        flb_sds_destroy(ref_name);
        if (path_prefix) {
            flb_sds_destroy(path_prefix);
        }
        return FLB_RETRY;
    }

    /* Map buffer */
    payload_buf = data;
    payload_size = bytes;

    ret = http_send_blob(config, ctx, ref_name, uri, block_id, event_type, payload_buf, payload_size);
    flb_plg_debug(ctx->ins, "http_send_blob()=%i", ret);

    if (ret == FLB_OK) {
        /* For Logs type, we need to commit the block right away */
        if (event_type == FLB_EVENT_TYPE_LOGS) {
            ret = azb_block_blob_commit_block(ctx, path_prefix, block_id,
                                              tag, ms, generated_random_string);
        }
    }
    else if (ret == CREATE_BLOB) {
        ret = create_blob(ctx, path_prefix, name);
        if (ret == FLB_OK) {
            ret = http_send_blob(config, ctx, ref_name, uri, block_id, event_type, payload_buf, payload_size);
        }
    }
    flb_sds_destroy(ref_name);

    if (payload_buf != data) {
        flb_sds_destroy(payload_buf);
    }

    flb_sds_destroy(uri);
    flb_free(generated_random_string);

    if (block_id != NULL) {
        flb_free(block_id);
    }

    if (path_prefix) {
        flb_sds_destroy(path_prefix);
    }

    return ret;
}

static int create_container(struct flb_azure_blob *ctx, char *name)
{
    int ret;
    size_t b_sent;
    flb_sds_t uri;
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
                      "cannot create upstream connection for container creation");
        return FLB_FALSE;
    }

    /* URI */
    uri = azb_uri_ensure_or_create_container(ctx);
    if (!uri) {
        flb_upstream_conn_release(u_conn);
        return FLB_FALSE;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_PUT,
                        uri,
                        NULL, 0, NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        flb_upstream_conn_release(u_conn);
        return FLB_FALSE;
    }

    /* Prepare headers and authentication */
    azb_http_client_setup(ctx, c, -1, FLB_FALSE,
                          AZURE_BLOB_CT_NONE, AZURE_BLOB_CE_NONE);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);

    /* Release URI */
    flb_sds_destroy(uri);

    /* Validate http response */
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error requesting container creation");
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return FLB_FALSE;
    }

    if (c->resp.status == 201) {
        flb_plg_info(ctx->ins, "container '%s' created sucessfully", name);
    }
    else {
        if (c->resp.payload_size > 0) {
            flb_plg_error(ctx->ins, "cannot create container '%s'\n%s",
                          name, c->resp.payload);
        }
        else {
            flb_plg_error(ctx->ins, "cannot create container '%s'\n%s",
                          name, c->resp.payload);
        }
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        return FLB_FALSE;
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);
    return FLB_TRUE;
}

/*
 * Check that the container exists, if it doesn't and the configuration property
 * auto_create_container is enabled, it will send a request to create it. If it
 * could not be created, it returns FLB_FALSE.
 * If auto_create_container is disabled, it will return FLB_TRUE assuming the container
 * already exists.
 */
static int ensure_container(struct flb_azure_blob *ctx)
{
    int ret;
    int status;
    size_t b_sent;
    flb_sds_t uri;
    struct flb_http_client *c;
    struct flb_connection *u_conn;

    if (!ctx->auto_create_container) {
        flb_plg_info(ctx->ins, "auto_create_container is disabled, assuming container '%s' already exists",
                     ctx->container_name);
        return FLB_TRUE;
    }

    uri = azb_uri_ensure_or_create_container(ctx);
    if (!uri) {
        flb_plg_error(ctx->ins, "cannot create container URI");
        return FLB_FALSE;
    }

    if (ctx->buffering_enabled == FLB_TRUE){
        ctx->u->base.flags &= ~(FLB_IO_ASYNC);
        ctx->u->base.net.io_timeout = ctx->io_timeout;
    }

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins,
                      "cannot create upstream connection for container check");
        flb_sds_destroy(uri);
        return FLB_FALSE;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_GET,
                        uri,
                        NULL, 0, NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        flb_upstream_conn_release(u_conn);
        return FLB_FALSE;
    }
    flb_http_strip_port_from_host(c);

    /* Prepare headers and authentication */
    azb_http_client_setup(ctx, c, -1, FLB_FALSE,
                          AZURE_BLOB_CT_NONE, AZURE_BLOB_CE_NONE);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);
    flb_sds_destroy(uri);

    if (ret == -1) {
        flb_plg_error(ctx->ins, "error requesting container properties");
        flb_upstream_conn_release(u_conn);
        return FLB_FALSE;
    }

    status = c->resp.status;
    flb_http_client_destroy(c);

    /* Release connection */
    flb_upstream_conn_release(u_conn);

    /* Request was successful, validate HTTP status code */
    if (status == 404) {
        /* The container was not found, try to create it */
        flb_plg_info(ctx->ins, "container '%s' not found, trying to create it",
                     ctx->container_name);
        ret = create_container(ctx, ctx->container_name);
        return ret;
    }
    else if (status == 200) {
        flb_plg_info(ctx->ins, "container '%s' already exists", ctx->container_name);
        return FLB_TRUE;
    }
    else if (status == 403) {
        flb_plg_error(ctx->ins, "failed getting container '%s', access denied",
                      ctx->container_name);
        return FLB_FALSE;
    }
    
    flb_plg_error(ctx->ins, "get container request failed, status=%i",
                  status);

    return FLB_FALSE;
}

static int cb_azure_blob_init(struct flb_output_instance *ins,
                              struct flb_config *config, void *data)
{
    struct flb_azure_blob *ctx = NULL;
    (void) ins;
    (void) config;
    (void) data;

    FLB_TLS_INIT(worker_info);

    ctx = flb_azure_blob_conf_create(ins, config);
    if (!ctx) {
        return -1;
    }

    if (ctx->buffering_enabled == FLB_TRUE) {
        ctx->ins = ins;
        ctx->retry_time = 0;

        /* Initialize local storage */
        int ret = azure_blob_store_init(ctx);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to initialize kusto storage: %s",
                          ctx->store_dir);
            return -1;
        }

        /* validate 'total_file_size' */
        if (ctx->file_size <= 0) {
            flb_plg_error(ctx->ins, "Failed to parse upload_file_size");
            return -1;
        }
        if (ctx->file_size < 1000000) {
            flb_plg_error(ctx->ins, "upload_file_size must be at least 1MB");
            return -1;
        }
        if (ctx->file_size > MAX_FILE_SIZE) {
            flb_plg_error(ctx->ins, "Max total_file_size must be lower than %ld bytes", MAX_FILE_SIZE);
            return -1;
        }
        ctx->has_old_buffers = azure_blob_store_has_data(ctx);
        ctx->timer_created = FLB_FALSE;
        ctx->timer_ms = (int) (ctx->upload_timeout / 6) * 1000;
        flb_plg_info(ctx->ins, "Using upload size %lu bytes", ctx->file_size);
    }

    flb_output_set_context(ins, ctx);

    flb_output_set_http_debug_callbacks(ins);
    return 0;
}

static int blob_chunk_register_parts(struct flb_azure_blob *ctx, uint64_t file_id, size_t total_size)
{
    int ret;
    int64_t parts = 0;
    int64_t id;
    size_t offset_start = 0;
    size_t offset_end = 0;

    /* generate file parts */
    while (offset_start < total_size) {
        offset_end = offset_start + ctx->part_size;

        /* do not exceed maximum size */
        if (offset_end > total_size) {
            offset_end = total_size;
        }

        /* insert part */
        ret = azb_db_file_part_insert(ctx, file_id, parts, offset_start, offset_end, &id);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "cannot insert blob file part into database");
            return -1;
        }
        offset_start = offset_end;
        parts++;
    }

    return parts;
}

static int process_blob_chunk(struct flb_azure_blob *ctx, struct flb_event_chunk *event_chunk)
{
    int64_t ret;
    int64_t file_id;
    cfl_sds_t file_path = NULL;
    cfl_sds_t source = NULL;
    size_t file_size;
    msgpack_object map;

    struct flb_log_event_decoder log_decoder;
    struct flb_log_event         log_event;

    if (ctx->db == NULL) {
        flb_plg_error(ctx->ins, "Cannot process blob because this operation requires a database.");

        return -1;
    }

    ret = flb_log_event_decoder_init(&log_decoder,
                                    (char *) event_chunk->data,
                                     event_chunk->size);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                    "Log event decoder initialization error : %i", (int) ret);
        return -1;

    }

    while (flb_log_event_decoder_next(&log_decoder, &log_event) == FLB_EVENT_DECODER_SUCCESS) {
        map = *log_event.body;
        ret = flb_input_blob_file_get_info(map, &source, &file_path, &file_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "cannot get file info from blob record, skipping");
            continue;
        }

        ret = azb_db_file_insert(ctx, source, ctx->real_endpoint, file_path, file_size);

        if (ret == -1) {
            flb_plg_error(ctx->ins, "cannot insert blob file into database: %s (size=%lu)",
                          file_path, file_size);
            cfl_sds_destroy(file_path);
            cfl_sds_destroy(source);
            continue;
        }
        cfl_sds_destroy(file_path);
        cfl_sds_destroy(source);

        /* generate the parts by using the newest id created (ret) */
        file_id = ret;
        ret = blob_chunk_register_parts(ctx, file_id, file_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "cannot register blob file '%s 'parts into database",
                            file_path);
            return -1;
        }

        flb_plg_debug(ctx->ins, "blob file '%s' (id=%zu) registered with %zu parts",
                      file_path, file_id, ret);
    }

    flb_log_event_decoder_destroy(&log_decoder);
    return 0;
}

static void cb_azb_blob_file_upload(struct flb_config *config, void *out_context)
{
    int ret;
    char *out_buf = NULL;
    size_t out_size;
    uint64_t id;
    uint64_t file_id;
    uint64_t part_id;
    uint64_t part_delivery_attempts;
    uint64_t file_delivery_attempts;
    off_t offset_start;
    off_t offset_end;
    cfl_sds_t file_destination = NULL;
    cfl_sds_t file_path = NULL;
    cfl_sds_t part_ids = NULL;
    cfl_sds_t source = NULL;
    struct flb_azure_blob *ctx = out_context;
    struct worker_info *info;
    struct flb_blob_delivery_notification *notification;

    info = FLB_TLS_GET(worker_info);

    if (info->active_upload) {
        flb_plg_trace(ctx->ins, "[worker: file upload] upload already in progress...");
        flb_sched_timer_cb_coro_return();
    }

    if (ctx->db == NULL) {
        flb_sched_timer_cb_coro_return();
    }

    info->active_upload = FLB_TRUE;

    /*
     * Check if is there any file which has been fully uploaded and we need to commit it with
     * the Put Block List operation
     */

    pthread_mutex_lock(&ctx->file_upload_commit_file_parts);

    while (1) {
        ret = azb_db_file_get_next_stale(ctx,
                                         &file_id,
                                         &file_path);

        if (ret == 1) {
            delete_blob(ctx, file_path);

            azb_db_file_reset_upload_states(ctx, file_id, file_path);
            azb_db_file_set_aborted_state(ctx, file_id, file_path, 0);

            cfl_sds_destroy(file_path);

            file_path = NULL;
        }
        else {
            break;
        }
    }

    while (1) {
        ret = azb_db_file_get_next_aborted(ctx,
                                           &file_id,
                                           &file_delivery_attempts,
                                           &file_path,
                                           &source);

        if (ret == 1) {
            ret = delete_blob(ctx, file_path);

            if (ctx->file_delivery_attempt_limit != FLB_OUT_RETRY_UNLIMITED &&
                file_delivery_attempts < ctx->file_delivery_attempt_limit) {
                azb_db_file_reset_upload_states(ctx, file_id, file_path);
                azb_db_file_set_aborted_state(ctx, file_id, file_path, 0);
            }
            else {
                ret = azb_db_file_delete(ctx, file_id, file_path);

                notification = flb_calloc(1,
                                        sizeof(
                                            struct flb_blob_delivery_notification));

                if (notification != NULL) {
                    notification->base.dynamically_allocated = FLB_TRUE;
                    notification->base.notification_type = FLB_NOTIFICATION_TYPE_BLOB_DELIVERY;
                    notification->base.destructor = flb_input_blob_delivery_notification_destroy;
                    notification->success = FLB_FALSE;
                    notification->path = cfl_sds_create(file_path);

                    ret = flb_notification_enqueue(FLB_PLUGIN_INPUT,
                                                source,
                                                &notification->base,
                                                config);

                    if (ret != 0) {
                        flb_plg_error(ctx->ins,
                                    "blob file '%s' (id=%" PRIu64 ") notification " \
                                    "delivery error %d", file_path, file_id, ret);

                        flb_notification_cleanup(&notification->base);
                    }
                }
            }

            cfl_sds_destroy(file_path);
            cfl_sds_destroy(source);

            file_path = NULL;
            source = NULL;
        }
        else {
            break;
        }
    }

    ret = azb_db_file_oldest_ready(ctx, &file_id, &file_path, &part_ids, &source);
    if (ret == 0) {
        flb_plg_trace(ctx->ins, "no blob files ready to commit");
    }
    else if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot get oldest blob file ready to upload");
    }
    else if (ret == 1) {
        /* one file is ready to be committed */
        flb_plg_debug(ctx->ins, "blob file '%s' (id=%" PRIu64 ") ready to upload", file_path, file_id);
        ret = azb_block_blob_commit_file_parts(ctx, file_id, file_path, part_ids);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "cannot commit blob file parts for file id=%" PRIu64 " path=%s",
                          file_id, file_path);
        }
        else {
            flb_plg_info(ctx->ins, "blob file '%s' (id=%" PRIu64 ") committed successfully", file_path, file_id);
            /* notify the engine the blob file has been processed */
            /* FIXME! */

            notification = flb_calloc(1,
                                    sizeof(
                                        struct flb_blob_delivery_notification));

            if (notification != NULL) {
                notification->base.dynamically_allocated = FLB_TRUE;
                notification->base.notification_type = FLB_NOTIFICATION_TYPE_BLOB_DELIVERY;
                notification->base.destructor = flb_input_blob_delivery_notification_destroy;
                notification->success = FLB_TRUE;
                notification->path = cfl_sds_create(file_path);

                ret = flb_notification_enqueue(FLB_PLUGIN_INPUT,
                                               source,
                                               &notification->base,
                                               config);

                if (ret != 0) {
                    flb_plg_error(ctx->ins,
                                "blob file '%s' (id=%" PRIu64 ") notification " \
                                "delivery error %d", file_path, file_id, ret);

                    flb_notification_cleanup(&notification->base);
                }
            }

            /* remove the file entry from the database */
            ret = azb_db_file_delete(ctx, file_id, file_path);
            if (ret == -1) {
                flb_plg_error(ctx->ins, "cannot delete blob file '%s' (id=%" PRIu64 ") from the database",
                              file_path, file_id);
            }
        }
    }
    pthread_mutex_unlock(&ctx->file_upload_commit_file_parts);

    if (file_path) {
        cfl_sds_destroy(file_path);
    }
    if (part_ids) {
        cfl_sds_destroy(part_ids);
    }
    if (source) {
        cfl_sds_destroy(source);
    }

    /* check for a next part file and lock it */
    ret = azb_db_file_part_get_next(ctx, &id, &file_id, &part_id,
                                    &offset_start, &offset_end,
                                    &part_delivery_attempts,
                                    &file_delivery_attempts,
                                    &file_path,
                                    &file_destination);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot get next blob file part");
        info->active_upload = FLB_FALSE;
        flb_sched_timer_cb_coro_return();
    }
    else if (ret == 0) {
        flb_plg_trace(ctx->ins, "no more blob file parts to process");
        info->active_upload = FLB_FALSE;
        flb_sched_timer_cb_coro_return();
    }
    else if (ret == 1) {
        /* just continue, the row info was retrieved */
    }


    if (strcmp(file_destination, ctx->real_endpoint) != 0) {
        flb_plg_info(ctx->ins,
                     "endpoint change detected, restarting file : %s\n%s\n%s",
                     file_path,
                     file_destination,
                     ctx->real_endpoint);

        info->active_upload = FLB_FALSE;

        /* we need to set the aborted state flag to wait for existing uploads
         * to finish and then wipe the slate and start again but we don't want
         * to increment the failure count in this case.
         */
        azb_db_file_set_aborted_state(ctx, file_id, file_path, 1);

        cfl_sds_destroy(file_path);
        cfl_sds_destroy(file_destination);

        flb_sched_timer_cb_coro_return();
    }

    /* since this is the first part we want to increment the files
     * delivery attempt counter.
     */
    if (part_id == 0) {
        ret = azb_db_file_delivery_attempts(ctx, file_id, ++file_delivery_attempts);
    }

    /* read the file content */
    ret = flb_utils_read_file_offset(file_path, offset_start, offset_end, &out_buf, &out_size);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot read file part %s", file_path);

        info->active_upload = FLB_FALSE;

        cfl_sds_destroy(file_path);
        cfl_sds_destroy(file_destination);

        flb_sched_timer_cb_coro_return();
    }

    azb_db_file_part_delivery_attempts(ctx, file_id, part_id, ++part_delivery_attempts);

    flb_plg_debug(ctx->ins, "sending part file %s (id=%" PRIu64 " part_id=%" PRIu64 ")", file_path, id, part_id);

    ret = send_blob(config, NULL, ctx, FLB_EVENT_TYPE_BLOBS,
                    AZURE_BLOB_BLOCKBLOB, file_path, part_id, NULL, 0, out_buf, out_size);

    if (ret == FLB_OK) {
        ret = azb_db_file_part_uploaded(ctx, id);

        if (ret == -1) {
            info->active_upload = FLB_FALSE;

            cfl_sds_destroy(file_path);
            cfl_sds_destroy(file_destination);

            flb_sched_timer_cb_coro_return();
        }
    }
    else if (ret == FLB_RETRY) {
        azb_db_file_part_in_progress(ctx, 0, id);

        if (ctx->part_delivery_attempt_limit != FLB_OUT_RETRY_UNLIMITED &&
            part_delivery_attempts >= ctx->part_delivery_attempt_limit) {
            azb_db_file_set_aborted_state(ctx, file_id, file_path, 1);
        }
    }

    info->active_upload = FLB_FALSE;

    if (out_buf) {
        flb_free(out_buf);
    }

    cfl_sds_destroy(file_path);
    cfl_sds_destroy(file_destination);

    flb_sched_timer_cb_coro_return();
}

static int azb_timer_create(struct flb_azure_blob *ctx)
{
    int ret;
    int64_t ms;
    struct flb_sched *sched;

    sched = flb_sched_ctx_get();

    /* convert from seconds to milliseconds (scheduler needs ms) */
    ms = ctx->upload_parts_timeout * 1000;

    ret = flb_sched_timer_coro_cb_create(sched, FLB_SCHED_TIMER_CB_PERM, ms,
                                         cb_azb_blob_file_upload, ctx, NULL);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "failed to create upload timer");
        return -1;
    }

    return 0;
}

/**
 * Azure Blob Storage ingestion callback function
 * This function handles the upload of data chunks to Azure Blob Storage with retry mechanism
 * @param config: Fluent Bit configuration
 * @param data: Azure Blob context data
 */
static void cb_azure_blob_ingest(struct flb_config *config, void *data) {
    /* Initialize context and file handling variables */
    struct flb_azure_blob *ctx = data;
    struct azure_blob_file *file = NULL;
    struct flb_fstore_file *fsf;
    char *buffer = NULL;
    size_t buffer_size = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    int ret;
    time_t now;
    flb_sds_t payload;
    flb_sds_t tag_sds;

    /* Retry mechanism configuration */
    int retry_count;
    int backoff_time;
    const int max_backoff_time = 64;  /* Maximum backoff time in seconds */

    /* Log entry point and container information */
    flb_plg_debug(ctx->ins, "Running upload timer callback (cb_azure_blob_ingest)..");

    /* Initialize jitter for retry mechanism */
    srand(time(NULL));
    now = time(NULL);

    /* Iterate through all chunks in the active stream */
    mk_list_foreach_safe(head, tmp, &ctx->stream_active->files) {
        fsf = mk_list_entry(head, struct flb_fstore_file, _head);
        file = fsf->data;

        /* Debug logging for current file processing */
        flb_plg_debug(ctx->ins, "Iterating files inside upload timer callback (cb_azure_blob_ingest).. %s",
                      file->fsf->name);

        /* Skip if chunk hasn't timed out yet */
        if (now < (file->create_time + ctx->upload_timeout + ctx->retry_time)) {
            continue;
        }

        /* Skip if file is already being processed */
        flb_plg_debug(ctx->ins, "cb_azure_blob_ingest :: Before file locked check %s", file->fsf->name);
        if (file->locked == FLB_TRUE) {
            continue;
        }

        /* Initialize retry mechanism parameters */
        retry_count = 0;
        backoff_time = 2;  /* Initial backoff time in seconds */

        /* Retry loop for upload attempts */
        while (retry_count < ctx->scheduler_max_retries) {
            /* Construct request buffer for upload */
            flb_plg_debug(ctx->ins, "cb_azure_blob_ingest :: Before construct_request_buffer %s", file->fsf->name);
            ret = construct_request_buffer(ctx, NULL, file, &buffer, &buffer_size);

            /* Handle request buffer construction failure */
            if (ret < 0) {
                flb_plg_error(ctx->ins, "cb_azure_blob_ingest :: Could not construct request buffer for %s",
                              file->fsf->name);
                retry_count++;

                /* Implement exponential backoff with jitter */
                int jitter = rand() % backoff_time;
                flb_plg_warn(ctx->ins, "cb_azure_blob_ingest :: failure in construct_request_buffer :: Retrying in %d seconds (attempt %d of %d) with jitter %d for file %s",
                             backoff_time + jitter, retry_count, ctx->scheduler_max_retries, jitter, file->fsf->name);
                sleep(backoff_time + jitter);
                backoff_time = (backoff_time * 2 < max_backoff_time) ? backoff_time * 2 : max_backoff_time;
                continue;
            }

            /* Create payload and tags for blob upload */
            payload = flb_sds_create_len(buffer, buffer_size);
            tag_sds = flb_sds_create(fsf->meta_buf);
            flb_plg_debug(ctx->ins, "cb_azure_blob_ingest ::: tag of the file %s", tag_sds);

            /* Attempt to send blob */
            ret = send_blob(config, NULL, ctx, FLB_EVENT_TYPE_LOGS,ctx->btype , (char *) tag_sds,0, (char *) tag_sds,
                            flb_sds_len(tag_sds), payload, flb_sds_len(payload));

            /* Handle blob creation if necessary */
            if (ret == CREATE_BLOB) {
                ret = azb_create_blob_with_tag(ctx, tag_sds,
                                               (int) flb_sds_len(tag_sds),
                                               tag_sds);
                if (ret == FLB_OK) {
                    ret = send_blob(config, NULL, ctx, FLB_EVENT_TYPE_LOGS,ctx->btype, (char *) tag_sds, 0, (char *) tag_sds,
                                    flb_sds_len(tag_sds), payload, flb_sds_len(payload));
                }
            }

            /* Handle blob send failure */
            if (ret != FLB_OK) {
                /* Clean up resources and update failure count */
                flb_plg_error(ctx->ins, "cb_azure_blob_ingest :: Failed to ingest data to Azure Blob Storage (attempt %d of %d)",
                              retry_count + 1, ctx->scheduler_max_retries);
                flb_free(buffer);
                flb_sds_destroy(payload);
                flb_sds_destroy(tag_sds);

                if (file) {
                    azure_blob_store_file_unlock(file);
                    file->failures += 1;
                }

                retry_count++;

                /* Implement exponential backoff with jitter for retry */
                int jitter = rand() % backoff_time;
                flb_plg_warn(ctx->ins, "cb_azure_blob_ingest :: error sending blob :: Retrying in %d seconds (attempt %d of %d) with jitter %d for file %s",
                             backoff_time + jitter, retry_count, ctx->scheduler_max_retries, jitter, file->fsf->name);
                sleep(backoff_time + jitter);
                backoff_time = (backoff_time * 2 < max_backoff_time) ? backoff_time * 2 : max_backoff_time;
                continue;
            }

            /* Handle successful upload */
            ret = azure_blob_store_file_delete(ctx, file);
            if (ret == 0) {
                flb_plg_debug(ctx->ins, "cb_azure_blob_ingest :: deleted successfully ingested file %s", fsf->name);
            }
            else {
                flb_plg_error(ctx->ins, "cb_azure_blob_ingest :: failed to delete ingested file %s", fsf->name);
                if (file) {
                    azure_blob_store_file_unlock(file);
                    file->failures += 1;
                }
            }

            /* Clean up resources */
            flb_free(buffer);
            flb_sds_destroy(payload);
            flb_sds_destroy(tag_sds);
            break;
        }

        /* Ensure file is unlocked if max retries reached */
        if (retry_count >= ctx->scheduler_max_retries) {
            flb_plg_error(ctx->ins, "cb_azure_blob_ingest :: Max retries reached for file :: attempting to delete/marking inactive %s",
                          file->fsf->name);
            if (ctx->delete_on_max_upload_error){
                azure_blob_store_file_delete(ctx, file);
            }
            else {
                azure_blob_store_file_inactive(ctx, file);
            }
        }

        flb_plg_debug(ctx->ins, "Exited upload timer callback (cb_azure_blob_ingest)..");
    }
}


static int ingest_all_chunks(struct flb_azure_blob *ctx, struct flb_config *config)
{
    struct azure_blob_file *chunk;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *f_head;
    struct flb_fstore_file *fsf;
    struct flb_fstore_stream *fs_stream;
    flb_sds_t payload = NULL;
    char *buffer = NULL;
    size_t buffer_size;
    int ret;
    flb_sds_t tag_sds;

    mk_list_foreach(head, &ctx->fs->streams) {
        /* skip multi upload stream */
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);
        if (fs_stream == ctx->stream_upload) {
            continue;
        }

        mk_list_foreach_safe(f_head, tmp, &fs_stream->files) {
            fsf = mk_list_entry(f_head, struct flb_fstore_file, _head);
            chunk = fsf->data;

            /* Locked chunks are being processed, skip */
            if (chunk->locked == FLB_TRUE) {
                continue;
            }

            if (chunk->failures >= ctx->scheduler_max_retries) {
                flb_plg_warn(ctx->ins,
                             "ingest_all_chunks :: Chunk for tag %s failed to send %i times, "
                             "will not retry",
                             (char *) fsf->meta_buf, ctx->scheduler_max_retries);
                if (ctx->delete_on_max_upload_error){
                    azure_blob_store_file_delete(ctx, chunk);
                }
                else {
                    azure_blob_store_file_inactive(ctx, chunk);
                }
                continue;
            }

            ret = construct_request_buffer(ctx, NULL, chunk,
                                           &buffer, &buffer_size);
            if (ret < 0) {
                flb_plg_error(ctx->ins,
                              "ingest_all_chunks :: Could not construct request buffer for %s",
                              chunk->file_path);
                return -1;
            }

            payload = flb_sds_create_len(buffer, buffer_size);
            tag_sds = flb_sds_create(fsf->meta_buf);
            flb_free(buffer);

            ret = send_blob(config, NULL, ctx, FLB_EVENT_TYPE_LOGS, ctx->btype, (char *)tag_sds, 0, (char *)tag_sds, flb_sds_len(tag_sds), payload, flb_sds_len(payload));

            if (ret == CREATE_BLOB) {
                ret = azb_create_blob_with_tag(ctx, tag_sds,
                                               (int) flb_sds_len(tag_sds),
                                               tag_sds);
                if (ret == FLB_OK) {
                    ret = send_blob(config, NULL, ctx, FLB_EVENT_TYPE_LOGS, ctx->btype, (char *)tag_sds, 0, (char *)tag_sds, flb_sds_len(tag_sds), payload, flb_sds_len(payload));
                }
            }

            if (ret != FLB_OK) {
                flb_plg_error(ctx->ins, "ingest_all_chunks :: Failed to ingest data to Azure Blob Storage");
                if (chunk){
                    azure_blob_store_file_unlock(chunk);
                    chunk->failures += 1;
                }
                flb_sds_destroy(tag_sds);
                flb_sds_destroy(payload);
                return -1;
            }

            flb_sds_destroy(tag_sds);
            flb_sds_destroy(payload);

            /* data was sent successfully- delete the local buffer */
            azure_blob_store_file_cleanup(ctx, chunk);
        }
    }

    return 0;
}

static void flush_init(void *out_context, struct flb_config *config)
{
    int ret;
    struct flb_azure_blob *ctx = out_context;
    struct flb_sched *sched;

    /* clean up any old buffers found on startup */
    if (ctx->has_old_buffers == FLB_TRUE) {
        flb_plg_info(ctx->ins,
                     "Sending locally buffered data from previous "
                     "executions to azure blob; buffer=%s",
                     ctx->fs->root_path);
        ctx->has_old_buffers = FLB_FALSE;
        ret = ingest_all_chunks(ctx, config);
        if (ret < 0) {
            ctx->has_old_buffers = FLB_TRUE;
            flb_plg_error(ctx->ins,
                          "Failed to send locally buffered data left over "
                          "from previous executions; will retry. Buffer=%s",
                          ctx->fs->root_path);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }
    else {
        flb_plg_debug(ctx->ins,
                      "Did not find any local buffered data from previous "
                      "executions to azure blob; buffer=%s",
                      ctx->fs->root_path);
    }

    /*
    * create a timer that will run periodically and check if uploads
    * are ready for completion
    * this is created once on the first flush
    */
    if (ctx->timer_created == FLB_FALSE) {
        flb_plg_debug(ctx->ins,
                      "Creating upload timer with frequency %ds",
                      ctx->timer_ms / 1000);

        sched = flb_sched_ctx_get();

        ret = flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_PERM,
                                        ctx->timer_ms, cb_azure_blob_ingest, ctx, NULL);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to create upload timer");
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        ctx->timer_created = FLB_TRUE;
    }
}

static void cb_azure_blob_flush(struct flb_event_chunk *event_chunk,
                                struct flb_output_flush *out_flush,
                                struct flb_input_instance *i_ins,
                                void *out_context,
                                struct flb_config *config)
{
    int ret = FLB_OK;
    struct flb_azure_blob *ctx = out_context;
    (void) i_ins;
    (void) config;
    flb_sds_t json = NULL;
    size_t json_size;

    if (event_chunk->type == FLB_EVENT_TYPE_LOGS) {
        if (ctx->buffering_enabled == FLB_TRUE) {
            size_t tag_len;
            struct azure_blob_file *upload_file = NULL;
            int upload_timeout_check = FLB_FALSE;
            int total_file_size_check = FLB_FALSE;

            char *final_payload = NULL;
            size_t final_payload_size = 0;
            flb_sds_t tag_name = NULL;

            flb_plg_trace(ctx->ins, "flushing bytes for event tag %s and size %zu", event_chunk->tag, event_chunk->size);

            if (ctx->unify_tag == FLB_TRUE) {
                tag_name = flb_sds_create("fluentbit-buffer-file-unify-tag.log");
            }
            else {
                tag_name = event_chunk->tag;
            }
            tag_len = flb_sds_len(tag_name);

            flush_init(ctx, config);
            /* Reformat msgpack to JSON payload */
            ret = azure_blob_format(config, i_ins, ctx, NULL, FLB_EVENT_TYPE_LOGS, tag_name, tag_len, event_chunk->data, event_chunk->size, (void **)&json, &json_size);
            if (ret != 0) {
                flb_plg_error(ctx->ins, "cannot reformat data into json");
                goto error;
            }

            /* Get a file candidate matching the given 'tag' */
            upload_file = azure_blob_store_file_get(ctx, tag_name, tag_len);

            /* Handle upload timeout or file size limits */
            if (upload_file != NULL) {
                if (upload_file->failures >= ctx->scheduler_max_retries) {
                    flb_plg_warn(ctx->ins, "File with tag %s failed to send %d times, will not retry", event_chunk->tag, ctx->scheduler_max_retries);
                    if (ctx->delete_on_max_upload_error) {
                        azure_blob_store_file_delete(ctx, upload_file);
                    } else {
                        azure_blob_store_file_inactive(ctx, upload_file);
                    }
                    upload_file = NULL;
                } else if (time(NULL) > (upload_file->create_time + ctx->upload_timeout)) {
                    upload_timeout_check = FLB_TRUE;
                } else if (upload_file->size + json_size > ctx->file_size) {
                    total_file_size_check = FLB_TRUE;
                }
            }

            if (upload_file != NULL && (upload_timeout_check == FLB_TRUE || total_file_size_check == FLB_TRUE)) {
                flb_plg_debug(ctx->ins, "uploading file %s with size %zu", upload_file->fsf->name, upload_file->size);

                /* Construct the payload for upload */
                ret = construct_request_buffer(ctx, json, upload_file, &final_payload, &final_payload_size);
                if (ret != 0) {
                    flb_plg_error(ctx->ins, "error constructing request buffer for %s", event_chunk->tag);
                    flb_sds_destroy(json);
                    upload_file->failures += 1;
                    FLB_OUTPUT_RETURN(FLB_RETRY);
                }

                /*
                * Azure blob requires a container. The following function validate that the container exists,
                * otherwise it will be created. Note that that container name is specified by the user
                * in the configuration file.
                *
                * https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blob-container-create#about-container-naming
                */
                ret = ensure_container(ctx);
                if (ret == FLB_FALSE) {
                    FLB_OUTPUT_RETURN(FLB_RETRY);
                }

                /* Upload the file */
                ret = send_blob(config, i_ins, ctx, FLB_EVENT_TYPE_LOGS, ctx->btype,(char *)tag_name, 0, (char *)tag_name, tag_len, final_payload, final_payload_size);

                if (ret == CREATE_BLOB) {
                    ret = azb_create_blob_with_tag(ctx, tag_name, tag_len, tag_name);
                    if (ret == FLB_OK) {
                        ret = send_blob(config, i_ins, ctx, FLB_EVENT_TYPE_LOGS, ctx->btype,(char *)tag_name, 0, (char *)tag_name, tag_len, final_payload, final_payload_size);
                    }
                }

                if (ret == FLB_OK) {
                    flb_plg_debug(ctx->ins, "uploaded file %s successfully", upload_file->fsf->name);
                    azure_blob_store_file_delete(ctx, upload_file);
                    goto cleanup;
                }
                else {
                    flb_plg_error(ctx->ins, "error uploading file %s", upload_file->fsf->name);
                    if (upload_file) {
                        azure_blob_store_file_unlock(upload_file);
                        upload_file->failures += 1;
                    }
                    goto error;
                }
            }
            else {
                /* Buffer current chunk */
                ret = azure_blob_store_buffer_put(ctx, upload_file, tag_name, tag_len, json, json_size);
                if (ret == 0) {
                    flb_plg_debug(ctx->ins, "buffered chunk %s", event_chunk->tag);
                    goto cleanup;
                }
                else {
                    flb_plg_error(ctx->ins, "failed to buffer chunk %s", event_chunk->tag);
                    goto error;
                }
            }

            cleanup:
            if (json) {
                flb_sds_destroy(json);
            }
            if (tag_name && ctx->unify_tag == FLB_TRUE) {
                flb_sds_destroy(tag_name);
            }
            if (final_payload) {
                flb_free(final_payload);
            }
            FLB_OUTPUT_RETURN(FLB_OK);

            error:
            if (json) {
                flb_sds_destroy(json);
            }
            if (tag_name && ctx->unify_tag == FLB_TRUE) {
                flb_sds_destroy(tag_name);
            }
            if (final_payload) {
                flb_free(final_payload);
            }
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        else {

            /*
            * Azure blob requires a container. The following function validate that the container exists,
            * otherwise it will be created. Note that that container name is specified by the user
            * in the configuration file.
            *
            * https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blob-container-create#about-container-naming
            */
            ret = ensure_container(ctx);
            if (ret == FLB_FALSE) {
                FLB_OUTPUT_RETURN(FLB_RETRY);
            }

            ret = azure_blob_format(config, i_ins, ctx, NULL, FLB_EVENT_TYPE_LOGS,(char *) event_chunk->tag, flb_sds_len(event_chunk->tag), (char *) event_chunk->data ,event_chunk->size, (void **)&json, &json_size);
            if (ret != 0) {
                flb_plg_error(ctx->ins, "cannot reformat data into json");
                ret = FLB_RETRY;
            }
            /* Buffering mode is disabled, proceed with regular flow */
            ret = send_blob(config, i_ins, ctx,
                            FLB_EVENT_TYPE_LOGS,
                            ctx->btype, /* blob type per user configuration  */
                            (char *) event_chunk->tag,  /* use tag as 'name' */
                            0,  /* part id */
                            (char *) event_chunk->tag, flb_sds_len(event_chunk->tag),
                            json, json_size);

            if (ret == CREATE_BLOB) {
                ret = azb_create_blob_with_tag(ctx, event_chunk->tag,
                                               (int) flb_sds_len(event_chunk->tag),
                                               event_chunk->tag);
                if (ret == FLB_OK) {
                    ret = send_blob(config, i_ins, ctx,
                                    FLB_EVENT_TYPE_LOGS,
                                    ctx->btype, /* blob type per user configuration  */
                                    (char *) event_chunk->tag,  /* use tag as 'name' */
                                    0,  /* part id */
                                    (char *) event_chunk->tag,  /* use tag as 'name' */
                                    flb_sds_len(event_chunk->tag),
                                    json, json_size);
                }
            }
        }
    }
    else if (event_chunk->type == FLB_EVENT_TYPE_BLOBS) {
        /*
         * For Blob types, we use the flush callback to enqueue the file, then cb_azb_blob_file_upload()
         * takes care of the rest like reading the file and uploading it to Azure.
         */
        ret = process_blob_chunk(ctx, event_chunk);
        if (ret == -1) {
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    if (json){
        flb_sds_destroy(json);
    }

    /* FLB_RETRY, FLB_OK, FLB_ERROR */
    FLB_OUTPUT_RETURN(ret);
}

static int cb_azure_blob_exit(void *data, struct flb_config *config)
{
    struct flb_azure_blob *ctx = data;
    int ret = -1;

    if (!ctx) {
        return 0;
    }

    if (ctx->buffering_enabled == FLB_TRUE){
        if (azure_blob_store_has_data(ctx) == FLB_TRUE) {
            flb_plg_info(ctx->ins, "Sending all locally buffered data to Azure Blob");
            ret = ingest_all_chunks(ctx, config);
            if (ret < 0) {
                flb_plg_error(ctx->ins, "Could not send all chunks on exit");
            }
        }
        azure_blob_store_exit(ctx);
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
        ctx->u = NULL;
    }

    flb_azure_blob_conf_destroy(ctx);
    return 0;
}

/* worker initialization, used for our internal timers */
static int cb_worker_init(void *data, struct flb_config *config)
{
    int ret;
    struct worker_info *info;
    struct flb_azure_blob *ctx = data;

    flb_plg_info(ctx->ins, "initializing worker");

    info = FLB_TLS_GET(worker_info);
    if (!info) {
        /* initialize worker global info */
        info = flb_malloc(sizeof(struct worker_info));
        if (!info) {
            flb_errno();
            return -1;
        }
        info->active_upload = FLB_FALSE;
        FLB_TLS_SET(worker_info, info);
    }

    ret = azb_timer_create(ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "failed to create upload timer");
        return -1;
    }

    return 0;
}

/* worker teardown */
static int cb_worker_exit(void *data, struct flb_config *config)
{
    struct worker_info *info;
    struct flb_azure_blob *ctx = data;

    flb_plg_info(ctx->ins, "initializing worker");

    info = FLB_TLS_GET(worker_info);
    if (info != NULL) {
        flb_free(info);
        FLB_TLS_SET(worker_info, NULL);
    }

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "account_name", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, account_name),
     "Azure account name (mandatory)"
    },

    {
     FLB_CONFIG_MAP_STR, "container_name", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, container_name),
     "Container name (mandatory)"
    },

    {
     FLB_CONFIG_MAP_BOOL, "auto_create_container", "true",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, auto_create_container),
     "Auto create container if it don't exists"
    },

    {
     FLB_CONFIG_MAP_STR, "blob_type", "appendblob",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, blob_type),
     "Set the block type: appendblob or blockblob"
    },

    {
     FLB_CONFIG_MAP_STR, "compress", NULL,
     0, FLB_FALSE, 0,
     "Set payload compression in network transfer. Option available is 'gzip'"
    },

    {
     FLB_CONFIG_MAP_BOOL, "compress_blob", "false",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, compress_blob),
     "Enable block blob GZIP compression in the final blob file. This option is "
     "not compatible with 'appendblob' block type"
    },

    {
     FLB_CONFIG_MAP_BOOL, "emulator_mode", "false",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, emulator_mode),
     "Use emulator mode, enable it if you want to use Azurite"
    },

    {
     FLB_CONFIG_MAP_STR, "shared_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, shared_key),
     "Azure shared key"
    },

    {
     FLB_CONFIG_MAP_STR, "endpoint", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, endpoint),
     "Custom full URL endpoint to use an emulator"
    },

    {
     FLB_CONFIG_MAP_STR, "path", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, path),
     "Set a path for your blob"
    },

    {
     FLB_CONFIG_MAP_STR, "date_key", "@timestamp",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, date_key),
     "Name of the key that will have the record timestamp"
    },

    {
     FLB_CONFIG_MAP_STR, "auth_type", "key",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, auth_type),
     "Set the auth type: key or sas"
    },

    {
     FLB_CONFIG_MAP_STR, "sas_token", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, sas_token),
     "Azure Blob SAS token"
    },

    {
     FLB_CONFIG_MAP_STR, "database_file", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, database_file),
     "Absolute path to a database file to be used to store blob files contexts"
    },

    {
     FLB_CONFIG_MAP_SIZE, "part_size", "25M",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, part_size),
     "Size of each part when uploading blob files"
    },

    {
     FLB_CONFIG_MAP_INT, "file_delivery_attempt_limit", "1",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, file_delivery_attempt_limit),
     "File delivery attempt limit"
    },

    {
     FLB_CONFIG_MAP_INT, "part_delivery_attempt_limit", "1",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, part_delivery_attempt_limit),
     "File part delivery attempt limit"
    },

    {
     FLB_CONFIG_MAP_TIME, "upload_parts_timeout", "10M",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, upload_parts_timeout),
     "Timeout to upload parts of a blob file"
    },

    {
     FLB_CONFIG_MAP_TIME, "upload_part_freshness_limit", "6D",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, upload_parts_freshness_threshold),
     "Maximum lifespan of an uncommitted file part"
    },

    {
     FLB_CONFIG_MAP_STR, "configuration_endpoint_url", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, configuration_endpoint_url),
     "Configuration endpoint URL"
    },

    {
     FLB_CONFIG_MAP_STR, "configuration_endpoint_username", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, configuration_endpoint_username),
     "Configuration endpoint basic authentication username"
    },

    {
     FLB_CONFIG_MAP_STR, "configuration_endpoint_password", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, configuration_endpoint_password),
     "Configuration endpoint basic authentication password"
    },

    {
     FLB_CONFIG_MAP_STR, "configuration_endpoint_bearer_token", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure_blob, configuration_endpoint_bearer_token),
     "Configuration endpoint bearer token"
    },

    {
     FLB_CONFIG_MAP_BOOL, "buffering_enabled", "false",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, buffering_enabled),
     "Enable buffering into disk before ingesting into Azure Blob"
    },

    {
     FLB_CONFIG_MAP_STR, "buffer_dir", "/tmp/fluent-bit/azure-blob/",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, buffer_dir),
     "Specifies the location of directory where the buffered data will be stored"
    },

    {
     FLB_CONFIG_MAP_TIME, "upload_timeout", "30m",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, upload_timeout),
     "Optionally specify a timeout for uploads. "
           "Fluent Bit will start ingesting buffer files which have been created more than x minutes and haven't reached upload_file_size limit yet"
           "Default is 30m."
    },

    {
     FLB_CONFIG_MAP_SIZE, "upload_file_size", "200M",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, file_size),
     "Specifies the size of files to be uploaded in MBs. Default is 200MB"
    },

    {
     FLB_CONFIG_MAP_STR, "azure_blob_buffer_key", "key",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, azure_blob_buffer_key),
     "Set the azure blob buffer key which needs to be specified when using multiple instances of azure blob output plugin and buffering is enabled"
    },

    {
     FLB_CONFIG_MAP_SIZE, "store_dir_limit_size", "8G",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, store_dir_limit_size),
     "Set the max size of the buffer directory. Default is 8GB"
    },

    {
     FLB_CONFIG_MAP_BOOL, "buffer_file_delete_early", "false",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, buffer_file_delete_early),
     "Whether to delete the buffered file early after successful blob creation. Default is false"
    },

    { 
     FLB_CONFIG_MAP_INT, "blob_uri_length", "64",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, blob_uri_length),
     "Set the length of generated blob uri before ingesting to Azure Kusto. Default is 64"
    },

    {
     FLB_CONFIG_MAP_BOOL, "unify_tag", "false",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, unify_tag),
     "Whether to create a single buffer file when buffering mode is enabled. Default is false"
    },

    {
     FLB_CONFIG_MAP_INT, "scheduler_max_retries", "3",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, scheduler_max_retries),
     "Maximum number of retries for the scheduler send blob. Default is 3"
    },

    {
     FLB_CONFIG_MAP_BOOL, "delete_on_max_upload_error", "false",
     0, FLB_TRUE, offsetof(struct flb_azure_blob, delete_on_max_upload_error),
     "Whether to delete the buffer file on maximum upload errors. Default is false"
    },

    {
     FLB_CONFIG_MAP_TIME, "io_timeout", "60s",0, FLB_TRUE, offsetof(struct flb_azure_blob, io_timeout),
     "HTTP IO timeout. Default is 60s"
    },

    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_azure_blob_plugin = {
    .name           = "azure_blob",
    .description    = "Azure Blob Storage",
    .cb_init        = cb_azure_blob_init,
    .cb_flush       = cb_azure_blob_flush,
    .cb_exit        = cb_azure_blob_exit,
    .cb_worker_init = cb_worker_init,
    .cb_worker_exit = cb_worker_exit,

    /* Test */
    .test_formatter.callback = azure_blob_format,

    .flags        = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
    .event_type   = FLB_OUTPUT_LOGS | FLB_OUTPUT_BLOBS,
    .config_map   = config_map,
    .workers      = 1,
};
