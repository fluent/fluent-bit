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

#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_jsmn.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_random.h>
#include <fluent-bit/flb_unescape.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_gcp_auth.h>
#include <fluent-bit/aws/flb_aws_compress.h>

#include "gcs.h"
#include "gcs_store.h"

#include <ctype.h>
#include <limits.h>
#include <sys/stat.h>

static int gcs_ctx_destroy(void *data, struct flb_config *config);

static int enable_parquet_format(struct flb_gcs *ctx)
{
#ifdef FLB_HAVE_ARROW_PARQUET
    ctx->gcs_format = FLB_GCS_FORMAT_PARQUET;
    return 0;
#else
    flb_plg_error(ctx->ins,
                  "parquet format requires parquet-glib at compile time");
    return -1;
#endif
}

static int parse_output_format(const char *format)
{
    if (strcasecmp(format, "parquet") == 0) {
        return FLB_GCS_FORMAT_PARQUET;
    }

    return flb_pack_to_json_format_type(format);
}

static int validate_parquet_compression(int compression_type)
{
    switch (compression_type) {
    case FLB_AWS_COMPRESS_NONE:
    case FLB_AWS_COMPRESS_SNAPPY:
    case FLB_AWS_COMPRESS_GZIP:
    case FLB_AWS_COMPRESS_ZSTD:
        return 0;
    default:
        return -1;
    }
}

static const char *get_predefined_acl(const char *canned_acl)
{
    if (!canned_acl) {
        return NULL;
    }

    if (strcasecmp(canned_acl, "authenticated-read") == 0 ||
        strcasecmp(canned_acl, "authenticatedRead") == 0) {
        return "authenticatedRead";
    }
    if (strcasecmp(canned_acl, "bucket-owner-full-control") == 0 ||
        strcasecmp(canned_acl, "bucketOwnerFullControl") == 0) {
        return "bucketOwnerFullControl";
    }
    if (strcasecmp(canned_acl, "bucket-owner-read") == 0 ||
        strcasecmp(canned_acl, "bucketOwnerRead") == 0) {
        return "bucketOwnerRead";
    }
    if (strcasecmp(canned_acl, "private") == 0) {
        return "private";
    }
    if (strcasecmp(canned_acl, "project-private") == 0 ||
        strcasecmp(canned_acl, "projectPrivate") == 0) {
        return "projectPrivate";
    }
    if (strcasecmp(canned_acl, "public-read") == 0 ||
        strcasecmp(canned_acl, "publicRead") == 0) {
        return "publicRead";
    }

    return NULL;
}

static inline int key_cmp(char *str, int len, char *cmp) {
    if (strlen(cmp) != len) {
        return -1;
    }

    return strncasecmp(str, cmp, len);
}

static int gcs_under_test_mode(void)
{
    char *env;

    env = getenv("FLB_GCS_PLUGIN_UNDER_TEST");

    if (env && strcasecmp(env, "true") == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int gcs_setenv(const char *key, const char *val)
{
#ifdef FLB_SYSTEM_WINDOWS
    return _putenv_s(key, val);
#else
    return setenv(key, val, 1);
#endif
}

static void mock_gcs_call_increment_counter(const char *api)
{
    char env_var[64];
    char *val;
    int count;
    char buf[16];

    snprintf(env_var, sizeof(env_var), "TEST_GCS_%s_CALL_COUNT", api);
    val = getenv(env_var);
    count = val ? atoi(val) : 0;
    count++;
    snprintf(buf, sizeof(buf), "%d", count);
    gcs_setenv(env_var, buf);
}

static int read_seq_index(const char *path, uint64_t *out_value)
{
    FILE *fp;
    unsigned long long val;

    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }
    if (fscanf(fp, "%llu", &val) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    *out_value = (uint64_t) val;
    return 0;
}

static int write_seq_index(const char *path, uint64_t value)
{
    FILE *fp;

    fp = fopen(path, "w");
    if (!fp) {
        return -1;
    }
    fprintf(fp, "%llu", (unsigned long long) value);
    fclose(fp);
    return 0;
}

static int init_seq_index(struct flb_gcs *ctx)
{
    flb_sds_t path;
    flb_sds_t tmp;

    path = flb_sds_create_size(256);
    if (!path) {
        flb_errno();
        return -1;
    }
    tmp = flb_sds_printf(&path, "%s/%s_seq_index",
                         ctx->store_dir, ctx->fs_stream_name);
    if (!tmp) {
        flb_sds_destroy(path);
        return -1;
    }
    path = tmp;
    ctx->seq_index_file = path;

    if (read_seq_index(ctx->seq_index_file, &ctx->seq_index) == -1) {
        ctx->seq_index = 0;
        if (write_seq_index(ctx->seq_index_file, ctx->seq_index) == -1) {
            return -1;
        }
    }
    return 0;
}

static int gcs_get_md5_base64(char *buf, size_t buf_size, char *md5_str, size_t md5_str_size)
{
    unsigned char md5_bin[16];
    size_t olen;
    int ret;

    ret = flb_hash_simple(FLB_HASH_MD5, (unsigned char *) buf, buf_size,
                          md5_bin, sizeof(md5_bin));
    if (ret != FLB_CRYPTO_SUCCESS) {
        return -1;
    }

    ret = flb_base64_encode((unsigned char *) md5_str, md5_str_size,
                            &olen, md5_bin, sizeof(md5_bin));
    if (ret != 0) {
        return -1;
    }
    return 0;
}

static int random_hex_suffix(char *buf, size_t buf_size)
{
    unsigned char rnd[4];
    int ret;

    if (buf_size < 9) {
        return -1;
    }

    ret = flb_random_bytes(rnd, sizeof(rnd));
    if (ret != 0) {
        return -1;
    }

    snprintf(buf, buf_size, "%02x%02x%02x%02x", rnd[0], rnd[1], rnd[2], rnd[3]);
    return 0;
}

flb_sds_t gcs_uri_encode_object_name(const char *name, size_t name_len)
{
    size_t index;
    size_t output_index;
    size_t output_size;
    unsigned char value;
    char *buffer;
    flb_sds_t output;
    const char hex[] = "0123456789ABCDEF";

    if (!name || name_len > (((size_t) -1) - 1) / 3) {
        return NULL;
    }

    output_size = (name_len * 3) + 1;
    buffer = flb_malloc(output_size);
    if (!buffer) {
        flb_errno();
        return NULL;
    }

    output_index = 0;
    for (index = 0; index < name_len; index++) {
        value = (unsigned char) name[index];
        if ((value >= 'a' && value <= 'z') ||
            (value >= 'A' && value <= 'Z') ||
            (value >= '0' && value <= '9') ||
            value == '-' || value == '_' || value == '.' || value == '~') {
            buffer[output_index++] = (char) value;
        }
        else {
            buffer[output_index++] = '%';
            buffer[output_index++] = hex[value >> 4];
            buffer[output_index++] = hex[value & 0x0f];
        }
    }
    buffer[output_index] = '\0';

    output = flb_sds_create_len(buffer, output_index);
    flb_free(buffer);

    return output;
}

/* thin wrapper kept for the unit tests; ctx is unused */
int gcs_jwt_encode(struct flb_gcs *ctx, char *payload, char *secret,
                   char **out_signature, size_t *out_size)
{
    (void) ctx;

    return flb_gcp_jwt_encode(payload, secret, out_signature, out_size);
}

/* test seam: mocks the metadata server token endpoint */
static int gcs_mock_metadata_fetch(void *data, flb_sds_t *payload)
{
    const char *test_response;
    flb_sds_t tmp;
    (void) data;

    test_response = getenv("TEST_GCS_METADATA_RESPONSE");
    if (!test_response) {
        return -1;
    }

    tmp = flb_sds_copy(*payload, test_response, strlen(test_response));
    if (!tmp) {
        return -1;
    }
    *payload = tmp;
    mock_gcs_call_increment_counter("MetadataToken");
    gcs_setenv("TEST_GCS_LAST_METADATA_URI", FLB_GCS_METADATA_TOKEN_URI);

    return 0;
}

static int upload_queue_contains(struct flb_gcs *ctx, struct gcs_file *chunk)
{
    struct mk_list *head;
    struct upload_queue *entry;

    mk_list_foreach(head, &ctx->upload_queue) {
        entry = mk_list_entry(head, struct upload_queue, _head);
        if (entry->upload_file == chunk) {
            return FLB_TRUE;
        }
    }
    return FLB_FALSE;
}

static int add_to_queue(struct flb_gcs *ctx, struct gcs_file *chunk,
                        const char *tag, int tag_len)
{
    struct upload_queue *entry;

    if (upload_queue_contains(ctx, chunk) == FLB_TRUE) {
        return 0;
    }

    entry = flb_calloc(1, sizeof(struct upload_queue));
    if (!entry) {
        return -1;
    }

    entry->tag = flb_strndup(tag, tag_len);
    if (!entry->tag) {
        flb_free(entry);
        return -1;
    }

    entry->upload_file = chunk;
    entry->tag_len = tag_len;
    entry->upload_time = chunk->create_time + ctx->upload_timeout;
    if (entry->upload_time < time(NULL)) {
        entry->upload_time = time(NULL);
    }
    mk_list_add(&entry->_head, &ctx->upload_queue);
    return 0;
}

static void remove_from_queue(struct upload_queue *entry)
{
    mk_list_del(&entry->_head);
    flb_free(entry->tag);
    flb_free(entry);
}

/*
 * Seal a buffered file that reached total_file_size: no more data is
 * appended to it and its queue entry becomes due immediately.
 */
static int seal_and_queue_for_upload(struct flb_gcs *ctx, struct gcs_file *chunk,
                                     const char *tag, int tag_len)
{
    struct mk_list *head;
    struct upload_queue *entry;

    if (add_to_queue(ctx, chunk, tag, tag_len) == -1) {
        return -1;
    }

    gcs_store_file_seal(chunk);

    mk_list_foreach(head, &ctx->upload_queue) {
        entry = mk_list_entry(head, struct upload_queue, _head);
        if (entry->upload_file == chunk) {
            entry->upload_time = time(NULL);
            break;
        }
    }

    flb_plg_debug(ctx->ins,
                  "total_file_size reached for tag %.*s (%zu bytes), "
                  "scheduling upload", tag_len, tag, chunk->size);
    return 0;
}


static void clear_upload_queue(struct flb_gcs *ctx)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct upload_queue *entry;

    mk_list_foreach_safe(head, tmp, &ctx->upload_queue) {
        entry = mk_list_entry(head, struct upload_queue, _head);
        remove_from_queue(entry);
    }
}

static void clear_file_chunks(struct flb_gcs *ctx)
{
    struct mk_list *head;
    struct flb_fstore_file *fsf;

    if (!ctx || !ctx->fs_stream) {
        return;
    }

    mk_list_foreach(head, &ctx->fs_stream->files) {
        fsf = mk_list_entry(head, struct flb_fstore_file, _head);

        if (fsf->data) {
            flb_free(fsf->data);
            fsf->data = NULL;
        }
    }
}

static int construct_request_buffer(struct flb_gcs *ctx,
                                    struct upload_queue *entry,
                                    char **out_buffer,
                                    size_t *out_size)
{
    int ret;

    if (gcs_under_test_mode() == FLB_TRUE &&
        getenv("TEST_GCS_CONSTRUCT_REQUEST_BUFFER_ERROR") != NULL) {
        return -1;
    }

    ret = gcs_store_file_read(ctx, entry->upload_file, out_buffer, out_size);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

static int gcs_upload_object(struct flb_gcs *ctx,
                             flb_sds_t auth,
                             flb_sds_t uri,
                             char *body,
                             size_t body_size)
{
    int ret;
    size_t bytes = 0;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    struct flb_aws_header content_type_header = {
        .key = "Content-Type",
        .key_len = 12
    };
    struct flb_aws_header content_md5_header = {
        .key = "Content-MD5",
        .key_len = 11
    };
    char final_body_md5[25];

    if (ctx->gcs_format == FLB_GCS_FORMAT_PARQUET &&
        flb_output_get_property("content_type", ctx->ins) == NULL) {
        content_type_header.val = "application/vnd.apache.parquet";
        content_type_header.val_len = 30;
    }
    else {
        content_type_header.val = ctx->content_type;
        content_type_header.val_len = flb_sds_len(ctx->content_type);
    }

    if (gcs_under_test_mode() == FLB_TRUE) {
        mock_gcs_call_increment_counter("UploadObject");
        gcs_setenv("TEST_GCS_LAST_URI", uri);
        gcs_setenv("TEST_GCS_LAST_CONTENT_TYPE", content_type_header.val);
        if (body_size >= 2 &&
            (unsigned char) body[0] == 0x1f &&
            (unsigned char) body[1] == 0x8b) {
            gcs_setenv("TEST_GCS_LAST_BODY_GZIP", "true");
        }
        else {
            gcs_setenv("TEST_GCS_LAST_BODY_GZIP", "false");
        }
        if (body_size >= 8 &&
            memcmp(body, "PAR1", 4) == 0 &&
            memcmp(body + body_size - 4, "PAR1", 4) == 0) {
            gcs_setenv("TEST_GCS_LAST_BODY_PARQUET", "true");
        }
        else {
            gcs_setenv("TEST_GCS_LAST_BODY_PARQUET", "false");
        }

        if (getenv("TEST_GCS_UPLOAD_ERROR") != NULL) {
            return -1;
        }

        return 0;
    }

    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        return -1;
    }

    c = flb_http_client(u_conn, FLB_HTTP_POST, uri, body, body_size,
                        FLB_GCS_DEFAULT_HOST, FLB_GCS_DEFAULT_PORT, NULL, 0);
    if (!c) {
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    flb_http_add_header(c, content_type_header.key, content_type_header.key_len,
                        content_type_header.val, content_type_header.val_len);
    flb_http_add_header(c, "Authorization", 13, auth, flb_sds_len(auth));

    if (ctx->send_content_md5 == FLB_TRUE) {
        memset(final_body_md5, 0, sizeof(final_body_md5));
        if (gcs_get_md5_base64(body, body_size, final_body_md5,
                               sizeof(final_body_md5)) == 0) {
            content_md5_header.val = final_body_md5;
            content_md5_header.val_len = strlen(final_body_md5);
            flb_http_add_header(c, content_md5_header.key, content_md5_header.key_len,
                                content_md5_header.val, content_md5_header.val_len);
        }
    }

    ret = flb_http_do(c, &bytes);
    if (ret == 0 &&
        (c->resp.status < 200 || c->resp.status >= 300)) {
        flb_plg_error(ctx->ins,
                      "gcs upload failed with status=%i",
                      c->resp.status);
        ret = -1;
    }
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    return ret;
}

static int upload_data(struct flb_gcs *ctx,
                       struct upload_queue *entry,
                       char *buffer,
                       size_t buffer_size)
{
    int ret;
    int append_random;
    int ret_seq;
    const char *predefined_acl;
    flb_sds_t auth;
    flb_sds_t gcs_key;
    flb_sds_t gcs_key_final;
    flb_sds_t gcs_key_encoded;
    flb_sds_t uri;
    flb_sds_t tmp;
    void *compressed_data = NULL;
    size_t compressed_size = 0;
    char *upload_body;
    size_t upload_size;
    char random_hex[9];

    if (gcs_under_test_mode() == FLB_TRUE &&
        flb_gcp_auth_uses_metadata_server(ctx->auth) == FLB_FALSE) {
        auth = flb_sds_create("Bearer test-token");
    }
    else {
        auth = flb_gcp_auth_get_header(ctx->auth);
    }

    if (!auth) {
        return -1;
    }

    if (ctx->key_fmt_has_seq_index) {
        ctx->seq_index++;
    }

    gcs_key = flb_get_s3_key(ctx->gcs_key_format, time(NULL),
                             entry->tag, ctx->tag_delimiters, ctx->seq_index);
    if (!gcs_key) {
        if (ctx->key_fmt_has_seq_index && ctx->seq_index > 0) {
            ctx->seq_index--;
        }
        flb_sds_destroy(auth);
        return -1;
    }

    gcs_key_final = gcs_key;
    append_random = FLB_FALSE;
    if (!ctx->key_fmt_has_uuid && !ctx->key_fmt_has_seq_index && !ctx->static_file_path) {
        append_random = FLB_TRUE;
    }
    if (append_random == FLB_TRUE) {
        if (random_hex_suffix(random_hex, sizeof(random_hex)) == -1) {
            flb_sds_destroy(auth);
            flb_sds_destroy(gcs_key);
            return -1;
        }

        gcs_key_final = flb_sds_create_size(flb_sds_len(gcs_key) + 16);
        if (!gcs_key_final) {
            flb_errno();
            flb_sds_destroy(auth);
            flb_sds_destroy(gcs_key);
            return -1;
        }
        tmp = flb_sds_printf(&gcs_key_final, "%s-object%s", gcs_key, random_hex);
        if (!tmp) {
            flb_sds_destroy(auth);
            flb_sds_destroy(gcs_key);
            flb_sds_destroy(gcs_key_final);
            return -1;
        }
        gcs_key_final = tmp;
        flb_sds_destroy(gcs_key);
    }

    if (ctx->key_fmt_has_seq_index) {
        ret_seq = write_seq_index(ctx->seq_index_file, ctx->seq_index);
        if (ret_seq == -1) {
            flb_sds_destroy(auth);
            flb_sds_destroy(gcs_key_final);
            return -1;
        }
    }

    gcs_key_encoded = gcs_uri_encode_object_name(gcs_key_final,
                                                  flb_sds_len(gcs_key_final));
    flb_sds_destroy(gcs_key_final);
    if (!gcs_key_encoded) {
        flb_sds_destroy(auth);
        return -1;
    }

    uri = flb_sds_create_size(flb_sds_len(ctx->bucket) +
                              flb_sds_len(gcs_key_encoded) + 48);
    if (!uri) {
        flb_errno();
        flb_sds_destroy(auth);
        flb_sds_destroy(gcs_key_encoded);
        return -1;
    }
    tmp = flb_sds_printf(&uri, "/upload/storage/v1/b/%s/o?uploadType=media&name=%s",
                         ctx->bucket, gcs_key_encoded);
    flb_sds_destroy(gcs_key_encoded);
    if (!tmp) {
        flb_sds_destroy(uri);
        flb_sds_destroy(auth);
        return -1;
    }
    uri = tmp;

    if (ctx->gcs_format != FLB_GCS_FORMAT_PARQUET &&
        ctx->compression_type == FLB_AWS_COMPRESS_GZIP) {
        tmp = flb_sds_cat(uri, "&contentEncoding=gzip", 21);
        if (!tmp) {
            flb_sds_destroy(uri);
            flb_sds_destroy(auth);
            return -1;
        }
        uri = tmp;
    }

    predefined_acl = get_predefined_acl(ctx->canned_acl);
    if (predefined_acl) {
        tmp = flb_sds_printf(&uri, "&predefinedAcl=%s", predefined_acl);
        if (!tmp) {
            flb_sds_destroy(uri);
            flb_sds_destroy(auth);
            return -1;
        }
        uri = tmp;
    }

    upload_body = buffer;
    upload_size = buffer_size;
#ifdef FLB_HAVE_ARROW_PARQUET
    if (ctx->gcs_format == FLB_GCS_FORMAT_PARQUET) {
        ret = flb_aws_compression_compress_columnar(
                    FLB_AWS_COMPRESS_FORMAT_PARQUET,
                    buffer, buffer_size,
                    &compressed_data, &compressed_size,
                    ctx->compression_type);
        if (ret != 0 || !compressed_data) {
            flb_plg_error(ctx->ins, "could not convert buffered data to parquet");
            flb_sds_destroy(auth);
            flb_sds_destroy(uri);
            if (ctx->key_fmt_has_seq_index && ctx->seq_index > 0) {
                ctx->seq_index--;
                write_seq_index(ctx->seq_index_file, ctx->seq_index);
            }
            return -1;
        }

        upload_body = compressed_data;
        upload_size = compressed_size;
    }
    else
#endif
    if (ctx->compression_type != FLB_AWS_COMPRESS_NONE) {
        ret = flb_aws_compression_compress(ctx->compression_type,
                                           buffer, buffer_size,
                                           &compressed_data, &compressed_size);
        if (ret != 0 || !compressed_data) {
            flb_plg_error(ctx->ins, "could not compress buffered data");
            flb_sds_destroy(auth);
            flb_sds_destroy(uri);
            if (ctx->key_fmt_has_seq_index && ctx->seq_index > 0) {
                ctx->seq_index--;
                write_seq_index(ctx->seq_index_file, ctx->seq_index);
            }
            return -1;
        }

        upload_body = compressed_data;
        upload_size = compressed_size;
        flb_plg_debug(ctx->ins,
                      "Pre-compression chunk size is %zu, After compression, chunk is %zu bytes",
                      buffer_size, compressed_size);
    }

    ret = gcs_upload_object(ctx, auth, uri, upload_body, upload_size);
    if (compressed_data) {
        flb_free(compressed_data);
    }
    flb_sds_destroy(auth);
    flb_sds_destroy(uri);

    if (ret != 0 && ctx->key_fmt_has_seq_index && ctx->seq_index > 0) {
        ctx->seq_index--;
        write_seq_index(ctx->seq_index_file, ctx->seq_index);
    }

    return ret;
}

static int process_upload_queue(struct flb_gcs *ctx)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct upload_queue *entry;
    char *buffer;
    size_t buffer_size;
    int ret;
    time_t now;

    /*
     * Queue processing runs during initialization or with upload_lock held.
     * Keep the re-entry guard so an entry cannot be processed twice.
     */
    if (ctx->upload_queue_processing == FLB_TRUE) {
        return 0;
    }
    ctx->upload_queue_processing = FLB_TRUE;

    mk_list_foreach_safe(head, tmp, &ctx->upload_queue) {
        entry = mk_list_entry(head, struct upload_queue, _head);
        now = time(NULL);
        if (now < entry->upload_time) {
            if (ctx->preserve_data_ordering == FLB_TRUE) {
                break;
            }
            continue;
        }
        gcs_store_file_lock(entry->upload_file);

        ret = construct_request_buffer(ctx, entry, &buffer, &buffer_size);
        if (ret == -1) {
            gcs_store_file_unlock(entry->upload_file);
            entry->retry_counter++;
            entry->upload_time = now + (2 * entry->retry_counter);
            break;
        }

        ret = upload_data(ctx, entry, buffer, buffer_size);

        if (ret == 0) {
            gcs_store_file_delete(ctx, entry->upload_file);
            flb_free(buffer);
            remove_from_queue(entry);
        }
        else {
            flb_free(buffer);
            gcs_store_file_unlock(entry->upload_file);
            entry->retry_counter++;
            entry->upload_time = now + (2 * entry->retry_counter);
            /*
             * Stop after a failed upload so the next pass can retry it
             * without blocking this thread on more network requests.
             */
            break;
        }
    }

    ctx->upload_queue_processing = FLB_FALSE;
    return 0;
}


static int attach_recovered_chunk(struct flb_gcs *ctx, struct flb_fstore_file *fsf)
{
    struct gcs_file *chunk;
    char *buf;
    size_t size;
    int ret;

    if (!fsf) {
        return -1;
    }

    if (fsf->data) {
        return 0;
    }

    chunk = flb_calloc(1, sizeof(struct gcs_file));
    if (!chunk) {
        flb_errno();
        return -1;
    }

    ret = flb_fstore_file_content_copy(ctx->fs, fsf, (void **) &buf, &size);
    if (ret != 0) {
        flb_free(chunk);
        return -1;
    }

    chunk->fsf = fsf;
    chunk->size = size;
    /* Recovered files are pending uploads, not buffers for new records. */
    gcs_store_file_seal(chunk);

    if (ctx->upload_timeout > 0) {
        chunk->create_time = time(NULL) - ctx->upload_timeout;
    }
    else {
        chunk->create_time = time(NULL);
    }

    fsf->data = chunk;
    ctx->current_buffer_size += size;

    flb_free(buf);

    return 0;
}

static void enqueue_backlog_files(struct flb_gcs *ctx)
{
    struct mk_list *head;
    struct flb_fstore_file *fsf;
    struct gcs_file *chunk;

    mk_list_foreach(head, &ctx->fs_stream->files) {
        fsf = mk_list_entry(head, struct flb_fstore_file, _head);

        if (attach_recovered_chunk(ctx, fsf) == -1) {
            flb_plg_warn(ctx->ins,
                         "could not recover buffered chunk %s, skipping",
                         fsf->name);
            continue;
        }

        chunk = fsf->data;
        if (chunk) {
            add_to_queue(ctx, chunk, (const char *) fsf->meta_buf, fsf->meta_size);
        }
    }
}


static void cb_gcs_upload(struct flb_config *config, void *data)
{
    struct flb_gcs *ctx = data;

    (void) config;

    if (!ctx) {
        return;
    }

    pthread_mutex_lock(&ctx->upload_lock);
    process_upload_queue(ctx);
    pthread_mutex_unlock(&ctx->upload_lock);
}


static int flush_init(struct flb_gcs *ctx)
{
    int ret;
    struct flb_sched *sched;

    if (ctx->timer_created == FLB_TRUE) {
        return 0;
    }

    sched = flb_sched_ctx_get();
    if (!sched) {
        return -1;
    }

    ret = flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_PERM,
                                    ctx->timer_ms, cb_gcs_upload, ctx, NULL);
    if (ret == -1) {
        return -1;
    }

    ctx->timer_created = FLB_TRUE;
    return 0;
}

/* init/flush/exit */
static int cb_gcs_init(struct flb_output_instance *ins, struct flb_config *config, void *data)
{
    int ret;
    size_t index;
    flb_sds_t normalized_compression;
    struct flb_gcs *ctx;
    const char *tmp;
    struct flb_gcp_auth_config auth_cfg;
    (void) data;

    ctx = flb_calloc(1, sizeof(*ctx));
    if (!ctx) {
        return -1;
    }
    ctx->ins = ins; ctx->config = config;
    mk_list_init(&ctx->upload_queue);
    if (pthread_mutex_init(&ctx->upload_lock, NULL) != 0) {
        flb_errno();
        flb_free(ctx);
        return -1;
    }
    ctx->upload_lock_initialized = FLB_TRUE;
    ctx->retry_time = 0;
    ctx->upload_queue_success = FLB_FALSE;
    ctx->timer_created = FLB_FALSE;

    ret = flb_output_config_map_set(ins, ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to load configuration");
        goto error;
    }

    if (!ctx->bucket) {
        flb_plg_error(ins, "'bucket' is required");
        goto error;
    }

    if (ctx->store_chunk_limit < 0) {
        flb_plg_error(ins, "'store_chunk_limit' cannot be negative");
        goto error;
    }

    if (ctx->canned_acl && !get_predefined_acl(ctx->canned_acl)) {
        flb_plg_error(ins, "unsupported canned ACL '%s'", ctx->canned_acl);
        goto error;
    }

    if (ctx->total_file_size != 0 &&
        ctx->total_file_size < FLB_GCS_MIN_TOTAL_FILE_SIZE) {
        flb_plg_error(ins, "'total_file_size' must be at least 1M "
                      "(or 0 to disable the size trigger)");
        goto error;
    }

    ctx->timer_ms = ctx->upload_timeout / 6;
    if (ctx->timer_ms >= 60) {
        ctx->timer_ms = 60000;
    }
    else if (ctx->timer_ms < 1) {
        ctx->timer_ms = 1000;
    }
    else {
        ctx->timer_ms *= 1000;
    }

    if (!ctx->store_dir) {
        ctx->store_dir = flb_sds_create("/tmp");
        if (!ctx->store_dir) {
            goto error;
        }
    }

    if (gcs_store_init(ctx) == -1) {
        goto error;
    }

    memset(&auth_cfg, 0, sizeof(auth_cfg));
    auth_cfg.config = config;
    auth_cfg.scope = FLB_GCP_SCOPE_STORAGE_READ_WRITE;
    auth_cfg.log_name = flb_output_name(ins);
    auth_cfg.credentials_file = ctx->credentials_file;
    auth_cfg.metadata_server = ctx->metadata_server;
    auth_cfg.identity_federation = ctx->has_identity_federation;
    auth_cfg.project_number = ctx->project_number;
    auth_cfg.pool_id = ctx->pool_id;
    auth_cfg.provider_id = ctx->provider_id;
    auth_cfg.identity_token_file = ctx->identity_token_file;
    auth_cfg.google_service_account = ctx->google_service_account;
    auth_cfg.subject_token_type = ctx->subject_token_type;
    auth_cfg.tls_verify = ins->tls_verify;
    auth_cfg.tls_debug = ins->tls_debug;
    auth_cfg.tls_verify_hostname = ins->tls_verify_hostname;
    auth_cfg.ipv6 = ins->host.ipv6;
    auth_cfg.tls_vhost = ins->tls_vhost;
    auth_cfg.tls_ca_path = ins->tls_ca_path;
    auth_cfg.tls_ca_file = ins->tls_ca_file;
    auth_cfg.tls_crt_file = ins->tls_crt_file;
    auth_cfg.tls_key_file = ins->tls_key_file;
    auth_cfg.tls_key_passwd = ins->tls_key_passwd;
    if (gcs_under_test_mode() == FLB_TRUE) {
        auth_cfg.metadata_fetch = gcs_mock_metadata_fetch;
    }

    ctx->auth = flb_gcp_auth_create(&auth_cfg);
    if (!ctx->auth) {
        goto error;
    }

    ctx->u = flb_upstream_create(config, FLB_GCS_DEFAULT_HOST, FLB_GCS_DEFAULT_PORT,
                                 FLB_IO_TLS, ins->tls);
    if (!ctx->u) {
        goto error;
    }
    /* apply net.* properties (keepalive, timeouts, ...) to the upstream */
    flb_output_upstream_set(ctx->u, ins);

    /*
     * The upstream must ALWAYS run in sync mode: uploads are also triggered
     * from the scheduler timer callback (and from init when a backlog is
     * recovered), which run outside of any coroutine. An async write from
     * there would try to yield a NULL coroutine and crash.
     */
    flb_stream_disable_async_mode(&ctx->u->base);

    if (ins->tp_workers < 1) {
        flb_plg_warn(ins, "uploads use synchronous network I/O; running "
                     "with 'workers 0' will block the main event loop, "
                     "configure 'workers 1' or higher");
    }

    ctx->out_format = FLB_PACK_JSON_FORMAT_LINES;
    ctx->gcs_format = FLB_GCS_FORMAT_JSON_LINES;
    ctx->json_date_format = FLB_PACK_JSON_DATE_ISO8601;
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        ret = flb_pack_to_json_date_type(tmp);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "invalid json_date_format '%s'", tmp);
            goto error;
        }
        ctx->json_date_format = ret;
    }

    /* The date key is written unless it is set to a false boolean value */
    ctx->date_key = ctx->json_date_key;
    tmp = flb_output_get_property("json_date_key", ins);
    if (tmp && flb_utils_bool(tmp) == FLB_FALSE) {
        ctx->date_key = NULL;
    }

    if (ctx->content_type == NULL) {
        ctx->content_type = flb_sds_create("application/json");
        if (!ctx->content_type) {
            goto error;
        }
    }

    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        ret = parse_output_format(tmp);
        if (ret == FLB_GCS_FORMAT_PARQUET) {
            if (enable_parquet_format(ctx) == -1) {
                goto error;
            }
        }
        else if (ret == FLB_PACK_JSON_FORMAT_JSON) {
            flb_plg_warn(ctx->ins,
                         "'json' format is interpreted as 'json_lines'");
        }
        else if (ret != FLB_PACK_JSON_FORMAT_LINES) {
            flb_plg_error(ctx->ins, "unsupported format '%s'", tmp);
            goto error;
        }
    }

    tmp = flb_output_get_property("compression", ins);
    if (!tmp) {
        ctx->compression_type = FLB_AWS_COMPRESS_NONE;
    }
    else {
        normalized_compression = flb_sds_create(tmp);
        if (!normalized_compression) {
            flb_errno();
            goto error;
        }

        for (index = 0; index < flb_sds_len(normalized_compression); index++) {
            normalized_compression[index] =
                tolower((unsigned char) normalized_compression[index]);
        }

        if (strcmp(normalized_compression, "none") == 0) {
            ret = FLB_AWS_COMPRESS_NONE;
        }
        else {
            ret = flb_aws_compression_get_type(normalized_compression);
        }

        flb_sds_destroy(normalized_compression);
        if (ret == -1) {
            flb_plg_error(ins, "unsupported compression type '%s'", tmp);
            goto error;
        }
        ctx->compression_type = ret;
    }

    if (ctx->gcs_format == FLB_GCS_FORMAT_PARQUET) {
        if (validate_parquet_compression(ctx->compression_type) != 0) {
            flb_plg_error(ins,
                          "'%s' is not a supported parquet compression codec",
                          tmp);
            goto error;
        }
    }
    else if (ctx->compression_type != FLB_AWS_COMPRESS_NONE &&
             ctx->compression_type != FLB_AWS_COMPRESS_GZIP) {
        flb_plg_error(ins, "unsupported compression type '%s'", tmp);
        goto error;
    }

    if (strstr(ctx->gcs_key_format, "$INDEX")) {
        if (init_seq_index(ctx) == -1) {
            goto error;
        }
        ctx->key_fmt_has_seq_index = FLB_TRUE;
    }
    if (strstr(ctx->gcs_key_format, "$UUID")) {
        ctx->key_fmt_has_uuid = FLB_TRUE;
    }

    if (gcs_store_has_data(ctx) == FLB_TRUE) {
        enqueue_backlog_files(ctx);

        if (mk_list_size(&ctx->upload_queue) > 0 && flush_init(ctx) == -1) {
            goto error;
        }

        process_upload_queue(ctx);
    }

    flb_output_set_context(ins, ctx);
    return 0;

error:
    gcs_ctx_destroy(ctx, config);
    return -1;
}

/*
 * Buffer the payload in the local store and process the upload queue.
 * Must be called with ctx->upload_lock held; returns an FLB_OUTPUT_RETURN
 * status code.
 */
static int gcs_flush_payload(struct flb_gcs *ctx,
                             struct flb_event_chunk *event_chunk,
                             flb_sds_t payload)
{
    flb_sds_t tag_name = NULL;
    int tag_name_len;
    int ret;
    struct gcs_file *chunk;

    if (flush_init(ctx) == -1) {
        return FLB_RETRY;
    }

    if (ctx->unify_tag == FLB_TRUE) {
        tag_name = ctx->unify_tag_name;
        tag_name_len = flb_sds_len(ctx->unify_tag_name);
    }
    else {
        tag_name = event_chunk->tag;
        tag_name_len = flb_sds_len(event_chunk->tag);
    }

    chunk = gcs_store_file_get(ctx, tag_name, tag_name_len);

    /* total_file_size reached: upload the current file, start a new one */
    if (chunk && ctx->total_file_size > 0 &&
        chunk->size + flb_sds_len(payload) > ctx->total_file_size) {
        ret = seal_and_queue_for_upload(ctx, chunk, tag_name, tag_name_len);
        if (ret == -1) {
            return FLB_RETRY;
        }
        chunk = NULL;
    }

    if (gcs_store_buffer_put(ctx, chunk, tag_name, tag_name_len,
                             payload, flb_sds_len(payload)) == -1) {
        return FLB_RETRY;
    }

    chunk = gcs_store_file_get(ctx, tag_name, tag_name_len);
    if (!chunk) {
        return FLB_RETRY;
    }

    if (ctx->total_file_size > 0 && chunk->size >= ctx->total_file_size) {
        ret = seal_and_queue_for_upload(ctx, chunk, tag_name, tag_name_len);
    }
    else {
        ret = add_to_queue(ctx, chunk, tag_name, tag_name_len);
    }
    if (ret == -1) {
        return FLB_RETRY;
    }

    /*
     * Non-order-preserving mode: try to flush every due queue entry.
     * Preserve-order mode: flush due entries strictly in FIFO order and
     * stop at the first failure.
     */
    ret = process_upload_queue(ctx);
    if (ret == -1) {
        return FLB_ERROR;
    }

    return FLB_OK;
}

static void cb_gcs_flush(struct flb_event_chunk *event_chunk, struct flb_output_flush *out_flush,
                         struct flb_input_instance *i_ins, void *out_context, struct flb_config *config)
{
    struct flb_gcs *ctx = out_context;
    flb_sds_t payload;
    int ret;

    (void) out_flush;
    (void) i_ins;

    payload = flb_pack_msgpack_to_json_format(event_chunk->data, event_chunk->size,
                                              ctx->out_format, ctx->json_date_format,
                                              ctx->date_key, config->json_escape_unicode);
    if (!payload) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /*
     * Flushes may run concurrently from several workers, and the upload
     * timer runs in one of them: serialize all access to the upload queue,
     * the local file store and the sequence index. The upstream is in sync
     * mode, so no coroutine switch happens while the lock is held.
     */
    pthread_mutex_lock(&ctx->upload_lock);
    ret = gcs_flush_payload(ctx, event_chunk, payload);
    pthread_mutex_unlock(&ctx->upload_lock);

    flb_sds_destroy(payload);
    FLB_OUTPUT_RETURN(ret);
}

static int gcs_ctx_destroy(void *data, struct flb_config *config)
{
    struct flb_gcs *ctx = data; (void) config;
    if (!ctx) {
        return 0;
    }

    /*
     * Leave pending chunks in the file store for recovery on the next startup.
     * Synchronous network requests here would delay shutdown.
     */
    clear_upload_queue(ctx);

    clear_file_chunks(ctx);

    gcs_store_exit(ctx);

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    flb_gcp_auth_destroy(ctx->auth);

    if (ctx->seq_index_file) {
        flb_sds_destroy(ctx->seq_index_file);
    }

    if (ctx->upload_lock_initialized == FLB_TRUE) {
        pthread_mutex_destroy(&ctx->upload_lock);
    }
    flb_free(ctx);

    return 0;
}

static int cb_gcs_exit(void *data, struct flb_config *config)
{
    gcs_ctx_destroy(data, config);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "format", "json_lines",
     0, FLB_FALSE, 0,
     "Output format. Supported values: json_lines and parquet. When format is "
     "parquet, compression selects the page-level codec."
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_format", NULL,
     0, FLB_FALSE, 0,
     FBL_PACK_JSON_DATE_FORMAT_DESCRIPTION
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_gcs, json_date_key),
     "Specifies the name of the date field in output. Set to false, off or no "
     "to disable it."
    },
    {
     FLB_CONFIG_MAP_STR, "bucket", NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, bucket),
     "GCS bucket."
    },
    {
     FLB_CONFIG_MAP_STR, "gcs_key_format", "fluent-bit-logs/$TAG/%Y/%m/%d/%H/%M/%S",
     0, FLB_TRUE, offsetof(struct flb_gcs, gcs_key_format),
     "Format string for keys in GCS."
    },
    {
     FLB_CONFIG_MAP_STR, "gcs_key_format_tag_delimiters", ".",
     0, FLB_TRUE, offsetof(struct flb_gcs, tag_delimiters),
     "Characters used to split tag parts for gcs_key_format."
    },
    {
     FLB_CONFIG_MAP_BOOL, "static_file_path", "false",
     0, FLB_TRUE, offsetof(struct flb_gcs, static_file_path),
     "Disable random suffix when UUID is not used in gcs_key_format."
    },
    {
     FLB_CONFIG_MAP_STR, "canned_acl", NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, canned_acl),
     "Predefined canned ACL for objects."
    },
    {
     FLB_CONFIG_MAP_TIME, "upload_timeout", "10m",
     0, FLB_TRUE, offsetof(struct flb_gcs, upload_timeout),
     "Upload timeout before chunk is flushed."
    },
    {
     FLB_CONFIG_MAP_SIZE, "total_file_size", "100M",
     0, FLB_TRUE, offsetof(struct flb_gcs, total_file_size),
     "Buffered data size per tag that triggers an upload before upload_timeout. "
     "Batches are not split, so objects can exceed this size. Minimum 1M, "
     "0 disables the size trigger. Ordered uploads still wait for older files."
    },
    {
     FLB_CONFIG_MAP_BOOL, "send_content_md5", "false",
     0, FLB_TRUE, offsetof(struct flb_gcs, send_content_md5),
     "Send Content-MD5 header with uploads."
    },
    {
     FLB_CONFIG_MAP_BOOL, "preserve_data_ordering", "false",
     0, FLB_TRUE, offsetof(struct flb_gcs, preserve_data_ordering),
     "Enable preserve-order upload queue semantics."
    },
    {
     FLB_CONFIG_MAP_INT, "store_chunk_limit", "0",
     0, FLB_TRUE, offsetof(struct flb_gcs, store_chunk_limit),
     "Maximum number of buffered fstore chunks for out_gcs (0 means unlimited)."
    },
    {
     FLB_CONFIG_MAP_SIZE, "store_dir_limit_size", (char *) NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, store_dir_limit_size),
     "Limit total buffered bytes in store_dir (0 means unlimited)."
    },
    {
     FLB_CONFIG_MAP_STR, "content_type", "application/json",
     0, FLB_TRUE, offsetof(struct flb_gcs, content_type),
     "Content type. Defaults to application/json for JSON lines and "
     "application/vnd.apache.parquet for Parquet."
    },
    {
     FLB_CONFIG_MAP_STR, "google_service_credentials", NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, credentials_file),
     "Service account JSON file."
    },
    {
     FLB_CONFIG_MAP_STR, "metadata_server", FLB_GCS_METADATA_SERVER,
     0, FLB_TRUE, offsetof(struct flb_gcs, metadata_server),
     "GCE/GKE metadata server used when no credentials file is configured."
    },
    {
     FLB_CONFIG_MAP_BOOL, "enable_identity_federation", "false",
     0, FLB_TRUE, offsetof(struct flb_gcs, has_identity_federation),
     "Enable Workload Identity Federation (external account) instead of a "
     "static service account key."
    },
    {
     FLB_CONFIG_MAP_STR, "project_number", NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, project_number),
     "GCP project number owning the workload identity pool (identity federation)."
    },
    {
     FLB_CONFIG_MAP_STR, "pool_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, pool_id),
     "Workload identity pool id (identity federation)."
    },
    {
     FLB_CONFIG_MAP_STR, "provider_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, provider_id),
     "Workload identity pool provider id (identity federation)."
    },
    {
     FLB_CONFIG_MAP_STR, "identity_token_file", NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, identity_token_file),
     "Path to the OIDC subject token file used as the federation credential "
     "source (identity federation)."
    },
    {
     FLB_CONFIG_MAP_STR, "google_service_account", NULL,
     0, FLB_TRUE, offsetof(struct flb_gcs, google_service_account),
     "Service account to impersonate. If unset, the federated token is used "
     "directly against GCS (direct resource access)."
    },
    {
     FLB_CONFIG_MAP_STR, "subject_token_type", FLB_GCP_STS_SUBJECT_TOKEN_TYPE,
     0, FLB_TRUE, offsetof(struct flb_gcs, subject_token_type),
     "OIDC subject token type for identity federation."
    },
    {
     FLB_CONFIG_MAP_STR, "store_dir", "/tmp/fluent-bit/gcs",
     0, FLB_TRUE, offsetof(struct flb_gcs, store_dir),
     "Directory for intermediate files."
    },
    {
     FLB_CONFIG_MAP_STR, "compression", "none",
     0, FLB_FALSE, 0,
     "Compression type. JSON lines support none and gzip. Parquet supports "
     "none, snappy, gzip, and zstd."
    },
    {
     FLB_CONFIG_MAP_BOOL, "unify_tag", "false",
     0, FLB_TRUE, offsetof(struct flb_gcs, unify_tag),
     "Unify all tags into a single buffer file (disables per-tag buffering)."
    },
    {
     FLB_CONFIG_MAP_STR, "unify_tag_name", "fluent-bit-buffer-file-unify-tag.log",
     0, FLB_TRUE, offsetof(struct flb_gcs, unify_tag_name),
     "Buffer file tag used when unify_tag is enabled."
    },
    {0}
};

struct flb_output_plugin out_gcs_plugin = {
    .name        = "gcs",
    .description = "Google Cloud Storage",
    .cb_init     = cb_gcs_init,
    .cb_flush    = cb_gcs_flush,
    .cb_exit     = cb_gcs_exit,
    .event_type  = FLB_OUTPUT_LOGS,
    .config_map  = config_map,
    .flags       = FLB_OUTPUT_NET | FLB_IO_TLS,
    .workers     = 1,
};
