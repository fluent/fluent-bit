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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/aws/flb_aws_compress.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_input_blob.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <msgpack.h>

#ifdef FLB_HAVE_PARQUET_ENCODER
#include <fluent-bit/flb_parquet.h>
#endif

#include "s3.h"
#include "s3_multipart.h"
#include "s3_store.h"
#include "s3_stream.h"
#include "s3_blob.h"
#include "s3_auth.h"
#include "s3_queue.h"

#define DEFAULT_S3_PORT 443
#define DEFAULT_S3_INSECURE_PORT 80

struct flb_aws_client *s3_get_client(struct flb_s3 *ctx)
{
    if (!ctx) {
        return NULL;
    }

    return ctx->s3_client;
}

static struct flb_aws_client *create_s3_client(struct flb_s3 *ctx)
{
    struct flb_aws_client *client;
    struct flb_aws_client_generator *generator;

    if (ctx->client_generator) {
        generator = ctx->client_generator;
    }
    else {
        generator = flb_aws_client_generator();
    }

    client = generator->create();
    if (!client) {
        return NULL;
    }

    client->name = "s3_client";
    client->has_auth = FLB_TRUE;
    client->provider = ctx->provider;
    client->region = ctx->region;
    client->service = "s3";
    client->port = ctx->port;
    client->flags = FLB_HTTP_11;
    client->proxy = NULL;
    client->s3_mode = S3_MODE_SIGNED_PAYLOAD;
    client->retry_requests = ctx->retry_requests;

    if (ctx->insecure == FLB_TRUE) {
        client->upstream = flb_upstream_create(ctx->ins->config, ctx->endpoint, ctx->port,
                                               FLB_IO_TCP, NULL);
    } else {
        client->upstream = flb_upstream_create(ctx->ins->config, ctx->endpoint, ctx->port,
                                               FLB_IO_TLS, ctx->client_tls);
    }

    if (!client->upstream) {
        flb_plg_error(ctx->ins, "Connection initialization error");
        flb_aws_client_destroy(client);
        return NULL;
    }

    flb_output_upstream_set(client->upstream, ctx->ins);

    /*
     * Disable keepalive by default - multipart uploads have long intervals
     * between requests which can cause connection reuse issues.
     */
    flb_stream_disable_keepalive(&client->upstream->base);

    client->host = ctx->endpoint;

    /* Sync mode: avoid race condition in queue/list access. Single worker for same reason. */
    flb_stream_disable_async_mode(&client->upstream->base);

    if (ctx->authorization_endpoint_url != NULL) {
        client->has_auth = FLB_FALSE;
    }

    return client;
}

#ifdef FLB_SYSTEM_WINDOWS
static int setenv(const char *name, const char *value, int overwrite)
{
    return SetEnvironmentVariableA(name, value);
}
#endif

/* Check if plugin is running under test mode */
int s3_plugin_under_test()
{
    if (getenv("FLB_S3_PLUGIN_UNDER_TEST") != NULL) {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

/* Timer callback - processes upload queue and retries pending uploads */
void cb_s3_upload(struct flb_config *ctx, void *data);

/* Concatenate two path segments with '/' separator */
static flb_sds_t concat_path(char *p1, char *p2)
{
    flb_sds_t dir;
    flb_sds_t tmp;

    dir = flb_sds_create_size(64);

    tmp = flb_sds_printf(&dir, "%s/%s", p1, p2);
    if (!tmp) {
        flb_errno();
        flb_sds_destroy(dir);
        return NULL;
    }
    dir = tmp;

    return dir;
}

/* Reads in index value from metadata file and sets seq_index to value */
static int read_seq_index(char *seq_index_file, uint64_t *seq_index)
{
    FILE *fp;
    int ret;

    fp = fopen(seq_index_file, "r");
    if (fp == NULL) {
        flb_errno();
        return -1;
    }

    ret = fscanf(fp, "%"PRIu64, seq_index);
    if (ret != 1) {
        fclose(fp);
        flb_errno();
        return -1;
    }

    fclose(fp);
    return 0;
}

/* Writes index value to metadata file */
int write_seq_index(char *seq_index_file, uint64_t seq_index)
{
    FILE *fp;
    int ret;

    fp = fopen(seq_index_file, "w+");
    if (fp == NULL) {
        flb_errno();
        return -1;
    }

    ret = fprintf(fp, "%"PRIu64, seq_index);
    if (ret < 0) {
        fclose(fp);
        flb_errno();
        return -1;
    }

    fclose(fp);
    return 0;
}

static int init_seq_index(void *context) {
    int ret;
    const char *tmp;
    char tmp_buf[1024];
    struct flb_s3 *ctx = context;

    ctx->key_fmt_has_seq_index = FLB_TRUE;

    ctx->stream_metadata = flb_fstore_stream_create(ctx->fs, "sequence");
    if (!ctx->stream_metadata) {
        flb_plg_error(ctx->ins, "could not initialize metadata stream");
        flb_fstore_destroy(ctx->fs);
        ctx->fs = NULL;
        return -1;
    }

    /* Construct directories and file path names */
    ctx->metadata_dir = flb_sds_create(ctx->stream_metadata->path);
    if (ctx->metadata_dir == NULL) {
        flb_plg_error(ctx->ins, "Failed to create metadata path");
        flb_errno();
        return -1;
    }
    tmp = "/index_metadata";
    ret = flb_sds_cat_safe(&ctx->metadata_dir, tmp, strlen(tmp));
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to create metadata path");
        flb_errno();
        return -1;
    }

    ctx->seq_index_file = flb_sds_create(ctx->metadata_dir);
    if (ctx->seq_index_file == NULL) {
        flb_plg_error(ctx->ins, "Failed to create sequential index file path");
        flb_errno();
        return -1;
    }
    tmp = "/seq_index_";
    ret = flb_sds_cat_safe(&ctx->seq_index_file, tmp, strlen(tmp));
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to create sequential index file path");
        flb_errno();
        return -1;
    }

    ret = snprintf(tmp_buf, sizeof(tmp_buf), "%d", ctx->ins->id);
    if (ret < 0 || ret >= sizeof(tmp_buf)) {
        flb_plg_error(ctx->ins, "Failed to format sequential index file path");
        flb_errno();
        return -1;
    }
    ret = flb_sds_cat_safe(&ctx->seq_index_file, tmp_buf, strlen(tmp_buf));
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to create sequential index file path");
        flb_errno();
        return -1;
    }

    /* Create directory path if it doesn't exist */
#ifdef FLB_SYSTEM_WINDOWS
    ret = mkdir(ctx->metadata_dir);
#else
    ret = mkdir(ctx->metadata_dir, 0700);
#endif
    if (ret < 0 && errno != EEXIST) {
        flb_plg_error(ctx->ins, "Failed to create metadata directory");
        return -1;
    }

    /* Check if index file doesn't exist and set index value */
    if (access(ctx->seq_index_file, F_OK) != 0) {
        ctx->seq_index = 0;
        ret = write_seq_index(ctx->seq_index_file, ctx->seq_index);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to write to sequential index metadata file");
            return -1;
        }
    }
    else {
        ret = read_seq_index(ctx->seq_index_file, &ctx->seq_index);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to read from sequential index "
                          "metadata file");
            return -1;
        }
        flb_plg_info(ctx->ins, "Successfully recovered index. "
                     "Continuing at index=%"PRIu64, ctx->seq_index);
    }
    return 0;
}

static void s3_context_destroy(struct flb_s3 *ctx)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct upload_queue *upload_contents;

    if (!ctx) {
        return;
    }

#ifdef FLB_HAVE_PARQUET_ENCODER
    if (ctx->cached_arrow_schema) {
        flb_parquet_schema_destroy(ctx->cached_arrow_schema);
        ctx->cached_arrow_schema = NULL;
    }
#endif

    /* Destroy provider wrapper first (STS) */
    if (ctx->provider) {
        flb_aws_provider_destroy(ctx->provider);
        ctx->provider = NULL;
    }

    /* Destroy base provider if distinct */
    if (ctx->base_provider && ctx->base_provider != ctx->provider) {
        flb_aws_provider_destroy(ctx->base_provider);
        ctx->base_provider = NULL;
    }

    if (ctx->provider_tls) {
        flb_tls_destroy(ctx->provider_tls);
    }

    if (ctx->sts_provider_tls) {
        flb_tls_destroy(ctx->sts_provider_tls);
    }

    if (ctx->client_tls) {
        flb_tls_destroy(ctx->client_tls);
    }

    if (ctx->free_endpoint == FLB_TRUE) {
        flb_free(ctx->endpoint);
    }

    if (ctx->buffer_dir) {
        flb_sds_destroy(ctx->buffer_dir);
    }

    if (ctx->metadata_dir) {
        flb_sds_destroy(ctx->metadata_dir);
    }

    if (ctx->seq_index_file) {
        flb_sds_destroy(ctx->seq_index_file);
    }

    if (ctx->authorization_endpoint_upstream != NULL) {
        flb_upstream_destroy(ctx->authorization_endpoint_upstream);
    }

    if (ctx->authorization_endpoint_tls_context != NULL) {
        flb_tls_destroy(ctx->authorization_endpoint_tls_context);
    }

    mk_list_foreach_safe(head, tmp, &ctx->upload_queue) {
        upload_contents = mk_list_entry(head, struct upload_queue, _head);
        s3_queue_remove(ctx, upload_contents);
    }

    if (ctx->s3_client) {
        flb_aws_client_destroy(ctx->s3_client);
    }

    flb_free(ctx);
}

static int cb_s3_init(struct flb_output_instance *ins,
                      struct flb_config *config, void *data)
{
    int ret;
    flb_sds_t tmp_sds;
    char *role_arn = NULL;
    char *session_name;
    const char *tmp;
    struct flb_s3 *ctx = NULL;
    struct flb_aws_client_generator *generator;
    struct flb_out_s3_init_options *init_options = NULL;
    (void) config;

    /* Check for init options (used by tests for dependency injection) */
    init_options = (struct flb_out_s3_init_options *) data;
    char *ep;
    struct flb_split_entry *tok;
    struct mk_list *split;
    int list_size;

    ctx = flb_calloc(1, sizeof(struct flb_s3));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    mk_list_init(&ctx->upload_queue);

    /* Initialize client generator (default or injected) */
    if (init_options) {
        ctx->client_generator = init_options->client_generator;
    }
    else {
        ctx->client_generator = flb_aws_client_generator();
    }

    ctx->initial_upload_done = FLB_FALSE;

    ctx->retry_time = 0;
    ctx->upload_queue_success = FLB_FALSE;
    ctx->is_exiting = FLB_FALSE;
    ctx->needs_recovery = FLB_FALSE;

    if(ctx->ins->retry_limit < 0) {
        ctx->ins->retry_limit = MAX_UPLOAD_ERRORS;
    }

    flb_output_set_context(ins, ctx);

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        return -1;
    }

    /* Fluent Bit uses -1 to indicate undefined for size_t fields */
    if (ctx->ins->total_limit_size != -1) {
        flb_plg_warn(ctx->ins, "Please use 'store_dir_limit_size' with s3 output instead of 'storage.total_limit_size'. "
                     "S3 has its own buffer files located in the store_dir.");
    }

    ctx->date_key = ctx->json_date_key;
    tmp = flb_output_get_property("json_date_key", ins);
    if (tmp) {
        if (flb_utils_bool(tmp) == FLB_FALSE) {
            ctx->date_key = NULL;
        }
    }

    ctx->json_date_format = FLB_PACK_JSON_DATE_ISO8601;
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        ret = flb_pack_to_json_date_type(tmp);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "invalid json_date_format '%s'. ", tmp);
            return -1;
        }
        else {
            ctx->json_date_format = ret;
        }
    }

    tmp = flb_output_get_property("bucket", ins);
    if (!tmp) {
        flb_plg_error(ctx->ins, "'bucket' is a required parameter");
        return -1;
    }

    /* Append bucket name to store_dir to support multiple plugin instances */
    tmp_sds = concat_path(ctx->store_dir, ctx->bucket);
    if (!tmp_sds) {
        flb_plg_error(ctx->ins, "Could not construct buffer path");
        return -1;
    }
    ctx->buffer_dir = tmp_sds;

    ret = s3_store_init(ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Failed to initialize S3 storage: %s",
                      ctx->store_dir);
        return -1;
    }

    tmp = flb_output_get_property("s3_key_format", ins);
    if (tmp) {
        if (tmp[0] != '/') {
            flb_plg_error(ctx->ins, "'s3_key_format' must start with a '/'");
            return -1;
        }
        if (strstr((char *) tmp, "$INDEX")) {
            ret = init_seq_index(ctx);
            if (ret < 0) {
                return -1;
            }
        }
        if (strstr((char *) tmp, "$UUID")) {
            ctx->key_fmt_has_uuid = FLB_TRUE;
        }
    }

    if (ctx->file_size <= 0) {
        flb_plg_error(ctx->ins, "Failed to parse total_file_size %s", tmp);
        return -1;
    }
    if (ctx->file_size > MAX_FILE_SIZE) {
        flb_plg_error(ctx->ins, "Max total_file_size is %s bytes", MAX_FILE_SIZE_STR);
        return -1;
    }
    flb_plg_info(ctx->ins, "total_file_size: %llu MiB",
                (unsigned long long)(ctx->file_size / S3_MiB));

    ctx->compression = FLB_AWS_COMPRESS_NONE;

    tmp = flb_output_get_property("compression", ins);
    if (tmp) {
        ret = flb_aws_compression_get_type(tmp);

        if (ret == FLB_AWS_COMPRESS_ARROW || ret == FLB_AWS_COMPRESS_PARQUET) {
#ifndef FLB_HAVE_PARQUET_ENCODER
            flb_plg_error(ctx->ins,
                         "Parquet format is not supported in this build. "
                         "Rebuild with -DFLB_PARQUET_ENCODER=On.");
            return -1;
#else
            flb_plg_warn(ctx->ins,
                "DEPRECATED: compression=%s is deprecated. Use format=parquet instead. "
                "Defaulting to GZIP compression for Parquet.", tmp);
            ctx->format = FLB_S3_FORMAT_PARQUET;
            ctx->compression = FLB_AWS_COMPRESS_GZIP;
#endif
        }
        else if (ret == -1) {
            flb_plg_error(ctx->ins, "Unknown compression type: %s", tmp);
            return -1;
        }
        else {
            ctx->compression = ret;
        }
    }

    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        if (strcasecmp(tmp, "json") == 0) {
            ctx->format = FLB_S3_FORMAT_JSON;
        }
#ifdef FLB_HAVE_PARQUET_ENCODER
        else if (strcasecmp(tmp, "parquet") == 0) {
            ctx->format = FLB_S3_FORMAT_PARQUET;
        }
#endif
        else {
#ifdef FLB_HAVE_PARQUET_ENCODER
            flb_plg_error(ctx->ins, "Invalid format '%s'. Supported formats: (json, parquet)", tmp);
#else
            flb_plg_error(ctx->ins, "Invalid format '%s'. Supported formats: (json), parquet requires build with -DFLB_PARQUET_ENCODER=On", tmp);
#endif
            return -1;
        }
    }
    else if (ctx->format != FLB_S3_FORMAT_PARQUET) {
        ctx->format = FLB_S3_FORMAT_JSON;
    }

#ifdef FLB_HAVE_PARQUET_ENCODER
    if (ctx->format == FLB_S3_FORMAT_PARQUET) {
        if (ctx->schema_str == NULL) {
            flb_plg_error(ctx->ins, "schema_str is required when format=parquet");
            return -1;
        }

        /*
         * CRITICAL: Pre-parse and cache Arrow schema in main thread context.
         * This avoids stack overflow when yyjson recursively parses the schema
         * in Fluent Bit's small coroutine stacks (37KB) during chunk processing.
         */
        char parse_error[512];
        ctx->cached_arrow_schema = flb_parquet_schema_create(
            ctx->schema_str,
            parse_error,
            sizeof(parse_error)
        );

        if (ctx->cached_arrow_schema == NULL) {
            flb_plg_error(ctx->ins, "Failed to parse schema_str: %s", parse_error);
            return -1;
        }

        flb_plg_info(ctx->ins, "schema_str parsed and cached successfully");

        if (ctx->compression == FLB_AWS_COMPRESS_NONE) {
            flb_plg_warn(ctx->ins,
                        "format=parquet with compression=none: Parquet files will be uncompressed. "
                        "For better storage efficiency and query performance, consider enabling compression.");
        }

        flb_plg_info(ctx->ins,
                    "format=parquet: using %s compression",
                    ctx->compression == FLB_AWS_COMPRESS_GZIP ? "GZIP" :
                    ctx->compression == FLB_AWS_COMPRESS_ZSTD ? "ZSTD" :
                    ctx->compression == FLB_AWS_COMPRESS_SNAPPY ? "SNAPPY" : "NONE");
    }
#endif

    tmp = flb_output_get_property("content_type", ins);
    if (tmp) {
        ctx->content_type = (char *) tmp;
    }

    /* Initialize upload_chunk_size (unified part size for all upload types) */
    {
        size_t user_configured = 0;

        /*
         * Support both upload_chunk_size and part_size (deprecated) parameters.
         * If both are set, upload_chunk_size takes precedence.
         * This ensures backward compatibility while unifying the configuration.
         */
        tmp = flb_output_get_property("upload_chunk_size", ins);
        if (tmp) {
            user_configured = ctx->upload_chunk_size;
            if (user_configured <= 0) {
                flb_plg_error(ctx->ins, "Failed to parse upload_chunk_size");
                return -1;
            }
        }
        else if (ctx->part_size > 0) {
            /* part_size is set but upload_chunk_size is not - use part_size value */
            flb_plg_warn(ctx->ins, "'part_size' is deprecated, please use 'upload_chunk_size' instead");
            user_configured = ctx->part_size;
        }

        ctx->upload_chunk_size = flb_s3_calculate_optimal_part_size(
            user_configured,
            ctx->file_size
        );

        flb_plg_info(ctx->ins, "upload_chunk_size=%lluM",
                    (unsigned long long)(ctx->upload_chunk_size / S3_MiB));
    }

    tmp = flb_output_get_property("endpoint", ins);
    if (tmp) {
        ctx->insecure = strncmp(tmp, "http://", 7) == 0 ? FLB_TRUE : FLB_FALSE;
        if (ctx->insecure == FLB_TRUE) {
          ep = removeProtocol((char *) tmp, "http://");
        }
        else {
          ep = removeProtocol((char *) tmp, "https://");
        }

        split = flb_utils_split((const char *)ep, ':', 1);
        if (!split) {
          flb_errno();
          return -1;
        }
        list_size = mk_list_size(split);
        if (list_size > 2) {
          flb_plg_error(ctx->ins, "Failed to split endpoint");
          flb_utils_split_free(split);
          return -1;
        }

        tok = mk_list_entry_first(split, struct flb_split_entry, _head);
        ctx->endpoint = flb_strndup(tok->value, tok->len);
        if (!ctx->endpoint) {
            flb_errno();
            flb_utils_split_free(split);
            return -1;
        }
        ctx->free_endpoint = FLB_TRUE;
        if (list_size == 2) {
          tok = mk_list_entry_next(&tok->_head, struct flb_split_entry, _head, split);
          ctx->port = atoi(tok->value);
        }
        else {
          ctx->port = ctx->insecure == FLB_TRUE ? DEFAULT_S3_INSECURE_PORT : DEFAULT_S3_PORT;
        }
        flb_utils_split_free(split);
    }
    else {
        ctx->endpoint = flb_aws_endpoint("s3", ctx->region);
        ctx->insecure = FLB_FALSE;
        ctx->port = DEFAULT_S3_PORT;
        ctx->free_endpoint = FLB_TRUE;
        if (!ctx->endpoint) {
            flb_plg_error(ctx->ins,  "Could not construct S3 endpoint");
            return -1;
        }
    }

    tmp = flb_output_get_property("sts_endpoint", ins);
    if (tmp) {
        ctx->sts_endpoint = (char *) tmp;
    }

    tmp = flb_output_get_property("canned_acl", ins);
    if (tmp) {
        ctx->canned_acl = (char *) tmp;
    }

    tmp = flb_output_get_property("storage_class", ins);
    if (tmp) {
        ctx->storage_class = (char *) tmp;
    }

    if (ctx->insecure == FLB_FALSE) {
        ctx->client_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                         ins->tls_verify,
                                         ins->tls_debug,
                                         ins->tls_vhost,
                                         ins->tls_ca_path,
                                         ins->tls_ca_file,
                                         ins->tls_crt_file,
                                         ins->tls_key_file,
                                         ins->tls_key_passwd);
        if (!ctx->client_tls) {
            flb_plg_error(ctx->ins, "Failed to create tls context");
            return -1;
        }
    }

    ctx->provider_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                       FLB_TRUE,
                                       ins->tls_debug,
                                       ins->tls_vhost,
                                       ins->tls_ca_path,
                                       ins->tls_ca_file,
                                       ins->tls_crt_file,
                                       ins->tls_key_file,
                                       ins->tls_key_passwd);
    if (!ctx->provider_tls) {
        flb_errno();
        return -1;
    }

    ctx->provider = flb_standard_chain_provider_create(config,
                                                       ctx->provider_tls,
                                                       ctx->region,
                                                       ctx->sts_endpoint,
                                                       NULL,
                                                       ctx->client_generator,
                                                       ctx->profile);

    if (!ctx->provider) {
        flb_plg_error(ctx->ins, "Failed to create AWS Credential Provider");
        return -1;
    }

    tmp = flb_output_get_property("role_arn", ins);
    if (tmp) {
        ctx->base_provider = ctx->provider;
        role_arn = (char *) tmp;

        ctx->sts_provider_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                               FLB_TRUE,
                                               ins->tls_debug,
                                               ins->tls_vhost,
                                               ins->tls_ca_path,
                                               ins->tls_ca_file,
                                               ins->tls_crt_file,
                                               ins->tls_key_file,
                                               ins->tls_key_passwd);

        if (!ctx->sts_provider_tls) {
            flb_errno();
            return -1;
        }

        session_name = flb_sts_session_name();
        if (!session_name) {
            flb_plg_error(ctx->ins, "Failed to create aws iam role "
                      "session name");
            flb_errno();
            return -1;
        }

        ctx->provider = flb_sts_provider_create(config,
                                                ctx->sts_provider_tls,
                                                ctx->base_provider,
                                                ctx->external_id,
                                                role_arn,
                                                session_name,
                                                ctx->region,
                                                ctx->sts_endpoint,
                                                NULL,
                                                flb_aws_client_generator());
        flb_free(session_name);
        if (!ctx->provider) {
            flb_plg_error(ctx->ins, "Failed to create AWS STS Credential "
                         "Provider");
            return -1;
        }
    }

    ctx->has_old_buffers = s3_store_has_data(ctx);

    ctx->provider->provider_vtable->sync(ctx->provider);
    ctx->provider->provider_vtable->init(ctx->provider);

    ctx->timer_created = FLB_FALSE;
    /*
     * Timer interval for upload queue processing.
     * In test mode, use a shorter interval (500ms) for faster test execution.
     * In production, use 5 seconds for responsive but efficient processing.
     */
    if (s3_plugin_under_test()) {
        ctx->timer_ms = 500;  /* 500ms in test mode for faster tests */
    }
    else {
        ctx->timer_ms = 5000; /* 5 seconds in production */
    }

    if (ctx->authorization_endpoint_url != NULL) {
        ret = s3_auth_init_endpoint(ctx);

        if (ret != 0) {
            flb_plg_error(ctx->ins, "Failed to initialize authorization endpoint upstream");
            return -1;
        }
    }

    ctx->provider->provider_vtable->upstream_set(ctx->provider, ctx->ins);

    /* Initialize blob database if configured */
    if (ctx->blob_database_file != NULL) {
        /* Blob uploads now use the unified upload_chunk_size parameter */
        flb_plg_info(ctx->ins, "Blob upload_chunk_size: %llu MiB (unified with log uploads)",
                    (unsigned long long)(ctx->upload_chunk_size / S3_MiB));

        ret = flb_blob_db_open(&ctx->blob_db, config, ctx->blob_database_file);
        if (ret != FLB_BLOB_DB_SUCCESS) {
            return -1;
        }
    }

    /* Initialize upload queue mutex for thread-safe access */
    ret = pthread_mutex_init(&ctx->upload_queue_lock, NULL);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "Failed to initialize upload queue mutex");
        if (ctx->blob_database_file != NULL) {
            flb_blob_db_close(&ctx->blob_db);
        }
        return -1;
    }

    /* Create S3 client (single instance for non-worker mode) */
    ctx->s3_client = create_s3_client(ctx);
    if (!ctx->s3_client) {
        flb_plg_error(ctx->ins, "Failed to create S3 client");
        return -1;
    }

    /*
     * Create timer for upload processing.
     * Timer is created immediately to ensure responsive queue processing.
     */
    if (ctx->timer_created == FLB_FALSE) {
        /*
         * In single-threaded mode, flb_sched_ctx_get() returns the main engine scheduler
         * which is what we want.
         */
        struct flb_sched *sched = flb_sched_ctx_get();
        ret = flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_PERM,
                                        ctx->timer_ms, cb_s3_upload, ctx, NULL);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to create upload timer");
            return -1;
        }
        ctx->timer_created = FLB_TRUE;
        flb_plg_debug(ctx->ins, "Upload timer created (interval: %dms)", ctx->timer_ms);
    }

    /*
     * Deferred recovery: Defer recovery to first timer callback.
     * This avoids blocking initialization if there are many pending files.
     * The timer will execute recovery on its first invocation (within timer_ms).
     */
    if (ctx->blob_database_file != NULL || ctx->has_old_buffers == FLB_TRUE) {
        ctx->needs_recovery = FLB_TRUE;
        flb_plg_debug(ctx->ins, "Recovery scheduled for first timer callback");
    }

    return 0;
}

/*
 * Create multipart upload and enqueue all parts (Orchestration function)
 * This function coordinates between multipart, blob, and queue modules:
 * 1. Creates a multipart upload
 * 2. Saves upload_id to database
 * 3. Queries all parts from database for this specific file
 * 4. Enqueues each part individually
 */
int s3_initiate_multipart_upload(struct flb_s3 *ctx,
                                           uint64_t file_id,
                                           const char *file_path,
                                           const char *tag,
                                           int tag_len)
{
    struct multipart_upload *m_upload = NULL;
    flb_sds_t pre_signed_url = NULL;
    uint64_t *part_db_ids = NULL;
    uint64_t *part_nums = NULL;
    off_t *offset_starts = NULL;
    off_t *offset_ends = NULL;
    int part_count = 0;
    int total_enqueued = 0;
    int ret;
    int i;

    /* Create multipart upload structure */
    m_upload = s3_multipart_upload_new(ctx, tag, tag_len, file_path);
    if (!m_upload) {
        flb_plg_error(ctx->ins, "Failed to create multipart upload structure");
        return -1;
    }

    /* Fetch presigned URL for CreateMultipartUpload */
    ret = s3_auth_fetch_presigned_url(ctx, &pre_signed_url,
                                       S3_PRESIGNED_URL_CREATE_MULTIPART,
                                       m_upload->s3_key, NULL, 0);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to fetch presigned URL for CreateMultipartUpload");
        s3_multipart_upload_destroy(m_upload);
        return -1;
    }

    /* Call AWS CreateMultipartUpload API */
    ret = s3_multipart_initiate(ctx, m_upload, pre_signed_url);
    flb_sds_destroy(pre_signed_url);

    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to create multipart upload for file_id=%" PRIu64, file_id);
        s3_multipart_upload_destroy(m_upload);
        return -1;
    }

    /* Save upload_id to database */
    ret = flb_blob_file_update_remote_id(&ctx->blob_db, file_id, m_upload->upload_id);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to save upload_id to database");
        s3_multipart_abort_with_url(ctx, m_upload);
        s3_multipart_upload_destroy(m_upload);
        return -1;
    }

    /* Save s3_key to database for reliable recovery */
    ret = flb_blob_file_update_s3_key(&ctx->blob_db, file_id, m_upload->s3_key);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to save s3_key to database for file_id=%" PRIu64, file_id);

        /*
         * CRITICAL: Without saved s3_key, we cannot reliably manage, resume, or abort
         * this upload later (especially if the key format uses timestamps).
         * We must abort now to prevent "orphaned" uploads that we can't track.
         */
        s3_multipart_abort_with_url(ctx, m_upload);
        s3_multipart_upload_destroy(m_upload);
        return -1;
    }

    /* Get all parts for this specific file */
    ret = flb_blob_db_file_fetch_all_parts(&ctx->blob_db, file_id,
                                            &part_db_ids, &part_nums,
                                            &offset_starts, &offset_ends,
                                            &part_count);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to get parts for file_id=%" PRIu64, file_id);
        s3_multipart_upload_destroy(m_upload);
        return -1;
    }

    if (part_count == 0) {
        flb_plg_error(ctx->ins, "No parts found for file_id=%" PRIu64, file_id);
        s3_multipart_upload_destroy(m_upload);
        return -1;
    }

    /* Enqueue all parts */
    for (i = 0; i < part_count; i++) {
        ret = s3_queue_add_part(ctx, file_id, part_db_ids[i], part_nums[i],
                               file_path, offset_starts[i], offset_ends[i],
                               m_upload->s3_key, m_upload->upload_id,
                               tag, tag_len);
        if (ret == 0) {
            total_enqueued++;
        }
    }

    /* Free allocated arrays */
    if (part_db_ids) {
        flb_free(part_db_ids);
    }
    if (part_nums) {
        flb_free(part_nums);
    }
    if (offset_starts) {
        flb_free(offset_starts);
    }
    if (offset_ends) {
        flb_free(offset_ends);
    }

    s3_multipart_upload_destroy(m_upload);

    if (total_enqueued == 0) {
        flb_plg_error(ctx->ins, "No parts enqueued for file_id=%" PRIu64, file_id);
        return -1;
    }

    flb_plg_info(ctx->ins, "Multipart upload created: file_id=%" PRIu64 " (%d parts)",
                 file_id, total_enqueued);
    return 0;
}

flb_sds_t s3_generate_key(struct flb_s3 *ctx,
                          const char *tag,
                          time_t timestamp,
                          const char *filename)
{
    int ret;
    flb_sds_t s3_key;

    if (ctx->key_fmt_has_seq_index) {
        ctx->seq_index++;
        ret = write_seq_index(ctx->seq_index_file, ctx->seq_index);
        if (ret < 0) {
            ctx->seq_index--;
            flb_plg_error(ctx->ins, "Failed to write sequential index");
            return NULL;
        }
    }

    s3_key = flb_get_s3_key(ctx->s3_key_format, timestamp, tag,
                            ctx->tag_delimiters, ctx->seq_index, filename);

    return s3_key;
}

static int s3_prepare_upload_data(struct flb_s3 *ctx,
                                  const char *input_path,
                                  flb_sds_t *out_final_path,
                                  int *out_is_temp)
{
    flb_sds_t compressed_path = NULL;
    int ret;

    *out_is_temp = FLB_FALSE;
    *out_final_path = NULL;

    /* Apply compression to temp file if needed (not for Parquet - already compressed) */
    if (ctx->compression != FLB_AWS_COMPRESS_NONE && ctx->format != FLB_S3_FORMAT_PARQUET) {
        const char *compression_suffix;

        /* Determine file suffix based on compression algorithm */
        switch (ctx->compression) {
            case FLB_AWS_COMPRESS_GZIP:
                compression_suffix = ".gz";
                break;
            case FLB_AWS_COMPRESS_ZSTD:
                compression_suffix = ".zstd";
                break;
            case FLB_AWS_COMPRESS_SNAPPY:
                compression_suffix = ".snappy";
                break;
            default:
                compression_suffix = ".compressed";
                flb_plg_warn(ctx->ins, "Unknown compression type %d, using generic suffix",
                            ctx->compression);
                break;
        }

        compressed_path = flb_sds_create_size(strlen(input_path) + 12);
        if (!compressed_path) {
            flb_errno();
            return FLB_RETRY;
        }

        compressed_path = flb_sds_printf(&compressed_path, "%s%s", input_path, compression_suffix);
        if (!compressed_path) {
            flb_errno();
            return FLB_RETRY;
        }

        ret = stream_compress_file(ctx, input_path, compressed_path, 0, -1);
        if (ret < 0) {
            flb_sds_destroy(compressed_path);
            return FLB_RETRY;
        }

        /* Delete original file after successful compression */
        if (flb_s3_unlink(input_path) != 0) {
            flb_plg_warn(ctx->ins, "Failed to delete uncompressed temp file: %s",
                        input_path);
        }

        *out_final_path = compressed_path;
        *out_is_temp = FLB_TRUE;
    }
    else {
        /* No compression needed, use input path directly */
        *out_final_path = flb_sds_create(input_path);
        *out_is_temp = FLB_FALSE;
    }

    return 0;
}

int s3_upload_file(struct flb_s3 *ctx,
                   const char *file_path,
                   const char *tag, int tag_len,
                   time_t file_first_log_time)
{
    int ret;
    flb_sds_t s3_key = NULL;
    flb_sds_t final_file_path = NULL;
    int is_temp_path = FLB_FALSE;
    const char *filename;

    /* Prepare data (handle compression if needed) */
    ret = s3_prepare_upload_data(ctx, file_path, &final_file_path, &is_temp_path);
    if (ret != 0) {
        /* Compression failed, original file likely intact or handled */
        if (is_temp_path == FLB_FALSE) {
             /* If prepare failed before creating temp, we might need to delete original input
              * if caller expects us to take ownership.
              * BUT existing contract says caller expects file to be deleted on success/fail inside here?
              * Original code: unlink(file_path) on error inside compression block.
              * If s3_prepare_upload_data fails, it should cleanup itself.
              */
             flb_s3_unlink(file_path);
        }
        return ret;
    }

    /* Extract filename from path for log data */
    filename = strrchr(final_file_path, '/');
    filename = filename ? filename + 1 : final_file_path;

    /* Generate s3_key using unified helper */
    s3_key = s3_generate_key(ctx, tag, file_first_log_time, filename);
    if (!s3_key) {
        flb_plg_error(ctx->ins, "Failed to generate S3 key for log data");
        
        /* Cleanup */
        if (is_temp_path == FLB_TRUE) {
            /* If we created a temp file (compressed), we must delete it */
            flb_s3_unlink(final_file_path);
        }
        else {
            /* If no temp file, final_file_path IS file_path.
             * We must delete the input file as per contract. */
            flb_s3_unlink(file_path);
        }
        
        flb_sds_destroy(final_file_path);
        return FLB_RETRY;
    }

    flb_plg_debug(ctx->ins, "Uploading log file %s to S3 key: %s", filename, s3_key);

    /* Use streaming multipart upload from disk - MEMORY OPTIMIZED */
    ret = s3_multipart_upload_file(ctx, final_file_path, s3_key, tag, tag_len);

    flb_sds_destroy(s3_key);

    flb_plg_debug(ctx->ins, "Cleaning up temporary file: %s", final_file_path);

    /* Always cleanup the file we uploaded */
    if (flb_s3_unlink(final_file_path) != 0) {
        if (errno != ENOENT) {
            flb_plg_warn(ctx->ins, "Failed to delete temporary file %s: %s",
                        final_file_path, strerror(errno));
        }
    }
    
    /* 
     * If is_temp_path is TRUE: final_file_path was a temp file, we deleted it above.
     *                          file_path was already deleted by s3_prepare_upload_data.
     * If is_temp_path is FALSE: final_file_path was file_path, we deleted it above.
     * 
     * In all cases, file_path is consumed.
     */

    flb_sds_destroy(final_file_path);

    return ret;
}


static int s3_stream_to_json(struct flb_s3 *ctx,
                              struct s3_file *chunk,
                              flb_sds_t *out_buf,
                              size_t *out_size)
{
    char chunk_path[PATH_MAX];
    int ret;

    if (!chunk || !chunk->stream_path || !chunk->fsf ||
        !chunk->fsf->chunk || !chunk->fsf->chunk->name) {
        flb_plg_error(ctx->ins, "Invalid chunk data");
        return -1;
    }

    /* Construct path on stack - chunk is locked, safe to access */
    ret = snprintf(chunk_path, sizeof(chunk_path), "%s/%s",
                   chunk->stream_path, chunk->fsf->chunk->name);
    if (ret < 0 || ret >= sizeof(chunk_path)) {
        flb_plg_error(ctx->ins, "Chunk path too long");
        return -1;
    }

    return stream_process_msgpack_file(
        ctx,
        chunk_path,
        chunk->size,
        ".json",
        stream_json_processor,
        NULL,
        out_buf,
        out_size
    );
}

static int s3_stream_extract_log_key(struct flb_s3 *ctx,
                                      struct s3_file *chunk,
                                      flb_sds_t *out_buf,
                                      size_t *out_size)
{
    char chunk_path[PATH_MAX];
    int ret;

    if (!chunk || !chunk->stream_path || !chunk->fsf ||
        !chunk->fsf->chunk || !chunk->fsf->chunk->name) {
        flb_plg_error(ctx->ins, "Invalid chunk data");
        return -1;
    }

    /* Construct path on stack - chunk is locked, safe to access */
    ret = snprintf(chunk_path, sizeof(chunk_path), "%s/%s",
                   chunk->stream_path, chunk->fsf->chunk->name);
    if (ret < 0 || ret >= sizeof(chunk_path)) {
        flb_plg_error(ctx->ins, "Chunk path too long");
        return -1;
    }

    return stream_process_msgpack_file(
        ctx,
        chunk_path,
        chunk->size,
        ".txt",
        stream_log_key_processor,
        NULL,
        out_buf,
        out_size
    );
}

/*
 * Convert chunk to upload format (JSON/Parquet).
 * Returns FILE: marker pointing to temp file for streaming upload.
 * Caller must unlock chunk on success (kept locked for retry on failure).
 */
int s3_format_chunk(struct flb_s3 *ctx,
                    struct s3_file *chunk,
                    flb_sds_t *out_buf, size_t *out_size)
{
    int ret;

    if (chunk == NULL) {
        flb_plg_error(ctx->ins, "[construct_request_buffer] chunk is NULL");
        return -1;
    }

    s3_store_file_lock(chunk);

    /* For JSON format with chunk file: use streaming conversion to minimize memory */
    if (ctx->format == FLB_S3_FORMAT_JSON && !ctx->log_key) {
        ret = s3_stream_to_json(ctx, chunk, out_buf, out_size);
        if (ret < 0) {
            s3_store_file_unlock(chunk);
        }
        return ret;
    }

    /* For log_key extraction with chunk file: use streaming extraction to minimize memory */
    if (ctx->log_key) {
        ret = s3_stream_extract_log_key(ctx, chunk, out_buf, out_size);
        if (ret < 0) {
            s3_store_file_unlock(chunk);
        }
        return ret;
    }

    /* For Parquet format with chunk file: use streaming conversion */
    if (ctx->format == FLB_S3_FORMAT_PARQUET) {
#ifdef FLB_HAVE_PARQUET_ENCODER
        char chunk_path[PATH_MAX];
        char temp_path[PATH_MAX];
        size_t parquet_file_size = 0;
        flb_sds_t formatted_data;
        size_t formatted_size;

        if (!ctx->schema_str) {
            flb_plg_error(ctx->ins, "schema_str is required when format=parquet");
            s3_store_file_unlock(chunk);
            return -1;
        }

        /* Validate chunk data before accessing */
        if (!chunk->stream_path || !chunk->fsf || !chunk->fsf->chunk || !chunk->fsf->chunk->name) {
            flb_plg_error(ctx->ins, "Invalid chunk data for Parquet conversion");
            s3_store_file_unlock(chunk);
            return -1;
        }

        /* Construct paths on stack - chunk is locked, safe to access */
        ret = snprintf(chunk_path, sizeof(chunk_path), "%s/%s",
                      chunk->stream_path, chunk->fsf->chunk->name);
        if (ret < 0 || ret >= sizeof(chunk_path)) {
            flb_plg_error(ctx->ins, "Chunk path too long");
            s3_store_file_unlock(chunk);
            return -1;
        }

        ret = snprintf(temp_path, sizeof(temp_path), "%s/parquet_stream_%p.parquet",
                      ctx->buffer_dir, (void*)chunk);
        if (ret < 0 || ret >= sizeof(temp_path)) {
            flb_plg_error(ctx->ins, "Temp path too long");
            s3_store_file_unlock(chunk);
            return -1;
        }

        /*
         * CRITICAL: Use streaming version with cached schema.
         * This avoids yyjson stack overflow in coroutines by using
         * the pre-parsed schema from initialization.
         */
        ret = flb_msgpack_to_parquet_streaming(
            chunk_path,
            ctx->cached_arrow_schema,
            ctx->compression,
            temp_path,
            &parquet_file_size,
            ctx->file_size
        );

        if (ret < 0) {
            flb_plg_error(ctx->ins, "Streaming Parquet conversion failed");
            unlink(temp_path);
            s3_store_file_unlock(chunk);
            return -1;
        }

        /* Handle empty Parquet output - mark as max failures to skip retry */
        if (parquet_file_size == 0) {
            flb_plg_warn(ctx->ins,
                        "Parquet conversion produced 0 records from %zu bytes of input. "
                        "Possible causes: empty msgpack data, schema mismatch with incoming data structure, "
                        "or filtered out by schema. Check your schema_str configuration. "
                        "File will be marked as failed and cleaned up on next restart.",
                        chunk->size);

            /* Mark as max failures so it won't be retried */
            chunk->failures = ctx->ins->retry_limit;

            unlink(temp_path);
            s3_store_file_unlock(chunk);
            return -1;
        }

        /* Return file path marker */
        formatted_data = flb_sds_create(temp_path);
        if (!formatted_data) {
            flb_plg_error(ctx->ins, "Failed to create path marker");
            unlink(temp_path);
            s3_store_file_unlock(chunk);
            return -1;
        }

        formatted_size = parquet_file_size;
        *out_buf = formatted_data;
        *out_size = formatted_size;

        return 0;
#else
        flb_plg_error(ctx->ins, "Parquet format not supported in this build");
        s3_store_file_unlock(chunk);
        return -1;
#endif
    }

    /* Should not reach here - all formats should be handled above */
    flb_plg_error(ctx->ins, "Unknown format in construct_request_buffer");
    s3_store_file_unlock(chunk);
    return -1;
}

/* Timer callback - scans for timed-out chunks and processes upload queue */
void cb_s3_upload(struct flb_config *config, void *data)
{
    struct flb_s3 *ctx = data;
    struct s3_file *chunk;
    struct flb_fstore_file *fsf;
    struct upload_queue *entry;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list pending_uploads;  /* Local list for thread-safe processing */
    time_t now;
    int ret;
    int uploaded = 0;
    int enqueued = 0;
    int do_recovery = FLB_FALSE;

    /* CRITICAL: Check exit flag at the very beginning */
    if (ctx->is_exiting == FLB_TRUE) {
        flb_plg_debug(ctx->ins, "Timer callback: exit in progress, skipping");
        return;
    }

    /* Initialize local list for collecting entries to process */
    mk_list_init(&pending_uploads);

    /*
     * CRITICAL: Acquire lock BEFORE checking needs_recovery.
     * This ensures only one worker executes recovery when workers > 1.
     * Without this, multiple workers could see needs_recovery=TRUE and
     * all execute recovery simultaneously.
     */
    pthread_mutex_lock(&ctx->upload_queue_lock);

    /*
     * Atomic check and clear of needs_recovery while holding lock.
     * Only one worker will execute recovery.
     */
    if (ctx->needs_recovery == FLB_TRUE) {
        ctx->needs_recovery = FLB_FALSE;
        do_recovery = FLB_TRUE;
    }

    pthread_mutex_unlock(&ctx->upload_queue_lock);

    /*
     * Execute recovery outside of lock to avoid blocking other workers.
     * Only one worker will reach here due to atomic check above.
     */
    if (do_recovery == FLB_TRUE) {
        ret = s3_queue_recover_all(ctx, config);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Recovery failed");
        }
    }

    now = time(NULL);

    /*
     * CRITICAL: Hold lock during ALL list operations.
     * When workers > 1, multiple cb_s3_upload callbacks run concurrently.
     * Without proper locking, one worker could delete a file/entry while
     * another is iterating, causing heap-use-after-free.
     *
     * Strategy: Collect entries into local list under lock, then process
     * without lock. This avoids holding lock during slow upload operations.
     */
    pthread_mutex_lock(&ctx->upload_queue_lock);

    /* Scan active stream for timed-out chunks and add them to queue */
    mk_list_foreach_safe(head, tmp, &ctx->stream_active->files) {
        fsf = mk_list_entry(head, struct flb_fstore_file, _head);
        chunk = fsf->data;

        /* Skip if not ready yet (check both timeout and size limit) */
        if (now < (chunk->create_time + ctx->upload_timeout + ctx->retry_time)) {
            if (chunk->size < ctx->file_size) {
                continue;
            }
        }

        /* Skip locked files */
        if (chunk->locked == FLB_TRUE) {
            continue;
        }

        /* Check failure limit */
        if (chunk->failures >= ctx->ins->retry_limit) {
            flb_plg_warn(ctx->ins,
                         "Chunk failed %d times, marking inactive (tag=%s)",
                         chunk->failures, (char*)fsf->meta_buf);
            s3_store_file_inactive(ctx, chunk);
            continue;
        }

        /*
         * Two supported upload modes:
         * - Database-tracked: Add to processing list (pending_uploads) to be formatted outside lock
         * - Non-database-tracked: Use queue entry (metadata only)
         */
        if (ctx->blob_db.db != NULL) {
            /*
             * Optimization: Move chunk to local list to process it OUTSIDE the lock.
             * This prevents s3_format_chunk (heavy I/O) from blocking other threads.
             * We use a special queue entry to hold the chunk reference.
             */
            entry = flb_calloc(1, sizeof(struct upload_queue));
            if (!entry) {
                flb_errno();
                continue;
            }

            /* Store reference to fstore file/chunk */
            s3_store_file_lock(chunk);
            entry->upload_file = chunk;
            entry->file_id = 0; /* Marker for processing stage */
            entry->tag = flb_sds_create_len((const char *)fsf->meta_buf, fsf->meta_size);
            entry->tag_len = fsf->meta_size;

            mk_list_add(&entry->_head, &pending_uploads);
        }
        else {
            /* Non-database-tracked upload (log data only, fstore storage) */
            s3_store_file_lock(chunk);
            /* Use _unlocked version since we're already holding upload_queue_lock */
            ret = s3_queue_add_file_unlocked(ctx, 0, chunk, NULL,
                                             (const char*)fsf->meta_buf,
                                             fsf->meta_size);
            if (ret == 0) {
                enqueued++;
            }
            else {
                s3_store_file_unlock(chunk);
            }
        }
    }

    /* Release lock before processing - local list is thread-safe */
    pthread_mutex_unlock(&ctx->upload_queue_lock);

    /* Process pending DB-tracked uploads (formatting) WITHOUT lock */
    mk_list_foreach_safe(head, tmp, &pending_uploads) {
        entry = mk_list_entry(head, struct upload_queue, _head);
        mk_list_del(&entry->_head);

        /* This is a temporary entry from above loop */
        chunk = entry->upload_file;

        flb_sds_t formatted_data = NULL;
        size_t formatted_size;
        const char *temp_file_path;
        struct stat st;
        int64_t file_id;
        int part_count;

        /* Format the chunk (converts msgpack to JSON/Parquet temp file) */
        ret = s3_format_chunk(ctx, chunk, &formatted_data, &formatted_size);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Timer: Failed to format chunk for DB-tracked upload");
            s3_store_file_unlock(chunk);
            s3_queue_entry_destroy(ctx, entry);
            continue;
        }

        /* Handle empty output */
        if (formatted_data == NULL || formatted_size == 0) {
            flb_plg_debug(ctx->ins, "Timer: Chunk produced no output data, skipping");
            s3_store_file_unlock(chunk);
            s3_store_file_delete(ctx, chunk);
            s3_queue_entry_destroy(ctx, entry);
            continue;
        }

        temp_file_path = formatted_data;

        if (stat(temp_file_path, &st) != 0) {
            flb_plg_error(ctx->ins, "Timer: Temp file not found: %s", temp_file_path);
            flb_sds_destroy(formatted_data);
            s3_store_file_unlock(chunk);
            s3_queue_entry_destroy(ctx, entry);
            continue;
        }

        /* Insert file into database */
        ret = flb_blob_db_file_insert(&ctx->blob_db, entry->tag, "",
                                      ctx->endpoint, (char *)temp_file_path, st.st_size);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Timer: Failed to insert chunk file into database");
            flb_sds_destroy(formatted_data);
            unlink(temp_file_path);
            s3_store_file_unlock(chunk);
            s3_queue_entry_destroy(ctx, entry);
            continue;
        }

        file_id = ret;

        /* Register parts */
        part_count = s3_blob_register_parts(ctx, file_id, st.st_size);
        if (part_count < 0) {
            flb_plg_error(ctx->ins, "Timer: Failed to register chunk file parts");
            flb_blob_db_file_delete(&ctx->blob_db, file_id);
            flb_sds_destroy(formatted_data);
            unlink(temp_file_path);
            s3_store_file_unlock(chunk);
            s3_queue_entry_destroy(ctx, entry);
            continue;
        }

        /* Re-acquire lock to add to shared queue */
        pthread_mutex_lock(&ctx->upload_queue_lock);

        ret = s3_queue_add_pending_file_unlocked(ctx, file_id, temp_file_path,
                                                 entry->tag, entry->tag_len);

        pthread_mutex_unlock(&ctx->upload_queue_lock);

        flb_sds_destroy(formatted_data);

        if (ret < 0) {
            flb_plg_error(ctx->ins, "Timer: Failed to enqueue pending file");
            flb_blob_db_file_delete(&ctx->blob_db, file_id);
            unlink(temp_file_path);
            s3_store_file_unlock(chunk);
            s3_queue_entry_destroy(ctx, entry);
            continue;
        }

        /* Delete the fstore chunk since data is now in DB */
        pthread_mutex_lock(&ctx->upload_queue_lock);
        s3_store_file_delete(ctx, chunk); /* Unlock happens inside destroy if needed, or handled */
        pthread_mutex_unlock(&ctx->upload_queue_lock);
        /* s3_store_file_delete unlocks and destroys. We locked it earlier. */

        flb_plg_info(ctx->ins, "Timer: Chunk registered in DB (file_id=%" PRId64 ", parts=%d)",
                    file_id, part_count);
        enqueued++;
        s3_queue_entry_destroy(ctx, entry);
    }

    /* Re-acquire lock for the next phase (processing upload queue) */
    pthread_mutex_lock(&ctx->upload_queue_lock);

    /*
     * CRITICAL FIX: Collect ready entries into local list while holding lock.
     * This prevents race condition where another worker modifies the queue
     * while we're iterating. We move entries to a local list, release the lock,
     * then process them safely.
     */
    mk_list_foreach_safe(head, tmp, &ctx->upload_queue) {
        entry = mk_list_entry(head, struct upload_queue, _head);

        /* Check if ready to upload */
        if (now < entry->upload_time) {
            continue;
        }

        /* Move from shared queue to local list (still under lock) */
        mk_list_del(&entry->_head);
        mk_list_add(&entry->_head, &pending_uploads);
    }

    /* Release lock before processing - local list is thread-safe */
    pthread_mutex_unlock(&ctx->upload_queue_lock);

    /* Process all entries in local list without holding lock */
    mk_list_foreach_safe(head, tmp, &pending_uploads) {
        /* CRITICAL: Check exit flag in each iteration to avoid blocking exit */
        if (ctx->is_exiting == FLB_TRUE) {
            struct mk_list *inner_head;
            struct mk_list *inner_tmp;

            flb_plg_info(ctx->ins, "Timer callback: exit requested during queue processing");
            /* Re-add remaining entries back to shared queue */
            pthread_mutex_lock(&ctx->upload_queue_lock);
            mk_list_foreach_safe(inner_head, inner_tmp, &pending_uploads) {
                entry = mk_list_entry(inner_head, struct upload_queue, _head);
                mk_list_del(&entry->_head);
                mk_list_add(&entry->_head, &ctx->upload_queue);
            }
            pthread_mutex_unlock(&ctx->upload_queue_lock);
            goto done;
        }

        entry = mk_list_entry(head, struct upload_queue, _head);

        /* Remove from local list before processing */
        mk_list_del(&entry->_head);

        /* Process upload (this calls the helper functions from s3_queue.c) */
        ret = s3_queue_process_entry(ctx, entry, now);

        if (ret == 1) {
            /* Success - entry already freed */
            uploaded++;
        }
        else if (ret == -1) {
            /* Failure - re-add to shared queue for retry (need lock) */
            pthread_mutex_lock(&ctx->upload_queue_lock);
            mk_list_add(&entry->_head, &ctx->upload_queue);
            pthread_mutex_unlock(&ctx->upload_queue_lock);
        }
        /* ret == 0 means entry was freed (invalid or retry limit reached) - do nothing */
    }

done:

    if (enqueued > 0 || uploaded > 0) {
        flb_plg_info(ctx->ins, "Timer: enqueued %d, uploaded %d file(s)",
                     enqueued, uploaded);
    }
}

static void cb_s3_flush(struct flb_event_chunk *event_chunk,
                        struct flb_output_flush *out_flush,
                        struct flb_input_instance *i_ins,
                        void *out_context,
                        struct flb_config *config)
{
    int ret;
    int chunk_size;
    int upload_timeout_check = FLB_FALSE;
    int total_file_size_check = FLB_FALSE;
    flb_sds_t chunk = NULL;
    struct s3_file *upload_file = NULL;
    struct flb_s3 *ctx = out_context;
    time_t file_first_log_time = 0;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    if (event_chunk->type == FLB_EVENT_TYPE_BLOBS) {
        /*
         * For Blob types, we use the flush callback to enqueue the file, then the upload timer
         * takes care of processing the queue and uploading parts to S3.
         */
        ret = s3_blob_process_events(ctx, event_chunk);
        if (ret == -1) {
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        FLB_OUTPUT_RETURN(FLB_OK);
    }

    /*
     * Store raw msgpack data directly - format conversion happens during upload.
     * This avoids repeated conversions and enables better batching for columnar formats.
     */
    chunk = flb_sds_create_len(event_chunk->data, event_chunk->size);
    if (chunk == NULL) {
        flb_plg_error(ctx->ins, "Failed to create buffer for msgpack data");
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }
    chunk_size = event_chunk->size;

    /*
     * CRITICAL: Acquire lock for fstore operations.
     * This protects against race conditions with the upload timer which iterates
     * the file list. It also ensures atomic "get or create" behavior.
     */
    pthread_mutex_lock(&ctx->upload_queue_lock);

    upload_file = s3_store_file_get(ctx,
                                    event_chunk->tag,
                                    flb_sds_len(event_chunk->tag));

    if (upload_file == NULL) {
        /*
         * Optimization opportunity: We could unlock here to parse, then re-lock.
         * But parsing only happens on new file creation, so we keep it simple
         * and safe by holding the lock.
         */
        ret = flb_log_event_decoder_init(&log_decoder,
                                         (char *) event_chunk->data,
                                         event_chunk->size);

        if (ret != FLB_EVENT_DECODER_SUCCESS) {
            flb_plg_error(ctx->ins,
                          "Log event decoder initialization error : %d", ret);

            flb_sds_destroy(chunk);
            pthread_mutex_unlock(&ctx->upload_queue_lock);

            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        while ((ret = flb_log_event_decoder_next(
                        &log_decoder,
                        &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
            if (log_event.timestamp.tm.tv_sec != 0) {
                file_first_log_time = log_event.timestamp.tm.tv_sec;
                break;
            }
        }

        flb_log_event_decoder_destroy(&log_decoder);
    }
    else {
        file_first_log_time = upload_file->first_log_time;
    }

    if (file_first_log_time == 0) {
        file_first_log_time = time(NULL);
    }

    /*
     * In test mode, data should be uploaded immediately for validation.
     * Set upload_timeout=1s in test config to trigger immediate uploads.
     */

    if (upload_file != NULL && upload_file->failures >= ctx->ins->retry_limit) {
        flb_plg_warn(ctx->ins, "File with tag %s failed to send %d/%d times, will not retry",
                     event_chunk->tag, upload_file->failures, ctx->ins->retry_limit);
        s3_store_file_inactive(ctx, upload_file);
        upload_file = NULL;
    }

    if (upload_file != NULL && time(NULL) >
        (upload_file->create_time + ctx->upload_timeout)) {
        upload_timeout_check = FLB_TRUE;
        flb_plg_info(ctx->ins, "upload_timeout reached for %s",
                     event_chunk->tag);
    }

    if (upload_file && upload_file->size + chunk_size > ctx->file_size) {
        total_file_size_check = FLB_TRUE;
        flb_plg_info(ctx->ins, "total_file_size reached for %s",
                     event_chunk->tag);
    }

    /*
     * Always buffer the chunk first.
     * s3_store_buffer_put will handle file rotation if size limit is reached.
     */
    ret = s3_queue_buffer_chunk(ctx, upload_file, chunk, chunk_size,
                       event_chunk->tag, flb_sds_len(event_chunk->tag),
                       file_first_log_time);

    pthread_mutex_unlock(&ctx->upload_queue_lock);

    if (ret < 0) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    if ((upload_file != NULL) && (upload_timeout_check == FLB_TRUE || total_file_size_check == FLB_TRUE)) {
        /*
         * Unified Worker Queue Architecture:
         * - Database-tracked: Do nothing here. The background timer (cb_s3_upload) scans the
         *   active stream files and detects if they are ready (timeout or size).
         *   This avoids blocking the flush callback with expensive formatting/DB ops.
         *
         * - Non-database-tracked: Use queue entry (metadata only)
         */

        if (ctx->blob_db.db != NULL) {
            /* Database-tracked: Let timer handle it */
            FLB_OUTPUT_RETURN(FLB_OK);
        }
        else {
            /* Non-database-tracked upload (log data only, fstore storage) */
            s3_store_file_lock(upload_file);

            /* Add to unified worker queue using unified interface (simple mode: file_id=0) */
            ret = s3_queue_add_file(ctx, 0, upload_file, NULL,
                                    event_chunk->tag, flb_sds_len(event_chunk->tag));
            if (ret < 0) {
                s3_store_file_unlock(upload_file);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }

            FLB_OUTPUT_RETURN(FLB_OK);
        }
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_s3_exit(void *data, struct flb_config *config)
{
    struct flb_s3 *ctx = data;

    if (!ctx) {
        return 0;
    }

    /* Signal shutdown */
    ctx->is_exiting = FLB_TRUE;

    /* Cleanup blob database if it was initialized */
    if (ctx->blob_database_file != NULL && ctx->blob_db.db != NULL) {
        flb_blob_db_close(&ctx->blob_db);
    }

    /* Cleanup upload queue mutex */
    pthread_mutex_destroy(&ctx->upload_queue_lock);

    /* Cleanup storage */
    s3_store_exit(ctx);

    /* Destroy context - MUST be last as it frees ctx */
    s3_context_destroy(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "json_date_format", NULL,
     0, FLB_FALSE, 0,
    FBL_PACK_JSON_DATE_FORMAT_DESCRIPTION
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_s3, json_date_key),
    "Specifies the name of the date field in output."
    },
    {
     FLB_CONFIG_MAP_SIZE, "total_file_size", "500M",
     0, FLB_TRUE, offsetof(struct flb_s3, file_size),
     "Buffer size threshold that triggers upload. When buffered data reaches this size, it is uploaded to S3. "
     "Works together with upload_timeout (either condition triggers upload). Maximum: 5TB, Default: 500M."
    },
    {
     FLB_CONFIG_MAP_SIZE, "upload_chunk_size", NULL,
     0, FLB_TRUE, offsetof(struct flb_s3, upload_chunk_size),
     "Part size for log data multipart uploads. Controls chunk size when uploading buffered data to S3. "
     "Default: 100MiB. Automatically adjusted based on total_file_size to stay within AWS 10,000 parts limit. "
     "Range: 5MiB - 5GiB. Allocates a buffer of this size per upload, larger values improve throughput but increase memory usage."
    },
    {
     FLB_CONFIG_MAP_STR, "bucket", NULL,
     0, FLB_TRUE, offsetof(struct flb_s3, bucket),
    "S3 bucket name."
    },
    {
     FLB_CONFIG_MAP_STR, "region", "us-east-1",
     0, FLB_TRUE, offsetof(struct flb_s3, region),
    "AWS region."
    },
    {
     FLB_CONFIG_MAP_STR, "role_arn", NULL,
     0, FLB_FALSE, 0,
     "ARN of an IAM role to assume (ex. for cross account access)."
    },
    {
     FLB_CONFIG_MAP_STR, "endpoint", NULL,
     0, FLB_TRUE, offsetof(struct flb_s3, endpoint),
    "Custom endpoint for the S3 API."
    },
    {
     FLB_CONFIG_MAP_STR, "sts_endpoint", NULL,
     0, FLB_TRUE, offsetof(struct flb_s3, sts_endpoint),
    "Custom endpoint for the STS API."
    },
    {
     FLB_CONFIG_MAP_STR, "canned_acl", NULL,
     0, FLB_FALSE, 0,
    "Predefined Canned ACL policy for S3 objects."
    },
    {
     FLB_CONFIG_MAP_STR, "compression", NULL,
     0, FLB_FALSE, 0,
    "Compression type for S3 objects. Supported values: `none`, `gzip`, `snappy`, `zstd`. Default: `none`. "
    "`arrow` and `parquet` are deprecated legacy values that will set format=parquet."
    },
    {
     FLB_CONFIG_MAP_STR, "format", "json",
     0, FLB_FALSE, 0,
     "Output format for S3 objects. Supported: json, parquet."
    },
    {
     FLB_CONFIG_MAP_STR, "schema_str", NULL,
     0, FLB_TRUE, offsetof(struct flb_s3, schema_str),
     "JSON schema for output format. Required when `format=parquet`. "
     "Example: `{\"fields\":[{\"name\":\"message\",\"type\":{\"name\":\"utf8\"}}]}`"
    },
    {
     FLB_CONFIG_MAP_STR, "content_type", NULL,
     0, FLB_FALSE, 0,
    "A standard MIME type for the S3 object; this will be set "
    "as the Content-Type HTTP header."
    },

    {
     FLB_CONFIG_MAP_STR, "store_dir", "/tmp/fluent-bit/s3",
     0, FLB_TRUE, offsetof(struct flb_s3, store_dir),
     "Directory to locally buffer data before sending. The plugin buffers data locally until "
     "total_file_size or upload_timeout is reached, then uploads using streaming multipart upload "
     "for memory efficiency. Upload chunk size is controlled by upload_chunk_size parameter."
    },

    {
     FLB_CONFIG_MAP_SIZE, "store_dir_limit_size", (char *) NULL,
     0, FLB_TRUE, offsetof(struct flb_s3, store_dir_limit_size),
     "S3 plugin has its own buffering system with files in the `store_dir`. "
     "Use the `store_dir_limit_size` to limit the amount of data S3 buffers in "
     "the `store_dir` to limit disk usage. If the limit is reached, "
     "data will be discarded. Default is 0 which means unlimited."
    },

    {
     FLB_CONFIG_MAP_STR, "s3_key_format", "/fluent-bit-logs/$TAG/%Y/%m/%d/%H/%M/%S",
     0, FLB_TRUE, offsetof(struct flb_s3, s3_key_format),
    "Format string for keys in S3. This option supports strftime time formatters "
    "and a syntax for selecting parts of the Fluent log tag using a syntax inspired "
    "by the rewrite_tag filter. Add $TAG in the format string to insert the full "
    "log tag; add $TAG[0] to insert the first part of the tag in the s3 key. "
    "The tag is split into “parts” using the characters specified with the "
    "s3_key_format_tag_delimiters option. Add $INDEX to enable sequential indexing "
    "for file names. Adding $INDEX will prevent random string being added to end of key"
    "when $UUID is not provided. See the in depth examples and tutorial in the "
    "documentation."
    },

    {
     FLB_CONFIG_MAP_STR, "s3_key_format_tag_delimiters", ".",
     0, FLB_TRUE, offsetof(struct flb_s3, tag_delimiters),
    "A series of characters which will be used to split the tag into parts for "
    "use with the s3_key_format option. See the in depth examples and tutorial in "
    "the documentation."
    },

    {
     FLB_CONFIG_MAP_BOOL, "auto_retry_requests", "true",
     0, FLB_TRUE, offsetof(struct flb_s3, retry_requests),
     "Immediately retry failed requests to AWS services once. This option "
     "does not affect the normal Fluent Bit retry mechanism with backoff. "
     "Instead, it enables an immediate retry with no delay for networking "
     "errors, which may help improve throughput when there are transient/random "
     "networking issues."
    },

    {
     FLB_CONFIG_MAP_BOOL, "use_put_object", "false",
     0, FLB_FALSE, 0,
     "Deprecated: This option has no effect. The plugin automatically handles uploads efficiently for all file sizes."
    },

    {
     FLB_CONFIG_MAP_BOOL, "send_content_md5", "false",
     0, FLB_TRUE, offsetof(struct flb_s3, send_content_md5),
     "Send the Content-MD5 header with object uploads, as is required when Object Lock is enabled"
    },

    {
     FLB_CONFIG_MAP_BOOL, "preserve_data_ordering", "true",
     0, FLB_FALSE, 0,
     "DEPRECATED: This parameter has no effect and will be removed in a future version. "
     "The plugin now always uses an efficient background worker thread architecture that "
     "maintains upload order automatically. Setting this parameter has no impact on behavior."
    },

    {
     FLB_CONFIG_MAP_STR, "log_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_s3, log_key),
     "By default, the whole log record will be sent to S3. "
     "If you specify a key name with this option, then only the value of "
     "that key will be sent to S3."
    },

    {
     FLB_CONFIG_MAP_STR, "external_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_s3, external_id),
     "Specify an external ID for the STS API, can be used with the role_arn parameter if your role "
     "requires an external ID."
    },

    {
     FLB_CONFIG_MAP_BOOL, "static_file_path", "false",
     0, FLB_TRUE, offsetof(struct flb_s3, static_file_path),
     "Disables behavior where UUID string is automatically appended to end of S3 key name when "
     "$UUID is not provided in s3_key_format. $UUID, time formatters, $TAG, and other dynamic "
     "key formatters all work as expected while this feature is set to true."
    },

    {
     FLB_CONFIG_MAP_STR, "storage_class", NULL,
     0, FLB_FALSE, 0,
     "Specify the storage class for S3 objects. If this option is not specified, objects "
     "will be stored with the default 'STANDARD' storage class."
    },

    {
     FLB_CONFIG_MAP_STR, "profile", NULL,
     0, FLB_TRUE, offsetof(struct flb_s3, profile),
     "AWS Profile name. AWS Profiles can be configured with AWS CLI and are usually stored in "
     "$HOME/.aws/ directory."
    },

    {
     FLB_CONFIG_MAP_STR, "blob_database_file", NULL,
     0, FLB_TRUE, offsetof(struct flb_s3, blob_database_file),
     "Absolute path to a database file to be used to store blob files contexts"
    },

    {
     FLB_CONFIG_MAP_SIZE, "part_size", NULL,
     0, FLB_TRUE, offsetof(struct flb_s3, part_size),
     "DEPRECATED: Use 'upload_chunk_size' instead. This parameter is kept for backward compatibility. "
    },

    {
     FLB_CONFIG_MAP_INT, "file_delivery_attempt_limit", "3",
     0, FLB_TRUE, offsetof(struct flb_s3, file_delivery_attempt_limit),
     "Maximum delivery attempts for entire file upload (including CreateMultipartUpload). "
     "Handles file-level failures such as credential expiration, bucket configuration issues, "
     "and complete part upload failures. Works with auto_retry_requests for comprehensive "
     "error handling. Aligns with AWS SDK standard defaults. Default: 3. "
     "Set to 1 for fail-fast behavior if needed."
    },

    {
     FLB_CONFIG_MAP_INT, "part_delivery_attempt_limit", "5",
     0, FLB_TRUE, offsetof(struct flb_s3, part_delivery_attempt_limit),
     "Maximum delivery attempts for individual parts in multipart uploads. "
     "Handles transient failures for specific parts such as network timeouts and S3 throttling. "
     "Should be >= file_delivery_attempt_limit for optimal reliability. Default: 5."
    },

    {
     FLB_CONFIG_MAP_TIME, "upload_parts_timeout", "10m",
     0, FLB_FALSE, 0,
     "DEPRECATED: This parameter has no effect and will be removed in a future version. "
     "Use 'upload_timeout' instead. Setting this parameter has no impact on behavior."
    },

    {
     FLB_CONFIG_MAP_TIME, "upload_part_freshness_limit", "6D",
     0, FLB_TRUE, offsetof(struct flb_s3, upload_parts_freshness_threshold),
     "Maximum lifespan of an uncommitted file part"
    },

    {
     FLB_CONFIG_MAP_TIME, "upload_timeout", "10m",
     0, FLB_TRUE, offsetof(struct flb_s3, upload_timeout),
     "Timeout to trigger upload of buffered data. When buffered data has been waiting for this duration, "
     "it will be uploaded to S3 even if total_file_size has not been reached. Default is 10m minutes."
    },

    {
     FLB_CONFIG_MAP_STR, "authorization_endpoint_url", NULL,
     0, FLB_TRUE, offsetof(struct flb_s3, authorization_endpoint_url),
     "Authorization endpoint URL"
    },

    {
     FLB_CONFIG_MAP_STR, "authorization_endpoint_username", NULL,
     0, FLB_TRUE, offsetof(struct flb_s3, authorization_endpoint_username),
     "Authorization endpoint basic authentication username"
    },

    {
     FLB_CONFIG_MAP_STR, "authorization_endpoint_password", NULL,
     0, FLB_TRUE, offsetof(struct flb_s3, authorization_endpoint_password),
     "Authorization endpoint basic authentication password"
    },

   {
    FLB_CONFIG_MAP_STR, "authorization_endpoint_bearer_token", NULL,
    0, FLB_TRUE, offsetof(struct flb_s3, authorization_endpoint_bearer_token),
    "Authorization endpoint bearer token"
   },

   /* EOF */
   {0}
};

/* Plugin registration */
struct flb_output_plugin out_s3_plugin = {
    .name           = "s3",
    .description    = "Send to S3",
    .cb_init        = cb_s3_init,
    .cb_flush       = cb_s3_flush,
    .cb_exit        = cb_s3_exit,
    .workers        = 0,
    .event_type     = FLB_OUTPUT_LOGS | FLB_OUTPUT_BLOBS,
    .flags          = FLB_OUTPUT_NET | FLB_IO_TLS,
    .config_map     = config_map
};