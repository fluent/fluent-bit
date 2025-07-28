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
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <msgpack.h>

#include "s3.h"
#include "s3_store.h"
#include "s3_parquet.h"

#define DEFAULT_S3_PORT 443
#define DEFAULT_S3_INSECURE_PORT 80

static int construct_request_buffer(struct flb_s3 *ctx, flb_sds_t new_data,
                                    struct s3_file *chunk,
                                    char **out_buf, size_t *out_size);

static int s3_put_object(struct flb_s3 *ctx, const char *tag, time_t file_first_log_time,
                         char *body, size_t body_size);

static int put_all_chunks(struct flb_s3 *ctx);

static void cb_s3_upload(struct flb_config *ctx, void *data);

static struct multipart_upload *get_upload(struct flb_s3 *ctx,
                                           const char *tag, int tag_len);

static struct multipart_upload *create_upload(struct flb_s3 *ctx,
                                              const char *tag, int tag_len,
                                              time_t file_first_log_time);

static void remove_from_queue(struct upload_queue *entry);

static struct flb_aws_header content_encoding_header = {
    .key = "Content-Encoding",
    .key_len = 16,
    .val = "gzip",
    .val_len = 4,
};

static struct flb_aws_header content_type_header = {
    .key = "Content-Type",
    .key_len = 12,
    .val = "",
    .val_len = 0,
};

static struct flb_aws_header octetstream_type_header = {
    .key = "Content-Type",
    .key_len = 12,
    .val = "application/octet-stream",
    .val_len = 24,
};

static struct flb_aws_header canned_acl_header = {
    .key = "x-amz-acl",
    .key_len = 9,
    .val = "",
    .val_len = 0,
};

static struct flb_aws_header content_md5_header = {
    .key = "Content-MD5",
    .key_len = 11,
    .val = "",
    .val_len = 0,
};

static struct flb_aws_header storage_class_header = {
    .key = "x-amz-storage-class",
    .key_len = 19,
    .val = "",
    .val_len = 0,
};

static char *mock_error_response(char *error_env_var)
{
    char *err_val = NULL;
    char *error = NULL;
    int len = 0;

    err_val = getenv(error_env_var);
    if (err_val != NULL && strlen(err_val) > 0) {
        error = flb_calloc(strlen(err_val) + 1, sizeof(char));
        if (error == NULL) {
            flb_errno();
            return NULL;
        }

        len = strlen(err_val);
        memcpy(error, err_val, len);
        error[len] = '\0';
        return error;
    }

    return NULL;
}

int s3_plugin_under_test()
{
    if (getenv("FLB_S3_PLUGIN_UNDER_TEST") != NULL) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

int create_headers(struct flb_s3 *ctx, char *body_md5,
                   struct flb_aws_header **headers, int *num_headers,
                   int multipart_upload)
{
    int n = 0;
    int headers_len = 0;
    struct flb_aws_header *s3_headers = NULL;

    if (ctx->content_type != NULL) {
        headers_len++;
    }
    if (ctx->compression == FLB_AWS_COMPRESS_GZIP) {
        headers_len++;
    }
    if (ctx->canned_acl != NULL) {
        headers_len++;
    }
    if (body_md5 != NULL && strlen(body_md5) && multipart_upload == FLB_FALSE) {
        headers_len++;
    }
    if (ctx->storage_class != NULL) {
        headers_len++;
    }
    if (headers_len == 0) {
        *num_headers = headers_len;
        *headers = s3_headers;
        return 0;
    }

    s3_headers = flb_calloc(headers_len, sizeof(struct flb_aws_header));
    if (s3_headers == NULL) {
        flb_errno();
        return -1;
    }

    if (ctx->compression == FLB_AWS_COMPRESS_PARQUET) {
        s3_headers[n] = octetstream_type_header;
        n++;
    }
    else if (ctx->content_type != NULL) {
        s3_headers[n] = content_type_header;
        s3_headers[n].val = ctx->content_type;
        s3_headers[n].val_len = strlen(ctx->content_type);
        n++;
    }
    if (ctx->compression == FLB_AWS_COMPRESS_GZIP) {
        s3_headers[n] = content_encoding_header;
        n++;
    }
    if (ctx->canned_acl != NULL) {
        s3_headers[n] = canned_acl_header;
        s3_headers[n].val = ctx->canned_acl;
        s3_headers[n].val_len = strlen(ctx->canned_acl);
        n++;
    }
    if (body_md5 != NULL && strlen(body_md5) && multipart_upload == FLB_FALSE) {
        s3_headers[n] = content_md5_header;
        s3_headers[n].val = body_md5;
        s3_headers[n].val_len = strlen(body_md5);
        n++;
    }
    if (ctx->storage_class != NULL) {
        s3_headers[n] = storage_class_header;
        s3_headers[n].val = ctx->storage_class;
        s3_headers[n].val_len = strlen(ctx->storage_class);
    }

    *num_headers = headers_len;
    *headers = s3_headers;
    return 0;
};

struct flb_http_client *mock_s3_call(char *error_env_var, char *api)
{
    /* create an http client so that we can set the response */
    struct flb_http_client *c = NULL;
    char *error = mock_error_response(error_env_var);
    char *resp;
    int len;

    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_errno();
        flb_free(error);
        return NULL;
    }
    mk_list_init(&c->headers);

    if (error != NULL) {
        c->resp.status = 400;
        /* resp.data is freed on destroy, payload is supposed to reference it */
        c->resp.data = error;
        c->resp.payload = c->resp.data;
        c->resp.payload_size = strlen(error);
    }
    else {
        c->resp.status = 200;
        c->resp.payload = "";
        c->resp.payload_size = 0;
        if (strcmp(api, "CreateMultipartUpload") == 0) {
            /* mocked success response */
            c->resp.payload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n"
              "<Bucket>example-bucket</Bucket>\n"
              "<Key>example-object</Key>\n"
              "<UploadId>VXBsb2FkIElEIGZvciA2aWWpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZA</UploadId>\n"
            "</InitiateMultipartUploadResult>";
            c->resp.payload_size = strlen(c->resp.payload);
        }
        else if (strcmp(api, "UploadPart") == 0) {
            /* mocked success response */
            resp =            "Date:  Mon, 1 Nov 2010 20:34:56 GMT\n"
                              "ETag: \"b54357faf0632cce46e942fa68356b38\"\n"
                              "Content-Length: 0\n"
                              "Connection: keep-alive\n"
                              "Server: AmazonS3";
            /* since etag is in the headers, this code uses resp.data */
            len = strlen(resp);
            c->resp.data = flb_calloc(len + 1, sizeof(char));
            if (!c->resp.data) {
                flb_errno();
                flb_free(c);
                return NULL;
            }
            memcpy(c->resp.data, resp, len);
            c->resp.data[len] = '\0';
            c->resp.data_size = len;
        }
        else {
            c->resp.payload = "";
            c->resp.payload_size = 0;
        }
    }

    return c;
}

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
static int write_seq_index(char *seq_index_file, uint64_t seq_index)
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

    sprintf(tmp_buf, "%d", ctx->ins->id);
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

void multipart_upload_destroy(struct multipart_upload *m_upload)
{
    int i;
    flb_sds_t etag;

    if (!m_upload) {
        return;
    }

    if (m_upload->s3_key) {
        flb_sds_destroy(m_upload->s3_key);
    }
    if (m_upload->tag) {
        flb_sds_destroy(m_upload->tag);
    }
    if (m_upload->upload_id) {
        flb_sds_destroy(m_upload->upload_id);
    }

    for (i = 0; i < m_upload->part_number; i++) {
        etag = m_upload->etags[i];
        if (etag) {
            flb_sds_destroy(etag);
        }
    }

    flb_free(m_upload);
}

static void s3_context_destroy(struct flb_s3 *ctx)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct multipart_upload *m_upload;
    struct upload_queue *upload_contents;

    if (!ctx) {
        return;
    }

    if (ctx->base_provider) {
        flb_aws_provider_destroy(ctx->base_provider);
    }

    if (ctx->provider) {
        flb_aws_provider_destroy(ctx->provider);
    }

    if (ctx->provider_tls) {
        flb_tls_destroy(ctx->provider_tls);
    }

    if (ctx->sts_provider_tls) {
        flb_tls_destroy(ctx->sts_provider_tls);
    }

    if (ctx->s3_client) {
        flb_aws_client_destroy(ctx->s3_client);
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

    if (ctx->parquet_compression) {
        flb_sds_destroy(ctx->parquet_compression);
    }

    if (ctx->parquet_record_type) {
        flb_sds_destroy(ctx->parquet_record_type);
    }

    if (ctx->parquet_schema_type) {
        flb_sds_destroy(ctx->parquet_schema_type);
    }

    if (ctx->parquet_schema_file) {
        flb_sds_destroy(ctx->parquet_schema_file);
    }

    /* Remove uploads */
    mk_list_foreach_safe(head, tmp, &ctx->uploads) {
        m_upload = mk_list_entry(head, struct multipart_upload, _head);
        mk_list_del(&m_upload->_head);
        multipart_upload_destroy(m_upload);
    }

    mk_list_foreach_safe(head, tmp, &ctx->upload_queue) {
        upload_contents = mk_list_entry(head, struct upload_queue, _head);
        s3_store_file_delete(ctx, upload_contents->upload_file);
        multipart_upload_destroy(upload_contents->m_upload_file);
        remove_from_queue(upload_contents);
    }

    flb_free(ctx);
}

static int cb_s3_init(struct flb_output_instance *ins,
                      struct flb_config *config, void *data)
{
    int ret;
    int i;
    flb_sds_t tmp_sds;
    char *role_arn = NULL;
    char *session_name;
    const char *tmp = NULL;
    struct flb_s3 *ctx = NULL;
    struct flb_aws_client_generator *generator;
    (void) config;
    (void) data;
    char *ep;
    struct flb_split_entry *tok;
    struct mk_list *split;
    int list_size;
    FILE *cmdp = NULL;
    char buf[32] = {0};

    ctx = flb_calloc(1, sizeof(struct flb_s3));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    mk_list_init(&ctx->uploads);
    mk_list_init(&ctx->upload_queue);

    ctx->retry_time = 0;
    ctx->upload_queue_success = FLB_FALSE;

    /* Export context */
    flb_output_set_context(ins, ctx);

    /* initialize config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        return -1;
    }

    /* the check against -1 is works here because size_t is unsigned
     * and (int) -1 == unsigned max value
     * Fluent Bit uses -1 (which becomes max value) to indicate undefined
     */
    if (ctx->ins->total_limit_size != -1) {
        flb_plg_warn(ctx->ins, "Please use 'store_dir_limit_size' with s3 output instead of 'storage.total_limit_size'. "
                     "S3 has its own buffer files located in the store_dir.");
    }

    /* Date key */
    ctx->date_key = ctx->json_date_key;
    tmp = flb_output_get_property("json_date_key", ins);
    if (tmp) {
        /* Just check if we have to disable it */
        if (flb_utils_bool(tmp) == FLB_FALSE) {
            ctx->date_key = NULL;
        }
    }

    /* Date format for JSON output */
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

    /*
     * store_dir is the user input, buffer_dir is what the code uses
     * We append the bucket name to the dir, to support multiple instances
     * of this plugin using the same buffer dir
     */
    tmp_sds = concat_path(ctx->store_dir, ctx->bucket);
    if (!tmp_sds) {
        flb_plg_error(ctx->ins, "Could not construct buffer path");
        return -1;
    }
    ctx->buffer_dir = tmp_sds;

    /* Initialize local storage */
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

    /* validate 'total_file_size' */
    if (ctx->file_size <= 0) {
        flb_plg_error(ctx->ins, "Failed to parse total_file_size %s", tmp);
        return -1;
    }
    if (ctx->file_size < 1000000) {
        flb_plg_error(ctx->ins, "total_file_size must be at least 1MB");
        return -1;
    }
    if (ctx->file_size > MAX_FILE_SIZE) {
        flb_plg_error(ctx->ins, "Max total_file_size is %s bytes", MAX_FILE_SIZE_STR);
        return -1;
    }
    flb_plg_info(ctx->ins, "Using upload size %lu bytes", ctx->file_size);

    if (ctx->use_put_object == FLB_FALSE && ctx->file_size < 2 * MIN_CHUNKED_UPLOAD_SIZE) {
            flb_plg_info(ctx->ins,
                         "total_file_size is less than 10 MB, will use PutObject API");
            ctx->use_put_object = FLB_TRUE;
    }

    tmp = flb_output_get_property("compression", ins);
    if (tmp) {
        ret = flb_aws_compression_get_type(tmp);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "unknown compression: %s", tmp);
            return -1;
        }
        if (ctx->use_put_object == FLB_FALSE && ctx->compression == FLB_AWS_COMPRESS_ARROW) {
            flb_plg_error(ctx->ins,
                          "use_put_object must be enabled when Apache Arrow is enabled");
            return -1;
        }
        if (ctx->use_put_object == FLB_FALSE && ctx->compression == FLB_AWS_COMPRESS_PARQUET) {
            flb_plg_error(ctx->ins,
                          "use_put_object must be enabled when parquet is enabled");
            return -1;
        }
        ctx->compression = ret;
    }

    /* Parquet */
    ctx->parquet_compression = NULL;
    ctx->parquet_record_type = NULL;
    ctx->parquet_schema_type = NULL;
    ctx->parquet_schema_file = NULL;

    if (ctx->compression == FLB_AWS_COMPRESS_PARQUET) {
        cmdp = flb_popen(DEFAULT_PARQUET_COMMAND_CHECK, "r");
        if (cmdp == NULL) {
            flb_plg_error(ctx->ins, "command %s failed. Is 'columnify' installed and in your PATH?",
                          DEFAULT_PARQUET_COMMAND_CHECK);
            goto on_error;
        }
        flb_pclose(cmdp);

        /* parquet.compression */
        tmp = flb_output_get_property("parquet.compression", ins);
        if (tmp != NULL) {
            if (strncasecmp(tmp, "uncompressed", 12) != 0 &&
                strncasecmp(tmp, "snappy", 6) != 0 &&
                strncasecmp(tmp, "gzip", 4) != 0 &&
                strncasecmp(tmp, "zstd", 4) != 0) {
                flb_plg_error(ctx->ins, "unsupported or unknown parquet.compression format %s", tmp);
                goto on_error;
            }
            for (i = 0; i < strlen(tmp); i++) {
                buf[i] = toupper(tmp[i]);
            }
            ctx->parquet_compression = flb_sds_create_len(buf, strlen(buf));
        }
        else {
            ctx->parquet_compression = flb_sds_create(DEFAULT_PARQUET_COMPRESSION_FORMAT_UPCASES);
        }
        if (!ctx->parquet_compression) {
            flb_plg_error(ctx->ins, "failed to allocate parquet.compression");
            goto on_error;
        }

        /* parquet.record_type */
        tmp = flb_output_get_property("parquet.record_type", ins);
        if (!tmp) {
            ctx->parquet_record_type = flb_sds_create(DEFAULT_PARQUET_RECORD_TYPE);
        }
        else {
            if (strncasecmp(tmp, "json", 4) == 0) {
                tmp = "jsonl";
            }
            else if (strncasecmp(tmp, "msgpack", 7) != 0 && strncasecmp(tmp, "jsonl", 5) != 0) {
                flb_plg_error(ctx->ins, "unknown parquet.record_type format %s", tmp);
                goto on_error;
            }
            ctx->parquet_record_type = flb_sds_create(tmp);
        }
        if (!ctx->parquet_record_type) {
            flb_plg_error(ctx->ins, "failed to allocate parquet.record_type");
            goto on_error;
        }

        /* parquet.schema_type */
        tmp = flb_output_get_property("parquet.schema_type", ins);
        if (!tmp) {
            ctx->parquet_schema_type = flb_sds_create(DEFAULT_PARQUET_SCHEMA_TYPE);
        }
        else {
            if (strncasecmp(tmp, "avro", 4) != 0 && strncasecmp(tmp, "bigquery", 8) != 0) {
                flb_plg_error(ctx->ins, "unknown parquet.schema_type format %s", tmp);
                goto on_error;
            }
            ctx->parquet_schema_type = flb_sds_create(tmp);
        }
        if (!ctx->parquet_schema_type) {
            flb_plg_error(ctx->ins, "failed to allocate parquet.schema_type");
            goto on_error;
        }

        /* parquet.schema_file */
        tmp = flb_output_get_property("parquet.schema_file", ins);
        if (!tmp) {
            flb_plg_error(ctx->ins, "parquet.schema_file is a required property for parquet format");
            goto on_error;
        }
        ctx->parquet_schema_file = flb_sds_create(tmp);
        if (!ctx->parquet_schema_file) {
            flb_plg_error(ctx->ins, "failed to allocate parquet.schema_file");
            goto on_error;
        }
    }

    tmp = flb_output_get_property("content_type", ins);
    if (tmp) {
        ctx->content_type = (char *) tmp;
    }
    if (ctx->use_put_object == FLB_FALSE) {
        /* upload_chunk_size */
        if (ctx->upload_chunk_size <= 0) {
            flb_plg_error(ctx->ins, "Failed to parse upload_chunk_size %s", tmp);
            return -1;
        }
        if (ctx->upload_chunk_size > ctx->file_size) {
            flb_plg_error(ctx->ins,
                          "upload_chunk_size can not be larger than total_file_size");
            return -1;
        }
        if (ctx->upload_chunk_size < MIN_CHUNKED_UPLOAD_SIZE) {
            flb_plg_error(ctx->ins, "upload_chunk_size must be at least 5,242,880 bytes");
            return -1;
        }
        if (ctx->compression == FLB_AWS_COMPRESS_GZIP) {
            if(ctx->upload_chunk_size > MAX_CHUNKED_UPLOAD_COMPRESS_SIZE) {
                flb_plg_error(ctx->ins, "upload_chunk_size in compressed multipart upload cannot exceed 5GB");
                return -1;
            }
        } else {
            if (ctx->upload_chunk_size > MAX_CHUNKED_UPLOAD_SIZE) {
                flb_plg_error(ctx->ins, "Max upload_chunk_size is 50MB");
                return -1;
            }
        }
    }

    if (ctx->upload_chunk_size != MIN_CHUNKED_UPLOAD_SIZE &&
        (ctx->upload_chunk_size * 2) > ctx->file_size) {
        flb_plg_error(ctx->ins, "total_file_size is less than 2x upload_chunk_size");
        return -1;
    }

    if (ctx->use_put_object == FLB_TRUE) {
        /*
         * code internally uses 'upload_chunk_size' as the unit for each Put,
         * regardless of which API is used to send data
         */
        ctx->upload_chunk_size = ctx->file_size;
        if (ctx->file_size > MAX_FILE_SIZE_PUT_OBJECT) {
            flb_plg_error(ctx->ins, "Max total_file_size is 50M when use_put_object is enabled");
            return -1;
        }
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
        /* default endpoint for the given region */
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

    /* AWS provider needs a separate TLS instance */
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
                                                       flb_aws_client_generator(),
                                                       ctx->profile);

    if (!ctx->provider) {
        flb_plg_error(ctx->ins, "Failed to create AWS Credential Provider");
        return -1;
    }

    tmp = flb_output_get_property("role_arn", ins);
    if (tmp) {
        /* Use the STS Provider */
        ctx->base_provider = ctx->provider;
        role_arn = (char *) tmp;

        /* STS provider needs yet another separate TLS instance */
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

    /* read any remaining buffers from previous (failed) executions */
    ctx->has_old_buffers = s3_store_has_data(ctx);
    ctx->has_old_uploads = s3_store_has_uploads(ctx);

    /* Multipart */
    multipart_read_uploads_from_fs(ctx);

    if (mk_list_size(&ctx->uploads) > 0) {
        /* note that these should be sent */
        ctx->has_old_uploads = FLB_TRUE;
    }

    /* create S3 client */
    generator = flb_aws_client_generator();
    ctx->s3_client = generator->create();
    if (!ctx->s3_client) {
        return -1;
    }
    ctx->s3_client->name = "s3_client";
    ctx->s3_client->has_auth = FLB_TRUE;
    ctx->s3_client->provider = ctx->provider;
    ctx->s3_client->region = ctx->region;
    ctx->s3_client->service = "s3";
    ctx->s3_client->port = ctx->port;
    ctx->s3_client->flags = 0;
    ctx->s3_client->proxy = NULL;
    ctx->s3_client->s3_mode = S3_MODE_SIGNED_PAYLOAD;
    ctx->s3_client->retry_requests = ctx->retry_requests;

    if (ctx->insecure == FLB_TRUE) {
        ctx->s3_client->upstream = flb_upstream_create(config, ctx->endpoint, ctx->port,
                                                       FLB_IO_TCP, NULL);
    } else {
        ctx->s3_client->upstream = flb_upstream_create(config, ctx->endpoint, ctx->port,
                                                       FLB_IO_TLS, ctx->client_tls);
    }
    if (!ctx->s3_client->upstream) {
        flb_plg_error(ctx->ins, "Connection initialization error");
        return -1;
    }

    flb_output_upstream_set(ctx->s3_client->upstream, ctx->ins);

    ctx->s3_client->host = ctx->endpoint;

    /* set to sync mode and initialize credentials */
    ctx->provider->provider_vtable->sync(ctx->provider);
    ctx->provider->provider_vtable->init(ctx->provider);

    ctx->timer_created = FLB_FALSE;
    ctx->timer_ms = (int) (ctx->upload_timeout / 6) * 1000;
    if (ctx->timer_ms > UPLOAD_TIMER_MAX_WAIT) {
        ctx->timer_ms = UPLOAD_TIMER_MAX_WAIT;
    }
    else if (ctx->timer_ms < UPLOAD_TIMER_MIN_WAIT) {
        ctx->timer_ms = UPLOAD_TIMER_MIN_WAIT;
    }

    /*
     * S3 must ALWAYS use sync mode
     * In the timer thread we do a mk_list_foreach_safe on the queue of uplaods and chunks
     * Iterating over those lists is not concurrent safe. If a flush call ran at the same time
     * And deleted an item from the list, this could cause a crash/corruption.
     */
    flb_stream_disable_async_mode(&ctx->s3_client->upstream->base);

    /* clean up any old buffers found on startup */
    if (ctx->has_old_buffers == FLB_TRUE) {
        flb_plg_info(ctx->ins,
                     "Sending locally buffered data from previous "
                     "executions to S3; buffer=%s",
                     ctx->fs->root_path);
        ctx->has_old_buffers = FLB_FALSE;
        ret = put_all_chunks(ctx);
        if (ret < 0) {
            ctx->has_old_buffers = FLB_TRUE;
            flb_plg_error(ctx->ins,
                          "Failed to send locally buffered data left over "
                          "from previous executions; will retry. Buffer=%s",
                          ctx->fs->root_path);
        }
    }

    /* clean up any old uploads found on start up */
    if (ctx->has_old_uploads == FLB_TRUE) {
        flb_plg_info(ctx->ins,
                     "Completing multipart uploads from previous "
                     "executions to S3; buffer=%s",
                     ctx->stream_upload->path);
        ctx->has_old_uploads = FLB_FALSE;

        /*
         * we don't need to worry if this fails; it will retry each
         * time the upload callback is called
         */
         cb_s3_upload(config, ctx);
    }

    /* this is done last since in the previous block we make calls to AWS */
    ctx->provider->provider_vtable->upstream_set(ctx->provider, ctx->ins);

    return 0;

on_error:
    if (ctx) {
        s3_context_destroy(ctx);
    }
    return -1;
}

/*
 * return value is one of FLB_OK, FLB_RETRY, FLB_ERROR
 *
 * Chunk is allowed to be NULL
 */
static int upload_data(struct flb_s3 *ctx, struct s3_file *chunk,
                       struct multipart_upload *m_upload,
                       char *body, size_t body_size,
                       const char *tag, int tag_len)
{
    int init_upload = FLB_FALSE;
    int complete_upload = FLB_FALSE;
    int size_check = FLB_FALSE;
    int part_num_check = FLB_FALSE;
    int timeout_check = FLB_FALSE;
    int ret;
    void *payload_buf = NULL;
    size_t payload_size = 0;
    size_t preCompress_size = 0;
    time_t file_first_log_time = time(NULL);

    /*
     * When chunk does not exist, file_first_log_time will be the current time.
     * This is only for unit tests and prevents unit tests from segfaulting when chunk is
     * NULL because if so chunk->first_log_time will be NULl either and will cause
     * segfault during the process of put_object upload or mutipart upload.
     */
    if (chunk != NULL) {
        file_first_log_time = chunk->first_log_time;
    }

    if (ctx->compression == FLB_AWS_COMPRESS_PARQUET) {
        ret = flb_s3_parquet_compress(ctx, body, body_size, &payload_buf, &payload_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to compress data with %s", DEFAULT_PARQUET_COMMAND);
            return FLB_RETRY;
        }
        else {
            preCompress_size = body_size;
            body = (void *) payload_buf;
            body_size = payload_size;
        }
    }
    else if (ctx->compression == FLB_AWS_COMPRESS_GZIP) {
        /* Map payload */
        ret = flb_aws_compression_compress(ctx->compression, body, body_size, &payload_buf, &payload_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to compress data");
            return FLB_RETRY;
        } else {
            preCompress_size = body_size;
            body = (void *) payload_buf;
            body_size = payload_size;
        }
    }

    if (ctx->use_put_object == FLB_TRUE) {
        goto put_object;
    }

    if (s3_plugin_under_test() == FLB_TRUE) {
        init_upload = FLB_TRUE;
        complete_upload = FLB_TRUE;
        if (ctx->use_put_object == FLB_TRUE) {
            goto put_object;
        }
        else {
            goto multipart;
        }
    }

    if (m_upload == NULL) {
        if (chunk != NULL && time(NULL) >
            (chunk->create_time + ctx->upload_timeout + ctx->retry_time)) {
            /* timeout already reached, just PutObject */
            goto put_object;
        }
        else if (body_size >= ctx->file_size) {
            /* already big enough, just use PutObject API */
            goto put_object;
        }
        else if(body_size > MIN_CHUNKED_UPLOAD_SIZE) {
            init_upload = FLB_TRUE;
            goto multipart;
        }
        else {
            if (ctx->use_put_object == FLB_FALSE && ctx->compression == FLB_AWS_COMPRESS_GZIP) {
                flb_plg_info(ctx->ins, "Pre-compression upload_chunk_size= %zu, After compression, chunk is only %zu bytes, "
                                       "the chunk was too small, using PutObject to upload", preCompress_size, body_size);
            }
            goto put_object;
        }
    }
    else {
        /* existing upload */
        if (body_size < MIN_CHUNKED_UPLOAD_SIZE) {
            complete_upload = FLB_TRUE;
        }

        goto multipart;
    }

put_object:

    /*
     * remove chunk from buffer list
     */
    ret = s3_put_object(ctx, tag, file_first_log_time, body, body_size);
    if (ctx->compression == FLB_AWS_COMPRESS_GZIP) {
        flb_free(payload_buf);
    }
    else if (ctx->compression == FLB_AWS_COMPRESS_PARQUET) {
        flb_sds_destroy(payload_buf);
    }
    if (ret < 0) {
        /* re-add chunk to list */
        if (chunk) {
            s3_store_file_unlock(chunk);
            chunk->failures += 1;
        }
        return FLB_RETRY;
    }

    /* data was sent successfully- delete the local buffer */
    if (chunk) {
        s3_store_file_delete(ctx, chunk);
    }
    return FLB_OK;

multipart:

    if (init_upload == FLB_TRUE) {
        m_upload = create_upload(ctx, tag, tag_len, file_first_log_time);
        if (!m_upload) {
            flb_plg_error(ctx->ins, "Could not find or create upload for tag %s", tag);
            if (chunk) {
                s3_store_file_unlock(chunk);
            }
            if (ctx->compression == FLB_AWS_COMPRESS_GZIP) {
                flb_free(payload_buf);
            }
            return FLB_RETRY;
        }
    }

    if (m_upload->upload_state == MULTIPART_UPLOAD_STATE_NOT_CREATED) {
        ret = create_multipart_upload(ctx, m_upload);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Could not initiate multipart upload");
            if (chunk) {
                s3_store_file_unlock(chunk);
            }
            if (ctx->compression == FLB_AWS_COMPRESS_GZIP) {
                flb_free(payload_buf);
            }
            return FLB_RETRY;
        }
        m_upload->upload_state = MULTIPART_UPLOAD_STATE_CREATED;
    }

    ret = upload_part(ctx, m_upload, body, body_size);
    if (ret < 0) {
        if (ctx->compression == FLB_AWS_COMPRESS_GZIP) {
            flb_free(payload_buf);
        }
        m_upload->upload_errors += 1;
        /* re-add chunk to list */
        if (chunk) {
            s3_store_file_unlock(chunk);
            chunk->failures += 1;
        }
        return FLB_RETRY;
    }
    m_upload->part_number += 1;
    /* data was sent successfully- delete the local buffer */
    if (chunk) {
        s3_store_file_delete(ctx, chunk);
        chunk = NULL;
    }
    if (ctx->compression == FLB_AWS_COMPRESS_GZIP) {
        flb_free(payload_buf);
    }
    if (m_upload->bytes >= ctx->file_size) {
        size_check = FLB_TRUE;
        flb_plg_info(ctx->ins, "Will complete upload for %s because uploaded data is greater"
                     " than size set by total_file_size", m_upload->s3_key);
    }
    if (m_upload->part_number >= 10000) {
        part_num_check = FLB_TRUE;
        flb_plg_info(ctx->ins, "Will complete upload for %s because 10,000 chunks "
                     "(the API limit) have been uploaded", m_upload->s3_key);
    }
    if (time(NULL) >
        (m_upload->init_time + ctx->upload_timeout + ctx->retry_time)) {
        timeout_check = FLB_TRUE;
        flb_plg_info(ctx->ins, "Will complete upload for %s because upload_timeout"
                     " has elapsed", m_upload->s3_key);
    }
    if (size_check || part_num_check || timeout_check) {
        complete_upload = FLB_TRUE;
    }

    if (complete_upload == FLB_TRUE) {
        /* mark for completion- the upload timer will handle actual completion */
        m_upload->upload_state = MULTIPART_UPLOAD_STATE_COMPLETE_IN_PROGRESS;
    }

    return FLB_OK;
}


/*
 * Attempts to send all chunks to S3 using PutObject
 * Used on shut down to try to send all buffered data
 * Used on start up to try to send any leftover buffers from previous executions
 */
static int put_all_chunks(struct flb_s3 *ctx)
{
    struct s3_file *chunk;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *f_head;
    struct flb_fstore_file *fsf;
    struct flb_fstore_stream *fs_stream;
    void *payload_buf = NULL;
    size_t payload_size = 0;
    char *buffer = NULL;
    size_t buffer_size;
    int ret;

    mk_list_foreach(head, &ctx->fs->streams) {
        /* skip multi upload stream */
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);
        if (fs_stream == ctx->stream_upload) {
            continue;
        }
        /* skip metadata stream */
        if (fs_stream == ctx->stream_metadata) {
            continue;
        }

        mk_list_foreach_safe(f_head, tmp, &fs_stream->files) {
            fsf = mk_list_entry(f_head, struct flb_fstore_file, _head);
            chunk = fsf->data;

            /* Locked chunks are being processed, skip */
            if (chunk->locked == FLB_TRUE) {
                continue;
            }

            if (chunk->failures >= MAX_UPLOAD_ERRORS) {
                flb_plg_warn(ctx->ins,
                             "Chunk for tag %s failed to send %i times, "
                             "will not retry",
                             (char *) fsf->meta_buf, MAX_UPLOAD_ERRORS);
                flb_fstore_file_inactive(ctx->fs, fsf);
                continue;
            }

            ret = construct_request_buffer(ctx, NULL, chunk,
                                           &buffer, &buffer_size);
            if (ret < 0) {
                flb_plg_error(ctx->ins,
                              "Could not construct request buffer for %s",
                              chunk->file_path);
                return -1;
            }

            if (ctx->compression == FLB_AWS_COMPRESS_PARQUET) {
                ret = flb_s3_parquet_compress(ctx, buffer, buffer_size, &payload_buf, &payload_size);
                if (ret == -1) {
                    flb_plg_error(ctx->ins, "Failed to compress data with %s", DEFAULT_PARQUET_COMMAND);
                    return FLB_RETRY;
                }
                else {
                    flb_plg_info(ctx->ins, "Pre-compression chunk size is %zu, After compression, chunk is %zu bytes", buffer_size, payload_size);
                    flb_free(buffer);

                    buffer = (void *) payload_buf;
                    buffer_size = payload_size;
                }
            }
            else if (ctx->compression != FLB_AWS_COMPRESS_NONE) {
                /* Map payload */
                ret = flb_aws_compression_compress(ctx->compression, buffer, buffer_size, &payload_buf, &payload_size);
                if (ret == -1) {
                    flb_plg_error(ctx->ins, "Failed to compress data, uploading uncompressed data instead to prevent data loss");
                } else {
                    flb_plg_info(ctx->ins, "Pre-compression chunk size is %zu, After compression, chunk is %zu bytes", buffer_size, payload_size);
                    flb_free(buffer);

                    buffer = (void *) payload_buf;
                    buffer_size = payload_size;
                }
            }

            ret = s3_put_object(ctx, (const char *)
                                fsf->meta_buf,
                                chunk->create_time, buffer, buffer_size);
            if (ctx->compression == FLB_AWS_COMPRESS_PARQUET) {
                flb_sds_destroy(buffer);
            }
            else {
                flb_free(buffer);
            }
            if (ret < 0) {
                s3_store_file_unlock(chunk);
                chunk->failures += 1;
                return -1;
            }

            /* data was sent successfully- delete the local buffer */
            s3_store_file_delete(ctx, chunk);
        }
    }

    return 0;
}

/*
 * Either new_data or chunk can be NULL, but not both
 */
static int construct_request_buffer(struct flb_s3 *ctx, flb_sds_t new_data,
                                    struct s3_file *chunk,
                                    char **out_buf, size_t *out_size)
{
    char *body;
    char *tmp;
    size_t body_size = 0;
    char *buffered_data = NULL;
    size_t buffer_size = 0;
    int ret;

    if (new_data == NULL && chunk == NULL) {
        flb_plg_error(ctx->ins, "[construct_request_buffer] Something went wrong"
                      " both chunk and new_data are NULL");
        return -1;
    }

    if (chunk) {
        ret = s3_store_file_read(ctx, chunk, &buffered_data, &buffer_size);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Could not read locally buffered data %s",
                          chunk->file_path);
            return -1;
        }

        /*
         * lock the chunk from buffer list
         */
        s3_store_file_lock(chunk);
        body = buffered_data;
        body_size = buffer_size;
    }

    /*
     * If new data is arriving, increase the original 'buffered_data' size
     * to append the new one.
     */
    if (new_data) {
        body_size += flb_sds_len(new_data);

        tmp = flb_realloc(buffered_data, body_size + 1);
        if (!tmp) {
            flb_errno();
            flb_free(buffered_data);
            if (chunk) {
                s3_store_file_unlock(chunk);
            }
            return -1;
        }
        body = buffered_data = tmp;
        memcpy(body + buffer_size, new_data, flb_sds_len(new_data));
        body[body_size] = '\0';
    }

    *out_buf = body;
    *out_size = body_size;

    return 0;
}

static int s3_put_object(struct flb_s3 *ctx, const char *tag, time_t file_first_log_time,
                         char *body, size_t body_size)
{
    flb_sds_t s3_key = NULL;
    struct flb_http_client *c = NULL;
    struct flb_aws_client *s3_client;
    struct flb_aws_header *headers = NULL;
    char *random_alphanumeric;
    int append_random = FLB_FALSE;
    int len;
    int ret;
    int num_headers = 0;
    char *final_key;
    flb_sds_t uri;
    flb_sds_t tmp;
    char final_body_md5[25];

    s3_key = flb_get_s3_key(ctx->s3_key_format, file_first_log_time, tag,
                            ctx->tag_delimiters, ctx->seq_index);
    if (!s3_key) {
        flb_plg_error(ctx->ins, "Failed to construct S3 Object Key for %s", tag);
        return -1;
    }

    len = strlen(s3_key);
    if ((len + 16) <= 1024 && !ctx->key_fmt_has_uuid && !ctx->static_file_path &&
        !ctx->key_fmt_has_seq_index) {
        append_random = FLB_TRUE;
        len += 16;
    }
    len += strlen(ctx->bucket + 1);

    uri = flb_sds_create_size(len);

    if (append_random == FLB_TRUE) {
        random_alphanumeric = flb_sts_session_name();
        if (!random_alphanumeric) {
            flb_sds_destroy(s3_key);
            flb_sds_destroy(uri);
            flb_plg_error(ctx->ins, "Failed to create randomness for S3 key %s", tag);
            return -1;
        }
        /* only use 8 chars of the random string */
        random_alphanumeric[8] = '\0';

        tmp = flb_sds_printf(&uri, "/%s%s-object%s", ctx->bucket, s3_key,
                             random_alphanumeric);
        flb_free(random_alphanumeric);
    }
    else {
        tmp = flb_sds_printf(&uri, "/%s%s", ctx->bucket, s3_key);
    }

    if (!tmp) {
        flb_sds_destroy(s3_key);
        flb_plg_error(ctx->ins, "Failed to create PutObject URI");
        return -1;
    }
    flb_sds_destroy(s3_key);
    uri = tmp;

    memset(final_body_md5, 0, sizeof(final_body_md5));
    if (ctx->send_content_md5 == FLB_TRUE) {
        ret = get_md5_base64(body, body_size,
                             final_body_md5, sizeof(final_body_md5));
        if (ret != 0) {
            flb_plg_error(ctx->ins, "Failed to create Content-MD5 header");
            flb_sds_destroy(uri);
            return -1;
        }
    }

    /* Update file and increment index value right before request */
    if (ctx->key_fmt_has_seq_index) {
        ctx->seq_index++;

        ret = write_seq_index(ctx->seq_index_file, ctx->seq_index);
        if (ret < 0 && access(ctx->seq_index_file, F_OK) == 0) {
            ctx->seq_index--;
            flb_plg_error(ctx->ins, "Failed to update sequential index metadata file");
            return -1;
        }
    }

    s3_client = ctx->s3_client;
    if (s3_plugin_under_test() == FLB_TRUE) {
        c = mock_s3_call("TEST_PUT_OBJECT_ERROR", "PutObject");
    }
    else {
        ret = create_headers(ctx, final_body_md5, &headers, &num_headers, FLB_FALSE);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to create headers");
            flb_sds_destroy(uri);
            goto decrement_index;
        }
        c = s3_client->client_vtable->request(s3_client, FLB_HTTP_PUT,
                                              uri, body, body_size,
                                              headers, num_headers);
        flb_free(headers);
    }
    if (c) {
        flb_plg_debug(ctx->ins, "PutObject http status=%d", c->resp.status);
        if (c->resp.status == 200) {
            /*
             * URI contains bucket name, so we must advance over it
             * to print the object key
             */
            final_key = uri + strlen(ctx->bucket) + 1;
            flb_plg_info(ctx->ins, "Successfully uploaded object %s", final_key);
            flb_sds_destroy(uri);
            flb_http_client_destroy(c);

            return 0;
        }
        flb_aws_print_xml_error(c->resp.payload, c->resp.payload_size,
                                "PutObject", ctx->ins);
        if (c->resp.data != NULL) {
            flb_plg_error(ctx->ins, "Raw PutObject response: %s", c->resp.data);
        }
        flb_http_client_destroy(c);
    }

    flb_plg_error(ctx->ins, "PutObject request failed");
    flb_sds_destroy(uri);
    goto decrement_index;

decrement_index:
    if (ctx->key_fmt_has_seq_index) {
        ctx->seq_index--;

        ret = write_seq_index(ctx->seq_index_file, ctx->seq_index);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to decrement index after request error");
            return -1;
        }
    }
    return -1;
}

int get_md5_base64(char *buf, size_t buf_size, char *md5_str, size_t md5_str_size)
{
    unsigned char md5_bin[16];
    size_t olen;
    int ret;

    ret = flb_hash_simple(FLB_HASH_MD5,
                          (unsigned char *) buf, buf_size,
                          md5_bin, sizeof(md5_bin));

    if (ret != FLB_CRYPTO_SUCCESS) {
        return -1;
    }

    ret = flb_base64_encode((unsigned char*) md5_str, md5_str_size,
                            &olen, md5_bin, sizeof(md5_bin));
    if (ret != 0) {
        return ret;
    }

    return 0;
}

static struct multipart_upload *get_upload(struct flb_s3 *ctx,
                                           const char *tag, int tag_len)
{
    struct multipart_upload *m_upload = NULL;
    struct multipart_upload *tmp_upload = NULL;
    struct mk_list *tmp;
    struct mk_list *head;

    mk_list_foreach_safe(head, tmp, &ctx->uploads) {
        tmp_upload = mk_list_entry(head, struct multipart_upload, _head);

        if (tmp_upload->upload_state == MULTIPART_UPLOAD_STATE_COMPLETE_IN_PROGRESS) {
            continue;
        }
        if (tmp_upload->upload_errors >= MAX_UPLOAD_ERRORS) {
            tmp_upload->upload_state = MULTIPART_UPLOAD_STATE_COMPLETE_IN_PROGRESS;
            flb_plg_error(ctx->ins, "Upload for %s has reached max upload errors",
                          tmp_upload->s3_key);
            continue;
        }
        if (strcmp(tmp_upload->tag, tag) == 0) {
            m_upload = tmp_upload;
            break;
        }
    }

    return m_upload;
}

static struct multipart_upload *create_upload(struct flb_s3 *ctx, const char *tag,
                                              int tag_len, time_t file_first_log_time)
{
    int ret;
    struct multipart_upload *m_upload = NULL;
    flb_sds_t s3_key = NULL;
    flb_sds_t tmp_sds = NULL;

    /* create new upload for this key */
    m_upload = flb_calloc(1, sizeof(struct multipart_upload));
    if (!m_upload) {
        flb_errno();
        return NULL;
    }
    s3_key = flb_get_s3_key(ctx->s3_key_format, file_first_log_time, tag,
                            ctx->tag_delimiters, ctx->seq_index);
    if (!s3_key) {
        flb_plg_error(ctx->ins, "Failed to construct S3 Object Key for %s", tag);
        flb_free(m_upload);
        return NULL;
    }
    m_upload->s3_key = s3_key;
    tmp_sds = flb_sds_create_len(tag, tag_len);
    if (!tmp_sds) {
        flb_errno();
        flb_free(m_upload);
        return NULL;
    }
    m_upload->tag = tmp_sds;
    m_upload->upload_state = MULTIPART_UPLOAD_STATE_NOT_CREATED;
    m_upload->part_number = 1;
    m_upload->init_time = time(NULL);
    mk_list_add(&m_upload->_head, &ctx->uploads);

    /* Update file and increment index value right before request */
    if (ctx->key_fmt_has_seq_index) {
        ctx->seq_index++;

        ret = write_seq_index(ctx->seq_index_file, ctx->seq_index);
        if (ret < 0) {
            ctx->seq_index--;
            flb_sds_destroy(s3_key);
            flb_plg_error(ctx->ins, "Failed to write to sequential index metadata file");
            return NULL;
        }
    }

    return m_upload;
}

/* Adds an entry to upload queue */
static int add_to_queue(struct flb_s3 *ctx, struct s3_file *upload_file,
                 struct multipart_upload *m_upload_file, const char *tag, int tag_len)
{
    struct upload_queue *upload_contents;
    flb_sds_t tag_cpy;

    /* Create upload contents object and add to upload queue */
    upload_contents = flb_calloc(1, sizeof(struct upload_queue));
    if (upload_contents == NULL) {
        flb_plg_error(ctx->ins, "Error allocating memory for upload_queue entry");
        flb_errno();
        return -1;
    }
    upload_contents->upload_file = upload_file;
    upload_contents->m_upload_file = m_upload_file;
    upload_contents->tag_len = tag_len;
    upload_contents->retry_counter = 0;
    upload_contents->upload_time = -1;

    /* Necessary to create separate string for tag to prevent corruption */
    tag_cpy = flb_sds_create_len(tag, tag_len);
    if (!tag_cpy) {
        flb_errno();
        flb_free(upload_contents);
        return -1;
    }
    upload_contents->tag = tag_cpy;


    /* Add entry to upload queue */
    mk_list_add(&upload_contents->_head, &ctx->upload_queue);
    return 0;
}

/* Removes an entry from upload_queue */
void remove_from_queue(struct upload_queue *entry)
{
    mk_list_del(&entry->_head);
    flb_sds_destroy(entry->tag);
    flb_free(entry);
    return;
}

/* Validity check for upload queue object */
static int upload_queue_valid(struct upload_queue *upload_contents, time_t now,
                              void *out_context)
{
    struct flb_s3 *ctx = out_context;

    if (upload_contents == NULL) {
        flb_plg_error(ctx->ins, "Error getting entry from upload_queue");
        return -1;
    }
    if (upload_contents->_head.next == NULL || upload_contents->_head.prev == NULL) {
        flb_plg_debug(ctx->ins, "Encountered previously deleted entry in "
                      "upload_queue. Deleting invalid entry");
        mk_list_del(&upload_contents->_head);
        return -1;
    }
    if (upload_contents->upload_file->locked == FLB_FALSE) {
        flb_plg_debug(ctx->ins, "Encountered unlocked file in upload_queue. "
                      "Exiting");
        return -1;
    }
    if (upload_contents->upload_file->size <= 0) {
        flb_plg_debug(ctx->ins, "Encountered empty chunk file in upload_queue. "
                      "Deleting empty chunk file");
        remove_from_queue(upload_contents);
        return -1;
    }
    if (now < upload_contents->upload_time) {
        flb_plg_debug(ctx->ins, "Found valid chunk file but not ready to upload");
        return -1;
    }
    return 0;
}

static int send_upload_request(void *out_context, flb_sds_t chunk,
                               struct s3_file *upload_file,
                               struct multipart_upload *m_upload_file,
                               const char *tag, int tag_len)
{
    int ret;
    char *buffer;
    size_t buffer_size;
    struct flb_s3 *ctx = out_context;

    /* Create buffer to upload to S3 */
    ret = construct_request_buffer(ctx, chunk, upload_file, &buffer, &buffer_size);
    flb_sds_destroy(chunk);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not construct request buffer for %s",
                      upload_file->file_path);
        return -1;
    }

    /* Upload to S3 */
    ret = upload_data(ctx, upload_file, m_upload_file, buffer, buffer_size, tag, tag_len);
    flb_free(buffer);

    return ret;
}

static int buffer_chunk(void *out_context, struct s3_file *upload_file,
                        flb_sds_t chunk, int chunk_size,
                        const char *tag, int tag_len,
                        time_t file_first_log_time)
{
    int ret;
    struct flb_s3 *ctx = out_context;

    ret = s3_store_buffer_put(ctx, upload_file, tag,
                              tag_len, chunk, (size_t) chunk_size, file_first_log_time);
    flb_sds_destroy(chunk);
    if (ret < 0) {
        flb_plg_warn(ctx->ins, "Could not buffer chunk. Data order preservation "
                     "will be compromised");
        return -1;
    }
    return 0;
}

/* Uploads all chunk files in queue synchronously */
static void s3_upload_queue(struct flb_config *config, void *out_context)
{
    int ret;
    time_t now;
    struct upload_queue *upload_contents;
    struct flb_s3 *ctx = out_context;
    struct mk_list *tmp;
    struct mk_list *head;

    flb_plg_debug(ctx->ins, "Running upload timer callback (upload_queue)..");

    /* No chunks in upload queue. Scan for timed out chunks. */
    if (mk_list_size(&ctx->upload_queue) == 0) {
        flb_plg_debug(ctx->ins, "No files found in upload_queue. Scanning for timed "
                      "out chunks");
        cb_s3_upload(config, out_context);
    }

    /* Iterate through each file in upload queue */
    mk_list_foreach_safe(head, tmp, &ctx->upload_queue) {
        upload_contents = mk_list_entry(head, struct upload_queue, _head);

        now = time(NULL);

        /* Checks if upload_contents is valid */
        ret = upload_queue_valid(upload_contents, now, ctx);
        if (ret < 0) {
            goto exit;
        }

        /* Try to upload file. Return value can be -1, FLB_OK, FLB_ERROR, FLB_RETRY. */
        ret = send_upload_request(ctx, NULL, upload_contents->upload_file,
                                  upload_contents->m_upload_file,
                                  upload_contents->tag, upload_contents->tag_len);
        if (ret < 0) {
            goto exit;
        }
        else if (ret == FLB_OK) {
            remove_from_queue(upload_contents);
            ctx->retry_time = 0;
            ctx->upload_queue_success = FLB_TRUE;
        }
        else {
            s3_store_file_lock(upload_contents->upload_file);
            ctx->upload_queue_success = FLB_FALSE;

            /* If retry limit was reached, discard file and remove file from queue */
            upload_contents->retry_counter++;
            if (upload_contents->retry_counter >= MAX_UPLOAD_ERRORS) {
                flb_plg_warn(ctx->ins, "Chunk file failed to send %d times, will not "
                             "retry", upload_contents->retry_counter);
                s3_store_file_inactive(ctx, upload_contents->upload_file);
                multipart_upload_destroy(upload_contents->m_upload_file);
                remove_from_queue(upload_contents);
                continue;
            }

            /* Retry in N seconds */
            upload_contents->upload_time = now + 2 * upload_contents->retry_counter;
            ctx->retry_time += 2 * upload_contents->retry_counter;
            flb_plg_debug(ctx->ins, "Failed to upload file in upload_queue. Will not "
                          "retry for %d seconds", 2 * upload_contents->retry_counter);
            break;
        }
    }

exit:
    return;
}

static void cb_s3_upload(struct flb_config *config, void *data)
{
    struct flb_s3 *ctx = data;
    struct s3_file *chunk = NULL;
    struct multipart_upload *m_upload = NULL;
    struct flb_fstore_file *fsf;
    char *buffer = NULL;
    size_t buffer_size = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    int complete;
    int ret;
    time_t now;

    flb_plg_debug(ctx->ins, "Running upload timer callback (cb_s3_upload)..");

    now = time(NULL);

    /* Check all chunks and see if any have timed out */
    mk_list_foreach_safe(head, tmp, &ctx->stream_active->files) {
        fsf = mk_list_entry(head, struct flb_fstore_file, _head);
        chunk = fsf->data;

        if (now < (chunk->create_time + ctx->upload_timeout + ctx->retry_time)) {
            continue; /* Only send chunks which have timed out */
        }

        /* Locked chunks are being processed, skip */
        if (chunk->locked == FLB_TRUE) {
            continue;
        }

        m_upload = get_upload(ctx, (const char *) fsf->meta_buf, fsf->meta_size);

        ret = construct_request_buffer(ctx, NULL, chunk, &buffer, &buffer_size);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Could not construct request buffer for %s",
                          chunk->file_path);
            continue;
        }

        /* FYI: if construct_request_buffer() succeedeed, the s3_file is locked */
        ret = upload_data(ctx, chunk, m_upload, buffer, buffer_size,
                          (const char *) fsf->meta_buf, fsf->meta_size);
        flb_free(buffer);
        if (ret != FLB_OK) {
            flb_plg_error(ctx->ins, "Could not send chunk with tag %s",
                          (char *) fsf->meta_buf);
        }
    }

    /* Check all uploads and see if any need completion */
    mk_list_foreach_safe(head, tmp, &ctx->uploads) {
        m_upload = mk_list_entry(head, struct multipart_upload, _head);
        complete = FLB_FALSE;

        if (m_upload->complete_errors >= MAX_UPLOAD_ERRORS) {
            flb_plg_error(ctx->ins,
                          "Upload for %s has reached max completion errors, "
                          "plugin will give up", m_upload->s3_key);
            mk_list_del(&m_upload->_head);
            continue;
        }

        if (m_upload->upload_state == MULTIPART_UPLOAD_STATE_NOT_CREATED) {
            continue;
        }

        if (m_upload->upload_state == MULTIPART_UPLOAD_STATE_COMPLETE_IN_PROGRESS) {
            complete = FLB_TRUE;
        }
        if (time(NULL) > (m_upload->init_time + ctx->upload_timeout + ctx->retry_time)) {
            flb_plg_info(ctx->ins, "Completing upload for %s because upload_timeout"
                         " has passed", m_upload->s3_key);
            complete = FLB_TRUE;
        }
        if (complete == FLB_TRUE) {
            m_upload->upload_state = MULTIPART_UPLOAD_STATE_COMPLETE_IN_PROGRESS;
            mk_list_del(&m_upload->_head);
            ret = complete_multipart_upload(ctx, m_upload);
            if (ret == 0) {
                multipart_upload_destroy(m_upload);
            }
            else {
                mk_list_add(&m_upload->_head, &ctx->uploads);
                /* data was persisted, this can be retried */
                m_upload->complete_errors += 1;
                flb_plg_error(ctx->ins, "Could not complete upload %s, will retry..",
                              m_upload->s3_key);
            }
        }
    }

}

static flb_sds_t flb_pack_msgpack_extract_log_key(void *out_context, const char *data,
                                                  uint64_t bytes)
{
    int i;
    int records = 0;
    int map_size;
    int check = FLB_FALSE;
    int found = FLB_FALSE;
    int log_key_missing = 0;
    int ret;
    int alloc_error = 0;
    struct flb_s3 *ctx = out_context;
    char *val_buf;
    char *key_str = NULL;
    size_t key_str_size = 0;
    size_t msgpack_size = bytes + bytes / 4;
    size_t val_offset = 0;
    flb_sds_t out_buf;
    msgpack_object map;
    msgpack_object key;
    msgpack_object val;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    /* Iterate the original buffer and perform adjustments */
    records = flb_mp_count(data, bytes);
    if (records <= 0) {
        return NULL;
    }

    /* Allocate buffer to store log_key contents */
    val_buf = flb_calloc(1, msgpack_size);
    if (val_buf == NULL) {
        flb_plg_error(ctx->ins, "Could not allocate enough "
                      "memory to read record");
        flb_errno();
        return NULL;
    }

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        flb_free(val_buf);

        return NULL;
    }


    while (!alloc_error &&
           (ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {

        /* Get the record/map */
        map = *log_event.body;

        if (map.type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        map_size = map.via.map.size;

        /* Reset variables for found log_key and correct type */
        found = FLB_FALSE;
        check = FLB_FALSE;

        /* Extract log_key from record and append to output buffer */
        for (i = 0; i < map_size; i++) {
            key = map.via.map.ptr[i].key;
            val = map.via.map.ptr[i].val;

            if (key.type == MSGPACK_OBJECT_BIN) {
                key_str  = (char *) key.via.bin.ptr;
                key_str_size = key.via.bin.size;
                check = FLB_TRUE;
            }
            if (key.type == MSGPACK_OBJECT_STR) {
                key_str  = (char *) key.via.str.ptr;
                key_str_size = key.via.str.size;
                check = FLB_TRUE;
            }

            if (check == FLB_TRUE) {
                if (strncmp(ctx->log_key, key_str, key_str_size) == 0) {
                    found = FLB_TRUE;

                    /*
                     * Copy contents of value into buffer. Necessary to copy
                     * strings because flb_msgpack_to_json does not handle nested
                     * JSON gracefully and double escapes them.
                     */
                    if (val.type == MSGPACK_OBJECT_BIN) {
                        memcpy(val_buf + val_offset, val.via.bin.ptr, val.via.bin.size);
                        val_offset += val.via.bin.size;
                        val_buf[val_offset] = '\n';
                        val_offset++;
                    }
                    else if (val.type == MSGPACK_OBJECT_STR) {
                        memcpy(val_buf + val_offset, val.via.str.ptr, val.via.str.size);
                        val_offset += val.via.str.size;
                        val_buf[val_offset] = '\n';
                        val_offset++;
                    }
                    else {
                        ret = flb_msgpack_to_json(val_buf + val_offset,
                                                  msgpack_size - val_offset, &val);
                        if (ret < 0) {
                            break;
                        }
                        val_offset += ret;
                        val_buf[val_offset] = '\n';
                        val_offset++;
                    }
                    /* Exit early once log_key has been found for current record */
                    break;
                }
            }
        }

        /* If log_key was not found in the current record, mark log key as missing */
        if (found == FLB_FALSE) {
            log_key_missing++;
        }
    }

    /* Throw error once per chunk if at least one log key was not found */
    if (log_key_missing > 0) {
        flb_plg_error(ctx->ins, "Could not find log_key '%s' in %d records",
                      ctx->log_key, log_key_missing);
    }

    flb_log_event_decoder_destroy(&log_decoder);

    /* If nothing was read, destroy buffer */
    if (val_offset == 0) {
        flb_free(val_buf);
        return NULL;
    }
    val_buf[val_offset] = '\0';

    /* Create output buffer to store contents */
    out_buf = flb_sds_create(val_buf);
    if (out_buf == NULL) {
        flb_plg_error(ctx->ins, "Error creating buffer to store log_key contents.");
        flb_errno();
    }
    flb_free(val_buf);

    return out_buf;
}

static void unit_test_flush(void *out_context, struct s3_file *upload_file,
                            const char *tag, int tag_len, flb_sds_t chunk,
                            int chunk_size, struct multipart_upload *m_upload_file,
                            time_t file_first_log_time)
{
    int ret;
    char *buffer;
    size_t buffer_size;
    struct flb_s3 *ctx = out_context;

    s3_store_buffer_put(ctx, upload_file, tag, tag_len,
                        chunk, (size_t) chunk_size, file_first_log_time);
    ret = construct_request_buffer(ctx, chunk, upload_file, &buffer, &buffer_size);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not construct request buffer for %s",
                      upload_file->file_path);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    ret = upload_data(ctx, upload_file, m_upload_file, buffer, buffer_size, tag, tag_len);
    flb_free(buffer);

    FLB_OUTPUT_RETURN(ret);
}

static void flush_init(void *out_context)
{
    int ret;
    struct flb_s3 *ctx = out_context;
    struct flb_sched *sched;

    /* clean up any old buffers found on startup */
    if (ctx->has_old_buffers == FLB_TRUE) {
        flb_plg_info(ctx->ins,
                     "Sending locally buffered data from previous "
                     "executions to S3; buffer=%s",
                     ctx->fs->root_path);
        ctx->has_old_buffers = FLB_FALSE;
        ret = put_all_chunks(ctx);
        if (ret < 0) {
            ctx->has_old_buffers = FLB_TRUE;
            flb_plg_error(ctx->ins,
                          "Failed to send locally buffered data left over "
                          "from previous executions; will retry. Buffer=%s",
                          ctx->fs->root_path);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
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

        if (ctx->preserve_data_ordering) {
            ret = flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_PERM,
                                            ctx->timer_ms, s3_upload_queue, ctx, NULL);
        }
        else {
            ret = flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_PERM,
                                            ctx->timer_ms, cb_s3_upload, ctx, NULL);
        }
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Failed to create upload timer");
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        ctx->timer_created = FLB_TRUE;
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
    struct multipart_upload *m_upload_file = NULL;
    time_t file_first_log_time = 0;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    /* Cleanup old buffers and initialize upload timer */
    flush_init(ctx);

    /* Process chunk */
    if (ctx->log_key) {
        chunk = flb_pack_msgpack_extract_log_key(ctx,
                                                 event_chunk->data,
                                                 event_chunk->size);
    }
    else {
        chunk = flb_pack_msgpack_to_json_format(event_chunk->data,
                                                event_chunk->size,
                                                FLB_PACK_JSON_FORMAT_LINES,
                                                ctx->json_date_format,
                                                ctx->date_key);
    }
    if (chunk == NULL) {
        flb_plg_error(ctx->ins, "Could not marshal msgpack to output string");
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }
    chunk_size = flb_sds_len(chunk);

    /* Get a file candidate matching the given 'tag' */
    upload_file = s3_store_file_get(ctx,
                                    event_chunk->tag,
                                    flb_sds_len(event_chunk->tag));

    if (upload_file == NULL) {
        ret = flb_log_event_decoder_init(&log_decoder,
                                         (char *) event_chunk->data,
                                         event_chunk->size);

        if (ret != FLB_EVENT_DECODER_SUCCESS) {
            flb_plg_error(ctx->ins,
                          "Log event decoder initialization error : %d", ret);

            flb_sds_destroy(chunk);

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
        /* Get file_first_log_time from upload_file */
        file_first_log_time = upload_file->first_log_time;
    }

    if (file_first_log_time == 0) {
        file_first_log_time = time(NULL);
    }

    /* Specific to unit tests, will not get called normally */
    if (s3_plugin_under_test() == FLB_TRUE) {
        unit_test_flush(ctx, upload_file,
                        event_chunk->tag, flb_sds_len(event_chunk->tag),
                        chunk, chunk_size,
                        m_upload_file, file_first_log_time);
    }

    /* Discard upload_file if it has failed to upload MAX_UPLOAD_ERRORS times */
    if (upload_file != NULL && upload_file->failures >= MAX_UPLOAD_ERRORS) {
        flb_plg_warn(ctx->ins, "File with tag %s failed to send %d times, will not "
                     "retry", event_chunk->tag, MAX_UPLOAD_ERRORS);
        s3_store_file_inactive(ctx, upload_file);
        upload_file = NULL;
    }

    /* If upload_timeout has elapsed, upload file */
    if (upload_file != NULL && time(NULL) >
        (upload_file->create_time + ctx->upload_timeout)) {
        upload_timeout_check = FLB_TRUE;
        flb_plg_info(ctx->ins, "upload_timeout reached for %s",
                     event_chunk->tag);
    }

    m_upload_file = get_upload(ctx,
                               event_chunk->tag, flb_sds_len(event_chunk->tag));

    if (m_upload_file != NULL && time(NULL) >
        (m_upload_file->init_time + ctx->upload_timeout)) {
        upload_timeout_check = FLB_TRUE;
        flb_plg_info(ctx->ins, "upload_timeout reached for %s", event_chunk->tag);
    }

    /* If total_file_size has been reached, upload file */
    if ((upload_file && upload_file->size + chunk_size > ctx->upload_chunk_size) ||
        (m_upload_file && m_upload_file->bytes + chunk_size > ctx->file_size)) {
        total_file_size_check = FLB_TRUE;
    }

    /* File is ready for upload, upload_file != NULL prevents from segfaulting. */
    if ((upload_file != NULL) && (upload_timeout_check == FLB_TRUE || total_file_size_check == FLB_TRUE)) {
        if (ctx->preserve_data_ordering == FLB_TRUE) {
            /* Buffer last chunk in file and lock file to prevent further changes */
            ret = buffer_chunk(ctx, upload_file, chunk, chunk_size,
                               event_chunk->tag, flb_sds_len(event_chunk->tag),
                               file_first_log_time);

            if (ret < 0) {
                FLB_OUTPUT_RETURN(FLB_RETRY);
            }
            s3_store_file_lock(upload_file);

            /* Add chunk file to upload queue */
            ret = add_to_queue(ctx, upload_file, m_upload_file,
                               event_chunk->tag, flb_sds_len(event_chunk->tag));
            if (ret < 0) {
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }

            /* Go through upload queue and return error if something went wrong */
            s3_upload_queue(config, ctx);
            if (ctx->upload_queue_success == FLB_FALSE) {
                ctx->upload_queue_success = FLB_TRUE;
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }
            FLB_OUTPUT_RETURN(FLB_OK);
        }
        else {
            /* Send upload directly without upload queue */
            ret = send_upload_request(ctx, chunk, upload_file, m_upload_file,
                                      event_chunk->tag,
                                      flb_sds_len(event_chunk->tag));
            if (ret < 0) {
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }
            FLB_OUTPUT_RETURN(ret);
        }
    }

    /* Buffer current chunk in filesystem and wait for next chunk from engine */
    ret = buffer_chunk(ctx, upload_file, chunk, chunk_size,
                       event_chunk->tag, flb_sds_len(event_chunk->tag),
                       file_first_log_time);

    if (ret < 0) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }
    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_s3_exit(void *data, struct flb_config *config)
{
    int ret;
    struct flb_s3 *ctx = data;
    struct multipart_upload *m_upload = NULL;
    struct mk_list *tmp;
    struct mk_list *head;

    if (!ctx) {
        return 0;
    }

    if (s3_store_has_data(ctx) == FLB_TRUE) {
        flb_plg_info(ctx->ins, "Sending all locally buffered data to S3");
        ret = put_all_chunks(ctx);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Could not send all chunks on exit");
        }
    }

    if (s3_store_has_uploads(ctx) == FLB_TRUE) {
        mk_list_foreach_safe(head, tmp, &ctx->uploads) {
            m_upload = mk_list_entry(head, struct multipart_upload, _head);

            if (m_upload->upload_state == MULTIPART_UPLOAD_STATE_NOT_CREATED) {
                continue;
            }

            if (m_upload->bytes > 0) {
                m_upload->upload_state = MULTIPART_UPLOAD_STATE_COMPLETE_IN_PROGRESS;
                mk_list_del(&m_upload->_head);
                ret = complete_multipart_upload(ctx, m_upload);
                if (ret == 0) {
                    multipart_upload_destroy(m_upload);
                }
                else {
                    mk_list_add(&m_upload->_head, &ctx->uploads);
                    flb_plg_error(ctx->ins, "Could not complete upload %s",
                                  m_upload->s3_key);
                }
            }
        }
    }

    s3_store_exit(ctx);
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
     FLB_CONFIG_MAP_SIZE, "total_file_size", "100000000",
     0, FLB_TRUE, offsetof(struct flb_s3, file_size),
     "Specifies the size of files in S3. Maximum size is 50GB, minimum is 1MB"
    },
    {
     FLB_CONFIG_MAP_SIZE, "upload_chunk_size", "5242880",
     0, FLB_TRUE, offsetof(struct flb_s3, upload_chunk_size),
     "This plugin uses the S3 Multipart Upload API to stream data to S3, "
     "ensuring your data gets-off-the-box as quickly as possible. "
     "This parameter configures the size of each “part” in the upload. "
     "The total_file_size option configures the size of the file you will see "
     "in S3; this option determines the size of chunks uploaded until that "
     "size is reached. These chunks are temporarily stored in chunk_buffer_path "
     "until their size reaches upload_chunk_size, which point the chunk is "
     "uploaded to S3. Default: 5M, Max: 50M, Min: 5M."
    },

    {
     FLB_CONFIG_MAP_TIME, "upload_timeout", "10m",
     0, FLB_TRUE, offsetof(struct flb_s3, upload_timeout),
     "Optionally specify a timeout for uploads. "
     "Whenever this amount of time has elapsed, Fluent Bit will complete an "
     "upload and create a new file in S3. For example, set this value to 60m "
     "and you will get a new file in S3 every hour. Default is 10m."
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
    "Compression type for S3 objects. 'gzip', 'arrow', and 'parquet' "
    "are the supported values. "
    "'arrow' is only an available if Apache Arrow was enabled at compile time. "
    "'parquet' is only an available if columify command is installed on a system. "
    "Defaults to no compression. "
    "If 'gzip' is selected, the Content-Encoding HTTP Header will be set to 'gzip'."
    "If 'parquet' is selected, the Content-Type HTTP Header will be set to 'application/octet-stream'."
    },
    {
     FLB_CONFIG_MAP_STR, "parquet.compression", "snappy",
     0, FLB_TRUE, offsetof(struct flb_s3, parquet_compression),
    "Compression type for Parquet format. 'uncompressed', 'snappy', 'gzip', "
    "'zstd' are the supported values. "
    "'lzo', 'brotli', 'lz4' are not supported for now. "
    "Defaults to snappy. "
    },
    {
     FLB_CONFIG_MAP_SIZE, "parquet.page_size", "8192",
     0, FLB_TRUE, offsetof(struct flb_s3, parquet_page_size),
    "Page size of parquet"
    "Defaults to 8192. "
    },
    {
     FLB_CONFIG_MAP_SIZE, "parquet.row_group_size", "134217728", /* 128 * 1024 * 1024 */
     0, FLB_TRUE, offsetof(struct flb_s3, parquet_row_group_size),
    "File row group size of parquet"
    "Defaults to 134217728 (= 128 * 1024 * 1024). "
    },
    {
     FLB_CONFIG_MAP_STR, "parquet.record_type", "json",
     0, FLB_FALSE, 0,
    "Record type for parquet objects. 'json' and 'msgpack' are the supported values. "
    "Defaults to json. "
    },
    {
     FLB_CONFIG_MAP_STR, "parquet.schema_type", "avro",
     0, FLB_FALSE, 0,
    "Record type for parquet objects. 'avro' and 'bigquery' are the supported values. "
    "Defaults to avro. "
    },
    {
     FLB_CONFIG_MAP_STR, "parquet.schema_file", NULL,
     0, FLB_FALSE, 0,
    "Schema file for parquet objects. "
    },
    {
     FLB_CONFIG_MAP_STR, "parquet.process_dir", DEFAULT_PARQUET_PROCESS_DIR,
     0, FLB_TRUE, offsetof(struct flb_s3, parquet_process_dir),
    "Specify a temporary directory for processing parquet objects. "
    "This paramater is effective for non Windows platforms. "
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
     "Directory to locally buffer data before sending. Plugin uses the S3 Multipart "
     "upload API to send data in chunks of 5 MB at a time- only a small amount of"
     " data will be locally buffered at any given point in time."
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
    "A series of characters which will be used to split the tag into “parts” for "
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
     0, FLB_TRUE, offsetof(struct flb_s3, use_put_object),
     "Use the S3 PutObject API, instead of the multipart upload API"
    },

    {
     FLB_CONFIG_MAP_BOOL, "send_content_md5", "false",
     0, FLB_TRUE, offsetof(struct flb_s3, send_content_md5),
     "Send the Content-MD5 header with object uploads, as is required when Object Lock is enabled"
    },

    {
     FLB_CONFIG_MAP_BOOL, "preserve_data_ordering", "true",
     0, FLB_TRUE, offsetof(struct flb_s3, preserve_data_ordering),
     "Normally, when an upload request fails, there is a high chance for the last "
     "received chunk to be swapped with a later chunk, resulting in data shuffling. "
     "This feature prevents this shuffling by using a queue logic for uploads."
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

    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_s3_plugin = {
    .name         = "s3",
    .description  = "Send to S3",
    .cb_init      = cb_s3_init,
    .cb_flush     = cb_s3_flush,
    .cb_exit      = cb_s3_exit,
    .workers      = 1,
    .flags        = FLB_OUTPUT_NET | FLB_IO_TLS,
    .config_map   = config_map
};
