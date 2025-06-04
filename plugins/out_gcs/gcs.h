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

#ifndef FLB_OUT_GCS_H
#define FLB_OUT_GCS_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_fstore.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>

/* GCS specific constants */
#define FLB_GCS_ENDPOINT_BASE         "https://storage.googleapis.com"
#define FLB_GCS_TOKEN_HOST            "oauth2.googleapis.com"
#define FLB_GCS_SCOPE                 "https://www.googleapis.com/auth/devstorage.read_write"

#define FLB_GCS_DEFAULT_CHUNK_SIZE    (5 * 1024 * 1024)    /* 5MB */
#define FLB_GCS_MAX_CHUNK_SIZE        (32 * 1024 * 1024)   /* 32MB */
#define FLB_GCS_DEFAULT_TIMEOUT       60                    /* 60 seconds */
#define FLB_GCS_DEFAULT_STORE_DIR     "/tmp/fluent-bit/gcs"
#define FLB_GCS_DEFAULT_STORE_LIMIT   0                     /* Unlimited */

#define FLB_GCS_MAX_UPLOAD_ERRORS     5
#define FLB_GCS_MAX_RETRY_ERRORS      3

/* File formats */
#define FLB_GCS_FORMAT_TEXT           0
#define FLB_GCS_FORMAT_JSON           1
#define FLB_GCS_FORMAT_PARQUET        2

/* Compression types */
#define FLB_GCS_COMPRESSION_NONE      0
#define FLB_GCS_COMPRESSION_GZIP      1

/* Upload states */
#define FLB_GCS_UPLOAD_STATE_NEW      0
#define FLB_GCS_UPLOAD_STATE_ACTIVE   1
#define FLB_GCS_UPLOAD_STATE_COMPLETE 2
#define FLB_GCS_UPLOAD_STATE_FAILED   3

/* Authentication modes */
#define FLB_GCS_AUTH_SERVICE_ACCOUNT  0
#define FLB_GCS_AUTH_ADC              1
#define FLB_GCS_AUTH_WORKLOAD_ID      2

/* File extension mappings for formats */
#define FLB_GCS_EXT_TEXT              ".txt"
#define FLB_GCS_EXT_JSON              ".json"
#define FLB_GCS_EXT_PARQUET           ".parquet"
#define FLB_GCS_EXT_GZIP              ".gz"

struct gcs_file {
    int locked;
    int failures;
    int format;
    int compression;
    size_t size;
    time_t create_time;
    time_t first_log_time;
    flb_sds_t file_path;
    flb_sds_t object_key;
    flb_sds_t tag;
    struct flb_fstore_file *fsf;
    struct mk_list _head;
};

struct gcs_upload {
    int upload_state;
    int upload_errors;
    int retry_count;
    flb_sds_t object_key;
    flb_sds_t tag;
    flb_sds_t upload_id;
    flb_sds_t session_uri;
    size_t bytes_uploaded;
    size_t total_size;
    time_t init_time;
    struct gcs_file *file;
    struct mk_list _head;
};

struct flb_gcs {
    /* Configuration parameters */
    char *bucket;
    char *project_id;
    char *region;
    char *object_key_format;
    char *credentials_file;
    char *service_account_email;
    char *store_dir;
    char *log_key;
    char *json_date_key;
    
    /* Settings */
    int format;
    int compression;
    int auth_type;
    int json_date_format;
    int preserve_data_ordering;
    int use_put_object;
    int static_file_path;
    
    /* Size and timing settings */
    size_t total_file_size;
    size_t upload_chunk_size;
    size_t store_dir_limit_size;
    time_t upload_timeout;
    int retry_limit;
    
    /* Authentication context */
    struct flb_oauth2 *oauth2;
    flb_sds_t access_token;
    time_t token_expires;
    
    /* HTTP client context */
    struct flb_upstream *u;
    struct flb_upstream *u_oauth;
    struct flb_config *config;
    struct flb_output_instance *ins;
    
    /* Local storage management */
    struct flb_fstore *fs;
    struct flb_fstore_stream *stream_active;
    struct flb_fstore_stream *stream_upload;
    
    /* Upload management */
    struct mk_list uploads;
    struct mk_list files;
    size_t current_buffer_size;
    int has_old_buffers;
    int has_old_uploads;
    
    /* Date formatting */
    struct tm *cached_gmtime;
    time_t cached_time;
    flb_sds_t cached_timestamp;
};

/* Function prototypes */

/* Plugin callbacks */
int cb_gcs_init(struct flb_output_instance *ins, struct flb_config *config,
                void *data);
void cb_gcs_flush(struct flb_event_chunk *event_chunk,
                  struct flb_output_flush *out_flush,
                  struct flb_input_instance *i_ins,
                  void *out_context,
                  struct flb_config *config);
int cb_gcs_exit(void *data, struct flb_config *config);

/* Configuration functions */
int gcs_config_init(struct flb_gcs *ctx, struct flb_output_instance *ins);
int gcs_config_check(struct flb_gcs *ctx);

/* Authentication functions */
int gcs_oauth2_init(struct flb_gcs *ctx);
int gcs_oauth2_token_refresh(struct flb_gcs *ctx);
flb_sds_t gcs_oauth2_get_token(struct flb_gcs *ctx);

/* HTTP client functions */
struct flb_http_client *gcs_http_client(struct flb_gcs *ctx,
                                        int method,
                                        const char *uri,
                                        const char *body,
                                        size_t body_len);
int gcs_http_send(struct flb_gcs *ctx, struct flb_http_client *c);

/* File management functions */
struct gcs_file *gcs_file_create(struct flb_gcs *ctx, const char *tag,
                                 time_t timestamp);
int gcs_file_write(struct flb_gcs *ctx, struct gcs_file *file,
                   const char *data, size_t size);
int gcs_file_close(struct flb_gcs *ctx, struct gcs_file *file);
void gcs_file_destroy(struct gcs_file *file);

/* Upload functions */
int gcs_upload_file(struct flb_gcs *ctx, struct gcs_file *file);
int gcs_upload_resumable_init(struct flb_gcs *ctx, struct gcs_upload *upload);
int gcs_upload_resumable_chunk(struct flb_gcs *ctx, struct gcs_upload *upload,
                               const char *data, size_t size);
int gcs_upload_resumable_complete(struct flb_gcs *ctx, struct gcs_upload *upload);

/* Utility functions */
flb_sds_t gcs_format_object_key(struct flb_gcs *ctx, const char *tag,
                                time_t timestamp);
int gcs_compress_data(struct flb_gcs *ctx, const char *data, size_t size,
                      char **out_data, size_t *out_size);
const char *gcs_get_content_type(struct flb_gcs *ctx);
const char *gcs_get_file_extension(struct flb_gcs *ctx);

/* Parquet support functions (optional) */
#ifdef FLB_HAVE_PARQUET
int gcs_parquet_write_init(struct gcs_file *file);
int gcs_parquet_write_record(struct gcs_file *file, msgpack_object *obj);
int gcs_parquet_write_close(struct gcs_file *file);
#endif

#endif /* FLB_OUT_GCS_H */