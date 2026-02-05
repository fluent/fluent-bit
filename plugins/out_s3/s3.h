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

#ifndef FLB_OUT_S3
#define FLB_OUT_S3

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_blob_db.h>
#include <fluent-bit/flb_hash_table.h>
#include <pthread.h>
#include <sys/types.h>  /* for off_t */
#include <fcntl.h>

/* Cross-platform file I/O compatibility macros */
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define flb_s3_unlink(path)     _unlink(path)
#define flb_s3_access(path, mode) _access((path), (mode))
#define flb_s3_open(path, flags, ...) _open((path), ((flags) | O_BINARY), ##__VA_ARGS__)
#define flb_s3_close(fd)        _close(fd)
#define flb_s3_read(fd, buf, count) _read((fd), (buf), (count))
#define flb_s3_lseek(fd, offset, origin) _lseeki64((fd), (offset), (origin))
#define flb_s3_stat(path, buf) _stat64((path), (buf))
#define flb_s3_fstat(fd, buf) _fstat64((fd), (buf))
#define flb_s3_stat_struct struct _stat64
#else
#include <unistd.h>
#define flb_s3_unlink(path)     unlink(path)
#define flb_s3_access(path, mode) access((path), (mode))
#define flb_s3_open(path, flags, ...) open((path), (flags), ##__VA_ARGS__)
#define flb_s3_close(fd)        close(fd)
#define flb_s3_read(fd, buf, count) read((fd), (buf), (count))
#define flb_s3_lseek(fd, offset, origin) lseek((fd), (offset), (origin))
#define flb_s3_stat(path, buf) stat((path), (buf))
#define flb_s3_fstat(fd, buf) fstat((fd), (buf))
#define flb_s3_stat_struct struct stat
#endif

/* Forward declaration for Parquet schema (defined in flb_parquet.h) */
struct flb_parquet_schema;

#define MAX_FILE_SIZE         54975581388800ULL  /* 50TB (AWS S3 max object size) */
#define MAX_FILE_SIZE_STR     "50TB"

#define MAX_UPLOAD_ERRORS 5

/* AWS S3 multipart upload constraints */
#define S3_MiB                      1048576ULL
#define S3_GiB                      (1024 * S3_MiB)
#define S3_AWS_MIN_PART_SIZE        (5 * S3_MiB)
#define S3_AWS_MAX_PART_SIZE        (5 * S3_GiB)
#define S3_AWS_MAX_PARTS            10000
#define S3_DEFAULT_PART_SIZE        (100 * S3_MiB)

/* Multipart upload error codes */
#define S3_MULTIPART_ERROR_GENERAL      -1
#define S3_MULTIPART_ERROR_NO_SUCH_UPLOAD -2

#define S3_SOURCE_FILE   0
#define S3_SOURCE_MEMORY 1

struct s3_data_source {
    int type;
    union {
        struct {
            const char *path;
            off_t offset_start;
            off_t offset_end;
        } file;
        struct {
            char *buf;
            size_t len;
        } memory;
    };
};

/* Queue Entry States */
enum s3_upload_state {
    S3_STATE_INITIATE_MULTIPART = 0, /* Create new multipart upload */
    S3_STATE_UPLOAD_PART,            /* Upload a single part (database-tracked) */
    S3_STATE_UPLOAD_FILE,            /* Upload a single file (non-database-tracked) */
};

struct upload_queue {
    int state;
    uint64_t file_id;
    uint64_t part_db_id;
    uint64_t part_id;

    struct s3_file *upload_file;

    flb_sds_t stream_path;
    off_t offset_start;
    off_t offset_end;

    flb_sds_t s3_key;
    flb_sds_t upload_id;

    flb_sds_t tag;
    int tag_len;
    int retry_counter;
    time_t upload_time;

    struct mk_list _head;
};

struct multipart_upload {
    flb_sds_t s3_key;
    flb_sds_t tag;
    flb_sds_t upload_id;
    time_t init_time;

    flb_sds_t etags[10000];
    int part_number;

    int parts_uploaded;
    size_t bytes;

    struct mk_list _head;

    int upload_errors;
    int complete_errors;
};

struct flb_s3 {
    char *bucket;
    char *region;
    char *s3_key_format;
    char *tag_delimiters;
    char *endpoint;
    char *sts_endpoint;
    char *canned_acl;
    char *content_type;
    char *storage_class;
    char *log_key;
    char *external_id;
    char *profile;
    int free_endpoint;
    int retry_requests;
    int send_content_md5;
    int static_file_path;
    int compression;                        /* Compression type (for Parquet internal or outer layer) */
    int port;
    int insecure;
    size_t store_dir_limit_size;

    struct flb_blob_db blob_db;
    flb_sds_t blob_database_file;
    size_t part_size;
    time_t upload_parts_freshness_threshold;
    int file_delivery_attempt_limit;
    int part_delivery_attempt_limit;
    flb_sds_t authorization_endpoint_url;
    flb_sds_t authorization_endpoint_username;
    flb_sds_t authorization_endpoint_password;
    flb_sds_t authorization_endpoint_bearer_token;
    struct flb_upstream *authorization_endpoint_upstream;
    struct flb_tls *authorization_endpoint_tls_context;

    size_t current_buffer_size;

    struct flb_aws_provider *provider;
    struct flb_aws_provider *base_provider;
    struct flb_tls *provider_tls;
    struct flb_tls *sts_provider_tls;
    struct flb_tls *client_tls;

    struct flb_aws_client *s3_client;
    int json_date_format;
    flb_sds_t json_date_key;
    flb_sds_t date_key;

    flb_sds_t buffer_dir;

    char *store_dir;
    struct flb_fstore *fs;
    struct flb_fstore_stream *stream_active;  /* default active stream */
    struct flb_fstore_stream *stream_metadata; /* s3 metadata stream */
    struct flb_hash_table *file_hash;
    pthread_mutex_t file_hash_lock; /* Protects file_hash access */

    int has_old_buffers;
    int initial_upload_done;
    int is_exiting;
    int needs_recovery;

    int preserve_data_ordering;
    int upload_queue_success;
    struct mk_list upload_queue;
    pthread_mutex_t upload_queue_lock;  /* Protects upload_queue access */

    size_t file_size;
    size_t upload_chunk_size;
    time_t upload_timeout;
    time_t retry_time;

    int timer_created;
    int timer_ms;
    int key_fmt_has_uuid;

    uint64_t seq_index;
    int key_fmt_has_seq_index;
    flb_sds_t metadata_dir;
    flb_sds_t seq_index_file;

    struct flb_output_instance *ins;

    int format;
    char *schema_str;
    struct flb_parquet_schema *cached_arrow_schema;

    struct flb_aws_client_generator *client_generator;
};

#define FLB_S3_FORMAT_JSON     0
#define FLB_S3_FORMAT_PARQUET  1

void cb_s3_upload(struct flb_config *config, void *data);
int s3_format_chunk(struct flb_s3 *ctx,
                    struct s3_file *chunk,
                    flb_sds_t *out_buf, size_t *out_size);
int s3_upload_file(struct flb_s3 *ctx,
                   const char *file_path,
                   const char *tag, int tag_len,
                   time_t file_first_log_time);

/* Unified S3 Key Generation */
flb_sds_t s3_generate_key(struct flb_s3 *ctx,
                          const char *tag,
                          time_t timestamp,
                          const char *filename);

/* Index persistence */
int write_seq_index(char *seq_index_file, uint64_t seq_index);

/* Orchestration: initiate multipart upload and enqueue parts */
int s3_initiate_multipart_upload(struct flb_s3 *ctx,
                                           uint64_t file_id,
                                           const char *file_path,
                                           const char *tag,
                                           int tag_len);

/* Test utility functions */
int s3_plugin_under_test();

/* Get S3 client */
struct flb_aws_client *s3_get_client(struct flb_s3 *ctx);

/* Init options for dependency injection (used by tests) */
struct flb_out_s3_init_options {
    struct flb_aws_client_generator *client_generator;
};

#endif