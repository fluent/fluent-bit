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
#include <fluent-bit/flb_pthread.h>
#include <fluent-bit/flb_sqldb.h>

/* S3 output format types */
#define FLB_S3_FORMAT_JSON_LINES  0
#define FLB_S3_FORMAT_PARQUET     100
#define FLB_S3_FORMAT_ARROW       101

/* Upload data to S3 in 5MB chunks */
#define MIN_CHUNKED_UPLOAD_SIZE 5242880
#define MAX_CHUNKED_UPLOAD_SIZE 50000000
#define MAX_CHUNKED_UPLOAD_COMPRESS_SIZE 5000000000

#define UPLOAD_TIMER_MAX_WAIT 60000
#define UPLOAD_TIMER_MIN_WAIT 6000

#define MULTIPART_UPLOAD_STATE_NOT_CREATED              0
#define MULTIPART_UPLOAD_STATE_CREATED                  1
#define MULTIPART_UPLOAD_STATE_COMPLETE_IN_PROGRESS     2
#define MULTIPART_UPLOAD_STATE_REJECTED                 3
#define MULTIPART_UPLOAD_STATE_CHECKPOINT_PENDING       4

#define DEFAULT_FILE_SIZE     100000000
#define MAX_FILE_SIZE         50000000000
#define MAX_FILE_SIZE_STR     "50,000,000,000"

/* Allowed max file size 1 GB for publishing to S3 */
#define MAX_FILE_SIZE_PUT_OBJECT        1000000000

#define DEFAULT_UPLOAD_TIMEOUT 3600

#define S3_MAX_PARTS 10000
#define MAX_UPLOAD_ERRORS 5
#define S3_RETRY_EXHAUSTED_DELETE     0
#define S3_RETRY_EXHAUSTED_QUARANTINE 1
#define S3_UPLOAD_DEFERRED -2
#define S3_UPLOAD_GONE -3
#define S3_RECOVERY_PREFIX "recover:"
#define S3_UPLOAD_REJECTED -4
#define S3_UPLOADER_IO_TIMEOUT 30

struct s3_retry_state {
    int failures;
    uint64_t retry_at;       /* monotonic deadline in this process */
    uint64_t until_ms;
    flb_sds_t uri;
};

/*
 * If we see repeated errors on an upload/chunk, we will discard it
 * This saves us from scenarios where something goes wrong and an upload can
 * not proceed (may be some other process completed it or deleted the upload)
 * instead of erroring out forever, we eventually discard the upload.
 *
 * The same is done for chunks, just to be safe, even though realistically
 * I can't think of a reason why a chunk could become unsendable.
 *
 * The retry limit is now configurable via the retry_limit parameter.
 */

struct upload_queue {
    struct s3_file *upload_file;
    /* Non-owning reference; refresh it before every upload attempt. */
    struct multipart_upload *m_upload_file;
    flb_sds_t tag;
    int tag_len;

    int retry_counter;
    time_t upload_time;
    uint64_t scan_id;
    int in_flight;

    struct mk_list _head;
};

struct flb_s3;

typedef struct flb_http_client *s3_request_fn(struct flb_s3 *ctx, int method,
                                            const char *uri, const char *body, size_t body_size,
                                            struct flb_aws_header *headers, size_t headers_count,
                                            int *deferred);

struct multipart_upload {
    flb_sds_t s3_key;
    flb_sds_t tag;
    flb_sds_t upload_id;
    int upload_state;
    int blob;
    int restored;
    time_t init_time;

    /*
     * maximum of 10,000 parts in an upload, for each we need to store mapping
     * of Part Number to ETag
     */
    int manifest_needs_sync;
    flb_sds_t pending_etag;
    size_t pending_part_size;
    flb_sds_t etags[S3_MAX_PARTS];
    int part_number;

    /*
     * we use async http, so we need to check that all part requests have
     * completed before we complete the upload
     */
    int parts_uploaded;

    /* ongoing tracker of how much data has been sent for this upload */
    size_t bytes;

    struct mk_list _head;

    /* see note for retry_limit configuration */
    int upload_errors;
    int complete_errors;
    uint64_t complete_retry_at;
    uint64_t completion_scan_id;
    /* Multipart helpers own files_mutex; requests release/reacquire it for I/O. */
    s3_request_fn *request;
};

struct flb_s3 {
    int follow_symlinks;
    char *bucket;
    char *region;
    char *s3_key_format;
    char *time_offset;
    char *tag_delimiters;
    char *endpoint;
    char *sts_endpoint;
    char *canned_acl;
    char *content_type;
    char *retry_exhausted_action_str;
    char *storage_class;
    char *log_key;
    char *external_id;
    char *profile;   
    int free_endpoint;
    int retry_requests;
    int use_put_object;
    int send_content_md5;
    int static_file_path;
    int retry_exhausted_action;
    int compression;
    int s3_format;
    int port;
    int insecure;
    size_t store_dir_limit_size;
    size_t quarantine_dir_limit_size;

    struct flb_blob_db blob_db;
    flb_sds_t blob_database_file;
    size_t part_size;
    time_t upload_parts_timeout;
    time_t upload_parts_freshness_threshold;
    int file_delivery_attempt_limit;
    int part_delivery_attempt_limit;
    flb_sds_t authorization_endpoint_url;
    flb_sds_t authorization_endpoint_username;
    flb_sds_t authorization_endpoint_password;
    flb_sds_t authorization_endpoint_bearer_token;
    struct flb_upstream *authorization_endpoint_upstream;
    struct flb_tls *authorization_endpoint_tls_context;

    /* track the total amount of buffered data */
    size_t unknown_spool_sizes;
    uint64_t current_buffer_size;
    uint64_t quarantine_buffer_size;

    struct flb_aws_provider *provider;
    struct flb_aws_provider *base_provider;
    /* tls instances can't be re-used; aws provider requires a separate one */
    struct flb_tls *provider_tls;
    /* one for the standard chain provider, one for sts assume role */
    struct flb_tls *sts_provider_tls;
    struct flb_tls *client_tls;

    struct flb_aws_client *s3_client;
    int out_format;
    int json_date_format;
    flb_sds_t json_date_key;
    flb_sds_t date_key;

    flb_sds_t buffer_dir;

    char *store_dir;
    struct flb_fstore *fs;
    struct flb_fstore_stream *stream_active;  /* default active stream */
    struct flb_fstore_stream *stream_upload;  /* multipart upload stream */
    struct flb_fstore_stream *stream_quarantine; /* retry-exhausted stream */
    struct flb_fstore_stream *stream_metadata; /* s3 metadata stream */
    /* Protects store and upload state; owned requests run outside this mutex. */
    pthread_mutex_t files_mutex;
    int files_mutex_initialized;
    struct mk_list upload_claims;
    uint64_t upload_scan_id;
    int blob_upload_in_progress;
    int blob_refund_pending;
    int blob_claims_initialized;
    sqlite3 *uploader_db;
    unsigned int journal_generation;
    struct flb_output_throttle uploader_gate;
    int uploader_gate_initialized;
    int uploader_storage_failed;
#ifdef FLB_HAVE_METRICS
    struct cmt_gauge *uploader_cooldown_deadline;
    struct cmt_gauge *uploader_storage_blocked;
    struct cmt_gauge *uploader_spool_full;
    struct cmt_gauge *uploader_rejected;
#endif
    int checkpoint_lost;
    struct mk_list pending_checkpoints;
    struct s3_file *rollback_file;
    uint64_t rollback_size;
    uint64_t uploader_file_order;

    /*
     * used to track that unset buffers were found on startup that have not
     * been sent
     */
    int has_old_buffers;
    int draining_backlog;
    /* old multipart uploads read on start up */
    int has_old_uploads;

    struct mk_list uploads;

    int preserve_data_ordering;
    int upload_queue_success;
    struct mk_list upload_queue;
    struct flb_sched_timer *upload_queue_retry_timer;

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
};

struct flb_http_client *s3_request(struct flb_s3 *ctx,
                                  int method, const char *uri,
                                  const char *body, size_t body_size,
                                  struct flb_aws_header *headers, size_t headers_count,
                                  int *deferred);

int s3_uploader_should_seal(struct flb_s3 *ctx, uint64_t size, size_t append_size);
int s3_uploader_storage_recover(struct flb_s3 *ctx);
void s3_uploader_count_rejected(struct flb_s3 *ctx, int delta);
void s3_uploader_storage_status(struct flb_s3 *ctx, int failed);
int s3_uploader_reconcile_files(struct flb_s3 *ctx);
int s3_uploader_init(struct flb_s3 *ctx);
void s3_uploader_destroy(struct flb_s3 *ctx);
int s3_uploader_admit(struct flb_s3 *ctx, uint64_t *generation);
int s3_uploader_response(struct flb_s3 *ctx, struct flb_http_client *response,
                         uint64_t generation);
uint64_t s3_uploader_wall_ms(void);
int s3_uploader_state_read(struct flb_s3 *ctx, const char *kind, const char *key,
                           struct s3_retry_state *state);
int s3_uploader_state_write(struct flb_s3 *ctx, const char *kind, const char *key,
                            const struct s3_retry_state *state);
void s3_uploader_state_delete(struct flb_s3 *ctx, const char *kind, const char *key);
int s3_uploader_save_failure(struct flb_s3 *ctx, const char *kind, const char *key,
                             struct s3_retry_state *state);

int upload_part(struct flb_s3 *ctx, struct multipart_upload *m_upload,
                char *body, size_t body_size, char *pre_signed_url);

int create_multipart_upload(struct flb_s3 *ctx,
                            struct multipart_upload *m_upload,
                            char *pre_signed_url);

int complete_multipart_upload(struct flb_s3 *ctx,
                              struct multipart_upload *m_upload,
                              char *pre_signed_url);

int abort_multipart_upload(struct flb_s3 *ctx,
                           struct multipart_upload *m_upload,
                           char *pre_signed_url);

int s3_checkpoint_upload(struct flb_s3 *ctx, struct multipart_upload *upload);
int multipart_read_uploads_from_fs(struct flb_s3 *ctx);

void multipart_upload_destroy(struct multipart_upload *m_upload);

struct flb_http_client *mock_s3_call(char *error_env_var, char *api);
int s3_plugin_under_test();
char *flb_s3_test_env_get(const char *name);
int flb_s3_test_env_set(const char *name, const char *value, int overwrite);
int flb_s3_test_env_unset(const char *name);
void flb_s3_test_env_reset(void);

int get_md5_base64(char *buf, size_t buf_size, char *md5_str, size_t md5_str_size);

int create_headers(struct flb_s3 *ctx, char *body_md5,
                   struct flb_aws_header **headers, int *num_headers,
                   int multipart_upload);

#endif
