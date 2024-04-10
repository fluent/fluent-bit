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

#ifndef FLB_OUT_GCS
#define FLB_OUT_GCS

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>

/* Upload data to GCS in 5MB chunks */
#define MIN_CHUNKED_UPLOAD_SIZE 5242880
#define MAX_CHUNKED_UPLOAD_SIZE 50000000
#define MAX_CHUNKED_UPLOAD_COMPRESS_SIZE 5000000000

#define UPLOAD_TIMER_MAX_WAIT 60000
#define UPLOAD_TIMER_MIN_WAIT 6000

#define MULTIPART_UPLOAD_STATE_NOT_CREATED              0
#define MULTIPART_UPLOAD_STATE_CREATED                  1
#define MULTIPART_UPLOAD_STATE_COMPLETE_IN_PROGRESS     2

#define DEFAULT_FILE_SIZE     100000000
#define MAX_FILE_SIZE         50000000000
#define MAX_FILE_SIZE_STR     "50,000,000,000"

/* Allowed max file size 1 GB for publishing to GCS */
#define MAX_FILE_SIZE_PUT_OBJECT        1000000000 

#define DEFAULT_UPLOAD_TIMEOUT 3600

/* refresh token every 50 minutes */
#define FLB_GCS_TOKEN_REFRESH 3000

/* GCS streaming inserts oauth scope */
#define FLB_GCS_SCOPE     "https://www.googleapis.com/auth/devstorage.read_write"

/* GCS authorization URL */
#define FLB_GCS_AUTH_URL  "https://oauth2.googleapis.com/token"

#define FLB_GCS_RESOURCE_TEMPLATE  "/bigquery/v2/projects/%s/datasets/%s/tables/%s/insertAll"
#define FLB_GCS_URL_BASE           "https://storage.googleapis.com"
/*
 * If we see repeated errors on an upload/chunk, we will discard it
 * This saves us from scenarios where something goes wrong and an upload can
 * not proceed (may be some other process completed it or deleted the upload)
 * instead of erroring out forever, we eventually discard the upload.
 *
 * The same is done for chunks, just to be safe, even though realistically
 * I can't think of a reason why a chunk could become unsendable.
 */
#define MAX_UPLOAD_ERRORS 5

struct upload_queue {
    struct gcs_file *upload_file;
    char *tag;
    int tag_len;

    int retry_counter;
    time_t upload_time;

    struct mk_list _head;
};

struct flb_gcs_oauth_credentials {
    /* parsed credentials file */
    flb_sds_t type;
    flb_sds_t project_id;
    flb_sds_t private_key_id;
    flb_sds_t private_key;
    flb_sds_t client_email;
    flb_sds_t client_id;
    flb_sds_t auth_uri;
    flb_sds_t token_uri;
};

struct flb_gcs {
    char *bucket;
    char *gcs_key_format;
    char *tag_delimiters;

    char *canned_acl;
    char *content_type;
    char *storage_class;
    char *log_key;
    char *external_id;

    int retry_requests;
    int send_content_md5;
    int static_file_path;
    int compression;

    size_t store_dir_limit_size;

    /* track the total amount of buffered data */
    size_t current_buffer_size;

    /* gcp credentials */
    flb_sds_t credentials_file;
    struct flb_gcs_oauth_credentials *oauth_credentials;
    /* oauth2 context */
    struct flb_oauth2 *o;

    /* mutex for acquiring oauth tokens */
    pthread_mutex_t token_mutex;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    int json_date_format;
    flb_sds_t json_date_key;
    flb_sds_t date_key;

    flb_sds_t buffer_dir;

    char *store_dir;
    struct flb_fstore *fs;
    struct flb_fstore_stream *stream_active;  /* default active stream */
    struct flb_fstore_stream *stream_metadata; /* gcs metadata stream */

    /*
     * used to track that unset buffers were found on startup that have not
     * been sent
     */
    int has_old_buffers;


    int preserve_data_ordering;
    int upload_queue_success;
    struct mk_list upload_queue;

    size_t file_size;
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

int gcs_get_md5_base64(char *buf, size_t buf_size, char *md5_str, size_t md5_str_size);

#endif
