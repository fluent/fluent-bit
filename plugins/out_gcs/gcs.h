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

#ifndef FLB_OUT_GCS_H
#define FLB_OUT_GCS_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_fstore.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_util.h>

#define FLB_GCS_DEFAULT_HOST "storage.googleapis.com"
#define FLB_GCS_DEFAULT_PORT 443
#define FLB_GCS_SCOPE "https://www.googleapis.com/auth/devstorage.read_write"
#define FLB_GCS_AUTH_URL "https://oauth2.googleapis.com/token"
#define FLB_GCS_TOKEN_REFRESH 3000

#define FLB_GCS_COMPRESSION_NONE 0
#define FLB_GCS_COMPRESSION_GZIP 1

struct upload_queue {
    struct gcs_file *upload_file;
    char *tag;
    int tag_len;
    int retry_counter;
    time_t upload_time;
    struct mk_list _head;
};

struct flb_gcs_oauth_credentials {
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
    struct flb_output_instance *ins;
    struct flb_config *config;
    struct flb_upstream *u;
    struct flb_oauth2 *o;
    pthread_mutex_t token_mutex;
    int token_mutex_initialized;

    flb_sds_t bucket;
    flb_sds_t object_key;
    flb_sds_t content_type;
    flb_sds_t credentials_file;
    flb_sds_t store_dir;
    flb_sds_t gcs_key_format;
    flb_sds_t tag_delimiters;
    flb_sds_t canned_acl;
    flb_sds_t storage_class;
    int send_content_md5;
    int preserve_data_ordering;
    int store_chunk_limit;
    size_t current_buffer_size;
    size_t store_dir_limit_size;
    flb_sds_t seq_index_file;
    uint64_t seq_index;
    int key_fmt_has_uuid;
    int key_fmt_has_seq_index;
    int static_file_path;

    int out_format;
    int json_date_format;
    flb_sds_t json_date_key;
    int compression_type;
    struct flb_fstore *fs;
    struct flb_fstore_stream *fs_stream;
    struct mk_list upload_queue;
    time_t upload_timeout;
    int retry_time;
    int upload_queue_success;
    int timer_created;
    int timer_ms;

    struct flb_gcs_oauth_credentials *oauth_credentials;
};

#endif
