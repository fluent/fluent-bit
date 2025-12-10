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

#ifndef FLB_OUT_AZURE_BLOB_H
#define FLB_OUT_AZURE_BLOB_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_sqldb.h>
#include <fluent-bit/flb_time.h>

/* Content-Type */
#define AZURE_BLOB_CT          "Content-Type"
#define AZURE_BLOB_CT_NONE     0
#define AZURE_BLOB_CT_JSON     1 /* application/json */
#define AZURE_BLOB_CT_GZIP     2 /* application/gzip */

/* Content-Encoding */
#define AZURE_BLOB_CE          "Content-Encoding"
#define AZURE_BLOB_CE_NONE     0
#define AZURE_BLOB_CE_GZIP     1 /* gzip */

/* service endpoint */
#define AZURE_ENDPOINT_PREFIX  ".blob.core.windows.net"

/* buffering directory max size */
#define FLB_AZURE_BLOB_BUFFER_DIR_MAX_SIZE "8G"
#define UPLOAD_TIMER_MAX_WAIT 180000
#define UPLOAD_TIMER_MIN_WAIT 18000
#define MAX_FILE_SIZE         4000000000 // 4GB

#define AZURE_BLOB_APPENDBLOB 0
#define AZURE_BLOB_BLOCKBLOB  1

#define AZURE_BLOB_AUTH_KEY 0
#define AZURE_BLOB_AUTH_SAS 1

struct flb_azure_blob {
    int auto_create_container;
    int emulator_mode;
    int compress_gzip;
    int compress_blob;
    flb_sds_t account_name;
    flb_sds_t container_name;
    flb_sds_t blob_type;
    flb_sds_t shared_key;
    flb_sds_t endpoint;
    flb_sds_t path;
    int path_templating_enabled;
    flb_sds_t date_key;
    flb_sds_t auth_type;
    flb_sds_t sas_token;
    flb_sds_t database_file;
    size_t part_size;
    time_t upload_parts_timeout;
    time_t upload_parts_freshness_threshold;
    int file_delivery_attempt_limit;
    int part_delivery_attempt_limit;
    flb_sds_t configuration_endpoint_url;
    flb_sds_t configuration_endpoint_username;
    flb_sds_t configuration_endpoint_password;
    flb_sds_t configuration_endpoint_bearer_token;

    int endpoint_overriden_flag;
    int shared_key_overriden_flag;
    int sas_token_overriden_flag;
    int container_name_overriden_flag;
    int path_overriden_flag;

    int buffering_enabled;
    flb_sds_t buffer_dir;
    int unify_tag;

    size_t file_size;
    time_t upload_timeout;
    time_t retry_time;
    int timer_created;
    int timer_ms;
    int io_timeout;

    flb_sds_t azure_blob_buffer_key;
    size_t store_dir_limit_size;
    int buffer_file_delete_early;
    int blob_uri_length;
    int delete_on_max_upload_error;

    int has_old_buffers;
    int scheduler_max_retries;
    /* track the total amount of buffered data */
    size_t current_buffer_size;
    char *store_dir;
    struct flb_fstore *fs;
    struct flb_fstore_stream *stream_active;  /* default active stream */
    struct flb_fstore_stream *stream_upload;

    /*
     * Internal use
     */
    int  btype;                  /* blob type */
    int  atype;                  /* auth type */
    flb_sds_t real_endpoint;
    flb_sds_t base_uri;
    flb_sds_t shared_key_prefix;

    /* Shared key */
    unsigned char *decoded_sk;        /* decoded shared key */
    size_t decoded_sk_size;           /* size of decoded shared key */

#ifdef FLB_HAVE_SQLDB
    /*
     * SQLite by default is not built with multi-threading enabled, and
     * since we aim to share the database connection and prepared statements
     * in the output workers, we need to protect the access to these
     * resources using a mutex.
     */
    pthread_mutex_t db_lock;

    pthread_mutex_t file_upload_commit_file_parts;

    /* database context */
    struct flb_sqldb *db;

    /* prepared statements: files  */
    sqlite3_stmt *stmt_insert_file;
    sqlite3_stmt *stmt_delete_file;
    sqlite3_stmt *stmt_abort_file;
    sqlite3_stmt *stmt_get_file;
    sqlite3_stmt *stmt_update_file_destination;
    sqlite3_stmt *stmt_update_file_delivery_attempt_count;
    sqlite3_stmt *stmt_set_file_aborted_state;
    sqlite3_stmt *stmt_get_next_aborted_file;
    sqlite3_stmt *stmt_get_next_stale_file;
    sqlite3_stmt *stmt_reset_file_upload_states;
    sqlite3_stmt *stmt_reset_file_part_upload_states;


    /* prepared statement: file parts */
    sqlite3_stmt *stmt_insert_file_part;
    sqlite3_stmt *stmt_update_file_part_uploaded;
    sqlite3_stmt *stmt_update_file_part_delivery_attempt_count;

    sqlite3_stmt *stmt_get_next_file_part;
    sqlite3_stmt *stmt_update_file_part_in_progress;
    sqlite3_stmt *stmt_get_oldest_file_with_parts;
#endif

    /* Upstream connection */
    struct flb_upstream *u;

    struct flb_output_instance *ins;
    struct flb_config *config;
};

int azb_resolve_path(struct flb_azure_blob *ctx,
                     const char *tag,
                     int tag_len,
                     const struct flb_time *timestamp,
                     flb_sds_t *out_path);

#endif
