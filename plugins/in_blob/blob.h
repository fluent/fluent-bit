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

#ifndef FLB_IN_BLOB_H
#define FLB_IN_BLOB_H

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_sqldb.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#define POST_UPLOAD_ACTION_NONE       0
#define POST_UPLOAD_ACTION_DELETE     1
#define POST_UPLOAD_ACTION_EMIT_LOG   2
#define POST_UPLOAD_ACTION_ADD_SUFFIX 3

struct blob_file {
    /* database reference (id) */
    uint64_t db_id;

    /* file path  */
    flb_sds_t path;

    /* file size found when registered */
    size_t size;

    /* link to parent list blob_ctx->files */
    struct cfl_list _head;
};

struct blob_ctx {
    /* collector for scan_refresh_interval */
    int coll_fd;

    /*
     * list of files that has been found and being processed: file as soon as they are found are
     * registered with the flb_input_blob_file_register() function.
     */
    struct cfl_list files;

    /* Fluent Bit context */
    struct flb_config *config;

    /* input instance */
    struct flb_input_instance *ins;

    /* log encoder */
    struct flb_log_event_encoder *log_encoder;

    /* database */
#ifdef FLB_HAVE_SQLDB
    struct flb_sqldb *db;
    sqlite3_stmt *stmt_insert_file;
    sqlite3_stmt *stmt_delete_file;
    sqlite3_stmt *stmt_get_file;
#endif

    /* config map options */
    flb_sds_t path;
    flb_sds_t exclude_pattern;
    flb_sds_t database_file;
    time_t scan_refresh_interval;

    int       upload_success_action;
    flb_sds_t upload_success_action_str;
    flb_sds_t upload_success_suffix;
    flb_sds_t upload_success_message;

    int       upload_failure_action;
    flb_sds_t upload_failure_action_str;
    flb_sds_t upload_failure_suffix;
    flb_sds_t upload_failure_message;
};

#endif
