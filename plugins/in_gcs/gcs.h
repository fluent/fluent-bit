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

#ifndef FLB_IN_GCS_H
#define FLB_IN_GCS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_gcp_auth.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/tls/flb_tls.h>

#ifdef FLB_HAVE_SQLDB
#include <fluent-bit/flb_sqldb.h>
#endif

#include <msgpack.h>

#define FLB_GCS_DEFAULT_ENDPOINT   "https://storage.googleapis.com"
#define FLB_GCS_DEFAULT_PAGE_SIZE  "1000"
#define FLB_GCS_DEFAULT_BATCH_SIZE "1000"
#define FLB_GCS_DEFAULT_MAX_OBJECT "128M"

/* one bounded unit of work is done every tick of the collector */
#define FLB_GCS_TICK_NSEC          100000000L

/* cheap iterations (skipped objects) allowed in a single tick */
#define FLB_GCS_SKIP_PER_TICK      256

/* worst-case size of a listing entry: 1024 bytes name escaped as \u00XX plus fields */
#define FLB_GCS_LIST_ENTRY_MAX     ((1024 * 6) + 512)

/* room for the HTTP headers on top of the object payload in the response buffer */
#define FLB_GCS_HEADERS_ROOM       16384

/* compression modes */
#define FLB_GCS_COMPRESSION_AUTO   0
#define FLB_GCS_COMPRESSION_NONE   1
#define FLB_GCS_COMPRESSION_GZIP   2

/* time formats */
#define FLB_GCS_TIME_AUTO          0
#define FLB_GCS_TIME_ISO8601       1
#define FLB_GCS_TIME_JAVA_SQL      2
#define FLB_GCS_TIME_DOUBLE        3
#define FLB_GCS_TIME_EPOCH         4
#define FLB_GCS_TIME_EPOCH_MS      5

/* state machine */
#define FLB_GCS_STATE_LIST         0   /* fetch the next page of the listing */
#define FLB_GCS_STATE_NEXT         1   /* pick the next object of the page   */
#define FLB_GCS_STATE_DOWNLOAD     2   /* download the current object        */
#define FLB_GCS_STATE_EMIT         3   /* emit the records of the object     */
#define FLB_GCS_STATE_DONE         4   /* nothing else to do                 */

/* results of in_gcs_emit_batch() */
#define FLB_GCS_EMIT_OK            0
#define FLB_GCS_EMIT_APPEND_FAILED -1  /* nothing ingested (e.g. backpressure) */
#define FLB_GCS_EMIT_ENCODE_FAILED -2  /* a record could not be encoded */

/* request results */
#define FLB_GCS_REQ_OK             0
#define FLB_GCS_REQ_TRANSIENT      1   /* connection error, 429, 5xx, token failure */
#define FLB_GCS_REQ_UNAUTHORIZED   2   /* 401 */
#define FLB_GCS_REQ_FORBIDDEN      3   /* 403 */
#define FLB_GCS_REQ_NOT_FOUND      4   /* 404 */
#define FLB_GCS_REQ_ERROR          5   /* any other status */

struct gcs_item {
    flb_sds_t name;
    flb_sds_t generation;
    uint64_t size;
};

struct gcs_response {
    struct flb_http_client *client;
    struct flb_connection *conn;
    int status;
};

struct flb_in_gcs {
    /* configuration */
    flb_sds_t bucket;
    flb_sds_t prefix;
    flb_sds_t start_offset;
    flb_sds_t end_offset;
    flb_sds_t endpoint;
    int page_size;
    int batch_size;
    size_t max_object_size;
    flb_sds_t compression_name;
    int compression;
    flb_sds_t parser_name;
    struct flb_parser *parser;
    flb_sds_t time_key;
    int time_key_enabled;               /* time_key is set and not false/off/none */
    flb_sds_t time_format_name;
    int time_format;
    int time_keep;
    flb_sds_t tag_regex_pattern;
    struct flb_regex *tag_regex;
    flb_sds_t object_key;
    flb_sds_t db_path;
    int exit_on_complete;
    int retry_limit;

    /* authentication (same keys as out_gcs) */
    flb_sds_t credentials_file;
    flb_sds_t metadata_server;
    int has_identity_federation;
    flb_sds_t project_number;
    flb_sds_t pool_id;
    flb_sds_t provider_id;
    flb_sds_t identity_token_file;
    flb_sds_t google_service_account;
    flb_sds_t subject_token_type;

    /* network */
    flb_sds_t host;
    int port;
    flb_sds_t base_path;
    struct flb_upstream *upstream;
    struct flb_tls *tls;                /* private TLS context, owned */
    struct flb_gcp_auth *auth;

    /* run state */
    int coll_id;
    int state;
    int done;
    int failed;
    int paused;
    int attempts;                       /* transient failures of the current request */
    int auth_retried;                   /* the single 401 retry was used */
    int encode_failures;                /* consecutive encode failures of the object */
    int under_test;                     /* FLB_IN_GCS_PLUGIN_UNDER_TEST is set */
    char last_error[320];               /* status and body excerpt of the last failure */

    /* current listing page */
    flb_sds_t page_token;               /* token of the page to fetch next */
    struct gcs_item *items;
    int items_count;
    int items_index;
    int has_more_pages;

    /* current object */
    struct gcs_item current;
    int has_current;
    char *buf;                          /* decoded (and decompressed) content */
    size_t buf_len;
    size_t buf_off;
    flb_sds_t tag;                      /* NULL: instance tag */

    /* summary */
    uint64_t objects_processed;
    uint64_t objects_skipped;
    uint64_t objects_failed;
    uint64_t records_emitted;

    struct flb_log_event_encoder *encoder;

#ifdef FLB_HAVE_SQLDB
    struct flb_sqldb *db;
    sqlite3_stmt *stmt_exists;
    sqlite3_stmt *stmt_insert;
#endif

    struct flb_input_instance *ins;
    struct flb_config *config;
};

/* gcs_api.c */
flb_sds_t in_gcs_uri_encode(const char *value, size_t len);
int in_gcs_list_page(struct flb_in_gcs *ctx);
int in_gcs_download_object(struct flb_in_gcs *ctx);
void in_gcs_items_destroy(struct flb_in_gcs *ctx);
void in_gcs_current_clear(struct flb_in_gcs *ctx);

/* gcs_record.c */
int in_gcs_time_parse_string(int format, const char *str, size_t len, struct flb_time *out);
int in_gcs_time_parse_number(int format, const msgpack_object *obj, struct flb_time *out);
int in_gcs_emit_batch(struct flb_in_gcs *ctx);
flb_sds_t in_gcs_tag_from_name(struct flb_in_gcs *ctx, const char *name, size_t len);

/* gcs_db.c */
int in_gcs_db_open(struct flb_in_gcs *ctx);
void in_gcs_db_close(struct flb_in_gcs *ctx);
int in_gcs_db_has_object(struct flb_in_gcs *ctx, const char *name, const char *generation);
int in_gcs_db_record_object(struct flb_in_gcs *ctx, const char *name, const char *generation);

#endif
