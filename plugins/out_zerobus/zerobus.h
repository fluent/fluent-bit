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

#ifndef FLB_OUT_ZEROBUS_H
#define FLB_OUT_ZEROBUS_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_slist.h>

#include <stdint.h>
#include <stdbool.h>

/*
 * ZeroBus FFI declarations
 *
 * These types and functions are provided by the prebuilt Rust FFI static
 * library (libzerobus_ffi.a).  The declarations below are extracted from
 * the Go SDK CGO preamble at:
 *   github.com/databricks/zerobus-sdk/go@v1.0.0/ffi.go
 */

/* Opaque SDK / stream handles */
typedef struct CZerobusSdk CZerobusSdk;
typedef struct CZerobusStream CZerobusStream;

/* Result returned by every fallible FFI call */
typedef struct CResult {
    bool  success;
    char *error_message;
    bool  is_retryable;
} CResult;

/* Stream configuration passed to create_stream */
typedef struct CStreamConfigurationOptions {
    uintptr_t max_inflight_requests;
    bool      recovery;
    uint64_t  recovery_timeout_ms;
    uint64_t  recovery_backoff_ms;
    uint32_t  recovery_retries;
    uint64_t  server_lack_of_ack_timeout_ms;
    uint64_t  flush_timeout_ms;
    int32_t   record_type;
    uint64_t  stream_paused_max_wait_time_ms;
    bool      has_stream_paused_max_wait_time_ms;
    uint64_t  callback_max_wait_time_ms;
    bool      has_callback_max_wait_time_ms;
} CStreamConfigurationOptions;

/* Record type enum values */
#define ZEROBUS_RECORD_TYPE_JSON 2

/* --- SDK lifecycle --- */
extern CZerobusSdk *zerobus_sdk_new(const char *endpoint,
                                    const char *unity_catalog_url,
                                    CResult *result);
extern void zerobus_sdk_free(CZerobusSdk *sdk);
extern void zerobus_sdk_set_use_tls(CZerobusSdk *sdk, bool use_tls);

/* --- Stream lifecycle --- */
extern CZerobusStream *zerobus_sdk_create_stream(
    CZerobusSdk *sdk,
    const char *table_name,
    const uint8_t *descriptor_proto_bytes,
    uintptr_t descriptor_proto_len,
    const char *client_id,
    const char *client_secret,
    const CStreamConfigurationOptions *options,
    CResult *result);

extern bool zerobus_stream_close(CZerobusStream *stream, CResult *result);
extern void zerobus_stream_free(CZerobusStream *stream);

/* --- Ingestion --- */
extern int64_t zerobus_stream_ingest_json_records(
    CZerobusStream *stream,
    const char **json_records,
    uintptr_t num_records,
    CResult *result);

extern bool zerobus_stream_wait_for_offset(CZerobusStream *stream,
                                           int64_t offset,
                                           CResult *result);

/* --- Utilities --- */
extern void zerobus_free_error_message(char *error_message);
extern CStreamConfigurationOptions zerobus_get_default_config(void);

/* ------------------------------------------------------------------ */

/* Plugin context */
struct flb_out_zerobus {
    /* ZeroBus handles */
    CZerobusSdk    *sdk;
    CZerobusStream *stream;

    /* Required config -- URL fields are read manually */
    flb_sds_t endpoint;  /* https:// auto-prepended if missing */
    flb_sds_t workspace_url;     /* https:// auto-prepended if missing */

    /* Required config -- auto-populated by config_map */
    flb_sds_t table_name;
    flb_sds_t client_id;
    flb_sds_t client_secret;

    /* Optional config -- auto-populated by config_map */
    int            add_tag;     /* FLB_TRUE / FLB_FALSE */
    flb_sds_t      time_key;    /* default "_time" */
    struct mk_list *log_keys;   /* CLIST, NULL when unset */
    flb_sds_t      raw_log_key; /* NULL when unset */

    /* Fluent Bit instance reference (used for logging macros) */
    struct flb_output_instance *ins;
};

#endif /* FLB_OUT_ZEROBUS_H */
