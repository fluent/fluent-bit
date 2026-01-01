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

#ifndef FLB_OUT_SPLUNK
#define FLB_OUT_SPLUNK

#define FLB_SPLUNK_DEFAULT_HOST          "127.0.0.1"
#define FLB_SPLUNK_DEFAULT_PORT          8088
#define FLB_SPLUNK_DEFAULT_ENDPOINT      "/services/collector/event"
#define FLB_SPLUNK_DEFAULT_TIME          "time"
#define FLB_SPLUNK_DEFAULT_EVENT_HOST    "host"
#define FLB_SPLUNK_DEFAULT_EVENT_SOURCE  "source"
#define FLB_SPLUNK_DEFAULT_EVENT_SOURCET "sourcetype"
#define FLB_SPLUNK_DEFAULT_EVENT_INDEX   "index"
#define FLB_SPLUNK_DEFAULT_EVENT_FIELDS  "fields"
#define FLB_SPLUNK_DEFAULT_EVENT         "event"
#define FLB_SPLUNK_DEFAULT_HTTP_MAX      "2M"

#define FLB_SPLUNK_CHANNEL_IDENTIFIER_HEADER "X-Splunk-Request-Channel"

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_record_accessor.h>

struct flb_splunk_field {
    flb_sds_t key_name;
    struct flb_record_accessor *ra;
    struct mk_list _head;
};

struct flb_splunk {
    /* Payload compression */
    int compress_gzip;

    /* HTTP Auth */
    char *http_user;
    char *http_passwd;

    /* Event key */
    flb_sds_t event_key;
    struct flb_record_accessor *ra_event_key;

    /* Event host */
    flb_sds_t event_host;
    struct flb_record_accessor *ra_event_host;

    /* Event source */
    flb_sds_t event_source;
    struct flb_record_accessor *ra_event_source;

    /*
     * NOTE: EVENT SOURCE
     * -------------------
     * we use two separate variables since we aim to specify a default in case
     * a record accessor pattern is given but not found. The event_sourcetype_key
     * has precedence over th the 'event_sourcetype' variable.
     */

    /* Event sourcetype */
    flb_sds_t event_sourcetype;

    /* Event sourcetype record key */
    flb_sds_t event_sourcetype_key;
    struct flb_record_accessor *ra_event_sourcetype_key;

    /* Event index */
    flb_sds_t event_index;

    /* Event sourcetype record key */
    flb_sds_t event_index_key;
    struct flb_record_accessor *ra_event_index_key;

    /* Event fields */
    struct mk_list *event_fields;

    /* Internal/processed event fields */
    struct mk_list fields;

    /* Token Auth */
    flb_sds_t auth_header;
    /* Token Auth (via metadata) */
    flb_sds_t metadata_auth_header;

    /* Metadata of Splunk Authentication */
    flb_sds_t metadata_auth_key;
    struct flb_record_accessor *ra_metadata_auth_key;

    /* Channel identifier */
    flb_sds_t channel;
    size_t channel_len;

    /* Send fields directly or pack data into "event" object */
    int splunk_send_raw;

    /* HTTP Client Setup */
    size_t buffer_size;

    /* HTTP: Debug bad requests (HTTP status 400) to stdout */
    int http_debug_bad_request;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    /* Plugin instance */
    struct flb_output_instance *ins;

    pthread_mutex_t mutex_hec_token;
};

#endif
