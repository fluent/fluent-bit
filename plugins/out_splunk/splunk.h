/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#define FLB_SPLUNK_DEFAULT_HOST       "127.0.0.1"
#define FLB_SPLUNK_DEFAULT_PORT       8088
#define FLB_SPLUNK_DEFAULT_URI_RAW    "/services/collector/raw"
#define FLB_SPLUNK_DEFAULT_URI_EVENT  "/services/collector/event"
#define FLB_SPLUNK_DEFAULT_TIME       "time"
#define FLB_SPLUNK_DEFAULT_EVENT      "event"

#define FLB_SPLUNK_CHANNEL_IDENTIFIER_HEADER "X-Splunk-Request-Channel"

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_record_accessor.h>

struct flb_splunk {
    /* Payload compression */
    int compress_gzip;

    /* HTTP Auth */
    char *http_user;
    char *http_passwd;

    /* Single value key */
    flb_sds_t event_key;
    struct flb_record_accessor *ra_event_key;

    /* Token Auth */
    flb_sds_t auth_header;

    /* Channel identifier */
    flb_sds_t channel;
    size_t channel_len;

    /* Send fields directly or pack data into "event" object */
    int splunk_send_raw;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    /* Plugin instance */
    struct flb_output_instance *ins;
};

#endif
