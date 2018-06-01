/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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
#define FLB_SPLUNK_DEFAULT_URI        "/services/collector/event"
#define FLB_SPLUNK_DEFAULT_TIME       "time"
#define FLB_SPLUNK_DEFAULT_EVENT      "event"

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_sds.h>

struct flb_splunk {
    /* HTTP Auth */
    char *http_user;
    char *http_passwd;

    /* Token Auth */
    flb_sds_t auth_header;

    /* Send fields directly or pack data into "event" object */
    int splunk_send_raw;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;
};

#endif
