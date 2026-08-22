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

#include <zerobus.h>

/* cbindgen does not export the Rust RecordType enum constants. */
#ifndef ZEROBUS_RECORD_TYPE_JSON
#define ZEROBUS_RECORD_TYPE_JSON 2
#endif

/* Plugin context */
struct flb_out_zerobus {
    /* Zerobus handles */
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
