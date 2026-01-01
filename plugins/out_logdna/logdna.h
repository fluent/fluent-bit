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

#ifndef FLB_OUT_LOGDNA_H
#define FLB_OUT_LOGDNA_H

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_upstream.h>

#define FLB_LOGDNA_HOST      "logs.logdna.com"
#define FLB_LOGDNA_PORT      "443"
#define FLB_LOGDNA_ENDPOINT  "/logs/ingest"
#define FLB_LOGDNA_CT        "Content-Type"
#define FLB_LOGDNA_CT_JSON   "application/json; charset=UTF-8"

struct flb_logdna {
    /* Incoming Configuration Properties */
    flb_sds_t logdna_host;
    int       logdna_port;
    flb_sds_t logdna_endpoint;
    flb_sds_t api_key;
    flb_sds_t hostname;
    flb_sds_t mac_addr;
    flb_sds_t ip_addr;
    flb_sds_t file;
    flb_sds_t app;
    struct mk_list *tags;

    /* Internal */
    flb_sds_t _hostname;
    flb_sds_t tags_formatted;
    struct flb_upstream *u;
    struct flb_output_instance *ins;
};


#endif
