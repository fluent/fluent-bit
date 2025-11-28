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

#ifndef FLB_OUT_ARVANCLOUD_CLOUDLOGS_H
#define FLB_OUT_ARVANCLOUD_CLOUDLOGS_H

#define FLB_ARVANCLOUD_LOG_TYPE "fluentbit"

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_record_accessor.h>

struct flb_out_arvancloud_cloudlogs {
    /* Network */
    struct flb_upstream *u;
    flb_sds_t host;
    int port;
    flb_sds_t uri;
    flb_sds_t scheme;

    /* Config */
    flb_sds_t api_key;
    int compress_gzip;
    int include_tag_key;
    flb_sds_t tag_key;
    flb_sds_t log_type;
    flb_sds_t log_type_key;
    struct flb_record_accessor *ra_log_type_key;
    flb_sds_t timestamp_key;
    struct flb_record_accessor *ra_timestamp_key;
    flb_sds_t timestamp_format;

    /* Instance */
    struct flb_output_instance *ins;
};

struct flb_out_arvancloud_cloudlogs *flb_arvancloud_conf_create(
                                    struct flb_output_instance *ins,
                                    struct flb_config *config);
int flb_arvancloud_conf_destroy(struct flb_out_arvancloud_cloudlogs *ctx);

#endif


