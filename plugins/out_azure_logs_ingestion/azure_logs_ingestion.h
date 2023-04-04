/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#ifndef FLB_OUT_AZURE_LOGS_INGESTION_H
#define FLB_OUT_AZURE_LOGS_INGESTION_H

#define FLB_AZURE_API_VERSION        "?api-version=2016-04-01"
#define FLB_AZURE_HOST               ".ods.opinsights.azure.com"
#define FLB_AZURE_PORT               443
#define FLB_AZURE_RESOURCE           "/api/logs"
#define FLB_AZURE_LOG_TYPE           "fluentbit"
#define FLB_AZURE_TIME_KEY           "@timestamp"

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_sds.h>

struct flb_azure_logs_ingestion {
    /* account setup */
    flb_sds_t tenant_id;
    flb_sds_t client_id;
    flb_sds_t client_secret;
    flb_sds_t dce_uri;
    flb_sds_t dcr_id;
    flb_sds_t table_name;

    /* networking */
    int port;
    flb_sds_t host;
    flb_sds_t uri;

    /* records */
    flb_sds_t time_key;

    /* time_generated: on/off */
    int time_generated;

    /* Upstream connection to the data collection endpoint */
    struct flb_upstream *u_dce;

    /* Plugin instance reference */
    struct flb_output_instance *ins;
};

#endif
