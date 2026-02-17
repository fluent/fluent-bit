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

#ifndef FLB_OUT_AZURE_LOGS_INGESTION
#define FLB_OUT_AZURE_LOGS_INGESTION

#define FLB_AZ_LI_API_VERSION       "api-version=2021-11-01-preview"
#define FLB_AZ_LI_TIME_KEY          "@timestamp"
#define FLB_AZ_LI_AUTH_SCOPE        "https://monitor.azure.com/.default"
/* auth url needs tenant_id */
#define FLB_AZ_LI_AUTH_URL_TMPLT    "https://login.microsoftonline.com/"\
                                    "%s/oauth2/v2.0/token"
/* DCE Full URL needs: dce_url, dcr_id, Log Analytics custom table name */
#define FLB_AZ_LI_DCE_URL_TMPLT     "%s/dataCollectionRules/%s/streams/"\
                                    "Custom-%s?"FLB_AZ_LI_API_VERSION
/* TLS Modes for upstream connection = FLB_IO_TLS or FLB_IO_OPT_TLS*/
#define FLB_AZ_LI_TLS_MODE          FLB_IO_TLS
/* refresh token every 60 minutes */
#define FLB_AZ_LI_TOKEN_TIMEOUT 3600

/* Authentication types */
typedef enum {
    FLB_AZ_LI_AUTH_SERVICE_PRINCIPAL = 0,    /* Client ID + Client Secret */
    FLB_AZ_LI_AUTH_MANAGED_IDENTITY_SYSTEM,  /* System-assigned managed identity */
    FLB_AZ_LI_AUTH_MANAGED_IDENTITY_USER     /* User-assigned managed identity */
} flb_az_li_auth_type;

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_sds.h>

/* Context structure for Azure Logs Ingestion API */
struct flb_az_li {
    /* log ingestion account setup */
    flb_sds_t tenant_id;
    flb_sds_t client_id;
    flb_sds_t client_secret;
    flb_sds_t dce_url;
    flb_sds_t dcr_id;
    flb_sds_t table_name;

    /* Authentication */
    int auth_type;
    char *auth_type_str;

    /* time_generated: on/off */
    int time_generated;
    /* time key name */
    flb_sds_t time_key;

    /* compress payload */
    int compress_enabled;

    /* mangement auth */
    flb_sds_t auth_url;
    struct flb_oauth2 *u_auth;
    /* mutex for acquiring tokens */
    pthread_mutex_t token_mutex;

    /* upstream connection to the data collection endpoint */
    struct flb_upstream *u_dce;
    flb_sds_t dce_u_url;

    /* plugin output and config instance reference */
    struct flb_output_instance *ins;
    struct flb_config *config;
};

#endif
