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

#ifndef FLB_OUT_CHRONICLE
#define FLB_OUT_CHRONICLE

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_sds.h>

/* refresh token every 50 minutes */
#define FLB_CHRONICLE_TOKEN_REFRESH 3000

/* Timestamp format */
#define FLB_STD_TIME_FMT  "%Y-%m-%dT%H:%M:%S"

/* Chronicle unstructureed logs oauth scope */
#define FLB_CHRONICLE_SCOPE     "https://www.googleapis.com/auth/malachite-ingestion"

/* Chronicle authorization URL */
#define FLB_CHRONICLE_AUTH_URL  "https://oauth2.googleapis.com/token"

#define FLB_CHRONICLE_UNSTRUCTURED_ENDPOINT "/v2/unstructuredlogentries:batchCreate"
#define FLB_CHRONICLE_LOG_TYPE_ENDPOINT     "/v2/logtypes"
#define FLB_CHRONICLE_URL_BASE              "https://malachiteingestion-pa.googleapis.com"
#define FLB_CHRONICLE_URL_BASE_EU           "https://europe-malachiteingestion-pa.googleapis.com"
#define FLB_CHRONICLE_URL_BASE_UK           "https://europe-west2-malachiteingestion-pa.googleapis.com"
#define FLB_CHRONICLE_URL_BASE_ASIA         "https://asia-southeast1-malachiteingestion-pa.googleapis.com"

struct flb_chronicle_oauth_credentials {
    /* parsed credentials file */
    flb_sds_t type;
    flb_sds_t project_id;
    flb_sds_t private_key_id;
    flb_sds_t private_key;
    flb_sds_t client_email;
    flb_sds_t client_id;
    flb_sds_t auth_uri;
    flb_sds_t token_uri;
};

struct flb_chronicle {
    /* credentials */
    flb_sds_t credentials_file;

    struct flb_chronicle_oauth_credentials *oauth_credentials;

    /* chronicle configuration */
    flb_sds_t project_id;
    flb_sds_t customer_id;
    flb_sds_t log_type;

    flb_sds_t uri;
    flb_sds_t health_uri;
    flb_sds_t endpoint;
    flb_sds_t region;
    flb_sds_t log_key;

    int json_date_format;
    flb_sds_t json_date_key;
    flb_sds_t date_key;

    /* oauth2 context */
    struct flb_oauth2 *o;

    /* mutex for acquiring oauth tokens */
    pthread_mutex_t token_mutex;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    /* Fluent Bit context */
    struct flb_config *config;

    /* Plugin output instance reference */
    struct flb_output_instance *ins;
};

#endif
