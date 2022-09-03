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

#ifndef FLB_OUT_AZURE_KUSTO
#define FLB_OUT_AZURE_KUSTO

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_upstream_ha.h>

/* refresh token every 50 minutes */
#define FLB_AZURE_KUSTO_TOKEN_REFRESH 3000

/* Kusto streaming inserts oauth scope */
#define FLB_AZURE_KUSTO_SCOPE "https://help.kusto.windows.net/.default"

/* MSAL authorization URL  */
#define FLB_MSAL_AUTH_URL_TEMPLATE \
    "https://login.microsoftonline.com/%s/oauth2/v2.0/token"

#define FLB_AZURE_KUSTO_MGMT_URI_PATH "/v1/rest/mgmt"
#define FLB_AZURE_KUSTO_MGMT_BODY_TEMPLATE "{\"csl\":\"%s\", \"db\": \"NetDefaultDB\"}"

#define FLB_AZURE_KUSTO_DEFAULT_TIME_KEY "timestamp"
#define FLB_AZURE_KUSTO_DEFAULT_TAG_KEY "tag"
#define FLB_AZURE_KUSTO_DEFAULT_LOG_KEY "log"

#define AZURE_KUSTO_RESOURCE_STORAGE 0
#define AZURE_KUSTO_RESOURCE_QUEUE 1

#define AZURE_KUSTO_RESOURCE_UPSTREAM_URI "uri"
#define AZURE_KUSTO_RESOURCE_UPSTREAM_SAS "sas"

#define FLB_AZURE_KUSTO_RESOURCES_LOAD_INTERVAL_SEC 3600

struct flb_azure_kusto_resources {
    struct flb_upstream_ha *blob_ha;
    struct flb_upstream_ha *queue_ha;
    flb_sds_t identity_token;

    /* used to reload resouces after some time */
    time_t load_time;
};

struct flb_azure_kusto {
    /* azure_kusto configuration */
    flb_sds_t tenant_id;
    flb_sds_t client_id;
    flb_sds_t client_secret;
    flb_sds_t ingestion_endpoint;
    flb_sds_t database_name;
    flb_sds_t table_name;
    flb_sds_t ingestion_mapping_reference;

    /* records configuration */
    flb_sds_t log_key;
    int include_tag_key;
    flb_sds_t tag_key;
    int include_time_key;
    flb_sds_t time_key;

    /* --- internal data --- */

    flb_sds_t ingestion_mgmt_endpoint;

    /* oauth2 context */
    flb_sds_t oauth_url;
    struct flb_oauth2 *o;

    /* mutex for acquiring oauth tokens */
    pthread_mutex_t token_mutex;

    /* ingestion resources */
    struct flb_azure_kusto_resources *resources;

    /* mutex for loading reosurces */
    pthread_mutex_t resources_mutex;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    /* Fluent Bit context */
    struct flb_config *config;

    /* Plugin output instance reference */
    struct flb_output_instance *ins;
};

flb_sds_t get_azure_kusto_token(struct flb_azure_kusto *ctx);
flb_sds_t execute_ingest_csl_command(struct flb_azure_kusto *ctx, const char *csl);

#endif
